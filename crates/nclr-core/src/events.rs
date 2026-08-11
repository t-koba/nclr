//! NDJSON event stream for machine monitoring (`--events-fd N`).
//!
//! Each line is a single JSON object; the stream is never mixed with the
//! final report on stdout.

use serde::Serialize;
use std::fs::File;
use std::io::Write;
use std::os::fd::{FromRawFd, OwnedFd};

#[derive(Serialize, Clone)]
pub struct Event {
    pub seq: u64,
    pub time: String,
    pub phase: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub done: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<u64>,
    /// Weak/defective blocks detected by the qualifying backend action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weak: Option<u64>,
    /// Status heartbeat for long-running self-executing operations; the
    /// value is a progress marker, not an action.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

pub struct EventWriter {
    file: Option<File>,
    seq: u64,
}

impl EventWriter {
    /// Create a writer for the given fd number, or a null writer when None.
    pub fn from_fd(fd: Option<i32>) -> Result<EventWriter, std::io::Error> {
        let file = match fd {
            Some(n) if n >= 0 => Some(File::from(unsafe { OwnedFd::from_raw_fd(n) })),
            _ => None,
        };
        Ok(EventWriter { file, seq: 0 })
    }

    /// Create a writer from an owned fd (a clone is made by the caller).
    pub fn from_owned(fd: Option<OwnedFd>) -> EventWriter {
        EventWriter {
            file: fd.map(File::from),
            seq: 0,
        }
    }

    pub fn emit(&mut self, phase: &str, f: impl FnOnce(&mut Event)) -> Result<(), std::io::Error> {
        let mut ev = Event {
            seq: self.seq,
            time: crate::journal::utc_now_rfc3339(),
            phase: phase.to_string(),
            action: None,
            done: None,
            total: None,
            unit: None,
            errors: None,
            weak: None,
            heartbeat: None,
            progress: None,
            message: None,
        };
        f(&mut ev);
        self.seq += 1;
        if let Some(file) = &mut self.file {
            let mut line = serde_json::to_vec(&ev)?;
            line.push(b'\n');
            file.write_all(&line)?;
        }
        Ok(())
    }

    pub fn progress(
        &mut self,
        phase: &str,
        done: u64,
        total: u64,
        unit: &str,
    ) -> Result<(), std::io::Error> {
        self.emit(phase, |e| {
            e.done = Some(done);
            e.total = Some(total);
            e.unit = Some(unit.to_string());
        })
    }

    /// Status heartbeat carrying a progress marker.
    /// Shares the writer's sequence, keeping the event stream monotonic.
    pub fn heartbeat(
        &mut self,
        phase: &str,
        progress: u64,
        unit: &str,
    ) -> Result<(), std::io::Error> {
        self.emit(phase, |e| {
            e.heartbeat = Some(true);
            e.progress = Some(progress);
            e.unit = Some(unit.to_string());
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_writer_works() {
        let mut w = EventWriter::from_fd(None).unwrap();
        w.emit("phase-x", |_| {}).unwrap();
    }

    #[test]
    fn event_json_is_ndjson() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.ndjson");
        let file = std::fs::File::create(&path).unwrap();
        use std::os::fd::IntoRawFd;
        let fd = file.into_raw_fd();
        let mut w = EventWriter::from_fd(Some(fd)).unwrap();
        w.emit("erase", |e| {
            e.done = Some(1);
            e.total = Some(10);
            e.unit = Some("block".into());
        })
        .unwrap();
        drop(w);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.starts_with("{\"seq\":0,\"time\":\"") && text.ends_with("}\n"));
        let _: serde_json::Value = serde_json::from_str(text.trim()).unwrap();
        assert_eq!(text.matches('\n').count(), 1);
    }

    #[test]
    fn seq_increments() {
        let mut w = EventWriter::from_fd(None).unwrap();
        let _ = w.emit("a", |_| {});
        let _ = w.emit("b", |_| {});
        assert_eq!(w.seq, 2);
    }
}
