//! NDJSON event stream for machine monitoring (`--events-fd N`).
//!
//! Each line is a single JSON object; the stream is never mixed with the
//! final report on stdout.

use serde::Serialize;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::net::UnixStream;

const MAX_EVENT_LINE_BYTES: usize = 1024 * 1024;

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

/// Serializes core and backend events through one pipe and assigns the final
/// stream sequence. Backend processes have independent counters, so writing
/// them directly to the destination fd would create duplicate sequence
/// numbers whenever a new backend process starts.
pub struct EventRelay {
    worker: Option<std::thread::JoinHandle<std::io::Result<()>>>,
}

impl EventRelay {
    /// Start a relay for an optional destination fd. The returned fd is the
    /// only writer that the core and its backend children should clone.
    pub fn start(
        output: Option<OwnedFd>,
    ) -> std::io::Result<(Option<OwnedFd>, Option<EventRelay>)> {
        let Some(output) = output else {
            return Ok((None, None));
        };
        let flags = unsafe { libc::fcntl(output.as_raw_fd(), libc::F_GETFD) };
        if flags < 0
            || unsafe { libc::fcntl(output.as_raw_fd(), libc::F_SETFD, flags | libc::FD_CLOEXEC) }
                < 0
        {
            return Err(std::io::Error::last_os_error());
        }
        let (reader, writer) = UnixStream::pair()?;
        let worker = std::thread::Builder::new()
            .name("nclr-event-relay".into())
            .spawn(move || relay_events(reader, File::from(output)))?;
        Ok((
            Some(writer.into()),
            Some(EventRelay {
                worker: Some(worker),
            }),
        ))
    }

    /// Wait until every relayed line has reached the destination fd.
    pub fn finish(mut self) -> std::io::Result<()> {
        let worker = self
            .worker
            .take()
            .ok_or_else(|| std::io::Error::other("event relay worker was already consumed"))?;
        worker
            .join()
            .map_err(|_| std::io::Error::other("event relay worker panicked"))?
    }
}

fn relay_events(reader: UnixStream, mut output: File) -> std::io::Result<()> {
    let mut reader = BufReader::new(reader);
    let mut line = Vec::new();
    let mut seq = 0u64;
    loop {
        line.clear();
        let read = (&mut reader)
            .take((MAX_EVENT_LINE_BYTES + 1) as u64)
            .read_until(b'\n', &mut line)?;
        if read == 0 {
            break;
        }
        if line.len() > MAX_EVENT_LINE_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("event line exceeds {MAX_EVENT_LINE_BYTES} bytes"),
            ));
        }
        if line.last() != Some(&b'\n') {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "event stream ended in a partial line",
            ));
        }
        line.pop();
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        let mut value: serde_json::Value = serde_json::from_slice(&line).map_err(|error| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                format!("invalid event JSON: {error}"),
            )
        })?;
        let object = value.as_object_mut().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "event line must contain a JSON object",
            )
        })?;
        object.insert("seq".into(), serde_json::Value::from(seq));
        seq = seq.checked_add(1).ok_or_else(|| {
            std::io::Error::new(std::io::ErrorKind::InvalidData, "event sequence overflow")
        })?;
        serde_json::to_writer(&mut output, &value).map_err(std::io::Error::other)?;
        output.write_all(b"\n")?;
    }
    output.flush()
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

    #[test]
    fn relay_assigns_one_monotonic_sequence_to_multiple_writers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("relayed.ndjson");
        let output = OwnedFd::from(std::fs::File::create(&path).unwrap());
        let (writer, relay) = EventRelay::start(Some(output)).unwrap();
        let writer = writer.unwrap();
        let backend_writer = writer.try_clone().unwrap();

        let mut core = EventWriter::from_owned(Some(writer));
        core.emit("action", |_| {}).unwrap();
        let mut backend = File::from(backend_writer);
        backend
            .write_all(b"{\"seq\":0,\"phase\":\"physical-read\"}\n")
            .unwrap();
        core.emit("action-done", |_| {}).unwrap();
        drop(backend);
        drop(core);
        relay.unwrap().finish().unwrap();

        let events: Vec<serde_json::Value> = std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(events.len(), 3);
        assert_eq!(events[0]["seq"], 0);
        assert_eq!(events[1]["seq"], 1);
        assert_eq!(events[2]["seq"], 2);
        assert_eq!(events[1]["phase"], "physical-read");
    }
}
