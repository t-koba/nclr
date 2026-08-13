//! Append-only NDJSON journal with a hash chain.
//!
//! One file per run; each record carries `seq`, `prev` (hash of the previous
//! raw line), `phase`, `state`, `device` fingerprint and plan hash.
//! Destructive phase boundaries are fsync'd by the caller.

use crate::errors::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;

/// Current UTC time in RFC 3339 format (no external chrono dependency).
pub fn utc_now_rfc3339() -> String {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let days = secs / 86_400;
    let rem = secs % 86_400;
    let (y, m, d) = civil_from_days(days as i64);
    let (hh, mm, ss) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Days since epoch to civil date (Howard Hinnant's algorithm).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Default journal/state directory depending on privilege.
pub fn default_state_dir() -> PathBuf {
    if nix_uid() == 0 {
        PathBuf::from("/var/lib/nclr/run")
    } else {
        std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| {
                std::env::var_os("HOME")
                    .map(|h| PathBuf::from(h).join(".local/state"))
                    .unwrap_or_else(|| PathBuf::from("/tmp/nclr"))
            })
            .join("nclr")
    }
}

pub fn nix_uid() -> u32 {
    unsafe { libc::geteuid() }
}

/// A single journal record as written to disk.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Record {
    pub seq: u64,
    pub prev: String,
    pub time: String,
    pub phase: String,
    pub state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_errors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action_details: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The full plan document is embedded in the first record so that
    /// `resume` is self-contained.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plan: Option<serde_json::Value>,
}

#[derive(Debug, Clone)]
pub struct ParsedRecord {
    pub raw: String,
    pub value: serde_json::Value,
}

#[derive(Debug)]
pub struct Journal {
    path: PathBuf,
    file: File,
    seq: u64,
    prev_hash: String,
}

impl Journal {
    /// Create or append to the journal at `path`.
    pub fn open(path: &Path) -> Result<Journal> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    Error::io(
                        format!("cannot create state dir {}", parent.display()),
                        Some(e),
                    )
                })?;
            }
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .map_err(|e| Error::io(format!("cannot open journal {}", path.display()), Some(e)))?;
        validate_journal_file(&file, path)?;
        // Recover sequence and hash chain from an existing journal. A journal
        // that cannot be parsed must not be silently discarded: appending to a
        // corrupt file would break the append-only chain undetected.
        let bytes = read_journal_bytes(&file, path)?;
        let existing = parse_records(&bytes)?;
        // A power loss may tear only the final append. Records are always
        // newline-terminated and fsync'd, so a non-terminated tail is not a
        // committed record and must be removed before appending again.
        if !bytes.is_empty() && bytes.last() != Some(&b'\n') {
            let committed_len = bytes
                .iter()
                .rposition(|b| *b == b'\n')
                .map(|i| i + 1)
                .unwrap_or(0);
            file.set_len(committed_len as u64).map_err(|e| {
                Error::io(
                    format!("cannot truncate torn journal tail {}", path.display()),
                    Some(e),
                )
            })?;
            file.sync_all().map_err(|e| {
                Error::io(
                    format!("cannot sync repaired journal {}", path.display()),
                    Some(e),
                )
            })?;
        }
        let mut seq = 0u64;
        let mut prev = String::new();
        if let Some(last) = existing.last() {
            seq = last
                .value
                .get("seq")
                .and_then(|v| v.as_u64())
                .map(|s| s + 1)
                .ok_or_else(|| {
                    Error::Invalid(format!(
                        "journal {}: final record has no valid seq; refusing to append",
                        path.display()
                    ))
                })?;
            prev = crate::digest(last.raw.as_bytes());
        }
        Ok(Journal {
            path: path.to_path_buf(),
            file,
            seq,
            prev_hash: prev,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append a record and fsync (durability at destructive phase boundaries).
    pub fn record(
        &mut self,
        phase: &str,
        state: &str,
        fields: impl FnOnce(&mut Record),
    ) -> Result<()> {
        let mut rec = Record {
            seq: self.seq,
            prev: self.prev_hash.clone(),
            time: utc_now_rfc3339(),
            phase: phase.to_string(),
            state: state.to_string(),
            device: None,
            device_path: None,
            plan_hash: None,
            action: None,
            action_status: None,
            action_errors: None,
            action_details: None,
            message: None,
            plan: None,
        };
        fields(&mut rec);
        validate_record(&rec, self.seq as usize + 1)?;
        let mut line = serde_json::to_vec(&rec)
            .map_err(|e| Error::Invalid(format!("journal record serialization: {e}")))?;
        line.push(b'\n');
        self.file
            .write_all(&line)
            .and_then(|_| self.file.sync_all())
            .map_err(|e| {
                Error::io(
                    format!("journal write/fsync {}", self.path.display()),
                    Some(e),
                )
            })?;
        // Chain hash covers the record bytes without the trailing newline
        // (readers iterate `lines()` which strips it).
        self.prev_hash = crate::digest(&line[..line.len() - 1]);
        self.seq += 1;
        Ok(())
    }
}

/// Read and parse all records, verifying the hash chain.
pub fn read_records(path: &Path) -> Result<Vec<ParsedRecord>> {
    let f = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|e| Error::io(format!("cannot open journal {}", path.display()), Some(e)))?;
    validate_journal_file(&f, path)?;
    let bytes = read_journal_bytes(&f, path)?;
    parse_records(&bytes)
}

fn validate_journal_file(file: &File, path: &Path) -> Result<()> {
    let metadata = file
        .metadata()
        .map_err(|e| Error::io(format!("cannot stat journal {}", path.display()), Some(e)))?;
    if !metadata.file_type().is_file() {
        return Err(Error::Invalid(format!(
            "journal {} is not a regular file",
            path.display()
        )));
    }
    if metadata.uid() != nix_uid() {
        return Err(Error::Permission(format!(
            "journal {} is not owned by the current user",
            path.display()
        )));
    }
    if metadata.mode() & 0o022 != 0 {
        return Err(Error::Permission(format!(
            "journal {} is writable by another user",
            path.display()
        )));
    }
    Ok(())
}

fn read_journal_bytes(file: &File, path: &Path) -> Result<Vec<u8>> {
    let mut reader = file
        .try_clone()
        .map_err(|e| Error::io(format!("cannot clone journal {}", path.display()), Some(e)))?;
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| Error::io(format!("cannot seek journal {}", path.display()), Some(e)))?;
    let mut bytes = Vec::new();
    reader
        .take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| Error::io(format!("cannot read journal {}", path.display()), Some(e)))?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(Error::Invalid(format!(
            "journal {} exceeds the {} byte limit",
            path.display(),
            MAX_JOURNAL_BYTES
        )));
    }
    Ok(bytes)
}

fn parse_records(bytes: &[u8]) -> Result<Vec<ParsedRecord>> {
    // Ignore only a non-newline-terminated final fragment. Invalid data in a
    // committed (newline-terminated) record remains a hard integrity error.
    let committed_len = if bytes.last() == Some(&b'\n') {
        bytes.len()
    } else {
        bytes
            .iter()
            .rposition(|b| *b == b'\n')
            .map(|i| i + 1)
            .unwrap_or(0)
    };
    let content = std::str::from_utf8(&bytes[..committed_len])
        .map_err(|e| Error::Invalid(format!("journal is not valid UTF-8: {e}")))?;

    let mut out = Vec::new();
    let mut prev_hash = String::new();
    let mut started_actions = std::collections::HashSet::<(String, String)>::new();
    for (i, line) in content.lines().enumerate() {
        let line = line.to_string();
        let value: serde_json::Value = serde_json::from_str(&line)
            .map_err(|e| Error::Invalid(format!("journal line {}: {e}", i + 1)))?;
        let record: Record = serde_json::from_value(value.clone())
            .map_err(|e| Error::Invalid(format!("journal line {} contract: {e}", i + 1)))?;
        if record.seq != i as u64 {
            return Err(Error::Invalid(format!(
                "journal sequence mismatch at line {}: expected {}, got {}",
                i + 1,
                i,
                record.seq
            )));
        }
        if record.prev != prev_hash {
            return Err(Error::Invalid(format!(
                "journal hash chain broken at line {}",
                i + 1
            )));
        }
        validate_record(&record, i + 1)?;
        if record.state == "action-started" {
            started_actions.insert((
                record.plan_hash.clone().expect("validated plan hash"),
                record.action.clone().expect("validated action"),
            ));
        } else if record.state == "action-completed" {
            let key = (
                record.plan_hash.clone().expect("validated plan hash"),
                record.action.clone().expect("validated action"),
            );
            if !started_actions.remove(&key) {
                return Err(Error::Invalid(format!(
                    "journal line {} completes an action that was not started",
                    i + 1
                )));
            }
        }
        prev_hash = crate::digest(line.as_bytes());
        out.push(ParsedRecord { raw: line, value });
    }
    Ok(out)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 71
        && value.starts_with("sha256:")
        && value[7..].bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn valid_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn validate_record(record: &Record, line: usize) -> Result<()> {
    if (line == 1 && record.state != "locked") || (line > 1 && record.state == "locked") {
        return Err(Error::Invalid(format!(
            "journal line {line} must contain the one and only initial locked plan"
        )));
    }
    if !valid_token(&record.phase) || !valid_token(&record.state) {
        return Err(Error::Invalid(format!(
            "journal line {line} has an invalid phase or state"
        )));
    }
    if record.time.is_empty()
        || record.time.len() > 64
        || !record.time.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(Error::Invalid(format!(
            "journal line {line} has an invalid timestamp"
        )));
    }
    if record
        .plan_hash
        .as_deref()
        .is_some_and(|value| !valid_digest(value))
        || record
            .device
            .as_deref()
            .is_some_and(|value| !valid_digest(value))
    {
        return Err(Error::Invalid(format!(
            "journal line {line} has an invalid digest"
        )));
    }
    if record
        .action
        .as_deref()
        .is_some_and(|value| !valid_token(value))
    {
        return Err(Error::Invalid(format!(
            "journal line {line} has an invalid action"
        )));
    }
    if record
        .device_path
        .as_deref()
        .is_some_and(|value| value.is_empty() || value.len() > 4096 || value.contains('\0'))
        || record
            .message
            .as_deref()
            .is_some_and(|value| value.len() > 16 * 1024 || value.contains('\0'))
    {
        return Err(Error::Invalid(format!(
            "journal line {line} has an invalid path or message"
        )));
    }
    if record.plan.is_some() && !matches!(record.state.as_str(), "locked" | "fallback-plan") {
        return Err(Error::Invalid(format!(
            "journal line {line} embeds a plan outside a plan boundary"
        )));
    }
    match record.state.as_str() {
        "locked" => {
            if record.plan.is_none()
                || record.plan_hash.is_none()
                || record.device.is_none()
                || record.device_path.is_none()
            {
                return Err(Error::Invalid(format!(
                    "journal line {line} has an incomplete locked plan record"
                )));
            }
        }
        "fallback-plan" => {
            if record.plan.is_none() || record.plan_hash.is_none() {
                return Err(Error::Invalid(format!(
                    "journal line {line} has an incomplete fallback plan record"
                )));
            }
        }
        "action-started" => {
            if record.action.is_none() || record.plan_hash.is_none() {
                return Err(Error::Invalid(format!(
                    "journal line {line} has an incomplete action start"
                )));
            }
        }
        "action-completed" => {
            let valid_status = record.action_status.as_deref().is_some_and(|status| {
                matches!(
                    status,
                    "ok" | "error" | "failed" | "partial" | "found" | "skipped" | "fallback"
                )
            });
            if record.action.is_none()
                || record.plan_hash.is_none()
                || record.action_errors.is_none()
                || !valid_status
            {
                return Err(Error::Invalid(format!(
                    "journal line {line} has an incomplete action completion"
                )));
            }
        }
        "outputs-created" | "outputs-restarted"
            if record.plan_hash.is_none() || record.action_details.is_none() =>
        {
            return Err(Error::Invalid(format!(
                "journal line {line} has an incomplete salvage output binding"
            )));
        }
        _ => {}
    }
    Ok(())
}

/// Summary of a journal used by `resume`.
#[derive(Debug, Clone)]
pub struct JournalState {
    pub records: Vec<ParsedRecord>,
    pub plan: Option<serde_json::Value>,
    pub plan_hash: Option<String>,
    pub device_fingerprint: Option<String>,
    pub device_path: Option<String>,
    /// The fallback plan embedded by a `fallback-plan` record, if any.
    pub fallback_plan: Option<serde_json::Value>,
    /// Last action that completed successfully, if any.
    pub last_completed_action: Option<String>,
    /// Completed actions per plan hash: (plan_hash, action id).
    pub completed_by_plan: Vec<(String, String)>,
}

pub fn summarize(path: &Path) -> Result<JournalState> {
    let records = read_records(path)?;
    let mut plan = None;
    let mut plan_hash = None;
    let mut device_fingerprint = None;
    let mut device_path = None;
    let mut last_completed_action: Option<String> = None;
    let mut fallback_plan = None;
    let mut completed_by_plan: Vec<(String, String)> = Vec::new();

    for r in &records {
        let state = r.value.get("state").and_then(|value| value.as_str());
        if state == Some("locked") {
            let embedded = r
                .value
                .get("plan")
                .cloned()
                .ok_or_else(|| Error::Invalid("locked journal record has no plan".into()))?;
            if plan.replace(embedded).is_some() {
                return Err(Error::Invalid(
                    "journal contains more than one locked plan".into(),
                ));
            }
        }
        if let Some(v) = r.value.get("plan_hash") {
            plan_hash = v.as_str().map(|s| s.to_string());
        }
        if let Some(v) = r.value.get("device") {
            device_fingerprint = v.as_str().map(|s| s.to_string());
        }
        if let Some(v) = r.value.get("device_path") {
            device_path = v.as_str().map(|s| s.to_string());
        }
        if let Some(st) = r.value.get("state") {
            if st.as_str() == Some("fallback-plan") {
                if let Some(p) = r.value.get("plan") {
                    fallback_plan = Some(p.clone());
                }
            }
            if st.as_str() == Some("action-completed") {
                let a = r.value.get("action").and_then(|v| v.as_str());
                let h = r.value.get("plan_hash").and_then(|v| v.as_str());
                if let Some(a) = a {
                    last_completed_action = Some(a.to_string());
                    if let Some(h) = h {
                        completed_by_plan.push((h.to_string(), a.to_string()));
                    }
                }
            }
        }
    }
    Ok(JournalState {
        records,
        plan,
        plan_hash,
        device_fingerprint,
        device_path,
        fallback_plan,
        last_completed_action,
        completed_by_plan,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_refuses_corrupt_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.state");
        std::fs::write(&path, b"{\"broken\"\n").unwrap();
        let err = Journal::open(&path).unwrap_err();
        assert!(
            err.to_string().contains("journal"),
            "corrupt journal must fail with a journal error: {err}"
        );
    }

    #[test]
    fn journal_chain_and_resume() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.state");
        let plan_hash = format!("sha256:{}", "a".repeat(64));
        let device_hash = format!("sha256:{}", "d".repeat(64));
        let mut j = Journal::open(&path).unwrap();
        j.record("plan", "locked", |r| {
            r.plan_hash = Some(plan_hash.clone());
            r.device = Some(device_hash.clone());
            r.device_path = Some("/dev/example".into());
            r.plan = Some(serde_json::json!({ "id": "example" }));
        })
        .unwrap();
        j.record("inventory", "inventory-complete", |r| {
            r.device = Some(device_hash.clone());
            r.action = Some("inventory".into());
        })
        .unwrap();
        j.record("erase", "action-started", |r| {
            r.action = Some("lba-prbs-write".into());
            r.plan_hash = Some(plan_hash.clone());
        })
        .unwrap();
        // Simulate power loss: no further records.
        drop(j);

        let st = summarize(&path).unwrap();
        assert_eq!(st.records.len(), 3);
        assert_eq!(st.plan_hash.as_deref(), Some(plan_hash.as_str()));
        assert_eq!(st.device_fingerprint.as_deref(), Some(device_hash.as_str()));
        assert!(st.last_completed_action.is_none());

        // Appending continues the chain.
        let mut j = Journal::open(&path).unwrap();
        j.record("erase", "action-completed", |r| {
            r.action = Some("lba-prbs-write".into());
            r.plan_hash = Some(plan_hash.clone());
            r.action_status = Some("ok".into());
            r.action_errors = Some(0);
        })
        .unwrap();
        let st = summarize(&path).unwrap();
        assert_eq!(st.last_completed_action.as_deref(), Some("lba-prbs-write"));
        assert_eq!(st.records.len(), 4);
    }

    #[test]
    fn rfc3339_timestamp_format() {
        let t = utc_now_rfc3339();
        assert_eq!(t.len(), 20, "YYYY-MM-DDTHH:MM:SSZ");
        assert!(t.ends_with('Z'));
        assert_eq!(&t[4..5], "-");
        assert_eq!(&t[10..11], "T");
        // Leap year and epoch sanity (Hinnant conversion).
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(11016), (2000, 2, 29));
    }

    #[test]
    fn journal_tampering_detected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t2.state");
        let mut j = Journal::open(&path).unwrap();
        let plan_hash = format!("sha256:{}", "a".repeat(64));
        let device_hash = format!("sha256:{}", "d".repeat(64));
        j.record("plan", "locked", |record| {
            record.plan_hash = Some(plan_hash);
            record.device = Some(device_hash);
            record.device_path = Some("/dev/example".into());
            record.plan = Some(serde_json::json!({ "id": "example" }));
        })
        .unwrap();
        j.record("b", "s2", |_| {}).unwrap();
        drop(j);
        // Corrupt the second line.
        let mut content = std::fs::read_to_string(&path).unwrap();
        content.replace_range(
            content.find("\"state\":\"s2\"").unwrap()
                ..content.find("\"state\":\"s2\"").unwrap() + 13,
            "\"state\":\"sX\"",
        );
        std::fs::write(&path, content).unwrap();
        assert!(read_records(&path).is_err());
    }

    #[test]
    fn summary_keeps_the_original_plan_across_fallback() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fallback.state");
        let original_hash = format!("sha256:{}", "1".repeat(64));
        let fallback_hash = format!("sha256:{}", "2".repeat(64));
        let device_hash = format!("sha256:{}", "3".repeat(64));
        let mut journal = Journal::open(&path).unwrap();
        journal
            .record("plan", "locked", |record| {
                record.plan_hash = Some(original_hash);
                record.device = Some(device_hash);
                record.device_path = Some("/dev/example".into());
                record.plan = Some(serde_json::json!({ "id": "original" }));
            })
            .unwrap();
        journal
            .record("fallback", "fallback-plan", |record| {
                record.plan_hash = Some(fallback_hash);
                record.plan = Some(serde_json::json!({ "id": "fallback" }));
            })
            .unwrap();
        drop(journal);

        let summary = summarize(&path).unwrap();
        assert_eq!(summary.plan.unwrap()["id"], "original");
        assert_eq!(summary.fallback_plan.unwrap()["id"], "fallback");
    }

    #[test]
    fn unknown_record_fields_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unknown.state");
        std::fs::write(
            &path,
            b"{\"seq\":0,\"prev\":\"\",\"time\":\"2026-01-01T00:00:00Z\",\"phase\":\"a\",\"state\":\"ready\",\"unknown\":true}\n",
        )
        .unwrap();
        assert!(read_records(&path).is_err());
    }

    #[test]
    fn torn_final_record_is_ignored_and_truncated_on_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("torn.state");
        let mut journal = Journal::open(&path).unwrap();
        let plan_hash = format!("sha256:{}", "a".repeat(64));
        let device_hash = format!("sha256:{}", "d".repeat(64));
        journal
            .record("plan", "locked", |record| {
                record.plan_hash = Some(plan_hash);
                record.device = Some(device_hash);
                record.device_path = Some("/dev/example".into());
                record.plan = Some(serde_json::json!({ "id": "example" }));
            })
            .unwrap();
        drop(journal);

        let committed_len = std::fs::metadata(&path).unwrap().len();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"seq\":1,\"prev\":\"sha256:").unwrap();
        drop(file);

        let records = read_records(&path).unwrap();
        assert_eq!(records.len(), 1);

        let mut journal = Journal::open(&path).unwrap();
        assert_eq!(std::fs::metadata(&path).unwrap().len(), committed_len);
        journal.record("b", "committed", |_| {}).unwrap();
        drop(journal);
        assert_eq!(read_records(&path).unwrap().len(), 2);
    }

    #[test]
    fn a_new_run_cannot_append_a_second_locked_plan() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("reused.state");
        let plan_hash = format!("sha256:{}", "a".repeat(64));
        let device_hash = format!("sha256:{}", "d".repeat(64));
        let mut journal = Journal::open(&path).unwrap();
        journal
            .record("plan", "locked", |record| {
                record.plan_hash = Some(plan_hash.clone());
                record.device = Some(device_hash.clone());
                record.device_path = Some("/dev/example".into());
                record.plan = Some(serde_json::json!({ "id": "original" }));
            })
            .unwrap();
        let error = journal
            .record("plan", "locked", |record| {
                record.plan_hash = Some(plan_hash);
                record.device = Some(device_hash);
                record.device_path = Some("/dev/example".into());
                record.plan = Some(serde_json::json!({ "id": "replacement" }));
            })
            .unwrap_err();
        assert!(error.to_string().contains("one and only"));
    }

    #[test]
    fn journal_symlinks_and_shared_writers_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.state");
        let link = dir.path().join("link.state");
        std::fs::write(&target, b"").unwrap();
        symlink(&target, &link).unwrap();
        assert!(Journal::open(&link).is_err());
        assert!(read_records(&link).is_err());

        let mut permissions = std::fs::metadata(&target).unwrap().permissions();
        permissions.set_mode(0o666);
        std::fs::set_permissions(&target, permissions).unwrap();
        assert!(Journal::open(&target).is_err());
    }
}
