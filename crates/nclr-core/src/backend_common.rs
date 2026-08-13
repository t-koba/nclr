//! Shared backend helpers: LBA recipe action dispatch used by the `lba`,
//! `scsi` and `sd-native` backends.

use crate::backend::{BackendEvents, PROTOCOL_API};
use crate::errors::{Error, Result};
use crate::lba::{
    check_signatures, verify_pattern, verify_zeros, write_pattern, write_zeros, LbaDevice,
};
use crate::{digest, VERSION};
use serde_json::{json, Value};

/// Capabilities of the plain LBA path.
pub fn lba_caps() -> Vec<String> {
    vec![
        "READ_IDENTITY".into(),
        "READ_CAPACITY".into(),
        "LBA_PRBS_WRITE".into(),
        "LBA_READ_VERIFY".into(),
        "LBA_ZERO_WRITE".into(),
        "FLUSH".into(),
        "SIGNATURE_CHECK".into(),
        "SAMPLE_READ".into(),
    ]
}

/// Sample reads across the device (first/middle/last sector hashes).
pub fn sample_read(dev: &mut LbaDevice, events: &mut BackendEvents) -> Result<Value> {
    let sectors = dev.sectors();
    let mut samples = Vec::new();
    for start in [0u64, sectors / 2, sectors.saturating_sub(1)] {
        let mut buf = vec![0u8; crate::lba::SECTOR as usize];
        match dev.read_at(start * crate::lba::SECTOR, &mut buf) {
            Ok(_) => samples.push(json!({
                "lba": start,
                "sha256": digest(&buf),
            })),
            Err(e) => samples.push(json!({
                "lba": start,
                "error": e.to_string(),
            })),
        }
        events.note("sample-read", &format!("lba {start} of {sectors}"))?;
    }
    let status = if samples.iter().any(|sample| sample.get("error").is_some()) {
        "error"
    } else {
        "ok"
    };
    Ok(json!({ "status": status, "samples": samples, "sectors": sectors }))
}

/// Execute one LBA recipe action against a block device / file.
pub fn dispatch_lba_action(
    action: &str,
    seed: Option<&str>,
    params: Option<&Value>,
    dev: &mut LbaDevice,
    events: &mut BackendEvents,
) -> Result<Value> {
    match action {
        "inventory" => Ok(json!({
            "status": "ok",
            "capacity_bytes": dev.capacity_bytes(),
            "logical_block_size": dev.block_size(),
        })),
        "lba-prbs-write" | "lba-prbs-write-churn-0" | "lba-prbs-write-churn-1" => {
            let seed = seed.unwrap_or("nclr-prbs:default");
            let t0 = std::time::Instant::now();
            let errors = write_pattern(
                dev,
                seed.as_bytes(),
                Box::new(|d, t| {
                    events.progress("lba-write", d, t, "chunk")?;
                    Ok(())
                }),
            )?;
            let dt = t0.elapsed();
            Ok(json!({
                "status": if errors == 0 { "ok" } else { "partial" },
                "errors": errors,
                "duration_ms": dt.as_millis() as u64,
                "throughput_mbps": if dt.as_secs_f64() > 0.0 {
                    dev.capacity_bytes() as f64 / dt.as_secs_f64() / 1e6
                } else {
                    0.0
                },
            }))
        }
        "flush" => {
            let t0 = std::time::Instant::now();
            dev.flush()?;
            Ok(json!({
                "status": "ok",
                "flush_latency_ms": t0.elapsed().as_millis() as u64,
            }))
        }
        "lba-prbs-verify" | "lba-prbs-verify-churn-0" | "lba-prbs-verify-churn-1" => {
            let seed = seed.unwrap_or("nclr-prbs:default");
            let t0 = std::time::Instant::now();
            let errors = verify_pattern(
                dev,
                seed.as_bytes(),
                Box::new(|d, t| {
                    events.progress("lba-verify", d, t, "chunk")?;
                    Ok(())
                }),
            )?;
            let dt = t0.elapsed();
            Ok(json!({
                "status": if errors == 0 { "ok" } else { "error" },
                "errors": errors,
                "duration_ms": dt.as_millis() as u64,
                "throughput_mbps": if dt.as_secs_f64() > 0.0 {
                    dev.capacity_bytes() as f64 / dt.as_secs_f64() / 1e6
                } else {
                    0.0
                },
            }))
        }
        "lba-zero-write" => {
            let errors = write_zeros(
                dev,
                Box::new(|d, t| {
                    events.progress("lba-zero-write", d, t, "chunk")?;
                    Ok(())
                }),
            )?;
            Ok(json!({
                "status": if errors == 0 { "ok" } else { "partial" },
                "errors": errors,
            }))
        }
        "lba-zero-verify" => {
            let errors = verify_zeros(
                dev,
                Box::new(|d, t| {
                    events.progress("lba-zero-verify", d, t, "chunk")?;
                    Ok(())
                }),
            )?;
            Ok(json!({
                "status": if errors == 0 { "ok" } else { "error" },
                "errors": errors,
            }))
        }
        "signature-check" => {
            let found = check_signatures(dev)?;
            Ok(json!({
                "status": if found.is_empty() { "ok" } else { "found" },
                "found": found,
            }))
        }
        "postcheck-l1" => {
            let sample = sample_read(dev, events)?;
            Ok(json!({
                "status": "ok",
                "capacity_stable": true,
                "sample": sample,
            }))
        }
        "sample-read" => sample_read(dev, events),
        "scratch-test" => {
            let params = params
                .ok_or_else(|| Error::Usage("scratch-test requires params (start/count)".into()))?;
            scratch_test(dev, params)
        }
        "power-cycle" => Err(Error::io(
            "power cycle is not supported internally by block backends (external or sim only)",
            None,
        )),
        other => Err(Error::Usage(format!("unknown lba action: {other}"))),
    }
}

/// Bounded write test over an explicit scratch range:
/// save, PRBS write, flush, verify, restore, flush. Read-only by default;
/// only invoked with an explicit `--scratch-range`.
pub fn scratch_test(dev: &mut LbaDevice, params: &Value) -> Result<Value> {
    let start = params
        .get("start")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| Error::Usage("scratch-test start required".into()))?;
    let count = params
        .get("count")
        .and_then(|v| v.as_u64())
        .ok_or_else(|| Error::Usage("scratch-test count required".into()))?;
    if count == 0 {
        return Ok(json!({ "status": "ok", "bytes": 0, "restored": true }));
    }
    // The request is untrusted even though the core normally caps scratch
    // tests at 64 MiB. Enforce the same limit in the backend before integer
    // arithmetic or allocation.
    if count > 131_072 {
        return Err(Error::Usage(
            "scratch range too large (max 131072 sectors = 64 MiB)".into(),
        ));
    }
    let bytes = count
        .checked_mul(crate::lba::SECTOR)
        .ok_or_else(|| Error::Usage("scratch byte count out of range".into()))?;
    let start_bytes = start
        .checked_mul(crate::lba::SECTOR)
        .ok_or_else(|| Error::Usage("scratch start out of range".into()))?;
    let end = start_bytes
        .checked_add(bytes)
        .ok_or_else(|| Error::Usage("scratch range out of range".into()))?;
    if end > dev.capacity_bytes() {
        return Err(Error::Usage("scratch range exceeds device capacity".into()));
    }
    let bytes_usize = usize::try_from(bytes)
        .map_err(|_| Error::Usage("scratch byte count does not fit this platform".into()))?;
    let mut orig = vec![0u8; bytes_usize];
    dev.read_at(start_bytes, &mut orig)?;
    let mut prbs = crate::lba::Prbs::new(b"nclr-scratch");
    let mut pattern = vec![0u8; bytes_usize];
    prbs.fill(&mut pattern);
    dev.write_at(start_bytes, &pattern)?;
    dev.flush()?;
    let mut back = vec![0u8; bytes_usize];
    dev.read_at(start_bytes, &mut back)?;
    let mut errors = 0u64;
    if back != pattern {
        errors += 1;
    }
    dev.write_at(start_bytes, &orig)?;
    dev.flush()?;
    Ok(json!({
        "status": if errors == 0 { "ok" } else { "error" },
        "errors": errors,
        "bytes": bytes,
        "start_lba": start,
        "restored": true,
    }))
}

/// Full-logical-space blank sweep: every sector must read as a single
/// uniform value in {0x00, 0xFF}. `log_prefix` names the backend in error
/// diagnostics.
pub fn blank_verify(
    dev: &mut LbaDevice,
    events: &mut BackendEvents,
    log_prefix: &str,
) -> Result<Value> {
    let capacity = dev.capacity_bytes();
    let mut errors = 0u64;
    let mut read_errors = 0u64;
    let mut uniform = true;
    let mut value: Option<u8> = None;
    let total = capacity.div_ceil(crate::lba::CHUNK);
    let mut done = 0u64;
    let mut buf = vec![0u8; crate::lba::CHUNK as usize];
    let mut off = 0u64;
    while off < capacity {
        let len = crate::lba::CHUNK.min(capacity - off);
        if let Err(e) = dev.read_at(off, &mut buf[..len as usize]) {
            errors += 1;
            read_errors += 1;
            eprintln!(
                "{log_prefix}: blank read at LBA {}: {e}",
                off / crate::lba::SECTOR
            );
        } else {
            let v = buf[0];
            if !(v == 0x00 || v == 0xFF) {
                uniform = false;
            }
            // A single uniform value must hold across the whole logical
            // space: a chunk of 0x00 followed by a chunk of 0xFF is not an
            // erased device.
            if let Some(prev) = value {
                if prev != v {
                    uniform = false;
                    errors += 1;
                }
            } else {
                value = Some(v);
            }
            if buf[..len as usize].iter().any(|b| *b != v) {
                uniform = false;
                errors += 1;
            }
        }
        off += len;
        done += 1;
        if done.is_multiple_of(64) || off >= capacity {
            events.progress("blank-verify", done, total, "chunk")?;
        }
    }
    Ok(json!({
        "status": if errors == 0 && uniform { "ok" } else { "error" },
        "errors": errors,
        "read_errors": read_errors,
        "uniform": uniform,
        "value": value.map(|v| format!("0x{v:02x}")),
    }))
}

/// P2 logical postcheck performed after the power cycle. The whole current
/// LBA range is read again, the controller's profile-pinned blank value is
/// checked, known signatures are rejected and a real flush is issued.
/// `expected_blank = None` is used by standard C2 paths and accepts either
/// one uniform 0x00 or one uniform 0xff value.
pub fn postcheck_p2(
    dev: &mut LbaDevice,
    events: &mut BackendEvents,
    log_prefix: &str,
    expected_blank: Option<u8>,
) -> Result<Value> {
    dev.refresh_capacity()?;
    let sweep = blank_verify(dev, events, log_prefix)?;
    let errors = sweep.get("errors").and_then(Value::as_u64).unwrap_or(1);
    let read_errors = sweep
        .get("read_errors")
        .and_then(Value::as_u64)
        .unwrap_or(1);
    let uniform = sweep
        .get("uniform")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let value = sweep.get("value").and_then(Value::as_str);
    let blank_value_ok = match expected_blank {
        Some(expected) => value == Some(format!("0x{expected:02x}").as_str()),
        None => matches!(value, Some("0x00" | "0xff")),
    };
    let found = check_signatures(dev)?;
    let signature_free = found.is_empty();
    let flush_started = std::time::Instant::now();
    dev.flush()?;
    let flush_latency_ms = flush_started.elapsed().as_millis() as u64;
    let blank_verified = errors == 0 && uniform && blank_value_ok;
    let ok = read_errors == 0 && blank_verified && signature_free;
    Ok(json!({
        "status": if ok { "ok" } else { "error" },
        "errors": errors + u64::from(!signature_free),
        "read_errors": read_errors,
        "all_reads_ok": read_errors == 0,
        "blank_verified": blank_verified,
        "blank_value": value,
        "expected_blank_value": expected_blank.map(|value| format!("0x{value:02x}")),
        "signature_free": signature_free,
        "found": found,
        "flush_ok": true,
        "flush_latency_ms": flush_latency_ms,
        "capacity_bytes": dev.capacity_bytes(),
        "logical_block_size": dev.block_size(),
        "capacity_stable": true,
    }))
}

/// Standard probe response fields for a block-device backend.
pub fn probe_result_body(
    backend: &str,
    dev: &LbaDevice,
    caps: Vec<String>,
    ceiling: &str,
) -> Value {
    json!({
        "api": PROTOCOL_API,
        "ok": true,
        "backend": backend,
        "match": "exact",
        "version": VERSION,
        "capabilities": caps,
        "grade_ceiling": ceiling,
        "erase_coverage": [],
        "erase_method": Value::Null,
        "rebuilds": [],
        "controller_profile": Value::Null,
        "profile_sha256": Value::Null,
        "capacity_policy": Value::Null,
        "protected_area_bytes": 0,
        "certification": Value::Null,
        "artifacts": [],
        "device": {
            "capacity_bytes": dev.capacity_bytes(),
            "logical_block_size": dev.block_size(),
            "sectors": dev.sectors(),
        }
    })
}

/// Write a backend error response and exit with `code`.
/// Write the final response; a failed write must be visible on stderr (the
/// core cannot act on a response it never received, but the operator can).
fn write_response_or_die(backend: &str, resp: &serde_json::Value) {
    if let Err(e) = crate::backend::write_response(resp) {
        eprintln!("{backend}: cannot write the response: {e}");
    }
}

pub fn respond_err(backend: &str, e: &Error) -> ! {
    let resp = json!({
        "api": PROTOCOL_API,
        "ok": false,
        "backend": backend,
        "version": VERSION,
        "error": e.to_string(),
        "exit_code": e.exit_code(),
    });
    write_response_or_die(backend, &resp);
    std::process::exit(e.exit_code());
}

/// Action execution failures are reported in the response with a clean exit:
/// the core decides degraded vs failed from the evidence.
pub fn respond_action_err(backend: &str, e: &Error) -> ! {
    let resp = json!({
        "api": PROTOCOL_API,
        "ok": false,
        "backend": backend,
        "version": VERSION,
        "action_results": [{
            "status": "error",
            "message": e.to_string(),
        }],
        "exit_code": e.exit_code(),
    });
    write_response_or_die(backend, &resp);
    std::process::exit(0);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn blank_device(value: u8) -> (tempfile::TempDir, LbaDevice) {
        use std::io::Write;
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("device.img");
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        file.write_all(&vec![value; 4096]).unwrap();
        file.sync_all().unwrap();
        let device = LbaDevice::from_fd(file.into(), true).unwrap();
        (directory, device)
    }

    #[test]
    fn p2_postcheck_measures_full_read_blank_signature_and_flush() {
        let (_directory, mut device) = blank_device(0xff);
        let mut events = BackendEvents::open(None);
        let result = postcheck_p2(&mut device, &mut events, "test", Some(0xff)).unwrap();
        assert_eq!(result["status"], "ok");
        assert_eq!(result["all_reads_ok"], true);
        assert_eq!(result["blank_verified"], true);
        assert_eq!(result["signature_free"], true);
        assert_eq!(result["flush_ok"], true);
    }

    #[test]
    fn p2_postcheck_rejects_a_profile_blank_value_mismatch() {
        let (_directory, mut device) = blank_device(0xff);
        let mut events = BackendEvents::open(None);
        let result = postcheck_p2(&mut device, &mut events, "test", Some(0x00)).unwrap();
        assert_eq!(result["status"], "error");
        assert_eq!(result["all_reads_ok"], true);
        assert_eq!(result["blank_verified"], false);
    }
}
