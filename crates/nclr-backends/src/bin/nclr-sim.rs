#![recursion_limit = "256"]

//! Sim backend: executes the L1 recipe, device
//! erase and controller reinitialization actions against the virtual NAND
//! model (crates/nclr-core/src/sim.rs). Power cycle is internal.

use nclr::backend::{BackendEvents, FD_DEVICE, PROTOCOL_API};
use nclr::backend_common;
use nclr::errors::{Error, Result};
use nclr::lba::{Prbs, SECTOR};
use nclr::sim::SimDevice;
use nclr::{digest, VERSION};
use serde_json::{json, Value};
use sha2::Digest;
use std::os::fd::FromRawFd;

/// Embedded, digest-protected reference profile for the sim controller
/// family. A single source file is used by development, packaging and the
/// fallback so their trust metadata cannot drift.
const EMBEDDED_SIM_PROFILE: &str = include_str!("../../../../profiles/sim-controller-1.toml");

fn embedded_sim_profile() -> nclr::profile::Profile {
    let mut profile = toml::from_str::<nclr::profile::Profile>(EMBEDDED_SIM_PROFILE)
        .expect("embedded sim profile must parse");
    profile.sha256 = Some(nclr::profile::source_digest(EMBEDDED_SIM_PROFILE));
    profile
}

/// The sim controller profile, validated by exact match against the device
/// identity. The embedded reference is used only when no profile file is
/// installed. A present but invalid profile disables destructive controller
/// capabilities instead of being hidden by a fallback.
fn sim_profile(dev: &SimDevice) -> nclr::profile::Profile {
    let dirs = nclr::profile::search_dirs(&[]);
    let configured = dirs
        .iter()
        .map(|dir| dir.join("sim-controller-1.toml"))
        .find(|path| path.is_file());
    let mut p = match configured {
        Some(path) => match nclr::profile::load(&path) {
            Ok(profile)
                if profile.sha256.as_deref()
                    == Some(nclr::profile::source_digest(EMBEDDED_SIM_PROFILE).as_str()) =>
            {
                profile
            }
            Ok(mut profile) => {
                eprintln!(
                    "nclr-sim: warning: configured profile {} is not the shipped digest; destructive controller operations are disabled",
                    path.display()
                );
                profile.trust = "research".into();
                profile
            }
            Err(e) => {
                eprintln!(
                    "nclr-sim: warning: configured profile {} is invalid ({e}); destructive controller operations are disabled",
                    path.display()
                );
                let mut profile = embedded_sim_profile();
                profile.trust = "research".into();
                profile
            }
        },
        None => embedded_sim_profile(),
    };
    if !p.matches(dev.controller_id(), dev.firmware(), dev.nand_id()) {
        // Exact match failed: build a research-state placeholder so that
        // destructive controller operations are refused. The downgrade is
        // announced: a silent trust change would hide the misconfiguration.
        eprintln!(
            "nclr-sim: warning: no exact profile match for controller {} fw {} nand {}; degrading to research (destructive controller operations refused)",
            dev.controller_id(),
            dev.firmware(),
            dev.nand_id()
        );
        p.trust = "research".into();
    }
    p
}

fn caps(dev: &SimDevice, profile: &nclr::profile::Profile) -> Vec<String> {
    let mut v = vec![
        "READ_IDENTITY".into(),
        "READ_CAPACITY".into(),
        "LBA_PRBS_WRITE".into(),
        "LBA_READ_VERIFY".into(),
        "LBA_ZERO_WRITE".into(),
        "FLUSH".into(),
        "SIGNATURE_CHECK".into(),
        "SAMPLE_READ".into(),
        "POWER_CYCLE_INTERNAL".into(),
    ];
    if dev.sanitize_available() {
        v.push("ERASE_USER_AREA".into());
    }
    if dev.controller_available() && profile.destructive_allowed() {
        v.push("CONTROLLER_REINITIALIZE".into());
        v.push("PHYSICAL_SALVAGE".into());
    }
    if dev.controller_available()
        && profile.destructive_allowed()
        && std::env::var("NCLR_SIM_NO_PHYSICAL").as_deref() != Ok("1")
    {
        v.push("PHYSICAL_SCOPE".into());
    }
    if profile.sd_vendor.read_only_health {
        v.push("SD_VENDOR_HEALTH".into());
    }
    v
}

/// The documented device-erase scope for the sim model: the device-level
/// erase clears the user area, the spare/OP pool and the obsolete region
/// (D0 + D1 + D2); FBB and system areas are preserved.
fn erase_coverage() -> Vec<String> {
    vec!["D0".into(), "D1".into(), "D2".into()]
}

/// Read data of `len` bytes at LBA offset `off` from the sim model.
fn sim_read(dev: &mut SimDevice, off: u64, len: usize, buf: &mut [u8]) -> Result<()> {
    let page = dev.info().page_bytes as u64;
    let mut n = 0usize;
    while n < len {
        let chunk = ((len - n) as u64).min(page) as usize;
        dev.read_lba(off + n as u64, &mut buf[n..n + chunk])?;
        n += chunk;
    }
    Ok(())
}

/// Write `len` bytes at LBA offset `off` into the sim model.
fn sim_write(dev: &mut SimDevice, off: u64, data: &[u8]) -> Result<()> {
    let page = dev.info().page_bytes as u64;
    let mut n = 0usize;
    while n < data.len() {
        let chunk = ((data.len() - n) as u64).min(page) as usize;
        dev.write_lba(off + n as u64, &data[n..n + chunk])?;
        n += chunk;
    }
    Ok(())
}

fn write_pattern(dev: &mut SimDevice, seed: &[u8], events: &mut BackendEvents) -> Result<u64> {
    let capacity = dev.capacity_bytes();
    let mut errors = 0u64;
    let mut prbs = Prbs::new(seed);
    let total = capacity.div_ceil(SECTOR);
    let mut done = 0u64;
    let mut buf = vec![0u8; SECTOR as usize];
    let mut off = 0u64;
    while off < capacity {
        prbs.fill(&mut buf);
        if let Err(e) = sim_write(dev, off, &buf) {
            errors += 1;
            eprintln!("nclr-sim: write at LBA {}: {e}", off / SECTOR);
        }
        off += SECTOR;
        done += 1;
        if done.is_multiple_of(256) || off >= capacity {
            events.progress("lba-write", done, total, "sector")?;
        }
    }
    dev.flush()?;
    Ok(errors)
}

fn verify_pattern(dev: &mut SimDevice, seed: &[u8], events: &mut BackendEvents) -> Result<u64> {
    let capacity = dev.capacity_bytes();
    let mut errors = 0u64;
    let mut prbs = Prbs::new(seed);
    let total = capacity.div_ceil(SECTOR);
    let mut done = 0u64;
    let mut buf = vec![0u8; SECTOR as usize];
    let mut expected = vec![0u8; SECTOR as usize];
    let mut off = 0u64;
    while off < capacity {
        prbs.fill(&mut expected);
        if let Err(e) = sim_read(dev, off, SECTOR as usize, &mut buf) {
            errors += 1;
            eprintln!("nclr-sim: read at LBA {}: {e}", off / SECTOR);
        } else if buf != expected {
            errors += 1;
        }
        off += SECTOR;
        done += 1;
        if done.is_multiple_of(256) || off >= capacity {
            events.progress("lba-verify", done, total, "sector")?;
        }
    }
    Ok(errors)
}

fn write_zeros(dev: &mut SimDevice, events: &mut BackendEvents) -> Result<u64> {
    let capacity = dev.capacity_bytes();
    let mut errors = 0u64;
    let total = capacity.div_ceil(SECTOR);
    let mut done = 0u64;
    let buf = vec![0u8; SECTOR as usize];
    let mut off = 0u64;
    while off < capacity {
        if let Err(e) = sim_write(dev, off, &buf) {
            errors += 1;
            eprintln!("nclr-sim: zero write at LBA {}: {e}", off / SECTOR);
        }
        off += SECTOR;
        done += 1;
        if done.is_multiple_of(256) || off >= capacity {
            events.progress("lba-zero-write", done, total, "sector")?;
        }
    }
    dev.flush()?;
    Ok(errors)
}

fn verify_zeros(dev: &mut SimDevice, events: &mut BackendEvents) -> Result<u64> {
    let capacity = dev.capacity_bytes();
    let mut errors = 0u64;
    let total = capacity.div_ceil(SECTOR);
    let mut done = 0u64;
    let mut buf = vec![0u8; SECTOR as usize];
    let mut off = 0u64;
    while off < capacity {
        if let Err(e) = sim_read(dev, off, SECTOR as usize, &mut buf) {
            errors += 1;
            eprintln!("nclr-sim: zero read at LBA {}: {e}", off / SECTOR);
        } else if buf.iter().any(|b| *b != 0) {
            errors += 1;
        }
        off += SECTOR;
        done += 1;
        if done.is_multiple_of(256) || off >= capacity {
            events.progress("lba-zero-verify", done, total, "sector")?;
        }
    }
    Ok(errors)
}

fn signature_check(dev: &mut SimDevice) -> Result<Vec<String>> {
    let sectors = dev.capacity_bytes() / SECTOR;
    let mut found = Vec::new();
    for (start, count) in nclr::lba::signature_check_regions(sectors) {
        let mut buf = vec![0u8; (count as usize) * SECTOR as usize];
        sim_read(dev, start * SECTOR, buf.len(), &mut buf)?;
        found.extend(nclr::lba::detect_signatures(&buf));
    }
    found.sort();
    found.dedup();
    Ok(found)
}

fn sample_read(dev: &mut SimDevice, events: &mut BackendEvents) -> Result<serde_json::Value> {
    let sectors = dev.capacity_bytes() / SECTOR;
    let mut samples = Vec::new();
    for start in [0u64, sectors / 2, sectors.saturating_sub(1)] {
        let mut buf = vec![0u8; SECTOR as usize];
        match sim_read(dev, start * SECTOR, SECTOR as usize, &mut buf) {
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

/// Full logical blank sweep used both before and after the power cycle.
fn blank_verify(dev: &mut SimDevice, events: &mut BackendEvents) -> Result<serde_json::Value> {
    let capacity = dev.capacity_bytes();
    let mut errors = 0u64;
    let mut read_errors = 0u64;
    let mut uniform = true;
    let mut value: Option<u8> = None;
    let total = capacity.div_ceil(SECTOR);
    let mut done = 0u64;
    let mut buf = vec![0u8; SECTOR as usize];
    let mut off = 0u64;
    while off < capacity {
        if let Err(e) = sim_read(dev, off, SECTOR as usize, &mut buf) {
            errors += 1;
            read_errors += 1;
            eprintln!("nclr-sim: blank read at LBA {}: {e}", off / SECTOR);
        } else {
            let current = buf[0];
            if !(current == 0x00 || current == nclr::sim::BLANK_VALUE) {
                uniform = false;
            }
            if let Some(previous) = value {
                if previous != current {
                    uniform = false;
                    errors += 1;
                }
            } else {
                value = Some(current);
            }
            if buf.iter().any(|byte| *byte != current) {
                uniform = false;
                errors += 1;
            }
        }
        off += SECTOR;
        done += 1;
        if done.is_multiple_of(256) || off >= capacity {
            events.progress("blank-verify", done, total, "sector")?;
        }
    }
    Ok(json!({
        "status": if errors == 0 && uniform { "ok" } else { "error" },
        "errors": errors,
        "read_errors": read_errors,
        "uniform": uniform,
        "value": value.map(|value| format!("0x{value:02x}")),
    }))
}

/// Full P2 logical postcheck after the simulated power cycle.
fn postcheck_p2(
    dev: &mut SimDevice,
    events: &mut BackendEvents,
    expected_blank: u8,
) -> Result<serde_json::Value> {
    dev.refresh_capacity()?;
    let sweep = blank_verify(dev, events)?;
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
    let expected = format!("0x{expected_blank:02x}");
    let blank_verified = errors == 0 && uniform && value == Some(expected.as_str());
    let found = signature_check(dev)?;
    let signature_free = found.is_empty();
    let flush_started = std::time::Instant::now();
    dev.flush()?;
    let flush_latency_ms = flush_started.elapsed().as_millis() as u64;
    let ok = read_errors == 0 && blank_verified && signature_free;
    Ok(json!({
        "status": if ok { "ok" } else { "error" },
        "errors": errors + u64::from(!signature_free),
        "read_errors": read_errors,
        "all_reads_ok": read_errors == 0,
        "blank_verified": blank_verified,
        "blank_value": value,
        "expected_blank_value": expected,
        "signature_free": signature_free,
        "found": found,
        "flush_ok": true,
        "flush_latency_ms": flush_latency_ms,
        "capacity_bytes": dev.capacity_bytes(),
        "logical_block_size": nclr::lba::SECTOR,
        "capacity_stable": true,
        "power_cycles": dev.power_cycles(),
    }))
}

/// Block-level evidence record (spec §1331): physical coordinates,
/// pre-classification state, FBB and historical RBB flags, ECC detail and,
/// when requested, the erase attempt with its verdict.
fn block_evidence(dev: &SimDevice, block: u32, erase: Option<bool>) -> Result<serde_json::Value> {
    let mut rec = dev.block_detail(block)?;
    let obj = rec
        .as_object_mut()
        .ok_or_else(|| Error::Invalid("block detail must be a JSON object".into()))?;
    if let Some(ok) = erase {
        obj.insert("erase_attempted".into(), json!(true));
        obj.insert(
            "erase_result".into(),
            json!(if ok { "erased" } else { "failed" }),
        );
        obj.insert("erased".into(), json!(ok));
    }
    Ok(rec)
}

fn dispatch(
    action: &str,
    seed: Option<&str>,
    params: Option<&serde_json::Value>,
    dev: &mut SimDevice,
    events: &mut BackendEvents,
    mut physical_image: Option<&mut std::fs::File>,
    mut physical_map: Option<&mut std::fs::File>,
) -> Result<serde_json::Value> {
    match action {
        "inventory" => Ok(json!({
            "status": "ok",
            "sim": dev.info(),
            "capacity_bytes": dev.capacity_bytes(),
            "power_cycles": dev.power_cycles(),
        })),
        "lba-prbs-write" | "lba-prbs-write-churn-0" | "lba-prbs-write-churn-1" => {
            let seed = seed.unwrap_or("nclr-prbs:default");
            let t0 = std::time::Instant::now();
            let errors = write_pattern(dev, seed.as_bytes(), events)?;
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
            let errors = verify_pattern(dev, seed.as_bytes(), events)?;
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
            let errors = write_zeros(dev, events)?;
            Ok(json!({
                "status": if errors == 0 { "ok" } else { "partial" },
                "errors": errors,
            }))
        }
        "lba-zero-verify" => {
            let errors = verify_zeros(dev, events)?;
            Ok(json!({
                "status": if errors == 0 { "ok" } else { "error" },
                "errors": errors,
            }))
        }
        "signature-check" => {
            let found = signature_check(dev)?;
            Ok(json!({
                "status": if found.is_empty() { "ok" } else { "found" },
                "found": found,
            }))
        }
        "power-cycle" => {
            dev.power_cycle()?;
            Ok(json!({
                "status": "ok",
                "power_cycles": dev.power_cycles(),
                "capacity_bytes": dev.capacity_bytes(),
            }))
        }
        "postcheck-l1" => {
            let sample = sample_read(dev, events)?;
            Ok(json!({
                "status": "ok",
                "capacity_stable": true,
                "power_cycles": dev.power_cycles(),
                "sample": sample,
            }))
        }
        "device-user-area-erase" => {
            // IMMED-style: start the self-running sanitize and return. The
            // completion check happens before restarting, since begin always
            // (re)starts the operation.
            let already = dev.sanitize_state() == nclr::sim::SANITIZE_COMPLETED;
            dev.begin_sanitize()?;
            Ok(json!({
                "status": "ok",
                "started": true,
                "already_completed": already,
                "progress": dev.sanitize_progress(),
                "sanitize_state": dev.sanitize_state(),
            }))
        }
        "blank-verify" => blank_verify(dev, events),
        "postcheck-p2" => {
            let mut result = postcheck_p2(dev, events, nclr::sim::BLANK_VALUE)?;
            // Physical sample outside the LBA window (OP/D2 region) must be
            // blank after a device erase.
            let mut phys = [0u8; 512];
            let d2_blank = if dev.blocks() > 0 {
                let last = dev.blocks() - 1;
                match dev.read_physical_page(last, 0, &mut phys) {
                    Ok(()) => phys.iter().all(|b| *b == nclr::sim::BLANK_VALUE),
                    Err(e) => {
                        // A failed physical read must not be silently
                        // reported as blank: surface the reason.
                        eprintln!("nclr-sim: physical sample read failed: {e}");
                        false
                    }
                }
            } else {
                false
            };
            let object = result
                .as_object_mut()
                .ok_or_else(|| Error::Invalid("sim postcheck result must be an object".into()))?;
            object.insert("sanitize_state".into(), json!(dev.sanitize_state()));
            object.insert("d2_blank".into(), json!(d2_blank));
            if !d2_blank {
                object.insert("status".into(), json!("error"));
                let errors = object.get("errors").and_then(Value::as_u64).unwrap_or(0);
                object.insert("errors".into(), json!(errors.saturating_add(1)));
            }
            Ok(result)
        }
        "sample-read" => sample_read(dev, events),
        "vendor-health" => {
            // Read-only SD vendor health query (CMD56-equivalent), gated by
            // the profile's sd_vendor declaration.
            if !sim_profile(dev).sd_vendor.read_only_health {
                return Err(Error::Permission(
                    "profile does not authorize the read-only vendor health query".into(),
                ));
            }
            Ok(json!({
                "status": "ok",
                "read_only": true,
                "health": {
                    "power_cycles": dev.power_cycles(),
                    "bbt_generation": dev.bbt_generation(),
                    "ftl_generation": dev.ftl_generation(),
                    "service_mode": dev.service_mode(),
                    "sanitize_state": dev.sanitize_state(),
                    "blocks": dev.blocks(),
                    "capacity_bytes": dev.capacity_bytes(),
                },
            }))
        }
        // --- Controller reinitialization (C3) -------------------------------
        "capture-old-bbt" => {
            let (generation, fbb, rbb) = dev.old_bbt();
            let old_bbt = serde_json::to_vec(&(generation, &fbb, &rbb))
                .map_err(|error| Error::Invalid(format!("serialize old BBT: {error}")))?;
            Ok(json!({
                "status": "ok",
                "generation": generation,
                "old_bbt_digest": hex::encode(sha2::Sha256::digest(&old_bbt)),
                "old_bbt_copies": 1,
                "fbb": fbb,
                "old_rbb": rbb,
                "old_rbb_count": rbb.len(),
                "fbb_count": fbb.len(),
            }))
        }
        "enter-service-mode" => {
            dev.enter_service_mode()?;
            Ok(json!({
                "status": "ok",
                "state": "in-service",
                "controller_id": dev.reported_controller_id(),
            }))
        }
        "erase-old-rbb" => {
            let results = dev.erase_old_rbb_all()?;
            let failed = results.iter().filter(|(_, ok)| !ok).count();
            let per_block: Vec<Value> = results
                .iter()
                .map(|(b, ok)| block_evidence(dev, *b, Some(*ok)))
                .collect::<Result<Vec<_>>>()?;
            Ok(json!({
                "status": if failed == 0 { "ok" } else { "partial" },
                "failed": failed as u64,
                "errors": failed as u64,
                "per_block": per_block,
            }))
        }
        "qualify-blocks" => {
            let seed = seed.unwrap_or("nclr-prbs:default");
            let (qualified, weak, failed) =
                dev.qualify_blocks(seed.as_bytes(), dev.ecc_strength(), dev.ecc_min_margin())?;
            Ok(json!({
                "status": "ok",
                "qualified": qualified.len() as u64,
                "weak": weak.len() as u64,
                "failed": failed.len() as u64,
                "weak_blocks": weak,
                "failed_blocks": failed,
            }))
        }
        "final-erase" => {
            let (_, fbb_before, _) = dev.old_bbt();
            let (erased, failed) = dev.final_erase()?;
            let (_, fbb_after, _) = dev.old_bbt();
            let fbb_preserved = fbb_before == fbb_after;
            // Per-block erase records (spec §1331: final erase result; the
            // core records each failure individually, §1187).
            let mut per_block: Vec<Value> = Vec::new();
            for b in &erased {
                per_block.push(block_evidence(dev, *b, Some(true))?);
            }
            for b in &failed {
                per_block.push(block_evidence(dev, *b, Some(false))?);
            }
            Ok(json!({
                "status": if failed.is_empty() && fbb_preserved { "ok" } else { "partial" },
                "erased": erased.len() as u64,
                "failed": failed.len() as u64,
                "errors": failed.len() as u64,
                "fbb_preserved": fbb_preserved,
                "per_block": per_block,
            }))
        }
        "rebuild-bbt-ftl" => {
            // The capacity policy comes from the plan's action params (the
            // core clamps spare_ratio with the site policy); the backend
            // never substitutes its own values.
            let policy = params
                .and_then(|p| p.get("capacity_policy"))
                .map(|v| nclr::profile::CapacityPolicy {
                    bin_bytes: v.get("bin_bytes").and_then(|x| x.as_u64()).unwrap_or(0),
                    minimum_spare_blocks: v
                        .get("minimum_spare_blocks")
                        .and_then(|x| x.as_u64())
                        .unwrap_or(4) as u32,
                    spare_ratio: v
                        .get("spare_ratio")
                        .and_then(|x| x.as_f64())
                        .unwrap_or(0.05),
                })
                .unwrap_or(nclr::profile::CapacityPolicy {
                    bin_bytes: 0,
                    minimum_spare_blocks: 4,
                    spare_ratio: 0.05,
                });
            let (user, spare, reduced) = dev.rebuild_bbt_ftl(&policy)?;
            Ok(json!({
                "status": "ok",
                "bbt_generation": dev.bbt_generation(),
                "ftl_generation": dev.ftl_generation(),
                "old_mapping_invalidated": true,
                "user_blocks": user,
                "spare_blocks": spare,
                "capacity_reduced": reduced,
                "capacity_bytes": dev.capacity_bytes(),
            }))
        }
        "exit-service-mode" => {
            dev.exit_service_mode()?;
            Ok(json!({
                "status": "ok",
                "state": "normal",
            }))
        }
        "re-enumeration" => {
            // Echo the run nonce so the core can prove the device came back
            // as the same media (service-mode re-enumeration tracking).
            let nonce = params
                .and_then(|p| p.get("nonce"))
                .and_then(|v| v.as_str())
                .unwrap_or("");
            Ok(json!({
                "status": "ok",
                "service_mode": dev.service_mode(),
                "controller_id": dev.reported_controller_id(),
                "capacity_bytes": dev.capacity_bytes(),
                "power_cycles": dev.power_cycles(),
                "nonce": nonce,
            }))
        }
        "postcheck-c3" => {
            let expected_blank = sim_profile(dev).logical_blank_value.ok_or_else(|| {
                Error::Invalid("sim controller profile has no logical blank value".into())
            })?;
            let mut result = postcheck_p2(dev, events, expected_blank)?;
            let (_, _, rbb) = dev.old_bbt();
            let in_service = dev.service_mode();
            let object = result
                .as_object_mut()
                .ok_or_else(|| Error::Invalid("sim postcheck result must be an object".into()))?;
            object.insert("spare_ok".into(), json!(dev.capacity_bytes() > 0));
            object.insert("service_mode".into(), json!(in_service));
            object.insert("bbt_generation".into(), json!(dev.bbt_generation()));
            object.insert("ftl_generation".into(), json!(dev.ftl_generation()));
            object.insert("old_rbb_quarantined".into(), json!(rbb.len()));
            if in_service {
                object.insert("status".into(), json!("error"));
                let errors = object.get("errors").and_then(Value::as_u64).unwrap_or(0);
                object.insert("errors".into(), json!(errors.saturating_add(1)));
            }
            Ok(result)
        }
        // --- Certified physical scope (C4) ---------------------------------
        "enumerate-blocks" => {
            let entries = dev.enumerate_blocks();
            let total = entries.len() as u64;
            let mut by_cat: std::collections::BTreeMap<&str, u64> = Default::default();
            let per_block: Vec<Value> = entries
                .iter()
                .map(|(b, c)| {
                    *by_cat.entry(c).or_default() += 1;
                    // Block-level evidence records (spec §1331): physical
                    // coordinates, pre-classification, FBB/historical RBB
                    // state, ECC and verdict detail.
                    let mut rec = block_evidence(dev, *b, None)?;
                    rec.as_object_mut()
                        .ok_or_else(|| Error::Invalid("block detail must be a JSON object".into()))?
                        .insert("category".into(), json!(c));
                    Ok(rec)
                })
                .collect::<Result<Vec<_>>>()?;
            let data_blocks = entries
                .iter()
                .filter(|(_, c)| !matches!(*c, "fbb" | "unknown" | "protected"))
                .count() as u64;
            Ok(json!({
                "status": "ok",
                "total": total,
                "data_blocks": data_blocks,
                "categories": by_cat,
                "unknown": by_cat.get("unknown").copied().unwrap_or(0),
                "per_block": per_block,
            }))
        }
        "erase-data-blocks" => {
            let results = dev.erase_all_data_blocks()?;
            let failed = results.iter().filter(|(_, ok)| !ok).count();
            let per_block: Vec<Value> = results
                .iter()
                .map(|(b, ok)| block_evidence(dev, *b, Some(*ok)))
                .collect::<Result<Vec<_>>>()?;
            Ok(json!({
                "status": if failed == 0 { "ok" } else { "partial" },
                "erased": (results.len() - failed) as u64,
                "failed": failed as u64,
                "errors": failed as u64,
                "per_block": per_block,
            }))
        }
        "verify-physical-erasure" | "salvage-physical" => {
            let salvage = action == "salvage-physical";
            if salvage && (physical_image.is_none() || physical_map.is_none()) {
                return Err(Error::Permission(
                    "salvage-physical requires physical-image and physical-map outputs".into(),
                ));
            }
            if !salvage && (physical_image.is_some() || physical_map.is_some()) {
                return Err(Error::Invalid(
                    "physical outputs are only valid for salvage-physical".into(),
                ));
            }
            let info = dev.info();
            let dispositions = dev
                .enumerate_blocks()
                .into_iter()
                .map(|(_, category)| match category {
                    "fbb" => nclr::physical::PhysicalDisposition::FactoryBad,
                    "old-rbb" => nclr::physical::PhysicalDisposition::HistoricalRuntimeBad,
                    "system" | "protected" => nclr::physical::PhysicalDisposition::SystemPreserved,
                    "unknown" => nclr::physical::PhysicalDisposition::Unknown,
                    "quarantined" => nclr::physical::PhysicalDisposition::Quarantined,
                    "erased" => nclr::physical::PhysicalDisposition::Erased,
                    _ => nclr::physical::PhysicalDisposition::Data,
                })
                .collect::<Vec<_>>();
            let summary = nclr::physical::sweep_physical_pages(
                nclr::physical::SweepGeometry {
                    blocks: u64::from(info.blocks),
                    channels: 1,
                    chips_per_channel: 1,
                    luns_per_chip: 1,
                    planes_per_lun: 1,
                    blocks_per_lun: info.blocks,
                    pages_per_block: info.pages_per_block,
                    page_bytes: info.page_bytes,
                    oob_bytes: 0,
                },
                &dispositions,
                nclr::sim::BLANK_VALUE,
                physical_image
                    .as_deref_mut()
                    .map(|writer| writer as &mut dyn nclr::physical::WriteSeek),
                physical_map
                    .as_deref_mut()
                    .map(|writer| writer as &mut dyn std::io::Write),
                |flat, page| {
                    let mut raw = vec![0u8; info.page_bytes as usize];
                    dev.read_physical_page(flat as u32, page, &mut raw)?;
                    Ok(nclr::physical::PageRead {
                        raw,
                        metrics: nclr::physical::PageMetrics {
                            ecc_status: nclr::physical::PageEccStatus::Correctable,
                            ..nclr::physical::PageMetrics::default()
                        },
                    })
                },
                |done, total| events.progress(action, done, total, "page"),
            )?;
            if let Some(output) = physical_image.as_mut() {
                output
                    .sync_all()
                    .map_err(|error| Error::io("sync physical image", Some(error)))?;
            }
            if let Some(output) = physical_map.as_mut() {
                output
                    .sync_all()
                    .map_err(|error| Error::io("sync physical page map", Some(error)))?;
            }
            let complete = if salvage {
                summary.all_addresses_readable && summary.all_pages_correctable
            } else {
                summary.erased_scope_verified
            };
            let block_summary = serde_json::to_vec(&summary.blocks).map_err(|error| {
                Error::Invalid(format!("serialize physical sweep block summary: {error}"))
            })?;
            let exception_count = summary
                .blocks
                .iter()
                .filter(|block| {
                    block.unreadable_pages > 0
                        || block.ecc_unknown_pages > 0
                        || block.uncorrectable_pages > 0
                        || (!salvage
                            && block.disposition.expected_erased()
                            && block.non_erased_pages > 0)
                })
                .count();
            let exception_blocks = summary
                .blocks
                .iter()
                .filter(|block| {
                    block.unreadable_pages > 0
                        || block.ecc_unknown_pages > 0
                        || block.uncorrectable_pages > 0
                        || (!salvage
                            && block.disposition.expected_erased()
                            && block.non_erased_pages > 0)
                })
                .take(256)
                .collect::<Vec<_>>();
            Ok(json!({
               "status": if complete { "ok" } else { "partial" },
               "errors": if complete { 0 } else if salvage {
                   summary.unreadable_pages
                       .saturating_add(summary.ecc_unknown_pages)
                       .saturating_add(summary.uncorrectable_pages)
               } else {
                   summary.target_unreadable_pages
                       .saturating_add(summary.target_ecc_unknown_pages)
                       .saturating_add(summary.target_uncorrectable_pages)
                       .saturating_add(summary.target_non_erased_pages)
               },
               "total_blocks": summary.total_blocks,
               "total_pages": summary.total_pages,
               "readable_pages": summary.readable_pages,
               "unreadable_pages": summary.unreadable_pages,
               "ecc_unknown_pages": summary.ecc_unknown_pages,
               "uncorrectable_pages": summary.uncorrectable_pages,
               "target_pages": summary.target_pages,
               "target_readable_pages": summary.target_readable_pages,
               "target_unreadable_pages": summary.target_unreadable_pages,
               "target_ecc_unknown_pages": summary.target_ecc_unknown_pages,
               "target_uncorrectable_pages": summary.target_uncorrectable_pages,
               "excluded_unreadable_pages": summary.excluded_unreadable_pages,
               "target_non_erased_pages": summary.target_non_erased_pages,
               "target_non_erased_bytes": summary.target_non_erased_bytes,
               "excluded_non_erased_pages": summary.excluded_non_erased_pages,
               "all_addresses_readable": summary.all_addresses_readable,
               "all_pages_ecc_known": summary.all_pages_ecc_known,
               "all_pages_correctable": summary.all_pages_correctable,
               "erased_scope_verified": summary.erased_scope_verified,
               "ordered_sweep_sha256": summary.ordered_sweep_sha256,
               "image_sha256": summary.image_sha256,
               "image_bytes": summary.image_bytes,
                "block_summary_sha256": hex::encode(sha2::Sha256::digest(&block_summary)),
                "exception_blocks": exception_blocks,
                "exception_block_count": exception_count,
                "exception_blocks_truncated": exception_count > 256,
                "per_block": summary
                    .blocks
                    .iter()
                    .map(|block| {
                        // Per-block page/OOB sweep summary (spec §1331).
                        json!({
                            "block": block.flat_block,
                            "physical_coordinate": {
                                "channel": block.channel,
                                "chip": block.chip,
                                "lun": block.lun,
                                "plane": block.plane,
                                "block": block.block,
                            },
                            "disposition": block.disposition,
                            "pages": block.pages,
                            "readable_pages": block.readable_pages,
                            "unreadable_pages": block.unreadable_pages,
                            "ecc_unknown_pages": block.ecc_unknown_pages,
                            "uncorrectable_pages": block.uncorrectable_pages,
                            "non_erased_pages": block.non_erased_pages,
                            "non_erased_bytes": block.non_erased_bytes,
                            "maximum_corrected_bits": block.maximum_corrected_bits,
                            "maximum_read_retries": block.maximum_read_retries,
                            "maximum_read_latency_ms": block.maximum_read_latency_ms,
                        })
                    })
                    .collect::<Vec<Value>>(),
            }))
        }
        "postcheck-c4" => {
            let expected_blank = sim_profile(dev).logical_blank_value.ok_or_else(|| {
                Error::Invalid("sim controller profile has no logical blank value".into())
            })?;
            let mut result = postcheck_p2(dev, events, expected_blank)?;
            let entries = dev.enumerate_blocks();
            let unknown = entries.iter().filter(|(_, c)| *c == "unknown").count() as u64;
            let in_service = dev.service_mode();
            let object = result
                .as_object_mut()
                .ok_or_else(|| Error::Invalid("sim postcheck result must be an object".into()))?;
            object.insert("spare_ok".into(), json!(dev.capacity_bytes() > 0));
            object.insert("service_mode".into(), json!(in_service));
            object.insert("unknown_reservation".into(), json!(unknown));
            object.insert("bbt_generation".into(), json!(dev.bbt_generation()));
            object.insert("ftl_generation".into(), json!(dev.ftl_generation()));
            if in_service {
                object.insert("status".into(), json!("error"));
                let errors = object.get("errors").and_then(Value::as_u64).unwrap_or(0);
                object.insert("errors".into(), json!(errors.saturating_add(1)));
            }
            Ok(result)
        }
        "scratch-test" => {
            let params = params
                .ok_or_else(|| Error::Usage("scratch-test requires params (start/count)".into()))?;
            let start = params
                .get("start")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| Error::Usage("scratch-test start required".into()))?;
            let count = params
                .get("count")
                .and_then(|v| v.as_u64())
                .ok_or_else(|| Error::Usage("scratch-test count required".into()))?;
            let bytes = count
                .checked_mul(SECTOR)
                .ok_or_else(|| Error::Usage("scratch count out of range".into()))?;
            let start_bytes = start
                .checked_mul(SECTOR)
                .ok_or_else(|| Error::Usage("scratch start out of range".into()))?;
            if start_bytes
                .checked_add(bytes)
                .map(|end| end > dev.capacity_bytes())
                .unwrap_or(true)
            {
                return Err(Error::Usage("scratch range exceeds device capacity".into()));
            }
            let mut orig = vec![0u8; bytes as usize];
            sim_read(dev, start * SECTOR, bytes as usize, &mut orig)?;
            let mut prbs = Prbs::new(b"nclr-scratch");
            let mut pattern = vec![0u8; bytes as usize];
            prbs.fill(&mut pattern);
            sim_write(dev, start * SECTOR, &pattern)?;
            dev.flush()?;
            let mut back = vec![0u8; bytes as usize];
            sim_read(dev, start * SECTOR, bytes as usize, &mut back)?;
            let errors = if back == pattern { 0u64 } else { 1 };
            sim_write(dev, start * SECTOR, &orig)?;
            dev.flush()?;
            Ok(json!({
                "status": if errors == 0 { "ok" } else { "error" },
                "errors": errors,
                "bytes": bytes,
                "start_lba": start,
                "restored": true,
            }))
        }
        other => Err(Error::Usage(format!("unknown sim action: {other}"))),
    }
}

fn op_run(
    request: &serde_json::Value,
    dev: &mut SimDevice,
    events: &mut BackendEvents,
    physical_image: Option<&mut std::fs::File>,
    physical_map: Option<&mut std::fs::File>,
) -> Result<serde_json::Value> {
    let action = request
        .get("action")
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Usage("run requires action".into()))?;
    let seed = request.get("seed").and_then(|v| v.as_str());
    let params = request.get("params");
    dispatch(
        action,
        seed,
        params,
        dev,
        events,
        physical_image,
        physical_map,
    )
    .map(|action_result| {
        json!({
            "api": PROTOCOL_API,
            "ok": true,
            "backend": "sim",
            "version": VERSION,
            "action": action,
            "action_results": [action_result],
        })
    })
}

fn op_status(dev: &mut SimDevice, events: &mut BackendEvents) -> Result<serde_json::Value> {
    // Advance the self-running sanitize if one is in progress. A persist
    // failure must surface: an ok status with stale progress would leave
    // the core polling forever.
    dev.sanitize_tick()?;
    let sample = sample_read(dev, events)?;
    let mut v = json!({
        "api": PROTOCOL_API,
        "ok": true,
        "backend": "sim",
        "version": VERSION,
        "device": {
            "sim": dev.info(),
            "capacity_bytes": dev.capacity_bytes(),
        },
        "state": "ready",
        "power_cycles": dev.power_cycles(),
        "pe_cycles": dev.pe_cycles(),
        "controller": {
            "id": dev.reported_controller_id(),
            "service_mode": dev.service_mode(),
            "bbt_generation": dev.bbt_generation(),
            "ftl_generation": dev.ftl_generation(),
        },
        "sample": sample,
    });
    if dev.sanitize_available() {
        let state = dev.sanitize_state();
        v["state"] = json!(if state == nclr::sim::SANITIZE_IN_PROGRESS {
            "in-progress"
        } else if state == nclr::sim::SANITIZE_FAILED {
            "failed"
        } else {
            "ready"
        });
        v["sanitize"] = json!({
            "state": state,
            "started": state != nclr::sim::SANITIZE_IDLE,
            "progress": dev.sanitize_progress(),
            "completed": state == nclr::sim::SANITIZE_COMPLETED,
            "failed": state == nclr::sim::SANITIZE_FAILED,
        });
    }
    Ok(v)
}

fn main() {
    // `init` is a standalone utility op (no fds needed).
    if std::env::args().nth(1).as_deref() == Some("init") {
        std::process::exit(cmd_init());
    }

    let invocation = match nclr::backend::parse_backend_args() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("nclr-sim: {e}");
            std::process::exit(64);
        }
    };

    let mut events = BackendEvents::open(invocation.events_fd);

    if std::env::var("NCLR_BACKEND_DEBUG").as_deref() == Ok("1") {
        for fd in [FD_DEVICE, nclr::backend::FD_REQUEST] {
            let mut st: libc::stat = unsafe { std::mem::zeroed() };
            let rc = unsafe { libc::fstat(fd, &mut st) };
            if rc == 0 {
                let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
                eprintln!(
                    "nclr-sim: fd {fd} mode={:o} size={} flags={flags:#x}",
                    st.st_mode, st.st_size,
                );
            } else {
                eprintln!(
                    "nclr-sim: fd {fd} fstat failed (errno {})",
                    std::io::Error::last_os_error()
                );
            }
        }
    }

    let request = match nclr::backend::read_request(invocation.request_fd) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("nclr-sim: {e}");
            std::process::exit(78);
        }
    };

    let dev_fd = unsafe { std::fs::File::from_raw_fd(FD_DEVICE) };
    let mut dev = match SimDevice::from_file(dev_fd) {
        Ok(d) => d,
        Err(e) => backend_common::respond_err("sim", &e),
    };

    let op = invocation.op.as_str();
    let result: Result<serde_json::Value> = match op {
        "probe" | "plan" => {
            let profile = sim_profile(&dev);
            let capabilities = caps(&dev, &profile);
            // A certified physical-scope profile raises the ceiling to C4;
            // without certification the controller path stops at C3.
            let physical_certified = profile.certification.is_some()
                && capabilities.iter().any(|c| c == "PHYSICAL_SCOPE");
            let ceiling = if physical_certified {
                "C4"
            } else if capabilities.iter().any(|c| c == "CONTROLLER_REINITIALIZE") {
                "C3"
            } else if dev.sanitize_available() {
                "C2"
            } else {
                "C1"
            };
            let pe_cycles = dev.pe_cycles();
            let protected_area_bytes = dev.protected_area_blocks() as u64
                * dev.info().pages_per_block as u64
                * dev.info().page_bytes as u64;
            let mut v = json!({
                "api": PROTOCOL_API,
                "ok": true,
                "backend": "sim",
                "match": "exact",
                "version": VERSION,
                "profile": format!("sim-{}", dev.info().id),
                "capabilities": capabilities,
                "grade_ceiling": ceiling,
                "erase_coverage": [],
                "erase_method": Value::Null,
                "rebuilds": [],
                "controller_profile": Value::Null,
                "profile_sha256": Value::Null,
                "capacity_policy": Value::Null,
                "protected_area_bytes": protected_area_bytes,
                "certification": Value::Null,
                "artifacts": [],
                "pe_cycles": pe_cycles,
                "device": {
                    "sim": dev.info(),
                    "capacity_bytes": dev.capacity_bytes(),
                    "logical_block_size": nclr::lba::SECTOR,
                    "controller": {
                        "id": dev.controller_id(),
                        "firmware": dev.firmware(),
                        "nand_id": dev.nand_id(),
                        "service_mode": dev.service_mode(),
                        "bbt_generation": dev.bbt_generation(),
                        "ftl_generation": dev.ftl_generation(),
                    },
                }
            });
            if dev.sanitize_available() {
                v["erase_coverage"] = serde_json::json!(erase_coverage());
                v["erase_method"] = serde_json::json!("sanitize-block-erase");
            }
            if profile.destructive_allowed()
                && profile.matches(dev.controller_id(), dev.firmware(), dev.nand_id())
            {
                v["rebuilds"] = serde_json::json!(profile.rebuilds);
                v["controller_profile"] = serde_json::json!(profile.id);
                v["profile_sha256"] = serde_json::json!(profile.sha256);
                v["capacity_policy"] = serde_json::json!(profile.capacity);
            }
            // The profile documents its certification (e.g. "C4" after the
            // independent physical validation fixture); it is only reported
            // when the physical scope capability is actually available and
            // the profile still matches exactly. Without a certified
            // profile, no certification is claimed.
            if let Some(cert) = profile.certification.as_deref() {
                if capabilities.iter().any(|c| c == "PHYSICAL_SCOPE")
                    && profile.matches(dev.controller_id(), dev.firmware(), dev.nand_id())
                {
                    v["certification"] = serde_json::json!(cert);
                }
            }
            Ok(v)
        }
        "run" => {
            let declarations = request
                .get("extra_fds")
                .and_then(|value| value.as_array())
                .cloned()
                .unwrap_or_default();
            if declarations.iter().enumerate().any(|(index, declaration)| {
                declaration.get("fd").and_then(|value| value.as_i64())
                    != Some(i64::from(nclr::backend::FD_EXTRA_BASE + index as i32))
            }) {
                backend_common::respond_err(
                    "sim",
                    &Error::Invalid("sim extra fd declarations are not contiguous".into()),
                );
            }
            let roles = declarations
                .iter()
                .filter_map(|declaration| declaration.get("role").and_then(|value| value.as_str()))
                .collect::<Vec<_>>();
            if roles
                .iter()
                .any(|role| !matches!(*role, "physical-image" | "physical-map"))
                || roles
                    .iter()
                    .filter(|role| **role == "physical-image")
                    .count()
                    > 1
                || roles.iter().filter(|role| **role == "physical-map").count() > 1
                || roles.contains(&"physical-image") != roles.contains(&"physical-map")
            {
                backend_common::respond_err(
                    "sim",
                    &Error::Invalid(
                        "sim accepts only paired physical-image and physical-map extra fds".into(),
                    ),
                );
            }
            let mut physical_image = None;
            let mut physical_map = None;
            for (index, role) in roles.iter().enumerate() {
                let fd = nclr::backend::FD_EXTRA_BASE + index as i32;
                let file = unsafe { std::fs::File::from_raw_fd(fd) };
                match *role {
                    "physical-image" => physical_image = Some(file),
                    "physical-map" => physical_map = Some(file),
                    _ => unreachable!(),
                }
            }
            op_run(
                &request,
                &mut dev,
                &mut events,
                physical_image.as_mut(),
                physical_map.as_mut(),
            )
        }
        "status" => op_status(&mut dev, &mut events),
        "recover" => {
            let was_in_service = dev.service_mode();
            let recovery = if was_in_service {
                dev.exit_service_mode().map(|()| "service-mode-exit")
            } else {
                Ok("not-required")
            };
            recovery.map(|recovery| {
                json!({
                    "api": PROTOCOL_API,
                    "ok": true,
                    "backend": "sim",
                    "version": VERSION,
                    "state": "ready",
                    "recovery": recovery,
                    "automated": true,
                })
            })
        }
        other => Err(Error::Usage(format!("unknown sim op: {other}"))),
    };

    match result {
        Ok(v) => {
            if let Err(e) = nclr::backend::write_response(&v) {
                eprintln!("nclr-sim: {e}");
                std::process::exit(74);
            }
        }
        Err(e) => {
            if op == "run" {
                backend_common::respond_action_err("sim", &e);
            }
            backend_common::respond_err("sim", &e);
        }
    }
}

/// `nclr-sim init` — create a sim image (testing / development tool).
fn cmd_init() -> i32 {
    let args: Vec<String> = std::env::args().skip(2).collect();
    let mut out = None;
    let mut spec = nclr::sim::SimSpec::default();
    let mut i = 0;
    let parse_u32 = |s: &str| -> Option<u32> { s.parse().ok() };
    let parse_list =
        |s: &str| -> Vec<u32> { s.split(',').filter_map(|x| x.trim().parse().ok()).collect() };
    while i < args.len() {
        match args[i].as_str() {
            "--out" => {
                i += 1;
                out = args.get(i).cloned();
            }
            "--id" => {
                i += 1;
                spec.id = args.get(i).cloned().unwrap_or_default();
            }
            "--blocks" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| parse_u32(s)) {
                    spec.blocks = v;
                }
            }
            "--pages-per-block" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| parse_u32(s)) {
                    spec.pages_per_block = v;
                }
            }
            "--page-bytes" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| parse_u32(s)) {
                    spec.page_bytes = v;
                }
            }
            "--user-blocks" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| parse_u32(s)) {
                    spec.user_blocks = v;
                }
            }
            "--op-blocks" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| parse_u32(s)) {
                    spec.op_blocks = v;
                }
            }
            "--fbb" => {
                i += 1;
                spec.fbb = args.get(i).map(|s| parse_list(s)).unwrap_or_default();
            }
            "--old-rbb" => {
                i += 1;
                spec.old_rbb = args.get(i).map(|s| parse_list(s)).unwrap_or_default();
            }
            "--fail-erase" => {
                i += 1;
                spec.fail_erase = args.get(i).map(|s| parse_list(s)).unwrap_or_default();
            }
            "--fail-program" => {
                i += 1;
                spec.fail_program = args.get(i).map(|s| parse_list(s)).unwrap_or_default();
            }
            "--fail-read" => {
                i += 1;
                spec.fail_read = args.get(i).map(|s| parse_list(s)).unwrap_or_default();
            }
            "--capacity-alias" => spec.capacity_alias = true,
            "--no-stale-mbr" => spec.stale_mbr = false,
            "--no-sanitize" => spec.sanitize = false,
            "--sanitize-fail" => spec.sanitize_fail = true,
            "--no-controller" => spec.controller = false,
            "--controller-id" => {
                i += 1;
                spec.controller_id = args.get(i).cloned().unwrap_or_default();
            }
            "--firmware" => {
                i += 1;
                spec.firmware = args.get(i).cloned().unwrap_or_default();
            }
            "--nand-id" => {
                i += 1;
                spec.nand_id = args.get(i).cloned().unwrap_or_default();
            }
            "--ecc-corrupt" => {
                i += 1;
                spec.ecc_corrupt = args.get(i).map(|s| parse_list(s)).unwrap_or_default();
            }
            "--weak-blocks" => {
                i += 1;
                spec.weak_blocks = args.get(i).map(|s| parse_list(s)).unwrap_or_default();
            }
            "--ecc-strength" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| parse_u32(s)) {
                    spec.ecc_strength = v;
                }
            }
            "--ecc-min-margin" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| parse_u32(s)) {
                    spec.ecc_min_margin = v;
                }
            }
            "--fail-ftl-commit" => spec.fail_ftl_commit = true,
            "--fail-service-exit" => spec.fail_service_exit = true,
            "--unknown-reservation" => {
                i += 1;
                spec.unknown_reservation = args.get(i).map(|s| parse_list(s)).unwrap_or_default();
            }
            "--protected-area-blocks" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|s| parse_u32(s)) {
                    spec.protected_area_blocks = v;
                }
            }
            other => {
                eprintln!("nclr-sim: unknown init arg: {other}");
                return 64;
            }
        }
        i += 1;
    }
    let Some(out) = out else {
        eprintln!("nclr-sim: init requires --out FILE");
        return 64;
    };
    if spec.user_blocks as u64 + spec.op_blocks as u64 > spec.blocks as u64 {
        eprintln!("nclr-sim: user_blocks + op_blocks exceed blocks");
        return 64;
    }
    match nclr::sim::create(std::path::Path::new(&out), &spec) {
        Ok(()) => {
            println!(
                "created {} ({} blocks, {} user)",
                out, spec.blocks, spec.user_blocks
            );
            0
        }
        Err(e) => {
            eprintln!("nclr-sim: {e}");
            e.exit_code()
        }
    }
}
