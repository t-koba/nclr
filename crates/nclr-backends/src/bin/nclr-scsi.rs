//! SCSI standard backend: probe/plan/run/status/recover
//! for USB mass storage devices on Linux.
//!
//! Uses SG_IO passthrough on the inherited block device fd. The protocol
//! layer (CDB construction/parsing) lives in `nclr::scsi` and is verified
//! with byte-level fixture tests; on-wire behavior against real devices must
//! be validated on Linux (scsi_debug or a USB stick).

#[cfg(not(target_os = "linux"))]
use nclr::backend::{FD_DEVICE, PROTOCOL_API};
#[cfg(not(target_os = "linux"))]
use nclr::VERSION;

fn main() {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (FD_DEVICE, PROTOCOL_API, VERSION);
        eprintln!("nclr-scsi: the SCSI backend requires Linux (SG_IO); use the lba backend on this platform");
        std::process::exit(69);
    }
    #[cfg(target_os = "linux")]
    {
        linux::linux_main();
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use nclr::backend::{BackendEvents, FD_DEVICE, PROTOCOL_API};
    use nclr::backend_common;
    use nclr::errors::{Error, Result};
    use nclr::lba::LbaDevice;
    use nclr::scsi;
    use nclr::VERSION;
    use serde_json::{json, Value};
    use std::os::fd::FromRawFd;

    /// A blocking SANITIZE can run for many hours; sg3_utils uses a 15 h
    /// cap (a 2 TB drive took 9.5 h in the reference implementation).
    const SANITIZE_BLOCKING_TIMEOUT_MS: u32 = 54_000_000;

    /// Run a command and return exactly `len` bytes of the data buffer.
    fn scsi_command(
        file: &std::fs::File,
        cdb: &[u8],
        direction: i32,
        len: usize,
    ) -> Result<Vec<u8>> {
        scsi_command_timeout(file, cdb, direction, len, 60_000)
    }

    /// scsi_command with an explicit ioctl timeout in milliseconds. The
    /// sg_io_hdr transport (linux/scsi/sg.h) lives in `nclr::scsi::sg`.
    fn scsi_command_timeout(
        file: &std::fs::File,
        cdb: &[u8],
        direction: i32,
        len: usize,
        timeout_ms: u32,
    ) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; len];
        scsi::sg::exec(file, cdb, direction, &mut buf, timeout_ms)?;
        // The resid field is not applied, so a short read leaves the tail
        // as received.
        Ok(buf)
    }

    /// Device identity and capability summary from a probe.
    struct ProbeData {
        inquiry: nclr::scsi::Inquiry,
        capacity_bytes: u64,
        block_size: u32,
        rsocc: Vec<nclr::scsi::SupportedCommand>,
    }

    fn probe_device(file: &std::fs::File) -> Result<ProbeData> {
        // INQUIRY standard data.
        let inq = scsi_command(
            file,
            &scsi::cdb_inquiry(false, 0, 96),
            scsi::SG_DXFER_FROM_DEV,
            96,
        )?;
        let inquiry = scsi::parse_inquiry(&inq)?;

        // READ CAPACITY(10) first (SBC-4): the 0xFFFFFFFF/0xFFFFFFFF
        // response means the device exceeds the 10-byte addressing range,
        // and only then READ CAPACITY(16) is used. Leading with the 16-byte
        // CDB resets some older USB bridges (they answer with DID_RESET
        // instead of a clean sense), leaving the device NOT READY for the
        // subsequent fallback.
        let cap10 = scsi_command(
            file,
            &scsi::cdb_read_capacity_10(),
            scsi::SG_DXFER_FROM_DEV,
            8,
        );
        let (capacity_bytes, block_size) = match cap10 {
            Ok(d) if d.len() >= 8 => {
                let blocks = u32::from_be_bytes(d[0..4].try_into().unwrap());
                let bsz = u32::from_be_bytes(d[4..8].try_into().unwrap());
                if blocks == 0xFFFF_FFFF && bsz == 0xFFFF_FFFF {
                    let d = scsi_command(
                        file,
                        &scsi::cdb_read_capacity_16(32),
                        scsi::SG_DXFER_FROM_DEV,
                        32,
                    )?;
                    if d.len() < 12 {
                        return Err(Error::Invalid(
                            "READ CAPACITY(16) returned a truncated response".into(),
                        ));
                    }
                    let blocks = u64::from_be_bytes(d[0..8].try_into().unwrap());
                    let bsz = u32::from_be_bytes(d[8..12].try_into().unwrap());
                    ((blocks + 1).saturating_mul(bsz as u64), bsz)
                } else {
                    ((blocks as u64 + 1).saturating_mul(bsz as u64), bsz)
                }
            }
            _ => {
                return Err(Error::io(
                    "READ CAPACITY(10) returned a truncated response".to_string(),
                    None,
                ))
            }
        };

        // REPORT SUPPORTED OPERATION CODES (best effort: a device without
        // RSOC support degrades to a plain LBA probe, but the reason is
        // announced instead of swallowed).
        let rsocc_raw = scsi_command(file, &scsi::cdb_rsocc(4096), scsi::SG_DXFER_FROM_DEV, 4096);
        let rsocc = match rsocc_raw {
            Ok(d) => match scsi::parse_rsocc(&d) {
                Ok(list) => list,
                Err(e) => {
                    eprintln!("nclr-scsi: warning: cannot parse the RSOC response: {e}");
                    Vec::new()
                }
            },
            Err(e) => {
                eprintln!("nclr-scsi: warning: RSOC unsupported ({e}); erasure capability unknown");
                Vec::new()
            }
        };

        Ok(ProbeData {
            inquiry,
            capacity_bytes,
            block_size,
            rsocc,
        })
    }

    /// Determine the documented device-erase capability.
    fn erase_capability(
        rsocc: &[nclr::scsi::SupportedCommand],
    ) -> Option<(&'static str, Vec<&'static str>)> {
        // SANITIZE BLOCK ERASE: documented by SBC-4 to cover the user data
        // area, spare blocks and obsolete data (D0-D2).
        if scsi::rsocc_supports(
            rsocc,
            scsi::OP_SANITIZE,
            Some(scsi::SA_SANITIZE_BLOCK_ERASE as u16),
        ) {
            return Some(("sanitize-block-erase", vec!["D0", "D1", "D2"]));
        }
        // SANITIZE CRYPTO ERASE: destroys the encryption key; D0 only.
        if scsi::rsocc_supports(
            rsocc,
            scsi::OP_SANITIZE,
            Some(scsi::SA_SANITIZE_CRYPTO_ERASE as u16),
        ) {
            return Some(("sanitize-crypto-erase", vec!["D0"]));
        }
        None
    }

    fn caps_with(
        erase: Option<(&'static str, Vec<&'static str>)>,
    ) -> (Vec<String>, Vec<String>, Option<String>, &'static str) {
        let mut caps = backend_common::lba_caps();
        let mut coverage = Vec::new();
        let mut method = None;
        let mut ceiling = "C1";
        if let Some((m, cov)) = erase {
            caps.push("ERASE_USER_AREA".into());
            coverage = cov.into_iter().map(String::from).collect();
            method = Some(m.to_string());
            ceiling = "C2";
        }
        (caps, coverage, method, ceiling)
    }

    fn probe_response(file: &std::fs::File) -> Result<Value> {
        let pd = probe_device(file)?;
        let erase = erase_capability(&pd.rsocc);
        let (caps, coverage, method, ceiling) = caps_with(erase);
        let mut inquiry = pd.inquiry.clone();
        // VPD 0x80 serial and 0x83 designators (best effort).
        if let Ok(d) = scsi_command(
            file,
            &scsi::cdb_inquiry(true, scsi::VPD_SERIAL, 252),
            scsi::SG_DXFER_FROM_DEV,
            252,
        ) {
            if let Ok(s) = scsi::parse_vpd_serial(&d) {
                inquiry.serial_number = s;
            }
        }
        if let Ok(d) = scsi_command(
            file,
            &scsi::cdb_inquiry(true, scsi::VPD_DEVICE_IDENTIFICATION, 1024),
            scsi::SG_DXFER_FROM_DEV,
            1024,
        ) {
            if let Ok(ds) = scsi::parse_vpd_designators(&d) {
                inquiry.designators = ds;
            }
        }
        let mut v = json!({
            "api": PROTOCOL_API,
            "ok": true,
            "backend": "scsi",
            "match": "exact",
            "version": VERSION,
            "capabilities": caps,
            "grade_ceiling": ceiling,
            "device": {
                "capacity_bytes": pd.capacity_bytes,
                "logical_block_size": pd.block_size,
                "sectors": pd.capacity_bytes / nclr::lba::SECTOR,
                "inquiry": inquiry,
            }
        });
        if !coverage.is_empty() {
            v["erase_coverage"] = json!(coverage);
            v["erase_method"] = json!(method);
        }
        Ok(v)
    }

    /// Start the SANITIZE BLOCK ERASE (IMMED) or run it blocking.
    fn start_device_erase(file: &std::fs::File, method: &str) -> Result<Value> {
        let sa = match method {
            "sanitize-block-erase" => scsi::SA_SANITIZE_BLOCK_ERASE,
            "sanitize-crypto-erase" => scsi::SA_SANITIZE_CRYPTO_ERASE,
            _ => return Err(Error::Unsupported(format!("unknown erase method {method}"))),
        };
        // Prefer IMMED (long-running with status monitoring); fall back to a
        // blocking SANITIZE only when the device rejected IMMED (CHECK
        // CONDITION). A transport failure (timeout, reset) must never
        // trigger a retransmission of a destructive command (§1213).
        match scsi::sg::exec(
            file,
            &scsi::cdb_sanitize(sa, true),
            scsi::SG_DXFER_NONE,
            &mut [],
            60_000,
        ) {
            Ok(_) => Ok(json!({ "status": "ok", "started": true })),
            Err(e) if scsi::sg::is_check_condition(&e) => {
                eprintln!(
                    "nclr-scsi: IMMED SANITIZE rejected ({}); falling back to a blocking SANITIZE",
                    e
                );
                // A blocking SANITIZE can take hours; give it a long timeout
                // instead of the 60 s used for short commands.
                scsi::sg::exec(
                    file,
                    &scsi::cdb_sanitize(sa, false),
                    scsi::SG_DXFER_NONE,
                    &mut [],
                    SANITIZE_BLOCKING_TIMEOUT_MS,
                )?;
                Ok(json!({ "status": "ok", "started": false, "completed": true }))
            }
            Err(e) => Err(e),
        }
    }

    /// Query the SANITIZE STATUS page (RECEIVE DIAGNOSTIC RESULTS).
    fn sanitize_status(file: &std::fs::File) -> Result<scsi::SanitizeStatus> {
        let d = scsi_command(
            file,
            &scsi::cdb_receive_diag_sanitize_status(64),
            scsi::SG_DXFER_FROM_DEV,
            64,
        )?;
        scsi::parse_sanitize_status(&d)
    }

    fn dispatch(
        action: &str,
        seed: Option<&str>,
        params: Option<&Value>,
        file: &std::fs::File,
        dev: &mut LbaDevice,
        events: &mut BackendEvents,
        erase_method: Option<&str>,
    ) -> Result<Value> {
        match action {
            "device-user-area-erase" => {
                let method = erase_method.ok_or_else(|| {
                    Error::Unsupported("device erase not available on this device".into())
                })?;
                start_device_erase(file, method)
            }
            "blank-verify" => backend_common::blank_verify(dev, events, "nclr-scsi"),
            "postcheck-p2" => {
                // Re-query the device geometry: capacity stability must be
                // measured after the erase/power cycle, not taken from the
                // values cached at process start.
                dev.refresh_capacity()?;
                let sample = backend_common::sample_read(dev, events)?;
                Ok(json!({
                    "status": "ok",
                    "capacity_bytes": dev.capacity_bytes(),
                    "logical_block_size": dev.block_size(),
                    "capacity_stable": true,
                    "sample": sample,
                }))
            }
            _ => backend_common::dispatch_lba_action(action, seed, params, dev, events),
        }
    }

    pub fn linux_main() {
        let invocation = match nclr::backend::parse_backend_args() {
            Ok(i) => i,
            Err(e) => {
                eprintln!("nclr-scsi: {e}");
                std::process::exit(64);
            }
        };
        let mut events = BackendEvents::open(invocation.events_fd);

        let request = match nclr::backend::read_request(invocation.request_fd) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("nclr-scsi: {e}");
                std::process::exit(78);
            }
        };

        // The block fd is used by both the SG_IO transport and LbaDevice;
        // dup it so each owner closes its own descriptor (never two close()
        // calls on the same fd number).
        let file = unsafe { std::fs::File::from_raw_fd(FD_DEVICE) };
        let is_file = match file.metadata() {
            Ok(m) => m.is_file(),
            Err(e) => backend_common::respond_err(
                "scsi",
                &Error::io("fstat of the inherited device fd", Some(e)),
            ),
        };
        let dup_fd = unsafe { libc::dup(FD_DEVICE) };
        if dup_fd < 0 {
            backend_common::respond_err(
                "scsi",
                &Error::io(
                    "dup of the inherited device fd",
                    Some(std::io::Error::last_os_error()),
                ),
            );
        }
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(dup_fd) };
        let mut dev = match LbaDevice::from_fd(owned, is_file) {
            Ok(d) => d,
            Err(e) => backend_common::respond_err("scsi", &e),
        };

        let op = invocation.op.as_str();
        let result: Result<Value> = (|| {
            match op {
                "probe" | "plan" => probe_response(&file),
                "run" => {
                    let action = request
                        .get("action")
                        .and_then(|v| v.as_str())
                        .ok_or_else(|| Error::Usage("run requires action".into()))?;
                    let seed = request.get("seed").and_then(|v| v.as_str());
                    let erase_method = if action == "device-user-area-erase" {
                        // Re-probe for the documented method.
                        let pd = probe_device(&file)?;
                        erase_capability(&pd.rsocc).map(|(m, _)| m.to_string())
                    } else {
                        None
                    };
                    let action_result = dispatch(
                        action,
                        seed,
                        request.get("params"),
                        &file,
                        &mut dev,
                        &mut events,
                        erase_method.as_deref(),
                    )?;
                    Ok(json!({
                        "api": PROTOCOL_API,
                        "ok": true,
                        "backend": "scsi",
                        "version": VERSION,
                        "action": action,
                        "action_results": [action_result],
                    }))
                }
                "status" => {
                    let mut v = json!({
                        "api": PROTOCOL_API,
                        "ok": true,
                        "backend": "scsi",
                        "version": VERSION,
                        "state": "ready",
                    });
                    // Long-running SANITIZE monitoring. The core's monitor
                    // reads the completed/failed booleans (mirroring the sim
                    // backend contract); the state string is informational.
                    match sanitize_status(&file) {
                        Ok(s) => {
                            v["sanitize"] = json!({
                                "state": if s.completed { "completed" } else { "in-progress" },
                                "started": true,
                                "completed": s.completed,
                                "failed": s.failed,
                                "progress": s.progress.unwrap_or(0),
                            });
                        }
                        Err(e) => {
                            // A failed status *query* is not a failed
                            // sanitize: many devices reject the SANITIZE
                            // STATUS page while the operation is still
                            // running (spec §1215: timeout is not failure).
                            // Report unknown and let the core keep
                            // monitoring; only a completed or failed device
                            // verdict stops the monitor. "started" is
                            // deliberately omitted: whether the erase began
                            // is unknown, so the core must not treat this as
                            // "not started" (which would re-issue the
                            // command) - the safe side is continued
                            // monitoring (a failed status query is not a
                            // failed erase, §1215).
                            v["sanitize"] = json!({
                                "state": "unknown",
                                "completed": false,
                                "failed": false,
                                "progress": 0,
                                "error": e.to_string(),
                            });
                        }
                    }
                    Ok(v)
                }
                "recover" => {
                    // SCSI devices recover at the transport level: re-issue
                    // the command or power-cycle the device.
                    Ok(json!({
                        "api": PROTOCOL_API,
                        "ok": true,
                        "backend": "scsi",
                        "state": "ready",
                        "recovery": {
                            "automated": false,
                            "method": "reissue-or-power-cycle",
                            "manual": "unplug and re-attach the device, then run nclr resume",
                        },
                    }))
                }
                other => Err(Error::Usage(format!("unknown scsi op: {other}"))),
            }
        })();

        match result {
            Ok(v) => {
                if let Err(e) = nclr::backend::write_response(&v) {
                    eprintln!("nclr-scsi: {e}");
                    std::process::exit(74);
                }
            }
            Err(e) => {
                if op == "run" {
                    backend_common::respond_action_err("scsi", &e);
                }
                backend_common::respond_err("scsi", &e);
            }
        }
    }
}
