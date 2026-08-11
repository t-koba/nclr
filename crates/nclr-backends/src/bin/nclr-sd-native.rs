//! Native SD backend: standard SD full-range erase via
//! MMC_IOC_CMD on Linux (CMD32/CMD33/CMD38).
//!
//! Only the standard ERASE is used (CMD38 argument 0). DISCARD/TRIM
//! (eMMC CMD38 argument 0x1 / 0x3; SD has no TRIM/DISCARD) is auxiliary
//! and is never treated as erase evidence (discard alone must not grant C2).
//!
//! CMD32/CMD33 are SD-specific: the core only routes cards whose sysfs
//! `type` attribute is "SD" to this backend, so eMMC (CMD35/36) never
//! reaches it.

#[cfg(not(target_os = "linux"))]
use nclr::backend::{FD_DEVICE, PROTOCOL_API};
#[cfg(not(target_os = "linux"))]
use nclr::VERSION;

fn main() {
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (FD_DEVICE, PROTOCOL_API, VERSION);
        eprintln!("nclr-sd-native: the native SD backend requires Linux (MMC_IOC_CMD); use the lba backend on this platform");
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
    use nclr::VERSION;
    use serde_json::{json, Value};
    use std::os::fd::{AsRawFd, FromRawFd};

    // linux/mmc/ioctl.h: MMC_IOC_CMD = _IOWR(MMC_BLOCK_MAJOR (179), 0,
    // struct mmc_ioc_cmd) with sizeof = 72 on 64-bit Linux (68 on 32-bit;
    // this backend targets 64-bit builds only).
    const MMC_IOC_CMD: libc::c_ulong = 0xC048_B300;

    // linux/mmc/core.h response/command flags for the ioctl (R1/R1B/etc).
    const MMC_RSP_PRESENT: u32 = 1 << 0;
    const MMC_RSP_CRC: u32 = 1 << 2;
    const MMC_RSP_BUSY: u32 = 1 << 3;
    const MMC_RSP_OPCODE: u32 = 1 << 4;
    /// R1: present|CRC|opcode. Used by CMD32/CMD33.
    const MMC_RSP_R1: u32 = MMC_RSP_PRESENT | MMC_RSP_CRC | MMC_RSP_OPCODE;
    /// R1B: R1 plus busy. Used by CMD38. In the MMC_IOC_CMD path the kernel
    /// (drivers/mmc/core/block.c) calls mmc_prepare_busy_cmd, which
    /// downgrades R1B to R1 when the busy budget exceeds the host's
    /// max_busy_timeout (mmc_ops.c), and then polls the card status with
    /// CMD13 (mmc_send_status, not the DAT0 line) until the erase finishes
    /// or cmd_timeout_ms elapses, OR-ing the accumulated card status into
    /// response[0]. (MMC_CMD_AC = 0 << 5 is implied: the flags carry no
    /// command-type bits.)
    const MMC_RSP_R1B: u32 = MMC_RSP_R1 | MMC_RSP_BUSY;

    // R1 card-status error bits (SD Physical Layer Spec Table 4-42 and
    // linux/mmc/mmc.h R1_* constants). The kernel's in-kernel erase path
    // uses R1_STATUS (0xFFF9A000, mmc.h R1_STATUS, used in mmc_ops.c
    // MMC_BUSY_ERASE) as the error mask, and its generic command error set
    // (CMD_ERRORS, block.c) is a subset of the same bits. The ioctl path
    // leaves the accumulated status in response[0] for userspace to check,
    // so the same mask is applied here. R1_UNDERRUN/OVERRUN (bits 18/17)
    // are deliberately absent: they are data-transfer errors that a
    // data-less CMD38 never reports. READY_FOR_DATA (bit 8) is excluded:
    // a successful CMD13 poll always sets it, so including it would make
    // every successful erase look like a failure.
    const CARD_STATUS_ERASE_ERRORS: u32 = 0xFFF9_A000;

    const CMD32_ERASE_WR_BLK_START: u32 = 32;
    const CMD33_ERASE_WR_BLK_END: u32 = 33;
    const CMD38_ERASE: u32 = 38;
    // Standard ERASE (not discard/trim).
    const MMC_ERASE_ARG: u32 = 0;

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct MmcIocCmd {
        write_flag: i32,
        is_acmd: i32,
        opcode: u32,
        arg: u32,
        response: [u32; 4],
        flags: u32,
        blksz: u32,
        blocks: u32,
        postsleep_min_us: u32,
        postsleep_max_us: u32,
        data_timeout_ns: u32,
        cmd_timeout_ms: u32,
        // The kernel layout ends with `__u32 __pad; __u64 data_ptr;` (72
        // bytes total on 64-bit); the pad keeps data_ptr 8-byte aligned.
        pad: u32,
        data_ptr: u64,
    }

    /// Send a command and check the R1/R1B card status. CMD32/CMD33 expect
    /// an R1 response; CMD38 returns R1B, which also makes the kernel poll
    /// the busy line until the erase completes or `cmd_timeout_ms` elapses.
    fn send_cmd(file: &std::fs::File, opcode: u32, arg: u32, r1b: bool) -> Result<()> {
        let mut cmd = MmcIocCmd {
            opcode,
            arg,
            // The kernel uses this value directly as the CMD13 busy-poll
            // budget for R1B commands in the MMC_IOC_CMD path
            // (busy_timeout_ms = cmd_timeout_ms); the kernel's own
            // mmc_sd_erase_timeout estimate (drivers/mmc/core/core.c) is
            // only used by the block-layer discard/erase path, not here.
            // That estimate can reach ~2.3 h for a 128 GB card (250 ms x
            // allocation units with an SSR AU set and no SSR erase_timeout;
            // without any SSR data it counts sectors and becomes absurd,
            // and a 2 TB card would estimate ~36 h). The 2.5 h cap covers
            // the realistic 128 GB-class case and must still be confirmed
            // on hardware (a timeout mid-erase reports failure while the
            // card keeps erasing; the erase is idempotent, so a resume
            // re-issue recovers).
            cmd_timeout_ms: 9_000_000,
            flags: if r1b { MMC_RSP_R1B } else { MMC_RSP_R1 },
            write_flag: if r1b { 1 } else { 0 },
            ..Default::default()
        };
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), MMC_IOC_CMD, &mut cmd) };
        if rc < 0 {
            let err = std::io::Error::last_os_error();
            // The kernel returns ETIMEDOUT when the DAT0/CMD13 busy budget
            // expires: the card is very likely still erasing. That is not a
            // failure (spec §1215): report a resumable interruption so the
            // core stops with exit 75 and resume re-issues the idempotent
            // erase instead of falling back to writes. Note that a card
            // stuck in an error state also times out and is classified as
            // interrupted here; the error surfaces on the resumed re-issue
            // (R1 error bits), so it is never silently accepted.
            if err.kind() == std::io::ErrorKind::TimedOut {
                return Err(Error::Interrupted(format!(
                    "MMC_IOC_CMD opcode {opcode} busy timeout; the card may still be erasing (resume to continue)"
                )));
            }
            return Err(Error::io(
                format!("MMC_IOC_CMD opcode {opcode} failed"),
                Some(err),
            ));
        }
        // R1/R1B: response[0] carries the card status. A nonzero error set
        // (write-protect violation, illegal command, erase-sequence error,
        // address error, ...) means the operation did NOT complete.
        let status = cmd.response[0];
        if status & CARD_STATUS_ERASE_ERRORS != 0 {
            return Err(Error::io(
                format!("opcode {opcode} rejected by the card: R1 status 0x{status:08x}"),
                None,
            ));
        }
        Ok(())
    }

    /// Full-card standard ERASE: CMD32(0) + CMD33(last LBA) + CMD38.
    fn device_user_area_erase(dev: &LbaDevice, file: &std::fs::File) -> Result<Value> {
        // CMD32/CMD33 carry a 32-bit block address, which caps the range at
        // 2 TiB (2^32 x 512). SDXC tops out at 2 TiB by specification, but a
        // larger (or non-conformant) device must fail loudly instead of
        // silently truncating the erase range.
        if dev.sectors() > u64::from(u32::MAX) + 1 {
            return Err(Error::Unsupported(format!(
                "device has {} sectors; CMD32/CMD33 address a maximum of 2^32 (2 TiB)",
                dev.sectors()
            )));
        }
        // SDSC (CSD_STRUCTURE 0, <2 GB) addresses CMD32/33 in bytes, not
        // blocks: sending block numbers would silently erase only a tiny
        // prefix. The sysfs `csd` attribute carries the structure bits in
        // the top two bits of its first byte. Refuse SDSC until the
        // byte-address conversion is validated on hardware.
        if is_sdsc_card(file)? {
            return Err(Error::Unsupported(
                "SDSC card (byte-addressed CMD32/33) is not supported for full-range erase; convert the range or use the lba backend".into(),
            ));
        }
        let last_lba = (dev.sectors() - 1) as u32;
        send_cmd(file, CMD32_ERASE_WR_BLK_START, 0, false)?;
        send_cmd(file, CMD33_ERASE_WR_BLK_END, last_lba, false)?;
        send_cmd(file, CMD38_ERASE, MMC_ERASE_ARG, true)?;
        Ok(json!({
            "status": "ok",
            "started": false,
            "completed": true,
            "method": "sd-full-range-erase",
            "range": {"start_lba": 0, "end_lba": last_lba},
        }))
    }

    /// Whether the card is SDSC (CSD_STRUCTURE 0). The CSD is read from
    /// /sys/block/<name>/device/csd (hex string); its top two bits select
    /// the structure: 0 = SDSC (byte addressing), 1 = SDHC/SDXC (block
    /// addressing). An unreadable or malformed CSD is an error, never a
    /// silent "not SDSC": erasing with the wrong address unit would only
    /// wipe a tiny prefix of the card.
    fn is_sdsc_card(file: &std::fs::File) -> Result<bool> {
        let dev_link = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd()))
            .map_err(|e| Error::io("readlink of the device fd", Some(e)))?;
        let name = dev_link
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .ok_or_else(|| Error::io("cannot resolve the device name", None))?;
        let csd_path = std::path::Path::new("/sys/block")
            .join(&name)
            .join("device")
            .join("csd");
        let csd = std::fs::read_to_string(&csd_path).map_err(|e| {
            Error::io(
                format!("cannot read the card CSD from {}", csd_path.display()),
                Some(e),
            )
        })?;
        let csd = csd.trim();
        let first_hex = csd
            .get(..2)
            .ok_or_else(|| Error::Invalid(format!("malformed CSD attribute \"{csd}\"")))?;
        let first = u8::from_str_radix(first_hex, 16)
            .map_err(|e| Error::Invalid(format!("malformed CSD attribute \"{csd}\": {e}")))?;
        Ok(first >> 6 == 0)
    }

    fn dispatch(
        action: &str,
        seed: Option<&str>,
        params: Option<&Value>,
        dev: &mut LbaDevice,
        file: &std::fs::File,
        events: &mut BackendEvents,
    ) -> Result<Value> {
        match action {
            "device-user-area-erase" => device_user_area_erase(dev, file),
            "blank-verify" => backend_common::blank_verify(dev, events, "nclr-sd-native"),
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
                eprintln!("nclr-sd-native: {e}");
                std::process::exit(64);
            }
        };
        let mut events = BackendEvents::open(invocation.events_fd);

        let request = match nclr::backend::read_request(invocation.request_fd) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("nclr-sd-native: {e}");
                std::process::exit(78);
            }
        };

        // The block fd is used by both MMC_IOC_CMD and LbaDevice; dup it so
        // each owner closes its own descriptor (never two close() calls on
        // the same fd number).
        let file = unsafe { std::fs::File::from_raw_fd(FD_DEVICE) };
        let is_file = match file.metadata() {
            Ok(m) => m.is_file(),
            Err(e) => backend_common::respond_err(
                "sd-native",
                &Error::io("fstat of the inherited device fd", Some(e)),
            ),
        };
        let dup_fd = unsafe { libc::dup(FD_DEVICE) };
        if dup_fd < 0 {
            backend_common::respond_err(
                "sd-native",
                &Error::io(
                    "dup of the inherited device fd",
                    Some(std::io::Error::last_os_error()),
                ),
            );
        }
        let owned = unsafe { std::os::fd::OwnedFd::from_raw_fd(dup_fd) };
        let mut dev = match LbaDevice::from_fd(owned, is_file) {
            Ok(d) => d,
            Err(e) => backend_common::respond_err("sd-native", &e),
        };

        let op = invocation.op.as_str();
        let result: Result<Value> = (|| match op {
            "probe" | "plan" => {
                // SDSC cards (byte addressing) cannot be erased with block
                // addresses at all; gate the capability at probe time.
                let sdsc = is_sdsc_card(&file)?;
                let mut caps = backend_common::lba_caps();
                if !sdsc {
                    caps.push("ERASE_USER_AREA".into());
                }
                let mut v = backend_common::probe_result_body(
                    "sd-native",
                    &dev,
                    caps,
                    if sdsc { "C1" } else { "C2" },
                );
                // The SD standard ERASE (CMD32/33/38) covers the
                // user-address area (D0) only; SD does not document
                // spare/OP (D1) or obsolete page (D2) erasure, so only D0
                // is claimed (spec §830/§865: never claim more than the
                // documented scope).
                if sdsc {
                    v["erase_coverage"] = json!([]);
                    v["erase_method"] = json!(Value::Null);
                    v["sdsc_unsupported"] = json!(true);
                } else {
                    v["erase_coverage"] = json!(["D0"]);
                    v["erase_method"] = json!("sd-full-range-erase");
                }
                Ok(v)
            }
            "run" => {
                let action = request
                    .get("action")
                    .and_then(|v| v.as_str())
                    .ok_or_else(|| Error::Usage("run requires action".into()))?;
                let seed = request.get("seed").and_then(|v| v.as_str());
                let action_result = dispatch(
                    action,
                    seed,
                    request.get("params"),
                    &mut dev,
                    &file,
                    &mut events,
                )?;
                Ok(json!({
                    "api": PROTOCOL_API,
                    "ok": true,
                    "backend": "sd-native",
                    "version": VERSION,
                    "action": action,
                    "action_results": [action_result],
                }))
            }
            "status" => Ok(json!({
                "api": PROTOCOL_API,
                "ok": true,
                "backend": "sd-native",
                "version": VERSION,
                "state": "ready",
                // No sanitize state is reported: the standard ERASE is a
                // synchronous full-range command whose busy phase is polled
                // by the kernel, so the card state cannot be queried here
                // without racing the operation. On resume the core re-issues
                // it, which is safe because the operation is idempotent
                // (§1255); a busy timeout is reported as an interruption
                // (exit 75) rather than a failure.
                "device": {
                    "capacity_bytes": dev.capacity_bytes(),
                    "logical_block_size": dev.block_size(),
                },
            })),
            "recover" => Ok(json!({
                "api": PROTOCOL_API,
                "ok": true,
                "backend": "sd-native",
                "state": "ready",
                "recovery": {
                    "automated": false,
                    "method": "power-cycle",
                    "manual": "remove and re-insert the card (or power-cycle the slot), then run nclr resume",
                },
            })),
            other => Err(Error::Usage(format!("unknown sd-native op: {other}"))),
        })();

        match result {
            Ok(v) => {
                if let Err(e) = nclr::backend::write_response(&v) {
                    eprintln!("nclr-sd-native: {e}");
                    std::process::exit(74);
                }
            }
            Err(e) => {
                if op == "run" {
                    // A resumable interruption (busy timeout mid-erase) is
                    // not a failure: report status "interrupted" so the
                    // core stops with exit 75 instead of falling back to
                    // writes against a possibly running erase.
                    if let Error::Interrupted(msg) = &e {
                        let action = request.get("action").and_then(|v| v.as_str()).unwrap_or("");
                        let resp = json!({
                            "api": PROTOCOL_API,
                            "ok": true,
                            "backend": "sd-native",
                            "version": VERSION,
                            "action": action,
                            "action_results": [{
                                "status": "interrupted",
                                "message": msg,
                            }],
                        });
                        if let Err(we) = nclr::backend::write_response(&resp) {
                            eprintln!("nclr-sd-native: {we}");
                        }
                        std::process::exit(0);
                    }
                    backend_common::respond_action_err("sd-native", &e);
                }
                backend_common::respond_err("sd-native", &e);
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn erase_error_mask_matches_kernel_sets() {
            // The mask is the kernel's R1_STATUS set (mmc.h, used as the
            // MMC_BUSY_ERASE error mask in mmc_ops.c), which also contains
            // every bit of the generic CMD_ERRORS set (block.c). It
            // excludes READY_FOR_DATA (bit 8), which a successful CMD13
            // poll always sets, and the data-transfer bits
            // (UNDERRUN/OVERRUN, bits 18/17) that a data-less CMD38 never
            // reports.
            let kernel_r1_status = 0xFFF9_A000u32;
            assert_eq!(
                CARD_STATUS_ERASE_ERRORS, kernel_r1_status,
                "must be exactly the kernel's R1_STATUS mask"
            );
            // R1_ERROR (bit 19) is part of R1_STATUS itself.
            assert_ne!(kernel_r1_status & (1 << 19), 0);
            // Every bit of the kernel's CMD_ERRORS (block.c:
            // OUT_OF_RANGE, ADDRESS_ERROR, BLOCK_LEN_ERROR, WP_VIOLATION,
            // CARD_ECC_FAILED, CC_ERROR, R1_ERROR) is inside the mask.
            let cmd_errors =
                (1 << 31) | (1 << 30) | (1 << 29) | (1 << 26) | (1 << 21) | (1 << 20) | (1 << 19);
            assert_eq!(cmd_errors & !CARD_STATUS_ERASE_ERRORS, 0);
            // The full R1_STATUS bit set (SD Physical Layer Table 4-42).
            assert_eq!(
                CARD_STATUS_ERASE_ERRORS,
                (1 << 31)
                    | (1 << 30)
                    | (1 << 29)
                    | (1 << 28)
                    | (1 << 27)
                    | (1 << 26)
                    | (1 << 25)
                    | (1 << 24)
                    | (1 << 23)
                    | (1 << 22)
                    | (1 << 21)
                    | (1 << 20)
                    | (1 << 19)
                    | (1 << 16)
                    | (1 << 15)
                    | (1 << 13),
                "must cover every erase-related R1 bit"
            );
            assert_eq!(CARD_STATUS_ERASE_ERRORS & (1 << 8), 0);
            assert_eq!(CARD_STATUS_ERASE_ERRORS & ((1 << 18) | (1 << 17)), 0);
        }
    }
}
