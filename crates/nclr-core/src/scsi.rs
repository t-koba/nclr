//! T10 SCSI protocol layer (Phase 2): CDB construction and response parsing.
//!
//! Platform-independent: byte-level construction/parsing is verified with
//! fixture tests (no hardware). The transport (SG_IO) lives in the
//! `nclr-scsi` backend under `#[cfg(target_os = "linux")]`.
//!
//! Reference: T10 SPC-4 (INQUIRY, REPORT SUPPORTED OPERATION CODES,
//! RECEIVE DIAGNOSTIC RESULTS) and SBC-4 (READ CAPACITY, MODE SENSE,
//! SANITIZE, UNMAP, FORMAT UNIT).

use crate::errors::{Error, Result};
use serde::Serialize;

pub const OP_INQUIRY: u8 = 0x12;
pub const OP_READ_CAPACITY_10: u8 = 0x25;
pub const OP_READ_CAPACITY_16: u8 = 0x9E;
pub const OP_FORMAT_UNIT: u8 = 0x04;
pub const OP_UNMAP: u8 = 0x42;
pub const OP_SANITIZE: u8 = 0x48;
pub const OP_RECEIVE_DIAGNOSTIC: u8 = 0x1C;
pub const OP_REPORT_SUPPORTED_OPCODES: u8 = 0xA3;

pub const SA_RSOOC_ALL: u8 = 0x0C;
// SBC-4 5.29: OVERWRITE=01h, BLOCK ERASE=02h, CRYPTO ERASE=03h.
pub const SA_SANITIZE_OVERWRITE: u8 = 0x01;
pub const SA_SANITIZE_BLOCK_ERASE: u8 = 0x02;
pub const SA_SANITIZE_CRYPTO_ERASE: u8 = 0x03;

// linux/scsi/sg.h: SG_DXFER_* are negative values. All three directions
// are used: the controller backend performs host-to-device transfers
// (TO_DEV) for vendor commands, while the scsi backend only sends data-in
// or no-data commands.
pub const SG_DXFER_NONE: i32 = -1;
pub const SG_DXFER_TO_DEV: i32 = -2;
pub const SG_DXFER_FROM_DEV: i32 = -3;

pub const VPD_SERIAL: u8 = 0x80;
pub const VPD_DEVICE_IDENTIFICATION: u8 = 0x83;

/// Page code of the SANITIZE STATUS page in RECEIVE DIAGNOSTIC RESULTS.
pub const PAGE_SANITIZE_STATUS: u8 = 0xC0;

// ---------------------------------------------------------------------------
// CDB construction
// ---------------------------------------------------------------------------

/// INQUIRY (SPC-4 6.4): standard data with optional EVPD pages.
pub fn cdb_inquiry(evpd: bool, page: u8, alloc_len: u16) -> Vec<u8> {
    let mut c = vec![0u8; 6];
    c[0] = OP_INQUIRY;
    if evpd {
        c[1] = 0x01;
        c[2] = page;
    }
    c[3] = (alloc_len >> 8) as u8;
    c[4] = alloc_len as u8;
    c
}

/// READ CAPACITY(16) (SBC-4 5.20): allocation length at bytes 10-11.
pub fn cdb_read_capacity_16(alloc_len: u16) -> Vec<u8> {
    let mut c = vec![0u8; 16];
    c[0] = OP_READ_CAPACITY_16;
    c[1] = 0x10; // service action READ CAPACITY(16)
    c[10] = (alloc_len >> 8) as u8;
    c[11] = alloc_len as u8;
    c
}

/// READ CAPACITY(10) (SBC-4 5.20): byte 8 bit 0 is PMI (bits 7-1 are
/// reserved and zero by initialization); byte 9 is the control byte.
pub fn cdb_read_capacity_10() -> Vec<u8> {
    let mut c = vec![0u8; 10];
    c[0] = OP_READ_CAPACITY_10;
    c[9] = 0x00;
    c
}

/// REPORT SUPPORTED OPERATION CODES (SPC-4 6.31).
/// Reporting option 0: report all supported operation codes. The
/// allocation length is a 32-bit field at bytes 6-9 (SPC-4; the kernel's
/// scsi_report_opcode writes it as one big-endian 32-bit value).
pub fn cdb_rsocc(alloc_len: u32) -> Vec<u8> {
    let mut c = vec![0u8; 12];
    c[0] = OP_REPORT_SUPPORTED_OPCODES;
    c[1] = SA_RSOOC_ALL;
    c[6..10].copy_from_slice(&alloc_len.to_be_bytes());
    c
}

/// SANITIZE (SBC-4 5.29): a 10-byte CDB. Byte 1: service action in bits 4-0,
/// IMMED in bit 7 (0x80); bytes 7-8 carry the parameter list length (0 for
/// block/crypto erase). `immed` starts the long-running operation and
/// returns immediately; completion is queried via the SANITIZE STATUS page.
pub fn cdb_sanitize(service_action: u8, immed: bool) -> Vec<u8> {
    let mut c = vec![0u8; 10];
    c[0] = OP_SANITIZE;
    c[1] = service_action;
    if immed {
        c[1] |= 0x80; // IMMED
    }
    c
}

/// RECEIVE DIAGNOSTIC RESULTS (SPC-4 6.15) requesting the SANITIZE STATUS
/// page (SBC-4 5.29.4). Byte 1 bit 0 is PCV; byte 2 is the page code.
pub fn cdb_receive_diag_sanitize_status(alloc_len: u16) -> Vec<u8> {
    let mut c = vec![0u8; 6];
    c[0] = OP_RECEIVE_DIAGNOSTIC;
    c[1] = 0x01; // PCV
    c[2] = PAGE_SANITIZE_STATUS;
    c[3] = (alloc_len >> 8) as u8;
    c[4] = alloc_len as u8;
    c
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parsed INQUIRY standard data.
#[derive(Debug, Clone, Default, Serialize)]
pub struct Inquiry {
    pub peripheral: u8,
    pub version: u8,
    pub response_data_format: u8,
    pub vendor_id: String,
    pub product_id: String,
    pub product_rev: String,
    pub serial_number: String,
    /// Designator strings collected from VPD page 0x83 (addressable, not
    /// the ASCII vendor designator).
    pub designators: Vec<String>,
}

/// Parse INQUIRY standard data (36 or 96 bytes).
pub fn parse_inquiry(data: &[u8]) -> Result<Inquiry> {
    if data.len() < 36 {
        return Err(Error::Invalid(format!(
            "INQUIRY response too short: {} bytes",
            data.len()
        )));
    }
    let vendor = bytes_to_ascii(&data[8..16]);
    let product = bytes_to_ascii(&data[16..32]);
    let rev = bytes_to_ascii(&data[32..36]);
    Ok(Inquiry {
        peripheral: data[0] & 0x1F,
        version: data[2],
        response_data_format: data[3] & 0x0F,
        vendor_id: vendor,
        product_id: product,
        product_rev: rev,
        serial_number: String::new(),
        designators: Vec::new(),
    })
}

fn bytes_to_ascii(data: &[u8]) -> String {
    data.iter()
        .map(|b| {
            if (0x20..=0x7E).contains(b) {
                *b as char
            } else {
                ' '
            }
        })
        .collect::<String>()
        .trim()
        .to_string()
}

/// Parse VPD page 0x80 (unit serial number). Layout: peripheral(1), page
/// code 0x80(1), page length(2, BE), then the serial number string.
pub fn parse_vpd_serial(data: &[u8]) -> Result<String> {
    if data.len() < 4 || data[1] != VPD_SERIAL {
        return Err(Error::Invalid("not a VPD 0x80 page".into()));
    }
    let len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if 4 + len > data.len() {
        return Err(Error::Invalid("VPD 0x80 length mismatch".into()));
    }
    Ok(bytes_to_ascii(&data[4..4 + len]))
}

/// Parse VPD page 0x83 (device identification) into designator strings.
/// Layout: peripheral(1), page code 0x83(1), page length(2, BE), then a
/// sequence of designators: [protocol id/code set | PIV | ASSOCIATION |
///  designator type | designator length | designator...].
pub fn parse_vpd_designators(data: &[u8]) -> Result<Vec<String>> {
    if data.len() < 4 || data[1] != VPD_DEVICE_IDENTIFICATION {
        return Err(Error::Invalid("not a VPD 0x83 page".into()));
    }
    let page_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    if 4 + page_len > data.len() {
        return Err(Error::Invalid("VPD 0x83 length mismatch".into()));
    }
    let mut out = Vec::new();
    let mut off = 4usize;
    let end = 4 + page_len;
    while off + 4 <= end {
        let dt = data[off + 1] & 0x0F;
        let len = data[off + 3] as usize;
        if off + 4 + len > end {
            return Err(Error::Invalid("VPD 0x83 designator truncated".into()));
        }
        let value = bytes_to_ascii(&data[off + 4..off + 4 + len]);
        // Skip the 0x01 type (T10 vendor specific ASCII) which duplicates
        // the vendor ID; keep the others.
        if dt != 0x01 && !value.is_empty() {
            out.push(format!("type-{dt}:{value}"));
        }
        off += 4 + len;
    }
    Ok(out)
}

/// A command descriptor reported by RSOOC (reporting option 0).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupportedCommand {
    pub opcode: u8,
    pub cdb_length: u16,
    pub service_action: u16,
    /// SERVACTV: when false, the descriptor covers all service actions.
    pub servactv: bool,
}

/// Parse a REPORT SUPPORTED OPERATION CODES response (reporting option 0,
/// RCTD unset). All-commands descriptors are 8 bytes, or 20 bytes when the
/// command-time-descriptor-present (CTDP, byte 5 bit 1) bit is set
/// (SPC-4; the descriptor carries per-command timeout data in that case).
/// Layout: [opcode(0), reserved(1), SA(2), reserved(2),
///  bits: CTDP|SERVACTV(1), CDB LENGTH(2, BE)].
pub fn parse_rsocc(data: &[u8]) -> Result<Vec<SupportedCommand>> {
    if data.len() < 4 {
        return Err(Error::Invalid("RSOOC response too short".into()));
    }
    // The COMMAND DATA LENGTH is a 32-bit field at bytes 0-3 in the SPC-4
    // all-commands format (the SUPPORTED/SUPPORT byte exists only in the
    // one-command format). sg3_utils reads the same 32-bit value, so the
    // header is consumed as one big-endian integer.
    let len = u32::from_be_bytes([data[0], data[1], data[2], data[3]]) as usize;
    // The length is checked against the actual response (saturating so a
    // malicious length can never wrap on 32-bit targets).
    if len > data.len().saturating_sub(4) {
        return Err(Error::Invalid("RSOOC length mismatch".into()));
    }
    let end = 4usize + len;
    let mut out = Vec::new();
    let mut off = 4usize;
    while off + 8 <= end {
        let opcode = data[off];
        let sa = u16::from_be_bytes([data[off + 2], data[off + 3]]);
        let servactv = data[off + 5] & 0x01 != 0;
        let ctdp = data[off + 5] & 0x02 != 0;
        let cdb_len = u16::from_be_bytes([data[off + 6], data[off + 7]]);
        out.push(SupportedCommand {
            opcode,
            cdb_length: cdb_len,
            service_action: sa,
            servactv,
        });
        // CTDP descriptors carry timeout data and are 20 bytes long; skip
        // the extra fields so the next descriptor starts at the right
        // offset even on non-conforming devices.
        let desc_len = if ctdp { 20 } else { 8 };
        if off + desc_len > end {
            return Err(Error::Invalid(
                "RSOOC descriptor truncated (CTDP length mismatch)".into(),
            ));
        }
        off += desc_len;
    }
    // A declared length that is not an exact multiple of the descriptor
    // size leaves a ragged tail (1..7 bytes for 8-byte descriptors): a
    // truncated descriptor must not be silently dropped, so reject it.
    if off != end {
        return Err(Error::Invalid(
            "RSOOC descriptor boundary mismatch (ragged tail)".into(),
        ));
    }
    Ok(out)
}

/// Whether the device reports support for a command (and optional service
/// action). A descriptor with SERVACTV=0 covers all service actions.
pub fn rsocc_supports(list: &[SupportedCommand], opcode: u8, service_action: Option<u16>) -> bool {
    list.iter().any(|c| {
        if c.opcode != opcode {
            return false;
        }
        match service_action {
            Some(sa) => !c.servactv || c.service_action == sa,
            None => true,
        }
    })
}

/// SANITIZE STATUS page progress (per-mille) and completion state.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SanitizeStatus {
    /// Progress 0..=1000 (per-mille); None while sanitize has not started.
    pub progress: Option<u32>,
    pub completed: bool,
    /// Device reported sanitize failure (SBC-4 SANITIZE FAILED bit).
    pub failed: bool,
    pub in_progress: bool,
}

/// Parse the SANITIZE STATUS page (SBC-4) returned by RECEIVE DIAGNOSTIC
/// RESULTS with page code 0xC0.
/// Layout: page code(1), page length(1), capabilities(4), reserved(1),
/// interrupt reason(1), reserved(1), SANITIZE PROGRESS (3 bytes, per-mille,
/// bytes 9..12), byte 12: bit 0 SANITIZE COMPLETED, bit 1 SANITIZE FAILED.
/// (The exact offsets must be confirmed against a real device during Linux
/// hardware validation.)
pub fn parse_sanitize_status(data: &[u8]) -> Result<SanitizeStatus> {
    if data.len() < 13 || data[0] != PAGE_SANITIZE_STATUS {
        return Err(Error::Invalid("not a SANITIZE STATUS page".into()));
    }
    let progress =
        (u32::from(data[9] & 0x3F) << 16) | (u32::from(data[10]) << 8) | u32::from(data[11]);
    let completed = data[12] & 0x01 != 0;
    let failed = data[12] & 0x02 != 0;
    Ok(SanitizeStatus {
        progress: Some(progress),
        completed,
        failed,
        in_progress: !completed && !failed && progress < 1000,
    })
}

// ---------------------------------------------------------------------------
// Linux SG_IO transport (shared by the scsi and controller backends)
// ---------------------------------------------------------------------------

/// Linux-only SG_IO passthrough on a block or sg fd.
#[cfg(target_os = "linux")]
pub mod sg {
    use crate::errors::{Error, Result};
    use std::os::fd::AsRawFd;

    /// SG_IO ioctl and the sg_io_hdr structure (linux/scsi/sg.h, 64-bit).
    pub const SG_IO: libc::c_ulong = 0x2285;
    /// The raw SCSI status byte placed in hdr.status by the kernel
    /// (drivers/scsi/scsi_ioctl.c: `hdr->status = scmd->result & 0xff`).
    /// CHECK CONDITION is 0x02 per the SCSI standards; note that
    /// linux/scsi/sg.h's own `CHECK_CONDITION 0x01` is a legacy shifted
    /// encoding that must not be used here.
    pub const SG_CHECK_CONDITION: u8 = 0x02;
    /// hdr.info flag: masked_status, host_status or driver_status is set.
    pub const SG_INFO_CHECK: u32 = 0x1;
    /// Fixed prefix of CHECK CONDITION errors; callers distinguish a device
    /// rejection from a transport failure (which must never be retried) by
    /// this prefix instead of parsing the message text.
    pub const CHECK_CONDITION_PREFIX: &str = "SCSI CHECK CONDITION";

    /// Whether an SG_IO error is a CHECK CONDITION (device rejection)
    /// rather than a transport failure (timeout, reset, ...). This matches
    /// the Error variant's message field directly: the Display string
    /// carries an "device I/O: " prefix, so string comparison against the
    /// rendered error would never match.
    pub fn is_check_condition(e: &crate::errors::Error) -> bool {
        matches!(
            e,
            crate::errors::Error::Io(m, _) if m.starts_with(CHECK_CONDITION_PREFIX)
        )
    }

    #[repr(C)]
    pub struct SgIoHdr {
        pub interface_id: i32,
        pub dxfer_direction: i32,
        pub cmd_len: u8,
        pub mx_sb_len: u8,
        pub iovec_count: u16,
        pub dxfer_len: u32,
        pub dxferp: *mut std::ffi::c_void,
        pub cmdp: *mut u8,
        pub sbp: *mut u8,
        pub timeout: u32,
        pub flags: u32,
        pub pack_id: i32,
        pub usr_ptr: *mut std::ffi::c_void,
        pub status: u8,
        pub masked_status: u8,
        pub msg_status: u8,
        pub sb_len_wr: u8,
        pub host_status: u16,
        pub driver_status: u16,
        pub resid: i32,
        pub duration: u32,
        pub info: u32,
    }

    /// Execute a SCSI command with an optional data buffer and an explicit
    /// ioctl timeout in milliseconds (a blocking SANITIZE needs far more
    /// than the 60 s used for short commands).
    pub fn exec(
        file: &std::fs::File,
        cdb: &[u8],
        direction: i32,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> Result<()> {
        exec_len(file, cdb, direction, data, timeout_ms).map(|_| ())
    }

    /// Execute a SCSI command and return the actual transfer length after
    /// validating the kernel-reported residual count.
    pub fn exec_len(
        file: &std::fs::File,
        cdb: &[u8],
        direction: i32,
        data: &mut [u8],
        timeout_ms: u32,
    ) -> Result<usize> {
        let mut hdr = SgIoHdr {
            interface_id: b'S' as i32,
            dxfer_direction: direction,
            cmd_len: cdb.len() as u8,
            mx_sb_len: 96,
            iovec_count: 0,
            dxfer_len: data.len() as u32,
            dxferp: if data.is_empty() {
                std::ptr::null_mut()
            } else {
                data.as_mut_ptr() as *mut std::ffi::c_void
            },
            cmdp: cdb.as_ptr() as *mut u8,
            sbp: std::ptr::null_mut(),
            timeout: timeout_ms,
            flags: 0,
            pack_id: 0,
            usr_ptr: std::ptr::null_mut(),
            status: 0,
            masked_status: 0,
            msg_status: 0,
            sb_len_wr: 0,
            host_status: 0,
            driver_status: 0,
            resid: 0,
            duration: 0,
            info: 0,
        };
        let mut sense = [0u8; 96];
        hdr.sbp = sense.as_mut_ptr();
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), SG_IO, &mut hdr) };
        if rc < 0 {
            return Err(Error::io(
                "SG_IO ioctl failed (is this a SCSI block device?)",
                Some(std::io::Error::last_os_error()),
            ));
        }
        // A transport failure is visible via host_status/driver_status and
        // the SG_INFO_CHECK flag even when the SCSI status byte is 0
        // (e.g. DID_TIME_OUT leaves status=0 and host_status set).
        if hdr.status != 0
            || hdr.host_status != 0
            || hdr.driver_status != 0
            || hdr.info & SG_INFO_CHECK != 0
        {
            let msg = if hdr.status == SG_CHECK_CONDITION {
                format!(
                    "{CHECK_CONDITION_PREFIX}: sense {:02x?}",
                    &sense[..hdr.sb_len_wr as usize]
                )
            } else if hdr.host_status != 0 {
                format!(
                    "SCSI transport error: host_status 0x{:04x} driver_status 0x{:04x} info 0x{:x}",
                    hdr.host_status, hdr.driver_status, hdr.info
                )
            } else {
                format!(
                    "SCSI status 0x{:02x} masked 0x{:02x} info 0x{:x}",
                    hdr.status, hdr.masked_status, hdr.info
                )
            };
            return Err(Error::io(msg, None));
        }
        if hdr.resid < 0 || hdr.resid as usize > data.len() {
            return Err(Error::Invalid(format!(
                "SG_IO returned invalid residual {} for {} transferred bytes",
                hdr.resid,
                data.len()
            )));
        }
        Ok(data.len() - hdr.resid as usize)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inquiry_cdb_bytes() {
        assert_eq!(
            cdb_inquiry(false, 0, 96),
            vec![0x12, 0x00, 0x00, 0x00, 0x60, 0x00]
        );
        assert_eq!(
            cdb_inquiry(true, VPD_SERIAL, 252),
            vec![0x12, 0x01, 0x80, 0x00, 0xFC, 0x00]
        );
    }

    #[test]
    fn sanitize_cdb_bytes() {
        // BLOCK ERASE, blocking (no IMMED): 10-byte CDB.
        assert_eq!(
            cdb_sanitize(SA_SANITIZE_BLOCK_ERASE, false),
            vec![0x48, 0x02, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        // BLOCK ERASE with IMMED: bit 7 of byte 1.
        let c = cdb_sanitize(SA_SANITIZE_BLOCK_ERASE, true);
        assert_eq!(c.len(), 10);
        assert_eq!(c[1], 0x82);
        // CRYPTO ERASE.
        assert_eq!(cdb_sanitize(SA_SANITIZE_CRYPTO_ERASE, false)[1], 0x03);
        // OVERWRITE.
        assert_eq!(cdb_sanitize(SA_SANITIZE_OVERWRITE, false)[1], 0x01);
    }

    #[test]
    fn rsocc_cdb_and_parse() {
        let cdb = cdb_rsocc(65535);
        assert_eq!(cdb[0], 0xA3);
        assert_eq!(cdb[1], 0x0C);
        // SPC-4: allocation length is a 32-bit field at bytes 6-9.
        assert_eq!(&cdb[6..10], &[0x00, 0x00, 0xFF, 0xFF]);

        // Fixture: supports INQUIRY (6-byte CDB), READ CAPACITY(10),
        // SANITIZE (10-byte CDB, SA 0x02) and UNMAP (10-byte CDB).
        let mut resp = vec![0u8; 4];
        let descs: Vec<Vec<u8>> = vec![
            // opcode 0x12, CDB length 6, no SA
            vec![0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06],
            // opcode 0x25, CDB length 10
            vec![0x25, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A],
            // opcode 0x42, CDB length 10
            vec![0x42, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0A],
            // opcode 0x48, CDB length 10, SA 0x0002, SERVACTV set
            vec![0x48, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x0A],
            // opcode 0x91, CDB length 16, SERVACTV clear: all SAs
            vec![0x91, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10],
        ];
        let body: Vec<u8> = descs.iter().flatten().cloned().collect();
        let len = body.len() as u16;
        resp[2..4].copy_from_slice(&len.to_be_bytes());
        resp.extend_from_slice(&body);

        let list = parse_rsocc(&resp).unwrap();
        assert_eq!(list.len(), 5);
        assert_eq!(list[0].cdb_length, 6);
        assert_eq!(list[3].cdb_length, 10);
        assert!(rsocc_supports(&list, OP_INQUIRY, None));
        assert!(rsocc_supports(&list, OP_READ_CAPACITY_10, None));
        assert!(rsocc_supports(
            &list,
            OP_SANITIZE,
            Some(SA_SANITIZE_BLOCK_ERASE as u16)
        ));
        assert!(!rsocc_supports(&list, OP_SANITIZE, Some(0x99)));
        assert!(!rsocc_supports(&list, 0x9E, None)); // READ CAPACITY(16) absent
        assert!(rsocc_supports(&list, OP_UNMAP, None));
        assert!(!rsocc_supports(&list, OP_FORMAT_UNIT, None));
        // SERVACTV=0 descriptor covers every service action.
        assert!(rsocc_supports(&list, 0x91, Some(0x0000)));
        assert!(rsocc_supports(&list, 0x91, Some(0x1234)));
    }

    #[test]
    fn rsocc_ctdp_descriptor_length() {
        // A CTDP=1 (byte 5 bit 1) descriptor is 20 bytes: a normal 8-byte
        // descriptor followed by one 20-byte descriptor must parse both.
        let mut resp = vec![0u8; 4];
        let d0 = [0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06];
        let mut d1 = vec![0x48, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x0A];
        d1.extend_from_slice(&[0u8; 12]); // timeout data tail
        let body: Vec<u8> = d0.iter().chain(d1.iter()).cloned().collect();
        let len = body.len() as u16;
        resp[2..4].copy_from_slice(&len.to_be_bytes());
        resp.extend_from_slice(&body);
        let list = parse_rsocc(&resp).unwrap();
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].opcode, OP_INQUIRY);
        assert_eq!(list[1].opcode, OP_SANITIZE);
        assert_eq!(list[1].cdb_length, 10);
        assert!(rsocc_supports(
            &list,
            OP_SANITIZE,
            Some(SA_SANITIZE_BLOCK_ERASE as u16)
        ));
    }

    #[test]
    fn rsocc_ctdp_truncated_is_rejected() {
        // A CTDP=1 descriptor that is cut off (fewer than 20 bytes left)
        // must be rejected, not mis-parsed as an 8-byte descriptor.
        let mut resp = vec![0u8; 4];
        let d1 = vec![0x48, 0x00, 0x00, 0x02, 0x00, 0x03, 0x00, 0x0A, 0x00, 0x00];
        resp[2..4].copy_from_slice(&(d1.len() as u16).to_be_bytes());
        resp.extend_from_slice(&d1);
        assert!(parse_rsocc(&resp).is_err());
    }

    #[test]
    fn rsocc_nonzero_prefix_is_rejected_as_length_mismatch() {
        // The length is read as one 32-bit big-endian value over bytes 0-3
        // (parity with sg3_utils). A nonzero SUPPORTED/reserved prefix
        // inflates the length beyond the response, which must be rejected
        // rather than mis-parsed; bytes 0-1 are zero on conforming devices.
        let mut resp = vec![0u8; 4];
        let d0 = [0x12u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06];
        resp[0] = 0x01; // SUPPORTED byte
        resp[1] = 0x02; // reserved byte
        resp[2..4].copy_from_slice(&(d0.len() as u16).to_be_bytes());
        resp.extend_from_slice(&d0);
        assert!(parse_rsocc(&resp).is_err());
    }

    #[test]
    fn rsocc_short_response_is_rejected() {
        // A response shorter than the 4-byte header is rejected outright.
        for len in 0..4 {
            assert!(parse_rsocc(&vec![0u8; len]).is_err());
        }
    }

    #[test]
    fn rsocc_ragged_tail_is_rejected() {
        // A declared length that leaves a partial descriptor at the end
        // (an 8-byte descriptor plus a 4-byte tail) must be rejected, not
        // silently dropped.
        let mut resp = vec![0u8; 4];
        let d0 = [0x12u8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06];
        let mut body: Vec<u8> = d0.to_vec();
        body.extend_from_slice(&[0u8; 4]); // ragged tail
        resp[2..4].copy_from_slice(&(body.len() as u16).to_be_bytes());
        resp.extend_from_slice(&body);
        assert!(parse_rsocc(&resp).is_err());
    }

    #[test]
    fn inquiry_parse_fixture() {
        // 96-byte standard inquiry from a USB mass storage device.
        let mut data = vec![0u8; 96];
        data[0] = 0x00; // direct access block device
        data[2] = 0x06; // SPC-4-ish
        data[3] = 0x02; // response data format 2
        data[8..16].copy_from_slice(b"ACME    ");
        data[16..32].copy_from_slice(b"FLASH DRIVE     ");
        data[32..36].copy_from_slice(b"1.00");
        let i = parse_inquiry(&data).unwrap();
        assert_eq!(i.peripheral, 0x00);
        assert_eq!(i.vendor_id, "ACME");
        assert_eq!(i.product_id, "FLASH DRIVE");
        assert_eq!(i.product_rev, "1.00");
        assert_eq!(i.version, 0x06);
    }

    #[test]
    fn vpd_serial_fixture() {
        let mut data = vec![0u8; 8];
        data[0] = 0x00; // PQ|PDT
        data[1] = VPD_SERIAL;
        data[2..4].copy_from_slice(&4u16.to_be_bytes());
        data[4..8].copy_from_slice(b"1234");
        assert_eq!(parse_vpd_serial(&data).unwrap(), "1234");
    }

    #[test]
    fn vpd_83_fixture() {
        // T10 vendor specific (0x01) + NAA (0x03) designators.
        let d1 = [0x00, 0x01, 0x01, 0x04, b'A', b'C', b'M', b'E'];
        let d2 = [
            0x20, 0x03, 0x00, 0x08, 0x50, 0x00, 0x53, 0x01, 0x02, 0x03, 0x04, 0x05,
        ];
        let mut data = vec![0u8; 4];
        data[0] = 0x00; // PQ|PDT
        data[1] = VPD_DEVICE_IDENTIFICATION;
        let body: Vec<u8> = d1.iter().chain(d2.iter()).cloned().collect();
        data[2..4].copy_from_slice(&(body.len() as u16).to_be_bytes());
        data.extend_from_slice(&body);
        let desigs = parse_vpd_designators(&data).unwrap();
        assert_eq!(desigs.len(), 1, "type 0x01 must be skipped: {desigs:?}");
        assert!(desigs[0].starts_with("type-3:"));
    }

    #[test]
    fn sanitize_status_fixture() {
        // Mid-progress: 50.0%.
        let mut data = vec![0u8; 64];
        data[0] = PAGE_SANITIZE_STATUS;
        data[1] = 62;
        data[9] = 0x00;
        data[10] = 0x01;
        data[11] = 0xF4; // 0x01F4 = 500 per-mille
        let s = parse_sanitize_status(&data).unwrap();
        assert_eq!(s.progress, Some(500));
        assert!(!s.completed);
        assert!(s.in_progress);

        // Completed: progress 1000 and COMPLETED bit set.
        data[9] = 0x00;
        data[10] = 0x03;
        data[11] = 0xE8;
        data[12] = 0x01;
        let s = parse_sanitize_status(&data).unwrap();
        assert_eq!(s.progress, Some(1000));
        assert!(s.completed);
        assert!(!s.failed);
        assert!(!s.in_progress);

        // Failed: SANITIZE FAILED bit set.
        data[9] = 0x00;
        data[10] = 0x00;
        data[11] = 0x00;
        data[12] = 0x02;
        let s = parse_sanitize_status(&data).unwrap();
        assert!(!s.completed);
        assert!(s.failed);
        assert!(!s.in_progress);
    }

    #[test]
    fn read_capacity_cdbs() {
        let c10 = cdb_read_capacity_10();
        assert_eq!(c10[0], 0x25);
        assert_eq!(c10[8], 0x00); // reserved must be clear (PMI is bit 0)
        let c16 = cdb_read_capacity_16(32);
        assert_eq!(c16[0], 0x9E);
        assert_eq!(c16[1], 0x10);
        assert_eq!(c16[10], 0x00);
        assert_eq!(c16[11], 32);
    }

    #[test]
    fn receive_diag_sanitize_cdb() {
        let c = cdb_receive_diag_sanitize_status(64);
        assert_eq!(c[0], 0x1C);
        assert_eq!(c[1], 0x01); // PCV
        assert_eq!(c[2], PAGE_SANITIZE_STATUS);
        assert_eq!(c[4], 64);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn check_condition_classification() {
        use crate::errors::Error;
        // The Display string carries a prefix; classification must match
        // the message field, not the rendered text.
        let cc = Error::io(
            format!("{CHECK_CONDITION_PREFIX}: sense [70 00 05 00 00 00 00 0a]"),
            None,
        );
        assert!(super::sg::is_check_condition(&cc));
        assert!(cc.to_string().starts_with("device I/O: "));
        let transport = Error::io(
            "SCSI transport error: host_status 0x0003 driver_status 0x0000 info 0x1".to_string(),
            None,
        );
        assert!(!super::sg::is_check_condition(&transport));
    }
}
