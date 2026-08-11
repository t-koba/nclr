//! Sim backend NAND model.
//!
//! A sim image is a regular file with a fixed header, a per-block table and
//! a sparse page-data area. It models: FBB, old RBB, OP/spare pool, obsolete
//! stale data, erase/program/read failure injection, capacity alias across
//! power cycles, an internal power-cycle, a self-running SANITIZE, and the
//! controller reinitialization path (BBT capture, per-RBB erase, PROGRAM/
//! READ/ECC qualification, new BBT/FTL/spare rebuild, service mode with
//! re-enumeration and capacity reduction).
//!
//! File layout (explicit little-endian, version 2):
//! ```text
//! [0..8)     magic "NCLRSIM1"
//! [8..12)    version u32
//! [12..16)   blocks u32
//! [16..20)   pages_per_block u32
//! [20..24)   page_bytes u32
//! [24..28)   user_blocks u32
//! [28..32)   op_blocks u32
//! [32..36)   fbb_count u32
//! [36..40)   rbb_count u32
//! [40..104)  id [64] (padded)
//! [104..108) flags u32 (bit0 = capacity_alias, bit1 = no_sanitize,
//!             bit2 = sanitize_fail, bit3 = no_controller)
//! [108..116) power_cycles u64
//! [116..120) sanitize_state u32
//! [120..128) sanitize_done u64
//! [128..136) sanitize_total u64
//! [136..168) controller_id [32]
//! [168..200) firmware [32]
//! [200..232) nand_id [32]
//! [232..240) bbt_generation u64
//! [240..248) ftl_generation u64
//! [248..252) service_mode u32 (0 normal, 1 in-service)
//! [252..256) reserved u32
//! [256..264) new_user_blocks u64 (0 = not committed by a rebuild)
//! [264..268) ecc_strength u32
//! [268..272) ecc_min_margin u32
//! [272..276) protected_area_blocks u32
//! [276..280) reserved u32
//! [280..288) pe_cycles u64
//! [288..512) reserved
//! [512..512+blocks*8) block table: u8 state, u8 inject, u16 corrected_bits,
//!                     u8 qual_flags, u8 read_retries, u8 latency, u8 reserved
//! [data area)  per block: pages_per_block * page_bytes
//! ```

use crate::device::{SimInfo, SIM_MAGIC};
use crate::errors::{Error, Result};
use crate::lba::Prbs;
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::Path;

pub const HEADER_SIZE: u64 = 512;
pub const BLOCK_TABLE_ENTRY: u64 = 8;

pub const STATE_ERASED: u8 = 0;
pub const STATE_FBB: u8 = 1;
pub const STATE_OLD_RBB: u8 = 2;
pub const STATE_ERASE_FAILED: u8 = 3;
pub const STATE_QUARANTINED: u8 = 4;
pub const STATE_OBSOLETE: u8 = 5;
pub const STATE_UNKNOWN: u8 = 6;

pub const INJ_ERASE: u8 = 0x01;
pub const INJ_PROGRAM: u8 = 0x02;
pub const INJ_READ: u8 = 0x04;

pub const QUAL_WEAK: u8 = 0x01;
pub const QUAL_QUARANTINED: u8 = 0x02;

const FLAG_CAPACITY_ALIAS: u32 = 0x0000_0001;
const FLAG_NO_SANITIZE: u32 = 0x0000_0002;
const FLAG_SANITIZE_FAIL: u32 = 0x0000_0004;
const FLAG_NO_CONTROLLER: u32 = 0x0000_0008;
const FLAG_FAIL_FTL_COMMIT: u32 = 0x0000_0010;
const FLAG_FAIL_SERVICE_EXIT: u32 = 0x0000_0020;

/// Header-resident sanitize state (a self-running operation that survives
/// process death).
const OFF_SANITIZE_STATE: u64 = 116;
const OFF_SANITIZE_DONE: u64 = 120;
const OFF_SANITIZE_TOTAL: u64 = 128;
const OFF_CONTROLLER_ID: u64 = 136;
const OFF_FIRMWARE: u64 = 168;
const OFF_NAND_ID: u64 = 200;
const OFF_BBT_GENERATION: u64 = 232;
const OFF_FTL_GENERATION: u64 = 240;
const OFF_SERVICE_MODE: u64 = 248;
const OFF_NEW_USER_BLOCKS: u64 = 256;
const OFF_ECC_STRENGTH: u64 = 264;
const OFF_ECC_MIN_MARGIN: u64 = 268;
const OFF_PROTECTED_BLOCKS: u64 = 272;
const OFF_PE_CYCLES: u64 = 280;

pub const SANITIZE_IDLE: u32 = 0;
pub const SANITIZE_IN_PROGRESS: u32 = 1;
pub const SANITIZE_COMPLETED: u32 = 2;
pub const SANITIZE_FAILED: u32 = 3;

/// Sanitize progress chunk per status poll (simulated background progress).
const SANITIZE_TICK: u64 = 4;

/// Blank value after an erase (erased NAND state).
pub const BLANK_VALUE: u8 = 0xFF;

/// Fixed system/reserved blocks (BBT copy etc.) in the sim model.
pub const SIM_RESERVED_BLOCKS: u64 = 1;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SimSpec {
    pub id: String,
    pub blocks: u32,
    pub pages_per_block: u32,
    pub page_bytes: u32,
    pub user_blocks: u32,
    pub op_blocks: u32,
    pub fbb: Vec<u32>,
    pub old_rbb: Vec<u32>,
    pub fail_erase: Vec<u32>,
    pub fail_program: Vec<u32>,
    pub fail_read: Vec<u32>,
    pub capacity_alias: bool,
    /// Write a stale MBR-like signature at LBA 0 to prove it is removed.
    pub stale_mbr: bool,
    /// Device-level erase (SANITIZE-like) is available on this device.
    pub sanitize: bool,
    /// The device's self-running sanitize fails partway (fault injection).
    pub sanitize_fail: bool,
    /// Controller reinitialization is available on this device.
    pub controller: bool,
    pub controller_id: String,
    pub firmware: String,
    pub nand_id: String,
    /// Blocks whose corrected-bit count makes them ECC-weak.
    pub ecc_corrupt: Vec<u32>,
    /// Explicitly weak blocks (quarantined by qualification).
    pub weak_blocks: Vec<u32>,
    pub ecc_strength: u32,
    pub ecc_min_margin: u32,
    /// The FTL commit fails (fault injection).
    pub fail_ftl_commit: bool,
    /// Service-mode exit fails and needs recovery (fault injection).
    pub fail_service_exit: bool,
    /// Blocks whose reservation category cannot be determined (left
    /// untouched; residual unknown-scope).
    pub unknown_reservation: Vec<u32>,
    /// SD Protected Area (D5) equivalent: the last N blocks are reserved and
    /// inaccessible without authentication; they are never erased.
    pub protected_area_blocks: u32,
}

impl Default for SimSpec {
    fn default() -> Self {
        SimSpec {
            id: "sim-test-001".into(),
            blocks: 64,
            pages_per_block: 8,
            page_bytes: 512,
            user_blocks: 56,
            op_blocks: 4,
            fbb: vec![2, 5],
            old_rbb: vec![10, 20, 30],
            fail_erase: Vec::new(),
            fail_program: Vec::new(),
            fail_read: Vec::new(),
            capacity_alias: false,
            stale_mbr: true,
            sanitize: true,
            sanitize_fail: false,
            controller: true,
            controller_id: "sim-ctlr-01".into(),
            firmware: "3.2".into(),
            nand_id: "SIMNAND-1".into(),
            ecc_corrupt: Vec::new(),
            weak_blocks: Vec::new(),
            ecc_strength: 40,
            ecc_min_margin: 8,
            fail_ftl_commit: false,
            fail_service_exit: false,
            unknown_reservation: Vec::new(),
            protected_area_blocks: 0,
        }
    }
}

fn put_u32(buf: &mut [u8], off: usize, v: u32) {
    buf[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn get_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(buf[off..off + 4].try_into().expect("slice"))
}

fn get_u64(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(buf[off..off + 8].try_into().expect("slice"))
}

fn put_u64(buf: &mut [u8], off: usize, v: u64) {
    buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

fn put_str(buf: &mut [u8], off: usize, max: usize, s: &str) {
    let bytes = s.as_bytes();
    let n = bytes.len().min(max);
    buf[off..off + n].copy_from_slice(&bytes[..n]);
}

fn get_str(buf: &[u8], off: usize, max: usize) -> String {
    let mut v = buf[off..off + max].to_vec();
    while v.last() == Some(&0) {
        v.pop();
    }
    String::from_utf8_lossy(&v).into_owned()
}

fn block_table_offset() -> u64 {
    HEADER_SIZE
}

fn block_data_offset(block: u32, blocks: u32, pages_per_block: u32, page_bytes: u32) -> u64 {
    block_table_offset()
        + (blocks as u64) * BLOCK_TABLE_ENTRY
        + (block as u64) * (pages_per_block as u64) * (page_bytes as u64)
}

/// Create a new sim image at `path`.
pub fn create(path: &Path, spec: &SimSpec) -> Result<()> {
    // Geometry validation: degenerate specs would produce division by zero
    // or overlapping regions downstream.
    if spec.blocks == 0 {
        return Err(Error::Invalid("sim spec: blocks must be > 0".into()));
    }
    if spec.pages_per_block == 0 {
        return Err(Error::Invalid(
            "sim spec: pages_per_block must be > 0".into(),
        ));
    }
    if spec.page_bytes == 0 {
        return Err(Error::Invalid("sim spec: page_bytes must be > 0".into()));
    }
    if spec.user_blocks as u64 + spec.op_blocks as u64 > spec.blocks as u64 {
        return Err(Error::Invalid(
            "sim spec: user_blocks + op_blocks exceed blocks".into(),
        ));
    }
    if spec.protected_area_blocks > spec.blocks {
        return Err(Error::Invalid(
            "sim spec: protected_area_blocks exceed blocks".into(),
        ));
    }
    let mut f = OpenOptions::new()
        .create(true)
        .truncate(true)
        .read(true)
        .write(true)
        .open(path)
        .map_err(|e| Error::io(format!("create sim image {}", path.display()), Some(e)))?;

    let mut header = vec![0u8; HEADER_SIZE as usize];
    header[..8].copy_from_slice(SIM_MAGIC);
    put_u32(&mut header, 8, 2); // version
    put_u32(&mut header, 12, spec.blocks);
    put_u32(&mut header, 16, spec.pages_per_block);
    put_u32(&mut header, 20, spec.page_bytes);
    put_u32(&mut header, 24, spec.user_blocks);
    put_u32(&mut header, 28, spec.op_blocks);
    put_u32(&mut header, 32, spec.fbb.len() as u32);
    put_u32(&mut header, 36, spec.old_rbb.len() as u32);
    put_str(&mut header, 40, 64, &spec.id);
    let mut flags = 0u32;
    if spec.capacity_alias {
        flags |= FLAG_CAPACITY_ALIAS;
    }
    if !spec.sanitize {
        flags |= FLAG_NO_SANITIZE;
    }
    if spec.sanitize_fail {
        flags |= FLAG_SANITIZE_FAIL;
    }
    if !spec.controller {
        flags |= FLAG_NO_CONTROLLER;
    }
    if spec.fail_ftl_commit {
        flags |= FLAG_FAIL_FTL_COMMIT;
    }
    if spec.fail_service_exit {
        flags |= FLAG_FAIL_SERVICE_EXIT;
    }
    put_u32(&mut header, 104, flags);
    put_u64(&mut header, 108, 0); // power_cycles
    put_u32(&mut header, OFF_SANITIZE_STATE as usize, SANITIZE_IDLE);
    put_u64(&mut header, OFF_SANITIZE_DONE as usize, 0);
    // Total sanitize work: every non-FBB block (D0 + D1 + D2 scope).
    put_u64(
        &mut header,
        OFF_SANITIZE_TOTAL as usize,
        (spec.blocks - spec.fbb.len() as u32) as u64,
    );
    put_str(
        &mut header,
        OFF_CONTROLLER_ID as usize,
        32,
        &spec.controller_id,
    );
    put_str(&mut header, OFF_FIRMWARE as usize, 32, &spec.firmware);
    put_str(&mut header, OFF_NAND_ID as usize, 32, &spec.nand_id);
    put_u64(&mut header, OFF_BBT_GENERATION as usize, 1);
    put_u64(&mut header, OFF_FTL_GENERATION as usize, 1);
    put_u32(&mut header, OFF_SERVICE_MODE as usize, 0);
    put_u64(&mut header, OFF_NEW_USER_BLOCKS as usize, 0);
    put_u32(&mut header, OFF_ECC_STRENGTH as usize, spec.ecc_strength);
    put_u32(
        &mut header,
        OFF_ECC_MIN_MARGIN as usize,
        spec.ecc_min_margin,
    );
    put_u32(
        &mut header,
        OFF_PROTECTED_BLOCKS as usize,
        spec.protected_area_blocks,
    );
    put_u64(&mut header, OFF_PE_CYCLES as usize, 0);
    f.write_all(&header)?;
    f.seek(SeekFrom::Start(block_table_offset()))?;

    // Block table.
    let mut states = vec![STATE_ERASED; spec.blocks as usize];
    for &b in &spec.fbb {
        if (b as usize) < states.len() {
            states[b as usize] = STATE_FBB;
        }
    }
    for &b in &spec.old_rbb {
        if (b as usize) < states.len() {
            states[b as usize] = STATE_OLD_RBB;
        }
    }
    for &b in &spec.unknown_reservation {
        if (b as usize) < states.len() {
            states[b as usize] = STATE_UNKNOWN;
        }
    }
    let inject = |list: &[u32], mask: u8| -> Vec<u8> {
        let mut v = vec![0u8; spec.blocks as usize];
        for &b in list {
            if (b as usize) < v.len() {
                v[b as usize] |= mask;
            }
        }
        v
    };
    let inj_e = inject(&spec.fail_erase, INJ_ERASE);
    let inj_p = inject(&spec.fail_program, INJ_PROGRAM);
    let inj_r = inject(&spec.fail_read, INJ_READ);

    for (i, st) in states.iter().enumerate() {
        // ECC-corrupt blocks start with a corrected-bit count that makes
        // them weak (margin below the profile threshold).
        let cb = if spec.ecc_corrupt.contains(&(i as u32)) {
            (spec.ecc_strength.saturating_sub(2)) as u16
        } else {
            0
        };
        let qual = if spec.weak_blocks.contains(&(i as u32)) {
            QUAL_WEAK
        } else {
            0
        };
        let entry = [
            *st,
            inj_e[i] | inj_p[i] | inj_r[i],
            (cb & 0xFF) as u8,
            (cb >> 8) as u8,
            qual,
            0,
            0,
            0,
        ];
        f.write_all(&entry)?;
    }

    // Stale data: fill the LBA window with 0xA5, old RBB and OP with 0x5A.
    let weak_excluded: Vec<u32> = spec
        .weak_blocks
        .iter()
        .chain(spec.ecc_corrupt.iter())
        .cloned()
        .collect();
    let window = lba_window(&states, spec.user_blocks as u64, &weak_excluded);
    let page_size = (spec.pages_per_block as u64) * (spec.page_bytes as u64);
    for &p in &window {
        let off = block_data_offset(p, spec.blocks, spec.pages_per_block, spec.page_bytes);
        let mut page = vec![0xA5u8; page_size as usize];
        if p == 0 && spec.stale_mbr {
            page[0] = 0xEB;
            page[1] = 0x3C;
            page[2] = 0x90;
            page[54..62].copy_from_slice(b"FAT16   ");
            page[510] = 0x55;
            page[511] = 0xAA;
        }
        f.seek(SeekFrom::Start(off))?;
        f.write_all(&page)?;
    }
    for (i, st) in states.iter().enumerate() {
        if *st == STATE_OLD_RBB || (i as u32) >= spec.user_blocks {
            let off =
                block_data_offset(i as u32, spec.blocks, spec.pages_per_block, spec.page_bytes);
            // Protected Area (D5) blocks hold a distinct stale pattern.
            let fill = if (i as u32) >= spec.blocks - spec.protected_area_blocks {
                0x6Au8
            } else {
                0x5Au8
            };
            let page = vec![fill; page_size as usize];
            f.seek(SeekFrom::Start(off))?;
            f.write_all(&page)?;
        }
    }
    f.sync_all()?;
    Ok(())
}

/// Read the header of an existing sim image.
pub fn read_header(path: &Path) -> Option<SimInfo> {
    let mut f = File::open(path).ok()?;
    let mut header = vec![0u8; HEADER_SIZE as usize];
    f.read_exact(&mut header).ok()?;
    if &header[..8] != SIM_MAGIC {
        return None;
    }
    let version = get_u32(&header, 8);
    if !(1..=2).contains(&version) {
        return None;
    }
    let blocks = get_u32(&header, 12);
    let pages_per_block = get_u32(&header, 16);
    let page_bytes = get_u32(&header, 20);
    let user_blocks = get_u32(&header, 24);
    let new_user_blocks = get_u64(&header, OFF_NEW_USER_BLOCKS as usize);
    let flags = get_u32(&header, 104);
    let power_cycles = get_u64(&header, 108);
    let base = if new_user_blocks > 0 {
        new_user_blocks as u32
    } else {
        user_blocks
    };
    let effective_user = if flags & FLAG_CAPACITY_ALIAS != 0 && power_cycles > 0 {
        base.saturating_sub(1)
    } else {
        base
    };
    Some(SimInfo {
        id: get_str(&header, 40, 64),
        blocks,
        pages_per_block,
        page_bytes,
        user_blocks,
        capacity_bytes: (effective_user as u64) * (pages_per_block as u64) * (page_bytes as u64),
    })
}

/// Physical blocks available to the LBA window: erased blocks, in order,
/// truncated to `user_blocks` (bad/weak blocks are skipped).
fn lba_window(states: &[u8], user_blocks: u64, extra_excluded: &[u32]) -> Vec<u32> {
    let mut out: Vec<u32> = states
        .iter()
        .enumerate()
        .filter(|(i, s)| **s == STATE_ERASED && !extra_excluded.contains(&(*i as u32)))
        .map(|(i, _)| i as u32)
        .collect();
    out.truncate(user_blocks as usize);
    out
}

/// In-memory view over an open sim image.
pub struct SimDevice {
    file: File,
    read_only: bool,
    id: String,
    blocks: u32,
    pages_per_block: u32,
    page_bytes: u32,
    user_blocks: u32,
    states: Vec<u8>,
    inject: Vec<u8>,
    corrected_bits: Vec<u16>,
    qual_flags: Vec<u8>,
    read_retries: Vec<u8>,
    read_latency_ms: Vec<u8>,
    window: Vec<u32>,
    power_cycles: u64,
    capacity_alias: bool,
    no_sanitize: bool,
    sanitize_fail: bool,
    sanitize_state: u32,
    sanitize_done: u64,
    sanitize_total: u64,
    controller_id: String,
    firmware: String,
    nand_id: String,
    bbt_generation: u64,
    ftl_generation: u64,
    service_mode: u32,
    new_user_blocks: u64,
    ecc_strength: u32,
    ecc_min_margin: u32,
    no_controller: bool,
    fail_ftl_commit: bool,
    fail_service_exit: bool,
    protected_area_blocks: u32,
    pe_cycles: u64,
}

impl SimDevice {
    pub fn open(path: &Path) -> Result<SimDevice> {
        // The device fd handed to us by the core may be read-only (probe);
        // retry without write access in that case.
        let (f, read_only) = match OpenOptions::new().read(true).write(true).open(path) {
            Ok(f) => (f, false),
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => (
                File::open(path).map_err(|e| {
                    Error::io(format!("open sim image {}", path.display()), Some(e))
                })?,
                true,
            ),
            Err(e) => {
                return Err(Error::io(
                    format!("open sim image {}", path.display()),
                    Some(e),
                ));
            }
        };
        Self::from_open_file(f, read_only)
    }

    /// Consume the pre-opened device file supplied by the core. Backends use
    /// this constructor so they never reopen a device path (including
    /// `/dev/fd/*`) and retain the core-validated access mode.
    pub fn from_file(f: File) -> Result<SimDevice> {
        let flags = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_GETFL) };
        if flags < 0 {
            return Err(Error::io(
                "read sim device fd flags",
                Some(std::io::Error::last_os_error()),
            ));
        }
        let read_only = flags & libc::O_ACCMODE == libc::O_RDONLY;
        Self::from_open_file(f, read_only)
    }

    fn from_open_file(mut f: File, read_only: bool) -> Result<SimDevice> {
        // The fd is a dup sharing the parent's file offset (which earlier
        // backend invocations may have advanced): always start at 0.
        f.seek(SeekFrom::Start(0))
            .map_err(|e| Error::io("sim image seek", Some(e)))?;
        let mut header = vec![0u8; HEADER_SIZE as usize];
        f.read_exact(&mut header)
            .map_err(|e| Error::io("sim image header", Some(e)))?;
        if &header[..8] != SIM_MAGIC {
            return Err(Error::Invalid("not a sim image".into()));
        }
        let version = get_u32(&header, 8);
        if !(1..=2).contains(&version) {
            return Err(Error::Invalid(format!(
                "unsupported sim image version {version}"
            )));
        }
        let blocks = get_u32(&header, 12);
        let pages_per_block = get_u32(&header, 16);
        let page_bytes = get_u32(&header, 20);
        let user_blocks = get_u32(&header, 24);
        let flags = get_u32(&header, 104);
        let power_cycles = get_u64(&header, 108);
        let sanitize_state = get_u32(&header, OFF_SANITIZE_STATE as usize);
        let sanitize_done = get_u64(&header, OFF_SANITIZE_DONE as usize);
        let sanitize_total = get_u64(&header, OFF_SANITIZE_TOTAL as usize);
        let controller_id = get_str(&header, OFF_CONTROLLER_ID as usize, 32);
        let firmware = get_str(&header, OFF_FIRMWARE as usize, 32);
        let nand_id = get_str(&header, OFF_NAND_ID as usize, 32);
        let bbt_generation = get_u64(&header, OFF_BBT_GENERATION as usize);
        let ftl_generation = get_u64(&header, OFF_FTL_GENERATION as usize);
        let service_mode = get_u32(&header, OFF_SERVICE_MODE as usize);
        let new_user_blocks = get_u64(&header, OFF_NEW_USER_BLOCKS as usize);
        let ecc_strength = get_u32(&header, OFF_ECC_STRENGTH as usize).max(1);
        let ecc_min_margin = get_u32(&header, OFF_ECC_MIN_MARGIN as usize);
        let protected_area_blocks = get_u32(&header, OFF_PROTECTED_BLOCKS as usize);
        let pe_cycles = get_u64(&header, OFF_PE_CYCLES as usize);

        let mut states = vec![STATE_ERASED; blocks as usize];
        let mut inject = vec![0u8; blocks as usize];
        let mut corrected_bits = vec![0u16; blocks as usize];
        let mut qual_flags = vec![0u8; blocks as usize];
        let mut read_retries = vec![0u8; blocks as usize];
        let mut read_latency_ms = vec![0u8; blocks as usize];
        f.seek(SeekFrom::Start(block_table_offset()))?;
        for i in 0..blocks as usize {
            let mut entry = [0u8; BLOCK_TABLE_ENTRY as usize];
            f.read_exact(&mut entry)
                .map_err(|e| Error::io("sim block table", Some(e)))?;
            states[i] = entry[0];
            inject[i] = entry[1];
            corrected_bits[i] = u16::from_le_bytes([entry[2], entry[3]]);
            qual_flags[i] = entry[4];
            read_retries[i] = entry[5];
            read_latency_ms[i] = entry[6];
        }
        let effective_user = if new_user_blocks > 0 {
            new_user_blocks
        } else {
            user_blocks as u64
        };
        let excluded: Vec<u32> = (0..blocks)
            .filter(|i| qual_flags[*i as usize] & (QUAL_WEAK | QUAL_QUARANTINED) != 0)
            .collect();
        let window = lba_window(&states, effective_user, &excluded);
        Ok(SimDevice {
            file: f,
            read_only,
            id: get_str(&header, 40, 64),
            blocks,
            pages_per_block,
            page_bytes,
            user_blocks,
            states,
            inject,
            corrected_bits,
            qual_flags,
            read_retries,
            read_latency_ms,
            window,
            power_cycles,
            capacity_alias: flags & FLAG_CAPACITY_ALIAS != 0,
            no_sanitize: flags & FLAG_NO_SANITIZE != 0,
            sanitize_fail: flags & FLAG_SANITIZE_FAIL != 0,
            sanitize_state,
            sanitize_done,
            sanitize_total,
            controller_id,
            firmware,
            nand_id,
            bbt_generation,
            ftl_generation,
            service_mode,
            new_user_blocks,
            ecc_strength,
            ecc_min_margin,
            no_controller: flags & FLAG_NO_CONTROLLER != 0,
            fail_ftl_commit: flags & FLAG_FAIL_FTL_COMMIT != 0,
            fail_service_exit: flags & FLAG_FAIL_SERVICE_EXIT != 0,
            protected_area_blocks,
            pe_cycles,
        })
    }

    pub fn info(&self) -> SimInfo {
        SimInfo {
            id: self.id.clone(),
            blocks: self.blocks,
            user_blocks: self.user_blocks,
            pages_per_block: self.pages_per_block,
            page_bytes: self.page_bytes,
            capacity_bytes: self.capacity_bytes(),
        }
    }

    // ------------------------------------------------------------------
    // Controller identity and service mode
    // ------------------------------------------------------------------

    pub fn controller_available(&self) -> bool {
        !self.no_controller
    }

    pub fn controller_id(&self) -> &str {
        &self.controller_id
    }

    pub fn firmware(&self) -> &str {
        &self.firmware
    }

    pub fn nand_id(&self) -> &str {
        &self.nand_id
    }

    pub fn ecc_strength(&self) -> u32 {
        self.ecc_strength
    }

    pub fn ecc_min_margin(&self) -> u32 {
        self.ecc_min_margin
    }

    pub fn bbt_generation(&self) -> u64 {
        self.bbt_generation
    }

    pub fn ftl_generation(&self) -> u64 {
        self.ftl_generation
    }

    pub fn service_mode(&self) -> bool {
        self.service_mode != 0
    }

    /// Enter service mode (re-enumeration: the reported identity changes).
    pub fn enter_service_mode(&mut self) -> Result<()> {
        if self.read_only {
            return Err(Error::Permission(
                "sim image opened read-only; service mode rejected".into(),
            ));
        }
        if !self.controller_available() {
            return Err(Error::Unsupported(
                "this sim device has no controller reinit support".into(),
            ));
        }
        if self.service_mode != 0 {
            return Ok(());
        }
        self.service_mode = 1;
        self.persist_header(|h| {
            put_u32(h, OFF_SERVICE_MODE as usize, 1);
        })
    }

    /// Exit service mode. With the fail_service_exit injection the device
    /// stays stuck and a recovery (controller reset / power cycle) is needed.
    pub fn exit_service_mode(&mut self) -> Result<()> {
        if self.read_only {
            return Err(Error::Permission(
                "sim image opened read-only; service mode rejected".into(),
            ));
        }
        if self.fail_service_exit {
            return Err(Error::io(
                "sim service-mode exit failed (injected); recovery required",
                None,
            ));
        }
        self.service_mode = 0;
        self.persist_header(|h| {
            put_u32(h, OFF_SERVICE_MODE as usize, 0);
        })
    }

    /// Identity as reported while in service mode (allowed change for the
    /// re-enumeration tracking).
    pub fn reported_controller_id(&self) -> String {
        if self.service_mode() {
            format!("{}-svc", self.controller_id)
        } else {
            self.controller_id.clone()
        }
    }

    // ------------------------------------------------------------------
    // Old BBT capture and old RBB erase
    // ------------------------------------------------------------------

    /// The old BBT summary (derived from the block table + generations).
    pub fn old_bbt(&self) -> (u64, Vec<u32>, Vec<u32>) {
        let fbb: Vec<u32> = self
            .states
            .iter()
            .enumerate()
            .filter(|(_, s)| **s == STATE_FBB)
            .map(|(i, _)| i as u32)
            .collect();
        let rbb: Vec<u32> = self
            .states
            .iter()
            .enumerate()
            .filter(|(_, s)| **s == STATE_OLD_RBB)
            .map(|(i, _)| i as u32)
            .collect();
        (self.bbt_generation, fbb, rbb)
    }

    /// Attempt a physical ERASE of every old RBB; per-block results.
    /// Success keeps the block quarantined (`historical_rbb`); failure is
    /// recorded and the block stays quarantined.
    pub fn erase_old_rbb_all(&mut self) -> Result<Vec<(u32, bool)>> {
        if self.read_only {
            return Err(Error::Permission(
                "sim image opened read-only; erase rejected".into(),
            ));
        }
        let rbb: Vec<u32> = self
            .states
            .iter()
            .enumerate()
            .filter(|(_, s)| **s == STATE_OLD_RBB)
            .map(|(i, _)| i as u32)
            .collect();
        let mut results = Vec::new();
        for block in rbb {
            match self.erase_physical(block) {
                Ok(()) => results.push((block, true)),
                Err(_) => results.push((block, false)),
            }
        }
        self.persist_pe_cycles()?;
        Ok(results)
    }

    // ------------------------------------------------------------------
    // Physical scope (C4): enumeration and per-block erase
    // ------------------------------------------------------------------

    /// Category of every physical block (phase 2).
    /// `protected` / `fbb` / `old-rbb` / `unknown` / `user` (erased,
    /// quarantined, erase-failed or obsolete blocks below user_blocks) /
    /// `spare` (the same states at or above user_blocks).
    pub fn enumerate_blocks(&self) -> Vec<(u32, &'static str)> {
        let mut out = Vec::new();
        for block in 0..self.blocks {
            let cat = if self.is_protected(block) {
                "protected"
            } else {
                match self.states[block as usize] {
                    STATE_FBB => "fbb",
                    STATE_OLD_RBB => "old-rbb",
                    STATE_UNKNOWN => "unknown",
                    STATE_ERASED | STATE_QUARANTINED | STATE_ERASE_FAILED | STATE_OBSOLETE => {
                        if block < self.user_blocks {
                            "user"
                        } else {
                            "spare"
                        }
                    }
                    _ => "unknown",
                }
            };
            out.push((block, cat));
        }
        out
    }

    /// Physical ERASE of every non-FBB, non-unknown block with per-block
    /// results (D0 + D1 + D2 + old RBB scope).
    pub fn erase_all_data_blocks(&mut self) -> Result<Vec<(u32, bool)>> {
        if self.read_only {
            return Err(Error::Permission(
                "sim image opened read-only; erase rejected".into(),
            ));
        }
        let mut results = Vec::new();
        for block in 0..self.blocks {
            match self.states[block as usize] {
                STATE_FBB | STATE_UNKNOWN => continue,
                _ => {}
            }
            if self.is_protected(block) {
                continue;
            }
            match self.erase_physical(block) {
                Ok(()) => results.push((block, true)),
                Err(_) => results.push((block, false)),
            }
        }
        self.persist_block_table()?;
        self.persist_pe_cycles()?;
        Ok(results)
    }

    // ------------------------------------------------------------------
    // Qualification (PROGRAM/READ/ECC)
    // ------------------------------------------------------------------

    /// PROGRAM/READ/ECC qualification of every non-FBB block with the plan
    /// PRBS pattern. Weak blocks (ECC margin / retry / latency thresholds)
    /// and failed blocks are quarantined. Returns (qualified, weak, failed)
    /// block lists.
    pub fn qualify_blocks(
        &mut self,
        seed: &[u8],
        ecc_strength: u32,
        min_margin: u32,
    ) -> Result<(Vec<u32>, Vec<u32>, Vec<u32>)> {
        if self.read_only {
            return Err(Error::Permission(
                "sim image opened read-only; qualification rejected".into(),
            ));
        }
        let mut qualified = Vec::new();
        let mut weak = Vec::new();
        let mut failed = Vec::new();
        let page = self.page_bytes as usize;
        let mut buf = vec![0u8; page];
        for block in 0..self.blocks {
            if matches!(self.states[block as usize], STATE_FBB | STATE_UNKNOWN) {
                continue;
            }
            if self.is_protected(block) {
                continue;
            }
            // PROGRAM (test pattern).
            if self.inject[block as usize] & INJ_PROGRAM != 0 {
                self.states[block as usize] = STATE_QUARANTINED;
                self.qual_flags[block as usize] |= QUAL_QUARANTINED;
                failed.push(block);
                continue;
            }
            let mut prbs = Prbs::new(&[seed, &block.to_le_bytes()].concat());
            for page_idx in 0..self.pages_per_block {
                prbs.fill(&mut buf);
                let off =
                    block_data_offset(block, self.blocks, self.pages_per_block, self.page_bytes)
                        + (page_idx as u64) * self.page_bytes as u64;
                self.file
                    .seek(SeekFrom::Start(off))
                    .and_then(|_| self.file.write_all(&buf))
                    .map_err(|e| Error::io("sim qualification program", Some(e)))?;
            }
            self.bump_pe_cycles(1);
            // READ + ECC evaluation.
            if self.inject[block as usize] & INJ_READ != 0 {
                self.states[block as usize] = STATE_QUARANTINED;
                self.qual_flags[block as usize] |= QUAL_QUARANTINED;
                failed.push(block);
                continue;
            }
            let corrected = self.corrected_bits[block as usize] as u32;
            let retries = self.read_retries[block as usize] as u32;
            let latency = self.read_latency_ms[block as usize] as u32;
            let policy = crate::profile::EccPolicy {
                strength: ecc_strength.max(1),
                min_margin,
                max_read_retry: 4,
                max_read_latency_ms: 200,
            };
            if crate::profile::is_weak(corrected, retries, latency, &policy) {
                self.states[block as usize] = STATE_QUARANTINED;
                self.qual_flags[block as usize] |= QUAL_WEAK | QUAL_QUARANTINED;
                weak.push(block);
            } else {
                qualified.push(block);
            }
        }
        self.persist_block_table()?;
        self.persist_pe_cycles()?;
        Ok((qualified, weak, failed))
    }

    /// Final physical ERASE of adopted + quarantined blocks (removes the
    /// test patterns; the blanks are then ready for the new FTL).
    pub fn final_erase(&mut self) -> Result<(Vec<u32>, Vec<u32>)> {
        if self.read_only {
            return Err(Error::Permission(
                "sim image opened read-only; final erase rejected".into(),
            ));
        }
        let mut erased = Vec::new();
        let mut failed = Vec::new();
        for block in 0..self.blocks {
            if matches!(self.states[block as usize], STATE_FBB | STATE_UNKNOWN) {
                continue;
            }
            if self.is_protected(block) {
                continue;
            }
            match self.erase_physical(block) {
                Ok(()) => erased.push(block),
                Err(_) => {
                    self.states[block as usize] = STATE_QUARANTINED;
                    failed.push(block);
                }
            }
        }
        self.persist_block_table()?;
        self.persist_pe_cycles()?;
        Ok((erased, failed))
    }

    // ------------------------------------------------------------------
    // New BBT / FTL / spare rebuild
    // ------------------------------------------------------------------

    /// Rebuild the BBT, spare pool and FTL from fresh results. Commits a new
    /// user capacity (may be reduced) and increments the BBT/FTL generations
    /// so the old FTL generation is invalidated. Returns
    /// (user_blocks, spare_blocks, capacity_reduced).
    pub fn rebuild_bbt_ftl(
        &mut self,
        policy: &crate::profile::CapacityPolicy,
    ) -> Result<(u64, u64, bool)> {
        if self.read_only {
            return Err(Error::Permission(
                "sim image opened read-only; rebuild rejected".into(),
            ));
        }
        if self.fail_ftl_commit {
            return Err(Error::io(
                "sim FTL commit failed (injected); controller state uncommitted",
                None,
            ));
        }
        // Admitted blocks: erased (good) blocks, excluding FBB/RBB/quarantined.
        let good = self.states.iter().filter(|s| **s == STATE_ERASED).count() as u64;
        let weak_quarantined = self
            .qual_flags
            .iter()
            .filter(|f| **f & (QUAL_WEAK | QUAL_QUARANTINED) != 0)
            .count() as u64;
        let plan =
            crate::profile::plan_capacity(good, SIM_RESERVED_BLOCKS, weak_quarantined, policy)
                .ok_or_else(|| Error::io("no usable capacity remains after quarantine", None))?;
        let reduced = plan.user_blocks < self.user_blocks as u64;
        self.new_user_blocks = plan.user_blocks;
        self.bbt_generation += 1;
        self.ftl_generation += 1;
        let excluded: Vec<u32> = (0..self.blocks)
            .filter(|i| {
                self.states[*i as usize] != STATE_ERASED
                    || self.qual_flags[*i as usize] & (QUAL_WEAK | QUAL_QUARANTINED) != 0
            })
            .collect();
        self.window = lba_window(&self.states, plan.user_blocks, &excluded);
        let bbt_gen = self.bbt_generation;
        let ftl_gen = self.ftl_generation;
        let new_user = self.new_user_blocks;
        self.persist_header(|h| {
            put_u64(h, OFF_NEW_USER_BLOCKS as usize, new_user);
            put_u64(h, OFF_BBT_GENERATION as usize, bbt_gen);
            put_u64(h, OFF_FTL_GENERATION as usize, ftl_gen);
        })?;
        Ok((plan.user_blocks, plan.spare_blocks, reduced))
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    fn persist_header(&mut self, f: impl FnOnce(&mut [u8])) -> Result<()> {
        let mut header = vec![0u8; HEADER_SIZE as usize];
        self.file
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.read_exact(&mut header))
            .map_err(|e| Error::io("sim header read", Some(e)))?;
        f(&mut header);
        self.file
            .seek(SeekFrom::Start(0))
            .and_then(|_| self.file.write_all(&header))
            .and_then(|_| self.file.sync_all())
            .map_err(|e| Error::io("sim header persist", Some(e)))
    }

    fn persist_block_table(&mut self) -> Result<()> {
        self.file.seek(SeekFrom::Start(block_table_offset()))?;
        for i in 0..self.blocks as usize {
            let entry = [
                self.states[i],
                self.inject[i],
                self.corrected_bits[i].to_le_bytes()[0],
                self.corrected_bits[i].to_le_bytes()[1],
                self.qual_flags[i],
                self.read_retries[i],
                self.read_latency_ms[i],
                0,
            ];
            self.file.write_all(&entry)?;
        }
        self.file.sync_all()?;
        Ok(())
    }

    // ------------------------------------------------------------------
    // Sanitize (self-running device erase)
    // ------------------------------------------------------------------

    pub fn sanitize_available(&self) -> bool {
        !self.no_sanitize
    }

    /// Start the self-running device erase (IMMED semantics).
    pub fn begin_sanitize(&mut self) -> Result<()> {
        if self.read_only {
            return Err(Error::Permission(
                "sim image opened read-only; sanitize rejected".into(),
            ));
        }
        if self.no_sanitize {
            return Err(Error::Unsupported(
                "this sim device has no device-level erase".into(),
            ));
        }
        if self.sanitize_state == SANITIZE_IN_PROGRESS {
            return Ok(()); // already running (self-running operation)
        }
        self.sanitize_state = SANITIZE_IN_PROGRESS;
        self.sanitize_done = 0;
        self.sanitize_total = (self.blocks - self.fbb_count()) as u64;
        self.persist_sanitize()
    }

    fn fbb_count(&self) -> u32 {
        self.states.iter().filter(|s| **s == STATE_FBB).count() as u32
    }

    /// Advance the self-running sanitize (called by status polls). Returns
    /// Ok(state) where state is IN_PROGRESS / COMPLETED / FAILED.
    pub fn sanitize_tick(&mut self) -> Result<u32> {
        if self.sanitize_state != SANITIZE_IN_PROGRESS {
            return Ok(self.sanitize_state);
        }
        let total = self.sanitize_total.max(1);
        // Fault injection: fail once past halfway.
        if self.sanitize_fail && self.sanitize_done > total / 2 {
            self.sanitize_state = SANITIZE_FAILED;
            self.persist_sanitize()?;
            return Ok(SANITIZE_FAILED);
        }
        self.sanitize_done = (self.sanitize_done + SANITIZE_TICK).min(total);
        if self.sanitize_done >= total {
            // The device erase completes: clear every non-FBB block.
            self.erase_all_non_fbb()?;
            self.sanitize_state = SANITIZE_COMPLETED;
            self.persist_sanitize()?;
            return Ok(SANITIZE_COMPLETED);
        }
        self.persist_sanitize()?;
        Ok(SANITIZE_IN_PROGRESS)
    }

    /// Progress of the sanitize in per-mille.
    pub fn sanitize_progress(&self) -> u32 {
        if self.sanitize_state != SANITIZE_IN_PROGRESS || self.sanitize_total == 0 {
            if self.sanitize_state == SANITIZE_COMPLETED {
                return 1000;
            }
            return 0;
        }
        ((self.sanitize_done as u128 * 1000) / self.sanitize_total as u128) as u32
    }

    pub fn sanitize_state(&self) -> u32 {
        self.sanitize_state
    }

    fn persist_sanitize(&mut self) -> Result<()> {
        let state = self.sanitize_state;
        let done = self.sanitize_done;
        let total = self.sanitize_total;
        self.persist_header(|h| {
            put_u32(h, OFF_SANITIZE_STATE as usize, state);
            put_u64(h, OFF_SANITIZE_DONE as usize, done);
            put_u64(h, OFF_SANITIZE_TOTAL as usize, total);
        })
    }

    /// Device-level erase of all non-FBB blocks (D0 + D1 + D2 scope).
    fn erase_all_non_fbb(&mut self) -> Result<()> {
        let page_size = (self.pages_per_block as u64) * (self.page_bytes as u64);
        let blank = vec![BLANK_VALUE; page_size as usize];
        for block in 0..self.blocks {
            if self.states[block as usize] == STATE_FBB {
                continue;
            }
            if self.is_protected(block) {
                continue;
            }
            let off = block_data_offset(block, self.blocks, self.pages_per_block, self.page_bytes);
            self.file
                .seek(SeekFrom::Start(off))
                .and_then(|_| self.file.write_all(&blank))
                .map_err(|e| Error::io("sim device erase", Some(e)))?;
        }
        self.file
            .sync_all()
            .map_err(|e| Error::io("sim device erase sync", Some(e)))
    }

    // ------------------------------------------------------------------
    // LBA window and physical access
    // ------------------------------------------------------------------

    /// Re-query the device geometry at postcheck time. The sim model
    /// derives capacity from the current model state on every read, so this
    /// is a no-op kept for API symmetry with LbaDevice.
    pub fn refresh_capacity(&mut self) -> Result<()> {
        Ok(())
    }

    /// Logical capacity in bytes (may change with capacity_alias or a
    /// controller capacity reduction).
    pub fn capacity_bytes(&self) -> u64 {
        // Effective capacity: the committed (rebuilt) value when set, else
        // the nominal user area; a capacity-alias shrinks whichever applies.
        let base = if self.new_user_blocks > 0 {
            self.new_user_blocks as u32
        } else {
            self.user_blocks
        };
        let effective = if self.capacity_alias && self.power_cycles > 0 {
            base.saturating_sub(1)
        } else {
            base
        };
        (effective as u64) * (self.pages_per_block as u64) * (self.page_bytes as u64)
    }

    pub fn power_cycles(&self) -> u64 {
        self.power_cycles
    }

    pub fn blocks(&self) -> u32 {
        self.blocks
    }

    pub fn protected_area_blocks(&self) -> u32 {
        self.protected_area_blocks
    }

    /// Accumulated program/erase cycles (wear accounting).
    pub fn pe_cycles(&self) -> u64 {
        self.pe_cycles
    }

    fn bump_pe_cycles(&mut self, n: u64) {
        self.pe_cycles += n;
    }

    fn persist_pe_cycles(&mut self) -> Result<()> {
        let pc = self.pe_cycles;
        self.persist_header(|h| {
            put_u64(h, OFF_PE_CYCLES as usize, pc);
        })
    }

    /// The first block index of the protected area (D5), if any.
    fn protected_start(&self) -> u32 {
        self.blocks.saturating_sub(self.protected_area_blocks)
    }

    fn is_protected(&self, block: u32) -> bool {
        self.protected_area_blocks > 0 && block >= self.protected_start()
    }

    /// Map an LBA byte offset to (physical block, page index).
    fn map_lba(&self, offset: u64) -> Result<(u32, u32)> {
        if offset >= self.capacity_bytes() {
            return Err(Error::io(
                format!(
                    "LBA offset {offset} beyond capacity {}",
                    self.capacity_bytes()
                ),
                None,
            ));
        }
        let lba_page = offset / self.page_bytes as u64;
        let block_idx = lba_page / self.pages_per_block as u64;
        let page_in_block = lba_page % self.pages_per_block as u64;
        let phys = *self
            .window
            .get(block_idx as usize)
            .ok_or_else(|| Error::io("LBA window exhausted", None))?;
        Ok((phys, page_in_block as u32))
    }

    /// Read from the LBA window at `offset` into `buf`.
    pub fn read_lba(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let (phys, page_in_block) = self.map_lba(offset)?;
        if self.inject[phys as usize] & INJ_READ != 0 {
            return Err(Error::io(
                format!("sim read failure injected on physical block {phys}"),
                None,
            ));
        }
        let data_off = block_data_offset(phys, self.blocks, self.pages_per_block, self.page_bytes)
            + (page_in_block as u64) * (self.page_bytes as u64);
        if buf.len() as u64 > self.page_bytes as u64 {
            return Err(Error::io("sim read larger than a page", None));
        }
        self.file
            .seek(SeekFrom::Start(data_off))
            .and_then(|_| self.file.read_exact(buf))
            .map_err(|e| Error::io("sim read", Some(e)))
    }

    /// Write into the LBA window at `offset`.
    pub fn write_lba(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        if self.read_only {
            return Err(Error::Permission(
                "sim image opened read-only; write rejected".into(),
            ));
        }
        let (phys, page_in_block) = self.map_lba(offset)?;
        if self.inject[phys as usize] & INJ_PROGRAM != 0 {
            return Err(Error::io(
                format!("sim program failure injected on physical block {phys}"),
                None,
            ));
        }
        let data_off = block_data_offset(phys, self.blocks, self.pages_per_block, self.page_bytes)
            + (page_in_block as u64) * (self.page_bytes as u64);
        if buf.len() as u64 > self.page_bytes as u64 {
            return Err(Error::io("sim write larger than a page", None));
        }
        self.file
            .seek(SeekFrom::Start(data_off))
            .and_then(|_| self.file.write_all(buf))
            .map_err(|e| Error::io("sim write", Some(e)))
    }

    pub fn flush(&mut self) -> Result<()> {
        self.file
            .sync_all()
            .map_err(|e| Error::io("sim flush", Some(e)))
    }

    /// Power cycle: increments the counter and persists the header.
    /// With capacity_alias the logical capacity shrinks by one block.
    pub fn power_cycle(&mut self) -> Result<()> {
        if self.read_only {
            return Err(Error::Permission(
                "sim image opened read-only; power cycle rejected".into(),
            ));
        }
        self.power_cycles += 1;
        let pc = self.power_cycles;
        self.persist_header(|h| {
            put_u64(h, 108, pc);
        })
    }

    /// Physical block information (for reports and later phases).
    pub fn block_states(&self) -> Vec<(u32, u8)> {
        self.states
            .iter()
            .enumerate()
            .map(|(i, s)| (i as u32, *s))
            .collect()
    }

    /// Per-block detail for the C4 block-level evidence records (spec §1331):
    /// physical coordinates, pre-classification state, FBB and historical
    /// RBB flags, PROGRAM/READ/ECC results (injection, corrected bits,
    /// weak/quarantine verdicts). The per-block vectors are all allocated
    /// to the block count at open (invariant).
    pub fn block_detail(&self, block: u32) -> Result<serde_json::Value> {
        let i = block as usize;
        if i >= self.states.len() {
            return Err(Error::Invalid(format!(
                "block {block} is out of range ({} blocks)",
                self.states.len()
            )));
        }
        let state = self.states[i];
        let inj = self.inject[i];
        let corrected = self.corrected_bits[i];
        let qual = self.qual_flags[i];
        let category = self
            .enumerate_blocks()
            .iter()
            .find(|(b, _)| *b == block)
            .map(|(_, c)| c.to_string())
            .unwrap_or_else(|| "unknown".to_string());
        Ok(serde_json::json!({
            "block": block,
            "category": category,
            "state": state,
            "is_fbb": state == STATE_FBB,
            "historical_rbb": state == STATE_OLD_RBB,
            "inject_erase": inj & INJ_ERASE != 0,
            "inject_program": inj & INJ_PROGRAM != 0,
            "inject_read": inj & INJ_READ != 0,
            "corrected_bits": corrected,
            "weak": qual & QUAL_WEAK != 0,
            "quarantined": qual & QUAL_QUARANTINED != 0,
            "protected": self.is_protected(block),
        }))
    }

    /// Attempt physical ERASE of a block. FBB is protected.
    pub fn erase_physical(&mut self, block: u32) -> Result<()> {
        if self.read_only {
            return Err(Error::Permission(
                "sim image opened read-only; erase rejected".into(),
            ));
        }
        if (block as usize) >= self.states.len() {
            return Err(Error::io("block out of range", None));
        }
        if self.states[block as usize] == STATE_FBB {
            return Err(Error::Permission(
                "refusing to erase factory bad block".into(),
            ));
        }
        if self.inject[block as usize] & INJ_ERASE != 0 {
            return Err(Error::io(
                format!("sim erase failure injected on block {block}"),
                None,
            ));
        }
        let size = (self.pages_per_block as u64) * (self.page_bytes as u64);
        let off = block_data_offset(block, self.blocks, self.pages_per_block, self.page_bytes);
        self.file
            .seek(SeekFrom::Start(off))
            .and_then(|_| self.file.write_all(&vec![0xFFu8; size as usize]))
            .map_err(|e| Error::io("sim erase", Some(e)))?;
        self.bump_pe_cycles(1);
        Ok(())
    }

    /// Read raw physical page data (for D2/OP verification in tests and the
    /// backend's postcheck).
    pub fn read_physical_page(&self, block: u32, page: u32, buf: &mut [u8]) -> Result<()> {
        if (block as usize) >= self.states.len() || (page as usize) >= self.pages_per_block as usize
        {
            return Err(Error::io("physical read out of range", None));
        }
        if self.inject[block as usize] & INJ_READ != 0 {
            return Err(Error::io(
                format!("sim physical read failure injected on block {block}"),
                None,
            ));
        }
        let data_off = block_data_offset(block, self.blocks, self.pages_per_block, self.page_bytes)
            + (page as u64) * (self.page_bytes as u64);
        if buf.len() as u64 > self.page_bytes as u64 {
            return Err(Error::io("physical read larger than a page", None));
        }
        let mut f = &self.file;
        f.seek(SeekFrom::Start(data_off))
            .and_then(|_| f.read_exact(buf))
            .map_err(|e| Error::io("sim physical read", Some(e)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_read_header() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s.img");
        create(&p, &SimSpec::default()).unwrap();
        let info = read_header(&p).unwrap();
        assert_eq!(info.id, "sim-test-001");
        assert_eq!(info.blocks, 64);
        assert_eq!(info.user_blocks, 56);

        let mut dev = SimDevice::open(&p).unwrap();
        assert_eq!(dev.capacity_bytes(), 56 * 8 * 512);
        // Stale data present before erase.
        let mut buf = [0u8; 512];
        dev.read_lba(0, &mut buf).unwrap();
        assert_eq!(buf[100], 0xA5);
        assert_eq!(&buf[510..512], &[0x55, 0xAA]); // stale MBR
        assert_eq!(dev.controller_id(), "sim-ctlr-01");
        assert_eq!(dev.firmware(), "3.2");
        assert_eq!(dev.nand_id, "SIMNAND-1");
        assert!(dev.controller_available());
        assert!(!dev.service_mode());
    }

    #[test]
    fn inherited_file_access_mode_is_preserved() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fd.img");
        create(&path, &SimSpec::default()).unwrap();

        let rw = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut writable = SimDevice::from_file(rw).unwrap();
        writable.write_lba(0, &[0x11; 512]).unwrap();

        let ro = File::open(&path).unwrap();
        let mut read_only = SimDevice::from_file(ro).unwrap();
        assert!(read_only.write_lba(0, &[0x22; 512]).is_err());
    }

    #[test]
    fn write_read_lba_window() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s2.img");
        create(&p, &SimSpec::default()).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        let mut buf = [0u8; 512];
        for i in 0..10 {
            buf.fill(i as u8);
            dev.write_lba(i as u64 * 512, &buf).unwrap();
        }
        dev.flush().unwrap();
        let mut out = [0u8; 512];
        dev.read_lba(5 * 512, &mut out).unwrap();
        assert_eq!(out[0], 5);
    }

    #[test]
    fn capacity_alias_shrinks_after_power_cycle() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s3.img");
        let spec = SimSpec {
            capacity_alias: true,
            ..SimSpec::default()
        };
        create(&p, &spec).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        let before = dev.capacity_bytes();
        dev.power_cycle().unwrap();
        let after = dev.capacity_bytes();
        assert_eq!(before, 56 * 8 * 512);
        assert_eq!(after, 55 * 8 * 512);
    }

    #[test]
    fn failure_injection() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s4.img");
        let spec = SimSpec {
            fail_read: vec![0],    // block 0 is in the window (first erased block)
            fail_program: vec![1], // block 1 is window[1] -> logical block 1
            ..SimSpec::default()
        };
        create(&p, &spec).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        let mut buf = [0u8; 512];
        assert!(dev.read_lba(0, &mut buf).is_err());
        let mut w = [0u8; 512];
        w.fill(0x77);
        // Logical block 1 = physical block 1 = page_size = 8 pages * 512.
        let page_size = dev.info().pages_per_block as u64 * 512;
        assert!(dev.write_lba(page_size, &w).is_err());
        assert!(dev.write_lba(0, &w).is_ok());
    }

    #[test]
    fn erase_protects_fbb() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s5.img");
        create(&p, &SimSpec::default()).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        assert!(dev.erase_physical(2).is_err()); // fbb
        assert!(dev.erase_physical(0).is_ok());
    }

    #[test]
    fn op_blocks_hold_stale_data_outside_window() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s6.img");
        create(&p, &SimSpec::default()).unwrap();
        let dev = SimDevice::open(&p).unwrap();
        // Physical block 63 (>= user_blocks) is OP space; verify stale data.
        let size = (dev.pages_per_block as u64) * (dev.page_bytes as u64);
        let off = block_data_offset(63, dev.blocks, dev.pages_per_block, dev.page_bytes);
        let mut f = File::open(&p).unwrap();
        let mut buf = vec![0u8; size as usize];
        f.seek(SeekFrom::Start(off)).unwrap();
        f.read_exact(&mut buf).unwrap();
        assert_eq!(buf[0], 0x5A);
    }

    #[test]
    fn device_erase_clears_d0_d1_d2_and_progresses() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s7.img");
        create(&p, &SimSpec::default()).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        assert!(dev.sanitize_available());

        // Stale user data present before the erase.
        let mut buf = [0u8; 512];
        dev.read_lba(0, &mut buf).unwrap();
        assert_eq!(buf[100], 0xA5);
        // D2/OP area holds stale data (physical block 63 = window-external).
        let mut phys = [0u8; 512];
        dev.read_physical_page(63, 0, &mut phys).unwrap();
        assert_eq!(phys[0], 0x5A);

        dev.begin_sanitize().unwrap();
        assert_eq!(dev.sanitize_state(), SANITIZE_IN_PROGRESS);
        assert!(dev.sanitize_progress() < 1000);
        // Self-running: status polls advance it until completion.
        let mut polls = 0;
        loop {
            let st = dev.sanitize_tick().unwrap();
            polls += 1;
            if st != SANITIZE_IN_PROGRESS {
                assert_eq!(st, SANITIZE_COMPLETED);
                break;
            }
            assert!(polls < 1000, "sanitize never completed");
        }
        assert_eq!(dev.sanitize_state(), SANITIZE_COMPLETED);
        assert_eq!(dev.sanitize_progress(), 1000);

        // LBA space is blank now.
        dev.read_lba(0, &mut buf).unwrap();
        assert!(buf.iter().all(|b| *b == BLANK_VALUE));
        // D2/OP area is blank too (only a device erase reaches it).
        dev.read_physical_page(63, 0, &mut phys).unwrap();
        assert!(phys.iter().all(|b| *b == BLANK_VALUE));
    }

    #[test]
    fn sanitize_persists_across_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s8.img");
        create(&p, &SimSpec::default()).unwrap();
        {
            let mut dev = SimDevice::open(&p).unwrap();
            dev.begin_sanitize().unwrap();
            let _ = dev.sanitize_tick().unwrap();
        }
        // Reopen mid-operation (e.g. after a process kill): still running.
        let mut dev = SimDevice::open(&p).unwrap();
        assert_eq!(dev.sanitize_state(), SANITIZE_IN_PROGRESS);
        let mut polls = 0;
        loop {
            let st = dev.sanitize_tick().unwrap();
            polls += 1;
            if st != SANITIZE_IN_PROGRESS {
                assert_eq!(st, SANITIZE_COMPLETED);
                break;
            }
            assert!(polls < 1000);
        }
        assert_eq!(dev.sanitize_progress(), 1000);
    }

    #[test]
    fn sanitize_failure_injection() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s9.img");
        let spec = SimSpec {
            sanitize_fail: true,
            ..SimSpec::default()
        };
        create(&p, &spec).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        dev.begin_sanitize().unwrap();
        let mut final_state = SANITIZE_IN_PROGRESS;
        for _ in 0..1000 {
            final_state = dev.sanitize_tick().unwrap();
            if final_state != SANITIZE_IN_PROGRESS {
                break;
            }
        }
        assert_eq!(final_state, SANITIZE_FAILED);
    }

    #[test]
    fn no_sanitize_device() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("s10.img");
        let spec = SimSpec {
            sanitize: false,
            ..SimSpec::default()
        };
        create(&p, &spec).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        assert!(!dev.sanitize_available());
        assert!(dev.begin_sanitize().is_err());
    }

    fn capacity_policy() -> crate::profile::CapacityPolicy {
        crate::profile::CapacityPolicy {
            bin_bytes: 0,
            minimum_spare_blocks: 4,
            spare_ratio: 0.05,
        }
    }

    #[test]
    fn old_bbt_capture_and_rbb_erase() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c1.img");
        create(&p, &SimSpec::default()).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        let (gen, fbb, rbb) = dev.old_bbt();
        assert_eq!(gen, 1);
        assert_eq!(fbb, vec![2, 5]);
        assert_eq!(rbb, vec![10, 20, 30]);
        // Old RBB blocks hold stale user data before the erase.
        let mut buf = [0u8; 512];
        dev.read_physical_page(10, 0, &mut buf).unwrap();
        assert_eq!(buf[0], 0x5A);
        // Per-block erase results.
        let results = dev.erase_old_rbb_all().unwrap();
        assert_eq!(results.len(), 3);
        assert!(results.iter().all(|(_, ok)| *ok));
        // Data erased but the block stays quarantined (historical RBB).
        dev.read_physical_page(10, 0, &mut buf).unwrap();
        assert!(buf.iter().all(|b| *b == BLANK_VALUE));
        assert_eq!(
            dev.block_states().iter().find(|(b, _)| *b == 10).unwrap().1,
            STATE_OLD_RBB
        );
    }

    #[test]
    fn qualification_isolates_weak_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c2.img");
        let spec = SimSpec {
            ecc_corrupt: vec![1], // block 1: corrected bits -> weak
            ..SimSpec::default()
        };
        create(&p, &spec).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        // create() seeded the corrected-bit count for block 1.
        assert_eq!(dev.corrected_bits[1], (dev.ecc_strength() - 2) as u16);
        let (qualified, weak, failed) = dev.qualify_blocks(b"seed", 40, 8).unwrap();
        assert!(weak.contains(&1));
        assert!(!qualified.contains(&1));
        assert!(failed.is_empty());
        assert_eq!(
            dev.block_states().iter().find(|(b, _)| *b == 1).unwrap().1,
            STATE_QUARANTINED
        );
    }

    #[test]
    fn rebuild_commits_capacity_and_generations() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c3.img");
        create(&p, &SimSpec::default()).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        let _ = dev.erase_old_rbb_all().unwrap();
        let (qualified, _weak, _failed) = dev.qualify_blocks(b"seed", 40, 8).unwrap();
        assert!(qualified.len() > 10);
        let (erased, failed_erase) = dev.final_erase().unwrap();
        assert!(failed_erase.is_empty());
        assert!(!erased.is_empty());
        let before_gen = dev.bbt_generation();
        let (user, spare, reduced) = dev.rebuild_bbt_ftl(&capacity_policy()).unwrap();
        // good = 64 - 2 fbb - 3 rbb = 59; reserved = 1;
        // spare = max(4, ceil(59*0.05)=3, 1) = 4; user = 59-1-4 = 54.
        // The nominal window was 56 blocks, so the explicit spare/reserved
        // accounting yields a documented (small) capacity change.
        assert_eq!(user, 54);
        assert_eq!(spare, 4);
        assert!(reduced);
        assert_eq!(dev.bbt_generation(), before_gen + 1);
        assert_eq!(dev.capacity_bytes(), 54 * 8 * 512);
        // FTL commit failure injection.
        let p2 = dir.path().join("c4.img");
        let spec = SimSpec {
            fail_ftl_commit: true,
            ..SimSpec::default()
        };
        create(&p2, &spec).unwrap();
        let mut dev2 = SimDevice::open(&p2).unwrap();
        assert!(dev2.rebuild_bbt_ftl(&capacity_policy()).is_err());
    }

    #[test]
    fn capacity_reduction_when_weak() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c5.img");
        create(&p, &SimSpec::default()).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        // Make 20 blocks weak so the capacity shrinks below the nominal size.
        for b in 0..20u32 {
            dev.corrected_bits[b as usize] = dev.ecc_strength() as u16;
        }
        let _ = dev.qualify_blocks(b"seed", 40, 8).unwrap();
        let (user, _spare, reduced) = dev.rebuild_bbt_ftl(&capacity_policy()).unwrap();
        assert!(reduced);
        assert!(user < 54);
        assert!(dev.capacity_bytes() < 54 * 8 * 512);
    }

    #[test]
    fn obsolete_state_classified_as_user_or_spare() {
        // STATE_OBSOLETE blocks are folded into user/spare by enumeration
        // (below / at user_blocks); obsolete is not a separate category.
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("obs.img");
        create(&p, &SimSpec::default()).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        let user = dev.user_blocks as usize;
        dev.states[0] = STATE_OBSOLETE; // within the user area
        dev.states[user] = STATE_OBSOLETE; // spare area
        let cats = dev.enumerate_blocks();
        assert_eq!(cats[0].1, "user");
        assert_eq!(cats[user].1, "spare");
    }

    #[test]
    fn protected_area_is_never_erased() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("pa.img");
        let spec = SimSpec {
            protected_area_blocks: 2,
            ..SimSpec::default()
        };
        create(&p, &spec).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        assert_eq!(dev.protected_area_blocks(), 2);
        // The protected blocks hold the distinct stale pattern.
        let mut buf = [0u8; 512];
        dev.read_physical_page(63, 0, &mut buf).unwrap();
        assert_eq!(buf[0], 0x6A);
        // Enumeration categorizes them as protected.
        let cats = dev.enumerate_blocks();
        assert_eq!(cats.iter().filter(|(_, c)| *c == "protected").count(), 2);
        // None of the erase paths touch them.
        let _ = dev.erase_old_rbb_all().unwrap();
        let _ = dev.erase_all_data_blocks().unwrap();
        let _ = dev.qualify_blocks(b"seed", 40, 8).unwrap();
        let _ = dev.final_erase().unwrap();
        dev.begin_sanitize().unwrap();
        loop {
            if dev.sanitize_tick().unwrap() != super::SANITIZE_IN_PROGRESS {
                break;
            }
        }
        dev.read_physical_page(63, 0, &mut buf).unwrap();
        assert_eq!(buf[0], 0x6A, "protected area must survive every erase path");
        dev.read_physical_page(62, 0, &mut buf).unwrap();
        assert_eq!(buf[0], 0x6A);
    }

    #[test]
    fn service_mode_and_identity_change() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("c6.img");
        create(&p, &SimSpec::default()).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        assert!(!dev.service_mode());
        assert_eq!(dev.reported_controller_id(), "sim-ctlr-01");
        dev.enter_service_mode().unwrap();
        assert!(dev.service_mode());
        assert_eq!(dev.reported_controller_id(), "sim-ctlr-01-svc");
        dev.exit_service_mode().unwrap();
        assert!(!dev.service_mode());
        // Exit failure -> stuck (recovery required).
        let p2 = dir.path().join("c7.img");
        let spec = SimSpec {
            fail_service_exit: true,
            ..SimSpec::default()
        };
        create(&p2, &spec).unwrap();
        let mut dev2 = SimDevice::open(&p2).unwrap();
        dev2.enter_service_mode().unwrap();
        assert!(dev2.exit_service_mode().is_err());
        assert!(dev2.service_mode());
    }

    #[test]
    fn block_detail_reports_state_injection_and_qualifiers() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("detail.img");
        let spec = SimSpec {
            fbb: vec![0],
            old_rbb: vec![1],
            fail_erase: vec![2],
            fail_program: vec![3],
            fail_read: vec![4],
            weak_blocks: vec![5],
            protected_area_blocks: 2,
            ..SimSpec::default()
        };
        create(&p, &spec).unwrap();
        let dev = SimDevice::open(&p).unwrap();

        let fbb = dev.block_detail(0).unwrap();
        assert_eq!(fbb["is_fbb"], true);
        assert_eq!(fbb["historical_rbb"], false);
        assert_eq!(fbb["protected"], false);

        let old = dev.block_detail(1).unwrap();
        assert_eq!(old["historical_rbb"], true);
        assert_eq!(old["is_fbb"], false);

        let inj_erase = dev.block_detail(2).unwrap();
        assert_eq!(inj_erase["inject_erase"], true);
        assert_eq!(inj_erase["inject_program"], false);
        assert_eq!(inj_erase["inject_read"], false);

        let inj_program = dev.block_detail(3).unwrap();
        assert_eq!(inj_program["inject_program"], true);

        let inj_read = dev.block_detail(4).unwrap();
        assert_eq!(inj_read["inject_read"], true);

        let weak = dev.block_detail(5).unwrap();
        assert_eq!(weak["weak"], true);
        assert_eq!(weak["quarantined"], false);

        let protected = dev.block_detail(spec.blocks - 1).unwrap();
        assert_eq!(protected["protected"], true);
        assert_eq!(protected["is_fbb"], false);

        let err = dev.block_detail(spec.blocks);
        assert!(err.is_err(), "out-of-range block must be an error");
    }
}

#[cfg(test)]
mod geometry_tests {
    use super::*;

    #[test]
    fn degenerate_geometry_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.img");
        for (mut spec, label) in [
            (
                SimSpec {
                    blocks: 0,
                    ..Default::default()
                },
                "blocks=0",
            ),
            (
                SimSpec {
                    pages_per_block: 0,
                    ..Default::default()
                },
                "pages=0",
            ),
            (
                SimSpec {
                    page_bytes: 0,
                    ..Default::default()
                },
                "page_bytes=0",
            ),
            (
                SimSpec {
                    protected_area_blocks: 999,
                    ..Default::default()
                },
                "protected>blocks",
            ),
        ] {
            spec.id = format!("bad-{label}");
            let err = create(&p, &spec);
            assert!(err.is_err(), "{label} must be rejected");
        }
    }

    #[test]
    fn valid_geometry_accepted() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("ok.img");
        create(&p, &SimSpec::default()).unwrap();
        let mut dev = SimDevice::open(&p).unwrap();
        // No division by zero: a simple write/read round trip.
        let mut buf = [0u8; 512];
        dev.write_lba(0, &buf).unwrap();
        dev.read_lba(0, &mut buf).unwrap();
    }
}
