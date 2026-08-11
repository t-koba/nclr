//! LBA processing primitives shared by the core and the `nclr-lba` backend:
//! PRBS generation (seeded by the plan), aligned block I/O, flush, read-back
//! verification and partition/filesystem signature detection (recipe L1).

use crate::errors::{Error, Result};
use std::fs::File;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::FileExt;

pub const SECTOR: u64 = 512;
/// I/O chunk size (1 MiB).
pub const CHUNK: u64 = 1024 * 1024;

/// xorshift64* PRBS seeded from a byte string (plan id / hash bytes).
#[derive(Clone, Copy, Debug)]
pub struct Prbs {
    state: u64,
}

impl Prbs {
    pub fn new(seed: &[u8]) -> Prbs {
        let mut state: u64 = 0x9E37_79B9_7F4A_7C15u64 ^ 0xDEAD_BEEF;
        for (i, b) in seed.iter().enumerate() {
            state ^= (*b as u64) << (8 * (i % 8));
            state ^= state >> 12;
            state ^= state << 25;
            state ^= state >> 27;
        }
        if state == 0 {
            state = 0x1234_5678_9ABC_DEF0;
        }
        Prbs { state }
    }

    #[inline]
    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Fill `buf` with the next bytes of the PRBS stream.
    pub fn fill(&mut self, buf: &mut [u8]) {
        for chunk in buf.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

/// Logical block device view over an inherited file descriptor.
/// For real block devices the capacity/block size come from ioctls;
/// for regular files they come from the file metadata.
pub struct LbaDevice {
    file: File,
    capacity_bytes: u64,
    block_size: u32,
    is_file: bool,
}

impl LbaDevice {
    /// Adopt an already-open fd (device or file) opened by the core.
    pub fn from_fd(fd: OwnedFd, is_file: bool) -> Result<LbaDevice> {
        let file = File::from(fd);
        let (capacity_bytes, block_size) = query_geometry(&file, is_file)?;
        Ok(LbaDevice {
            file,
            capacity_bytes,
            block_size,
            is_file,
        })
    }

    /// Re-query the device geometry so a postcheck measures the *current*
    /// capacity and block size instead of the values cached at process
    /// start (an erase or a power cycle may have changed them).
    pub fn refresh_capacity(&mut self) -> Result<()> {
        let (capacity_bytes, block_size) = query_geometry(&self.file, self.is_file)?;
        self.capacity_bytes = capacity_bytes;
        self.block_size = block_size;
        Ok(())
    }

    pub fn capacity_bytes(&self) -> u64 {
        self.capacity_bytes
    }

    pub fn block_size(&self) -> u32 {
        self.block_size
    }

    pub fn sectors(&self) -> u64 {
        self.capacity_bytes / SECTOR
    }

    /// Write a full buffer at the given byte offset (sector-aligned).
    pub fn write_at(&mut self, offset: u64, buf: &[u8]) -> Result<()> {
        self.file
            .write_all_at(buf, offset)
            .map_err(|e| Error::io(format!("write at LBA {}", offset / SECTOR), Some(e)))
    }

    /// Read a full buffer from the given byte offset.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.file
            .read_exact_at(buf, offset)
            .map_err(|e| Error::io(format!("read at LBA {}", offset / SECTOR), Some(e)))
    }

    pub fn flush(&mut self) -> Result<()> {
        self.file
            .sync_all()
            .map_err(|e| Error::io("flush", Some(e)))
    }
}

/// Shared geometry acquisition for `from_fd` and `refresh_capacity`:
/// ioctls for real block devices, file metadata for regular files, with a
/// capacity sanity check (nonzero and sector-aligned).
fn query_geometry(file: &File, is_file: bool) -> Result<(u64, u32)> {
    let (capacity_bytes, block_size) = if is_file {
        let len = file
            .metadata()
            .map_err(|e| Error::io("file metadata", Some(e)))?
            .len();
        (len, SECTOR as u32)
    } else {
        query_block_device(file)?
    };
    if capacity_bytes == 0 || capacity_bytes % SECTOR != 0 {
        return Err(Error::io(
            format!("device has no valid capacity: {capacity_bytes} bytes"),
            None,
        ));
    }
    Ok((capacity_bytes, block_size))
}

/// Query capacity and logical block size via ioctls (Linux/macOS).
fn query_block_device(file: &File) -> Result<(u64, u32)> {
    #[cfg(target_os = "linux")]
    {
        // BLKGETSIZE64 = _IOR(0x12, 114, size_t) is size_t-dependent: the
        // constant below is for 64-bit builds only (32-bit would be
        // 0x40081272). BLKSSZGET = _IO(0x12, 104) is architecture
        // independent. The libc crate does not export these on all
        // targets; they are defined here per the kernel uapi headers.
        const BLKGETSIZE64: libc::c_ulong = 0x8008_1272;
        const BLKSSZGET: libc::c_ulong = 0x1268;
        let mut bytes: u64 = 0;
        let r = unsafe { libc::ioctl(file.as_raw_fd(), BLKGETSIZE64, &mut bytes as *mut u64) };
        if r == 0 && bytes > 0 {
            let mut bsz: u32 = 0;
            let r2 = unsafe { libc::ioctl(file.as_raw_fd(), BLKSSZGET, &mut bsz as *mut u32) };
            if r2 != 0 || bsz == 0 {
                // A missing block size would silently misreport 4Kn devices
                // as 512-byte; the error must not be swallowed. The errno is
                // only meaningful when the ioctl itself failed.
                let src = if r2 != 0 {
                    Some(std::io::Error::last_os_error())
                } else {
                    None
                };
                return Err(Error::io(
                    "cannot query the logical block size (BLKSSZGET)",
                    src,
                ));
            }
            return Ok((bytes, bsz));
        }
        Err(Error::io(
            "cannot query block device size (BLKGETSIZE64)",
            None,
        ))
    }
    #[cfg(target_os = "macos")]
    {
        // DKIOCGETBLOCKCOUNT = _IOR('d', 25, uint64_t); DKIOCGETBLOCKSIZE = _IOR('d', 24, uint32_t)
        const DKIOCGETBLOCKCOUNT: libc::c_ulong = 0x4008_6419;
        const DKIOCGETBLOCKSIZE: libc::c_ulong = 0x4004_6418;
        let mut blocks: u64 = 0;
        let mut bsz: u32 = 0;
        let r1 = unsafe {
            libc::ioctl(
                file.as_raw_fd(),
                DKIOCGETBLOCKCOUNT,
                &mut blocks as *mut u64,
            )
        };
        let r2 = unsafe { libc::ioctl(file.as_raw_fd(), DKIOCGETBLOCKSIZE, &mut bsz as *mut u32) };
        if r1 == 0 && r2 == 0 && blocks > 0 && bsz > 0 {
            return Ok((blocks.saturating_mul(bsz as u64), bsz));
        }
        Err(Error::io(
            "cannot query block device size (DKIOCGETBLOCKCOUNT)",
            None,
        ))
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = file;
        Err(Error::Unsupported(
            "block device I/O on this platform".into(),
        ))
    }
}

/// Partition / filesystem signature detection over raw bytes.
/// Returns a list of detected signature names.
pub fn detect_signatures(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    if data.len() >= 512 && data[510] == 0x55 && data[511] == 0xAA {
        // A boot signature alone is weak; require a partition table marker.
        let pt = &data[446..510];
        let has_entry = pt.chunks(16).any(|e| {
            let Some(boot) = e.first() else {
                return false;
            };
            *boot == 0x80 || (0x01..=0x7F).contains(boot) || e[4] != 0x00 || e[8..12] != [0; 4]
        });
        if has_entry {
            out.push("MBR".into());
        }
    }
    for (pat, name) in [(b"EFI PART", "GPT"), (b"EXFAT   ", "exFAT")] {
        if data.windows(pat.len()).any(|w| w == pat) {
            out.push(name.into());
        }
    }
    // FAT12/FAT16/FAT32 boot sectors (EB ?? 90 or E9 ?? ??).
    if data.len() >= 90 {
        let b0 = data[0];
        if b0 == 0xEB || b0 == 0xE9 {
            let fat16 = &data[54..62];
            let fat32 = &data[82..90];
            if fat16 == b"FAT12   " || fat16 == b"FAT16   " || fat32 == b"FAT32   " {
                out.push("FAT".into());
            }
        }
    }
    // ext2/3/4 superblock magic at 0x438.
    if data.len() >= 0x43A && data[0x438] == 0x53 && data[0x439] == 0xEF {
        out.push("ext2/3/4".into());
    }
    out.sort();
    out.dedup();
    out
}

/// Region to check for signatures: first and last N sectors.
pub fn signature_check_regions(sectors: u64) -> Vec<(u64, u64)> {
    const N: u64 = 64; // sectors
    let mut regions = Vec::new();
    regions.push((0, N.min(sectors)));
    if sectors > N {
        regions.push((sectors - N, N));
    }
    regions
}

/// Perform the signature check over the whole device (first/last regions).
pub fn check_signatures(dev: &mut LbaDevice) -> Result<Vec<String>> {
    let mut found = Vec::new();
    for (start_sector, count) in signature_check_regions(dev.sectors()) {
        let mut buf = vec![0u8; (count * SECTOR) as usize];
        dev.read_at(start_sector * SECTOR, &mut buf)?;
        found.extend(detect_signatures(&buf));
    }
    found.sort();
    found.dedup();
    Ok(found)
}

/// A progress callback used by the L1 recipe steps.
pub type Progress<'a> = Box<dyn FnMut(u64, u64) -> Result<()> + Send + 'a>;

/// Write a PRBS pattern over the full logical space, flushing at the end.
/// Returns the number of I/O errors.
pub fn write_pattern(dev: &mut LbaDevice, seed: &[u8], mut progress: Progress<'_>) -> Result<u64> {
    let mut errors = 0u64;
    let capacity = dev.capacity_bytes();
    let mut offset = 0u64;
    let mut prbs = Prbs::new(seed);
    let total_chunks = capacity.div_ceil(CHUNK);
    let mut done = 0u64;
    while offset < capacity {
        let len = CHUNK.min(capacity - offset);
        let mut buf = vec![0u8; len as usize];
        prbs.fill(&mut buf);
        if let Err(e) = dev.write_at(offset, &buf) {
            errors += 1;
            eprintln!("nclr-lba: {e}");
        }
        offset += len;
        done += 1;
        progress(done, total_chunks)?;
    }
    dev.flush()?;
    Ok(errors)
}

/// Read back and verify a PRBS pattern over the full logical space.
pub fn verify_pattern(dev: &mut LbaDevice, seed: &[u8], mut progress: Progress<'_>) -> Result<u64> {
    let mut errors = 0u64;
    let mut mismatches = 0u64;
    let capacity = dev.capacity_bytes();
    let mut offset = 0u64;
    let mut prbs = Prbs::new(seed);
    let total_chunks = capacity.div_ceil(CHUNK);
    let mut done = 0u64;
    while offset < capacity {
        let len = CHUNK.min(capacity - offset);
        let mut buf = vec![0u8; len as usize];
        // The PRBS stream is stateful across chunks: it must be advanced
        // even when the read fails, otherwise every later chunk would be
        // compared against a wrong expected value (mirroring write_pattern).
        let mut expected = vec![0u8; len as usize];
        prbs.fill(&mut expected);
        if let Err(e) = dev.read_at(offset, &mut buf) {
            errors += 1;
            eprintln!("nclr-lba: {e}");
        } else if buf != expected {
            mismatches += 1;
        }
        offset += len;
        done += 1;
        progress(done, total_chunks)?;
    }
    Ok(errors + mismatches)
}

/// Write zeros over the full logical space.
pub fn write_zeros(dev: &mut LbaDevice, mut progress: Progress<'_>) -> Result<u64> {
    let mut errors = 0u64;
    let capacity = dev.capacity_bytes();
    let mut offset = 0u64;
    let buf = vec![0u8; CHUNK as usize];
    let total_chunks = capacity.div_ceil(CHUNK);
    let mut done = 0u64;
    while offset < capacity {
        let len = CHUNK.min(capacity - offset);
        if let Err(e) = dev.write_at(offset, &buf[..len as usize]) {
            errors += 1;
            eprintln!("nclr-lba: {e}");
        }
        offset += len;
        done += 1;
        progress(done, total_chunks)?;
    }
    dev.flush()?;
    Ok(errors)
}

/// Verify that the full logical space reads as zeros.
pub fn verify_zeros(dev: &mut LbaDevice, mut progress: Progress<'_>) -> Result<u64> {
    let mut errors = 0u64;
    let capacity = dev.capacity_bytes();
    let mut offset = 0u64;
    let total_chunks = capacity.div_ceil(CHUNK);
    let mut done = 0u64;
    while offset < capacity {
        let len = CHUNK.min(capacity - offset);
        let mut buf = vec![0u8; len as usize];
        if let Err(e) = dev.read_at(offset, &mut buf) {
            errors += 1;
            eprintln!("nclr-lba: {e}");
        } else if buf.iter().any(|b| *b != 0) {
            errors += 1;
        }
        offset += len;
        done += 1;
        progress(done, total_chunks)?;
    }
    Ok(errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prbs_is_deterministic() {
        let mut a = Prbs::new(b"plan-id-123");
        let mut b = Prbs::new(b"plan-id-123");
        let mut ba = [0u8; 1000];
        let mut bb = [0u8; 1000];
        a.fill(&mut ba);
        b.fill(&mut bb);
        assert_eq!(ba, bb);
        assert!(ba.iter().any(|x| *x != 0));
    }

    #[test]
    fn prbs_differs_by_seed() {
        let mut a = Prbs::new(b"seed-a");
        let mut b = Prbs::new(b"seed-b");
        let mut ba = [0u8; 64];
        let mut bb = [0u8; 64];
        a.fill(&mut ba);
        b.fill(&mut bb);
        assert_ne!(ba, bb);
    }

    #[test]
    fn prbs_stream_continuity() {
        // Filling chunk-wise produces the same stream as one fill, provided
        // chunk sizes are multiples of the u64 word (1 MiB and 512 sectors
        // used by the recipes both are).
        let mut a = Prbs::new(b"s");
        let mut full = [0u8; 32];
        a.fill(&mut full);
        let mut b = Prbs::new(b"s");
        let mut part1 = [0u8; 16];
        let mut part2 = [0u8; 16];
        b.fill(&mut part1);
        b.fill(&mut part2);
        assert_eq!(&full[..16], &part1[..]);
        assert_eq!(&full[16..], &part2[..]);
    }

    #[test]
    fn signature_detection() {
        let mut mbr = vec![0u8; 512];
        mbr[446] = 0x80; // active partition entry
        mbr[510] = 0x55;
        mbr[511] = 0xAA;
        assert_eq!(detect_signatures(&mbr), vec!["MBR"]);

        let mut gpt = vec![0u8; 4096];
        gpt[0] = b'E';
        gpt[1] = b'F';
        gpt[2] = b'I';
        gpt[3] = b' ';
        gpt[4] = b'P';
        gpt[5] = b'A';
        gpt[6] = b'R';
        gpt[7] = b'T';
        assert_eq!(detect_signatures(&gpt), vec!["GPT"]);

        let mut fat = vec![0u8; 512];
        fat[0] = 0xEB;
        fat[1] = 0x3C;
        fat[2] = 0x90;
        fat[54..62].copy_from_slice(b"FAT12   ");
        assert_eq!(detect_signatures(&fat), vec!["FAT"]);

        assert!(detect_signatures(&[0u8; 512]).is_empty());
        assert!(detect_signatures(&[0xFFu8; 512]).is_empty());
    }

    #[test]
    fn signature_detection_short_buffers_do_not_panic() {
        // Regression: the MBR/FAT checks must not index beyond the buffer.
        for len in 0..512 {
            let buf = vec![0u8; len];
            detect_signatures(&buf);
        }
        // A short buffer that looks like a FAT boot sector.
        let mut fat = vec![0u8; 60];
        fat[0] = 0xEB;
        detect_signatures(&fat);
        let mut mbr = vec![0u8; 511];
        mbr[510] = 0x55;
        detect_signatures(&mbr);
        assert!(detect_signatures(&fat).is_empty());
        assert!(detect_signatures(&mbr).is_empty());
    }

    #[test]
    fn signature_check_regions_bounds() {
        let regions = signature_check_regions(100);
        assert_eq!(regions, vec![(0, 64), (36, 64)]);
        let small = signature_check_regions(4);
        assert_eq!(small, vec![(0, 4)]);
    }

    #[test]
    fn refresh_capacity_file_geometry() {
        use std::os::fd::{FromRawFd, OwnedFd};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.bin");
        // 2 MiB: sector aligned.
        std::fs::write(&path, vec![0u8; 2 * 1024 * 1024]).unwrap();
        let f = std::fs::File::open(&path).unwrap();
        let owned = unsafe { OwnedFd::from_raw_fd(libc::dup(f.as_raw_fd())) };
        let mut dev = LbaDevice::from_fd(owned, true).unwrap();
        assert_eq!(dev.capacity_bytes(), 2 * 1024 * 1024);
        // A grow of the backing file is visible after refresh.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(4 * 1024 * 1024)
            .unwrap();
        dev.refresh_capacity().unwrap();
        assert_eq!(dev.capacity_bytes(), 4 * 1024 * 1024);
        // A file that is not sector aligned is rejected by refresh.
        let bad = dir.path().join("bad.bin");
        std::fs::write(&bad, vec![0u8; 100]).unwrap();
        let f2 = std::fs::File::open(&bad).unwrap();
        let owned2 = unsafe { OwnedFd::from_raw_fd(libc::dup(f2.as_raw_fd())) };
        assert!(LbaDevice::from_fd(owned2, true).is_err());
    }

    #[test]
    fn verify_pattern_reports_read_errors_and_continues() {
        // A failing read (the file shrinks below the cached capacity) must
        // be counted as an error and the sweep must continue without
        // panicking; the PRBS stream stays aligned with the chunk sequence
        // (fill runs before the read, mirroring write_pattern).
        use std::os::fd::{FromRawFd, OwnedFd};
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("dev.bin");
        std::fs::write(&path, vec![0u8; CHUNK as usize * 2]).unwrap();
        let f = std::fs::File::options()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let owned = unsafe { OwnedFd::from_raw_fd(libc::dup(f.as_raw_fd())) };
        let mut dev = LbaDevice::from_fd(owned, true).unwrap();
        // Write a pattern (a single stateful PRBS stream across chunks).
        let seed = b"nclr-prbs:test";
        let mut prbs = Prbs::new(seed);
        let mut b0 = vec![0u8; CHUNK as usize];
        prbs.fill(&mut b0);
        dev.write_at(0, &b0).unwrap();
        let mut b1 = vec![0u8; CHUNK as usize];
        prbs.fill(&mut b1);
        dev.write_at(CHUNK, &b1).unwrap();
        // Shrink the backing file: chunk 1 now reads past EOF. The device
        // capacity cache still covers two chunks, so verify hits a real
        // read error on chunk 1 and must count it, not crash.
        std::fs::OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_len(CHUNK)
            .unwrap();
        let noop = Box::new(|_, _| Ok(())) as Progress<'_>;
        let errors = verify_pattern(&mut dev, seed, noop).unwrap();
        assert_eq!(errors, 1, "the EOF chunk must be counted as a read error");
    }
}
