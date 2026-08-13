//! Device discovery and identification.
//!
//! DeviceIdentity follows the self-describing device JSON schema. Platform backends:
//! - Linux: sysfs (/sys/class/block, mmc, scsi, usb topology, mountinfo)
//! - macOS: diskutil info/list -plist piped through plutil
//! - any platform: regular files act as pseudo-devices (plain file = LBA
//!   transport, "NCLRSIM1" file = sim transport)

pub mod fingerprint;
#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;

use crate::errors::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const TRANSPORT_MMC: &str = "mmc";
pub const TRANSPORT_USB_MSD: &str = "usb-msd";
pub const TRANSPORT_SD_VIA_USB: &str = "sd-via-usb";
pub const TRANSPORT_FILE: &str = "file";
pub const TRANSPORT_FILE_SIM: &str = "file-sim";

pub const SIM_MAGIC: &[u8; 8] = b"NCLRSIM1";

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct MmcInfo {
    pub cid: String,
    pub csd: String,
    pub scr: String,
    pub manfid: String,
    pub oemid: String,
    pub name: String,
    pub serial: String,
    pub date: String,
    pub host: String,
    /// The card type from `/sys/block/<name>/device/type` ("SD", "MMC",
    /// "SDIO", "SDcombo"); empty when the attribute is unavailable. Used to
    /// select SD-only commands (CMD32/33) which eMMC does not implement.
    pub kind: String,
    /// Protocol erase group size reported by the MMC core, in bytes.
    #[serde(default)]
    pub erase_size_bytes: u64,
    /// Preferred erase request size reported by the MMC core, in bytes.
    #[serde(default)]
    pub preferred_erase_size_bytes: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct UsbInfo {
    pub vid: String,
    pub pid: String,
    pub bcd_device: String,
    pub serial: String,
    pub manufacturer: String,
    pub product: String,
    pub port_chain: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct ScsiInfo {
    pub vendor: String,
    pub model: String,
    pub rev: String,
    pub sg_path: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct SimInfo {
    pub id: String,
    pub blocks: u32,
    pub user_blocks: u32,
    pub pages_per_block: u32,
    pub page_bytes: u32,
    /// Effective logical capacity in bytes (a controller capacity reduction
    /// is reflected here).
    #[serde(default, skip_serializing_if = "is_zero")]
    pub capacity_bytes: u64,
}

fn is_zero(v: &u64) -> bool {
    *v == 0
}

/// macOS diskutil-provided stable identification fields.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
pub struct MacInfo {
    pub protocol: String,
    pub serial: String,
    pub media_name: String,
    pub uuid: String,
    pub media_type: String,
    pub parent_whole_disk: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct DeviceIdentity {
    pub schema: String,
    pub transport: String,
    pub kernel_path: String,
    pub physical_path: String,
    pub fingerprint: String,
    pub capacity_bytes: u64,
    pub logical_block_size: u32,
    pub removable: bool,
    /// Device reports read-only / write-protected (sysfs `ro` on Linux).
    #[serde(default)]
    pub read_only: bool,
    pub mounted: bool,
    pub holders: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mmc: Option<MmcInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usb: Option<UsbInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scsi: Option<ScsiInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sim: Option<SimInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<MacInfo>,
}

impl DeviceIdentity {
    pub fn new(transport: &str, kernel_path: &str, physical_path: &str) -> DeviceIdentity {
        let mut d = DeviceIdentity {
            schema: crate::SCHEMA_DEVICE.to_string(),
            transport: transport.to_string(),
            kernel_path: kernel_path.to_string(),
            physical_path: physical_path.to_string(),
            fingerprint: String::new(),
            capacity_bytes: 0,
            logical_block_size: 512,
            removable: true,
            read_only: false,
            mounted: false,
            holders: Vec::new(),
            mmc: None,
            usb: None,
            scsi: None,
            sim: None,
            mac: None,
        };
        d.fingerprint = fingerprint::compute(&d);
        d
    }

    /// Recompute the fingerprint (call after fields change).
    pub fn refresh_fingerprint(&mut self) {
        self.fingerprint = fingerprint::compute(self);
    }

    pub fn is_sim(&self) -> bool {
        self.transport == TRANSPORT_FILE_SIM
    }
}

/// Identify a device (or file-backed pseudo device).
pub fn identify(path: &str) -> Result<DeviceIdentity> {
    let p = Path::new(path);
    if !p.exists() {
        return Err(Error::Usage(format!("device does not exist: {path}")));
    }
    if p.is_file() {
        return identify_file(path);
    }
    #[cfg(target_os = "linux")]
    {
        linux::identify(path)
    }
    #[cfg(target_os = "macos")]
    {
        macos::identify(path)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(Error::Unsupported(format!(
            "platform not supported for device access: {}",
            std::env::consts::OS
        )))
    }
}

/// Whether two identities refer to the same physical media. Capacity and
/// logical block size are deliberately excluded: a controller rebuild may
/// legitimately change them. Every other stable anchor (physical path,
/// vendor/serial identities) must match; otherwise the device was swapped.
pub fn same_physical_media(a: &DeviceIdentity, b: &DeviceIdentity) -> bool {
    if a.transport != b.transport || a.physical_path != b.physical_path {
        return false;
    }
    match (&a.mmc, &b.mmc) {
        (Some(x), Some(y)) => {
            if x.cid != y.cid || x.serial != y.serial {
                return false;
            }
        }
        (None, None) => {}
        _ => return false,
    }
    match (&a.usb, &b.usb) {
        (Some(x), Some(y)) => {
            if x.vid != y.vid || x.pid != y.pid || x.serial != y.serial {
                return false;
            }
        }
        (None, None) => {}
        _ => return false,
    }
    match (&a.scsi, &b.scsi) {
        (Some(x), Some(y)) => {
            if x.vendor != y.vendor || x.model != y.model || x.rev != y.rev {
                return false;
            }
        }
        (None, None) => {}
        _ => return false,
    }
    match (&a.sim, &b.sim) {
        (Some(x), Some(y)) => {
            if x.id != y.id {
                return false;
            }
        }
        (None, None) => {}
        _ => return false,
    }
    match (&a.mac, &b.mac) {
        (Some(x), Some(y)) => {
            if x.uuid != y.uuid || x.serial != y.serial {
                return false;
            }
        }
        (None, None) => {}
        _ => return false,
    }
    true
}

/// Identify a regular file as a pseudo-device (LBA or sim transport).
pub fn identify_file(path: &str) -> Result<DeviceIdentity> {
    let meta = std::fs::metadata(path).map_err(|e| Error::io(format!("stat {path}"), Some(e)))?;
    let mut identity = DeviceIdentity::new(TRANSPORT_FILE, path, &format!("file:{path}"));
    identity.capacity_bytes = meta.len();
    identity.removable = true;
    // DeviceIdentity::new computes the initial fingerprint before the file
    // geometry is known. Refresh it after setting the capacity so a resize
    // between plan and run cannot retain the old identity.
    identity.refresh_fingerprint();

    // Detect sim images by magic.
    if let Ok(f) = std::fs::File::open(path) {
        use std::io::Read;
        let mut head = [0u8; 8];
        if f.take(8).read_exact(&mut head).is_ok() && &head == SIM_MAGIC {
            if let Some(info) = crate::sim::read_header(Path::new(path)) {
                let sim_id = info.id.clone();
                identity.transport = TRANSPORT_FILE_SIM.to_string();
                identity.capacity_bytes = info.capacity_bytes;
                identity.sim = Some(info);
                identity.physical_path = format!("sim:{sim_id}");
                identity.refresh_fingerprint();
            }
        }
    }
    Ok(identity)
}

/// List removable whole-disk candidates (one line per device for `nclr ls`).
pub fn list_candidates() -> Result<Vec<DeviceIdentity>> {
    #[cfg(target_os = "linux")]
    {
        linux::list_candidates()
    }
    #[cfg(target_os = "macos")]
    {
        macos::list_candidates()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(Error::Unsupported(format!(
            "platform not supported for device listing: {}",
            std::env::consts::OS
        )))
    }
}

/// List all whole block devices for identity-bound re-enumeration tracking.
/// User-facing discovery continues to use [`list_candidates`] and therefore
/// excludes non-removable devices.
pub fn list_all_devices() -> Result<Vec<DeviceIdentity>> {
    #[cfg(target_os = "linux")]
    {
        linux::list_all_devices()
    }
    #[cfg(target_os = "macos")]
    {
        macos::list_candidates()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(Error::Unsupported(format!(
            "platform not supported for device listing: {}",
            std::env::consts::OS
        )))
    }
}

/// Open the target for raw block I/O with the given access mode.
/// On macOS the raw device (`/dev/rdiskN`) is used.
pub fn open_raw(path: &str, write: bool) -> Result<std::fs::File> {
    let p = Path::new(path);
    if p.is_file() {
        return std::fs::OpenOptions::new()
            .read(true)
            .write(write)
            .open(p)
            .map_err(|e| Error::io(format!("open {path}"), Some(e)));
    }
    #[cfg(target_os = "macos")]
    {
        let raw = raw_path(path);
        std::fs::OpenOptions::new()
            .read(true)
            .write(write)
            .open(&raw)
            .map_err(|e| Error::io(format!("open {} (macOS raw device)", raw), Some(e)))
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::fs::OpenOptions::new()
            .read(true)
            .write(write)
            .open(p)
            .map_err(|e| Error::io(format!("open {path}"), Some(e)))
    }
}

#[cfg(target_os = "macos")]
/// Translate /dev/diskX to the raw variant /dev/rdiskN.
fn raw_path(path: &str) -> String {
    if let Some(rest) = path.strip_prefix("/dev/disk") {
        format!("/dev/rdisk{rest}")
    } else {
        path.to_string()
    }
}

/// Check whether the path refers to a regular file.
pub fn is_regular_file(path: &str) -> bool {
    Path::new(path).is_file()
}

/// Reasons why a whole-disk block name is used by the running system
/// (Linux). An error is returned when the mount/swap state cannot be
/// determined (unknown usage must never authorize a run).
#[cfg(target_os = "linux")]
pub fn linux_system_disk_usage(name: &str) -> Result<Vec<String>> {
    linux::system_disk_usage(name)
}

/// Mount points on a Linux whole-disk block name.
#[cfg(target_os = "linux")]
pub fn linux_mount_points(name: &str) -> Result<Vec<String>> {
    linux::mount_points(name)
}

/// System disk device names on macOS (boot + system volumes).
#[cfg(target_os = "macos")]
pub fn macos_system_disk_devices() -> Result<Vec<String>> {
    macos::system_disk_devices()
}

/// SCSI generic node for a Linux block device (e.g. /dev/sg3).
#[cfg(target_os = "linux")]
pub fn linux_sg_path(name: &str) -> Option<String> {
    linux::resolve_sg_path(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn file_identity_is_stable() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("dev.img");
        std::fs::write(&f, vec![0u8; 4096]).unwrap();
        let a = identify(f.to_str().unwrap()).unwrap();
        let b = identify(f.to_str().unwrap()).unwrap();
        assert_eq!(a.fingerprint, b.fingerprint);
        assert_eq!(a.transport, TRANSPORT_FILE);
        assert_eq!(a.capacity_bytes, 4096);
        // The physical path is part of the fingerprint: a rename changes it
        // (consistent with physical-path matching).
        let f2 = dir.path().join("renamed.img");
        std::fs::rename(&f, &f2).unwrap();
        let c = identify(f2.to_str().unwrap()).unwrap();
        assert_ne!(c.fingerprint, a.fingerprint);
    }

    #[test]
    fn file_fingerprint_tracks_capacity() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("resized.img");
        std::fs::write(&f, vec![0u8; 4096]).unwrap();
        let before = identify(f.to_str().unwrap()).unwrap();

        std::fs::OpenOptions::new()
            .write(true)
            .open(&f)
            .unwrap()
            .set_len(8192)
            .unwrap();
        let after = identify(f.to_str().unwrap()).unwrap();

        assert_eq!(before.capacity_bytes, 4096);
        assert_eq!(after.capacity_bytes, 8192);
        assert_ne!(before.fingerprint, after.fingerprint);
    }

    #[test]
    fn unknown_path_is_usage_error() {
        assert!(identify("/nonexistent/device/xyz").is_err());
    }
}
