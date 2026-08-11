//! macOS device discovery via `diskutil info/list -plist` piped through
//! `plutil -convert json`. LBA I/O uses the raw device `/dev/rdiskN`.
//!
//! System disk / mount detection uses the `mount` table; holders are
//! limited to APFS physical stores (macOS has no dm/md concept).

use super::{DeviceIdentity, MacInfo, TRANSPORT_USB_MSD};
use crate::errors::{Error, Result};
use std::process::{Command, Stdio};

fn diskutil(args: &[&str]) -> Result<serde_json::Value> {
    let out = Command::new("diskutil")
        .args(args)
        .stdin(Stdio::null())
        .output()
        .map_err(|e| Error::Backend(format!("cannot execute diskutil: {e}")))?;
    if !out.status.success() {
        return Err(Error::io(
            format!(
                "diskutil {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            ),
            None,
        ));
    }
    let json = Command::new("plutil")
        .args(["-convert", "json", "-o", "-", "-"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write;
            let stdin = child.stdin.as_mut().ok_or_else(|| {
                std::io::Error::new(std::io::ErrorKind::BrokenPipe, "plutil stdin unavailable")
            })?;
            stdin.write_all(&out.stdout)?;
            child.wait_with_output()
        })
        .map_err(|e| Error::Backend(format!("cannot execute plutil: {e}")))?;
    if !json.status.success() {
        return Err(Error::Invalid(format!(
            "plutil failed while converting diskutil output: {}",
            String::from_utf8_lossy(&json.stderr).trim()
        )));
    }
    serde_json::from_slice(&json.stdout)
        .map_err(|e| Error::Invalid(format!("cannot parse plutil output: {e}")))
}

fn get<'a>(v: &'a serde_json::Value, key: &str) -> Option<&'a serde_json::Value> {
    v.get(key).filter(|x| !x.is_null())
}

fn str_field(v: &serde_json::Value, key: &str) -> String {
    get(v, key)
        .and_then(|x| x.as_str())
        .unwrap_or("")
        .to_string()
}

fn bool_field(v: &serde_json::Value, key: &str) -> bool {
    get(v, key).and_then(|x| x.as_bool()).unwrap_or(false)
}

fn optional_bool_field(v: &serde_json::Value, key: &str) -> Option<bool> {
    get(v, key).and_then(|x| x.as_bool())
}

fn u64_field(v: &serde_json::Value, key: &str) -> u64 {
    get(v, key).and_then(|x| x.as_u64()).unwrap_or(0)
}

/// Whole disk list from `diskutil list -plist`.
pub fn whole_disks() -> Result<Vec<String>> {
    let list = diskutil(&["list", "-plist"])?;
    let disks = get(&list, "WholeDisks")
        .and_then(|x| x.as_array())
        .ok_or_else(|| Error::Invalid("diskutil list did not return WholeDisks".into()))?;
    disks
        .iter()
        .map(|value| {
            value
                .as_str()
                .map(String::from)
                .ok_or_else(|| Error::Invalid("diskutil WholeDisks contains a non-string".into()))
        })
        .collect()
}

/// Extract mount table entries as (device, mount_point). A failure to read
/// the mount table must propagate: an unknown mount state must never be
/// reported as "unmounted" (that would authorize destructive runs).
fn mount_table() -> Result<Vec<(String, String)>> {
    let out = Command::new("mount")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| Error::io("cannot run mount", Some(e)))?
        .stdout;
    let out = String::from_utf8_lossy(&out).into_owned();
    let mut table = Vec::new();
    for line in out.lines() {
        // e.g. "/dev/disk3s5 on /System/Volumes/Data (apfs, ...)"
        let mut it = line.splitn(3, " on ");
        if let (Some(dev), Some(rest)) = (it.next(), it.next()) {
            let mp = rest.split(" (").next().unwrap_or("").trim();
            table.push((dev.trim().to_string(), mp.to_string()));
        }
    }
    if table.is_empty() {
        return Err(Error::Invalid(
            "mount returned no parseable entries; system-disk state is unknown".into(),
        ));
    }
    Ok(table)
}

/// Whole-disk prefix of a macOS disk name ("disk2s1" -> Some("disk2")).
/// Whole disks match `disk<digits>` ("disk0", "disk10", ...).
fn whole_prefix(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("disk")?;
    let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    Some(&name[..4 + digits])
}

fn is_whole_disk(name: &str) -> bool {
    whole_prefix(name).map(|w| w == name).unwrap_or(false)
}

/// Whole disk that a device path belongs to ("disk2s1" -> "disk2").
fn parent_whole_disk(device: &str) -> String {
    let name = device.trim_start_matches("/dev/").to_string();
    whole_prefix(&name).map(|w| w.to_string()).unwrap_or(name)
}

/// Build identity from `diskutil info -plist` output for /dev/<name>.
fn identify_diskutil(name: &str) -> Result<DeviceIdentity> {
    let dev = format!("/dev/{name}");
    let info = diskutil(&["info", "-plist", &dev])?;

    let removable = bool_field(&info, "RemovableMedia")
        || bool_field(&info, "RemovableMediaOrExternalDevice")
        || bool_field(&info, "Ejectable");
    let protocol = str_field(&info, "BusProtocol");
    let serial = str_field(&info, "SerialNumber");
    let media_name = str_field(&info, "MediaName");
    let uuid = str_field(&info, "DiskUUID");
    let media_type = str_field(&info, "MediaType");
    let size = u64_field(&info, "Size").max(u64_field(&info, "IOKitSize"));
    let block_size_raw = u64_field(&info, "DeviceBlockSize");
    let block_size = u32::try_from(block_size_raw).map_err(|_| {
        Error::Invalid(format!(
            "diskutil returned out-of-range block size {block_size_raw} for {dev}"
        ))
    })?;
    let parent = str_field(&info, "ParentWholeDisk");

    // SD via a USB card reader is not distinguishable from USB MSD via
    // diskutil; keep the generic USB label (SD pass-through is a Phase 5 item).
    let transport = TRANSPORT_USB_MSD;

    let mac = MacInfo {
        protocol,
        serial,
        media_name,
        uuid,
        media_type,
        parent_whole_disk: parent.clone(),
    };

    let physical_path = format!(
        "macos:{}",
        if parent.is_empty() {
            name.to_string()
        } else {
            parent
        }
    );

    let mut identity = DeviceIdentity::new(transport, &dev, &physical_path);
    if size == 0 {
        return Err(Error::Invalid(format!(
            "diskutil returned zero capacity for {dev}"
        )));
    }
    if block_size < 512 || !block_size.is_power_of_two() {
        return Err(Error::Invalid(format!(
            "diskutil returned invalid block size {block_size} for {dev}"
        )));
    }
    identity.capacity_bytes = size;
    identity.logical_block_size = block_size;
    identity.removable = removable;
    identity.read_only =
        bool_field(&info, "ReadOnlyMedia") || optional_bool_field(&info, "Writable") == Some(false);
    identity.mac = Some(mac);
    identity.mounted = false;

    // Mount state: any mount entry for this device or its partitions. An
    // unreadable mount table fails identification: unknown != unmounted.
    let whole = parent_whole_disk(name);
    for (mdev, _mp) in mount_table()? {
        let mwhole = parent_whole_disk(&mdev);
        if mwhole == whole {
            identity.mounted = true;
        }
    }
    identity.refresh_fingerprint();
    Ok(identity)
}

/// Identify a device path (/dev/diskX).
pub fn identify(path: &str) -> Result<DeviceIdentity> {
    let name = path.trim_start_matches("/dev/").to_string();
    if name.is_empty() {
        return Err(Error::Usage(format!("invalid device path: {path}")));
    }
    if !is_whole_disk(&name) {
        return Err(Error::Usage(format!(
            "target must be a whole disk (e.g. /dev/disk2), got: {path}"
        )));
    }
    identify_diskutil(&name)
}

/// List removable whole disks.
pub fn list_candidates() -> Result<Vec<DeviceIdentity>> {
    let mut out = Vec::new();
    for name in whole_disks()? {
        // Skip internal / non-removable disks.
        let ident = identify_diskutil(&name)?;
        if ident.removable {
            out.push(ident);
        }
    }
    Ok(out)
}

/// System disk check for macOS: find the device that "/" is mounted from and
/// return it; also the parent whole disk. An unreadable mount table must
/// propagate: an unknown system-disk state must never authorize a run.
pub fn system_disk_devices() -> Result<Vec<String>> {
    let mut out = Vec::new();
    for (dev, mp) in mount_table()? {
        let critical = matches!(
            mp.as_str(),
            "/" | "/System/Volumes/Data"
                | "/System/Volumes/Preboot"
                | "/System/Volumes/VM"
                | "/System/Volumes/Update"
                | "/System/Volumes/Hardware"
                | "/System/Volumes/iSCPreboot"
                | "/System/Volumes/xarts"
        );
        if critical {
            out.push(dev.trim_start_matches("/dev/").to_string());
        }
    }
    if out.is_empty() {
        return Err(Error::Invalid(
            "the macOS system disk could not be resolved from the mount table".into(),
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parent_whole_disk_logic() {
        assert_eq!(parent_whole_disk("/dev/disk2s1"), "disk2");
        assert_eq!(parent_whole_disk("/dev/disk0"), "disk0");
        assert_eq!(parent_whole_disk("/dev/disk3s1s1"), "disk3");
        assert_eq!(parent_whole_disk("/dev/disk10s2"), "disk10");
    }

    #[test]
    fn whole_disk_name_detection() {
        assert!(is_whole_disk("disk0"));
        assert!(!is_whole_disk("disk0s1"));
    }

    #[test]
    fn mount_table_parses() {
        // Runs on any macOS; must not panic.
        let table = mount_table().unwrap();
        assert!(!table.is_empty(), "macOS always has a mount table");
    }
}
