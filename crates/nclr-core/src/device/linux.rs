//! Linux device discovery via sysfs, procfs and mountinfo.
//!
//! - whole/partition classification via /sys/class/block/<name>/partition
//! - removable, size, queue geometry from sysfs attributes
//! - MMC identity from the mmc device attributes (CID/CSD/SCR)
//! - SCSI vendor/model/rev and sg association from the device chain
//! - USB VID/PID/serial/port chain by walking up the device chain
//! - mount/holder/swap detection via mountinfo, /proc/swaps and holders/

use super::{DeviceIdentity, MmcInfo, ScsiInfo, UsbInfo, TRANSPORT_MMC, TRANSPORT_USB_MSD};
use crate::errors::{Error, Result};
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const SYS_BLOCK: &str = "/sys/class/block";

fn read_attr(dir: &Path, name: &str) -> Option<String> {
    fs::read_to_string(dir.join(name))
        .ok()
        .map(|s| s.trim().to_string())
}

fn is_partition(dir: &Path) -> bool {
    fs::read_to_string(dir.join("partition")).is_ok()
}

/// major:minor of a block device, e.g. "8:16".
fn dev_majmin(name: &str) -> Option<String> {
    read_attr(&PathBuf::from(SYS_BLOCK).join(name), "dev")
}

/// Whether a directory name is an NVMe controller node ("nvme0", "nvme1",
/// ...); NVMe whole-disk nodes are "nvme0n1" and are not matched.
fn is_nvme_controller_dir(name: &str) -> bool {
    let Some(rest) = name.strip_prefix("nvme") else {
        return false;
    };
    !rest.is_empty() && rest.chars().all(|c| c.is_ascii_digit())
}

/// Whole-disk name for a major:minor pair by resolving the
/// /sys/dev/block/<maj:min> symlink.
/// - Partition sdb1: target .../block/sdb/sdb1 -> parent basename "sdb".
/// - Whole disk sdb: target .../block/sdb -> parent basename is "block";
///   the disk name is the target's own basename.
/// - NVMe whole disk nvme0n1: target .../nvme/nvme0/nvme0n1 -> the parent
///   is the controller node ("nvme0"); the disk name is the target's own
///   basename.
fn whole_disk_from_link(majmin: &str) -> Option<String> {
    let link = PathBuf::from(format!("/sys/dev/block/{majmin}"));
    let target = fs::read_link(&link).ok()?;
    let target = if target.is_absolute() {
        target
    } else {
        Path::new("/sys/dev/block").join(target)
    };
    let parent = target.parent()?;
    let parent_base = parent.file_name()?.to_string_lossy().into_owned();
    if parent_base == "block" || is_nvme_controller_dir(&parent_base) {
        target.file_name().map(|s| s.to_string_lossy().into_owned())
    } else {
        Some(parent_base)
    }
}

/// Whole-disk name for a partition name by resolving the dev symlink.
fn whole_disk_of_partition(name: &str) -> Option<String> {
    let majmin = dev_majmin(name)?;
    whole_disk_from_link(&majmin)
}

pub fn block_names() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(SYS_BLOCK) {
        for e in rd.flatten() {
            out.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    out.sort();
    out
}

/// Walk up the device chain from /sys/class/block/<name>/device to find
/// the closest USB device directory; returns (attrs, usb_path_basename).
fn find_usb_device(start: &Path) -> Option<(PathBuf, String)> {
    let mut dir = fs::canonicalize(start).ok()?;
    for _ in 0..10 {
        if dir.join("idVendor").exists() {
            let port = dir.file_name()?.to_string_lossy().into_owned();
            return Some((dir, port));
        }
        dir = dir.parent()?.to_path_buf();
    }
    None
}

fn block_device_path(name: &str) -> String {
    format!("/dev/{name}")
}

/// Identify a whole block device by its /sys/class/block/<name>.
fn identify_name(name: &str) -> Option<DeviceIdentity> {
    let dir = PathBuf::from(SYS_BLOCK).join(name);
    let majmin = dev_majmin(name)?;

    let size_sectors: u64 = read_attr(&dir, "size")?.parse().ok()?;
    let removable = read_attr(&dir, "removable") == Some("1".to_string());
    let read_only = read_attr(&dir, "ro") == Some("1".to_string());
    // Discovery is best-effort: a missing attribute must not drop the
    // device from the candidate list, and 512 is the de-facto standard
    // logical block size (real 4Kn devices always expose the attribute).
    // The fingerprint includes the value, so an incorrect fallback would
    // still fail the plan identity check rather than pass silently.
    let logical_block_size: u32 = read_attr(&dir.join("queue"), "logical_block_size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(512);
    let capacity_bytes = size_sectors.saturating_mul(512);

    // MMC?
    let mmc = if name.starts_with("mmcblk") {
        let dev_dir = fs::canonicalize(dir.join("device")).ok()?;
        let host = dev_dir
            .file_name()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_default();
        Some(MmcInfo {
            cid: read_attr(&dev_dir, "cid").unwrap_or_default(),
            csd: read_attr(&dev_dir, "csd").unwrap_or_default(),
            scr: read_attr(&dev_dir, "scr").unwrap_or_default(),
            manfid: read_attr(&dev_dir, "manfid").unwrap_or_default(),
            oemid: read_attr(&dev_dir, "oemid").unwrap_or_default(),
            name: read_attr(&dev_dir, "name").unwrap_or_default(),
            serial: read_attr(&dev_dir, "serial").unwrap_or_default(),
            date: read_attr(&dev_dir, "date").unwrap_or_default(),
            host,
            kind: read_attr(&dev_dir, "type").unwrap_or_default(),
            erase_size_bytes: read_attr(&dev_dir, "erase_size")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
            preferred_erase_size_bytes: read_attr(&dev_dir, "preferred_erase_size")
                .and_then(|value| value.parse().ok())
                .unwrap_or(0),
        })
    } else {
        None
    };

    // SCSI info (sd*/sr*).
    let scsi = if name.starts_with("sd") || name.starts_with("sr") {
        let dev_dir = fs::canonicalize(dir.join("device")).ok();
        let vendor = dev_dir
            .as_ref()
            .and_then(|d| read_attr(d, "vendor"))
            .unwrap_or_default();
        let model = dev_dir
            .as_ref()
            .and_then(|d| read_attr(d, "model"))
            .unwrap_or_default();
        let rev = dev_dir
            .as_ref()
            .and_then(|d| read_attr(d, "rev"))
            .unwrap_or_default();
        Some(ScsiInfo {
            vendor,
            model,
            rev,
            sg_path: resolve_sg_path(name).unwrap_or_default(),
        })
    } else {
        None
    };

    // USB info by walking up the device chain.
    let usb = if let Some((udir, port_chain)) = find_usb_device(&dir.join("device")) {
        Some(UsbInfo {
            vid: read_attr(&udir, "idVendor").unwrap_or_default(),
            pid: read_attr(&udir, "idProduct").unwrap_or_default(),
            bcd_device: read_attr(&udir, "bcdDevice").unwrap_or_default(),
            serial: read_attr(&udir, "serial").unwrap_or_default(),
            manufacturer: read_attr(&udir, "manufacturer").unwrap_or_default(),
            product: read_attr(&udir, "product").unwrap_or_default(),
            port_chain,
        })
    } else {
        None
    };

    // USB mass storage (and opaque USB card readers whose SD pass-through
    // cannot be proven from sysfs): both are reported as usb-msd. The
    // "sd-via-usb" transport is not produced on Linux today.
    let transport = if mmc.is_some() {
        TRANSPORT_MMC
    } else {
        TRANSPORT_USB_MSD
    };

    let physical_path = if let Some(u) = &usb {
        format!("usb:{}", u.port_chain)
    } else if let Some(m) = &mmc {
        format!("mmc-host:{}", m.host)
    } else {
        format!("block:{majmin}")
    };

    let mut identity = DeviceIdentity::new(transport, &block_device_path(name), &physical_path);
    identity.capacity_bytes = capacity_bytes;
    identity.logical_block_size = logical_block_size;
    identity.removable = removable;
    identity.read_only = read_only;
    identity.mmc = mmc;
    identity.usb = usb;
    identity.scsi = scsi;
    identity.refresh_fingerprint();
    Some(identity)
}

/// Fill in holders (direct holders + dm/md membership) and mount state.
/// Mount-state detection propagates errors: an unreadable mount table must
/// never be reported as "unmounted".
fn enrich(name: &str, identity: &mut DeviceIdentity) -> Result<()> {
    let dir = PathBuf::from(SYS_BLOCK).join(name);
    let mut holders: Vec<String> = Vec::new();
    if let Ok(rd) = fs::read_dir(dir.join("holders")) {
        for e in rd.flatten() {
            holders.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    // dm-crypt / LVM / mdraid membership: target appears as a slave of some dm/md device.
    let majmin = dev_majmin(name);
    for other in block_names() {
        if other == name {
            continue;
        }
        let slaves_dir = PathBuf::from(SYS_BLOCK).join(&other).join("slaves");
        if let Ok(rd) = fs::read_dir(&slaves_dir) {
            for e in rd.flatten() {
                let slave = e.file_name().to_string_lossy().into_owned();
                let slave_majmin = dev_majmin(&slave);
                if slave_majmin.is_some() && slave_majmin == majmin {
                    holders.push(other.clone());
                }
            }
        }
    }
    holders.sort();
    holders.dedup();
    identity.holders = holders;
    identity.mounted = !mount_points(name)?.is_empty();
    Ok(())
}

/// Parse /proc/self/mountinfo into (major:minor -> mount points).
fn parse_mountinfo(content: &str) -> Vec<(String, String, String, String)> {
    let mut out = Vec::new();
    for line in content.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        // fields[1] = parent id, fields[2] = major:minor, fields[4] = mountpoint, fields[8] = fstype
        let majmin = fields[2].to_string();
        let mount_point = fields[4].to_string();
        let fs_type = fields[8].to_string();
        let source = fields.get(9).unwrap_or(&"").to_string();
        out.push((majmin, mount_point, fs_type, source));
    }
    out
}

pub fn read_mountinfo() -> Result<Vec<(String, String, String, String)>> {
    let content = fs::read_to_string("/proc/self/mountinfo")
        .map_err(|e| Error::io("cannot read /proc/self/mountinfo", Some(e)))?;
    Ok(parse_mountinfo(&content))
}

/// Mount points belonging to a whole-disk block name (Linux).
pub fn mount_points(name: &str) -> Result<Vec<String>> {
    Ok(mount_hits(
        name,
        dev_majmin(name),
        &read_mountinfo()?,
        whole_disk_of_partition_by_majmin,
    ))
}

/// Pure mount-matching core: mounts that touch `name` directly (its major:
/// minor) or via one of its partitions (resolved by `resolve_partition`).
fn mount_hits(
    name: &str,
    my_majmin: Option<String>,
    mounts: &[(String, String, String, String)],
    resolve_partition: impl Fn(u32, u32) -> Option<String>,
) -> Vec<String> {
    let mut out = Vec::new();
    for (m, mp, _ft, _src) in mounts {
        let hit = if Some(m) == my_majmin.as_ref() {
            true
        } else {
            let pmaj = m.split(':').next().unwrap_or("").parse::<u32>().ok();
            let pmin = m.split(':').nth(1).unwrap_or("").parse::<u32>().ok();
            match (pmaj, pmin) {
                (Some(pmaj), Some(pmin)) => resolve_partition(pmaj, pmin).as_deref() == Some(name),
                _ => false,
            }
        };
        if hit {
            out.push(mp.clone());
        }
    }
    out
}

/// Whether the given device is used by the system (/, /boot, /usr, /var
/// or swap). `name` is the whole-disk block name. A failure to read the
/// mount table or /proc/swaps propagates: unknown system usage must refuse.
pub fn system_disk_usage(name: &str) -> Result<Vec<String>> {
    let mut reasons = Vec::new();
    let my_majmin = dev_majmin(name);
    for (m, mount_point, _ft, _src) in read_mountinfo()? {
        let is_critical = matches!(mount_point.as_str(), "/" | "/boot" | "/usr" | "/var");
        if is_critical {
            let hits = if Some(&m) == my_majmin.as_ref() {
                true
            } else {
                // check if the mounted device belongs to this whole disk
                let pmaj = m.split(':').next().unwrap_or("");
                let pmin = m.split(':').nth(1).unwrap_or("");
                if let (Ok(pmaj), Ok(pmin)) = (pmaj.parse::<u32>(), pmin.parse::<u32>()) {
                    if let Some(whole) = whole_disk_of_partition_by_majmin(pmaj, pmin) {
                        whole == name
                    } else {
                        false
                    }
                } else {
                    false
                }
            };
            if hits {
                reasons.push(format!("mounted at {mount_point}"));
            }
        }
    }
    let swaps = fs::read_to_string("/proc/swaps")
        .map_err(|e| Error::io("cannot read /proc/swaps", Some(e)))?;
    for line in swaps.lines().skip(1) {
        let dev = line.split_whitespace().next().unwrap_or("");
        let dev_name = dev.rsplit('/').next().unwrap_or("");
        if dev_name == name || whole_disk_of_partition(dev_name).as_deref() == Some(name) {
            reasons.push(format!("in use as swap ({dev})"));
        }
    }
    Ok(reasons)
}

fn whole_disk_of_partition_by_majmin(pmaj: u32, pmin: u32) -> Option<String> {
    whole_disk_from_link(&format!("{pmaj}:{pmin}"))
}

/// Resolve the SCSI generic node (/dev/sgN) for a block device by matching
/// the canonical scsi-device path under /sys/class/scsi_generic.
pub fn resolve_sg_path(name: &str) -> Option<String> {
    let block_dev = fs::canonicalize(PathBuf::from(SYS_BLOCK).join(name).join("device")).ok()?;
    let sg_root = PathBuf::from("/sys/class/scsi_generic");
    let rd = fs::read_dir(&sg_root).ok()?;
    for e in rd.flatten() {
        let sg_name = e.file_name().to_string_lossy().into_owned();
        let dev = fs::canonicalize(sg_root.join(&sg_name).join("device")).ok()?;
        if dev == block_dev {
            return Some(format!("/dev/{sg_name}"));
        }
    }
    None
}

pub fn identify(path: &str) -> Result<DeviceIdentity> {
    let name = path
        .trim_start_matches("/dev/")
        .split('/')
        .next()
        .unwrap_or("")
        .to_string();
    if name.is_empty() {
        return Err(Error::Usage(format!("invalid device path: {path}")));
    }
    if !Path::new(SYS_BLOCK).join(&name).exists() {
        return Err(Error::Usage(format!(
            "not a block device in sysfs: {path} (name {name})"
        )));
    }
    if is_partition(&PathBuf::from(SYS_BLOCK).join(&name)) {
        return Err(Error::Usage(format!(
            "target must be a whole block device, not a partition: {path}"
        )));
    }
    let mut identity = identify_name(&name)
        .ok_or_else(|| Error::io(format!("cannot read sysfs attributes for {name}"), None))?;
    enrich(&name, &mut identity)?;
    Ok(identity)
}

fn list_whole_disks(removable_only: bool) -> Result<Vec<DeviceIdentity>> {
    let mut out = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for name in block_names() {
        let dir = PathBuf::from(SYS_BLOCK).join(&name);
        if is_partition(&dir) {
            continue;
        }
        // Skip kernel-internal and virtual devices.
        if name.starts_with("loop")
            || name.starts_with("ram")
            || name.starts_with("zram")
            || name.starts_with("fd")
            || name.starts_with("dm-")
            || name.starts_with("md")
            || name.starts_with("sr")
        {
            continue;
        }
        if let Some(mut identity) = identify_name(&name) {
            if removable_only && !identity.removable {
                continue;
            }
            enrich(&name, &mut identity)?;
            // De-duplicate devices that alias the same whole disk.
            if let Some(whole) = whole_disk_of_partition(&name) {
                if !seen.insert(whole) {
                    continue;
                }
            } else if !seen.insert(name.clone()) {
                continue;
            }
            out.push(identity);
        }
    }
    Ok(out)
}

pub fn list_candidates() -> Result<Vec<DeviceIdentity>> {
    list_whole_disks(true)
}

pub fn list_all_devices() -> Result<Vec<DeviceIdentity>> {
    list_whole_disks(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mountinfo_parsing() {
        let sample = "36 22 0:24 / /sys rw,nosuid,nodev,noexec shared:7 - sysfs sysfs rw\n\
                      93 36 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
                      94 93 8:2 /boot /boot rw shared:2 - ext4 /dev/sda2 rw\n\
                      95 93 8:17 / /media/usb rw shared:3 - vfat /dev/sdb1 rw\n";
        let mounts = parse_mountinfo(sample);
        assert_eq!(mounts.len(), 4);
        assert_eq!(mounts[1].0, "8:1");
        assert_eq!(mounts[1].1, "/");
        assert_eq!(mounts[3].3, "/dev/sdb1");
    }

    #[test]
    fn mounted_detection() {
        // A mount on a partition must mark the whole disk mounted.
        let sample = "36 22 0:24 / /sys rw,nosuid,nodev,noexec shared:7 - sysfs sysfs rw\n\
                      93 36 8:1 / / rw,relatime shared:1 - ext4 /dev/sda1 rw\n\
                      94 93 8:2 /boot /boot rw shared:2 - ext4 /dev/sda2 rw\n\
                      95 93 8:17 / /media/usb rw shared:3 - vfat /dev/sdb1 rw\n";
        let mounts = parse_mountinfo(sample);
        let resolve = |pmaj: u32, pmin: u32| -> Option<String> {
            match (pmaj, pmin) {
                (8, 1) | (8, 2) => Some("sda".into()),
                (8, 17) => Some("sdb".into()),
                _ => None,
            }
        };
        // sdb's partition sdb1 is mounted -> sdb is mounted.
        let hits = mount_hits("sdb", Some("8:16".into()), &mounts, resolve);
        assert_eq!(hits, vec!["/media/usb"]);
        assert!(
            !hits.is_empty(),
            "partition mount must mark the whole disk mounted"
        );
        // sda is mounted too (root and /boot).
        let hits_sda = mount_hits("sda", Some("8:0".into()), &mounts, resolve);
        assert_eq!(hits_sda.len(), 2);
        // An unmounted disk (no partitions in the table) reports nothing.
        let hits_none = mount_hits("sdc", Some("8:32".into()), &mounts, resolve);
        assert!(hits_none.is_empty());
    }
}
