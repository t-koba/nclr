//! Safety interlock checks:
//! system disk protection, mounts, holders, swap, removable policy.

use crate::device::DeviceIdentity;
use crate::errors::{Error, Result};
use std::process::Command;

#[derive(Debug, Clone, Default)]
pub struct SafetyOptions {
    pub unmount: bool,
    pub allow_nonremovable: bool,
}

#[derive(Debug, Default)]
pub struct SafetyResult {
    pub unmounted: Vec<String>,
}

/// Whether a whole-disk device name is the system disk, given the boot
/// device names from the mount table (e.g. "disk3s1s1"). The comparison is
/// whole-disk aware: any partition of the system disk matches.
#[cfg(target_os = "macos")]
fn is_system_disk(whole_disk_name: &str, boot_devices: &[String]) -> bool {
    boot_devices.iter().any(|d| {
        // Strip a leading /dev/ prefix, then compare whole disks.
        let d = d.trim_start_matches("/dev/");
        whole_disk_of(d) == Some(whole_disk_name)
    })
}

/// The whole-disk prefix of a macOS device name ("disk3s1s1" -> "disk3").
#[cfg(target_os = "macos")]
fn whole_disk_of(name: &str) -> Option<&str> {
    let rest = name.strip_prefix("disk")?;
    let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    Some(&name[..4 + digits])
}

/// Reject critical system disk usage. No single-flag unlock: system disk
/// protection is absolute in this build.
fn check_system_disk(identity: &DeviceIdentity) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let name = identity.kernel_path.trim_start_matches("/dev/").to_string();
        let reasons = crate::device::linux_system_disk_usage(&name)?;
        if !reasons.is_empty() {
            return Err(Error::Permission(format!(
                "target {} is used by the running system ({}); refusing",
                identity.kernel_path,
                reasons.join(", ")
            )));
        }
    }
    #[cfg(target_os = "macos")]
    {
        let name = identity.kernel_path.trim_start_matches("/dev/").to_string();
        let boot_devices = crate::device::macos_system_disk_devices()?;
        if is_system_disk(&name, &boot_devices) {
            return Err(Error::Permission(format!(
                "target {} is the macOS system disk; refusing",
                identity.kernel_path
            )));
        }
    }
    Ok(())
}

fn check_mounted(identity: &DeviceIdentity, opts: &SafetyOptions) -> Result<SafetyResult> {
    let mut result = SafetyResult::default();
    if !identity.mounted {
        return Ok(result);
    }
    if !opts.unmount {
        return Err(Error::Permission(format!(
            "target {} is mounted; refusing without --unmount",
            identity.kernel_path
        )));
    }
    // Unmount target mounts (normal unmount only; no lazy/force).
    #[cfg(target_os = "linux")]
    {
        let name = identity.kernel_path.trim_start_matches("/dev/").to_string();
        let mounts = crate::device::linux_mount_points(&name)?;
        if mounts.is_empty() {
            return Err(Error::Permission(format!(
                "target {} reports mounted but no mount points found",
                identity.kernel_path
            )));
        }
        for mp in mounts {
            let st = Command::new("umount")
                .arg(&mp)
                .status()
                .map_err(|e| Error::io(format!("cannot execute umount for {mp}"), Some(e)))?;
            if !st.success() {
                return Err(Error::Permission(format!(
                    "unmount failed for {mp}; refusing to continue"
                )));
            }
            result.unmounted.push(mp);
        }
    }
    #[cfg(target_os = "macos")]
    {
        let st = Command::new("diskutil")
            // The target is always a whole disk. `unmount` handles only one
            // volume, while `unmountDisk` normally unmounts every volume and
            // storage-system export backed by the disk. Do not pass `force`.
            .arg("unmountDisk")
            .arg(&identity.kernel_path)
            .status()
            .map_err(|e| {
                Error::io(
                    format!("cannot execute diskutil unmount {}", identity.kernel_path),
                    Some(e),
                )
            })?;
        if !st.success() {
            return Err(Error::Permission(
                "diskutil unmountDisk failed; refusing to continue".into(),
            ));
        }
        result.unmounted.push(identity.kernel_path.clone());
    }
    Ok(result)
}

fn check_holders(identity: &DeviceIdentity) -> Result<()> {
    if identity.holders.is_empty() {
        return Ok(());
    }
    Err(Error::Permission(format!(
        "target {} has kernel holders (dm/md/LVM/RAID: {}); refusing",
        identity.kernel_path,
        identity.holders.join(", ")
    )))
}

fn check_read_only(identity: &DeviceIdentity) -> Result<()> {
    if identity.read_only {
        return Err(Error::Permission(format!(
            "target {} is read-only / write-protected; destructive operations are refused",
            identity.kernel_path
        )));
    }
    Ok(())
}

fn check_removable(identity: &DeviceIdentity, opts: &SafetyOptions) -> Result<()> {
    if identity.removable {
        return Ok(());
    }
    if opts.allow_nonremovable {
        // Additional conditions (full fingerprint confirmation, explicit
        // level) are enforced by the caller; system disk protection above
        // remains absolute.
        return Ok(());
    }
    Err(Error::Permission(format!(
        "target {} is not marked removable by the kernel/OS; use --allow-nonremovable together with full fingerprint confirmation",
        identity.kernel_path
    )))
}

/// Full preflight check. Returns unmounted mount points on success.
pub fn preflight(identity: &DeviceIdentity, opts: &SafetyOptions) -> Result<SafetyResult> {
    check_system_disk(identity)?;
    check_holders(identity)?;
    check_read_only(identity)?;
    let result = check_mounted(identity, opts)?;
    check_removable(identity, opts)?;
    // Swap on macOS: swap is a system file, not a device.
    Ok(result)
}

/// Full topology/mount preflight for a workflow that does not write media.
/// Read-only or write-protected targets are accepted, but system disks,
/// holders, mounted filesystems and non-removable policy remain enforced.
pub fn preflight_read(identity: &DeviceIdentity, opts: &SafetyOptions) -> Result<SafetyResult> {
    check_system_disk(identity)?;
    check_holders(identity)?;
    let result = check_mounted(identity, opts)?;
    check_removable(identity, opts)?;
    Ok(result)
}

/// Check a single device for `check` / `info` commands (read-only):
/// returns warnings instead of errors where appropriate.
pub fn preflight_soft(identity: &DeviceIdentity) -> Vec<String> {
    let mut warnings = Vec::new();
    if identity.mounted {
        warnings.push("device is mounted".to_string());
    }
    if !identity.holders.is_empty() {
        warnings.push(format!("has holders: {}", identity.holders.join(", ")));
    }
    if !identity.removable {
        warnings.push("not marked removable".to_string());
    }
    warnings
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_identity(path: &str) -> DeviceIdentity {
        crate::device::identify(path).unwrap()
    }

    #[test]
    fn plain_file_passes_safety() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("img");
        std::fs::write(&f, vec![0u8; 8192]).unwrap();
        let id = file_identity(f.to_str().unwrap());
        let r = preflight(&id, &SafetyOptions::default()).unwrap();
        assert!(r.unmounted.is_empty());
    }

    #[test]
    fn nonexistent_holder_refusal_logic() {
        // holders refusal must trigger on populated holders
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("img2");
        std::fs::write(&f, vec![0u8; 8192]).unwrap();
        let mut id = file_identity(f.to_str().unwrap());
        id.holders.push("dm-0".into());
        assert!(preflight(&id, &SafetyOptions::default()).is_err());
    }

    #[test]
    fn nonremovable_requires_flag() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("img3");
        std::fs::write(&f, vec![0u8; 8192]).unwrap();
        let mut id = file_identity(f.to_str().unwrap());
        id.removable = false;
        assert!(preflight(&id, &SafetyOptions::default()).is_err());
        assert!(preflight(
            &id,
            &SafetyOptions {
                allow_nonremovable: true,
                ..Default::default()
            }
        )
        .is_ok());
    }
}

#[cfg(target_os = "macos")]
#[test]
fn whole_disk_of_macos_names() {
    assert_eq!(whole_disk_of("disk3"), Some("disk3"));
    assert_eq!(whole_disk_of("disk3s1s1"), Some("disk3"));
    assert_eq!(whole_disk_of("disk10s2"), Some("disk10"));
    assert_eq!(whole_disk_of("disk0s1"), Some("disk0"));
    assert_eq!(whole_disk_of("usb-stick"), None);
}

#[cfg(target_os = "macos")]
#[test]
fn system_disk_matches_partitions() {
    let boot = vec![
        "/dev/disk3s1s1".to_string(),
        "/dev/disk3s5".to_string(),
        "/dev/disk3s6".to_string(),
    ];
    // The whole system disk and any of its partitions match.
    assert!(is_system_disk("disk3", &boot));
    // A different disk is not the system disk.
    assert!(!is_system_disk("disk0", &boot));
    assert!(!is_system_disk("disk2", &boot));
    // Empty table: never the system disk.
    assert!(!is_system_disk("disk3", &[]));
}

#[cfg(target_os = "macos")]
#[test]
fn system_disk_preflight_refuses() {
    // The preflight must refuse a device that is the macOS system disk.
    // Resolve the live system disk from the mount table and assert the
    // refusal (exit 77) for it.
    let boot_devices = crate::device::macos_system_disk_devices().unwrap();
    let Some(whole) = boot_devices.iter().find_map(|d| whole_disk_of(d)) else {
        panic!("macOS mount table must list a system volume");
    };
    let dir = tempfile::tempdir().unwrap();
    let f = dir.path().join("img");
    std::fs::write(&f, vec![0u8; 8192]).unwrap();
    let mut id = crate::device::identify(f.to_str().unwrap()).unwrap();
    id.kernel_path = format!("/dev/{whole}");
    let err = preflight(&id, &SafetyOptions::default()).unwrap_err();
    assert_eq!(err.exit_code(), crate::errors::exit::PERMISSION);
    assert!(
        err.to_string().contains("system disk"),
        "unexpected error: {err}"
    );
}

#[cfg(test)]
mod read_only_tests {
    use super::*;

    #[test]
    fn read_only_media_is_refused_for_destructive_runs() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("img");
        std::fs::write(&f, vec![0u8; 8192]).unwrap();
        let mut id = crate::device::identify(f.to_str().unwrap()).unwrap();
        id.read_only = true;
        let err = preflight(&id, &SafetyOptions::default()).unwrap_err();
        assert_eq!(
            err.exit_code(),
            77,
            "read-only must be a permission refusal"
        );
        assert!(err.to_string().contains("read-only"));

        id.read_only = false;
        assert!(preflight(&id, &SafetyOptions::default()).is_ok());
    }
}
