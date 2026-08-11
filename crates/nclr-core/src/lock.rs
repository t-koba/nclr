//! Exclusive per-device/physical-path locking via flock.
//!
//! Lock path: `/run/lock/nclr/<fingerprint-sha>.lock` on Linux,
//! $XDG_RUNTIME_DIR or TMPDIR on other systems. Callers use a stable physical
//! path key when a controller may change its reported identity.

use crate::errors::{Error, Result};
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::os::fd::AsRawFd;
use std::path::PathBuf;

pub struct DeviceLock {
    #[allow(dead_code)] // held open so the flock is released on drop
    file: std::fs::File,
}

fn lock_name(identity_key: &str) -> String {
    hex::encode(Sha256::digest(identity_key.as_bytes()))
}

fn lock_dir() -> PathBuf {
    #[cfg(target_os = "linux")]
    {
        if crate::journal::nix_uid() == 0 {
            return PathBuf::from("/run/lock/nclr");
        }
    }
    let base = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("TMPDIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from("/tmp"));
    base.join("nclr-lock")
}

/// Acquire an exclusive flock for the given stable device identity key.
pub fn acquire(identity_key: &str) -> Result<DeviceLock> {
    let dir = lock_dir();
    std::fs::create_dir_all(&dir)
        .map_err(|e| Error::io(format!("cannot create lock dir {}", dir.display()), Some(e)))?;
    let name = lock_name(identity_key);
    let path = dir.join(format!("{name}.lock"));
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|e| Error::io(format!("cannot open lock {}", path.display()), Some(e)))?;
    let rc = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if rc != 0 {
        let source = std::io::Error::last_os_error();
        if source.kind() == std::io::ErrorKind::WouldBlock {
            return Err(Error::Permission(format!(
                "another nclr process holds the lock for this device ({})",
                path.display()
            )));
        }
        return Err(Error::io(
            format!("cannot lock {}", path.display()),
            Some(source),
        ));
    }
    Ok(DeviceLock { file })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn double_lock_refused() {
        // No global env mutation: a per-process fingerprint keeps this test
        // isolated from parallel tests sharing the lock directory.
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let fp = format!("sha256:test-{}-{nonce}", std::process::id());
        let a = acquire(&fp).unwrap();
        let b = acquire(&fp);
        assert!(b.is_err());
        drop(a);
        let c = acquire(&fp);
        assert!(c.is_ok());
    }

    #[test]
    fn common_fingerprint_prefixes_do_not_collide() {
        let prefix = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        assert_ne!(
            lock_name(&format!("{prefix}00000000000000000000000000000000")),
            lock_name(&format!("{prefix}11111111111111111111111111111111"))
        );
    }
}
