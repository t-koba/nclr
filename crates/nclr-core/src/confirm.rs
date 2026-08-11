//! Interactive confirmation with a fingerprint token for `run`.
//!
//! The token is `{devbase}-{fingerprint8}-{capacity}` (first 8 characters of
//! the SHA-256 fingerprint); a device name alone is not accepted. `--yes`
//! skips the prompt but the fixed-plan and safety checks are never skipped.

use crate::device::DeviceIdentity;
use std::io::{BufRead, Write};

/// Human-readable capacity, e.g. "31GB", "512MB".
pub fn human_capacity(bytes: u64) -> String {
    const GB: u64 = 1_000_000_000;
    const MB: u64 = 1_000_000;
    if bytes >= GB {
        format!("{}GB", (bytes as f64 / GB as f64).round() as u64)
    } else if bytes >= MB {
        format!("{}MB", (bytes as f64 / MB as f64).round() as u64)
    } else {
        format!("{bytes}B")
    }
}

/// Build the confirmation token for a device.
pub fn token(identity: &DeviceIdentity) -> String {
    let base = identity
        .kernel_path
        .rsplit('/')
        .next()
        .unwrap_or(&identity.kernel_path)
        .to_string();
    let last8 = identity
        .fingerprint
        .trim_start_matches("sha256:")
        .chars()
        .take(8)
        .collect::<String>();
    format!("{base}-{last8}-{}", human_capacity(identity.capacity_bytes))
}

/// Prompt on stderr and require an exact token match from stdin.
/// Returns Ok(()) when confirmed.
pub fn confirm(identity: &DeviceIdentity, yes: bool) -> Result<(), crate::errors::Error> {
    let expected = token(identity);
    if yes {
        return Ok(());
    }
    eprintln!(
        "nclr: target {}, {}, fingerprint {}",
        identity.kernel_path,
        human_capacity(identity.capacity_bytes),
        &identity.fingerprint[..24]
    );
    eprint!("nclr: type this token to confirm: {expected}\n> ");
    let _ = std::io::stderr().flush();
    let mut line = String::new();
    let stdin = std::io::stdin();
    let mut lock = stdin.lock();
    if lock.read_line(&mut line).is_err() {
        return Err(crate::errors::Error::Interrupted(
            "cannot read confirmation from stdin (non-interactive?)".into(),
        ));
    }
    if line.trim() != expected {
        return Err(crate::errors::Error::Permission(
            "confirmation token mismatch; aborting".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_format() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("mydev.img");
        // Sparse file so the test stays cheap.
        let file = std::fs::File::create(&f).unwrap();
        file.set_len(31_000_000_000).unwrap();
        let id = crate::device::identify(f.to_str().unwrap()).unwrap();
        let t = token(&id);
        let last8 = &id.fingerprint["sha256:".len().."sha256:".len() + 8];
        assert!(t.starts_with("mydev.img-"));
        assert!(t.contains(last8));
        assert!(t.ends_with("-31GB"));
    }

    #[test]
    fn capacity_formatting() {
        assert_eq!(human_capacity(31_000_000_000), "31GB");
        assert_eq!(human_capacity(512_000_000), "512MB");
        assert_eq!(human_capacity(999_999_999), "1000MB");
        assert_eq!(human_capacity(1000), "1000B");
    }
}
