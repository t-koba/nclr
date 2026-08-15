//! Exact, read-only controller probe profiles.
//!
//! These profiles break the dependency between controller identification and
//! a complete destructive recipe. They are loaded only from package-managed
//! directories, select one fixed command pair using an exact USB/SCSI tuple,
//! and compare controller-owned response payloads byte-for-byte. A successful
//! probe identifies a tuple but never authorizes erase, service entry or
//! metadata writes.

use crate::controller_protocol::{family_from_recipe_str, ControllerIdentity, Family};
use crate::controller_recipe::{self as recipe, CommandContext, CommandSpec, TransferDirection};
use crate::errors::{Error, Result};
use crate::profile::{self, ControllerBootstrapPolicy};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const CONTROLLER_PROBE_SCHEMA: u32 = 1;
pub const MAX_CONTROLLER_PROBE_BYTES: u64 = 1024 * 1024;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerProbeProfile {
    pub schema: u32,
    pub id: String,
    pub family: String,
    pub controller_id: String,
    pub firmware: String,
    pub nand_id: String,
    pub transport: String,
    pub bootstrap: ControllerBootstrapPolicy,
    pub controller_identity_hex: String,
    pub protocol_evidence_sha256: String,
    pub source_reference: String,
    pub commands: BTreeMap<String, CommandSpec>,
    #[serde(skip)]
    pub source_sha256: String,
}

#[derive(Clone, Debug)]
pub struct ObservedBootstrap<'a> {
    pub usb_vid: u16,
    pub usb_pid: u16,
    pub usb_bcd_device: u16,
    pub usb_manufacturer: &'a str,
    pub usb_product: &'a str,
    pub usb_serial: &'a str,
    pub scsi_vendor: &'a str,
    pub scsi_product: &'a str,
    pub scsi_revision: &'a str,
}

impl ControllerProbeProfile {
    pub fn family_value(&self) -> Result<Family> {
        family_from_recipe_str(&self.family).ok_or_else(|| {
            Error::Invalid(format!(
                "controller probe {} names unsupported family {}",
                self.id, self.family
            ))
        })
    }

    pub fn matches(&self, observed: &ObservedBootstrap<'_>) -> bool {
        let expected = &self.bootstrap;
        expected.usb_vid == observed.usb_vid
            && expected.usb_pid == observed.usb_pid
            && expected.usb_bcd_device == observed.usb_bcd_device
            && expected.usb_manufacturer == observed.usb_manufacturer
            && expected.usb_product == observed.usb_product
            && expected.usb_serial == observed.usb_serial
            && expected.scsi_vendor == observed.scsi_vendor
            && expected.scsi_product == observed.scsi_product
            && expected.scsi_revision == observed.scsi_revision
    }
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
}

fn digest_value(value: &str) -> Option<&str> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    (value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())).then_some(value)
}

fn validate_source_reference(value: &str) -> bool {
    !value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace())
        && value.starts_with("https://")
        && value["https://".len()..]
            .split('/')
            .next()
            .is_some_and(|authority| !authority.is_empty() && !authority.contains('@'))
}

fn exact_identity_bytes(value: &str, field: &str, maximum: usize) -> Result<Vec<u8>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    if value.is_empty()
        || !value.len().is_multiple_of(2)
        || !value.bytes().all(|byte| byte.is_ascii_hexdigit())
    {
        return Err(Error::Invalid(format!(
            "controller probe {field} must contain complete hexadecimal bytes"
        )));
    }
    let bytes = hex::decode(value)
        .map_err(|error| Error::Invalid(format!("controller probe {field}: {error}")))?;
    if bytes.is_empty()
        || bytes.len() > maximum
        || bytes.iter().all(|byte| *byte == 0)
        || bytes.iter().all(|byte| *byte == 0xff)
    {
        return Err(Error::Invalid(format!(
            "controller probe {field} must contain 1..={maximum} non-empty identity bytes"
        )));
    }
    Ok(bytes)
}

/// Validate a package-managed read-only probe profile. This validates only
/// exact identity collection and deliberately has no destructive capability
/// or trust state.
pub fn validate(profile: &ControllerProbeProfile, path: &Path) -> Result<()> {
    if profile.schema != CONTROLLER_PROBE_SCHEMA {
        return Err(Error::Invalid(format!(
            "controller probe {}: schema {} != {CONTROLLER_PROBE_SCHEMA}",
            path.display(),
            profile.schema
        )));
    }
    if !safe_id(&profile.id)
        || !safe_id(&profile.controller_id)
        || profile.firmware.is_empty()
        || profile.firmware.len() > 255
        || profile.firmware.trim() != profile.firmware
        || !profile
            .firmware
            .bytes()
            .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        || profile.nand_id.trim().is_empty()
        || profile.transport != "scsi"
    {
        return Err(Error::Invalid(format!(
            "controller probe {} has an invalid id, exact identity or transport",
            path.display()
        )));
    }
    let family = profile.family_value()?;
    if profile.family != family.recipe_str()
        || profile.bootstrap.family != profile.family
        || !family.accepts_controller_id(&profile.controller_id)
    {
        return Err(Error::Invalid(format!(
            "controller probe {} has inconsistent family and controller identity",
            path.display()
        )));
    }
    profile::validate_controller_bootstrap(
        &profile.bootstrap,
        &profile.controller_id,
        false,
        path,
    )?;
    if digest_value(&profile.protocol_evidence_sha256).is_none()
        || !validate_source_reference(&profile.source_reference)
    {
        return Err(Error::Invalid(format!(
            "controller probe {} requires an exact protocol-evidence digest and HTTPS source reference",
            path.display()
        )));
    }

    let expected_names = BTreeSet::from(["read-controller-id", "read-nand-id"]);
    let actual_names = profile
        .commands
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if actual_names != expected_names {
        return Err(Error::Invalid(format!(
            "controller probe {} must contain exactly read-controller-id and read-nand-id",
            path.display()
        )));
    }
    let controller_identity = exact_identity_bytes(
        &profile.controller_identity_hex,
        "controller_identity_hex",
        4096,
    )?;
    let nand_identity = recipe::exact_nand_id_bytes(&profile.nand_id)?;
    if profile.controller_identity_hex != hex::encode(&controller_identity)
        || profile.nand_id != hex::encode(&nand_identity)
    {
        return Err(Error::Invalid(format!(
            "controller probe {} identity hexadecimal values must be canonical lowercase without prefixes",
            path.display()
        )));
    }
    for (name, expected) in [
        ("read-controller-id", controller_identity.as_slice()),
        ("read-nand-id", nand_identity.as_slice()),
    ] {
        let command = &profile.commands[name];
        recipe::validate_identity_command(name, command)?;
        if command.response.payload_bytes as usize != expected.len() {
            return Err(Error::Invalid(format!(
                "controller probe {name} payload length {} does not match the exact identity length {}",
                command.response.payload_bytes,
                expected.len()
            )));
        }
    }
    Ok(())
}

/// Load one TOML probe profile without following a symbolic link.
pub fn load(path: &Path) -> Result<ControllerProbeProfile> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|error| {
        Error::io(
            format!("open controller probe {}", path.display()),
            Some(error),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        Error::io(
            format!("stat controller probe {}", path.display()),
            Some(error),
        )
    })?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_CONTROLLER_PROBE_BYTES {
        return Err(Error::Invalid(format!(
            "controller probe {} must be a regular file in 1..={MAX_CONTROLLER_PROBE_BYTES} bytes",
            path.display()
        )));
    }
    let mut source = String::with_capacity(metadata.len() as usize);
    file.take(MAX_CONTROLLER_PROBE_BYTES + 1)
        .read_to_string(&mut source)
        .map_err(|error| {
            Error::io(
                format!("read controller probe {}", path.display()),
                Some(error),
            )
        })?;
    if source.len() as u64 > MAX_CONTROLLER_PROBE_BYTES {
        return Err(Error::Invalid(format!(
            "controller probe {} grew beyond its size bound",
            path.display()
        )));
    }
    let mut profile: ControllerProbeProfile = toml::from_str(&source)
        .map_err(|error| Error::Invalid(format!("controller probe {}: {error}", path.display())))?;
    profile.source_sha256 = profile::source_digest(&source);
    validate(&profile, path)?;
    Ok(profile)
}

/// Load the unique package-managed probe whose exact USB/SCSI bootstrap
/// matches the observed device. An optional built-in family hint must agree
/// before any vendor command can be sent.
pub fn matching(
    dirs: &[PathBuf],
    observed: &ObservedBootstrap<'_>,
    family_hint: Option<Family>,
) -> Result<Option<ControllerProbeProfile>> {
    let mut found: Option<ControllerProbeProfile> = None;
    for directory in dirs {
        let entries = match std::fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(Error::io(
                    format!("read trusted probe directory {}", directory.display()),
                    Some(error),
                ))
            }
        };
        for entry in entries {
            let entry = entry.map_err(|error| {
                Error::io(
                    format!("read trusted probe directory {}", directory.display()),
                    Some(error),
                )
            })?;
            let path = entry.path();
            let name = path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("");
            if !name.starts_with("probe-")
                || path.extension().and_then(|value| value.to_str()) != Some("toml")
            {
                continue;
            }
            let candidate = load(&path)?;
            if !candidate.matches(observed) {
                continue;
            }
            let family = candidate.family_value()?;
            if family_hint.is_some_and(|hint| hint != family) {
                return Err(Error::Permission(format!(
                    "controller probe {} family conflicts with the vendor-id hint",
                    candidate.id
                )));
            }
            if let Some(existing) = &found {
                if existing.id == candidate.id && existing.source_sha256 == candidate.source_sha256
                {
                    continue;
                }
                return Err(Error::Invalid(format!(
                    "multiple read-only probe profiles match one exact USB/SCSI tuple: {} and {}",
                    existing.id, candidate.id
                )));
            }
            found = Some(candidate);
        }
    }
    Ok(found)
}

/// Execute the two validated identity reads through a caller-owned SCSI
/// transport. The closure must transfer exactly the requested number of
/// bytes or return an error.
pub fn execute_with(
    profile: &ControllerProbeProfile,
    mut read: impl FnMut(&str, &[u8], usize, u64) -> Result<Vec<u8>>,
) -> Result<ControllerIdentity> {
    validate(profile, Path::new(&profile.id))?;
    let expected_controller = exact_identity_bytes(
        &profile.controller_identity_hex,
        "controller_identity_hex",
        4096,
    )?;
    let expected_nand = recipe::exact_nand_id_bytes(&profile.nand_id)?;
    for (name, expected) in [
        ("read-controller-id", expected_controller.as_slice()),
        ("read-nand-id", expected_nand.as_slice()),
    ] {
        let command = &profile.commands[name];
        if command.direction != TransferDirection::FromDevice {
            return Err(Error::Permission(format!(
                "controller probe {name} is not read-only"
            )));
        }
        let cdb = recipe::build_cdb(command, CommandContext::default())?;
        let response = read(
            name,
            &cdb,
            command.transfer_bytes as usize,
            command.timeout_ms,
        )?;
        recipe::decode_response(command, &response)?;
        let payload = recipe::response_payload(command, &response)?;
        if payload != expected {
            return Err(Error::Permission(format!(
                "controller probe {name} response {} does not match expected identity {}",
                hex::encode(payload),
                hex::encode(expected)
            )));
        }
    }
    Ok(ControllerIdentity {
        family: profile.family_value()?,
        controller_id: profile.controller_id.clone(),
        firmware: profile.firmware.clone(),
        nand_id: Some(hex::encode(expected_nand)),
        mode: "firmware".into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::controller_recipe::{ResponseRule, TransferDirection};

    fn command(
        cdb_hex: &str,
        transfer_bytes: u32,
        prefix_hex: &str,
        payload_bytes: u32,
    ) -> CommandSpec {
        CommandSpec {
            cdb_hex: cdb_hex.into(),
            direction: TransferDirection::FromDevice,
            transfer_bytes,
            timeout_ms: 10_000,
            fields: Vec::new(),
            payload: None,
            response: ResponseRule {
                min_bytes: transfer_bytes,
                max_bytes: transfer_bytes,
                prefix_hex: prefix_hex.into(),
                payload_offset: 0,
                payload_bytes,
                fields: Vec::new(),
            },
        }
    }

    fn alcor_probe() -> ControllerProbeProfile {
        ControllerProbeProfile {
            schema: CONTROLLER_PROBE_SCHEMA,
            id: "alcor-au6989-example-probe".into(),
            family: "alcor-ufd".into(),
            controller_id: "alcor-au6989".into(),
            firmware: "example-fw".into(),
            nand_id: "98de94827656".into(),
            transport: "scsi".into(),
            bootstrap: ControllerBootstrapPolicy {
                family: "alcor-ufd".into(),
                usb_vid: 0x058f,
                usb_pid: 0x6387,
                usb_bcd_device: 0x0100,
                usb_manufacturer: "Alcor Micro".into(),
                usb_product: "Mass Storage".into(),
                usb_serial: "EXAMPLE".into(),
                scsi_vendor: "Generic".into(),
                scsi_product: "Flash Disk".into(),
                scsi_revision: "1.00".into(),
            },
            controller_identity_hex: "9907".into(),
            protocol_evidence_sha256: "11".repeat(32),
            source_reference: "https://github.com/tizbac/alcorhack".into(),
            commands: BTreeMap::from([
                (
                    "read-controller-id".into(),
                    command("82510100000000000000", 512, "9907", 2),
                ),
                (
                    "read-nand-id".into(),
                    command("fa00000000000000", 10, "98", 6),
                ),
            ]),
            source_sha256: String::new(),
        }
    }

    #[test]
    fn validates_exact_read_only_probe_contract() {
        let profile = alcor_probe();
        assert!(validate(&profile, Path::new("probe-alcor.toml")).is_ok());
    }

    #[test]
    fn rejects_writes_and_incomplete_bootstrap() {
        let mut profile = alcor_probe();
        profile.commands.get_mut("read-nand-id").unwrap().direction = TransferDirection::ToDevice;
        assert!(validate(&profile, Path::new("probe-alcor.toml")).is_err());

        let mut profile = alcor_probe();
        profile.bootstrap.scsi_revision.clear();
        assert!(validate(&profile, Path::new("probe-alcor.toml")).is_err());

        let mut profile = alcor_probe();
        profile.nand_id = "98DE94827656".into();
        assert!(validate(&profile, Path::new("probe-alcor.toml")).is_err());
    }

    #[test]
    fn matching_requires_one_exact_package_profile_and_agreeing_hint() {
        let directory = tempfile::tempdir().unwrap();
        let profile = alcor_probe();
        let first = directory.path().join("probe-alcor-first.toml");
        std::fs::write(&first, toml::to_string(&profile).unwrap()).unwrap();
        let observed = ObservedBootstrap {
            usb_vid: 0x058f,
            usb_pid: 0x6387,
            usb_bcd_device: 0x0100,
            usb_manufacturer: "Alcor Micro",
            usb_product: "Mass Storage",
            usb_serial: "EXAMPLE",
            scsi_vendor: "Generic",
            scsi_product: "Flash Disk",
            scsi_revision: "1.00",
        };
        let matched = matching(
            &[directory.path().to_path_buf()],
            &observed,
            Some(Family::AlcorUfd),
        )
        .unwrap()
        .unwrap();
        assert_eq!(matched.id, profile.id);
        assert!(!matched.source_sha256.is_empty());
        assert!(matching(
            &[directory.path().to_path_buf()],
            &observed,
            Some(Family::PhisonUfd),
        )
        .is_err());

        let mut second = profile;
        second.id = "alcor-au6989-second-probe".into();
        std::fs::write(
            directory.path().join("probe-alcor-second.toml"),
            toml::to_string(&second).unwrap(),
        )
        .unwrap();
        assert!(matching(
            &[directory.path().to_path_buf()],
            &observed,
            Some(Family::AlcorUfd),
        )
        .is_err());
    }
}
