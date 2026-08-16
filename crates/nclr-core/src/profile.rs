//! Controller profile system.
//!
//! A profile declares the identification conditions, operations, coverage,
//! destructiveness, timeouts, recovery method, capacity boundaries, FBB
//! marker and ECC thresholds for a controller/firmware/NAND combination.
//! Destructive execution requires an *exact* match and a `production` trust
//! state; anything else is refused.

use crate::artifact::{self, ArtifactFormat, ArtifactKind, ArtifactSpec, VerifiedArtifact};
use crate::errors::{Error, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const PROFILE_SCHEMA: u32 = 1;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Trust {
    Research,
    Experimental,
    Validated,
    Production,
}

impl Trust {
    /// Whether destructive operations are permitted for this trust state.
    pub fn destructive_allowed(&self) -> bool {
        matches!(self, Trust::Production)
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Trust::Research => "research",
            Trust::Experimental => "experimental",
            Trust::Validated => "validated",
            Trust::Production => "production",
        }
    }

    pub fn parse(s: &str) -> Option<Trust> {
        match s {
            "research" => Some(Trust::Research),
            "experimental" => Some(Trust::Experimental),
            "validated" => Some(Trust::Validated),
            "production" => Some(Trust::Production),
            _ => None,
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct VersionRange {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct CapacityPolicy {
    /// Capacity bin the controller supports (e.g. 512 MiB increments).
    #[serde(default)]
    pub bin_bytes: u64,
    #[serde(default)]
    pub minimum_spare_blocks: u32,
    #[serde(default)]
    pub spare_ratio: f64,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct EccPolicy {
    #[serde(default)]
    pub strength: u32,
    #[serde(default)]
    pub min_margin: u32,
    #[serde(default)]
    pub max_read_retry: u32,
    #[serde(default)]
    pub max_read_latency_ms: u32,
}

/// SD vendor interface declaration: only read-only
/// health queries may be declared without hardware validation; the query
/// structure (CMD56 equivalent: argument, direction, block length, response
/// layout) is documented by the profile.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct SdVendorPolicy {
    #[serde(default)]
    pub read_only_health: bool,
    #[serde(default)]
    pub cmd56_arg: u32,
    #[serde(default)]
    pub block_len: u16,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct RecoveryPolicy {
    #[serde(default)]
    pub method: String,
    #[serde(default)]
    pub timeout_ms: u64,
}

/// Independent hardware qualification attached to a real production
/// controller profile. This is evidence metadata, not a self-asserted grade.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct QualificationPolicy {
    /// SHA-256 of the immutable HIL qualification report.
    pub report_sha256: String,
    /// Independent physical reader or method used to inspect D1-D4.
    pub independent_reader: String,
    /// Number of distinct sacrificial media tested for this exact tuple.
    #[serde(default)]
    pub samples: u32,
    /// Number of injected power-cut points recovered successfully.
    #[serde(default)]
    pub power_cut_cases: u32,
    /// Artifact id for the immutable report named by `report_sha256`.
    #[serde(default)]
    pub report_artifact_id: String,
}

/// How the controller protocol implementation was obtained and which exact
/// runtime artifacts it needs. The compiled backend remains authoritative;
/// this declaration cannot enable a missing driver primitive.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct ImplementationPolicy {
    /// `clean-room` or `runtime-artifact`.
    pub strategy: String,
    /// Digest of the exact protocol trace or factory-tool executable used as
    /// implementation evidence. Executables are analyzed as inert bytes and
    /// are never inherited by the backend through this field.
    pub protocol_evidence_sha256: String,
    /// Primary-source URL or public clean-room design record.
    pub source_reference: String,
    /// Artifact ids that must be opened and inherited by the backend.
    #[serde(default)]
    pub artifact_ids: Vec<String>,
}

/// Read-only tuple used to select the recipe artifacts needed to perform a
/// controller-owned identity probe. This is only a bootstrap selector: it
/// never authorizes destructive execution by itself.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ControllerBootstrapPolicy {
    pub family: String,
    pub usb_vid: u16,
    pub usb_pid: u16,
    pub usb_bcd_device: u16,
    /// Exact USB descriptor strings. Empty values mean the observed
    /// descriptor was absent; they are never wildcards.
    pub usb_manufacturer: String,
    pub usb_product: String,
    pub usb_serial: String,
    pub scsi_vendor: String,
    pub scsi_product: String,
    pub scsi_revision: String,
}

/// Exact physical geometry for one controller/firmware/NAND tuple.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct NandGeometryPolicy {
    pub channels: u32,
    pub chips_per_channel: u32,
    pub luns_per_chip: u32,
    pub planes_per_lun: u32,
    pub blocks_per_lun: u32,
    pub pages_per_block: u32,
    pub page_bytes: u32,
    pub oob_bytes: u32,
    pub address_cycles: u8,
    pub bits_per_cell: u8,
    #[serde(default)]
    pub bad_block_marker_pages: Vec<u32>,
    #[serde(default)]
    pub bad_block_marker_offsets: Vec<u32>,
    pub randomizer: String,
    pub read_retry: String,
    pub ecc_layout: String,
}

/// Exact on-flash controller metadata and atomic commit rules.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct MetadataLayoutPolicy {
    pub bbt_format: String,
    pub ftl_format: String,
    pub spare_format: String,
    pub commit_protocol: String,
    #[serde(default)]
    pub system_block_ranges: Vec<SystemBlockRange>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct SystemBlockRange {
    pub start: u64,
    pub end: u64,
    pub purpose: String,
    pub policy: SystemBlockPolicy,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SystemBlockPolicy {
    Preserve,
    RebuildBbt,
    RebuildFtl,
    RebuildControllerMetadata,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub schema: u32,
    pub id: String,
    pub controller_id: String,
    pub firmware: VersionRange,
    pub nand_id: VersionRange,
    pub trust: String,
    /// True only for the built-in virtual NAND family. Real profiles must
    /// carry independent qualification evidence.
    #[serde(default)]
    pub simulated: bool,
    #[serde(default)]
    pub operations: Vec<String>,
    #[serde(default)]
    pub coverage: Vec<String>,
    #[serde(default)]
    pub rebuilds: Vec<String>,
    #[serde(default)]
    pub preserves: Vec<String>,
    /// Controller domains that remain outside the reported user LBA space.
    /// Real production profiles must state this explicitly, including zero.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protected_area_bytes: Option<u64>,
    #[serde(default)]
    pub capacity: CapacityPolicy,
    #[serde(default)]
    pub ecc: EccPolicy,
    #[serde(default)]
    pub recovery: RecoveryPolicy,
    /// Uniform logical blank value that must be observed after a controller
    /// rebuild. Controller profiles may currently certify only the two values
    /// the postcheck engine can independently verify.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub logical_blank_value: Option<u8>,
    #[serde(default, skip_serializing_if = "is_default_sdvendor")]
    pub sd_vendor: SdVendorPolicy,
    /// Certified erase grade (e.g. "C4" for a certified physical-scope
    /// profile). Only a profile that documents its certification may be
    /// credited with it; the value is validated against the grade table.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certification: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qualification: Option<QualificationPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub implementation: Option<ImplementationPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_bootstrap: Option<ControllerBootstrapPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub geometry: Option<NandGeometryPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_layout: Option<MetadataLayoutPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<ArtifactSpec>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
}

fn is_default_sdvendor(v: &SdVendorPolicy) -> bool {
    !v.read_only_health && v.cmd56_arg == 0 && v.block_len == 0
}

// ---------------------------------------------------------------------------
// Read-only identification profiles (profiles/identify-*.toml)
// ---------------------------------------------------------------------------

/// Identification parameters for a controller carried in the standard
/// INQUIRY response's vendor-specific area (past the 36-byte standard
/// data). No vendor CDB is involved: a non-matching device answers INQUIRY
/// harmlessly and the marker simply does not match.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct InquiryMarkerIdentify {
    /// Byte pattern searched in the vendor-specific INQUIRY area (e.g.
    /// "U163" for the USBest UT163 "UtffU163A1BM" marker).
    pub marker: String,
    /// INQUIRY allocation length that exposes the vendor area.
    #[serde(default = "default_inquiry_alloc_len")]
    pub alloc_len: u16,
    /// Standard INQUIRY data length; the marker is searched beyond it.
    #[serde(default = "default_inquiry_standard_len")]
    pub standard_len: u16,
}

fn default_inquiry_alloc_len() -> u16 {
    96
}

fn default_inquiry_standard_len() -> u16 {
    36
}

/// Read-only controller-family identification profile. This is not a
/// destructive-execution profile: it only declares which USB vendor ids may
/// be probed and how the controller answers, so `nclr info` can name the
/// family. Destructive capability is never derived from it.
#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct IdentifyProfile {
    pub schema: u32,
    pub id: String,
    /// Family name; must match a known `controller_protocol::Family` string.
    pub family: String,
    /// USB vendor ids that may select this family for a read-only probe.
    #[serde(default)]
    pub usb_vid_hints: Vec<u16>,
    /// Optional INQUIRY vendor-area marker used to identify the family
    /// without a vendor CDB (USBest UT163).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inquiry_marker: Option<InquiryMarkerIdentify>,
}

/// Load all read-only identification profiles from the profile search
/// directories (`identify-*.toml`). Invalid or unreadable profiles are
/// skipped with a warning so a single bad file cannot break `nclr info`.
pub fn load_identify_profiles(explicit: &[PathBuf]) -> Vec<IdentifyProfile> {
    let mut out = Vec::new();
    for dir in search_dirs(explicit) {
        let rd = match std::fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(_) => continue,
        };
        for entry in rd.flatten() {
            let path = entry.path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if !name.starts_with("identify-") {
                continue;
            }
            match load_identify_profile(&path) {
                Ok(p) => out.push(p),
                Err(e) => eprintln!("nclr: warning: skipping {}: {e}", path.display()),
            }
        }
    }
    out
}

/// Load and validate a single identification profile file.
pub fn load_identify_profile(path: &Path) -> Result<IdentifyProfile> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::io(format!("identify profile read {}", path.display()), Some(e)))?;
    let profile: IdentifyProfile = toml::from_str(&raw)
        .map_err(|e| Error::Invalid(format!("identify profile {}: {e}", path.display())))?;
    validate_identify_profile(&profile, path)?;
    Ok(profile)
}

/// Validate an identification profile. The family name must match a known
/// controller family and every field must be non-empty and in range.
pub fn validate_identify_profile(profile: &IdentifyProfile, path: &Path) -> Result<()> {
    if profile.schema != PROFILE_SCHEMA {
        return Err(Error::Invalid(format!(
            "identify profile {}: schema {} != {PROFILE_SCHEMA}",
            path.display(),
            profile.schema
        )));
    }
    if profile.id.is_empty() || profile.family.is_empty() {
        return Err(Error::Invalid(format!(
            "identify profile {}: id and family are required",
            path.display()
        )));
    }
    if !crate::controller_protocol::is_known_family(&profile.family) {
        return Err(Error::Invalid(format!(
            "identify profile {}: unknown family {}",
            path.display(),
            profile.family
        )));
    }
    for vid in &profile.usb_vid_hints {
        if *vid == 0 {
            return Err(Error::Invalid(format!(
                "identify profile {}: usb_vid_hints must not contain 0",
                path.display()
            )));
        }
    }
    if let Some(marker) = &profile.inquiry_marker {
        if marker.marker.is_empty() || !marker.marker.bytes().all(|byte| byte.is_ascii_graphic()) {
            return Err(Error::Invalid(format!(
                "identify profile {}: inquiry_marker.marker must be non-empty printable ASCII",
                path.display()
            )));
        }
        if marker.standard_len == 0
            || marker.alloc_len <= marker.standard_len
            || usize::from(marker.alloc_len - marker.standard_len) < marker.marker.len()
        {
            return Err(Error::Invalid(format!(
                "identify profile {}: inquiry_marker alloc_len must leave enough vendor-specific bytes after standard_len",
                path.display()
            )));
        }
    }
    Ok(())
}

/// Controller family selected by a USB vendor id, from the identification
/// profiles. Only vendor-owned ids are accepted as hints (OEM ids are never
/// guessed); a vid that hints several families is ambiguous and rejected.
pub fn family_hint_from_vid(vid: u16, profiles: &[IdentifyProfile]) -> Option<Family> {
    let mut found = None;
    for profile in profiles
        .iter()
        .filter(|profile| profile.usb_vid_hints.contains(&vid))
    {
        let family = crate::controller_protocol::family_from_str(&profile.family)?;
        match found {
            None => found = Some(family),
            Some(existing) if existing == family => {}
            Some(_) => return None,
        }
    }
    found
}

use crate::controller_protocol::Family;

// ---------------------------------------------------------------------------
// usb.ids (linux-usb.org) vendor/model database
// ---------------------------------------------------------------------------

/// Candidate locations of the USB id database. The udev hwdb
/// `20-usb-vendor-model.hwdb` is generated from this same file
/// ("Data imported from: http://www.linux-usb.org/usb.ids"), so reading it
/// resolves both vendor and model names exactly like lsusb/udev.
fn usb_ids_paths() -> &'static [&'static str] {
    &[
        "/usr/share/hwdata/usb.ids",
        "/usr/share/misc/usb.ids",
        "/usr/local/share/hwdata/usb.ids",
    ]
}

fn read_usb_ids() -> Option<String> {
    for path in usb_ids_paths() {
        if let Ok(content) = std::fs::read_to_string(path) {
            return Some(content);
        }
    }
    None
}

fn usb_ids_vendor_from(content: &str, vid: u16) -> Option<String> {
    let needle = format!("{vid:04x}");
    content.lines().find_map(|line| {
        let bytes = line.as_bytes();
        (bytes.len() >= 6 && bytes.get(..4) == Some(needle.as_bytes()) && bytes[4..6] == *b"  ")
            .then(|| line.get(6..).map(str::trim).filter(|name| !name.is_empty()))
            .flatten()
            .map(str::to_string)
    })
}

fn usb_ids_model_from(content: &str, vid: u16, pid: u16) -> Option<String> {
    let vendor = format!("{vid:04x}");
    let product = format!("{pid:04x}");
    let mut inside_vendor = false;
    for line in content.lines() {
        let bytes = line.as_bytes();
        if bytes.is_empty() || bytes[0] == b'#' {
            continue;
        }
        if bytes[0] != b'\t' {
            inside_vendor = bytes.len() >= 6
                && bytes.get(..4) == Some(vendor.as_bytes())
                && bytes[4..6] == *b"  ";
            continue;
        }
        if !inside_vendor || bytes.get(1) == Some(&b'\t') {
            continue;
        }
        let model = &bytes[1..];
        if model.len() >= 6 && model.get(..4) == Some(product.as_bytes()) && model[4..6] == *b"  " {
            return std::str::from_utf8(&model[6..])
                .ok()
                .map(str::trim)
                .filter(|name| !name.is_empty())
                .map(str::to_string);
        }
    }
    None
}

/// Vendor name for a USB vendor id from usb.ids (`^XXXX  Name` lines).
pub fn usb_ids_vendor(vid: u16) -> Option<String> {
    usb_ids_vendor_from(&read_usb_ids()?, vid)
}

/// Model name for a USB vendor/product id pair from usb.ids
/// (`\tXXXX  Name` lines under the vendor). A model name may carry the
/// controller name when the vendor used it as the product name (e.g.
/// 13fe:1f23 "PS2232 flash drive controller").
pub fn usb_ids_model(vid: u16, pid: u16) -> Option<String> {
    usb_ids_model_from(&read_usb_ids()?, vid, pid)
}

impl Profile {
    pub fn trust(&self) -> Option<Trust> {
        Trust::parse(&self.trust)
    }

    /// Exact profile match (Phase 3 acceptance "exact match"
    /// requirement). Controller id must be identical; firmware and NAND
    /// ids must fall within the declared ranges.
    pub fn matches(&self, controller_id: &str, firmware: &str, nand_id: &str) -> bool {
        if self.controller_id != controller_id {
            return false;
        }
        in_range(&self.firmware, firmware) && in_range(&self.nand_id, nand_id)
    }

    /// Whether this profile permits destructive execution.
    pub fn destructive_allowed(&self) -> bool {
        matches!(self.trust(), Some(Trust::Production))
    }
}

/// Natural-order component used for controller, firmware and NAND ranges.
/// Text is preserved instead of discarded: opaque identifiers such as
/// `SIMNAND-1` and `OTHERNAND-1` must never compare as the same value.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum VersionPart {
    Text(String),
    Number(usize, String),
}

fn version_key(s: &str) -> Vec<VersionPart> {
    let mut parts = Vec::new();
    let chars: Vec<char> = s.trim().chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        if matches!(chars[i], '.' | '-' | '_') {
            i += 1;
            continue;
        }
        let numeric = chars[i].is_ascii_digit();
        let start = i;
        while i < chars.len()
            && !matches!(chars[i], '.' | '-' | '_')
            && chars[i].is_ascii_digit() == numeric
        {
            i += 1;
        }
        let raw: String = chars[start..i].iter().collect();
        if numeric {
            let normalized = raw.trim_start_matches('0');
            let normalized = if normalized.is_empty() {
                "0"
            } else {
                normalized
            };
            parts.push(VersionPart::Number(
                normalized.len(),
                normalized.to_string(),
            ));
        } else {
            parts.push(VersionPart::Text(raw));
        }
    }
    parts
}

fn in_range(range: &VersionRange, value: &str) -> bool {
    let v = version_key(value);
    let ge_min = match &range.min {
        Some(m) => v >= version_key(m),
        None => true,
    };
    let le_max = match &range.max {
        Some(m) => v <= version_key(m),
        None => true,
    };
    ge_min && le_max
}

// ---------------------------------------------------------------------------
// Capacity planning (shared with the sim controller model)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CapacityPlan {
    pub good_blocks: u64,
    pub reserved_blocks: u64,
    pub spare_blocks: u64,
    pub user_blocks: u64,
}

/// Spare pool and user-capacity computation (phase 9):
///
/// ```text
/// good    = qualified blocks
/// reserved = system blocks + bbt blocks
/// spare   = max(profile.minimum_spare_blocks,
///               ceil(good * policy.spare_ratio),
///               observed_weak_blocks + historical_rbb_quarantine_margin)
/// user_blocks = round_down_to_controller_bin(good - reserved - spare)
/// ```
pub fn plan_capacity(
    good_blocks: u64,
    reserved_blocks: u64,
    weak_quarantined: u64,
    policy: &CapacityPolicy,
) -> Option<CapacityPlan> {
    let spare_candidates = [
        policy.minimum_spare_blocks as u64,
        ((good_blocks as f64) * policy.spare_ratio).ceil() as u64,
        weak_quarantined + 1, // quarantine margin for the observed weak set
    ];
    let spare = spare_candidates.into_iter().max().unwrap_or(0);
    let available = good_blocks
        .saturating_sub(reserved_blocks)
        .saturating_sub(spare);
    if available == 0 {
        return None;
    }
    let user = if policy.bin_bytes >= 512 {
        // Round down to whole controller capacity bins.
        let per_bin_blocks = policy.bin_bytes / 512;
        let binned = (available / per_bin_blocks.max(1)) * per_bin_blocks;
        binned.max(1)
    } else {
        available
    };
    Some(CapacityPlan {
        good_blocks,
        reserved_blocks,
        spare_blocks: spare,
        user_blocks: user,
    })
}

/// Weak-block decision (phase 5):
///
/// ```text
/// margin = ecc_strength - corrected_bits
/// weak if: margin < profile.min_ecc_margin
///          OR retry_count > profile.max_read_retry
///          OR read_latency_ms > profile.max_read_latency_ms
/// ```
pub fn is_weak(
    corrected_bits: u32,
    read_retries: u32,
    read_latency_ms: u32,
    policy: &EccPolicy,
) -> bool {
    let margin = policy.strength.saturating_sub(corrected_bits);
    margin < policy.min_margin
        || read_retries > policy.max_read_retry
        || read_latency_ms > policy.max_read_latency_ms
}

// ---------------------------------------------------------------------------
// Loading and validation
// ---------------------------------------------------------------------------

/// Load and validate a profile from a TOML file.
pub fn load(path: &Path) -> Result<Profile> {
    let raw = std::fs::read_to_string(path)
        .map_err(|e| Error::io(format!("profile read {}", path.display()), Some(e)))?;
    let mut profile: Profile = toml::from_str(&raw)
        .map_err(|e| Error::Invalid(format!("profile {}: {e}", path.display())))?;
    validate(&profile, path)?;
    // Always retain the verified content digest in the loaded value, even
    // when the source omitted a self-digest. Reports must identify the exact
    // profile bytes that influenced a destructive plan.
    profile.sha256 = Some(source_digest(&raw));
    Ok(profile)
}

/// SHA-256 of profile source with the self-referential `sha256` assignment
/// removed. The returned form is 64 lowercase hex characters.
pub fn source_digest(source: &str) -> String {
    let filtered: Vec<&str> = source
        .lines()
        .filter(|line| {
            let trimmed = line.trim_start();
            !(trimmed.starts_with("sha256") && trimmed[6..].trim_start().starts_with('='))
        })
        .collect();
    let digest = crate::digest(filtered.join("\n").as_bytes());
    digest["sha256:".len()..].to_string()
}

pub fn validate(profile: &Profile, path: &Path) -> Result<()> {
    validate_common(profile, path)?;
    if profile.destructive_allowed() && !profile.simulated {
        validate_real_production(profile, path)?;
    }
    Ok(())
}

fn validate_common(profile: &Profile, path: &Path) -> Result<()> {
    if profile.schema != PROFILE_SCHEMA {
        return Err(Error::Invalid(format!(
            "profile {}: schema {} != {PROFILE_SCHEMA}",
            path.display(),
            profile.schema
        )));
    }
    if profile.id.is_empty() || profile.controller_id.is_empty() {
        return Err(Error::Invalid(format!(
            "profile {}: id and controller_id are required",
            path.display()
        )));
    }
    if profile.id.starts_with('.')
        || !profile
            .id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(Error::Invalid(format!(
            "profile {}: id contains unsafe path characters",
            path.display()
        )));
    }
    if profile.trust().is_none() {
        return Err(Error::Invalid(format!(
            "profile {}: unknown trust \"{}\"",
            path.display(),
            profile.trust
        )));
    }
    if profile.simulated
        && (profile.id != "sim-controller-1" || profile.controller_id != "sim-ctlr-01")
    {
        return Err(Error::Invalid(format!(
            "profile {}: simulated is reserved for the built-in sim-controller-1 family",
            path.display()
        )));
    }
    if profile.destructive_allowed() && !matches!(profile.logical_blank_value, Some(0x00 | 0xff)) {
        return Err(Error::Invalid(format!(
            "profile {}: a destructive controller profile requires logical_blank_value 0 or 255",
            path.display()
        )));
    }
    if let Some(bootstrap) = &profile.controller_bootstrap {
        validate_controller_bootstrap(bootstrap, &profile.controller_id, profile.simulated, path)?;
    }
    // A read-only health query is a CMD56-style read (SD spec argument
    // bit 0 = 1); declaring read_only_health with the write direction is
    // contradictory and must not pass validation.
    if profile.sd_vendor.read_only_health && profile.sd_vendor.cmd56_arg & 1 == 0 {
        return Err(Error::Invalid(format!(
            "profile {}: sd_vendor read_only_health requires the CMD56 read \
             direction (argument bit 0 = 1)",
            path.display()
        )));
    }
    if let Some(c) = &profile.certification {
        if !matches!(c.as_str(), "C1" | "C2" | "C3" | "C4") {
            return Err(Error::Invalid(format!(
                "profile {}: certification must be C1..=C4 (got {c})",
                path.display()
            )));
        }
    }
    validate_artifacts(profile, path)?;
    if profile.destructive_allowed() {
        validate_capacity_policy(&profile.capacity).map_err(|error| {
            Error::Invalid(format!(
                "profile {}: invalid capacity policy: {error}",
                path.display()
            ))
        })?;
    }
    if let Some(d) = &profile.sha256 {
        let d = d.strip_prefix("sha256:").unwrap_or(d);
        if d.len() != 64 || !d.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(Error::Invalid(format!(
                "profile {}: sha256 must be 64 hex chars",
                path.display()
            )));
        }
        // The digest is tamper-evidence (like the backend manifest): a
        // changed profile no longer matches its declared digest. It is
        // computed over the profile with the self-referential sha256 line
        // removed, so a profile can contain its own digest.
        let source = std::fs::read_to_string(path)
            .map_err(|e| Error::io(format!("profile read {}", path.display()), Some(e)))?;
        let actual = source_digest(&source);
        if !actual.eq_ignore_ascii_case(d) {
            return Err(Error::Invalid(format!(
                "profile {}: sha256 mismatch (declared {d}, actual {actual})",
                path.display(),
            )));
        }
    }
    Ok(())
}

/// Validate an exact USB/SCSI bootstrap used only to select a controller-
/// owned identity command. The tuple is a selector, never authorization for
/// destructive execution.
pub fn validate_controller_bootstrap(
    bootstrap: &ControllerBootstrapPolicy,
    controller_id: &str,
    simulated: bool,
    path: &Path,
) -> Result<()> {
    let canonical_scsi = |value: &str, maximum: usize| {
        !value.is_empty()
            && value.len() <= maximum
            && value.trim() == value
            && value
                .bytes()
                .all(|byte| byte.is_ascii_graphic() || byte == b' ')
    };
    let canonical_usb = |value: &str| {
        value.len() <= 255
            && value
                .chars()
                .all(|character| !character.is_control() && character != '\0')
    };
    let family = crate::controller_protocol::family_from_recipe_str(&bootstrap.family);
    let controller_family_matches =
        family.is_some_and(|family| family.accepts_controller_id(controller_id));
    if simulated
        || family.is_none()
        || family.is_some_and(|family| bootstrap.family != family.recipe_str())
        || !controller_family_matches
        || bootstrap.usb_vid == 0
        || !canonical_usb(&bootstrap.usb_manufacturer)
        || !canonical_usb(&bootstrap.usb_product)
        || !canonical_usb(&bootstrap.usb_serial)
        || !canonical_scsi(&bootstrap.scsi_vendor, 8)
        || !canonical_scsi(&bootstrap.scsi_product, 16)
        || !canonical_scsi(&bootstrap.scsi_revision, 4)
    {
        return Err(Error::Invalid(format!(
            "profile {}: controller_bootstrap must name a supported family and exact USB/SCSI tuple",
            path.display()
        )));
    }
    Ok(())
}

/// Validate a controller capacity policy before it can influence a plan.
pub fn validate_capacity_policy(policy: &CapacityPolicy) -> Result<()> {
    if policy.minimum_spare_blocks == 0 {
        return Err(Error::Invalid(
            "minimum_spare_blocks must be greater than zero".into(),
        ));
    }
    if !policy.spare_ratio.is_finite() || policy.spare_ratio <= 0.0 || policy.spare_ratio >= 1.0 {
        return Err(Error::Invalid(
            "spare_ratio must be finite and strictly between zero and one".into(),
        ));
    }
    if policy.bin_bytes != 0 && (policy.bin_bytes < 512 || !policy.bin_bytes.is_multiple_of(512)) {
        return Err(Error::Invalid(
            "bin_bytes must be zero or a multiple of 512".into(),
        ));
    }
    Ok(())
}

fn exact_value(range: &VersionRange) -> Option<&str> {
    match (&range.min, &range.max) {
        (Some(min), Some(max)) if !min.is_empty() && min == max => Some(min),
        _ => None,
    }
}

fn digest_value(value: &str) -> Option<&str> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    (value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())).then_some(value)
}

fn validate_artifacts(profile: &Profile, path: &Path) -> Result<()> {
    let mut ids = std::collections::BTreeSet::new();
    let mut roles = std::collections::BTreeSet::new();
    for spec in &profile.artifacts {
        artifact::validate_spec(spec).map_err(|e| {
            Error::Invalid(format!(
                "profile {}: artifact {} is invalid: {e}",
                path.display(),
                spec.id
            ))
        })?;
        if !ids.insert(spec.id.as_str()) {
            return Err(Error::Invalid(format!(
                "profile {}: duplicate artifact id {}",
                path.display(),
                spec.id
            )));
        }
        if !roles.insert(spec.role.as_str()) {
            return Err(Error::Invalid(format!(
                "profile {}: duplicate artifact role {}",
                path.display(),
                spec.role
            )));
        }
        if spec.controller_id != profile.controller_id
            || !in_range(&profile.firmware, &spec.firmware)
            || !in_range(&profile.nand_id, &spec.nand_id)
        {
            return Err(Error::Invalid(format!(
                "profile {}: artifact {} hardware tuple is outside the profile identity",
                path.display(),
                spec.id
            )));
        }
    }
    Ok(())
}

/// Validate every production-profile requirement that can be established
/// without hardware-in-the-loop qualification. Passing this function does
/// not authorize destructive execution and does not change profile trust.
pub fn validate_pre_hil(profile: &Profile, path: &Path) -> Result<()> {
    validate_common(profile, path)?;
    validate_pre_hil_requirements(profile, path)
}

fn validate_pre_hil_requirements(profile: &Profile, path: &Path) -> Result<()> {
    if profile.simulated {
        return Err(Error::Invalid(format!(
            "profile {}: pre-HIL validation applies only to real controller profiles",
            path.display()
        )));
    }
    if !matches!(profile.logical_blank_value, Some(0x00 | 0xff)) {
        return Err(Error::Invalid(format!(
            "profile {}: a pre-HIL controller profile requires logical_blank_value 0 or 255",
            path.display()
        )));
    }
    validate_capacity_policy(&profile.capacity).map_err(|error| {
        Error::Invalid(format!(
            "profile {}: invalid capacity policy: {error}",
            path.display()
        ))
    })?;
    let firmware = exact_value(&profile.firmware);
    let nand_id = exact_value(&profile.nand_id);
    if firmware.is_none() || nand_id.is_none() {
        return Err(Error::Invalid(format!(
            "profile {}: a pre-HIL controller profile requires exact firmware and NAND ids",
            path.display()
        )));
    }
    if profile.protected_area_bytes.is_none() {
        return Err(Error::Invalid(format!(
            "profile {}: a pre-HIL controller profile must explicitly declare protected_area_bytes",
            path.display()
        )));
    }
    for domain in ["D1", "D2", "D3", "D4"] {
        if !profile.coverage.iter().any(|d| d == domain) {
            return Err(Error::Invalid(format!(
                "profile {}: a pre-HIL controller profile must account for {domain}",
                path.display()
            )));
        }
    }
    for rebuild in ["BBT", "FTL", "spare"] {
        if !profile.rebuilds.iter().any(|r| r == rebuild) {
            return Err(Error::Invalid(format!(
                "profile {}: a pre-HIL controller profile must declare {rebuild} rebuild",
                path.display()
            )));
        }
    }
    let implementation = profile.implementation.as_ref().ok_or_else(|| {
        Error::Invalid(format!(
            "profile {}: a pre-HIL controller profile requires implementation provenance",
            path.display()
        ))
    })?;
    if !matches!(
        implementation.strategy.as_str(),
        "clean-room" | "runtime-artifact"
    ) {
        return Err(Error::Invalid(format!(
            "profile {}: implementation strategy must be clean-room or runtime-artifact",
            path.display()
        )));
    }
    let protocol_digest =
        digest_value(&implementation.protocol_evidence_sha256).ok_or_else(|| {
            Error::Invalid(format!(
                "profile {}: implementation protocol_evidence_sha256 must be 64 hex chars",
                path.display()
            ))
        })?;
    if implementation
        .source_reference
        .chars()
        .any(|c| c.is_whitespace() || c.is_control())
        || !implementation.source_reference.starts_with("https://")
        || implementation.source_reference["https://".len()..]
            .split('/')
            .next()
            .is_none_or(|authority| authority.is_empty() || authority.contains('@'))
    {
        return Err(Error::Invalid(format!(
            "profile {}: implementation source_reference must be an HTTPS URL without user information",
            path.display()
        )));
    }
    let valid_protocol_evidence = profile.artifacts.iter().any(|artifact| {
        protocol_digest.eq_ignore_ascii_case(
            artifact
                .sha256
                .strip_prefix("sha256:")
                .unwrap_or(&artifact.sha256),
        ) && matches!(
            (&artifact.kind, &artifact.format),
            (ArtifactKind::ProtocolTrace, ArtifactFormat::Pcapng)
                | (
                    ArtifactKind::FactoryToolExecutable,
                    ArtifactFormat::PortableExecutable
                )
        ) && (artifact.kind != ArtifactKind::FactoryToolExecutable || artifact.source_url.is_some())
    });
    if !valid_protocol_evidence {
        return Err(Error::Invalid(format!(
            "profile {}: no protocol-trace or sourced factory-tool executable artifact matches protocol_evidence_sha256",
            path.display()
        )));
    }
    let mut runtime_ids = std::collections::BTreeSet::new();
    for id in &implementation.artifact_ids {
        if !runtime_ids.insert(id) {
            return Err(Error::Invalid(format!(
                "profile {}: duplicate runtime artifact id {id}",
                path.display()
            )));
        }
        if !profile.artifacts.iter().any(|a| &a.id == id) {
            return Err(Error::Invalid(format!(
                "profile {}: runtime artifact {id} is not declared",
                path.display()
            )));
        }
        if profile.artifacts.iter().any(|artifact| {
            &artifact.id == id && artifact.kind == ArtifactKind::FactoryToolExecutable
        }) {
            return Err(Error::Invalid(format!(
                "profile {}: factory-tool executable {id} is static evidence and must not be inherited by the backend",
                path.display()
            )));
        }
    }
    if implementation.strategy == "runtime-artifact"
        && !implementation.artifact_ids.iter().any(|id| {
            profile
                .artifacts
                .iter()
                .any(|a| &a.id == id && a.kind == ArtifactKind::ServiceLoader)
        })
    {
        return Err(Error::Invalid(format!(
            "profile {}: runtime-artifact strategy requires a declared service loader",
            path.display()
        )));
    }

    let recipe_artifacts = implementation
        .artifact_ids
        .iter()
        .filter_map(|id| profile.artifacts.iter().find(|artifact| &artifact.id == id))
        .filter(|artifact| artifact.kind == ArtifactKind::ProtocolRecipe)
        .collect::<Vec<_>>();
    if recipe_artifacts.len() != 1
        || recipe_artifacts[0].role != "runtime"
        || !matches!(
            recipe_artifacts[0].format,
            ArtifactFormat::Json | ArtifactFormat::Toml
        )
    {
        return Err(Error::Invalid(format!(
            "profile {}: a pre-HIL controller profile requires exactly one runtime protocol-recipe artifact",
            path.display()
        )));
    }

    let geometry = profile.geometry.as_ref().ok_or_else(|| {
        Error::Invalid(format!(
            "profile {}: a pre-HIL controller profile requires exact NAND geometry",
            path.display()
        ))
    })?;
    validate_geometry(geometry, path)?;
    let metadata = profile.metadata_layout.as_ref().ok_or_else(|| {
        Error::Invalid(format!(
            "profile {}: a pre-HIL controller profile requires controller metadata layout",
            path.display()
        ))
    })?;
    validate_metadata(metadata, geometry, path)?;
    if metadata
        .system_block_ranges
        .iter()
        .any(|range| range.policy == SystemBlockPolicy::Preserve)
    {
        return Err(Error::Invalid(format!(
            "profile {}: a pre-HIL controller profile cannot preserve controller metadata blocks",
            path.display()
        )));
    }
    Ok(())
}

/// Authenticate and semantically validate every non-HIL artifact declared by
/// a pre-HIL profile. Qualification reports are deliberately excluded: they
/// are hardware evidence and are checked by [`validate_hil_qualification`].
///
/// Passing this function establishes that the profile, static executable or
/// trace evidence, runtime recipe, loader and other declared research bytes
/// are locally complete. It never changes trust or authorizes destructive
/// execution.
pub fn validate_pre_hil_artifacts(
    profile: &Profile,
    path: &Path,
    stores: &[PathBuf],
) -> Result<Vec<VerifiedArtifact>> {
    validate_pre_hil(profile, path)?;
    if stores.is_empty() {
        return Err(Error::Usage(
            "pre-HIL artifact validation requires at least one artifact store".into(),
        ));
    }

    let mut verified = Vec::new();
    for spec in profile
        .artifacts
        .iter()
        .filter(|spec| spec.kind != ArtifactKind::QualificationReport)
    {
        let (mut file, artifact) = artifact::find_verified(spec, stores)?;
        if spec.kind == ArtifactKind::ProtocolRecipe {
            let recipe = crate::controller_recipe::load_reader(&mut file, spec.format.clone())?;
            crate::controller_recipe::validate(&recipe, profile)?;
        }
        verified.push(artifact);
    }
    Ok(verified)
}

/// Validate the independent HIL evidence required for a production profile.
/// This function validates only the qualification attachment; callers that
/// need a production decision must also call [`validate_pre_hil`].
pub fn validate_hil_qualification(profile: &Profile, path: &Path) -> Result<()> {
    let q = profile.qualification.as_ref().ok_or_else(|| {
        Error::Invalid(format!(
            "profile {}: a real production profile requires independent qualification",
            path.display()
        ))
    })?;
    let digest = digest_value(&q.report_sha256);
    if digest.is_none() {
        return Err(Error::Invalid(format!(
            "profile {}: qualification report_sha256 must be 64 hex chars",
            path.display()
        )));
    }
    if q.independent_reader.trim().is_empty()
        || q.samples == 0
        || q.power_cut_cases == 0
        || q.report_artifact_id.is_empty()
    {
        return Err(Error::Invalid(format!(
            "profile {}: qualification requires an independent reader, samples, power-cut cases and report artifact",
            path.display()
        )));
    }
    let report = profile
        .artifacts
        .iter()
        .find(|artifact| artifact.id == q.report_artifact_id)
        .ok_or_else(|| {
            Error::Invalid(format!(
                "profile {}: qualification report artifact {} is absent",
                path.display(),
                q.report_artifact_id
            ))
        })?;
    if report.kind != ArtifactKind::QualificationReport
        || report.format != ArtifactFormat::Json
        || !digest
            .expect("validated report digest")
            .eq_ignore_ascii_case(
                report
                    .sha256
                    .strip_prefix("sha256:")
                    .unwrap_or(&report.sha256),
            )
    {
        return Err(Error::Invalid(format!(
            "profile {}: qualification report artifact kind or digest mismatch",
            path.display()
        )));
    }
    Ok(())
}

fn validate_real_production(profile: &Profile, path: &Path) -> Result<()> {
    validate_pre_hil_requirements(profile, path)?;
    validate_hil_qualification(profile, path)
}

fn validate_geometry(geometry: &NandGeometryPolicy, path: &Path) -> Result<()> {
    let bounded = geometry.channels <= 32
        && geometry.chips_per_channel <= 16
        && geometry.luns_per_chip <= 16
        && geometry.planes_per_lun <= 8
        && geometry.blocks_per_lun <= 1_048_576
        && geometry.pages_per_block <= 4096;
    if !bounded
        || geometry.channels == 0
        || geometry.chips_per_channel == 0
        || geometry.luns_per_chip == 0
        || geometry.planes_per_lun == 0
        || geometry.blocks_per_lun < 16
        || !geometry
            .blocks_per_lun
            .is_multiple_of(geometry.planes_per_lun)
        || geometry.pages_per_block < 16
        || !geometry.pages_per_block.is_power_of_two()
        || !(512..=65_536).contains(&geometry.page_bytes)
        || !geometry.page_bytes.is_power_of_two()
        || !(16..=8192).contains(&geometry.oob_bytes)
        || !(3..=6).contains(&geometry.address_cycles)
        || !(1..=4).contains(&geometry.bits_per_cell)
    {
        return Err(Error::Invalid(format!(
            "profile {}: NAND geometry contains zero, non-power-of-two or out-of-range dimensions",
            path.display()
        )));
    }
    if geometry.bad_block_marker_pages.is_empty()
        || geometry.bad_block_marker_offsets.is_empty()
        || geometry
            .bad_block_marker_pages
            .iter()
            .any(|page| *page >= geometry.pages_per_block)
        || geometry
            .bad_block_marker_offsets
            .iter()
            .any(|offset| *offset >= geometry.oob_bytes)
        || geometry.randomizer.trim().is_empty()
        || geometry.read_retry.trim().is_empty()
        || geometry.ecc_layout.trim().is_empty()
    {
        return Err(Error::Invalid(format!(
            "profile {}: NAND geometry requires bounded bad-block markers, randomizer, read-retry and ECC layout",
            path.display()
        )));
    }
    let total_blocks = u64::from(geometry.channels)
        .checked_mul(u64::from(geometry.chips_per_channel))
        .and_then(|v| v.checked_mul(u64::from(geometry.luns_per_chip)))
        .and_then(|v| v.checked_mul(u64::from(geometry.blocks_per_lun)))
        .ok_or_else(|| {
            Error::Invalid(format!(
                "profile {}: NAND block count overflow",
                path.display()
            ))
        })?;
    if total_blocks > crate::controller_recipe::MAX_PHYSICAL_BLOCKS {
        return Err(Error::Invalid(format!(
            "profile {}: NAND block count {total_blocks} exceeds the durable controller evidence bound {}",
            path.display(),
            crate::controller_recipe::MAX_PHYSICAL_BLOCKS
        )));
    }
    Ok(())
}

fn validate_metadata(
    metadata: &MetadataLayoutPolicy,
    geometry: &NandGeometryPolicy,
    path: &Path,
) -> Result<()> {
    if metadata.bbt_format.trim().is_empty()
        || metadata.ftl_format.trim().is_empty()
        || metadata.spare_format.trim().is_empty()
        || metadata.commit_protocol.trim().is_empty()
        || metadata.system_block_ranges.is_empty()
    {
        return Err(Error::Invalid(format!(
            "profile {}: metadata layout requires BBT, FTL, spare, commit protocol and system block ranges",
            path.display()
        )));
    }
    let total_blocks = u64::from(geometry.channels)
        * u64::from(geometry.chips_per_channel)
        * u64::from(geometry.luns_per_chip)
        * u64::from(geometry.blocks_per_lun);
    let mut previous_end = None;
    for range in &metadata.system_block_ranges {
        if range.start > range.end
            || range.end >= total_blocks
            || range.purpose.trim().is_empty()
            || previous_end.is_some_and(|end| range.start <= end)
        {
            return Err(Error::Invalid(format!(
                "profile {}: metadata system block ranges must be named, ordered, disjoint and within geometry",
                path.display()
            )));
        }
        previous_end = Some(range.end);
    }
    Ok(())
}

/// Search directories for profiles: NCLR_PROFILE_DIR,
/// /usr/share/nclr/profiles, and the backend dirs (for dev builds).
pub fn search_dirs(explicit: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(env) = std::env::var("NCLR_PROFILE_DIR") {
        dirs.push(PathBuf::from(env));
    }
    dirs.extend(explicit.iter().cloned());
    dirs.extend(trusted_search_dirs());
    for bd in crate::backend::search_dirs(&[]) {
        dirs.push(bd.join("profiles"));
    }
    dirs
}

/// Package-managed profile locations. Environment and explicit search paths
/// are intentionally excluded: a user-controlled directory cannot promote a
/// real controller profile to production trust merely by editing TOML.
pub fn trusted_search_dirs() -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from("/usr/share/nclr/profiles")];
    // Prefix-relative discovery supports both the core at <prefix>/bin/nclr
    // and backends at <prefix>/libexec/nclr/nclr-*.
    if let Ok(exe) = std::env::current_exe() {
        if let Some(prefix) = install_prefix(&exe) {
            let relative = prefix.join("share/nclr/profiles");
            if !dirs.contains(&relative) {
                dirs.push(relative);
            }
        }
    }
    dirs
}

/// Whether a TOML file is a full runtime profile rather than a read-only
/// identification or probe profile stored in the same package directory.
pub fn is_runtime_profile_path(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("");
    path.extension().and_then(|extension| extension.to_str()) == Some("toml")
        && !name.starts_with("identify-")
        && !name.starts_with("probe-")
}

fn install_prefix(executable: &Path) -> Option<&Path> {
    let parent = executable.parent()?;
    if parent.file_name().and_then(|n| n.to_str()) == Some("bin") {
        return parent.parent();
    }
    if parent.file_name().and_then(|n| n.to_str()) == Some("nclr")
        && parent
            .parent()
            .and_then(|p| p.file_name())
            .and_then(|n| n.to_str())
            == Some("libexec")
    {
        return parent.parent().and_then(Path::parent);
    }
    None
}

/// Find the first profile (by id) across the search dirs.
pub fn find(id: &str, dirs: &[PathBuf]) -> Result<Profile> {
    if id.starts_with('.')
        || id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    {
        return Err(Error::Invalid(format!("invalid profile id: {id}")));
    }
    for dir in dirs {
        let path = dir.join(format!("{id}.toml"));
        if path.is_file() {
            return load(&path);
        }
    }
    Err(Error::Invalid(format!(
        "profile {id} not found in {}",
        dirs.iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile() -> Profile {
        Profile {
            schema: PROFILE_SCHEMA,
            id: "sim-controller-1".into(),
            controller_id: "sim-ctlr-01".into(),
            firmware: VersionRange {
                min: Some("1.0".into()),
                max: Some("9.9".into()),
            },
            nand_id: VersionRange {
                min: Some("SIMNAND-1".into()),
                max: Some("SIMNAND-1".into()),
            },
            trust: "production".into(),
            simulated: true,
            operations: vec![
                "probe".into(),
                "plan".into(),
                "run".into(),
                "status".into(),
                "recover".into(),
            ],
            coverage: vec![
                "D0".into(),
                "D1".into(),
                "D2".into(),
                "D3".into(),
                "D4".into(),
            ],
            rebuilds: vec!["BBT".into(), "FTL".into(), "spare".into()],
            preserves: vec!["FBB-marker".into()],
            protected_area_bytes: Some(0),
            capacity: CapacityPolicy {
                bin_bytes: 512 * 512,
                minimum_spare_blocks: 4,
                spare_ratio: 0.05,
            },
            ecc: EccPolicy {
                strength: 40,
                min_margin: 8,
                max_read_retry: 4,
                max_read_latency_ms: 200,
            },
            recovery: RecoveryPolicy {
                method: "service-mode-exit+reset".into(),
                timeout_ms: 30_000,
            },
            logical_blank_value: Some(0xff),
            sd_vendor: SdVendorPolicy::default(),
            certification: None,
            qualification: None,
            implementation: None,
            controller_bootstrap: None,
            geometry: None,
            metadata_layout: None,
            artifacts: Vec::new(),
            sha256: None,
        }
    }

    #[test]
    fn exact_match() {
        let p = profile();
        assert!(p.matches("sim-ctlr-01", "3.2", "SIMNAND-1"));
        // Controller id must match exactly.
        assert!(!p.matches("sim-ctlr-02", "3.2", "SIMNAND-1"));
        // Firmware outside the range.
        assert!(!p.matches("sim-ctlr-01", "10.0", "SIMNAND-1"));
        assert!(!p.matches("sim-ctlr-01", "0.9", "SIMNAND-1"));
        // NAND id outside the range.
        assert!(!p.matches("sim-ctlr-01", "3.2", "SIMNAND-2"));
    }

    #[test]
    fn version_ranges_compare_numerically() {
        assert!(in_range(
            &VersionRange {
                min: Some("1.0".into()),
                max: Some("2.5".into())
            },
            "1.9"
        ));
        assert!(in_range(
            &VersionRange {
                min: Some("1.0".into()),
                max: Some("2.5".into())
            },
            "2.5"
        ));
        // 1.10 > 1.9 (numeric segments, not lexicographic).
        assert!(!in_range(
            &VersionRange {
                min: Some("1.10".into()),
                max: None
            },
            "1.9"
        ));
        assert!(in_range(
            &VersionRange {
                min: Some("1.9".into()),
                max: Some("1.10".into())
            },
            "1.10"
        ));

        // Textual identity components are security-sensitive and must not be
        // discarded while comparing numeric suffixes.
        assert!(!in_range(
            &VersionRange {
                min: Some("SIMNAND-1".into()),
                max: Some("SIMNAND-1".into())
            },
            "OTHERNAND-1"
        ));
        assert!(in_range(
            &VersionRange {
                min: Some("SIMNAND-1".into()),
                max: Some("SIMNAND-3".into())
            },
            "SIMNAND-2"
        ));
        assert!(!in_range(
            &VersionRange {
                min: Some("SIMNAND-1".into()),
                max: Some("SIMNAND-3".into())
            },
            "OTHERNAND-2"
        ));
    }

    #[test]
    fn trust_gating() {
        let p = profile();
        assert!(p.destructive_allowed());
        let mut r = p.clone();
        r.trust = "research".into();
        assert!(!r.destructive_allowed());
        assert_eq!(r.trust(), Some(Trust::Research));
    }

    #[test]
    fn controller_bootstrap_requires_a_supported_family_and_exact_tuple() {
        let mut p = profile();
        p.id = "sandisk-cruzer-research".into();
        p.controller_id = "sandisk-82-00263-1".into();
        p.simulated = false;
        p.trust = "research".into();
        p.controller_bootstrap = Some(ControllerBootstrapPolicy {
            family: "sandisk-cruzer".into(),
            usb_vid: 0x0781,
            usb_pid: 0x5567,
            usb_bcd_device: 0x0100,
            usb_manufacturer: "SanDisk".into(),
            usb_product: "Cruzer Slice".into(),
            usb_serial: "4C530001".into(),
            scsi_vendor: "SanDisk".into(),
            scsi_product: "Cruzer Slice".into(),
            scsi_revision: "1.00".into(),
        });
        let path = Path::new("sandisk-cruzer-research.toml");
        assert!(validate(&p, path).is_ok());

        // USB permits product id and bcdDevice value zero. They remain exact
        // tuple values and are followed by recipe-owned identity checks.
        p.controller_bootstrap.as_mut().unwrap().usb_pid = 0;
        p.controller_bootstrap.as_mut().unwrap().usb_bcd_device = 0;
        assert!(validate(&p, path).is_ok());
        p.controller_bootstrap.as_mut().unwrap().usb_pid = 0x5567;
        p.controller_bootstrap.as_mut().unwrap().usb_bcd_device = 0x0100;

        p.controller_bootstrap.as_mut().unwrap().usb_vid = 0;
        assert!(validate(&p, path).is_err());
        p.controller_bootstrap.as_mut().unwrap().usb_vid = 0x0781;
        p.controller_bootstrap.as_mut().unwrap().scsi_product = " Cruzer Slice".into();
        assert!(validate(&p, path).is_err());
        p.controller_bootstrap.as_mut().unwrap().scsi_product = "Cruzer Slice".into();
        p.controller_bootstrap.as_mut().unwrap().family = "unknown".into();
        assert!(validate(&p, path).is_err());

        p.controller_bootstrap.as_mut().unwrap().family = "silicon-motion-ufd".into();
        p.controller_bootstrap.as_mut().unwrap().usb_vid = 0x125f;
        assert!(validate(&p, path).is_err());
        p.controller_id = "smi-sm3281bb".into();
        assert!(validate(&p, path).is_ok());
    }

    #[test]
    fn real_production_requires_exact_hil_qualification() {
        let mut p = profile();
        p.id = "phison-ps2303-test".into();
        p.controller_id = "phison-ps2303".into();
        p.firmware = VersionRange {
            min: Some("01.03.53".into()),
            max: Some("01.03.53".into()),
        };
        p.nand_id = VersionRange {
            min: Some("98de94827656".into()),
            max: Some("98de94827656".into()),
        };
        p.simulated = false;
        let path = Path::new("phison-ps2303-test.toml");
        assert!(validate(&p, path).is_err());
        p.qualification = Some(QualificationPolicy {
            report_sha256: "11".repeat(32),
            independent_reader: "socketed NAND reader".into(),
            samples: 3,
            power_cut_cases: 8,
            report_artifact_id: "qualification-report".into(),
        });
        let artifact = |id: &str, role: &str, kind: ArtifactKind, format| ArtifactSpec {
            id: id.into(),
            role: role.into(),
            kind,
            format,
            controller_id: p.controller_id.clone(),
            firmware: "01.03.53".into(),
            nand_id: "98de94827656".into(),
            sha256: if id == "qualification-report" {
                "11".repeat(32)
            } else {
                "22".repeat(32)
            },
            size_bytes: 4096,
            source_url: Some(format!("https://example.invalid/{id}")),
            terms_url: None,
            redistributable: true,
        };
        p.artifacts = vec![
            artifact(
                "qualification-report",
                "qualification-report",
                ArtifactKind::QualificationReport,
                crate::artifact::ArtifactFormat::Json,
            ),
            artifact(
                "protocol-trace",
                "protocol-trace",
                ArtifactKind::ProtocolTrace,
                crate::artifact::ArtifactFormat::Pcapng,
            ),
            artifact(
                "protocol-recipe",
                "runtime",
                ArtifactKind::ProtocolRecipe,
                crate::artifact::ArtifactFormat::Json,
            ),
        ];
        p.implementation = Some(ImplementationPolicy {
            strategy: "clean-room".into(),
            protocol_evidence_sha256: "22".repeat(32),
            source_reference: "https://example.invalid/clean-room-design".into(),
            artifact_ids: vec!["protocol-recipe".into()],
        });
        p.geometry = Some(NandGeometryPolicy {
            channels: 2,
            chips_per_channel: 1,
            luns_per_chip: 1,
            planes_per_lun: 2,
            blocks_per_lun: 1024,
            pages_per_block: 256,
            page_bytes: 8192,
            oob_bytes: 640,
            address_cycles: 5,
            bits_per_cell: 2,
            bad_block_marker_pages: vec![0, 1],
            bad_block_marker_offsets: vec![0],
            randomizer: "documented-seed-v1".into(),
            read_retry: "vendor-table-v1".into(),
            ecc_layout: "bch-40-1k".into(),
        });
        p.metadata_layout = Some(MetadataLayoutPolicy {
            bbt_format: "dual-copy-generation-crc32".into(),
            ftl_format: "dual-copy-generation-crc32".into(),
            spare_format: "factory-marker-preserving".into(),
            commit_protocol: "write-inactive-verify-switch-generation".into(),
            system_block_ranges: vec![SystemBlockRange {
                start: 0,
                end: 15,
                purpose: "controller-metadata".into(),
                policy: SystemBlockPolicy::RebuildControllerMetadata,
            }],
        });
        assert!(validate(&p, path).is_ok());
        let complete = p.clone();
        let mut pre_hil = complete.clone();
        pre_hil.trust = "validated".into();
        pre_hil.qualification = None;
        pre_hil
            .artifacts
            .retain(|artifact| artifact.kind != ArtifactKind::QualificationReport);
        assert!(validate(&pre_hil, path).is_ok());
        assert!(validate_pre_hil(&pre_hil, path).is_ok());
        assert!(validate_hil_qualification(&pre_hil, path).is_err());

        let mut static_evidence = pre_hil.clone();
        let evidence = static_evidence
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.kind == ArtifactKind::ProtocolTrace)
            .unwrap();
        evidence.id = "factory-tool-evidence".into();
        evidence.role = "protocol-evidence".into();
        evidence.kind = ArtifactKind::FactoryToolExecutable;
        evidence.format = ArtifactFormat::PortableExecutable;
        assert!(validate_pre_hil(&static_evidence, path).is_ok());
        static_evidence
            .implementation
            .as_mut()
            .unwrap()
            .artifact_ids
            .push("factory-tool-evidence".into());
        assert!(validate_pre_hil(&static_evidence, path).is_err());
        static_evidence
            .implementation
            .as_mut()
            .unwrap()
            .artifact_ids
            .pop();
        static_evidence
            .artifacts
            .iter_mut()
            .find(|artifact| artifact.id == "factory-tool-evidence")
            .unwrap()
            .source_url = None;
        assert!(validate_pre_hil(&static_evidence, path).is_err());

        assert!(validate_pre_hil_artifacts(&pre_hil, path, &[]).is_err());
        let empty_store = tempfile::tempdir().unwrap();
        assert!(
            validate_pre_hil_artifacts(&pre_hil, path, &[empty_store.path().to_path_buf()])
                .is_err()
        );

        let mut invalid_recipe_profile = pre_hil.clone();
        let trace_bytes = b"\x0a\x0d\x0d\x0a";
        let recipe_bytes = b"{}";
        let trace_digest = crate::digest(trace_bytes)
            .trim_start_matches("sha256:")
            .to_string();
        let recipe_digest = crate::digest(recipe_bytes)
            .trim_start_matches("sha256:")
            .to_string();
        for artifact in &mut invalid_recipe_profile.artifacts {
            let (digest, size) = if artifact.kind == ArtifactKind::ProtocolTrace {
                (&trace_digest, trace_bytes.len())
            } else {
                (&recipe_digest, recipe_bytes.len())
            };
            artifact.sha256 = digest.clone();
            artifact.size_bytes = size as u64;
        }
        invalid_recipe_profile
            .implementation
            .as_mut()
            .unwrap()
            .protocol_evidence_sha256 = trace_digest;
        let store = tempfile::tempdir().unwrap();
        for artifact in &invalid_recipe_profile.artifacts {
            let bytes = if artifact.kind == ArtifactKind::ProtocolTrace {
                trace_bytes.as_slice()
            } else {
                recipe_bytes.as_slice()
            };
            let artifact_path = crate::artifact::store_path(store.path(), artifact);
            std::fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
            std::fs::write(artifact_path, bytes).unwrap();
        }
        let error = validate_pre_hil_artifacts(
            &invalid_recipe_profile,
            path,
            &[store.path().to_path_buf()],
        )
        .unwrap_err();
        assert!(
            error.to_string().contains("controller recipe JSON"),
            "verified but semantically incomplete recipe must be rejected: {error}"
        );

        p.metadata_layout.as_mut().unwrap().system_block_ranges[0].policy =
            SystemBlockPolicy::Preserve;
        assert!(validate(&p, path).is_err());
        p = complete.clone();
        p.geometry.as_mut().unwrap().bad_block_marker_offsets = vec![640];
        assert!(validate(&p, path).is_err());
        p = complete.clone();
        p.implementation.as_mut().unwrap().protocol_evidence_sha256 = "33".repeat(32);
        assert!(validate(&p, path).is_err());
        p = complete.clone();
        p.metadata_layout.as_mut().unwrap().system_block_ranges = vec![
            SystemBlockRange {
                start: 10,
                end: 20,
                purpose: "first".into(),
                policy: SystemBlockPolicy::Preserve,
            },
            SystemBlockRange {
                start: 20,
                end: 30,
                purpose: "overlap".into(),
                policy: SystemBlockPolicy::RebuildBbt,
            },
        ];
        assert!(validate(&p, path).is_err());
        let mut runtime = complete.clone();
        runtime.artifacts.push(ArtifactSpec {
            id: "factory-tool".into(),
            role: "factory-tool".into(),
            kind: ArtifactKind::FactoryToolExecutable,
            format: crate::artifact::ArtifactFormat::PortableExecutable,
            controller_id: runtime.controller_id.clone(),
            firmware: "01.03.53".into(),
            nand_id: "98de94827656".into(),
            sha256: "33".repeat(32),
            size_bytes: 4096,
            source_url: Some("https://example.invalid/factory-tool".into()),
            terms_url: None,
            redistributable: true,
        });
        runtime.implementation.as_mut().unwrap().strategy = "runtime-artifact".into();
        runtime
            .implementation
            .as_mut()
            .unwrap()
            .artifact_ids
            .push("factory-tool".into());
        assert!(validate(&runtime, path).is_err());
        runtime.artifacts.pop();
        runtime.implementation.as_mut().unwrap().artifact_ids.pop();
        runtime.artifacts.push(ArtifactSpec {
            id: "service-loader".into(),
            role: "service-loader".into(),
            kind: ArtifactKind::ServiceLoader,
            format: crate::artifact::ArtifactFormat::Opaque,
            controller_id: runtime.controller_id.clone(),
            firmware: "01.03.53".into(),
            nand_id: "98de94827656".into(),
            sha256: "44".repeat(32),
            size_bytes: 4096,
            source_url: Some("https://example.invalid/service-loader".into()),
            terms_url: None,
            redistributable: true,
        });
        runtime
            .implementation
            .as_mut()
            .unwrap()
            .artifact_ids
            .push("service-loader".into());
        assert!(validate(&runtime, path).is_ok());
        p = complete;
        p.firmware.max = Some("01.03.54".into());
        assert!(validate(&p, path).is_err());
    }

    #[test]
    fn simulated_flag_cannot_bypass_real_qualification() {
        let mut p = profile();
        p.id = "other-sim".into();
        assert!(validate(&p, Path::new("other-sim.toml")).is_err());
    }

    #[test]
    fn runtime_profile_paths_exclude_read_only_profile_namespaces() {
        assert!(is_runtime_profile_path(Path::new("phison-ps2303.toml")));
        assert!(!is_runtime_profile_path(Path::new(
            "identify-phison-ufd.toml"
        )));
        assert!(!is_runtime_profile_path(Path::new(
            "probe-phison-ps2303.toml"
        )));
        assert!(!is_runtime_profile_path(Path::new("phison-ps2303.json")));
    }

    #[test]
    fn destructive_capacity_policy_is_bounded() {
        let mut p = profile();
        p.logical_blank_value = None;
        assert!(validate(&p, Path::new("blank.toml")).is_err());

        let mut p = profile();
        p.capacity.minimum_spare_blocks = 0;
        assert!(validate(&p, Path::new("capacity.toml")).is_err());

        p = profile();
        p.capacity.spare_ratio = 1.0;
        assert!(validate(&p, Path::new("capacity.toml")).is_err());

        p = profile();
        p.capacity.bin_bytes = 513;
        assert!(validate(&p, Path::new("capacity.toml")).is_err());
    }

    #[test]
    fn capacity_plan() {
        // 100 good, 4 reserved, policy min spare 4 / ratio 5% / weak 3:
        // spare = max(4, ceil(5), 3+1) = 5. No binning -> user = 91.
        let plan = plan_capacity(
            100,
            4,
            3,
            &CapacityPolicy {
                bin_bytes: 0,
                minimum_spare_blocks: 4,
                spare_ratio: 0.05,
            },
        )
        .unwrap();
        assert_eq!(plan.good_blocks, 100);
        assert_eq!(plan.reserved_blocks, 4);
        assert_eq!(plan.spare_blocks, 5);
        assert_eq!(plan.user_blocks, 91);
        // Binning: bin = 512 blocks -> rounded down to a whole bin.
        let plan2 = plan_capacity(
            1000,
            4,
            0,
            &CapacityPolicy {
                bin_bytes: 512 * 512,
                minimum_spare_blocks: 4,
                spare_ratio: 0.05,
            },
        )
        .unwrap();
        assert_eq!(plan2.user_blocks % 512, 0);
        assert!(plan2.user_blocks >= 512);
    }

    #[test]
    fn weak_block_decision() {
        let p = profile();
        // margin = 40 - 30 = 10 >= 8: not weak.
        assert!(!is_weak(30, 0, 10, &p.ecc));
        // margin = 40 - 35 = 5 < 8: weak.
        assert!(is_weak(35, 0, 10, &p.ecc));
        // Too many read retries.
        assert!(is_weak(10, 9, 10, &p.ecc));
        // Excessive read latency.
        assert!(is_weak(10, 0, 500, &p.ecc));
    }

    #[test]
    fn load_validate_and_find() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("sim-controller-1.toml");
        let toml_str = toml::to_string(&profile()).unwrap();
        std::fs::write(&path, toml_str).unwrap();
        let loaded = load(&path).unwrap();
        assert_eq!(loaded.id, "sim-controller-1");
        assert_eq!(loaded.sha256.as_deref().map(str::len), Some(64));
        let found = find("sim-controller-1", &[dir.path().to_path_buf()]).unwrap();
        assert_eq!(found.controller_id, "sim-ctlr-01");
        // Invalid trust rejected.
        let mut bad = profile();
        bad.trust = "bogus".into();
        let bad_path = dir.path().join("bad.toml");
        std::fs::write(&bad_path, toml::to_string(&bad).unwrap()).unwrap();
        assert!(load(&bad_path).is_err());
    }

    #[test]
    fn shipped_sim_profile_digest_is_valid() {
        let path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../profiles/sim-controller-1.toml");
        let profile = load(&path).unwrap();
        assert_eq!(profile.id, "sim-controller-1");
        assert_eq!(profile.sha256.as_deref().map(str::len), Some(64));
        assert!(profile.destructive_allowed());
    }

    #[test]
    fn install_prefix_supports_core_and_backend_layouts() {
        assert_eq!(
            install_prefix(Path::new("/opt/nclr/bin/nclr")),
            Some(Path::new("/opt/nclr"))
        );
        assert_eq!(
            install_prefix(Path::new("/opt/nclr/libexec/nclr/nclr-sim")),
            Some(Path::new("/opt/nclr"))
        );
        assert_eq!(install_prefix(Path::new("/tmp/target/debug/nclr")), None);
    }

    #[test]
    fn usb_ids_parses_vendor_and_model_lines() {
        let fixture = concat!(
            "# usb.ids fixture\n",
            "0718  Imation Corp.\n",
            "13fe  Phison Electronics Corp.\n",
            "\t1f23  PS2232 flash drive controller\n",
            "\t\t0001  Interface entry\n",
            "3538  Power Quotient International Co., Ltd.\n",
            "\t0901  Traveling Disk U273 (4GB)\n",
        );
        assert_eq!(
            usb_ids_vendor_from(fixture, 0x13FE).as_deref(),
            Some("Phison Electronics Corp.")
        );
        assert_eq!(
            usb_ids_model_from(fixture, 0x13FE, 0x1F23).as_deref(),
            Some("PS2232 flash drive controller")
        );
        assert_eq!(
            usb_ids_vendor_from(fixture, 0x0718).as_deref(),
            Some("Imation Corp.")
        );
        assert_eq!(
            usb_ids_model_from(fixture, 0x3538, 0x0901).as_deref(),
            Some("Traveling Disk U273 (4GB)")
        );
        // Unknown ids are not matched.
        assert_eq!(usb_ids_vendor_from(fixture, 0xF0F0), None);
        assert_eq!(usb_ids_model_from(fixture, 0x13FE, 0xFFFF), None);
        // Invalid UTF-8 boundaries in a non-ID prefix cannot panic.
        assert_eq!(usb_ids_vendor_from("éé  invalid\n", 0x13FE), None);
    }

    #[test]
    fn identify_profiles_validate_and_resolve_family_hints() {
        // All shipped identify-*.toml files load and validate.
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../profiles");
        let mut loaded = 0;
        for entry in std::fs::read_dir(&dir).unwrap().flatten() {
            let path = entry.path();
            if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|n| n.starts_with("identify-"))
            {
                load_identify_profile(&path).unwrap();
                loaded += 1;
            }
        }
        assert!(
            loaded >= 28,
            "expected at least 28 identify profiles, got {loaded}"
        );

        // VID hints resolve to a single family.
        let profiles = load_identify_profiles(&[dir]);
        assert_eq!(
            family_hint_from_vid(0x13FE, &profiles),
            Some(crate::controller_protocol::Family::PhisonUfd)
        );
        assert_eq!(
            family_hint_from_vid(0x4146, &profiles),
            Some(crate::controller_protocol::Family::UsbestUfd)
        );
        assert_eq!(
            family_hint_from_vid(0x1E3D, &profiles),
            Some(crate::controller_protocol::Family::ChipsbankUfd)
        );
        assert_eq!(
            family_hint_from_vid(0x0EA0, &profiles),
            Some(crate::controller_protocol::Family::OtiUfd)
        );
        assert_eq!(
            family_hint_from_vid(0x1951, &profiles),
            Some(crate::controller_protocol::Family::HyperstoneUfd)
        );
        assert_eq!(
            family_hint_from_vid(0x23A9, &profiles),
            Some(crate::controller_protocol::Family::YeestorUfd)
        );
        // Vendor-owned VIDs confirmed via usb.ids for the recipe-only
        // legacy families.
        assert_eq!(
            family_hint_from_vid(0x0A16, &profiles),
            Some(crate::controller_protocol::Family::Trek2000Ufd)
        );
        assert_eq!(
            family_hint_from_vid(0x102A, &profiles),
            Some(crate::controller_protocol::Family::RamosUfd)
        );
        assert_eq!(
            family_hint_from_vid(0x0424, &profiles),
            Some(crate::controller_protocol::Family::SmscUfd)
        );
        // An unknown / unlisted VID hints nothing.
        assert_eq!(family_hint_from_vid(0x1234, &profiles), None);
        // The marker parameters for UT163 come from the profile.
        let ut163 = profiles.iter().find(|p| p.family == "usbest-ufd").unwrap();
        let marker = ut163.inquiry_marker.as_ref().unwrap();
        assert_eq!(marker.marker, "U163");
        assert_eq!(marker.alloc_len, 96);
        assert_eq!(marker.standard_len, 36);
    }

    #[test]
    fn identify_profile_validation_rejects_bad_fields() {
        let good = IdentifyProfile {
            schema: PROFILE_SCHEMA,
            id: "x".into(),
            family: "usbest-ufd".into(),
            usb_vid_hints: vec![0x4146],
            inquiry_marker: Some(InquiryMarkerIdentify {
                marker: "U163".into(),
                alloc_len: 96,
                standard_len: 36,
            }),
        };
        validate_identify_profile(&good, Path::new("good.toml")).unwrap();

        let mut unknown_family = good.clone();
        unknown_family.family = "bogus".into();
        assert!(validate_identify_profile(&unknown_family, Path::new("bad.toml")).is_err());

        let mut bad_marker = good.clone();
        bad_marker.inquiry_marker.as_mut().unwrap().standard_len = 200;
        assert!(validate_identify_profile(&bad_marker, Path::new("bad.toml")).is_err());

        let mut zero_vid = good.clone();
        zero_vid.usb_vid_hints = vec![0];
        assert!(validate_identify_profile(&zero_vid, Path::new("bad.toml")).is_err());

        let duplicate = vec![good.clone(), good];
        assert_eq!(
            family_hint_from_vid(0x4146, &duplicate),
            Some(crate::controller_protocol::Family::UsbestUfd),
            "the same packaged profile found through two search paths must not become ambiguous"
        );
    }
}
