//! Controller profile system.
//!
//! A profile declares the identification conditions, operations, coverage,
//! destructiveness, timeouts, recovery method, capacity boundaries, FBB
//! marker and ECC thresholds for a controller/firmware/NAND combination.
//! Destructive execution requires an *exact* match and a `production` trust
//! state; anything else is refused.

use crate::artifact::{self, ArtifactFormat, ArtifactKind, ArtifactSpec};
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
    /// Digest of a captured USB BOT trace supporting the implementation.
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
    #[serde(default)]
    pub capacity: CapacityPolicy,
    #[serde(default)]
    pub ecc: EccPolicy,
    #[serde(default)]
    pub recovery: RecoveryPolicy,
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
    if let Some(bootstrap) = &profile.controller_bootstrap {
        const BOOTSTRAP_FAMILIES: [&str; 4] = [
            "phison-ps2251",
            "alcor-au698x",
            "smi-sm32x",
            "sandisk-cruzer",
        ];
        let canonical_scsi = |value: &str, maximum: usize| {
            !value.is_empty()
                && value.len() <= maximum
                && value.trim() == value
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_graphic() || byte == b' ')
        };
        let controller_family_matches = match bootstrap.family.as_str() {
            "phison-ps2251" => profile.controller_id.starts_with("phison-ps"),
            "alcor-au698x" => profile.controller_id.starts_with("alcor-au"),
            "smi-sm32x" => profile.controller_id.starts_with("smi-sm"),
            "sandisk-cruzer" => profile.controller_id.starts_with("sandisk-"),
            _ => false,
        };
        if profile.simulated
            || !BOOTSTRAP_FAMILIES.contains(&bootstrap.family.as_str())
            || !controller_family_matches
            || bootstrap.usb_vid == 0
            || bootstrap.usb_pid == 0
            || bootstrap.usb_bcd_device == 0
            || !canonical_scsi(&bootstrap.scsi_vendor, 8)
            || !canonical_scsi(&bootstrap.scsi_product, 16)
            || !canonical_scsi(&bootstrap.scsi_revision, 4)
        {
            return Err(Error::Invalid(format!(
                "profile {}: controller_bootstrap must name a supported family and exact USB/SCSI tuple",
                path.display()
            )));
        }
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
    if profile.destructive_allowed() && !profile.simulated {
        validate_real_production(profile, path)?;
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

fn validate_real_production(profile: &Profile, path: &Path) -> Result<()> {
    let firmware = exact_value(&profile.firmware);
    let nand_id = exact_value(&profile.nand_id);
    if firmware.is_none() || nand_id.is_none() {
        return Err(Error::Invalid(format!(
            "profile {}: a real production profile requires exact firmware and NAND ids",
            path.display()
        )));
    }
    for domain in ["D1", "D2", "D3", "D4"] {
        if !profile.coverage.iter().any(|d| d == domain) {
            return Err(Error::Invalid(format!(
                "profile {}: a real production profile must account for {domain}",
                path.display()
            )));
        }
    }
    for rebuild in ["BBT", "FTL", "spare"] {
        if !profile.rebuilds.iter().any(|r| r == rebuild) {
            return Err(Error::Invalid(format!(
                "profile {}: a real production profile must declare {rebuild} rebuild",
                path.display()
            )));
        }
    }
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
        .find(|a| a.id == q.report_artifact_id)
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

    let implementation = profile.implementation.as_ref().ok_or_else(|| {
        Error::Invalid(format!(
            "profile {}: a real production profile requires implementation provenance",
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
    if !profile.artifacts.iter().any(|a| {
        a.kind == ArtifactKind::ProtocolTrace
            && a.format == ArtifactFormat::Pcapng
            && protocol_digest
                .eq_ignore_ascii_case(a.sha256.strip_prefix("sha256:").unwrap_or(&a.sha256))
    }) {
        return Err(Error::Invalid(format!(
            "profile {}: no protocol-trace artifact matches protocol_evidence_sha256",
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
            "profile {}: a real production profile requires exactly one runtime protocol-recipe artifact",
            path.display()
        )));
    }

    let geometry = profile.geometry.as_ref().ok_or_else(|| {
        Error::Invalid(format!(
            "profile {}: a real production profile requires exact NAND geometry",
            path.display()
        ))
    })?;
    validate_geometry(geometry, path)?;
    let metadata = profile.metadata_layout.as_ref().ok_or_else(|| {
        Error::Invalid(format!(
            "profile {}: a real production profile requires controller metadata layout",
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
            "profile {}: a real production profile cannot preserve controller metadata blocks",
            path.display()
        )));
    }
    Ok(())
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
            scsi_vendor: "SanDisk".into(),
            scsi_product: "Cruzer Slice".into(),
            scsi_revision: "1.00".into(),
        });
        let path = Path::new("sandisk-cruzer-research.toml");
        assert!(validate(&p, path).is_ok());

        p.controller_bootstrap.as_mut().unwrap().usb_vid = 0;
        assert!(validate(&p, path).is_err());
        p.controller_bootstrap.as_mut().unwrap().usb_vid = 0x0781;
        p.controller_bootstrap.as_mut().unwrap().scsi_product = " Cruzer Slice".into();
        assert!(validate(&p, path).is_err());
        p.controller_bootstrap.as_mut().unwrap().scsi_product = "Cruzer Slice".into();
        p.controller_bootstrap.as_mut().unwrap().family = "unknown".into();
        assert!(validate(&p, path).is_err());

        p.controller_bootstrap.as_mut().unwrap().family = "smi-sm32x".into();
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
}
