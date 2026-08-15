//! Offline vendor-tool protocol candidate extraction.
//!
//! Static byte matches are leads for trace analysis, never proof that a
//! command is reachable, safe for a particular controller, or sufficient for
//! D1-D4 coverage. Patterns in this module come from public source code and
//! retain their source URL in every finding.

use crate::controller_protocol::{family_from_str, Family};
use crate::errors::{Error, Result};
use des::{
    cipher::{BlockCipherDecrypt, KeyInit},
    Des,
};
use encoding_rs::GBK;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const TOOL_ANALYSIS_SCHEMA: u32 = 12;
pub const MAX_TOOL_FILES: usize = 100_000;
pub const MAX_TOOL_FILE_BYTES: u64 = crate::artifact::MAX_ARTIFACT_BYTES;
const READ_CHUNK_BYTES: usize = 1024 * 1024;
const MAX_PATTERN_BYTES: usize = 16;
const MAX_PATTERN_TEXT_BYTES: usize = 256;
const MAX_STRUCTURED_TEXT_BYTES: u64 = 8 * 1024 * 1024;
const MAX_STRUCTURED_LINE_BYTES: usize = 4096;
const MAX_STRUCTURED_LINES: usize = 100_000;
const MAX_SMI_ASSIGNMENTS: usize = 100_000;
const MAX_ALCOR_MODULE_MAPPINGS: usize = 100_000;
const MAX_FIRSTCHIP_RECORDS: usize = 100_000;
const MAX_FIRSTCHIP_PARAMETERS: usize = 1_000_000;
const FIRSTCHIP_CONFIG_KEY: &[u8; 8] = b"ixtec898";
const CHIPSBANK_CBM_MAGIC: &[u8; 8] = b"cbmv1001";
const CHIPSBANK_CBM_XOR_KEY: &[u8; 128] = &[
    0x35, 0x29, 0x16, 0x21, 0xa9, 0x49, 0xb1, 0x08, 0x48, 0x4d, 0x8a, 0x45, 0x42, 0x6a, 0x52, 0x2c,
    0x11, 0x52, 0x93, 0x62, 0x8b, 0x90, 0x9a, 0x14, 0x58, 0x84, 0xd4, 0xa4, 0xc5, 0x22, 0xa4, 0x26,
    0x29, 0x16, 0x21, 0x35, 0x49, 0xb1, 0x08, 0xa9, 0x4d, 0x8a, 0x45, 0x48, 0x6a, 0x52, 0x2c, 0x42,
    0x52, 0x93, 0x62, 0x11, 0x90, 0x9a, 0x14, 0x8b, 0x84, 0xd4, 0xa4, 0x58, 0x22, 0xa4, 0x26, 0xc5,
    0x16, 0x21, 0x35, 0x29, 0xb1, 0x08, 0xa9, 0x49, 0x8a, 0x45, 0x48, 0x4d, 0x52, 0x2c, 0x42, 0x6a,
    0x93, 0x62, 0x11, 0x52, 0x9a, 0x14, 0x8b, 0x90, 0xd4, 0xa4, 0x58, 0x84, 0xa4, 0x26, 0xc5, 0x22,
    0x21, 0x35, 0x29, 0x16, 0x08, 0xa9, 0x49, 0xb1, 0x45, 0x48, 0x4d, 0x8a, 0x2c, 0x42, 0x6a, 0x52,
    0x62, 0x11, 0x52, 0x93, 0x14, 0x8b, 0x90, 0x9a, 0xa4, 0x58, 0x84, 0xd4, 0x26, 0xc5, 0x22, 0xa4,
];

const ALCOR_REVERSE_ENGINEERING_SOURCE: &str =
    "https://github.com/tizbac/alcorhack/blob/master/main.cpp";
const ALCOR_UFDAPI_GEN_201310_SHA256: &str =
    crate::alcor_au698x::FLASH_DATABASE_CONVERTER_SOURCE_SHA256;
const PHISON_PRIMARY_IMPLEMENTATION_SOURCE: &str =
    "https://github.com/flowswitch/phison/blob/master/host/Phison.py";
const SMI_PRIMARY_IMPLEMENTATION_SOURCE: &str =
    "https://github.com/ValdikSS/usb-flash-read-write-counter";

#[derive(Clone, Debug, Serialize)]
pub struct ToolFinding {
    pub id: &'static str,
    pub family: &'static str,
    pub offset: u64,
    pub bytes_hex: String,
    pub representation: &'static str,
    pub classification: &'static str,
    pub meaning: &'static str,
    pub source: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolMarker {
    pub id: &'static str,
    pub family: &'static str,
    pub offset: u64,
    pub occurrences: u64,
    pub encoding: &'static str,
    pub value: &'static str,
    pub meaning: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolComponent {
    pub family: &'static str,
    pub role: &'static str,
    pub controller_id: Option<String>,
    pub evidence: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolResolvedArtifact {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolArtifactReference {
    pub declared_path: String,
    pub resolution: &'static str,
    pub candidates: Vec<ToolResolvedArtifact>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolTupleAssignment {
    pub key_suffix: Option<String>,
    pub value: String,
    pub source_line: usize,
    pub artifact: Option<ToolArtifactReference>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolNandBinding {
    pub family: &'static str,
    pub controller_id: String,
    pub nand_id: String,
    pub source_path: PathBuf,
    pub assignments: Vec<ToolTupleAssignment>,
    pub conflicting_key_suffixes: Vec<String>,
    pub selection_unambiguous: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolNandIdentity {
    pub family: &'static str,
    pub controller_id: Option<String>,
    pub database_selector: String,
    pub nand_id: String,
    pub nand_id_byte_aligned: bool,
    pub model: String,
    pub aliases: Vec<String>,
    pub parameters: Vec<ToolNamedParameter>,
    pub conflicting_parameter_names: Vec<String>,
    pub selection_unambiguous: bool,
    pub artifact_references: Vec<ToolArtifactReference>,
    pub source_path: PathBuf,
    pub source_line: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolNamedParameter {
    pub name: String,
    pub value: String,
    pub source_line: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolReadRetryRecord {
    pub family: &'static str,
    pub id: String,
    pub parameters: Vec<ToolNamedParameter>,
    pub conflicting_parameter_names: Vec<String>,
    pub selection_unambiguous: bool,
    pub source_path: PathBuf,
    pub source_line: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolFirmwareArtifact {
    pub role: &'static str,
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolFirmwareIndexRecord {
    pub family: &'static str,
    pub controller_id: Option<String>,
    pub purpose: &'static str,
    pub selector: String,
    pub declared_directory: String,
    pub version: String,
    pub source_path: PathBuf,
    pub source_line: usize,
    pub artifacts: Vec<ToolFirmwareArtifact>,
    pub missing_required_roles: Vec<&'static str>,
    pub duplicate_roles: Vec<&'static str>,
    pub selection_unambiguous: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolDecodedContent {
    pub scheme: &'static str,
    pub key_hex: String,
    pub block_bytes: usize,
    pub encrypted_block_bytes: usize,
    pub trailing_cleartext_bytes: usize,
    pub text_encoding: &'static str,
    pub decoded_size_bytes: usize,
    pub decoded_sha256: String,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolModuleMapping {
    pub family: &'static str,
    pub controller_id: String,
    pub module: String,
    pub parameters: Vec<u64>,
    pub source_path: PathBuf,
    pub source_line: usize,
    pub artifact: ToolArtifactReference,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolAlcorConverterSource {
    pub implementation: &'static str,
    pub converter: crate::alcor_au698x::FlashDatabaseConverter,
    pub source_path: PathBuf,
    pub source_sha256: String,
    pub routine_va_hex: String,
    pub selector_table_va_hex: Option<String>,
    pub recovered_contract: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolAlcorCandidateTuple {
    pub family: &'static str,
    pub controller_id: String,
    pub nand_id: String,
    pub model: String,
    pub database_selector: String,
    pub operational_record_sha256: String,
    pub runtime_module: String,
    pub auxiliary_1: Option<String>,
    pub auxiliary_2: Option<String>,
    pub operational_input: crate::alcor_au698x::FlashDatabaseOperationalInput,
    pub default_enable_25ns_required: bool,
    pub default_enable_25ns_resolution: &'static str,
    pub default_enable_25ns: Option<bool>,
    pub default_enable_25ns_source_path: Option<PathBuf>,
    pub default_enable_25ns_source_line: Option<usize>,
    pub default_enable_25ns_source_section: Option<String>,
    pub operational_fields: Option<crate::alcor_au698x::FlashDatabaseOperationalFields>,
    pub module_feature_resolution: &'static str,
    pub module_feature_error: Option<String>,
    pub module_feature_candidates: Vec<ToolModuleMapping>,
    pub parsed_module_feature: Option<crate::alcor_au698x::ModuleFeature>,
    pub controller_adjusted_module_feature: Option<crate::alcor_au698x::ModuleFeature>,
    pub selection_unambiguous: bool,
    pub flash_database_converter_resolution: &'static str,
    pub flash_database_converter_sources: Vec<ToolAlcorConverterSource>,
    pub source_path: PathBuf,
    pub source_line: usize,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolContractEvidence {
    pub role: &'static str,
    pub offset: u64,
    pub bytes_hex: String,
    pub interpretation: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolReadOnlyCommandContract {
    pub name: &'static str,
    pub cdb_hex: &'static str,
    pub cdb_length: usize,
    pub data_direction: &'static str,
    pub transfer_bytes: usize,
    pub response_layout: &'static str,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolVendorCommandContract {
    pub name: &'static str,
    pub opcode_hex: &'static str,
    pub subcommand_hex: Option<&'static str>,
    pub cdb_length: usize,
    pub data_direction: &'static str,
    pub transfer_contract: &'static str,
    pub cdb_layout: &'static str,
    pub classification: &'static str,
    pub semantic_basis: &'static str,
}

/// A bounded, reproducible host-side transport contract extracted from an
/// exact factory-tool executable. It does not assert controller support or
/// destructive-command semantics.
#[derive(Clone, Debug, Serialize)]
pub struct ToolHostTransportContract {
    pub family: &'static str,
    pub source_path: PathBuf,
    pub source_size_bytes: u64,
    pub source_sha256: String,
    pub source_format: &'static str,
    pub provenance: &'static str,
    pub transport: &'static str,
    pub ioctl_codes_hex: Vec<&'static str>,
    pub sptd_header_bytes: usize,
    pub sense_bytes: usize,
    pub outer_buffer_bytes: usize,
    pub timeout_seconds: Vec<usize>,
    pub transfer_unit_bytes: usize,
    pub retry_attempts: usize,
    pub cdb_lengths: Vec<usize>,
    pub data_directions: Vec<&'static str>,
    pub read_only_commands: Vec<ToolReadOnlyCommandContract>,
    pub vendor_commands: Vec<ToolVendorCommandContract>,
    pub evidence: Vec<ToolContractEvidence>,
    pub corroborating_source: Option<&'static str>,
    pub contract_scope: &'static str,
    pub production_eligible: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolFileAnalysis {
    pub path: PathBuf,
    pub size_bytes: u64,
    pub sha256: String,
    pub format: &'static str,
    pub findings: Vec<ToolFinding>,
    pub markers: Vec<ToolMarker>,
    pub components: Vec<ToolComponent>,
    pub decoded_content: Option<ToolDecodedContent>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ToolAnalysis {
    pub schema: u32,
    pub root: PathBuf,
    pub family_filter: Option<String>,
    pub candidate_family_scope: Vec<&'static str>,
    pub scanned_files: usize,
    pub matched_files: usize,
    pub findings: usize,
    pub markers: usize,
    pub components: usize,
    pub nand_bindings: usize,
    pub ambiguous_nand_bindings: usize,
    pub nand_identities: usize,
    pub read_retry_records: usize,
    pub firmware_index_records: usize,
    pub module_mappings: usize,
    pub alcor_candidate_tuples: usize,
    pub ambiguous_alcor_candidate_tuples: usize,
    pub host_transport_contracts: usize,
    pub unique_artifact_references: usize,
    pub identical_content_artifact_references: usize,
    pub ambiguous_artifact_references: usize,
    pub missing_artifact_references: usize,
    pub static_matches_are_candidates_only: bool,
    pub production_eligible: bool,
    pub nand_binding_records: Vec<ToolNandBinding>,
    pub nand_identity_records: Vec<ToolNandIdentity>,
    pub read_retry_record_records: Vec<ToolReadRetryRecord>,
    pub firmware_index_record_records: Vec<ToolFirmwareIndexRecord>,
    pub module_mapping_records: Vec<ToolModuleMapping>,
    pub alcor_candidate_tuple_records: Vec<ToolAlcorCandidateTuple>,
    pub host_transport_contract_records: Vec<ToolHostTransportContract>,
    pub files: Vec<ToolFileAnalysis>,
}

#[derive(Clone, Debug)]
struct RawSmiAssignment {
    controller_id: String,
    nand_id: String,
    source_path: PathBuf,
    key_suffix: Option<String>,
    value: String,
    source_line: usize,
}

#[derive(Debug)]
struct AnalyzedFile {
    report: ToolFileAnalysis,
    smi_assignments: Vec<RawSmiAssignment>,
    nand_identities: Vec<ToolNandIdentity>,
    read_retry_records: Vec<ToolReadRetryRecord>,
    firmware_indices: Vec<RawFirmwareIndex>,
    module_mappings: Vec<RawAlcorModuleMapping>,
    alcor_selections: Vec<RawAlcorSelection>,
    alcor_default_enable_25ns: Option<RawAlcorSetting>,
    host_transport_contracts: Vec<ToolHostTransportContract>,
}

#[derive(Clone, Debug)]
struct RawAlcorModuleMapping {
    controller_id: String,
    module: String,
    parameters: Vec<u64>,
    source_path: PathBuf,
    source_line: usize,
}

#[derive(Clone, Debug)]
struct RawAlcorSelection {
    controller_id: String,
    nand_id: String,
    model: String,
    database_selector: String,
    operational_record_sha256: String,
    operational_input: crate::alcor_au698x::FlashDatabaseOperationalInput,
    legacy_operational_fields_25ns_disabled: crate::alcor_au698x::FlashDatabaseOperationalFields,
    ufdapi_operational_fields_25ns_disabled: crate::alcor_au698x::FlashDatabaseOperationalFields,
    object_14_25ns_enabled: u8,
    runtime_module: String,
    auxiliary_1: Option<String>,
    auxiliary_2: Option<String>,
    source_path: PathBuf,
    source_line: usize,
}

#[derive(Clone, Debug)]
struct RawAlcorSetting {
    value: bool,
    source_section: String,
    source_path: PathBuf,
    source_line: usize,
}

#[derive(Clone, Debug)]
struct RawFirmwareIndex {
    family: &'static str,
    controller_id: Option<String>,
    purpose: &'static str,
    selector: String,
    declared_directory: String,
    version: String,
    source_path: PathBuf,
    source_line: usize,
}

struct Pattern {
    id: &'static str,
    family: Family,
    bytes: &'static [u8],
    mask: &'static [u8],
    classification: &'static str,
    meaning: &'static str,
    source: &'static str,
}

struct MarkerPattern {
    id: &'static str,
    family: Option<Family>,
    value: &'static str,
    meaning: &'static str,
}

const EXACT_8: &[u8] = &[0xff; 8];
const EXACT_10: &[u8] = &[0xff; 10];
const EXACT_12: &[u8] = &[0xff; 12];
const EXACT_16: &[u8] = &[0xff; 16];
const SANDISK_X86_CONSTRUCTOR_MASK: &[u8] = &[
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00, 0xff, 0xff,
];
const SANDISK_U3_SOURCE: &str = "https://sources.debian.org/src/u3-tool/0.3-4/src/u3_commands.c/";
const SANDISK_OFFICIAL_TOOL_SOURCE: &str = "https://web.archive.org/web/20110616074940id_/http://u3.sandisk.com/download/apps/LPInstaller.exe";

const PATTERNS: &[Pattern] = &[
    Pattern {
        id: "phison-version-page",
        family: Family::PhisonUfd,
        bytes: &[0x06, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_16,
        classification: "read-only",
        meaning: "PS2251 version page; response still requires the VR signature parser",
        source: "https://github.com/flowswitch/phison/blob/master/host/Phison.py",
    },
    Pattern {
        id: "phison-nand-id",
        family: Family::PhisonUfd,
        bytes: &[0x06, 0x56, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_16,
        classification: "read-only",
        meaning: "PS2251 NAND ID read",
        source: "https://github.com/brandonlw/Psychson/blob/master/DriveCom/DriveCom/PhisonDevice.cs",
    },
    Pattern {
        id: "phison-enter-bootrom",
        family: Family::PhisonUfd,
        bytes: &[0x06, 0xbf, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_16,
        classification: "state-changing",
        meaning: "enter BootROM; may re-enumerate and must never be treated as an identity read",
        source: "https://github.com/flowswitch/phison/blob/master/host/Phison.py",
    },
    Pattern {
        id: "phison-run-pram",
        family: Family::PhisonUfd,
        bytes: &[0x06, 0xb3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_16,
        classification: "state-changing",
        meaning: "execute transferred PRAM code",
        source: "https://github.com/flowswitch/phison/blob/master/host/Phison.py",
    },
    Pattern {
        id: "phison-loader-header",
        family: Family::PhisonUfd,
        bytes: &[0x06, 0xb1, 0x03, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_16,
        classification: "state-changing",
        meaning: "transfer the 512-byte BtPramCd loader header",
        source: "https://github.com/brandonlw/Psychson/blob/master/DriveCom/DriveCom/PhisonDevice.cs",
    },
    Pattern {
        id: "phison-loader-status",
        family: Family::PhisonUfd,
        bytes: &[0x06, 0xb0, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_16,
        classification: "read-only-mode-dependent",
        meaning: "loader-transfer acknowledgement read; valid only in the documented transfer state",
        source: "https://github.com/flowswitch/phison/blob/master/host/Phison.py",
    },
    Pattern {
        id: "phison-burner-nand-read",
        family: Family::PhisonUfd,
        bytes: &[0x06, 0x03, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: &[
            0xff, 0xff, 0, 0, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
        classification: "read-only-mode-dependent",
        meaning: "burner-mode NAND/FW-area read skeleton; not a general raw-NAND geometry contract",
        source: "https://github.com/flowswitch/phison/blob/master/host/Phison.py",
    },
    Pattern {
        id: "alcor-config-read",
        family: Family::AlcorUfd,
        bytes: &[0x82, 0x51, 0x01, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_10,
        classification: "read-only",
        meaning: "AU698x configuration page; response requires the 99 07 signature",
        source: "https://github.com/tizbac/alcorhack/blob/master/main.cpp",
    },
    Pattern {
        id: "alcor-flash-id",
        family: Family::AlcorUfd,
        bytes: &[0xfa, 0x00, 0, 0, 0, 0, 0, 0],
        mask: EXACT_8,
        classification: "read-only",
        meaning: "Alcor flash ID read",
        source: "https://github.com/tizbac/alcorhack/blob/master/main.cpp",
    },
    Pattern {
        id: "alcor-service-code-a",
        family: Family::AlcorUfd,
        bytes: &[0xfa, 0x0a, 0, 0x10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_16,
        classification: "state-changing",
        meaning: "upload service code A",
        source: "https://github.com/tizbac/alcorhack/blob/master/main.cpp",
    },
    Pattern {
        id: "alcor-service-code-b",
        family: Family::AlcorUfd,
        bytes: &[0xfa, 0x0b, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_16,
        classification: "state-changing",
        meaning: "upload service code B",
        source: "https://github.com/tizbac/alcorhack/blob/master/main.cpp",
    },
    Pattern {
        id: "alcor-service-read",
        family: Family::AlcorUfd,
        bytes: &[0xfa, 0x0b, 0x20, 0, 0, 0, 0, 1, 4, 0, 0, 0, 0, 0, 2, 1],
        mask: &[
            0xff, 0xff, 0xff, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ],
        classification: "read-only-mode-dependent",
        meaning: "service-code 512-byte read with variable address bytes",
        source: "https://github.com/tizbac/alcorhack/blob/master/main.cpp",
    },
    Pattern {
        id: "alcor-rebuild-config-write",
        family: Family::AlcorUfd,
        bytes: &[0x81, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_16,
        classification: "state-changing",
        meaning: "configuration/rebuild write; it is not evidence of physical NAND erase",
        source: "https://github.com/tizbac/alcorhack/blob/master/main.cpp",
    },
    Pattern {
        id: "smi-sm32x-identity-page",
        family: Family::SiliconMotionUfd,
        bytes: &[0xf0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02],
        mask: EXACT_12,
        classification: "read-only",
        meaning: "SM32X controller identity page; it is not NAND identity",
        source: "https://github.com/ValdikSS/usb-flash-read-write-counter",
    },
    Pattern {
        id: "sandisk-u3-property-read",
        family: Family::SandiskCruzer,
        bytes: &[0xff, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_12,
        classification: "read-only-logical",
        meaning: "U3 logical property read template; property 0x03 describes logical device size, not NAND geometry",
        source: SANDISK_U3_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-chip-info",
        family: Family::SandiskCruzer,
        bytes: &[0xff, 0x03, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_12,
        classification: "read-only-logical",
        meaning: "U3 controller manufacturer/revision property; not NAND identity",
        source: SANDISK_U3_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-domain-round",
        family: Family::SandiskCruzer,
        bytes: &[0xff, 0x20, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_12,
        classification: "read-only-logical",
        meaning: "U3 logical-domain sector rounding; not raw NAND page/block geometry",
        source: SANDISK_U3_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-domain-info",
        family: Family::SandiskCruzer,
        bytes: &[0xff, 0x21, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_12,
        classification: "read-only-logical",
        meaning: "U3 logical partition information; not BBT or FTL metadata",
        source: SANDISK_U3_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-set-domains",
        family: Family::SandiskCruzer,
        bytes: &[0xff, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: &[0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        classification: "state-changing-logical",
        meaning: "U3 logical-domain reconfiguration; not physical NAND erase",
        source: SANDISK_U3_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-cd-write",
        family: Family::SandiskCruzer,
        bytes: &[0xff, 0x42, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0x01],
        mask: EXACT_12,
        classification: "state-changing-logical",
        meaning: "U3 2048-byte CD-domain block write; not raw NAND page/OOB programming",
        source: SANDISK_U3_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-data-partition-info",
        family: Family::SandiskCruzer,
        bytes: &[0xff, 0xa0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_12,
        classification: "read-only-logical",
        meaning: "U3 logical data-partition information; not raw NAND or FTL metadata",
        source: SANDISK_U3_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-enable-security",
        family: Family::SandiskCruzer,
        bytes: &[0xff, 0xa2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_12,
        classification: "state-changing-logical-security",
        meaning: "U3 logical data-partition security operation; not physical erase",
        source: SANDISK_U3_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-security-round",
        family: Family::SandiskCruzer,
        bytes: &[0xff, 0xa3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_12,
        classification: "read-only-logical",
        meaning: "U3 secure-zone size rounding; not raw NAND page/block geometry",
        source: SANDISK_U3_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-unlock",
        family: Family::SandiskCruzer,
        bytes: &[0xff, 0xa4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_12,
        classification: "state-changing-logical-security",
        meaning: "U3 logical data-partition unlock; not physical erase",
        source: SANDISK_U3_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-change-password",
        family: Family::SandiskCruzer,
        bytes: &[0xff, 0xa6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_12,
        classification: "state-changing-logical-security",
        meaning: "U3 logical data-partition password change; not physical erase",
        source: SANDISK_U3_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-disable-security",
        family: Family::SandiskCruzer,
        bytes: &[0xff, 0xa7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_12,
        classification: "state-changing-logical-security",
        meaning: "U3 logical data-partition security disable; not physical erase",
        source: SANDISK_U3_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-reset",
        family: Family::SandiskCruzer,
        bytes: &[0xff, 0x01, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        mask: EXACT_12,
        classification: "state-changing-logical",
        meaning: "U3 controller reset/reconnect; not an erase or metadata commit",
        source: SANDISK_U3_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-x86-domain-round",
        family: Family::SandiskCruzer,
        bytes: &[0x6a, 0x00, 0x68, 0xff, 0, 0, 0, 0x6a, 0, 0x6a, 0x20],
        mask: SANDISK_X86_CONSTRUCTOR_MASK,
        classification: "read-only-logical-constructor",
        meaning: "x86 constructor for U3 logical-domain size rounding; not raw NAND geometry",
        source: SANDISK_OFFICIAL_TOOL_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-x86-domain-info",
        family: Family::SandiskCruzer,
        bytes: &[0x6a, 0x00, 0x68, 0xff, 0, 0, 0, 0x6a, 0, 0x6a, 0x21],
        mask: SANDISK_X86_CONSTRUCTOR_MASK,
        classification: "read-only-logical-constructor",
        meaning: "x86 constructor for U3 logical-domain information; not FTL metadata",
        source: SANDISK_OFFICIAL_TOOL_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-x86-set-domains",
        family: Family::SandiskCruzer,
        bytes: &[0x6a, 0x00, 0x68, 0xff, 0, 0, 0, 0x6a, 0, 0x6a, 0x22],
        mask: SANDISK_X86_CONSTRUCTOR_MASK,
        classification: "state-changing-logical-constructor",
        meaning: "x86 constructor for U3 logical-domain reconfiguration; not physical erase",
        source: SANDISK_OFFICIAL_TOOL_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-x86-private-config-23",
        family: Family::SandiskCruzer,
        bytes: &[0x6a, 0x00, 0x68, 0xff, 0, 0, 0, 0x6a, 0, 0x6a, 0x23],
        mask: SANDISK_X86_CONSTRUCTOR_MASK,
        classification: "private-logical-constructor",
        meaning: "x86 constructor for private U3 configuration command 0x23; no raw NAND semantics established",
        source: SANDISK_OFFICIAL_TOOL_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-x86-private-config-24",
        family: Family::SandiskCruzer,
        bytes: &[0x6a, 0x00, 0x68, 0xff, 0, 0, 0, 0x6a, 0, 0x6a, 0x24],
        mask: SANDISK_X86_CONSTRUCTOR_MASK,
        classification: "private-logical-constructor",
        meaning: "x86 constructor for private U3 configuration command 0x24; no raw NAND semantics established",
        source: SANDISK_OFFICIAL_TOOL_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-x86-private-config-25",
        family: Family::SandiskCruzer,
        bytes: &[0x6a, 0x00, 0x68, 0xff, 0, 0, 0, 0x6a, 0, 0x6a, 0x25],
        mask: SANDISK_X86_CONSTRUCTOR_MASK,
        classification: "private-logical-constructor",
        meaning: "x86 constructor for private U3 configuration command 0x25; no raw NAND semantics established",
        source: SANDISK_OFFICIAL_TOOL_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-x86-cd-info",
        family: Family::SandiskCruzer,
        bytes: &[0x6a, 0x00, 0x68, 0xff, 0, 0, 0, 0x6a, 0, 0x6a, 0x40],
        mask: SANDISK_X86_CONSTRUCTOR_MASK,
        classification: "read-only-logical-constructor",
        meaning: "x86 constructor for U3 CD-domain information; not NAND page/OOB access",
        source: SANDISK_OFFICIAL_TOOL_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-x86-cd-operation",
        family: Family::SandiskCruzer,
        bytes: &[0x6a, 0x00, 0x68, 0xff, 0, 0, 0, 0x6a, 0, 0x6a, 0x41],
        mask: SANDISK_X86_CONSTRUCTOR_MASK,
        classification: "logical-cd-constructor",
        meaning: "x86 constructor for U3 CD-domain command 0x41; not NAND page/OOB access",
        source: SANDISK_OFFICIAL_TOOL_SOURCE,
    },
    Pattern {
        id: "sandisk-u3-x86-cd-write",
        family: Family::SandiskCruzer,
        bytes: &[0x6a, 0x00, 0x68, 0xff, 0, 0, 0, 0x6a, 0, 0x6a, 0x42],
        mask: SANDISK_X86_CONSTRUCTOR_MASK,
        classification: "state-changing-logical-constructor",
        meaning: "x86 constructor for 2048-byte U3 CD-domain writes; not raw NAND programming",
        source: SANDISK_OFFICIAL_TOOL_SOURCE,
    },
];

const MARKERS: &[MarkerPattern] = &[
    MarkerPattern {
        id: "phison-bt-pram-image",
        family: Some(Family::PhisonUfd),
        value: "BtPramCd",
        meaning: "Phison PRAM/firmware image marker; the header still requires semantic validation",
    },
    MarkerPattern {
        id: "smi-3257-controller-line",
        family: Some(Family::SiliconMotionUfd),
        value: "SM3257ENAA",
        meaning: "SM3257ENAA controller-specific component marker",
    },
    MarkerPattern {
        id: "smi-3281-controller-line",
        family: Some(Family::SiliconMotionUfd),
        value: "SM3281BB",
        meaning: "SM3281BB controller-specific component marker",
    },
    MarkerPattern {
        id: "sandisk-u3-musk-sdk",
        family: Some(Family::SandiskCruzer),
        value: "MUSK SDK",
        meaning: "SanDisk/U3 logical-device SDK provenance marker",
    },
    MarkerPattern {
        id: "sandisk-u3-scsi-command-source",
        family: Some(Family::SandiskCruzer),
        value: "SCSICommands.cpp",
        meaning: "embedded SCSI command implementation source path",
    },
    MarkerPattern {
        id: "sandisk-u3-config-command-source",
        family: Some(Family::SandiskCruzer),
        value: "U3CfgCommands.cpp",
        meaning: "embedded U3 logical-domain configuration source path",
    },
    MarkerPattern {
        id: "sandisk-u3-cd-command-source",
        family: Some(Family::SandiskCruzer),
        value: "U3CDCommands.cpp",
        meaning: "embedded U3 logical CD-domain command source path",
    },
    MarkerPattern {
        id: "sandisk-u3-set-domains-method",
        family: Some(Family::SandiskCruzer),
        value: "CConfigServiceImpl::setDomains",
        meaning: "logical domain reconfiguration implementation; not raw NAND purge",
    },
    MarkerPattern {
        id: "family-phison",
        family: Some(Family::PhisonUfd),
        value: "PS2251",
        meaning: "Phison controller-line inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-alcor",
        family: Some(Family::AlcorUfd),
        value: "AU698",
        meaning: "Alcor controller-line inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-silicon-motion",
        family: Some(Family::SiliconMotionUfd),
        value: "SM32",
        meaning: "Silicon Motion controller-line inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-sandisk-cruzer",
        family: Some(Family::SandiskCruzer),
        value: "Cruzer",
        meaning: "SanDisk product-family inventory marker; not controller silicon identity",
    },
    MarkerPattern {
        id: "family-usbest",
        family: Some(Family::UsbestUfd),
        value: "UT163",
        meaning: "USBest controller-line inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-chipsbank",
        family: Some(Family::ChipsbankUfd),
        value: "CBM21",
        meaning: "ChipsBank controller-line inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-innostor",
        family: Some(Family::InnostorUfd),
        value: "IS917",
        meaning: "Innostor controller-line inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-firstchip",
        family: Some(Family::FirstchipUfd),
        value: "FirstChip",
        meaning: "FirstChip package inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-solid-state-system",
        family: Some(Family::SolidStateSystemUfd),
        value: "SSS66",
        meaning:
            "Solid State System controller-line inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-skymedi",
        family: Some(Family::SkymediUfd),
        value: "SK62",
        meaning: "Skymedi controller-line inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-appotech",
        family: Some(Family::AppotechUfd),
        value: "DM82",
        meaning: "AppoTech controller-line inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-silicongo",
        family: Some(Family::SilicongoUfd),
        value: "SG158",
        meaning: "SiliconGo controller-line inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-icreate",
        family: Some(Family::IcreateUfd),
        value: "iCreate",
        meaning: "iCreate package inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-oti",
        family: Some(Family::OtiUfd),
        value: "OTi",
        meaning: "OTi package inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-prolific",
        family: Some(Family::ProlificUfd),
        value: "Prolific",
        meaning: "Prolific package inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-ameco",
        family: Some(Family::AmecoUfd),
        value: "MXT",
        meaning: "Ameco/MXTronics controller-line inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-netac",
        family: Some(Family::NetacUfd),
        value: "Netac",
        meaning: "Netac package inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-efortune",
        family: Some(Family::EfortuneUfd),
        value: "eFortune",
        meaning: "eFortune package inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-ite",
        family: Some(Family::IteUfd),
        value: "IT11",
        meaning: "ITE controller-line inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-hyperstone",
        family: Some(Family::HyperstoneUfd),
        value: "Hyperstone",
        meaning: "Hyperstone package inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-yeestor",
        family: Some(Family::YeestorUfd),
        value: "Yeestor",
        meaning: "Yeestor package inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-ramos",
        family: Some(Family::RamosUfd),
        value: "Ramos",
        meaning: "Ramos package inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-trek2000",
        family: Some(Family::Trek2000Ufd),
        value: "Trek 2000",
        meaning: "Trek 2000 package inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-moai",
        family: Some(Family::MoaiUfd),
        value: "Moai",
        meaning: "Moai package inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-realway",
        family: Some(Family::RealwayUfd),
        value: "Real-Way",
        meaning: "Real-Way package inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-huayi",
        family: Some(Family::HuayiUfd),
        value: "HuaYi",
        meaning: "HuaYi package inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-ktc",
        family: Some(Family::KtcUfd),
        value: "FC1325",
        meaning: "KTC controller-line inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "family-smsc",
        family: Some(Family::SmscUfd),
        value: "USB97C242",
        meaning: "SMSC controller-line inventory marker; not a protocol or tuple match",
    },
    MarkerPattern {
        id: "research-flash-id",
        family: None,
        value: "Flash ID",
        meaning: "cross-family research marker; locate the surrounding identity parser and trace",
    },
    MarkerPattern {
        id: "research-nand-id",
        family: None,
        value: "NAND ID",
        meaning: "cross-family research marker; locate the surrounding identity parser and trace",
    },
    MarkerPattern {
        id: "research-bad-block",
        family: None,
        value: "Bad Block",
        meaning: "cross-family research marker; does not define a BBT format",
    },
    MarkerPattern {
        id: "research-bbt",
        family: None,
        value: "BBT",
        meaning: "cross-family research marker; does not define a BBT format",
    },
    MarkerPattern {
        id: "research-low-level-format",
        family: None,
        value: "Low Level Format",
        meaning: "cross-family research marker; factory terminology is not physical-coverage proof",
    },
    MarkerPattern {
        id: "research-preformat",
        family: None,
        value: "Preformat",
        meaning: "cross-family research marker; locate the selected runtime payload and trace",
    },
    MarkerPattern {
        id: "research-isp",
        family: None,
        value: "ISP",
        meaning: "cross-family research marker; locate the selected firmware artifact and trace",
    },
    MarkerPattern {
        id: "research-loader",
        family: None,
        value: "Loader",
        meaning: "cross-family research marker; locate the selected volatile loader and trace",
    },
    MarkerPattern {
        id: "research-firmware",
        family: None,
        value: "Firmware",
        meaning: "cross-family research marker; locate version binding and artifact selection",
    },
    MarkerPattern {
        id: "research-ecc",
        family: None,
        value: "ECC",
        meaning: "cross-family research marker; locate strength, coverage and parity layout",
    },
    MarkerPattern {
        id: "research-read-retry",
        family: None,
        value: "Read Retry",
        meaning: "cross-family research marker; locate exact NAND-specific retry tables",
    },
    MarkerPattern {
        id: "research-randomizer",
        family: None,
        value: "Randomizer",
        meaning: "cross-family research marker; locate seed and coverage semantics",
    },
    MarkerPattern {
        id: "research-page-size",
        family: None,
        value: "Page Size",
        meaning: "cross-family research marker; locate page and OOB geometry binding",
    },
    MarkerPattern {
        id: "research-spare",
        family: None,
        value: "Spare",
        meaning: "cross-family research marker; distinguish OOB from reserve-block policy",
    },
    MarkerPattern {
        id: "research-oob",
        family: None,
        value: "OOB",
        meaning: "cross-family research marker; locate exact OOB and ECC layout",
    },
    MarkerPattern {
        id: "research-burner",
        family: None,
        value: "Burner",
        meaning: "cross-family research marker; locate volatile service code and transition trace",
    },
];

fn pattern_matches(bytes: &[u8], pattern: &Pattern) -> bool {
    bytes
        .iter()
        .zip(pattern.bytes)
        .zip(pattern.mask)
        .all(|((actual, expected), mask)| actual & mask == expected & mask)
}

fn binary_representation_allowed(pattern: &Pattern) -> bool {
    // The Debian U3 definitions are command arrays reconstructed from C
    // source. Searching their zero-heavy 12-byte values as arbitrary PE data
    // produces padding false positives; the official binary constructs these
    // CDBs dynamically and has separate x86 patterns.
    pattern.source != SANDISK_U3_SOURCE
}

fn source_literal_representation_allowed(pattern: &Pattern) -> bool {
    // The archived SanDisk patterns are x86 instruction sequences, not CDB
    // literals. Treating source arrays as machine code would invert their
    // provenance and manufacture misleading constructor findings.
    pattern.source != SANDISK_OFFICIAL_TOOL_SOURCE
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn parse_hex_byte(high: u8, low: u8) -> Option<u8> {
    Some(hex_nibble(high)? << 4 | hex_nibble(low)?)
}

/// Extract contiguous C/C++ `0xNN, ...` and escaped `\xNN...` byte runs.
/// This recognizes source literals only; it does not evaluate expressions.
fn source_literal_runs(bytes: &[u8]) -> Vec<(Vec<usize>, Vec<u8>)> {
    let mut runs = Vec::new();
    let mut index = 0usize;
    while index + 3 < bytes.len() {
        let c_literal = bytes[index] == b'0'
            && matches!(bytes[index + 1], b'x' | b'X')
            && parse_hex_byte(bytes[index + 2], bytes[index + 3]).is_some();
        let escaped = bytes[index] == b'\\'
            && bytes[index + 1] == b'x'
            && parse_hex_byte(bytes[index + 2], bytes[index + 3]).is_some();
        if !c_literal && !escaped {
            index += 1;
            continue;
        }
        let mut offsets = Vec::new();
        let mut values = Vec::new();
        let mut cursor = index;
        loop {
            let prefix = cursor + 3 < bytes.len()
                && ((c_literal
                    && bytes[cursor] == b'0'
                    && matches!(bytes[cursor + 1], b'x' | b'X'))
                    || (escaped && bytes[cursor] == b'\\' && bytes[cursor + 1] == b'x'));
            if !prefix {
                break;
            }
            let Some(value) = parse_hex_byte(bytes[cursor + 2], bytes[cursor + 3]) else {
                break;
            };
            offsets.push(cursor);
            values.push(value);
            cursor += 4;
            if escaped {
                continue;
            }
            while cursor < bytes.len()
                && (bytes[cursor].is_ascii_whitespace() || bytes[cursor] == b',')
            {
                cursor += 1;
            }
        }
        if values.len() >= 8 {
            runs.push((offsets, values));
        }
        index = cursor.max(index + 1);
    }
    runs
}

fn marker_bytes(value: &str, utf16le: bool) -> Vec<u8> {
    if utf16le {
        value
            .encode_utf16()
            .flat_map(u16::to_le_bytes)
            .collect::<Vec<_>>()
    } else {
        value.as_bytes().to_vec()
    }
}

fn marker_offsets(haystack: &[u8], needle: &[u8]) -> Vec<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return Vec::new();
    }
    (0..=haystack.len() - needle.len())
        .filter(|offset| haystack[*offset..].starts_with(needle))
        .collect()
}

fn format_name(head: &[u8]) -> &'static str {
    if head.starts_with(b"MZ") {
        "portable-executable"
    } else if head.starts_with(b"PK\x03\x04") {
        "zip"
    } else if head.starts_with(b"Rar!\x1a\x07") {
        "rar"
    } else if head.starts_with(b"7z\xbc\xaf\x27\x1c") {
        "7z"
    } else if head.starts_with(b"BtPramCd") {
        "phison-bt-pram"
    } else {
        "opaque"
    }
}

fn family_enabled(filter: Option<Family>, family: Family) -> bool {
    filter.is_none_or(|selected| selected == family)
}

fn lower_path_components(path: &Path) -> Vec<String> {
    path.components()
        .map(|component| component.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect()
}

fn has_component(components: &[String], expected: &str) -> bool {
    components.iter().any(|component| component == expected)
}

fn smi_controller_id(value: &str) -> Option<String> {
    let uppercase = value.to_ascii_uppercase();
    let body = uppercase.strip_prefix("SM").unwrap_or(&uppercase);
    if body.len() < 4
        || !body.as_bytes()[..4].iter().all(u8::is_ascii_digit)
        || !body
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
    {
        return None;
    }
    Some(format!("smi-sm{}", body.to_ascii_lowercase()))
}

fn smi_controller_from_filename(path: &Path) -> Option<String> {
    let stem = path.file_stem()?.to_str()?;
    let raw = stem
        .strip_prefix("flash_")
        .or_else(|| stem.strip_prefix("FLASH_"))
        .unwrap_or(stem);
    if raw.len() > 16 {
        return None;
    }
    smi_controller_id(raw)
}

fn smi_controller_from_text(value: &str) -> Option<String> {
    let uppercase = value.to_ascii_uppercase();
    for (offset, _) in uppercase.match_indices("SM") {
        let candidate = uppercase[offset..]
            .chars()
            .take_while(|character| character.is_ascii_alphanumeric())
            .collect::<String>();
        if candidate.len() <= 16 {
            if let Some(controller) = smi_controller_id(&candidate) {
                return Some(controller);
            }
        }
    }
    None
}

fn alcor_controller_scope(components: &[String]) -> Option<String> {
    for index in 0..components.len().saturating_sub(1) {
        if components[index] != "ctl" {
            continue;
        }
        let identifier = components.get(index + 1)?;
        if identifier.len() != 2 || !identifier.as_bytes().iter().all(u8::is_ascii_hexdigit) {
            return None;
        }
        return Some(format!("alcor-ctl-{identifier}"));
    }
    None
}

fn chipsbank_controller_scope(components: &[String]) -> Option<String> {
    let index = components
        .iter()
        .position(|component| component == "firmware")?;
    let identifier = components.get(index + 1)?;
    if identifier.is_empty()
        || identifier.len() > 16
        || !identifier
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'_')
    {
        return None;
    }
    Some(format!("chipsbank-cbm{identifier}"))
}

fn component_inventory(path: &Path, family: Option<Family>) -> Vec<ToolComponent> {
    let components = lower_path_components(path);
    let filename = components.last().map(String::as_str).unwrap_or_default();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    let mut result = Vec::new();

    if family_enabled(family, Family::SiliconMotionUfd) {
        let force_map = has_component(&components, "ufd_all_forcefw") && extension == "ffw";
        let controller_database = has_component(&components, "ufd_all_dbf")
            && extension == "dbf"
            && filename.starts_with("flash_");
        let known_smi_tree = force_map
            || controller_database
            || has_component(&components, "rtytab")
            || has_component(&components, "dlllib")
            || components
                .iter()
                .any(|component| component.starts_with("ufd_all_"));
        let inferred_controller =
            smi_controller_from_filename(path).or_else(|| smi_controller_from_text(filename));
        let role = if force_map {
            Some((
                "force-firmware-map",
                "exact UFD_ALL_ForceFW path and FFW extension",
            ))
        } else if controller_database {
            Some((
                "controller-nand-database",
                "exact UFD_ALL_DBF path and flash_<controller>.dbf filename",
            ))
        } else if has_component(&components, "rtytab") && extension == "bin" {
            Some(("read-retry-table", "RTYTAB package path and BIN extension"))
        } else if has_component(&components, "dlllib")
            && extension == "dll"
            && filename.starts_with("pretest")
        {
            Some(("pretest-module", "DLLLIB path and Pretest DLL filename"))
        } else if has_component(&components, "dlllib")
            && extension == "dll"
            && filename.starts_with("script")
        {
            Some((
                "low-level-script-module",
                "DLLLIB path and Script DLL filename",
            ))
        } else if has_component(&components, "dlllib") && filename == "ufdif.dll" {
            Some((
                "host-transport-library",
                "exact SMI UFDIF DLL filename under DLLLIB",
            ))
        } else if extension == "exe" && filename.starts_with("sm32xtest") {
            Some(("factory-tool-host", "SMI sm32Xtest executable filename"))
        } else if known_smi_tree && extension == "ebi" {
            Some(("nand-script", "SMI package path and EBI extension"))
        } else if known_smi_tree && extension == "bin" && filename.contains("ptest") {
            Some(("pretest-loader", "SMI package path and PTEST filename"))
        } else if known_smi_tree && extension == "bin" && filename.contains("sortingcmd") {
            Some((
                "sorting-command",
                "SMI package path and SortingCmd filename",
            ))
        } else if known_smi_tree && extension == "bin" && filename.contains("geninfocmd") {
            Some((
                "generic-info-command",
                "SMI package path and GenInfoCmd filename",
            ))
        } else if known_smi_tree
            && extension == "bin"
            && (filename.contains("ispboot0") || filename.contains("bootcode"))
        {
            Some(("boot-code", "SMI package path and boot-code filename"))
        } else if known_smi_tree && extension == "bin" && filename.contains("isp") {
            Some(("service-isp", "SMI package path and ISP filename"))
        } else {
            None
        };
        if let Some((role, evidence)) = role {
            result.push(ToolComponent {
                family: Family::SiliconMotionUfd.as_str(),
                role,
                controller_id: inferred_controller,
                evidence,
            });
        }
    }

    if family_enabled(family, Family::PhisonUfd) && filename == "getinfo.exe" && extension == "exe"
    {
        result.push(ToolComponent {
            family: Family::PhisonUfd.as_str(),
            role: "read-only-identity-tool",
            controller_id: None,
            evidence: "exact Phison GetInfo executable filename",
        });
    }

    if family_enabled(family, Family::AlcorUfd) {
        let controller_id = alcor_controller_scope(&components);
        let role = if filename == "ufdcomlib.dll" {
            Some((
                "host-transport-library",
                "exact Alcor UfdComLib DLL filename",
            ))
        } else if filename == "ufdapi_gen.dll" {
            Some((
                "controller-operation-library",
                "exact Alcor UfdApi_Gen DLL filename",
            ))
        } else if controller_id.is_none() && filename == "alcormp.ini" {
            Some((
                "factory-tool-settings",
                "exact top-level AlcorMP.ini package filename",
            ))
        } else if controller_id.is_some()
            && has_component(&components, "ufdcom")
            && extension == "bin"
            && filename.ends_with("_gen.bin")
        {
            Some((
                "controller-gen-code",
                "UfdCom/CTL/<generation>/<generation>_GEN.BIN package path",
            ))
        } else if controller_id.is_some()
            && has_component(&components, "dgd_bin")
            && extension == "bin"
        {
            Some((
                "die-grade-module",
                "UfdApi_Gen/CTL/<generation>/DGD_BIN package path",
            ))
        } else if controller_id.is_some()
            && has_component(&components, "scan_bin")
            && extension == "bin"
        {
            Some((
                "scan-sort-module",
                "UfdApi_Gen/CTL/<generation>/SCAN_BIN package path",
            ))
        } else if controller_id.is_some()
            && has_component(&components, "sort_bin")
            && extension == "bin"
        {
            Some((
                "sorting-module",
                "UfdApi_Gen/CTL/<generation>/SORT_BIN package path",
            ))
        } else if controller_id.is_some() && has_component(&components, "bin") && extension == "bin"
        {
            Some((
                "nand-operation-module",
                "UfdApi_Gen/CTL/<generation>/BIN package path",
            ))
        } else if controller_id.is_some() && filename == "flashlist.ini" {
            Some((
                "nand-module-map",
                "CTL/<generation>/FlashList.ini package path",
            ))
        } else if controller_id.is_none() && filename == "flashlist.ini" {
            Some((
                "nand-id-database",
                "top-level FlashList.ini exact FID database filename",
            ))
        } else if controller_id.is_none() && filename == "flashlist.afl" {
            Some((
                "encrypted-nand-database",
                "top-level Alcor encrypted FlashList database filename",
            ))
        } else if controller_id.is_none() && filename == "flashlist.dat" {
            Some((
                "opaque-nand-database",
                "top-level Alcor FlashList database filename",
            ))
        } else {
            None
        };
        if let Some((role, evidence)) = role {
            result.push(ToolComponent {
                family: Family::AlcorUfd.as_str(),
                role,
                controller_id,
                evidence,
            });
        }
    }

    if family_enabled(family, Family::FirstchipUfd) {
        let controller_id = components
            .windows(2)
            .find(|window| window[0] == "code")
            .map(|window| format!("firstchip-{}", window[1]));
        let role = if has_component(&components, "config") && filename == "flash.bin" {
            Some((
                "encrypted-nand-database",
                "exact FirstChip config/Flash.bin package path",
            ))
        } else if has_component(&components, "config") && filename == "readretry.bin" {
            Some((
                "encrypted-read-retry-database",
                "exact FirstChip config/ReadRetry.bin package path",
            ))
        } else if matches!(filename, "fcmptools.exe" | "fcmptools_32.exe") {
            Some((
                "factory-tool-host",
                "exact FirstChip FCMpTools executable filename",
            ))
        } else if filename == "entryappite.dll" {
            Some((
                "host-transport-library",
                "exact FirstChip EntryAppIte DLL filename",
            ))
        } else if filename == "nandparse.dll" {
            Some((
                "nand-database-parser",
                "exact FirstChip NandParse DLL filename",
            ))
        } else if controller_id.is_some() && filename.starts_with("extcode") {
            Some((
                "controller-extension-code",
                "code/<controller> path and extcode filename",
            ))
        } else if controller_id.is_some() && filename.starts_with("extmp") {
            Some((
                "manufacturing-loader",
                "code/<controller> path and extmp filename",
            ))
        } else if controller_id.is_some() && filename.starts_with("extscan") {
            Some(("scan-loader", "code/<controller> path and extscan filename"))
        } else if controller_id.is_some() && filename.contains("seed") {
            Some((
                "controller-seed-data",
                "code/<controller> path and seed filename",
            ))
        } else {
            None
        };
        if let Some((role, evidence)) = role {
            result.push(ToolComponent {
                family: Family::FirstchipUfd.as_str(),
                role,
                controller_id,
                evidence,
            });
        }
    }

    if family_enabled(family, Family::ChipsbankUfd) {
        let controller_id = chipsbank_controller_scope(&components);
        let role = if filename == "aptoolv6a.exe" {
            Some((
                "factory-tool-host",
                "exact ChipsBank APToolV6A executable filename",
            ))
        } else if filename == "apdevicemp.dll" {
            Some((
                "controller-operation-library",
                "exact ChipsBank APDeviceMP DLL filename",
            ))
        } else if filename.starts_with("cbmusbdrv") && extension == "dll" {
            Some(("host-transport-library", "ChipsBank CBMUsbDrv DLL filename"))
        } else if has_component(&components, "flash") && filename == "flash.cbm" {
            Some((
                "encoded-nand-database",
                "exact ChipsBank flash/flash.cbm package path",
            ))
        } else if has_component(&components, "libin") && filename == "umptool.ini" {
            Some((
                "controller-manifest",
                "exact ChipsBank libin/UmpTool.ini package path",
            ))
        } else if controller_id.is_some() && has_component(&components, "codefile") {
            Some((
                "nand-operation-module",
                "FirmWare/<controller>/CodeFile package path",
            ))
        } else if controller_id.is_some() && has_component(&components, "scanfile") {
            Some((
                "scan-sort-module",
                "FirmWare/<controller>/ScanFile package path",
            ))
        } else {
            None
        };
        if let Some((role, evidence)) = role {
            result.push(ToolComponent {
                family: Family::ChipsbankUfd.as_str(),
                role,
                controller_id,
                evidence,
            });
        }
    }

    if family_enabled(family, Family::InnostorUfd) {
        let in_binary_tree = has_component(&components, "binary");
        let controller_id = components
            .iter()
            .find(|component| matches!(component.as_str(), "is917" | "is917cp"))
            .map(|component| format!("innostor-{component}"));
        let role = if filename == "innostor mptool.exe" {
            Some((
                "factory-tool-host",
                "exact Innostor MPTool executable filename",
            ))
        } else if filename.contains("flashdatabase") && extension == "ini" {
            Some(("nand-database", "Innostor FlashDatabase INI filename"))
        } else if in_binary_tree && filename.contains("fwindex") {
            Some((
                "firmware-index",
                "binary controller tree and FWINDEX filename",
            ))
        } else if in_binary_tree && has_component(&components, "sorting") {
            Some(("sorting-loader", "binary/Sorting package path"))
        } else if in_binary_tree && has_component(&components, "firstexecute") {
            Some((
                "first-execute-loader",
                "binary controller tree and FIRSTEXECUTE path",
            ))
        } else if in_binary_tree && filename.contains("pc1") {
            Some((
                "controller-stage-one-code",
                "binary controller tree and pc1 filename",
            ))
        } else if in_binary_tree && filename.contains("pc2") {
            Some((
                "controller-stage-two-code",
                "binary controller tree and pc2 filename",
            ))
        } else if in_binary_tree && filename.contains("nftl") {
            Some((
                "flash-translation-layer-code",
                "binary controller tree and nftl filename",
            ))
        } else if in_binary_tree && filename.contains("init") {
            Some((
                "controller-initializer",
                "binary controller tree and init filename",
            ))
        } else {
            None
        };
        if let Some((role, evidence)) = role {
            result.push(ToolComponent {
                family: Family::InnostorUfd.as_str(),
                role,
                controller_id,
                evidence,
            });
        }
    }

    result
}

fn structured_text_required(path: &Path, family: Option<Family>) -> bool {
    let components = lower_path_components(path);
    let filename = components.last().map(String::as_str).unwrap_or_default();
    (family_enabled(family, Family::SiliconMotionUfd)
        && has_component(&components, "ufd_all_forcefw")
        && filename.ends_with(".ffw"))
        || (family_enabled(family, Family::AlcorUfd)
            && matches!(filename, "alcormp.ini" | "flashlist.ini" | "flashlist.afl"))
        || alcor_ascii_hex_module(path, family)
        || (family_enabled(family, Family::FirstchipUfd)
            && has_component(&components, "config")
            && matches!(filename, "flash.bin" | "readretry.bin"))
        || (family_enabled(family, Family::ChipsbankUfd)
            && ((has_component(&components, "flash") && filename == "flash.cbm")
                || (has_component(&components, "libin") && filename == "umptool.ini")))
        || (family_enabled(family, Family::InnostorUfd)
            && filename.contains("flashdatabase")
            && filename.ends_with(".ini"))
        || (family_enabled(family, Family::InnostorUfd)
            && filename.contains("fwindex")
            && filename.ends_with(".cfg"))
}

fn alcor_ascii_hex_module(path: &Path, family: Option<Family>) -> bool {
    let components = lower_path_components(path);
    let filename = components.last().map(String::as_str).unwrap_or_default();
    family_enabled(family, Family::AlcorUfd)
        && filename.ends_with(".bin")
        && alcor_controller_scope(&components).is_some()
        && ["bin", "dgd_bin", "scan_bin", "sort_bin"]
            .iter()
            .any(|directory| has_component(&components, directory))
}

fn firstchip_encrypted_database(path: &Path, family: Option<Family>) -> bool {
    let components = lower_path_components(path);
    let filename = components.last().map(String::as_str).unwrap_or_default();
    family_enabled(family, Family::FirstchipUfd)
        && has_component(&components, "config")
        && matches!(filename, "flash.bin" | "readretry.bin")
}

fn static_contract_required(path: &Path, family: Option<Family>) -> bool {
    let Some(filename) = path
        .file_name()
        .and_then(|value| value.to_str())
        .map(str::to_ascii_lowercase)
    else {
        return false;
    };
    (family_enabled(family, Family::AlcorUfd)
        && matches!(filename.as_str(), "ufdcomlib.dll" | "ufdapi_gen.dll"))
        || (family_enabled(family, Family::SiliconMotionUfd)
            && (filename == "ufdif.dll"
                || (filename.starts_with("sm32xtest") && filename.ends_with(".exe"))))
        || (family_enabled(family, Family::PhisonUfd) && filename == "getinfo.exe")
        || (family_enabled(family, Family::FirstchipUfd) && filename == "entryappite.dll")
        || (family_enabled(family, Family::ChipsbankUfd)
            && matches!(filename.as_str(), "aptoolv6a.exe" | "apdevicemp.dll"))
        || (family_enabled(family, Family::InnostorUfd) && filename == "innostor mptool.exe")
}

fn first_offset(haystack: &[u8], needle: &[u8]) -> Option<u64> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .find(|offset| haystack[*offset..].starts_with(needle))
        .map(|offset| offset as u64)
}

fn first_masked_offset(haystack: &[u8], pattern: &[u8], mask: &[u8]) -> Option<u64> {
    if pattern.is_empty() || pattern.len() != mask.len() || haystack.len() < pattern.len() {
        return None;
    }
    (0..=haystack.len() - pattern.len())
        .find(|offset| {
            haystack[*offset..*offset + pattern.len()]
                .iter()
                .zip(pattern)
                .zip(mask)
                .all(|((&actual, &expected), &mask)| actual & mask == expected & mask)
        })
        .map(|offset| offset as u64)
}

fn exact_contract_evidence(
    bytes: &[u8],
    role: &'static str,
    signature: &[u8],
    interpretation: &'static str,
) -> Option<ToolContractEvidence> {
    Some(ToolContractEvidence {
        role,
        offset: first_offset(bytes, signature)?,
        bytes_hex: hex::encode(signature),
        interpretation,
    })
}

#[derive(Clone, Copy)]
struct PeSection {
    virtual_address: u32,
    virtual_size: u32,
    raw_offset: u32,
    raw_size: u32,
}

fn pe_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_le_bytes(
        bytes.get(offset..offset + 2)?.try_into().ok()?,
    ))
}

fn pe_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_le_bytes(
        bytes.get(offset..offset + 4)?.try_into().ok()?,
    ))
}

fn pe_rva_offset(bytes: &[u8], sections: &[PeSection], rva: u32) -> Option<usize> {
    for section in sections {
        let extent = section.virtual_size.max(section.raw_size);
        let Some(delta) = rva.checked_sub(section.virtual_address) else {
            continue;
        };
        if delta >= extent || delta >= section.raw_size {
            continue;
        }
        let offset = section.raw_offset.checked_add(delta)? as usize;
        if offset < bytes.len() {
            return Some(offset);
        }
    }
    None
}

fn pe_named_export(bytes: &[u8], expected_name: &str) -> Option<(u32, Vec<PeSection>)> {
    const MAX_PE_SECTIONS: usize = 96;
    const MAX_PE_EXPORTS: usize = 4096;
    const MAX_PE_EXPORT_NAME: usize = 256;

    if bytes.get(..2)? != b"MZ" {
        return None;
    }
    let pe_offset = pe_u32(bytes, 0x3c)? as usize;
    if bytes.get(pe_offset..pe_offset.checked_add(4)?)? != b"PE\0\0" {
        return None;
    }
    let section_count = usize::from(pe_u16(bytes, pe_offset.checked_add(6)?)?);
    if section_count == 0 || section_count > MAX_PE_SECTIONS {
        return None;
    }
    let optional_size = usize::from(pe_u16(bytes, pe_offset.checked_add(20)?)?);
    let optional_offset = pe_offset.checked_add(24)?;
    let optional_end = optional_offset.checked_add(optional_size)?;
    if optional_end > bytes.len() {
        return None;
    }
    let data_directory_offset = match pe_u16(bytes, optional_offset)? {
        0x10b => optional_offset.checked_add(96)?,
        0x20b => optional_offset.checked_add(112)?,
        _ => return None,
    };
    if data_directory_offset.checked_add(8)? > optional_end {
        return None;
    }
    let export_rva = pe_u32(bytes, data_directory_offset)?;
    let export_size = pe_u32(bytes, data_directory_offset.checked_add(4)?)?;
    if export_rva == 0 || export_size < 40 {
        return None;
    }

    let mut sections = Vec::with_capacity(section_count);
    for index in 0..section_count {
        let offset = optional_end.checked_add(index.checked_mul(40)?)?;
        let end = offset.checked_add(40)?;
        if end > bytes.len() {
            return None;
        }
        sections.push(PeSection {
            virtual_size: pe_u32(bytes, offset.checked_add(8)?)?,
            virtual_address: pe_u32(bytes, offset.checked_add(12)?)?,
            raw_size: pe_u32(bytes, offset.checked_add(16)?)?,
            raw_offset: pe_u32(bytes, offset.checked_add(20)?)?,
        });
    }

    let export_offset = pe_rva_offset(bytes, &sections, export_rva)?;
    let function_count = pe_u32(bytes, export_offset.checked_add(20)?)? as usize;
    let name_count = pe_u32(bytes, export_offset.checked_add(24)?)? as usize;
    if function_count == 0
        || name_count == 0
        || function_count > MAX_PE_EXPORTS
        || name_count > MAX_PE_EXPORTS
    {
        return None;
    }
    let functions_offset = pe_rva_offset(
        bytes,
        &sections,
        pe_u32(bytes, export_offset.checked_add(28)?)?,
    )?;
    let names_offset = pe_rva_offset(
        bytes,
        &sections,
        pe_u32(bytes, export_offset.checked_add(32)?)?,
    )?;
    let ordinals_offset = pe_rva_offset(
        bytes,
        &sections,
        pe_u32(bytes, export_offset.checked_add(36)?)?,
    )?;

    for index in 0..name_count {
        let name_entry = names_offset.checked_add(index.checked_mul(4)?)?;
        let name_offset = pe_rva_offset(bytes, &sections, pe_u32(bytes, name_entry)?)?;
        let name_end = bytes
            .get(
                name_offset
                    ..name_offset
                        .checked_add(MAX_PE_EXPORT_NAME)?
                        .min(bytes.len()),
            )?
            .iter()
            .position(|byte| *byte == 0)
            .map(|length| name_offset + length)?;
        if bytes.get(name_offset..name_end)? != expected_name.as_bytes() {
            continue;
        }
        let ordinal_entry = ordinals_offset.checked_add(index.checked_mul(2)?)?;
        let ordinal = usize::from(pe_u16(bytes, ordinal_entry)?);
        if ordinal >= function_count {
            return None;
        }
        let function_entry = functions_offset.checked_add(ordinal.checked_mul(4)?)?;
        let function_rva = pe_u32(bytes, function_entry)?;
        if function_rva >= export_rva && function_rva < export_rva.checked_add(export_size)? {
            return None;
        }
        return Some((function_rva, sections));
    }
    None
}

/// Resolve one named PE export to its bounded file offset.
fn pe_export_function_offset(bytes: &[u8], expected_name: &str) -> Option<usize> {
    let (function_rva, sections) = pe_named_export(bytes, expected_name)?;
    pe_rva_offset(bytes, &sections, function_rva)
}

/// Resolve one named PE export through a direct x86 relative-jump thunk.
///
/// Factory DLL command ABIs are authenticated against their export table,
/// rather than by accepting an instruction sequence found at an unrelated
/// location in the file.
fn pe_export_x86_target(bytes: &[u8], expected_name: &str) -> Option<(usize, usize)> {
    let (function_rva, sections) = pe_named_export(bytes, expected_name)?;
    let thunk_offset = pe_rva_offset(bytes, &sections, function_rva)?;
    if *bytes.get(thunk_offset)? != 0xe9 {
        return None;
    }
    let relative = i32::from_le_bytes(
        bytes
            .get(thunk_offset.checked_add(1)?..thunk_offset.checked_add(5)?)?
            .try_into()
            .ok()?,
    );
    let target_rva = i64::from(function_rva)
        .checked_add(5)?
        .checked_add(i64::from(relative))?;
    let target_rva = u32::try_from(target_rva).ok()?;
    Some((thunk_offset, pe_rva_offset(bytes, &sections, target_rva)?))
}

struct ExportedVendorCommandSpec<'a> {
    role: &'static str,
    export_name: &'a str,
    signature_offset: usize,
    signature_hex: &'a str,
    interpretation: &'static str,
    command: ToolVendorCommandContract,
}

macro_rules! append_exported_vendor_command {
    (
        $bytes:expr,
        $evidence:expr,
        $commands:expr,
        $role:expr,
        $export_name:expr,
        $signature_offset:expr,
        $signature_hex:expr,
        $interpretation:expr,
        $command:expr $(,)?
    ) => {
        append_exported_vendor_command_impl(
            $bytes,
            $evidence,
            $commands,
            ExportedVendorCommandSpec {
                role: $role,
                export_name: $export_name,
                signature_offset: $signature_offset,
                signature_hex: $signature_hex,
                interpretation: $interpretation,
                command: $command,
            },
        )
    };
}

fn append_exported_vendor_command_impl(
    bytes: &[u8],
    evidence: &mut Vec<ToolContractEvidence>,
    commands: &mut Vec<ToolVendorCommandContract>,
    spec: ExportedVendorCommandSpec<'_>,
) -> bool {
    let Some((_thunk_offset, target_offset)) = pe_export_x86_target(bytes, spec.export_name) else {
        return false;
    };
    let Ok(signature) = hex::decode(spec.signature_hex) else {
        return false;
    };
    let Some(signature_start) = target_offset.checked_add(spec.signature_offset) else {
        return false;
    };
    let Some(signature_end) = signature_start.checked_add(signature.len()) else {
        return false;
    };
    if !bytes
        .get(signature_start..signature_end)
        .is_some_and(|actual| actual == signature)
    {
        return false;
    }
    evidence.push(ToolContractEvidence {
        role: spec.role,
        offset: signature_start as u64,
        bytes_hex: hex::encode(&signature),
        interpretation: spec.interpretation,
    });
    commands.push(spec.command);
    true
}

fn masked_contract_evidence(
    bytes: &[u8],
    role: &'static str,
    pattern: &[u8],
    mask: &[u8],
    interpretation: &'static str,
) -> Option<ToolContractEvidence> {
    let offset = first_masked_offset(bytes, pattern, mask)?;
    let start = usize::try_from(offset).ok()?;
    Some(ToolContractEvidence {
        role,
        offset,
        bytes_hex: hex::encode(&bytes[start..start + pattern.len()]),
        interpretation,
    })
}

fn alcor_transport_contract(
    path: &Path,
    size_bytes: u64,
    sha256: &str,
    format: &'static str,
    bytes: &[u8],
) -> Option<ToolHostTransportContract> {
    if format != "portable-executable" {
        return None;
    }
    let signatures: [(&str, &[u8], &str); 8] = [
        (
            "sptd-header-length",
            &[0x66, 0xc7, 0x44, 0x24, 0x2c, 0x2c, 0x00],
            "SCSI_PASS_THROUGH_DIRECT.Length is 0x2c",
        ),
        (
            "sense-length",
            &[0xc6, 0x44, 0x24, 0x33, 0x10],
            "SenseInfoLength is 0x10",
        ),
        (
            "sense-offset",
            &[0xc7, 0x44, 0x24, 0x44, 0x30, 0x00, 0x00, 0x00],
            "SenseInfoOffset is 0x30",
        ),
        (
            "ioctl-scsi-pass-through-direct",
            &[0x68, 0x14, 0xd0, 0x04, 0x00],
            "DeviceIoControl uses IOCTL_SCSI_PASS_THROUGH_DIRECT 0x0004d014",
        ),
        (
            "sector-transfer-unit",
            &[0x6a, 0x3c, 0xc1, 0xe2, 0x09],
            "timeout is 60 seconds and transfer sectors are multiplied by 512",
        ),
        (
            "data-out-wrapper",
            &[0x6a, 0x00, 0x8b, 0x54, 0x24, 0x14, 0x83, 0xec, 0x10],
            "wrapper passes DataIn value 0",
        ),
        (
            "data-in-wrapper",
            &[0x6a, 0x01, 0x8b, 0x54, 0x24, 0x14, 0x83, 0xec, 0x10],
            "wrapper passes DataIn value 1",
        ),
        (
            "flash-id-cdb-constructor",
            &[0x68, 0xfa, 0x00, 0x00, 0x00, 0x50, 0x6a, 0x01, 0x51],
            "read-only flash-ID command starts with FA 00 and uses the 16-byte read wrapper",
        ),
    ];
    let mut evidence = Vec::with_capacity(signatures.len() + 3);
    for (role, signature, interpretation) in signatures {
        evidence.push(ToolContractEvidence {
            role,
            offset: first_offset(bytes, signature)?,
            bytes_hex: hex::encode(signature),
            interpretation,
        });
    }
    for (role, signature, interpretation) in [
        (
            "outer-io-buffer-length",
            &[
                0x6a, 0x50, 0x51, 0x8d, 0x54, 0x24, 0x3c, 0x6a, 0x50, 0x52, 0x68, 0x14, 0xd0, 0x04,
                0x00,
            ][..],
            "DeviceIoControl input and output envelopes are 0x50 bytes",
        ),
        (
            "sixteen-byte-cdb-wrapper",
            &[0x6a, 0x10, 0x89, 0x08][..],
            "wrapper submits a 16-byte CDB",
        ),
        (
            "eight-byte-cdb-wrapper",
            &[0x6a, 0x08, 0x89, 0x11][..],
            "a separate wrapper submits an 8-byte CDB",
        ),
    ] {
        evidence.push(ToolContractEvidence {
            role,
            offset: first_offset(bytes, signature)?,
            bytes_hex: hex::encode(signature),
            interpretation,
        });
    }
    evidence.sort_by_key(|item| item.offset);
    Some(ToolHostTransportContract {
        family: Family::AlcorUfd.as_str(),
        source_path: path.to_path_buf(),
        source_size_bytes: size_bytes,
        source_sha256: sha256.to_string(),
        source_format: format,
        provenance: "untrusted-unsigned-factory-tool-executable",
        transport: "windows-scsi-pass-through-direct",
        ioctl_codes_hex: vec!["0004d014"],
        sptd_header_bytes: 0x2c,
        sense_bytes: 0x10,
        outer_buffer_bytes: 0x50,
        timeout_seconds: vec![60],
        transfer_unit_bytes: 512,
        retry_attempts: 1,
        cdb_lengths: vec![8, 16],
        data_directions: vec!["to-device", "from-device"],
        read_only_commands: vec![ToolReadOnlyCommandContract {
            name: "read-flash-id",
            cdb_hex: "fa000000000000000000000000000000",
            cdb_length: 16,
            data_direction: "from-device",
            transfer_bytes: 512,
            response_layout: "one primary and eight additional 6-byte identifiers are copied from 16-byte response slots",
        }],
        vendor_commands: Vec::new(),
        evidence,
        corroborating_source: Some(ALCOR_REVERSE_ENGINEERING_SOURCE),
        contract_scope: "host transport and read-only flash-ID command only",
        production_eligible: false,
    })
}

fn alcor_ufdapi_gen_contract(
    path: &Path,
    size_bytes: u64,
    sha256: &str,
    format: &'static str,
    bytes: &[u8],
) -> Option<ToolHostTransportContract> {
    if format != "portable-executable" || sha256 != ALCOR_UFDAPI_GEN_201310_SHA256 {
        return None;
    }

    let export_signature = hex::decode(
        "558bec8b4508c7006c1200108b4d08c74104f01200108b5508c74208271300108b4508c7400ca31300108b4d08c74110d11300108b5508c74214fb1300108b4508c740189e1400108b4d08c7411cc51400108b5508c74220e8140010b8010000005dc3",
    )
    .ok()?;
    let export_offset = pe_export_function_offset(bytes, "UfdApi_ExportFunc")?;
    let export_end = export_offset.checked_add(export_signature.len())?;
    if bytes.get(export_offset..export_end)? != export_signature {
        return None;
    }

    let mut evidence = vec![ToolContractEvidence {
        role: "ufdapi-export-function-table",
        offset: export_offset as u64,
        bytes_hex: hex::encode(&export_signature),
        interpretation:
            "UfdApi_ExportFunc directly installs the nine-entry factory operation table",
    }];
    for (role, signature, interpretation) in [
        (
            "sptd-envelope",
            &[
                0x66, 0xc7, 0x45, 0xac, 0x2c, 0x00, 0xc6, 0x45, 0xaf, 0x00, 0xc6, 0x45, 0xb0, 0x01,
                0xc6, 0x45, 0xb1, 0x00, 0x8a, 0x45, 0x0c, 0x88, 0x45, 0xb2, 0x8a, 0x4d, 0x20, 0x88,
                0x4d, 0xb4, 0xc6, 0x45, 0xb3, 0x10,
            ][..],
            "SPTD Length is 0x2c, target ID is 1, sense length is 16, and CDB length is supplied by the bounded wrapper",
        ),
        (
            "sense-offset",
            &[0xc7, 0x45, 0xc4, 0x30, 0x00, 0x00, 0x00][..],
            "SenseInfoOffset is 0x30",
        ),
        (
            "ioctl-scsi-pass-through-direct",
            &[
                0x8b, 0x4d, 0xa4, 0x51, 0x8d, 0x55, 0xac, 0x52, 0x68, 0x14, 0xd0, 0x04, 0x00,
            ][..],
            "DeviceIoControl uses IOCTL_SCSI_PASS_THROUGH_DIRECT 0x0004d014",
        ),
        (
            "transport-retry-bound",
            &[0xc6, 0x45, 0xfc, 0x0a][..],
            "the transport initializes a ten-attempt retry counter",
        ),
        (
            "eight-byte-data-out-wrapper",
            &[
                0x8b, 0x45, 0x2c, 0xc1, 0xe0, 0x09, 0x50, 0x6a, 0x00, 0x83, 0xec, 0x10,
            ][..],
            "the 8-byte wrapper multiplies sectors by 512 and selects data-out",
        ),
        (
            "eight-byte-data-in-wrapper",
            &[
                0x8b, 0x45, 0x2c, 0xc1, 0xe0, 0x09, 0x50, 0x6a, 0x01, 0x83, 0xec, 0x10,
            ][..],
            "the 8-byte wrapper multiplies sectors by 512 and selects data-in",
        ),
        (
            "ten-byte-data-out-wrapper",
            &[
                0x8b, 0x55, 0x34, 0xc1, 0xe2, 0x09, 0x52, 0x6a, 0x00, 0x83, 0xec, 0x10,
            ][..],
            "the 10-byte wrapper multiplies sectors by 512 and selects data-out",
        ),
        (
            "ten-byte-data-in-wrapper",
            &[
                0x8b, 0x55, 0x34, 0xc1, 0xe2, 0x09, 0x52, 0x6a, 0x01, 0x83, 0xec, 0x10,
            ][..],
            "the 10-byte wrapper multiplies sectors by 512 and selects data-in",
        ),
        (
            "factory-ascii-hex-decoder",
            &[
                0x8b, 0x4d, 0x10, 0x03, 0x4d, 0xd0, 0x51, 0x68, 0x04, 0x67, 0x0e, 0x10, 0x8b, 0x55,
                0xc4, 0x52, 0xff, 0x15, 0xb8, 0x11, 0x0d, 0x10, 0x83, 0xc4, 0x0c,
            ][..],
            "the selected module is decoded with %2hx into the bounded transfer buffer",
        ),
        (
            "service-code-upload-constructor",
            &[
                0xc6, 0x82, 0xfe, 0x01, 0x00, 0x00, 0x4a, 0x8b, 0x85, 0x68, 0xff, 0xff, 0xff, 0xc6,
                0x80, 0xff, 0x01, 0x00, 0x00, 0x4e, 0x8b, 0x4d, 0xdc, 0x51, 0x8b, 0x55, 0xe4, 0x81,
                0xe2, 0xff, 0x00, 0x00, 0x00, 0x83, 0xc2, 0x01, 0x52,
            ][..],
            "the factory appends JN to the 512-byte parameter page and transfers module sectors plus one",
        ),
        (
            "erase-selection-bitmap-constructor",
            &[
                0x8a, 0x55, 0x08, 0x52, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00,
                0x6a, 0x04, 0x6a, 0x0b, 0x68, 0xfa, 0x00, 0x00, 0x00,
            ][..],
            "FA 0B 04 carries the sector count in CDB byte 8 and uploads the erase-selection bitmap",
        ),
        (
            "physical-block-erase-constructor",
            &[
                0x8b, 0x45, 0x0c, 0x25, 0xff, 0xff, 0x00, 0x00, 0x25, 0xff, 0x00, 0x00, 0x00, 0x50,
                0x8b, 0x4d, 0x0c, 0x81, 0xe1, 0xff, 0xff, 0x00, 0x00, 0xc1, 0xe9, 0x08, 0x51, 0x8a,
                0x55, 0x08, 0x52, 0x6a, 0x11, 0x6a, 0x0b, 0x68, 0xfa, 0x00, 0x00, 0x00,
            ][..],
            "FA 0B 11 encodes chip-enable and a big-endian 16-bit physical block",
        ),
        (
            "raw-page-program-constructor",
            &[
                0x8a, 0x4d, 0x08, 0x51, 0x6a, 0x18, 0x6a, 0x0b, 0x68, 0xfa, 0x00, 0x00, 0x00,
            ][..],
            "FA 0B 18 is submitted through the 16-byte data-out wrapper",
        ),
        (
            "raw-page-read-constructor",
            &[
                0x8a, 0x4d, 0x08, 0x51, 0x6a, 0x19, 0x6a, 0x0b, 0x68, 0xfa, 0x00, 0x00, 0x00,
            ][..],
            "FA 0B 19 is submitted through the 16-byte data-in wrapper",
        ),
        (
            "operation-status-constructor",
            &[
                0x8d, 0x85, 0x00, 0xfe, 0xff, 0xff, 0x50, 0x6a, 0x01, 0x6a, 0x00, 0x6a, 0x00, 0x6a,
                0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x06, 0x6a, 0x0b, 0x68, 0xfa, 0x00, 0x00, 0x00,
            ][..],
            "FA 0B 06 reads one 512-byte status sector and requires response byte 0 to be zero",
        ),
        (
            "physical-range-erase-constructor",
            &[
                0x8b, 0x55, 0x0c, 0x81, 0xe2, 0xff, 0xff, 0x00, 0x00, 0x81, 0xe2, 0xff, 0x00, 0x00,
                0x00, 0x52, 0x8b, 0x45, 0x0c, 0x25, 0xff, 0xff, 0x00, 0x00, 0xc1, 0xe8, 0x08, 0x50,
                0x8a, 0x4d, 0x08, 0x51, 0x68, 0xa7, 0x00, 0x00, 0x00, 0x6a, 0x0b, 0x68, 0xfa, 0x00,
                0x00, 0x00,
            ][..],
            "FA 0B A7 encodes chip-enable, big-endian first block and big-endian block count",
        ),
        (
            "factory-service-90-constructor",
            &[
                0x8b, 0x45, 0x0c, 0x25, 0xff, 0xff, 0x00, 0x00, 0x25, 0xff, 0x00, 0x00, 0x00, 0x50,
                0x8b, 0x4d, 0x0c, 0x81, 0xe1, 0xff, 0xff, 0x00, 0x00, 0xc1, 0xe9, 0x08, 0x51, 0x8a,
                0x55, 0x08, 0x52, 0x68, 0x90, 0x00, 0x00, 0x00, 0x6a, 0x0b, 0x68, 0xfa, 0x00, 0x00,
                0x00,
            ][..],
            "FA 0B 90 carries one byte and one big-endian word, performs no data transfer, then reads factory status",
        ),
        (
            "factory-service-91-constructor",
            &[
                0x8a, 0x4d, 0x08, 0x51, 0x68, 0x91, 0x00, 0x00, 0x00, 0x6a, 0x0b, 0x68, 0xfa, 0x00,
                0x00, 0x00,
            ][..],
            "FA 0B 91 is a parameter-only service command with byte 15 fixed to one; the operation meaning is not inferred",
        ),
        (
            "factory-service-9a-constructor",
            &[
                0x8a, 0x55, 0x08, 0x52, 0x68, 0x9a, 0x00, 0x00, 0x00, 0x6a, 0x0b, 0x68, 0xfa, 0x00,
                0x00, 0x00,
            ][..],
            "FA 0B 9A is a parameter-only service command with byte 15 fixed to one; the operation meaning is not inferred",
        ),
        (
            "factory-service-92-constructor",
            &[
                0x8a, 0x4d, 0x08, 0x51, 0x68, 0x92, 0x00, 0x00, 0x00, 0x6a, 0x0b, 0x68, 0xfa, 0x00,
                0x00, 0x00,
            ][..],
            "FA 0B 92 performs bounded sector reads using a factory-generated list of trailing big-endian words",
        ),
        (
            "factory-service-94-constructor",
            &[
                0x8b, 0x4d, 0x08, 0x81, 0xe1, 0xff, 0x00, 0x00, 0x00, 0x51, 0x6a, 0x00, 0x6a, 0x00,
                0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00,
                0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x68, 0x94, 0x00, 0x00, 0x00,
            ][..],
            "FA 0B 94 uploads a caller-selected number of 512-byte sectors with an otherwise zero CDB",
        ),
        (
            "factory-service-99-constructor",
            &[
                0x6a, 0x02, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00,
                0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00, 0x6a, 0x00,
                0x68, 0x99, 0x00, 0x00, 0x00,
            ][..],
            "FA 0B 99 uploads exactly two 512-byte sectors with an otherwise zero CDB",
        ),
        (
            "factory-service-95-constructor",
            &[
                0x6a, 0x00, 0x68, 0x95, 0x00, 0x00, 0x00, 0x6a, 0x0b, 0x68, 0xfa, 0x00, 0x00, 0x00,
            ][..],
            "FA 0B 95 is submitted through the data-in wrapper with zero sectors; no operation meaning is inferred",
        ),
        (
            "factory-service-96-constructor",
            &[
                0x6a, 0x00, 0x68, 0x96, 0x00, 0x00, 0x00, 0x6a, 0x0b, 0x68, 0xfa, 0x00, 0x00, 0x00,
            ][..],
            "FA 0B 96 is submitted through the data-in wrapper with zero sectors; no operation meaning is inferred",
        ),
        (
            "factory-service-97-constructor",
            &[
                0x8a, 0x4d, 0x08, 0x51, 0x68, 0x97, 0x00, 0x00, 0x00, 0x6a, 0x0b, 0x68, 0xfa, 0x00,
                0x00, 0x00,
            ][..],
            "FA 0B 97 uploads a parameterized sector payload and then reads factory status; semantics remain tuple-specific",
        ),
        (
            "factory-service-9b-constructor",
            &[
                0x8a, 0x55, 0x08, 0x52, 0x68, 0x9b, 0x00, 0x00, 0x00, 0x6a, 0x0b, 0x68, 0xfa, 0x00,
                0x00, 0x00,
            ][..],
            "FA 0B 9B carries one byte and one big-endian word, performs no data transfer, then reads factory status",
        ),
        (
            "factory-service-98-constructor",
            &[
                0x8a, 0x4d, 0x08, 0x51, 0x68, 0x98, 0x00, 0x00, 0x00, 0x6a, 0x0b, 0x68, 0xfa, 0x00,
                0x00, 0x00,
            ][..],
            "FA 0B 98 reads exactly two 512-byte sectors with parameterized CDB fields, then reads factory status",
        ),
        (
            "write-read-compare-call-chain",
            &[
                0x6a, 0x00, 0x8b, 0x45, 0xe4, 0x50, 0x8a, 0x4d, 0xe0, 0x51, 0x6a, 0x00, 0x6a, 0x00,
                0x66, 0x8b, 0x55, 0x08, 0x52, 0x6a, 0x00, 0x8b, 0x4d, 0xc0,
            ][..],
            "the factory validation path erases one block, programs FA 0B 18, reads FA 0B 19, and compares returned data",
        ),
        (
            "erase-after-mp-range-call",
            &[
                0x66, 0x8b, 0x45, 0xf8, 0x50, 0x66, 0x8b, 0x4d, 0xc8, 0x51, 0x8a, 0x55, 0xe4, 0x52,
                0x8b, 0x4d, 0xc0, 0xe8, 0xcc, 0x01, 0x00, 0x00,
            ][..],
            "the EraseAfterMP loop calls the FA 0B A7 constructor with count, first block and chip-enable",
        ),
    ] {
        evidence.push(exact_contract_evidence(
            bytes,
            role,
            signature,
            interpretation,
        )?);
    }

    let vendor_commands = vec![
        ToolVendorCommandContract {
            name: "upload-service-code-and-parameter-page",
            opcode_hex: "fa",
            subcommand_hex: Some("0a"),
            cdb_length: 8,
            data_direction: "to-device",
            transfer_contract: "decode 16-byte ASCII-hex records to N complete 512-byte sectors, append one exact 512-byte parameter page ending in JN, transfer (N+1)*512 bytes",
            cdb_layout: "FA 0A 00 <module-sectors:u8> 00 00 00 00",
            classification: "service-code-upload",
            semantic_basis: "exact UfdApi_Gen.dll SHA-256, factory decoder and upload call path",
        },
        ToolVendorCommandContract {
            name: "upload-erase-selection-bitmap",
            opcode_hex: "fa",
            subcommand_hex: Some("0b04"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "CDB byte 8 sectors and transfer length both equal N*512 bytes",
            cdb_layout: "FA 0B 04 00 00 00 00 00 <sectors:u8> 00 00 00 00 00 00 00",
            classification: "physical-erase-parameter",
            semantic_basis: "exact EraseAfterMP bitmap builder and FA 0B 04 constructor",
        },
        ToolVendorCommandContract {
            name: "erase-physical-block",
            opcode_hex: "fa",
            subcommand_hex: Some("0b11"),
            cdb_length: 8,
            data_direction: "none",
            transfer_contract: "no data transfer; followed by FA 0B 06 status",
            cdb_layout: "FA 0B 11 <ce:u8> <block:be16> 00 00",
            classification: "destructive-physical-erase",
            semantic_basis: "exact constructor plus factory erase/program/read comparison call chain",
        },
        ToolVendorCommandContract {
            name: "program-raw-page",
            opcode_hex: "fa",
            subcommand_hex: Some("0b18"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "CDB byte 9 page sectors and transfer length both equal N*512 bytes",
            cdb_layout: "FA 0B 18 <ce:u8> <block:be16> <page:be16> <module-arg:u8> <page-sectors:u8> 00 00 00 00 <trailing-arg:be16>",
            classification: "destructive-raw-page-program",
            semantic_basis: "exact constructor plus factory erase/program/read comparison call chain",
        },
        ToolVendorCommandContract {
            name: "read-raw-page-and-ecc-trailer",
            opcode_hex: "fa",
            subcommand_hex: Some("0b19"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "CDB byte 9 is N page sectors; transfer length is (N+2)*512 bytes for data plus factory status/ECC trailer",
            cdb_layout: "FA 0B 19 <ce:u8> <block:be16> <page:be16> <module-arg:u8> <page-sectors:u8> 00 00 00 00 <trailing-arg:be16>",
            classification: "raw-physical-read",
            semantic_basis: "exact constructor plus factory erase/program/read comparison call chain",
        },
        ToolVendorCommandContract {
            name: "read-operation-status",
            opcode_hex: "fa",
            subcommand_hex: Some("0b06"),
            cdb_length: 8,
            data_direction: "from-device",
            transfer_contract: "one 512-byte sector; byte 0 must be zero, bytes 1..=3 carry the factory detail value",
            cdb_layout: "FA 0B 06 00 00 00 00 00",
            classification: "operation-status",
            semantic_basis: "exact status constructor and response branch",
        },
        ToolVendorCommandContract {
            name: "erase-physical-block-range",
            opcode_hex: "fa",
            subcommand_hex: Some("0ba7"),
            cdb_length: 8,
            data_direction: "none",
            transfer_contract: "no data transfer; followed by FA 0B 06 status",
            cdb_layout: "FA 0B A7 <ce:u8> <first-block:be16> <block-count:be16>",
            classification: "destructive-physical-range-erase",
            semantic_basis: "exact constructor and EraseAfterMP range loop",
        },
        ToolVendorCommandContract {
            name: "factory-service-90",
            opcode_hex: "fa",
            subcommand_hex: Some("0b90"),
            cdb_length: 16,
            data_direction: "none",
            transfer_contract: "no data transfer; followed by FA 0B 06 status",
            cdb_layout: "FA 0B 90 <arg0:u8> <arg1:be16> 00 00 00 00 00 00 00 00 00 00 00",
            classification: "opaque-factory-service-command",
            semantic_basis: "exact constructor; call sites are scan-internal and do not establish a reusable BBT or erase meaning",
        },
        ToolVendorCommandContract {
            name: "factory-service-91",
            opcode_hex: "fa",
            subcommand_hex: Some("0b91"),
            cdb_length: 16,
            data_direction: "none",
            transfer_contract: "no data transfer; followed by FA 0B 06 status",
            cdb_layout: "FA 0B 91 <a:u8> <b:be16> <c:be16> <d:u8> <bool:u8> <e:u8> 00 00 00 00 01",
            classification: "opaque-factory-service-command",
            semantic_basis: "exact constructor only; operation semantics are deliberately unresolved",
        },
        ToolVendorCommandContract {
            name: "factory-service-9a",
            opcode_hex: "fa",
            subcommand_hex: Some("0b9a"),
            cdb_length: 16,
            data_direction: "none",
            transfer_contract: "no data transfer; followed by FA 0B 06 status",
            cdb_layout: "FA 0B 9A <a:u8> <b:be16> <c:be16> <d:u8> 00 00 00 00 00 00 01",
            classification: "opaque-factory-service-command",
            semantic_basis: "exact constructor only; operation semantics are deliberately unresolved",
        },
        ToolVendorCommandContract {
            name: "factory-service-92-sector-read",
            opcode_hex: "fa",
            subcommand_hex: Some("0b92"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "the factory splits a caller sector total into bounded chunks and transfers chunk_sectors*512 bytes per command",
            cdb_layout: "FA 0B 92 <a:u8> <b:be16> <c:be16> <d:u8> 00 <e:u8> <f:u8> 00 00 <factory-list-entry:be16>",
            classification: "opaque-factory-service-read",
            semantic_basis: "exact loop and constructor; response meaning is deliberately unresolved",
        },
        ToolVendorCommandContract {
            name: "factory-service-94-sector-upload",
            opcode_hex: "fa",
            subcommand_hex: Some("0b94"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "caller sector count N and transfer length N*512 bytes",
            cdb_layout: "FA 0B 94 00 00 00 00 00 00 00 00 00 00 00 00 00",
            classification: "opaque-factory-service-upload",
            semantic_basis: "exact constructor; uploaded record semantics are deliberately unresolved",
        },
        ToolVendorCommandContract {
            name: "factory-service-99-two-sector-upload",
            opcode_hex: "fa",
            subcommand_hex: Some("0b99"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "exactly 1024 bytes",
            cdb_layout: "FA 0B 99 00 00 00 00 00 00 00 00 00 00 00 00 00",
            classification: "opaque-factory-service-upload",
            semantic_basis: "exact constructor; uploaded record semantics are deliberately unresolved",
        },
        ToolVendorCommandContract {
            name: "factory-service-95",
            opcode_hex: "fa",
            subcommand_hex: Some("0b95"),
            cdb_length: 16,
            data_direction: "none",
            transfer_contract: "zero sectors through the factory data-in wrapper",
            cdb_layout: "FA 0B 95 00 00 00 00 00 00 00 00 00 00 00 00 00",
            classification: "opaque-factory-service-command",
            semantic_basis: "exact constructor only; no call site establishes a reusable meaning",
        },
        ToolVendorCommandContract {
            name: "factory-service-96",
            opcode_hex: "fa",
            subcommand_hex: Some("0b96"),
            cdb_length: 16,
            data_direction: "none",
            transfer_contract: "zero sectors through the factory data-in wrapper",
            cdb_layout: "FA 0B 96 00 00 00 00 00 00 00 00 00 00 00 00 00",
            classification: "opaque-factory-service-command",
            semantic_basis: "exact constructor only; operation semantics are deliberately unresolved",
        },
        ToolVendorCommandContract {
            name: "factory-service-97-sector-upload",
            opcode_hex: "fa",
            subcommand_hex: Some("0b97"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "zero bytes for a null payload, otherwise N*512 bytes; followed by FA 0B 06 status",
            cdb_layout: "FA 0B 97 <a:u8> <b:be16> <c:be16> <d:u8> <sectors:u8> <e:be16> <f:u8> <g:u8> 00 00",
            classification: "opaque-factory-service-upload",
            semantic_basis: "exact constructor; payload semantics are deliberately unresolved",
        },
        ToolVendorCommandContract {
            name: "factory-service-9b",
            opcode_hex: "fa",
            subcommand_hex: Some("0b9b"),
            cdb_length: 16,
            data_direction: "none",
            transfer_contract: "no data transfer; followed by FA 0B 06 status",
            cdb_layout: "FA 0B 9B <a:u8> <b:be16> 00 00 00 00 00 00 00 00 00 00 00",
            classification: "opaque-factory-service-command",
            semantic_basis: "exact constructor only; operation semantics are deliberately unresolved",
        },
        ToolVendorCommandContract {
            name: "factory-service-98-two-sector-read",
            opcode_hex: "fa",
            subcommand_hex: Some("0b98"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "exactly 1024 bytes; followed by FA 0B 06 status",
            cdb_layout: "FA 0B 98 <a:u8> <b:be16> <c:be16> <d:u8> <e:u8> <f:be16> <g:u8> 00 00 00",
            classification: "opaque-factory-service-read",
            semantic_basis: "exact constructor; response semantics are deliberately unresolved",
        },
    ];
    evidence.sort_by_key(|item| item.offset);
    Some(ToolHostTransportContract {
        family: Family::AlcorUfd.as_str(),
        source_path: path.to_path_buf(),
        source_size_bytes: size_bytes,
        source_sha256: sha256.to_string(),
        source_format: format,
        provenance: "untrusted-unsigned-factory-tool-executable",
        transport: "windows-scsi-pass-through-direct",
        ioctl_codes_hex: vec!["0004d014"],
        sptd_header_bytes: 0x2c,
        sense_bytes: 0x10,
        outer_buffer_bytes: 0x50,
        timeout_seconds: vec![60],
        transfer_unit_bytes: 512,
        retry_attempts: 10,
        cdb_lengths: vec![8, 10, 16],
        data_directions: vec!["none", "to-device", "from-device"],
        read_only_commands: Vec::new(),
        vendor_commands,
        evidence,
        corroborating_source: None,
        contract_scope: "exact 2013-10 UfdApi_Gen service-code, physical erase, raw page and status constructors plus a conservative catalog of opaque scan-internal FA 0B 90..9B commands; module selection, parameter-page field meanings, ECC-trailer decoding, opaque-command semantics, exact hardware tuple and HIL qualification remain required",
        production_eligible: false,
    })
}

fn smi_ufdif_transport_contract(
    path: &Path,
    size_bytes: u64,
    sha256: &str,
    format: &'static str,
    bytes: &[u8],
) -> Option<ToolHostTransportContract> {
    if format != "portable-executable" {
        return None;
    }
    let mut evidence = Vec::new();
    for (role, signature, interpretation) in [
        (
            "sptd-header-and-cdb-length",
            &[
                0x66, 0xc7, 0x85, 0x78, 0xff, 0xff, 0xff, 0x2c, 0x00, 0xc6, 0x85, 0x7b, 0xff, 0xff,
                0xff, 0x00, 0xc6, 0x85, 0x7c, 0xff, 0xff, 0xff, 0x01, 0xc6, 0x85, 0x7d, 0xff, 0xff,
                0xff, 0x00, 0xc6, 0x85, 0x7e, 0xff, 0xff, 0xff, 0x10,
            ][..],
            "SPTD Length is 0x2c, target ID is 1, and CdbLength is 16",
        ),
        (
            "data-in-direction",
            &[0xc6, 0x45, 0x80, 0x01][..],
            "read wrapper sets DataIn to 1",
        ),
        (
            "data-out-direction",
            &[0xc6, 0x45, 0x80, 0x00][..],
            "write wrapper sets DataIn to 0",
        ),
        (
            "timeout-load",
            &[0xa1, 0xa8, 0x55, 0x14, 0x10, 0x89, 0x45, 0x88][..],
            "SPTD timeout is loaded from the executable's 0x101455a8 static value",
        ),
        (
            "sense-offset",
            &[0xc7, 0x45, 0x90, 0x30, 0x00, 0x00, 0x00][..],
            "SenseInfoOffset is 0x30",
        ),
        (
            "ioctl-scsi-pass-through-direct",
            &[0x68, 0x14, 0xd0, 0x04, 0x00][..],
            "DeviceIoControl uses IOCTL_SCSI_PASS_THROUGH_DIRECT 0x0004d014",
        ),
        (
            "retry-bound",
            &[0x83, 0xbd, 0x68, 0xff, 0xff, 0xff, 0x08][..],
            "the direct transport loop stops after eight attempts",
        ),
    ] {
        evidence.push(exact_contract_evidence(
            bytes,
            role,
            signature,
            interpretation,
        )?);
    }
    let timeout_offset = 0x1455a8usize;
    let timeout_bytes = bytes.get(timeout_offset..timeout_offset + 4)?;
    if timeout_bytes != 300u32.to_le_bytes() {
        return None;
    }
    evidence.push(ToolContractEvidence {
        role: "timeout-value",
        offset: timeout_offset as u64,
        bytes_hex: hex::encode(timeout_bytes),
        interpretation: "the static SPTD timeout value is 300 seconds",
    });
    let mut vendor_commands = Vec::new();
    macro_rules! append_smi_recovered_command {
        (
            $role:literal,
            $export:literal,
            $offset:expr,
            $signature:literal,
            $interpretation:literal,
            $name:literal,
            $opcode:literal,
            $subcommand:literal,
            $direction:literal,
            $transfer:literal,
            $layout:literal,
            $classification:literal,
            $basis:literal $(,)?
        ) => {
            append_exported_vendor_command!(
                bytes,
                &mut evidence,
                &mut vendor_commands,
                $role,
                $export,
                $offset,
                $signature,
                $interpretation,
                ToolVendorCommandContract {
                    name: $name,
                    opcode_hex: $opcode,
                    subcommand_hex: Some($subcommand),
                    cdb_length: 16,
                    data_direction: $direction,
                    transfer_contract: $transfer,
                    cdb_layout: $layout,
                    classification: $classification,
                    semantic_basis: $basis,
                },
            );
        };
    }
    append_smi_recovered_command!(
        "smi-exported-set-driving",
        "LIB_SetDriving",
        0x54,
        "c685ecfdfffff1c685edfdffff118b85fcfdffff9981e2ff01000003",
        "the LIB_SetDriving export constructs F1/11 and a zeroed 512-byte descriptor with three caller bytes",
        "set-driving",
        "f1",
        "11",
        "to-device",
        "exactly 512 bytes; descriptor bytes 0..2 are positional caller values",
        "00=F1; 01=11; 02..10=00; 11=01 sector; 12..15=00",
        "raw-nand-electrical-setup",
        "exact PE export mapping, descriptor initialization, scalar stores, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-clock-duty",
        "LIB_SetClockAndDutyCycle",
        0x54,
        "c685ecfdfffff1c685edfdffff128b85fcfdffff9981e2ff01000003",
        "the LIB_SetClockAndDutyCycle export constructs F1/12 with four positional caller bytes",
        "set-clock-and-duty-cycle",
        "f1",
        "12",
        "to-device",
        "exactly 512 bytes; descriptor bytes 0..3 are positional caller values",
        "00=F1; 01=12; 02..10=00; 11=01 sector; 12..15=00",
        "raw-nand-timing-setup",
        "exact PE export mapping, descriptor initialization, scalar stores, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-voltage",
        "LIB_SetVoltage",
        0x54,
        "c685ecfdfffff1c685edfdffff138b85fcfdffff9981e2ff01000003",
        "the LIB_SetVoltage export constructs F1/13 with one positional caller byte",
        "set-voltage",
        "f1",
        "13",
        "to-device",
        "exactly 512 bytes; descriptor byte 0 is caller supplied",
        "00=F1; 01=13; 02..10=00; 11=01 sector; 12..15=00",
        "raw-nand-electrical-setup",
        "exact PE export mapping, descriptor initialization, scalar store, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-info",
        "LIB_SetInfo",
        0x69,
        "c645ecf1c645ed148b45fc9981e2ff01000003c2c1f8098845f78b45",
        "the LIB_SetInfo export constructs F1/14 with a sector-ceiling caller table",
        "set-info-table",
        "f1",
        "14",
        "to-device",
        "caller table rounded up to a 512-byte sector boundary",
        "00=F1; 01=14; 02..10=00; 11=derived sectors; 12..15=00",
        "raw-nand-geometry-setup",
        "exact PE export mapping, length branch, constructor, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-seed-table",
        "LIB_SetSeedTable",
        0x7c,
        "c645ecf1c645ed158b451cc1f8088845ee8a4d1c884def8b45fc9981",
        "the LIB_SetSeedTable export constructs F1/15, caps at 1024 bytes, and records the unpadded length",
        "set-seed-table",
        "f1",
        "15",
        "to-device",
        "caller table capped at 1024 bytes and rounded to 512 bytes; unpadded length is CDB bytes 2..3",
        "00=F1; 01=15; 02..03=source bytes BE16; 04..10=00; 11=derived sectors; 12..15=00",
        "raw-nand-randomizer-setup",
        "exact PE export mapping, 1024-byte cap, length stores, constructor, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-rb-timeout",
        "LIB_SetRBTimeout",
        0x54,
        "c685ecfdfffff1c685edfdffff168b85fcfdffff9981e2ff01000003",
        "the LIB_SetRBTimeout export constructs F1/16 with one BE16 value",
        "set-ready-busy-timeout",
        "f1",
        "16",
        "to-device",
        "exactly 512 bytes; descriptor bytes 0..1 are one caller value in big-endian order",
        "00=F1; 01=16; 02..10=00; 11=01 sector; 12..15=00",
        "raw-nand-timing-setup",
        "exact PE export mapping, descriptor initialization, BE16 stores, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-check-rb-mode",
        "LIB_SetCheckRBMode",
        0x54,
        "c685ecfdfffff1c685edfdffff178b85fcfdffff9981e2ff01000003",
        "the LIB_SetCheckRBMode export constructs F1/17 with one positional caller byte",
        "set-ready-busy-check-mode",
        "f1",
        "17",
        "to-device",
        "exactly 512 bytes; descriptor byte 0 is caller supplied",
        "00=F1; 01=17; 02..10=00; 11=01 sector; 12..15=00",
        "raw-nand-status-setup",
        "exact PE export mapping, descriptor initialization, scalar store, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-force-ce-low",
        "LIB_SetForceCEtoLow",
        0x54,
        "c685ecfdfffff1c685edfdffff198b85fcfdffff9981e2ff01000003",
        "the LIB_SetForceCEtoLow export constructs F1/19 with one positional caller byte",
        "set-force-ce-low",
        "f1",
        "19",
        "to-device",
        "exactly 512 bytes; descriptor byte 0 is caller supplied",
        "00=F1; 01=19; 02..10=00; 11=01 sector; 12..15=00",
        "raw-nand-electrical-setup",
        "exact PE export mapping, descriptor initialization, scalar store, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-ce-switch",
        "LIB_SetCESwitch",
        0x54,
        "c685ecfdfffff1c685edfdffff1a8b85fcfdffff9981e2ff01000003",
        "the LIB_SetCESwitch export constructs F1/1A with four positional caller bytes",
        "set-ce-switch",
        "f1",
        "1a",
        "to-device",
        "exactly 512 bytes; descriptor bytes 0..3 are positional caller values",
        "00=F1; 01=1A; 02..10=00; 11=01 sector; 12..15=00",
        "raw-nand-topology-setup",
        "exact PE export mapping, descriptor initialization, scalar stores, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-write-pattern",
        "LIB_WritePattern",
        0x69,
        "c645ecf1c645ed228b45fc9981e2ff01000003c2c1f8098845f78b45",
        "the LIB_WritePattern export constructs F1/22 with a sector-ceiling pattern table",
        "write-pattern-table",
        "f1",
        "22",
        "to-device",
        "caller table rounded up to a 512-byte sector boundary",
        "00=F1; 01=22; 02..10=00; 11=derived sectors; 12..15=00",
        "raw-nand-write-setup",
        "exact PE export mapping, length branch, constructor, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-bad-column-table",
        "LIB_SetBadColTable",
        0x6c,
        "c645ecf1c645ed268a45188845ee8b45fc9981e2ff01000003c2c1f8",
        "the LIB_SetBadColTable export constructs F1/26 with a selector and sector-ceiling table",
        "set-bad-column-table",
        "f1",
        "26",
        "to-device",
        "caller table rounded up to 512 bytes; selector is CDB byte 2",
        "00=F1; 01=26; 02=selector; 03..10=00; 11=derived sectors; 12..15=00",
        "raw-nand-bad-column-setup",
        "exact PE export mapping, selector store, length branch, constructor, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-bad-column-addresses",
        "LIB_SetBadColAddr",
        0x69,
        "c645ecf1c645ed278b45fc9981e2ff01000003c2c1f8098845f78b45",
        "the LIB_SetBadColAddr export constructs F1/27 with a sector-ceiling address table",
        "set-bad-column-address-table",
        "f1",
        "27",
        "to-device",
        "caller table rounded up to a 512-byte sector boundary",
        "00=F1; 01=27; 02..10=00; 11=derived sectors; 12..15=00",
        "raw-nand-bad-column-setup",
        "exact PE export mapping, length branch, constructor, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-send-copyback-source",
        "LIB_SendCopyBackSourceBlock",
        0x54,
        "c685ecfdfffff1c685edfdffff298b85fcfdffff9981e2ff01000003",
        "the LIB_SendCopyBackSourceBlock export constructs F1/29 with two BE16 values",
        "send-copy-back-source-block",
        "f1",
        "29",
        "to-device",
        "exactly 512 bytes; descriptor bytes 0..3 are two caller values in big-endian order",
        "00=F1; 01=29; 02..10=00; 11=01 sector; 12..15=00",
        "raw-nand-copy-back-setup",
        "exact PE export mapping, descriptor initialization, BE16 stores, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-retry-table",
        "LIB_SetRetryTable",
        0x7c,
        "c645ecf1c645ed308a45188845ee8a4d1c884def8b45fc9981e2ff01",
        "the LIB_SetRetryTable export constructs F1/30 with two CDB selector bytes and at most 1024 data bytes",
        "set-retry-table",
        "f1",
        "30",
        "to-device",
        "caller table rounded to 512 bytes and capped at 1024 bytes; two positional values are CDB bytes 2 and 3",
        "00=F1; 01=30; 02..03=caller values; 04..10=00; 11=derived sectors; 12..15=00",
        "raw-nand-read-retry-setup",
        "exact PE export mapping, 1024-byte cap, selector stores, constructor, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-send-modify-info",
        "LIB_SendModifyInfo",
        0x69,
        "c645ecf1c645ed318b45fc9981e2ff01000003c2c1f8098845f78b45",
        "the LIB_SendModifyInfo export constructs F1/31 with a sector-ceiling table",
        "send-modify-info",
        "f1",
        "31",
        "to-device",
        "caller table rounded up to a 512-byte sector boundary",
        "00=F1; 01=31; 02..10=00; 11=derived sectors; 12..15=00",
        "controller-metadata-update",
        "exact PE export mapping, length branch, constructor, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-send-block-fail-table",
        "LIB_SendBlockFailBitTable",
        0x7a,
        "c645e4f1c645e5328a45f88845e68b45fc9981e2ff01000003c2c1f8",
        "the LIB_SendBlockFailBitTable export constructs indexed F1/32 writes in 1024-byte chunks",
        "send-block-fail-bit-table",
        "f1",
        "32",
        "to-device",
        "one 1024-byte chunk for lengths through 1024, otherwise two; chunk index is CDB byte 2",
        "00=F1; 01=32; 02=chunk index; 03..10=00; 11=02 sectors; 12..15=00",
        "retired-block-metadata-update",
        "exact PE export mapping, two-chunk bound, indexed constructor, and data-out loop",
    );
    append_smi_recovered_command!(
        "smi-exported-bad-column-write-flash",
        "LIB_BadColumnWriteFlash",
        0x9e,
        "c685ecfdfffff1c685edfdffff338b85fcfdffff9981e2ff01000003",
        "the LIB_BadColumnWriteFlash export constructs F1/33 with a fixed 512-byte positional descriptor",
        "bad-column-write-flash",
        "f1",
        "33",
        "to-device",
        "exactly 512 bytes; first 16 bytes are scalar fields and bytes 16..511 retain the optional caller table",
        "00=F1; 01=33; 02..10=00; 11=01 sector; 12..15=00",
        "state-changing-raw-nand-request",
        "exact PE export mapping, bounded table copy, descriptor overlay, constructor, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-write-diff-page-table",
        "LIB_WriteDiffPageTable",
        0x9d,
        "c685ecdffffff1c685eddfffff368b451825ffff0000c1f8088885ee",
        "the LIB_WriteDiffPageTable export constructs F1/36 with a 1 KiB-unit payload",
        "write-differential-page-table",
        "f1",
        "36",
        "to-device",
        "payload bytes are low16(CDB bytes 6..7) multiplied by 1024 and zero padded after the bounded source copy",
        "00=F1; 01=36; 02..03 and 04..05=two BE16 values; 06..07=1KiB units BE16; 08=discriminator; 11=derived sectors",
        "raw-nand-differential-map-setup",
        "exact PE export mapping, 1 KiB multiplier, bounded copy, constructor, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-diff-block",
        "LIB_SetDiffBlock",
        0x90,
        "c685ecfdfffff1c685edfdffff378a4d18888deefdffff8b85fcfdff",
        "the LIB_SetDiffBlock export constructs F1/37 with a selector and fixed zero-padded 512-byte descriptor",
        "set-differential-block-table",
        "f1",
        "37",
        "to-device",
        "exactly 512 bytes; at most 512 caller bytes are copied and selector is CDB byte 2",
        "00=F1; 01=37; 02=selector; 03..10=00; 11=01 sector; 12..15=00",
        "raw-nand-differential-map-setup",
        "exact PE export mapping, bounded copy, selector store, constructor, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-copy-back-mode",
        "LIB_SetInCopyBackMode",
        0x54,
        "c685ecfdfffff1c685edfdffff398b85fcfdffff9981e2ff01000003",
        "the LIB_SetInCopyBackMode export constructs F1/39 with one positional caller byte",
        "set-copy-back-mode",
        "f1",
        "39",
        "to-device",
        "exactly 512 bytes; descriptor byte 0 is caller supplied",
        "00=F1; 01=39; 02..10=00; 11=01 sector; 12..15=00",
        "raw-nand-copy-back-setup",
        "exact PE export mapping, descriptor initialization, scalar store, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-find-new-retry",
        "LIB_SetFindNewRetryTable",
        0x54,
        "c685ecfdfffff1c685edfdffff408b85fcfdffff9981e2ff01000003",
        "the LIB_SetFindNewRetryTable export constructs F1/40 with two positional caller bytes",
        "set-find-new-retry-table",
        "f1",
        "40",
        "to-device",
        "exactly 512 bytes; descriptor bytes 0..1 are caller supplied",
        "00=F1; 01=40; 02..10=00; 11=01 sector; 12..15=00",
        "raw-nand-read-retry-setup",
        "exact PE export mapping, descriptor initialization, scalar stores, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-strong-table",
        "LIB_SetStrongTable",
        0xb4,
        "c685ecfbfffff1c685edfbffff418b85fcfbffff9981e2ff01000003",
        "the LIB_SetStrongTable export constructs F1/41 with an at-most-1024-byte local table",
        "set-strong-table",
        "f1",
        "41",
        "to-device",
        "caller table rounded to 512 bytes and capped at 1024 bytes",
        "00=F1; 01=41; 02..10=00; 11=derived sectors; 12..15=00",
        "raw-nand-read-retry-setup",
        "exact PE export mapping, 1024-byte local buffer, transfer cap, constructor, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-set-find-new-retry-b0-b7",
        "LIB_SetFindNewRetryTableB0B7",
        0x54,
        "c685ecfdfffff1c685edfdffff428b85fcfdffff9981e2ff01000003",
        "the LIB_SetFindNewRetryTableB0B7 export constructs F1/42 with eight positional caller bytes",
        "set-find-new-retry-table-b0-b7",
        "f1",
        "42",
        "to-device",
        "exactly 512 bytes; descriptor bytes 0..7 are caller supplied",
        "00=F1; 01=42; 02..10=00; 11=01 sector; 12..15=00",
        "raw-nand-read-retry-setup",
        "exact PE export mapping, descriptor initialization, scalar stores, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-end-sorting",
        "LIB_EndSorting",
        0x54,
        "c685ecfdfffff1c685edfdffff608b85fcfdffff9981e2ff01000003",
        "the LIB_EndSorting export constructs F1/60 with a zeroed 512-byte descriptor",
        "end-sorting",
        "f1",
        "60",
        "to-device",
        "exactly 512 zero bytes",
        "00=F1; 01=60; 02..10=00; 11=01 sector; 12..15=00",
        "state-changing-factory-transition",
        "exact PE export mapping, descriptor initialization, constructor, and data-out call",
    );
    append_smi_recovered_command!(
        "smi-exported-bad-column-read-flash",
        "LIB_BadColumnReadFlash",
        0x142,
        "83c40cc645f0f0c645f1378b551881e2ffff0000c1fa088855f28a45",
        "the LIB_BadColumnReadFlash export constructs chunked F0/37 physical page-data reads",
        "read-bad-column-page-data",
        "f0",
        "37",
        "from-device",
        "up to 8 KiB per command; final transfer is rounded to 1 KiB and copied back only to the caller's requested length",
        "00=F0; 01=37; 02..03 and 04..05=two BE16 values; 06..07=1KiB unit range; 11=derived sectors",
        "read-only-raw-nand-data",
        "exact PE export mapping, bounded 8 KiB loop, unit-range constructor, data-in call, and trimmed final copy",
    );
    append_smi_recovered_command!(
        "smi-exported-get-original-retry",
        "LIB_GetOriginalRetryTable",
        0x3b,
        "c645f0f0c645f138c645fb0268000400008b4d18518d55f05283ec10",
        "the LIB_GetOriginalRetryTable export constructs a fixed 1024-byte F0/38 read",
        "get-original-retry-table",
        "f0",
        "38",
        "from-device",
        "exactly 1024 bytes",
        "00=F0; 01=38; 02..10=00; 11=02 sectors; 12..15=00",
        "read-only-read-retry-metadata",
        "exact PE export mapping, fixed-size guard, constructor, and data-in call",
    );
    append_smi_recovered_command!(
        "smi-exported-get-one-s-count",
        "LIB_GetOneSCountNumber",
        0x3b,
        "c645f0f0c645f139c645fb0168000200008b4d18518d55f05283ec10",
        "the LIB_GetOneSCountNumber export constructs a fixed 512-byte F0/39 read",
        "get-one-s-count-number",
        "f0",
        "39",
        "from-device",
        "exactly 512 bytes",
        "00=F0; 01=39; 02..10=00; 11=01 sector; 12..15=00",
        "read-only-nand-characterization-metadata",
        "exact PE export mapping, fixed-size guard, constructor, and data-in call",
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-set-erase-flash-parameters",
        "LIB_SetEraseFlashPara",
        0x54,
        "c685ecfdfffff1c685edfdffff1f8b85fcfdffff9981e2ff01000003c2c1f8098885f7fdffff8a4d18888d00feffff8a551c889501feffff8b85fcfdffff508d8d00feffff518d95ecfdffff5283ec108bc48b4d0889088b550c8950048b4d10",
        "the LIB_SetEraseFlashPara export constructs F1/1F with a zeroed 512-byte descriptor and two one-byte ABI fields",
        ToolVendorCommandContract {
            name: "set-erase-flash-parameters",
            opcode_hex: "f1",
            subcommand_hex: Some("1f"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "exactly 512 bytes; descriptor bytes 0 and 1 are the two caller scalar fields",
            cdb_layout: "00=F1; 01=1F; 02..10=00; 11=01 sector; 12..15=00",
            classification: "raw-nand-setup",
            semantic_basis: "exact PE export mapping, descriptor initialization, scalar stores, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-set-read-flash-parameters",
        "LIB_SetReadFlashPara",
        0x54,
        "c685ecfdfffff1c685edfdffff248b85fcfdffff9981e2ff01000003c2c1f8098885f7fdffff8a4d18888d00feffff8a551c889502feffff8a4520888504feffff8a4d24888d05feffff8a5528889506feffff8a452c888507feffff8b8dfcfdffff518d9500feffff528d85ecfdffff5083ec108bcc8b55",
        "the LIB_SetReadFlashPara export constructs F1/24 and maps six caller bytes to descriptor offsets 0, 2, 4, 5, 6, and 7",
        ToolVendorCommandContract {
            name: "set-read-flash-parameters",
            opcode_hex: "f1",
            subcommand_hex: Some("24"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "exactly 512 bytes; six scalar fields occupy descriptor offsets 0,2,4,5,6,7 and all other bytes are zero",
            cdb_layout: "00=F1; 01=24; 02..10=00; 11=01 sector; 12..15=00",
            classification: "raw-nand-read-setup",
            semantic_basis: "exact PE export mapping, descriptor initialization, scalar stores, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-set-write-flash-parameters",
        "LIB_SetWriteFlashPara",
        0x8e,
        "c685ecfbfffff1c685edfbffff218b85fcfbffff9981e2ff01000003c2c1f8098885f7fbffff8a4518888500fcffff8a4d1c888d01fcffff8a5520889502fcffff8a4524888503fcffff8a4d28888d05fcffff8a552c889506fcffff8a4530888507fcffff8a4d34888d0cfcffff8a553888950dfcffff8b85fcfbffff508d8d00fcffff518d95ecfbffff5283ec108bc48b4d088908",
        "the LIB_SetWriteFlashPara export constructs F1/21, a 1024-byte descriptor, nine scalar fields, and a bounded second-sector table",
        ToolVendorCommandContract {
            name: "set-write-flash-parameters",
            opcode_hex: "f1",
            subcommand_hex: Some("21"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "exactly 1024 bytes; scalar fields occupy first-sector offsets 0,1,2,3,5,6,7,12,13 and at most 512 caller bytes occupy the second sector",
            cdb_layout: "00=F1; 01=21; 02..10=00; 11=02 sectors; 12..15=00",
            classification: "raw-nand-write-setup",
            semantic_basis: "exact PE export mapping, 512-byte table bound, descriptor initialization, scalar stores, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-set-ewr-flash-parameters",
        "LIB_SetEWRFlashPara",
        0x8e,
        "c685ecfbfffff1c685edfbffff348b85fcfbffff9981e2ff01000003c2c1f8098885f7fbffff8a4518888500fcffff8a4d1c888d01fcffff8a5520889502fcffff8a4524888503fcffff8a4d28888d04fcffff8a552c889505fcffff8a4530888506fcffff8a4d34888d07fcffff8a5538889508fcffff8a453c888509fcffff8a4d40888d0afcffff8a554488950bfcffff8a454888850cfcffff8a4d4c888d0dfcffff8a555088950efcffff8a455488850ffcffff8b8dfcfbffff518d9500fcffff528d85ecfbffff5083ec108bcc8b550889118b450c8941048b",
        "the LIB_SetEWRFlashPara export constructs F1/34, sixteen scalar descriptor bytes, and a bounded second-sector table",
        ToolVendorCommandContract {
            name: "set-erase-write-read-flash-parameters",
            opcode_hex: "f1",
            subcommand_hex: Some("34"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "exactly 1024 bytes; sixteen scalar fields occupy first-sector offsets 0..15 and at most 512 caller bytes occupy the second sector",
            cdb_layout: "00=F1; 01=34; 02..10=00; 11=02 sectors; 12..15=00",
            classification: "raw-nand-combined-operation-setup",
            semantic_basis: "exact PE export mapping, 512-byte table bound, descriptor initialization, scalar stores, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-set-ce-die-plane",
        "LIB_SetCEDiePlane",
        0x54,
        "c685ecfdfffff1c685edfdffff358b85fcfdffff9981e2ff01000003c2c1f8098885f7fdffff8a4d18888d00feffff8a551c889501feffff8a4520888502feffff8b8dfcfdffff518d9500feffff528d85ecfdffff5083ec108bcc8b55088911",
        "the LIB_SetCEDiePlane export constructs F1/35 and stores three caller bytes at descriptor offsets 0..2",
        ToolVendorCommandContract {
            name: "set-ce-die-plane",
            opcode_hex: "f1",
            subcommand_hex: Some("35"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "exactly 512 bytes; descriptor offsets 0,1,2 are the three caller scalar fields",
            cdb_layout: "00=F1; 01=35; 02..10=00; 11=01 sector; 12..15=00",
            classification: "raw-nand-topology-setup",
            semantic_basis: "exact PE export mapping, descriptor initialization, scalar stores, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-set-ecc-value",
        "LIB_SetECCValue",
        0x54,
        "c685ecfdfffff1c685edfdffff1b8b85fcfdffff9981e2ff01000003c2c1f8098885f7fdffff8a4d18888d00feffff8a551c889501feffff8a4520888502feffff8a4d24888d03feffff8b95fcfdffff528d8500feffff508d8decfdffff5183ec108bd48b450889",
        "the LIB_SetECCValue export constructs F1/1B and stores four caller bytes at descriptor offsets 0..3",
        ToolVendorCommandContract {
            name: "set-ecc-values",
            opcode_hex: "f1",
            subcommand_hex: Some("1b"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "exactly 512 bytes; descriptor offsets 0..3 are the four caller scalar fields",
            cdb_layout: "00=F1; 01=1B; 02..10=00; 11=01 sector; 12..15=00",
            classification: "raw-nand-ecc-setup",
            semantic_basis: "exact PE export mapping, descriptor initialization, scalar stores, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-set-page-table",
        "LIB_SetPageTable",
        0x6c,
        "c645ecf1c645ed1c8a45188845ee8b45fc9981e2ff01000003c2c1f8098845f78b4dfc518b551c528d45ec5083ec108bcc8b550889118b450c8941048b55108951088b451489410ce87c33ffff83c41c85c075188bf4686ce61210ff15",
        "the LIB_SetPageTable export constructs F1/1C with a caller selector and sector-ceiling transfer length",
        ToolVendorCommandContract {
            name: "set-page-table",
            opcode_hex: "f1",
            subcommand_hex: Some("1c"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "nonzero caller table; aligned lengths are unchanged and a partial sector is rounded up to the next sector; selector is CDB byte 2 and sector count is CDB byte 11",
            cdb_layout: "00=F1; 01=1C; 02=selector; 03..10=00; 11=derived sectors; 12..15=00",
            classification: "raw-nand-page-map-setup",
            semantic_basis: "exact PE export mapping, length branch, constructor, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-set-sector-table",
        "LIB_SetSectorTable",
        0x6c,
        "c645ecf1c645ed1d8a45188845ee8b45fc9981e2ff01000003c2c1f8098845f78b4dfc518b551c528d45ec5083ec108bcc8b550889118b450c8941048b55108951088b451489410ce84c32ffff83c41c85c075188bf46888e61210ff15",
        "the LIB_SetSectorTable export constructs F1/1D with a caller selector and sector-ceiling transfer length",
        ToolVendorCommandContract {
            name: "set-sector-table",
            opcode_hex: "f1",
            subcommand_hex: Some("1d"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "nonzero caller table; aligned lengths are unchanged and a partial sector is rounded up to the next sector; selector is CDB byte 2 and sector count is CDB byte 11",
            cdb_layout: "00=F1; 01=1D; 02=selector; 03..10=00; 11=derived sectors; 12..15=00",
            classification: "raw-nand-sector-map-setup",
            semantic_basis: "exact PE export mapping, length branch, constructor, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-erase-flash",
        "LIB_EraseFlash",
        0x9e,
        "c685ecfdfffff1c685edfdffff208b85fcfdffff9981e2ff01000003c2c1f8098885f7fdffff6a106a008d9500feffff52e8bc47000083c40c8a4518888500feffff8b4d1c81e1ffff0000c1f908888d02feffff8a551c889503feffff8b452025ffff0000c1f808888504feffff8a4d20888d05feffff8b95fcfdffff528d8500feffff508d8decfdffff5183ec108bd48b450889028b4d0c894a048b45108942088b4d14894a0ce81a2effff",
        "the LIB_EraseFlash export resolves to the F1/20 constructor, fixed 512-byte descriptor, and data-out transport call",
        ToolVendorCommandContract {
            name: "erase-flash-block-range-request",
            opcode_hex: "f1",
            subcommand_hex: Some("20"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "exactly 512 bytes; descriptor byte 0 is CE, bytes 2..3 are block count BE16, and bytes 4..5 are start block BE16",
            cdb_layout: "00=F1; 01=20; 02..10=00; 11=01 sector; 12..15=00",
            classification: "destructive-physical-erase-request",
            semantic_basis: "exact PE export mapping, command constructor, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-write-flash",
        "LIB_WriteFlash",
        0x9e,
        "c685ecfdfffff1c685edfdffff238b85fcfdffff9981e2ff01000003c2c1f8098885f7fdffff6a106a008d9500feffff52e8dc42000083c40c8a4518888500feffff8b4d1c81e1ffff0000c1f908888d02feffff8a551c889503feffff8b452025ffff0000c1f808888504feffff8a4d20888d05feffff8b552481e2ffff0000c1fa08889508feffff8a4524888509feffff8b4d2881e1ffff00008b552481e2ffff00003bca7d1c8b452425ffff0000c1f80888850afeffff8a4d24888d0bfeffff",
        "the LIB_WriteFlash export resolves to the F1/23 raw-flash write-request constructor",
        ToolVendorCommandContract {
            name: "write-flash-page-range-request",
            opcode_hex: "f1",
            subcommand_hex: Some("23"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "exactly 512 bytes; descriptor carries CE and four bounded BE16 range fields",
            cdb_layout: "00=F1; 01=23; 02..10=00; 11=01 sector; 12..15=00",
            classification: "state-changing-raw-nand-request",
            semantic_basis: "exact PE export mapping, command constructor, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-read-flash",
        "LIB_ReadFlash",
        0x9e,
        "c685ecfdfffff1c685edfdffff258b85fcfdffff9981e2ff01000003c2c1f8098885f7fdffff6a106a008d9500feffff52e8fc3e000083c40c8a4518888500feffff8b4d1c81e1ffff0000c1f908888d02feffff8a551c889503feffff8b452025ffff0000c1f808888504feffff8a4d20888d05feffff8b552481e2ffff0000c1fa08889508feffff8a4524888509feffff8b4d2881e1ffff00008b552481e2ffff00003bca7d1c8b452425ffff0000c1f80888850afeffff8a4d24888d0bfeffff",
        "the LIB_ReadFlash export resolves to the F1/25 raw-flash read-request constructor; this request itself is data-out",
        ToolVendorCommandContract {
            name: "read-flash-page-range-request",
            opcode_hex: "f1",
            subcommand_hex: Some("25"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "exactly 512 bytes; descriptor carries CE and four bounded BE16 range fields",
            cdb_layout: "00=F1; 01=25; 02..10=00; 11=01 sector; 12..15=00",
            classification: "read-trigger-raw-nand-request",
            semantic_basis: "exact PE export mapping proves the trigger is separate from subsequent data/ECC retrieval",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-check-status",
        "LIB_CheckStatus",
        0x54,
        "c685ecfdfffff1c685edfdffff188b85fcfdffff9981e2ff01000003c2c1f8098885f7fdffff8a4d18888d00feffff8b95fcfdffff528d8500feffff508d8decfdffff5183ec108bd48b450889028b4d0c894a048b45108942088b4d14894a0c",
        "the LIB_CheckStatus export resolves to the F1/18 fixed descriptor request",
        ToolVendorCommandContract {
            name: "check-flash-operation-status-request",
            opcode_hex: "f1",
            subcommand_hex: Some("18"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "exactly 512 bytes; descriptor byte 0 is the caller status selector",
            cdb_layout: "00=F1; 01=18; 02..10=00; 11=01 sector; 12..15=00",
            classification: "read-trigger-status-request",
            semantic_basis: "exact PE export mapping, command constructor, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-reset-flash",
        "LIB_ResetFlash",
        0x54,
        "c685ecfdfffff1c685edfdffff1e8b85fcfdffff9981e2ff01000003c2c1f8098885f7fdffff8b8dfcfdffff518d9500feffff528d85ecfdffff5083ec108bcc8b550889118b450c8941048b55108951088b451489410ce82531ffff83c41c85",
        "the LIB_ResetFlash export resolves to the F1/1E fixed reset request",
        ToolVendorCommandContract {
            name: "reset-flash-interface-request",
            opcode_hex: "f1",
            subcommand_hex: Some("1e"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "exactly 512 zero bytes",
            cdb_layout: "00=F1; 01=1E; 02..10=00; 11=01 sector; 12..15=00",
            classification: "state-changing-flash-reset",
            semantic_basis: "exact PE export mapping, command constructor, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-read-ram",
        "LIB_UFDReadRam",
        0x97,
        "c685ecf7fffff0c685edf7ffff048b4d1881e1ffff0000c1f908888deef7ffff8a55188895eff7ffff8b85fcf7ffff9981e2ff01000003c2c1f8098885f7f7ffff8b85fcf7ffff508b4d1c518d95ecf7ffff5283ec108bc48b4d0889088b550c8950048b4d108948088b551489500ce8e5fafeff83c41c85c07518",
        "the LIB_UFDReadRam export resolves to the bounded F0/04 controller-RAM read constructor",
        ToolVendorCommandContract {
            name: "read-controller-ram-window",
            opcode_hex: "f0",
            subcommand_hex: Some("04"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "caller bytes in 1..=2048; CDB sector count is ceil(bytes/512)",
            cdb_layout: "00=F0; 01=04; 02..03=RAM address BE16; 04..10=00; 11=sector count; 12..15=00",
            classification: "read-only-controller-memory",
            semantic_basis: "exact PE export mapping, 0x800 bound, constructor, and data-in call",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-write-ram",
        "LIB_UFDWriteRam",
        0x97,
        "c685ecf7fffff1c685edf7ffff048b4d1881e1ffff0000c1f908888deef7ffff8a55188895eff7ffff8b85fcf7ffff9981e2ff01000003c2c1f8098885f7f7ffff8b85fcf7ffff508d8d00f8ffff518d95ecf7ffff5283ec108bc48b4d0889088b550c8950048b4d108948088b551489500ce88710ffff83c41c85",
        "the LIB_UFDWriteRam export resolves to the bounded F1/04 controller-RAM write constructor",
        ToolVendorCommandContract {
            name: "write-controller-ram-window",
            opcode_hex: "f1",
            subcommand_hex: Some("04"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "caller bytes in 1..=2048; CDB sector count is ceil(bytes/512)",
            cdb_layout: "00=F1; 01=04; 02..03=RAM address BE16; 04..10=00; 11=sector count; 12..15=00",
            classification: "state-changing-controller-memory",
            semantic_basis: "exact PE export mapping, 0x800 bound, constructor, and data-out call",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-call-address",
        "LIB_UFDCallAddress",
        0x28,
        "c645f0f1c645f10ac645f2a0c645f3008b451c9981e2ff01000003c2c1f8098845fb8b4d1c518b5518528d45f05083ec108bcc8b550889118b450c8941048b55108951088b451489410ce83e43ffff83c41c",
        "the LIB_UFDCallAddress export resolves to the F1/0A/A0 service-code transition constructor",
        ToolVendorCommandContract {
            name: "call-uploaded-controller-code",
            opcode_hex: "f1",
            subcommand_hex: Some("0a"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "caller bytes; CDB sector count is ceil(bytes/512)",
            cdb_layout: "00=F1; 01=0A; 02=A0; 03=00; 04..10=00; 11=sector count; 12..15=00",
            classification: "state-changing-service-code-transition",
            semantic_basis: "exact PE export mapping, constructor, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-read-info",
        "LIB_ReadInfo",
        0x3b,
        "c645f0f0c645f136c645fb0268000400008b4d18518d55f05283ec108bc48b4d0889088b550c8950048b4d108948088b551489500ce81b01ffff83c41c85c075188bf468ccea1210ff150c6315103bf4e8a0",
        "the LIB_ReadInfo export resolves to a fixed 1024-byte F0/36 data-in command",
        ToolVendorCommandContract {
            name: "read-operation-info",
            opcode_hex: "f0",
            subcommand_hex: Some("36"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "exactly 1024 bytes",
            cdb_layout: "00=F0; 01=36; 02..10=00; 11=02 sectors; 12..15=00",
            classification: "read-only-operation-result",
            semantic_basis: "exact PE export mapping, fixed-size guard, constructor, and data-in call",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-read-ecc-table",
        "LIB_ReadECCTable",
        0x6d,
        "c645e8f0c645e9338a55fc8855eac645f30268000400008b45fc25ff000000c1e00a8b4d1c03c8518d55e85283ec108bc48b4d0889088b550c8950048b4d108948088b551489500ce80605ffff83c41c85c075188bf4684cea1210ff150c6315",
        "the LIB_ReadECCTable export resolves to indexed 1024-byte F0/33 reads with an 8192-byte aggregate bound",
        ToolVendorCommandContract {
            name: "read-page-ecc-table",
            opcode_hex: "f0",
            subcommand_hex: Some("33"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "1024-byte chunks; aggregate length truncated to 8192 bytes; chunk index in CDB byte 2",
            cdb_layout: "00=F0; 01=33; 02=chunk index; 03..10=00; 11=02 sectors; 12..15=00",
            classification: "read-only-ecc-metadata",
            semantic_basis: "exact PE export mapping, bounded loop, constructor, and data-in call",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-read-metadata-ecc",
        "LIB_ReadMetaDataECCTable",
        0x3b,
        "c645f0f0c645f134c645fb0168000200008b4d18518d55f05283ec108bc48b4d0889088b550c8950048b4d108948088b551489500ce80b04ffff83c41c85c075188bf46868ea1210ff150c6315103bf4e890",
        "the LIB_ReadMetaDataECCTable export resolves to a fixed 512-byte F0/34 data-in command",
        ToolVendorCommandContract {
            name: "read-metadata-ecc-table",
            opcode_hex: "f0",
            subcommand_hex: Some("34"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "exactly 512 bytes",
            cdb_layout: "00=F0; 01=34; 02..10=00; 11=01 sector; 12..15=00",
            classification: "read-only-controller-metadata",
            semantic_basis: "exact PE export mapping, fixed-size guard, constructor, and data-in call",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-read-original-bad-columns",
        "LIB_ReadOrgBadColTable",
        0x49,
        "c645f0f0c645f1318b451c9981e2ff01000003c2c1f8098845fb8b551c528b4518508d4df05183ec108bd48b450889028b4d0c894a048b45108942088b4d14894a0ce83006ffff83c41c85c075188bf46828ea1210ff150c6315103bf4e8b51c",
        "the LIB_ReadOrgBadColTable export resolves to a caller-sized, sector-aligned F0/31 data-in command",
        ToolVendorCommandContract {
            name: "read-original-bad-column-table",
            opcode_hex: "f0",
            subcommand_hex: Some("31"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "nonzero caller length divisible by 512; sector count encoded in CDB byte 11",
            cdb_layout: "00=F0; 01=31; 02..10=00; 11=sector count; 12..15=00",
            classification: "read-only-factory-bad-block-metadata",
            semantic_basis: "exact PE export mapping, alignment guard, constructor, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-read-rb-fail-table",
        "LIB_ReadRBFailBitTable",
        0x3b,
        "c645f0f0c645f135c645fb0168000200008b4d18518d55f05283ec108bc48b4d0889088b550c8950048b4d108948088b551489500ce8fb01ffff83c41c85c075188bf468a8ea1210ff150c6315103bf4e880",
        "the LIB_ReadRBFailBitTable export resolves to a fixed 512-byte F0/35 data-in command",
        ToolVendorCommandContract {
            name: "read-retired-block-fail-bit-table",
            opcode_hex: "f0",
            subcommand_hex: Some("35"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "exactly 512 bytes",
            cdb_layout: "00=F0; 01=35; 02..10=00; 11=01 sector; 12..15=00",
            classification: "read-only-retired-block-metadata",
            semantic_basis: "exact PE export mapping, fixed-size guard, constructor, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-read-index",
        "LIB_ReadIndex",
        0x3e,
        "c645f0f0c645f1328b4d1881e1ffff0000c1f908884df28a55188855f38b451c25ffff0000c1f8088845f48a4d1c884df58b552081e2ffff0000c1fa088855f68a45208845f7c645fb0168000200008b4d24518d55f05283ec108bc48b4d0889088b550c8950048b4d108948088b551489500ce8ea02ffff",
        "the LIB_ReadIndex export resolves to the indexed 512-byte F0/32 metadata read constructor",
        ToolVendorCommandContract {
            name: "read-index-metadata-page",
            opcode_hex: "f0",
            subcommand_hex: Some("32"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "exactly 512 bytes",
            cdb_layout: "00=F0; 01=32; 02..03,04..05,06..07=three caller values BE16; 08..10=00; 11=01 sector; 12..15=00",
            classification: "read-only-index-metadata",
            semantic_basis: "exact PE export mapping, fixed-size guard, constructor, and data-in call",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-write-index",
        "LIB_WriteIndex",
        0x54,
        "c685ecfdfffff1c685edfdffff288b4d1881e1ffff0000c1f908888deefdffff8a55188895effdffff8b451c25ffff0000c1f8088885f0fdffff8a4d1c888df1fdffff8b552081e2ffff0000c1fa088895f2fdffff8a45208885f3fdffff8b85fcfdffff9981e2ff01000003c2c1f8098885f7fdffff8b4d2481e1ffff0000c1f908888d00feffff8a5524889501feffff8b452825ffff0000c1f808888502fe",
        "the LIB_WriteIndex export resolves to the F1/28 indexed metadata write constructor",
        ToolVendorCommandContract {
            name: "write-index-metadata-page",
            opcode_hex: "f1",
            subcommand_hex: Some("28"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "exactly 512 bytes; three BE16 index values occur in both CDB and descriptor",
            cdb_layout: "00=F1; 01=28; 02..03,04..05,06..07=three caller values BE16; 08..10=00; 11=01 sector; 12..15=00",
            classification: "state-changing-index-metadata",
            semantic_basis: "exact PE export mapping, constructor, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-read-original-retry",
        "LIB_ReadOriginalReadRetry",
        0x3b,
        "c645f0f0c645f13ac645fb028b4d1c518b5518528d45f05083ec108bcc8b550889118b450c8941048b55108951088b451489410ce81cf8feff83c41c85c075188bf46870eb1210ff150c6315103bf4e8a10e",
        "the LIB_ReadOriginalReadRetry export resolves to a fixed 1024-byte F0/3A data-in command",
        ToolVendorCommandContract {
            name: "read-original-read-retry-table",
            opcode_hex: "f0",
            subcommand_hex: Some("3a"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "exactly 1024 bytes",
            cdb_layout: "00=F0; 01=3A; 02..10=00; 11=02 sectors; 12..15=00",
            classification: "read-only-read-retry-metadata",
            semantic_basis: "exact PE export mapping, size guard, constructor, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-do-read-retry",
        "LIB_DoReadRetry",
        0x5d,
        "c685ecfdfffff1c685edfdffff388b85fcfdffff9981e2ff01000003c2c1f8098885f7fdffff8b95fcfdffff528d8500feffff508d8decfdffff5183ec108bd48b450889028b4d0c894a048b45108942088b4d14894a0ce8bc0dffff83c41c85c075188b",
        "the LIB_DoReadRetry export resolves to the fixed F1/38 retry request constructor",
        ToolVendorCommandContract {
            name: "apply-read-retry-request",
            opcode_hex: "f1",
            subcommand_hex: Some("38"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "exactly 512 bytes; retry descriptor byte 0 is caller supplied",
            cdb_layout: "00=F1; 01=38; 02..10=00; 11=01 sector; 12..15=00",
            classification: "state-changing-read-retry",
            semantic_basis: "exact PE export mapping, constructor, and named factory ABI",
        },
    );
    append_exported_vendor_command!(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "smi-exported-boot-card-mode",
        "LIB_UFDBootCardMode",
        0x28,
        "c645f0f1c645f104c645f2c0c645f3008b451c9981e2ff01000003c2c1f8098845fb8b4d1c518b5518528d45f05083ec108bcc8b550889118b450c8941048b55108951088b451489410ce85e42ffff83c41c",
        "the LIB_UFDBootCardMode export resolves to the F1/04/C0 boot-card transition constructor",
        ToolVendorCommandContract {
            name: "enter-boot-card-mode",
            opcode_hex: "f1",
            subcommand_hex: Some("04c0"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "caller bytes; CDB sector count is ceil(bytes/512)",
            cdb_layout: "00=F1; 01=04; 02=C0; 03=00; 04..10=00; 11=sector count; 12..15=00",
            classification: "state-changing-service-mode-transition",
            semantic_basis: "exact PE export mapping, constructor, and named factory ABI",
        },
    );
    if sha256 == crate::smi_ufdif::UFDIF_SOURCE_SHA256
        && vendor_commands.len() != crate::smi_ufdif::REVIEWED_UFDIF_COMMAND_COUNT
    {
        return None;
    }
    evidence.sort_by_key(|item| item.offset);
    Some(ToolHostTransportContract {
        family: Family::SiliconMotionUfd.as_str(),
        source_path: path.to_path_buf(),
        source_size_bytes: size_bytes,
        source_sha256: sha256.to_string(),
        source_format: format,
        provenance: "untrusted-unsigned-factory-tool-executable",
        transport: "windows-scsi-pass-through-direct",
        ioctl_codes_hex: vec!["0004d014"],
        sptd_header_bytes: 0x2c,
        sense_bytes: 0,
        outer_buffer_bytes: 0x50,
        timeout_seconds: vec![300],
        transfer_unit_bytes: 1,
        retry_attempts: 8,
        cdb_lengths: vec![16],
        data_directions: vec!["to-device", "from-device"],
        read_only_commands: Vec::new(),
        vendor_commands,
        evidence,
        corroborating_source: Some(SMI_PRIMARY_IMPLEMENTATION_SOURCE),
        contract_scope: "host transport plus all 53 command-producing named exports authenticated to their exact PE targets: electrical/timing/topology setup, raw flash read/write/erase, controller RAM, bad-column data, status/result, ECC, retired-block/index metadata, read-retry, copy-back, differential maps, and service transitions; handle/version/timeout accessors and the two generic SCSI wrappers are intentionally not classified as vendor commands; exact controller/firmware/NAND tuple, response semantics, service entry points, recovery behavior, and final HIL qualification remain separate",
        production_eligible: false,
    })
}

fn smi_sm32xtest_transport_contract(
    path: &Path,
    size_bytes: u64,
    sha256: &str,
    format: &'static str,
    bytes: &[u8],
) -> Option<ToolHostTransportContract> {
    if format != "portable-executable" {
        return None;
    }
    let mut evidence = Vec::new();
    for (role, signature, interpretation) in [
        (
            "spt-header-length",
            &[0x66, 0xc7, 0x85, 0xb0, 0xf7, 0xff, 0xff, 0x2c, 0x00][..],
            "SCSI_PASS_THROUGH.Length is 0x2c",
        ),
        (
            "inquiry-envelope",
            &[
                0xc6, 0x85, 0xb6, 0xf7, 0xff, 0xff, 0x06, 0xc6, 0x85, 0xb7, 0xf7, 0xff, 0xff, 0x00,
                0xc6, 0x85, 0xb8, 0xf7, 0xff, 0xff, 0x01,
            ][..],
            "CdbLength is 6, SenseInfoLength is zero, and DataIn is 1",
        ),
        (
            "inquiry-transfer-length",
            &[0xc7, 0x85, 0xbc, 0xf7, 0xff, 0xff, 0x24, 0x00, 0x00, 0x00][..],
            "standard INQUIRY requests 36 response bytes",
        ),
        (
            "inquiry-timeout",
            &[0xc7, 0x85, 0xc0, 0xf7, 0xff, 0xff, 0x05, 0x00, 0x00, 0x00][..],
            "standard INQUIRY timeout is 5 seconds",
        ),
        (
            "data-and-sense-offsets",
            &[
                0xc7, 0x85, 0xc4, 0xf7, 0xff, 0xff, 0x50, 0x00, 0x00, 0x00, 0xc7, 0x85, 0xc8, 0xf7,
                0xff, 0xff, 0x30, 0x00, 0x00, 0x00,
            ][..],
            "DataBufferOffset is 0x50 and SenseInfoOffset is 0x30",
        ),
        (
            "standard-inquiry-cdb",
            &[
                0xc6, 0x85, 0xcc, 0xf7, 0xff, 0xff, 0x12, 0xc6, 0x85, 0xd0, 0xf7, 0xff, 0xff, 0x24,
            ][..],
            "CDB opcode is 0x12 with allocation length 0x24",
        ),
        (
            "ioctl-scsi-pass-through-buffered",
            &[0x68, 0x04, 0xd0, 0x04, 0x00][..],
            "DeviceIoControl uses IOCTL_SCSI_PASS_THROUGH 0x0004d004",
        ),
    ] {
        evidence.push(exact_contract_evidence(
            bytes,
            role,
            signature,
            interpretation,
        )?);
    }
    evidence.sort_by_key(|item| item.offset);
    Some(ToolHostTransportContract {
        family: Family::SiliconMotionUfd.as_str(),
        source_path: path.to_path_buf(),
        source_size_bytes: size_bytes,
        source_sha256: sha256.to_string(),
        source_format: format,
        provenance: "untrusted-unsigned-factory-tool-executable",
        transport: "windows-scsi-pass-through-buffered",
        ioctl_codes_hex: vec!["0004d004"],
        sptd_header_bytes: 0x2c,
        sense_bytes: 0,
        outer_buffer_bytes: 0x850,
        timeout_seconds: vec![5],
        transfer_unit_bytes: 1,
        retry_attempts: 1,
        cdb_lengths: vec![6],
        data_directions: vec!["from-device"],
        read_only_commands: vec![ToolReadOnlyCommandContract {
            name: "standard-inquiry",
            cdb_hex: "120000002400",
            cdb_length: 6,
            data_direction: "from-device",
            transfer_bytes: 36,
            response_layout: "standard SCSI INQUIRY response",
        }],
        vendor_commands: Vec::new(),
        evidence,
        corroborating_source: Some(SMI_PRIMARY_IMPLEMENTATION_SOURCE),
        contract_scope: "host transport and standard read-only INQUIRY wrapper only",
        production_eligible: false,
    })
}

fn phison_getinfo_transport_contract(
    path: &Path,
    size_bytes: u64,
    sha256: &str,
    format: &'static str,
    bytes: &[u8],
) -> Option<ToolHostTransportContract> {
    if format != "portable-executable" {
        return None;
    }
    let mut evidence = Vec::new();
    for (role, signature, interpretation) in [
        (
            "cdb-length-bound",
            &[0x83, 0x7d, 0x0c, 0x10, 0x76][..],
            "the generic direct builder accepts CDB lengths through 16 bytes",
        ),
        (
            "sptd-header-length",
            &[
                0xb9, 0x2c, 0x00, 0x00, 0x00, 0x8b, 0x55, 0x08, 0x66, 0x89, 0x0a,
            ][..],
            "SCSI_PASS_THROUGH_DIRECT.Length is 0x2c",
        ),
        (
            "sense-length",
            &[0xc6, 0x42, 0x07, 0x18][..],
            "SenseInfoLength is 0x18",
        ),
        (
            "sense-offset",
            &[0xc7, 0x42, 0x18, 0x30, 0x00, 0x00, 0x00][..],
            "SenseInfoOffset is 0x30",
        ),
        (
            "data-in-direction",
            &[0xc6, 0x45, 0xa8, 0x01][..],
            "the direct wrapper accepts DataIn value 1",
        ),
        (
            "data-out-direction",
            &[0xc6, 0x45, 0xa8, 0x00][..],
            "the direct wrapper accepts DataIn value 0",
        ),
        (
            "data-unspecified-direction",
            &[0xc6, 0x45, 0xa8, 0x02][..],
            "the direct wrapper accepts DataIn value 2",
        ),
        (
            "nand-id-command",
            &[
                0xc6, 0x45, 0xe4, 0x06, 0xc6, 0x45, 0xe5, 0x56, 0x6a, 0x0a, 0x68, 0x00, 0x02, 0x00,
                0x00, 0x6a, 0x01,
            ][..],
            "read-only 06 56 NAND-ID command uses a 10-second timeout and 512-byte response",
        ),
        (
            "ioctl-scsi-pass-through-buffered",
            &[0x68, 0x04, 0xd0, 0x04, 0x00][..],
            "DeviceIoControl uses IOCTL_SCSI_PASS_THROUGH 0x0004d004",
        ),
        (
            "ioctl-scsi-pass-through-direct",
            &[0x68, 0x14, 0xd0, 0x04, 0x00][..],
            "DeviceIoControl uses IOCTL_SCSI_PASS_THROUGH_DIRECT 0x0004d014",
        ),
    ] {
        evidence.push(exact_contract_evidence(
            bytes,
            role,
            signature,
            interpretation,
        )?);
    }
    evidence.push(masked_contract_evidence(
        bytes,
        "buffered-envelope-bound",
        &[0x68, 0x50, 0x80, 0x00, 0x00, 0x6a, 0x00, 0x68, 0, 0, 0, 0],
        &[0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0],
        "the buffered SPT workspace is cleared to 0x8050 bytes",
    )?);
    evidence.sort_by_key(|item| item.offset);
    Some(ToolHostTransportContract {
        family: Family::PhisonUfd.as_str(),
        source_path: path.to_path_buf(),
        source_size_bytes: size_bytes,
        source_sha256: sha256.to_string(),
        source_format: format,
        provenance: "untrusted-unsigned-factory-tool-executable",
        transport: "windows-scsi-pass-through-buffered-and-direct",
        ioctl_codes_hex: vec!["0004d004", "0004d014"],
        sptd_header_bytes: 0x2c,
        sense_bytes: 0x18,
        outer_buffer_bytes: 0x8050,
        timeout_seconds: vec![10],
        transfer_unit_bytes: 1,
        retry_attempts: 1,
        cdb_lengths: vec![12, 16],
        data_directions: vec!["to-device", "from-device", "unspecified"],
        read_only_commands: vec![ToolReadOnlyCommandContract {
            name: "read-nand-id",
            cdb_hex: "065600000000000000000000",
            cdb_length: 12,
            data_direction: "from-device",
            transfer_bytes: 512,
            response_layout: "factory-tool NAND identification response",
        }],
        vendor_commands: Vec::new(),
        evidence,
        corroborating_source: Some(PHISON_PRIMARY_IMPLEMENTATION_SOURCE),
        contract_scope: "host transport and read-only NAND-ID command only",
        production_eligible: false,
    })
}

fn firstchip_entryappite_transport_contract(
    path: &Path,
    size_bytes: u64,
    sha256: &str,
    format: &'static str,
    bytes: &[u8],
) -> Option<ToolHostTransportContract> {
    if format != "portable-executable" {
        return None;
    }
    let mut evidence = Vec::new();
    for (role, signature, interpretation) in [
        (
            "direct-header",
            &[
                0xba, 0x2c, 0x00, 0x00, 0x00, 0x66, 0x89, 0x55, 0x98, 0xc6, 0x45, 0x9b, 0x00, 0xc6,
                0x45, 0x9c, 0x01, 0xc6, 0x45, 0x9d, 0x00, 0x8a, 0x45, 0x24, 0x88, 0x45, 0x9e, 0xc6,
                0x45, 0x9f, 0x18,
            ][..],
            "direct SPTD header is 0x2c bytes, target ID is 1, and sense length is 0x18",
        ),
        (
            "direct-caller-fields",
            &[
                0x8a, 0x4d, 0x18, 0x88, 0x4d, 0xa0, 0x8b, 0x55, 0x14, 0x89, 0x55, 0xa4, 0x8b, 0x45,
                0x20, 0x89, 0x45, 0xa8, 0x8b, 0x4d, 0x10, 0x89, 0x4d, 0xac,
            ][..],
            "data direction, transfer length, timeout, and direct data pointer are caller supplied",
        ),
        (
            "direct-sense-offset",
            &[0xc7, 0x45, 0xb0, 0x30, 0x00, 0x00, 0x00][..],
            "direct SenseInfoOffset is 0x30",
        ),
        (
            "ioctl-scsi-pass-through-direct",
            &[0x68, 0x14, 0xd0, 0x04, 0x00][..],
            "DeviceIoControl uses IOCTL_SCSI_PASS_THROUGH_DIRECT 0x0004d014",
        ),
        (
            "buffered-workspace",
            &[0x68, 0x50, 0x04, 0x00, 0x00, 0x6a, 0x00][..],
            "buffered SPT workspace is cleared to 0x450 bytes",
        ),
        (
            "buffered-header",
            &[
                0xba, 0x2c, 0x00, 0x00, 0x00, 0x66, 0x89, 0x95, 0x40, 0xfb, 0xff, 0xff,
            ][..],
            "buffered SPT header Length is 0x2c",
        ),
        (
            "buffered-offsets",
            &[
                0xc7, 0x85, 0x54, 0xfb, 0xff, 0xff, 0x50, 0x00, 0x00, 0x00, 0xc7, 0x85, 0x58, 0xfb,
                0xff, 0xff, 0x30, 0x00, 0x00, 0x00,
            ][..],
            "buffered DataBufferOffset is 0x50 and SenseInfoOffset is 0x30",
        ),
        (
            "ioctl-scsi-pass-through-buffered",
            &[0x68, 0x04, 0xd0, 0x04, 0x00][..],
            "DeviceIoControl uses IOCTL_SCSI_PASS_THROUGH 0x0004d004",
        ),
    ] {
        evidence.push(exact_contract_evidence(
            bytes,
            role,
            signature,
            interpretation,
        )?);
    }
    evidence.sort_by_key(|item| item.offset);
    Some(ToolHostTransportContract {
        family: Family::FirstchipUfd.as_str(),
        source_path: path.to_path_buf(),
        source_size_bytes: size_bytes,
        source_sha256: sha256.to_string(),
        source_format: format,
        provenance: "untrusted-unsigned-factory-tool-executable",
        transport: "windows-scsi-pass-through-buffered-and-direct",
        ioctl_codes_hex: vec!["0004d004", "0004d014"],
        sptd_header_bytes: 0x2c,
        sense_bytes: 0x18,
        outer_buffer_bytes: 0x450,
        timeout_seconds: Vec::new(),
        transfer_unit_bytes: 1,
        retry_attempts: 1,
        cdb_lengths: Vec::new(),
        data_directions: vec!["caller-supplied"],
        read_only_commands: Vec::new(),
        vendor_commands: Vec::new(),
        evidence,
        corroborating_source: None,
        contract_scope: "host transport only; caller-supplied CDB, timeout, and command semantics remain unasserted",
        production_eligible: false,
    })
}

fn chipsbank_aptool_transport_contract(
    path: &Path,
    size_bytes: u64,
    sha256: &str,
    format: &'static str,
    bytes: &[u8],
) -> Option<ToolHostTransportContract> {
    if format != "portable-executable" {
        return None;
    }
    let mut evidence = Vec::new();
    for (role, signature, interpretation) in [
        (
            "buffered-workspace",
            &[0x68, 0x50, 0x10, 0x02, 0x00, 0x6a, 0x00][..],
            "buffered SPT workspace is cleared to 0x21050 bytes",
        ),
        (
            "spt-header-length",
            &[
                0xb9, 0x2c, 0x00, 0x00, 0x00, 0x66, 0x89, 0x8d, 0xa8, 0xef, 0xfd, 0xff,
            ][..],
            "SCSI_PASS_THROUGH.Length is 0x2c",
        ),
        (
            "sense-length",
            &[0xc6, 0x85, 0xaf, 0xef, 0xfd, 0xff, 0x18][..],
            "SenseInfoLength is 0x18",
        ),
        (
            "timeout",
            &[0xc7, 0x85, 0xb8, 0xef, 0xfd, 0xff, 0x2c, 0x01, 0x00, 0x00][..],
            "timeout is 0x12c or 300 seconds",
        ),
        (
            "cdb-length-cap",
            &[
                0x83, 0x7d, 0x0c, 0x10, 0x73, 0x0b, 0x8b, 0x55, 0x0c, 0x89, 0x95, 0x84, 0xef, 0xfd,
                0xff,
            ][..],
            "caller CDB length is capped at 16 bytes",
        ),
        (
            "data-direction",
            &[0x8a, 0x45, 0x10, 0x88, 0x85, 0xb0, 0xef, 0xfd, 0xff][..],
            "DataIn is caller supplied",
        ),
        (
            "data-and-sense-offsets",
            &[
                0xc7, 0x85, 0xbc, 0xef, 0xfd, 0xff, 0x50, 0x00, 0x00, 0x00, 0xc7, 0x85, 0xc0, 0xef,
                0xfd, 0xff, 0x30, 0x00, 0x00, 0x00,
            ][..],
            "DataBufferOffset is 0x50 and SenseInfoOffset is 0x30",
        ),
        (
            "ioctl-scsi-pass-through-buffered",
            &[0x68, 0x04, 0xd0, 0x04, 0x00][..],
            "DeviceIoControl uses IOCTL_SCSI_PASS_THROUGH 0x0004d004",
        ),
        (
            "retry-bound",
            &[0x83, 0xbd, 0x8c, 0xef, 0xfd, 0xff, 0x64][..],
            "ERROR_GEN_FAILURE retry loop stops after 100 attempts",
        ),
    ] {
        evidence.push(exact_contract_evidence(
            bytes,
            role,
            signature,
            interpretation,
        )?);
    }
    evidence.sort_by_key(|item| item.offset);
    Some(ToolHostTransportContract {
        family: Family::ChipsbankUfd.as_str(),
        source_path: path.to_path_buf(),
        source_size_bytes: size_bytes,
        source_sha256: sha256.to_string(),
        source_format: format,
        provenance: "untrusted-unsigned-factory-tool-executable",
        transport: "windows-scsi-pass-through-buffered",
        ioctl_codes_hex: vec!["0004d004"],
        sptd_header_bytes: 0x2c,
        sense_bytes: 0x18,
        outer_buffer_bytes: 0x21050,
        timeout_seconds: vec![300],
        transfer_unit_bytes: 1,
        retry_attempts: 100,
        cdb_lengths: vec![16],
        data_directions: vec!["caller-supplied"],
        read_only_commands: Vec::new(),
        vendor_commands: Vec::new(),
        evidence,
        corroborating_source: None,
        contract_scope: "host transport bounds only; CDB values and controller command semantics remain unasserted",
        production_eligible: false,
    })
}

fn append_exact_vendor_command(
    bytes: &[u8],
    evidence: &mut Vec<ToolContractEvidence>,
    commands: &mut Vec<ToolVendorCommandContract>,
    role: &'static str,
    signature_hex: &str,
    interpretation: &'static str,
    command: ToolVendorCommandContract,
) -> bool {
    let Ok(signature) = hex::decode(signature_hex) else {
        return false;
    };
    let Some(item) = exact_contract_evidence(bytes, role, &signature, interpretation) else {
        return false;
    };
    evidence.push(item);
    commands.push(command);
    true
}

fn chipsbank_apdevice_command_contract(
    path: &Path,
    size_bytes: u64,
    sha256: &str,
    format: &'static str,
    bytes: &[u8],
) -> Option<ToolHostTransportContract> {
    if format != "portable-executable" {
        return None;
    }
    let common_signature = hex::decode(
        "8b4c241485c975028bce8b7424208b50048b00568b742420568b74242056518b4c2420518b4c2420518b4c2420518bc8ffd2",
    )
    .ok()?;
    let mut evidence = vec![exact_contract_evidence(
        bytes,
        "seven-argument-command-forwarder",
        &common_signature,
        "the operation library forwards CDB, CDB length, DataIn, sense/result, data pointer, transfer length, and byte count to the host callback",
    )?];
    let mut vendor_commands = Vec::new();

    append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "command-ea-e3",
        "8bd36a108d442420c1ea0250c6442424ea6689542427c6442433e3e8f6feffff",
        "EA/E3 builds a 16-byte data-in CDB after enforcing four-byte alignment, a sub-0x2000 chunk, and a 0x6000 memory-window bound",
        ToolVendorCommandContract {
            name: "read-controller-memory-window",
            opcode_hex: "ea",
            subcommand_hex: Some("e3"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "caller bytes; four-byte aligned; each chunk < 0x2000; offset + bytes < 0x6000",
            cdb_layout: "00=EA; 01..02=offset/4 LE16; 03..04=bytes/4 LE16; 05..14=00; 15=E3",
            classification: "read-only",
            semantic_basis: "exact constructor and chunked controller-memory read call graph",
        },
    );
    append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "command-ea-e0",
        "c1e0095052884c24178a4c243c6a006a01884c24266a108d4c241c518bcec6442420eac644242fe0",
        "EA/E0 multiplies its one-byte sector count by 512 and submits a 16-byte data-in CDB",
        ToolVendorCommandContract {
            name: "read-service-physical-sectors",
            opcode_hex: "ea",
            subcommand_hex: Some("e0"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "sector_count * 512 bytes",
            cdb_layout: "00=EA; 01..04=address LE32; 05..06=00; 07=selector; 08=unit; 09=sector_count; 10..13=00; 14=mode; 15=E0",
            classification: "read-only",
            semantic_basis: "exact constructor and paired physical write/read verification call graph",
        },
    );
    append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "command-ea-e1",
        "0fb6d2894424098a44242cc1e20952884424138a442434566a008844241c8a4424406a00884424266a108d44241c50c6442420eac644242fe1",
        "EA/E1 accepts 1..32 sectors, multiplies the count by 512, and submits a 16-byte data-out CDB",
        ToolVendorCommandContract {
            name: "write-service-physical-sectors",
            opcode_hex: "ea",
            subcommand_hex: Some("e1"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "sector_count * 512 bytes; sector_count in 1..=32",
            cdb_layout: "00=EA; 01..04=address LE32; 05..06=00; 07=selector; 08=unit; 09=sector_count; 10..13=00; 14=mode; 15=E1",
            classification: "state-changing",
            semantic_basis: "exact constructor and paired physical write/read verification call graph",
        },
    );
    let erase_batch = hex::decode(
        "8b4424142bc3c1f8023d800000008bf07c05be800000008b4c24108b1183c208528d4c241ce82508faff8b4424108b080fb691a95c00008b45105250568d3cb50000000057538d4c242ce8700afaff85c074a403df3b5c241475a55f",
    )
    .ok()
    .and_then(|signature| {
        exact_contract_evidence(
            bytes,
            "erase-batch-128-dword-bound",
            &signature,
            "the erase dispatcher caps each payload at 128 four-byte entries before invoking EA/E2",
        )
    });
    let erase_dispatch = hex::decode(
        "8b5424208b4c24280fafd66a01528d44243850e802feffff85c0742a",
    )
    .ok()
    .and_then(|signature| {
        exact_contract_evidence(
            bytes,
            "erase-physical-address-dispatch",
            &signature,
            "the physical erase path multiplies the selected entry count by its geometry factor and dispatches the encoded address vector",
        )
    });
    let erase_label = exact_contract_evidence(
        bytes,
        "erase-block-operation-label",
        b"-----------Erase Block-----------",
        "the only caller labels this bounded vector operation as Erase Block and records explicit success/failure outcomes",
    );
    if let (Some(erase_batch), Some(erase_dispatch), Some(erase_label)) =
        (erase_batch, erase_dispatch, erase_label)
    {
        if append_exact_vendor_command(
            bytes,
            &mut evidence,
            &mut vendor_commands,
            "command-ea-e2",
            "6a00884424108b44242050526a006a006a108d54241852c644241ceac644242be2",
            "EA/E2 submits a data-out payload with mode and geometry bytes in CDB positions 12 and 11",
            ToolVendorCommandContract {
                name: "erase-physical-block-batch",
                opcode_hex: "ea",
                subcommand_hex: Some("e2"),
                cdb_length: 16,
                data_direction: "to-device",
                transfer_contract: "4 * block_count bytes; block_count in 1..=128; payload contains encoded physical block addresses",
                cdb_layout: "00=EA; 01..10=00; 11=geometry_selector; 12=erase_mode; 13..14=00; 15=E2",
                classification: "destructive-physical-erase",
                semantic_basis: "exact constructor and bounded erase success/failure call graph",
            },
        ) {
            evidence.extend([erase_batch, erase_dispatch, erase_label]);
        }
    }
    append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "command-ea-e4",
        "8b442434c60424ea668944240d740a0d00800000668944240d8b44241c6a0050526a006a016a108d54241852c644242be4",
        "EA/E4 submits caller-sized data-in with a packed physical-page and geometry CDB",
        ToolVendorCommandContract {
            name: "read-raw-nand-page",
            opcode_hex: "ea",
            subcommand_hex: Some("e4"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "caller bytes; page data and auxiliary/OOB extent are geometry supplied",
            cdb_layout: "00=EA; 01..04=arg3 LE32; 05..06=arg4 LE16; 07=arg12; 08=arg5; 09=arg10; 10=arg6; 11=arg7; 12=arg11; 13..14=arg8 LE16 with bit15 from arg9; 15=E4",
            classification: "read-only-raw-nand",
            semantic_basis: "exact constructor and physical-page read/write verification call graph",
        },
    );
    append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "command-ea-e5",
        "668b4424346a0066894424118b44242050526a006a006a108d54241852c644241ceac644242be5",
        "EA/E5 submits caller-sized data-out with a packed physical-page and geometry CDB",
        ToolVendorCommandContract {
            name: "program-raw-nand-page",
            opcode_hex: "ea",
            subcommand_hex: Some("e5"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract:
                "caller bytes; page data and auxiliary/OOB extent are geometry supplied",
            cdb_layout:
                "00=EA; 01..04, 07..12 and 13..14 are caller/geometry fields; 05..06=00; 15=E5",
            classification: "state-changing-raw-nand",
            semantic_basis:
                "exact constructor and physical-page write/read verification call graph",
        },
    );
    append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "command-ea-e6",
        "6a006800080000526a006a018944241588442423894424198944241d66894424218a4424306a108d54241852c644241cea8844241dc644242be6",
        "EA/E6 reads exactly 0x800 bytes with one selector byte",
        ToolVendorCommandContract {
            name: "read-service-configuration-page",
            opcode_hex: "ea",
            subcommand_hex: Some("e6"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "exactly 2048 bytes",
            cdb_layout: "00=EA; 01=selector; 02..14=00; 15=E6",
            classification: "read-only",
            semantic_basis: "exact constructor and fixed-size boot/configuration readers",
        },
    );
    append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "command-ea-e6-variant",
        "8a44242c6a01884424158a4424346a108d54241852c644241cea8844241ec644242be6",
        "the second EA/E6 wrapper reads exactly 0x800 bytes with two selector bytes",
        ToolVendorCommandContract {
            name: "read-service-configuration-page-variant",
            opcode_hex: "ea",
            subcommand_hex: Some("e6"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "exactly 2048 bytes",
            cdb_layout: "00=EA; 01=selector; 02=variant; 03..14=00; 15=E6",
            classification: "read-only",
            semantic_basis: "exact constructor and fixed-size configuration reader",
        },
    );
    let e7_found = append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "command-ea-e7",
        "8b4c243c6a0051576a006a006a108d54242c528bcec644243fe7e8c8f9ffff",
        "EA/E7 submits a 16-byte data-out CDB and caller-sized controller-memory payload",
        ToolVendorCommandContract {
            name: "upload-controller-memory-window",
            opcode_hex: "ea",
            subcommand_hex: Some("e7"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "caller bytes; payload length and destination are four-byte aligned",
            cdb_layout: "00=EA; 01..02=destination/4 LE16; 03..04=destination LE16; 05..08=loader parameter LE32; 09..12=library token LE32; 13=special window mode; 14=00; 15=E7",
            classification: "state-changing-controller-memory",
            semantic_basis: "exact constructor and fixed 0x5800/0x6000/0x9800/0xA000 service-code upload call graph",
        },
    );
    if e7_found {
        let layout_signature = hex::decode(
            "668bcb66c1e902668954241766894c24158b4c2448ba00a00000c6442414ea894c24198944241d66",
        )
        .ok()?;
        evidence.push(exact_contract_evidence(
            bytes,
            "command-ea-e7-layout",
            &layout_signature,
            "EA/E7 encodes both the byte destination and destination/4 and attaches a library-generated token",
        )?);
    }
    append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "command-eb-session-event",
        "8bc15733f6c6442414ebc64424100133ff8d5801908a104084d275f92bc383f80f760a885424108bf18bf8eb0f50518d44241d50e81cf3090083c40c8b4c24106a0057566a00516a108d54242c528bcde800f9ffff",
        "EB carries a zero-terminated event name inline when it is at most 15 bytes and otherwise exposes a bounded external buffer path",
        ToolVendorCommandContract {
            name: "controller-session-event",
            opcode_hex: "eb",
            subcommand_hex: None,
            cdb_length: 16,
            data_direction: "from-device-or-none",
            transfer_contract: "zero for inline names up to 15 bytes; otherwise string length bytes",
            cdb_layout: "00=EB; 01..15=zero-terminated event name when length <= 15",
            classification: "controller-session-transition",
            semantic_basis: "exact constructor and DeviceMP_Begin/DeviceMP_End callers",
        },
    );
    append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "zero-cdb-ready-probe",
        "505050506a018844241489442415894424198944241d6689442421884424236a108d44241850e8a5f8ffff8b4c241033cce8bced090083c414c3",
        "the readiness wrapper submits sixteen zero CDB bytes with no payload",
        ToolVendorCommandContract {
            name: "zero-cdb-ready-probe",
            opcode_hex: "00",
            subcommand_hex: None,
            cdb_length: 16,
            data_direction: "from-device-or-none",
            transfer_contract: "zero bytes",
            cdb_layout: "00..15=00",
            classification: "read-only",
            semantic_basis: "exact constructor and readiness polling caller",
        },
    );
    append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "command-ea-e8",
        "8a54241c33c089442405894424016a008944240d8844241366894424118a44241c6a00884424098a4424286a006a00884424158a442438885424128a5424346a018844241b8854241a8b5424406a108d44241850c644241ceac644242be889542425e81bf8ffff",
        "EA/E8 submits a no-payload mode-transition CDB assembled from six dynamic fields",
        ToolVendorCommandContract {
            name: "device-mode-transition",
            opcode_hex: "ea",
            subcommand_hex: Some("e8"),
            cdb_length: 16,
            data_direction: "from-device-or-none",
            transfer_contract: "zero bytes",
            cdb_layout: "00=EA; 01,02,05,06,07 and 09..12 are dynamic mode fields; all other parameter bytes are zero; 15=E8",
            classification: "state-changing-device-mode",
            semantic_basis: "exact constructor and USB logical-drive re-enumeration caller",
        },
    );
    append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "command-ea-f3",
        "33c0568b74242485d2743b578b7c242485ff7431505752566a018844242b8944241d894424218944242566894424296a108d44242050c6442424eac6442433f3e8a9f7ffff",
        "EA/F3 is a caller-sized data-in operation with no dynamic CDB parameter bytes",
        ToolVendorCommandContract {
            name: "read-f3-service-payload",
            opcode_hex: "ea",
            subcommand_hex: Some("f3"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "caller bytes",
            cdb_layout: "00=EA; 01..14=00; 15=F3",
            classification: "read-only-unresolved-semantics",
            semantic_basis: "exact constructor only",
        },
    );
    append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "command-ea-f5",
        "894424098944240d894424058844241366894424118b4424246a0089442409668b44242c565266894424158a4424386a008844241c8a4424406a00884424228a4424486a108d54241c52c6442420ea8844242bc644242ff5e812f7ffff",
        "EA/F5 is a caller-sized data-out operation with packed dynamic address and geometry fields",
        ToolVendorCommandContract {
            name: "write-f5-service-payload",
            opcode_hex: "ea",
            subcommand_hex: Some("f5"),
            cdb_length: 16,
            data_direction: "to-device",
            transfer_contract: "caller bytes",
            cdb_layout: "00=EA; 01..09 are dynamic address/geometry fields; 10..14=00; 15=F5",
            classification: "state-changing-unresolved-semantics",
            semantic_basis: "exact constructor only",
        },
    );
    append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "command-ea-f6",
        "894424098944240589442401668944240d8844240f8b44242089442401668b44242466894424058a442428884424088a442434884424098a44242c8844240a8a4424308844240b668b44241c6a0066894424110fb7c050526a006a016a108d54241852c644241ceac644242bf6e876f6ffff",
        "EA/F6 is a caller-sized data-in operation whose transfer length is also encoded in CDB bytes 13..14",
        ToolVendorCommandContract {
            name: "read-f6-service-payload",
            opcode_hex: "ea",
            subcommand_hex: Some("f6"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "caller LE16 bytes, duplicated in CDB positions 13..14",
            cdb_layout: "00=EA; 01..06,08..11 and 13..14 are dynamic address/geometry fields; 07 and 12=00; 15=F6",
            classification: "read-only-unresolved-semantics",
            semantic_basis: "exact constructor and random read/write test caller",
        },
    );
    append_exact_vendor_command(
        bytes,
        &mut evidence,
        &mut vendor_commands,
        "command-ea-f4",
        "568b74242085f67465894424098944240d894424058844241366894424118b44242489442405668b4424286a00668944240d8a4424305652884424178a44243c6a008844241c8a4424446a01884424228a44244c6a108d54241c52c6442420ea8844242bc644242ff4e8daf5ffff",
        "EA/F4 is a caller-sized data-in operation with packed dynamic address and geometry fields",
        ToolVendorCommandContract {
            name: "read-f4-service-payload",
            opcode_hex: "ea",
            subcommand_hex: Some("f4"),
            cdb_length: 16,
            data_direction: "from-device",
            transfer_contract: "caller bytes",
            cdb_layout: "00=EA; 01..08,10..11 are dynamic address/geometry fields; 09 and 12..14=00; 15=F4",
            classification: "read-only-unresolved-semantics",
            semantic_basis: "exact constructor only",
        },
    );

    if vendor_commands.is_empty() {
        return None;
    }
    evidence.sort_by_key(|item| item.offset);
    Some(ToolHostTransportContract {
        family: Family::ChipsbankUfd.as_str(),
        source_path: path.to_path_buf(),
        source_size_bytes: size_bytes,
        source_sha256: sha256.to_string(),
        source_format: format,
        provenance: "untrusted-unsigned-factory-tool-executable",
        transport: "delegated-16-byte-vendor-cdb-callback",
        ioctl_codes_hex: Vec::new(),
        sptd_header_bytes: 0,
        sense_bytes: 0,
        outer_buffer_bytes: 0,
        timeout_seconds: Vec::new(),
        transfer_unit_bytes: 1,
        retry_attempts: 1,
        cdb_lengths: vec![16],
        data_directions: vec!["to-device", "from-device", "none"],
        read_only_commands: Vec::new(),
        vendor_commands,
        evidence,
        corroborating_source: None,
        contract_scope: "statically authenticated APDeviceMP command constructors and call-graph semantics only; the APToolV6A record supplies the Windows pass-through envelope; exact controller/firmware/NAND tuple selection, response signatures, metadata layout, recovery behavior, and HIL qualification remain separate",
        production_eligible: false,
    })
}

fn innostor_mptool_transport_contract(
    path: &Path,
    size_bytes: u64,
    sha256: &str,
    format: &'static str,
    bytes: &[u8],
) -> Option<ToolHostTransportContract> {
    if format != "portable-executable" {
        return None;
    }
    let mut evidence = Vec::new();
    for (role, signature, interpretation) in [
        (
            "buffered-data-out-header",
            &[
                0x66, 0xc7, 0x44, 0x24, 0x18, 0x2c, 0x00, 0xc6, 0x44, 0x24, 0x1d, 0x00, 0xc6, 0x44,
                0x24, 0x1e, 0x10, 0xc6, 0x44, 0x24, 0x1f, 0x00,
            ][..],
            "buffered data-out path uses a 0x2c header and a 16-byte CDB",
        ),
        (
            "buffered-data-out-timeout-and-offsets",
            &[
                0xc7, 0x44, 0x24, 0x28, 0x0a, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x2c, 0x50, 0x00,
                0x00, 0x00, 0xc7, 0x44, 0x24, 0x30, 0x30, 0x00, 0x00, 0x00,
            ][..],
            "buffered path timeout is 10 seconds with data offset 0x50 and sense offset 0x30",
        ),
        (
            "ioctl-scsi-pass-through-buffered",
            &[0x68, 0x04, 0xd0, 0x04, 0x00][..],
            "DeviceIoControl uses IOCTL_SCSI_PASS_THROUGH 0x0004d004",
        ),
        (
            "buffered-retry-bound",
            &[0x40, 0x83, 0xf8, 0x32, 0x89, 0x44, 0x24, 0x10][..],
            "the generic buffered path stops after 50 attempts",
        ),
        (
            "buffered-wide-sense-contract",
            &[
                0x66, 0xc7, 0x44, 0x24, 0x2c, 0x2c, 0x00, 0xc6, 0x44, 0x24, 0x32, 0x10, 0xc6, 0x44,
                0x24, 0x33, 0x20,
            ][..],
            "a second buffered path uses a 16-byte CDB and 0x20-byte sense area",
        ),
        (
            "buffered-wide-sense-timeout-and-offsets",
            &[
                0xc7, 0x44, 0x24, 0x3c, 0x1e, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x40, 0x50, 0x00,
                0x00, 0x00, 0xc7, 0x44, 0x24, 0x44, 0x30, 0x00, 0x00, 0x00,
            ][..],
            "wide-sense path timeout is 30 seconds with data offset 0x50 and sense offset 0x30",
        ),
        (
            "direct-write-header",
            &[0x66, 0xc7, 0x44, 0x24, 0x28, 0x2c, 0x00][..],
            "direct write path uses a 0x2c SPTD header",
        ),
        (
            "direct-write-target-and-cdb-length",
            &[0xc6, 0x44, 0x24, 0x2c, 0x01, 0xc6, 0x44, 0x24, 0x2e, 0x10][..],
            "direct write path uses target ID 1 and a 16-byte CDB envelope",
        ),
        (
            "direct-write-timeout-and-opcode",
            &[
                0xc7, 0x44, 0x24, 0x38, 0x09, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x40, 0x30, 0x00,
                0x00, 0x00, 0xc6, 0x44, 0x24, 0x44, 0x2a,
            ][..],
            "direct path timeout is 9 seconds and constructs standard WRITE(10) opcode 0x2a",
        ),
        (
            "ioctl-scsi-pass-through-direct",
            &[0x68, 0x14, 0xd0, 0x04, 0x00][..],
            "DeviceIoControl uses IOCTL_SCSI_PASS_THROUGH_DIRECT 0x0004d014",
        ),
        (
            "buffered-read-constructor",
            &[
                0x66, 0xc7, 0x44, 0x24, 0x34, 0x2c, 0x00, 0xc6, 0x44, 0x24, 0x38, 0x01, 0xc6, 0x44,
                0x24, 0x3a, 0x10, 0xc6, 0x44, 0x24, 0x3c, 0x01,
            ][..],
            "buffered read path uses target ID 1, a 16-byte CDB envelope, and DataIn value 1",
        ),
        (
            "buffered-read-timeout-and-opcode",
            &[
                0xc7, 0x44, 0x24, 0x44, 0x0a, 0x00, 0x00, 0x00, 0xc7, 0x44, 0x24, 0x48, 0x50, 0x00,
                0x00, 0x00, 0xc7, 0x44, 0x24, 0x4c, 0x30, 0x00, 0x00, 0x00, 0xc6, 0x44, 0x24, 0x50,
                0x28,
            ][..],
            "buffered read timeout is 10 seconds and constructs standard READ(10) opcode 0x28",
        ),
    ] {
        evidence.push(exact_contract_evidence(
            bytes,
            role,
            signature,
            interpretation,
        )?);
    }
    evidence.sort_by_key(|item| item.offset);
    Some(ToolHostTransportContract {
        family: Family::InnostorUfd.as_str(),
        source_path: path.to_path_buf(),
        source_size_bytes: size_bytes,
        source_sha256: sha256.to_string(),
        source_format: format,
        provenance: "untrusted-unsigned-factory-tool-executable",
        transport: "windows-scsi-pass-through-buffered-and-direct",
        ioctl_codes_hex: vec!["0004d004", "0004d014"],
        sptd_header_bytes: 0x2c,
        sense_bytes: 0x20,
        outer_buffer_bytes: 0x10050,
        timeout_seconds: vec![9, 10, 30],
        transfer_unit_bytes: 1,
        retry_attempts: 50,
        cdb_lengths: vec![16],
        data_directions: vec!["to-device", "from-device"],
        read_only_commands: Vec::new(),
        vendor_commands: Vec::new(),
        evidence,
        corroborating_source: None,
        contract_scope: "host transport plus standard READ(10)/WRITE(10) constructors only; vendor-command semantics remain unasserted",
        production_eligible: false,
    })
}

fn static_transport_contract(
    path: &Path,
    family: Option<Family>,
    size_bytes: u64,
    sha256: &str,
    format: &'static str,
    bytes: &[u8],
) -> Option<ToolHostTransportContract> {
    let filename = path.file_name()?.to_str()?.to_ascii_lowercase();
    if family_enabled(family, Family::AlcorUfd) && filename == "ufdapi_gen.dll" {
        return alcor_ufdapi_gen_contract(path, size_bytes, sha256, format, bytes);
    }
    if family_enabled(family, Family::AlcorUfd) && filename == "ufdcomlib.dll" {
        return alcor_transport_contract(path, size_bytes, sha256, format, bytes);
    }
    if family_enabled(family, Family::SiliconMotionUfd) && filename == "ufdif.dll" {
        return smi_ufdif_transport_contract(path, size_bytes, sha256, format, bytes);
    }
    if family_enabled(family, Family::SiliconMotionUfd)
        && filename.starts_with("sm32xtest")
        && filename.ends_with(".exe")
    {
        return smi_sm32xtest_transport_contract(path, size_bytes, sha256, format, bytes);
    }
    if family_enabled(family, Family::PhisonUfd) && filename == "getinfo.exe" {
        return phison_getinfo_transport_contract(path, size_bytes, sha256, format, bytes);
    }
    if family_enabled(family, Family::FirstchipUfd) && filename == "entryappite.dll" {
        return firstchip_entryappite_transport_contract(path, size_bytes, sha256, format, bytes);
    }
    if family_enabled(family, Family::ChipsbankUfd) && filename == "aptoolv6a.exe" {
        return chipsbank_aptool_transport_contract(path, size_bytes, sha256, format, bytes);
    }
    if family_enabled(family, Family::ChipsbankUfd) && filename == "apdevicemp.dll" {
        return chipsbank_apdevice_command_contract(path, size_bytes, sha256, format, bytes);
    }
    if family_enabled(family, Family::InnostorUfd) && filename == "innostor mptool.exe" {
        return innostor_mptool_transport_contract(path, size_bytes, sha256, format, bytes);
    }
    None
}

fn checked_utf8_lines<'a>(bytes: &'a [u8], path: &Path) -> Result<Vec<(usize, &'a str)>> {
    if bytes.len() as u64 > MAX_STRUCTURED_TEXT_BYTES {
        return Err(Error::Invalid(format!(
            "structured vendor map {} exceeds {MAX_STRUCTURED_TEXT_BYTES} bytes",
            path.display()
        )));
    }
    if bytes.contains(&0) {
        return Err(Error::Invalid(format!(
            "structured vendor map {} contains NUL bytes",
            path.display()
        )));
    }
    let mut lines = Vec::new();
    for (index, raw) in bytes.split(|byte| *byte == b'\n').enumerate() {
        if index >= MAX_STRUCTURED_LINES {
            return Err(Error::Invalid(format!(
                "structured vendor map {} exceeds {MAX_STRUCTURED_LINES} lines",
                path.display()
            )));
        }
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        if raw.len() > MAX_STRUCTURED_LINE_BYTES {
            return Err(Error::Invalid(format!(
                "structured vendor map {} line {} exceeds {MAX_STRUCTURED_LINE_BYTES} bytes",
                path.display(),
                index + 1
            )));
        }
        let line = std::str::from_utf8(raw).map_err(|error| {
            Error::Invalid(format!(
                "structured vendor map {} line {} is not UTF-8: {error}",
                path.display(),
                index + 1
            ))
        })?;
        lines.push((index + 1, line));
    }
    Ok(lines)
}

fn checked_ascii_lines<'a>(bytes: &'a [u8], path: &Path) -> Result<Vec<(usize, &'a str)>> {
    if !bytes.is_ascii() {
        return Err(Error::Invalid(format!(
            "structured vendor map {} is not ASCII",
            path.display()
        )));
    }
    checked_utf8_lines(bytes, path)
}

fn decode_firstchip_config(bytes: &[u8], path: &Path) -> Result<(Vec<u8>, ToolDecodedContent)> {
    if bytes.len() < FIRSTCHIP_CONFIG_KEY.len() || bytes.len() as u64 > MAX_STRUCTURED_TEXT_BYTES {
        return Err(Error::Invalid(format!(
            "FirstChip encrypted database {} has an invalid size",
            path.display()
        )));
    }
    let encrypted_block_bytes =
        bytes.len() / FIRSTCHIP_CONFIG_KEY.len() * FIRSTCHIP_CONFIG_KEY.len();
    let trailing_cleartext_bytes = bytes.len() - encrypted_block_bytes;
    let cipher = Des::new_from_slice(FIRSTCHIP_CONFIG_KEY)
        .map_err(|_| Error::Invalid("internal FirstChip DES key length is invalid".to_string()))?;
    let mut decoded = bytes.to_vec();
    for chunk in decoded[..encrypted_block_bytes].chunks_exact_mut(8) {
        let mut block = des::cipher::Block::<Des>::default();
        block.copy_from_slice(chunk);
        cipher.decrypt_block(&mut block);
        chunk.copy_from_slice(&block);
    }
    if decoded.len() < 2 || decoded[..2] != [0xff, 0xfe] {
        return Err(Error::Invalid(format!(
            "FirstChip encrypted database {} does not decode to a UTF-16LE BOM",
            path.display()
        )));
    }
    if !decoded.len().is_multiple_of(2) {
        return Err(Error::Invalid(format!(
            "FirstChip encrypted database {} decodes to an odd UTF-16LE byte count",
            path.display()
        )));
    }
    let code_units = decoded[2..]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect::<Vec<_>>();
    let text = String::from_utf16(&code_units).map_err(|error| {
        Error::Invalid(format!(
            "FirstChip encrypted database {} is not valid UTF-16LE: {error}",
            path.display()
        ))
    })?;
    if text.contains('\0') {
        return Err(Error::Invalid(format!(
            "FirstChip encrypted database {} decodes to embedded NUL characters",
            path.display()
        )));
    }
    let decoded_sha256 = hex::encode(Sha256::digest(&decoded));
    let decoded_size_bytes = decoded.len();
    Ok((
        text.into_bytes(),
        ToolDecodedContent {
            scheme: "firstchip-des-ecb-complete-blocks-with-cleartext-tail",
            key_hex: "6978746563383938".to_string(),
            block_bytes: 8,
            encrypted_block_bytes,
            trailing_cleartext_bytes,
            text_encoding: "UTF-16LE",
            decoded_size_bytes,
            decoded_sha256,
        },
    ))
}

fn decode_chipsbank_cbm(bytes: &[u8], path: &Path) -> Result<(Vec<u8>, ToolDecodedContent)> {
    const DECODED_PREFIX_BYTES: usize = 4;
    const DECODED_SUFFIX_BYTES: usize = 6;

    if bytes.len() < CHIPSBANK_CBM_MAGIC.len() + DECODED_PREFIX_BYTES + DECODED_SUFFIX_BYTES
        || bytes.len() as u64 > MAX_STRUCTURED_TEXT_BYTES
        || !bytes.ends_with(CHIPSBANK_CBM_MAGIC)
    {
        return Err(Error::Invalid(format!(
            "ChipsBank database {} is not a bounded cbmv1001 file",
            path.display()
        )));
    }
    let encrypted_block_bytes = bytes.len() - CHIPSBANK_CBM_MAGIC.len();
    let mut decoded = bytes[..encrypted_block_bytes].to_vec();
    for (index, byte) in decoded.iter_mut().enumerate() {
        *byte ^= CHIPSBANK_CBM_XOR_KEY[index % CHIPSBANK_CBM_XOR_KEY.len()];
    }
    if decoded[DECODED_PREFIX_BYTES] != b'['
        || decoded[decoded.len() - DECODED_SUFFIX_BYTES..decoded.len() - 4] != [0, 0]
    {
        return Err(Error::Invalid(format!(
            "ChipsBank database {} has an invalid decoded envelope",
            path.display()
        )));
    }
    let encoded_text = &decoded[DECODED_PREFIX_BYTES..decoded.len() - DECODED_SUFFIX_BYTES];
    if encoded_text.contains(&0) {
        return Err(Error::Invalid(format!(
            "ChipsBank database {} has an embedded NUL in its decoded text",
            path.display()
        )));
    }
    let (text, _, had_errors) = GBK.decode(encoded_text);
    if had_errors {
        return Err(Error::Invalid(format!(
            "ChipsBank database {} is not valid GBK text",
            path.display()
        )));
    }
    if !text.starts_with('[') || !text.ends_with("\r\n") {
        return Err(Error::Invalid(format!(
            "ChipsBank database {} does not contain a complete INI payload",
            path.display()
        )));
    }
    let decoded_sha256 = hex::encode(Sha256::digest(&decoded));
    let decoded_size_bytes = decoded.len();
    Ok((
        text.into_owned().into_bytes(),
        ToolDecodedContent {
            scheme: "chipsbank-cbmv1001-repeating-xor",
            key_hex: hex::encode(CHIPSBANK_CBM_XOR_KEY),
            block_bytes: CHIPSBANK_CBM_XOR_KEY.len(),
            encrypted_block_bytes,
            trailing_cleartext_bytes: CHIPSBANK_CBM_MAGIC.len(),
            text_encoding: "GBK",
            decoded_size_bytes,
            decoded_sha256,
        },
    ))
}

fn decode_alcor_ascii_hex(bytes: &[u8], path: &Path) -> Result<(Vec<u8>, ToolDecodedContent)> {
    let decoded = crate::alcor_au698x::decode_ascii_hex_module(bytes).map_err(|error| {
        Error::Invalid(format!(
            "Alcor module {} is not a valid factory ASCII-hex payload: {error}",
            path.display()
        ))
    })?;
    let decoded_sha256 = hex::encode(Sha256::digest(&decoded));
    let decoded_size_bytes = decoded.len();
    let trailing_cleartext_bytes = usize::from(bytes.last() == Some(&0x1a));
    Ok((
        decoded,
        ToolDecodedContent {
            scheme: "alcor-fixed-16-byte-ascii-hex-records",
            key_hex: String::new(),
            block_bytes: crate::alcor_au698x::ASCII_HEX_RECORD_BYTES,
            encrypted_block_bytes: decoded_size_bytes
                .checked_mul(2)
                .ok_or_else(|| Error::Invalid("Alcor ASCII-hex payload size overflow".into()))?,
            trailing_cleartext_bytes,
            text_encoding: "ASCII hexadecimal with CRLF records",
            decoded_size_bytes,
            decoded_sha256,
        },
    ))
}

#[derive(Debug)]
struct RawIniSection {
    name: String,
    source_line: usize,
    parameters: Vec<ToolNamedParameter>,
}

fn parse_bounded_ini_sections(path: &Path, bytes: &[u8]) -> Result<Vec<RawIniSection>> {
    let mut sections = Vec::new();
    let mut current: Option<RawIniSection> = None;
    let mut parameter_count = 0usize;
    for (line_number, raw_line) in checked_utf8_lines(bytes, path)? {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with(';')
            || line.starts_with('#')
            || line.starts_with("//")
        {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            if let Some(section) = current.take() {
                sections.push(section);
            }
            let name = &line[1..line.len() - 1];
            if name.is_empty()
                || name.len() > 128
                || !name.as_bytes().iter().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'.' | b'-' | b' ')
                })
            {
                return Err(Error::Invalid(format!(
                    "FirstChip database {} line {line_number} has an invalid section name",
                    path.display()
                )));
            }
            current = Some(RawIniSection {
                name: name.to_string(),
                source_line: line_number,
                parameters: Vec::new(),
            });
            if sections.len() >= MAX_FIRSTCHIP_RECORDS {
                return Err(Error::Invalid(format!(
                    "FirstChip database {} exceeds {MAX_FIRSTCHIP_RECORDS} sections",
                    path.display()
                )));
            }
            continue;
        }
        if line.starts_with('[') || line.ends_with(']') {
            return Err(Error::Invalid(format!(
                "FirstChip database {} line {line_number} has malformed section delimiters",
                path.display()
            )));
        }
        let (raw_name, raw_value) = line.split_once('=').ok_or_else(|| {
            Error::Invalid(format!(
                "FirstChip database {} line {line_number} has no assignment delimiter",
                path.display()
            ))
        })?;
        let name = raw_name.trim();
        if name.is_empty()
            || name.len() > 128
            || !name
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            return Err(Error::Invalid(format!(
                "FirstChip database {} line {line_number} has an invalid parameter name",
                path.display()
            )));
        }
        let section = current.as_mut().ok_or_else(|| {
            Error::Invalid(format!(
                "FirstChip database {} line {line_number} has an assignment outside a section",
                path.display()
            ))
        })?;
        section.parameters.push(ToolNamedParameter {
            name: name.to_string(),
            value: raw_value.trim().to_string(),
            source_line: line_number,
        });
        parameter_count = parameter_count
            .checked_add(1)
            .ok_or_else(|| Error::Invalid("FirstChip parameter count overflow".to_string()))?;
        if parameter_count > MAX_FIRSTCHIP_PARAMETERS {
            return Err(Error::Invalid(format!(
                "FirstChip database {} exceeds {MAX_FIRSTCHIP_PARAMETERS} parameters",
                path.display()
            )));
        }
    }
    if let Some(section) = current {
        sections.push(section);
    }
    Ok(sections)
}

fn parameter_conflicts(parameters: &[ToolNamedParameter]) -> Vec<String> {
    let mut values: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
    for parameter in parameters {
        values
            .entry(parameter.name.to_ascii_lowercase())
            .or_default()
            .insert(parameter.value.as_str());
    }
    values
        .into_iter()
        .filter_map(|(name, values)| (values.len() > 1).then_some(name))
        .collect()
}

fn parse_firstchip_nand_identities(path: &Path, bytes: &[u8]) -> Result<Vec<ToolNandIdentity>> {
    let mut identities = Vec::new();
    let mut seen_selectors = BTreeSet::new();
    for section in parse_bounded_ini_sections(path, bytes)? {
        let raw_nand_id = section
            .name
            .split_once('_')
            .map_or(section.name.as_str(), |(nand_id, _)| nand_id);
        if !(8..=16).contains(&raw_nand_id.len())
            || !raw_nand_id.as_bytes().iter().all(u8::is_ascii_hexdigit)
        {
            continue;
        }
        if raw_nand_id.bytes().all(|byte| byte == b'0')
            || raw_nand_id
                .bytes()
                .all(|byte| byte.eq_ignore_ascii_case(&b'f'))
        {
            return Err(Error::Invalid(format!(
                "FirstChip NAND database {} line {} has an empty NAND id",
                path.display(),
                section.source_line
            )));
        }
        let database_selector = section.name.to_ascii_lowercase();
        if !seen_selectors.insert(database_selector.clone()) {
            return Err(Error::Invalid(format!(
                "FirstChip NAND database {} repeats selector {database_selector}",
                path.display()
            )));
        }
        let nand_id = raw_nand_id.to_ascii_lowercase();
        let models = section
            .parameters
            .iter()
            .filter(|parameter| parameter.name.eq_ignore_ascii_case("Name"))
            .map(|parameter| parameter.value.trim())
            .filter(|value| !value.is_empty())
            .collect::<BTreeSet<_>>();
        if models.len() != 1 {
            return Err(Error::Invalid(format!(
                "FirstChip NAND database {} line {} must contain one unambiguous non-empty Name",
                path.display(),
                section.source_line
            )));
        }
        let mut aliases = Vec::new();
        for parameter in &section.parameters {
            if matches!(
                parameter.name.to_ascii_lowercase().as_str(),
                "name2" | "name4" | "name8"
            ) && !parameter.value.is_empty()
                && !aliases.contains(&parameter.value)
            {
                aliases.push(parameter.value.clone());
            }
        }
        let conflicting_parameter_names = parameter_conflicts(&section.parameters);
        let nand_id_byte_aligned = nand_id.len() % 2 == 0;
        identities.push(ToolNandIdentity {
            family: Family::FirstchipUfd.as_str(),
            controller_id: None,
            database_selector,
            nand_id,
            nand_id_byte_aligned,
            model: (*models.first().expect("model cardinality checked")).to_string(),
            aliases,
            parameters: section.parameters,
            selection_unambiguous: nand_id_byte_aligned && conflicting_parameter_names.is_empty(),
            conflicting_parameter_names,
            artifact_references: Vec::new(),
            source_path: path.to_path_buf(),
            source_line: section.source_line,
        });
    }
    if identities.is_empty() {
        return Err(Error::Invalid(format!(
            "FirstChip NAND database {} contains no bounded hexadecimal NAND sections",
            path.display()
        )));
    }
    let mut selector_counts = BTreeMap::new();
    for identity in &identities {
        *selector_counts
            .entry(identity.nand_id.clone())
            .or_insert(0usize) += 1;
    }
    for identity in &mut identities {
        if selector_counts.get(&identity.nand_id).copied().unwrap_or(0) > 1 {
            identity.selection_unambiguous = false;
        }
    }
    Ok(identities)
}

fn parse_chipsbank_nand_identities(path: &Path, bytes: &[u8]) -> Result<Vec<ToolNandIdentity>> {
    const REQUIRED_TUPLE_FIELDS: &[&str] = &[
        "CELLNUM",
        "PAGEMASK_SP",
        "PLANE_OF_CHIP",
        "BANK_OF_CHIP",
        "BLOCK_OF_BANK",
        "PAGE_OF_BLOCK",
        "SECTOR_OF_PAGE",
        "SPARE_SIZE",
        "RW_CYCLE",
        "SCAN_FILE",
        "CODE_FILE",
    ];

    let mut identities = Vec::new();
    let mut seen_selectors = BTreeSet::new();
    for section in parse_bounded_ini_sections(path, bytes)? {
        if !(8..=16).contains(&section.name.len())
            || !section.name.as_bytes().iter().all(u8::is_ascii_hexdigit)
        {
            continue;
        }
        let database_selector = section.name.to_ascii_lowercase();
        if database_selector.bytes().all(|byte| byte == b'0')
            || database_selector
                .bytes()
                .all(|byte| byte.eq_ignore_ascii_case(&b'f'))
        {
            return Err(Error::Invalid(format!(
                "ChipsBank NAND database {} line {} has an empty NAND id",
                path.display(),
                section.source_line
            )));
        }
        if !seen_selectors.insert(database_selector.clone()) {
            return Err(Error::Invalid(format!(
                "ChipsBank NAND database {} repeats selector {database_selector}",
                path.display()
            )));
        }
        let models = section
            .parameters
            .iter()
            .filter(|parameter| parameter.name.eq_ignore_ascii_case("FLASHNAME_1CE"))
            .map(|parameter| parameter.value.trim())
            .filter(|value| !value.is_empty())
            .collect::<BTreeSet<_>>();
        if models.len() != 1 {
            return Err(Error::Invalid(format!(
                "ChipsBank NAND database {} line {} must contain one unambiguous non-empty FLASHNAME_1CE",
                path.display(),
                section.source_line
            )));
        }
        let mut aliases = Vec::new();
        for parameter in &section.parameters {
            if matches!(
                parameter.name.to_ascii_uppercase().as_str(),
                "FLASHNAME_2CE" | "FLASHNAME_4CE" | "FLASHNAME_8CE"
            ) && !parameter.value.is_empty()
                && !aliases.contains(&parameter.value)
            {
                aliases.push(parameter.value.clone());
            }
        }
        let conflicting_parameter_names = parameter_conflicts(&section.parameters);
        let nand_id_byte_aligned = database_selector.len() % 2 == 0;
        let complete_tuple = REQUIRED_TUPLE_FIELDS.iter().all(|required| {
            section
                .parameters
                .iter()
                .filter(|parameter| parameter.name.eq_ignore_ascii_case(required))
                .filter(|parameter| !parameter.value.trim().is_empty())
                .count()
                == 1
        });
        identities.push(ToolNandIdentity {
            family: Family::ChipsbankUfd.as_str(),
            controller_id: None,
            database_selector: database_selector.clone(),
            nand_id: database_selector,
            nand_id_byte_aligned,
            model: (*models.first().expect("model cardinality checked")).to_string(),
            aliases,
            parameters: section.parameters,
            selection_unambiguous: nand_id_byte_aligned
                && complete_tuple
                && conflicting_parameter_names.is_empty(),
            conflicting_parameter_names,
            artifact_references: Vec::new(),
            source_path: path.to_path_buf(),
            source_line: section.source_line,
        });
    }
    if identities.is_empty() {
        return Err(Error::Invalid(format!(
            "ChipsBank NAND database {} contains no NAND identities",
            path.display()
        )));
    }
    Ok(identities)
}

fn parse_firstchip_read_retry_records(
    path: &Path,
    bytes: &[u8],
) -> Result<Vec<ToolReadRetryRecord>> {
    let mut records = Vec::new();
    let mut seen_ids = BTreeSet::new();
    for section in parse_bounded_ini_sections(path, bytes)? {
        let Some(id) = section
            .name
            .to_ascii_lowercase()
            .strip_prefix("readretry_")
            .map(str::to_string)
        else {
            continue;
        };
        if id.is_empty() || !id.as_bytes().iter().all(u8::is_ascii_digit) {
            return Err(Error::Invalid(format!(
                "FirstChip read-retry database {} line {} has an invalid record id",
                path.display(),
                section.source_line
            )));
        }
        if !seen_ids.insert(id.clone()) {
            return Err(Error::Invalid(format!(
                "FirstChip read-retry database {} repeats record {id}",
                path.display()
            )));
        }
        let conflicting_parameter_names = parameter_conflicts(&section.parameters);
        records.push(ToolReadRetryRecord {
            family: Family::FirstchipUfd.as_str(),
            id,
            parameters: section.parameters,
            selection_unambiguous: conflicting_parameter_names.is_empty(),
            conflicting_parameter_names,
            source_path: path.to_path_buf(),
            source_line: section.source_line,
        });
    }
    if records.is_empty() {
        return Err(Error::Invalid(format!(
            "FirstChip read-retry database {} contains no ReadRetry records",
            path.display()
        )));
    }
    Ok(records)
}

fn unambiguous_parameter(
    parameters: &[ToolNamedParameter],
    name: &str,
    path: &Path,
    section: &str,
) -> Result<String> {
    let values = parameters
        .iter()
        .filter(|parameter| parameter.name.eq_ignore_ascii_case(name))
        .map(|parameter| parameter.value.trim())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();
    if values.len() != 1 {
        return Err(Error::Invalid(format!(
            "structured vendor map {} section [{section}] must contain one unambiguous non-empty {name}",
            path.display()
        )));
    }
    Ok((*values.first().expect("parameter cardinality checked")).to_string())
}

fn innostor_database_controller(path: &Path) -> Option<String> {
    let filename = path.file_name()?.to_str()?.to_ascii_lowercase();
    let prefix = filename.split_once("_flashdatabase")?.0;
    if prefix.is_empty() || prefix.len() > 8 || !prefix.as_bytes().iter().all(u8::is_ascii_digit) {
        return None;
    }
    Some(format!("innostor-is{prefix}"))
}

fn parse_innostor_nand_identities(path: &Path, bytes: &[u8]) -> Result<Vec<ToolNandIdentity>> {
    let controller_id = innostor_database_controller(path).ok_or_else(|| {
        Error::Invalid(format!(
            "Innostor FlashDatabase {} has no exact numeric controller prefix",
            path.display()
        ))
    })?;
    let required_geometry = [
        "Vendor",
        "Feature",
        "MLC",
        "Planes",
        "PageSize",
        "Blocks",
        "Die",
        "Pagesperblock",
        "Sparesize",
        "ColumnAddrCycles",
        "RowAddrCycles",
    ];
    let mut identities = Vec::new();
    let mut selector_counts = BTreeMap::new();
    for section in parse_bounded_ini_sections(path, bytes)? {
        if section.name.eq_ignore_ascii_case("FlashDB Version") {
            continue;
        }
        let nand_id = unambiguous_parameter(&section.parameters, "FlashID", path, &section.name)?;
        if !(8..=64).contains(&nand_id.len())
            || nand_id.len() % 2 != 0
            || !nand_id.as_bytes().iter().all(u8::is_ascii_hexdigit)
            || nand_id.bytes().all(|byte| byte == b'0')
            || nand_id.bytes().all(|byte| byte.eq_ignore_ascii_case(&b'f'))
        {
            return Err(Error::Invalid(format!(
                "Innostor FlashDatabase {} section [{}] has an invalid exact NAND id",
                path.display(),
                section.name
            )));
        }
        for field in required_geometry {
            unambiguous_parameter(&section.parameters, field, path, &section.name)?;
        }
        let normalized_nand_id = nand_id.to_ascii_lowercase();
        let suffix = format!("-{normalized_nand_id}");
        let normalized_selector = section.name.to_ascii_lowercase();
        if !normalized_selector.ends_with(&suffix) {
            return Err(Error::Invalid(format!(
                "Innostor FlashDatabase {} section [{}] does not end in its exact NAND id",
                path.display(),
                section.name
            )));
        }
        let model_length = section.name.len() - suffix.len();
        let model = section.name[..model_length].trim().to_string();
        if model.is_empty() {
            return Err(Error::Invalid(format!(
                "Innostor FlashDatabase {} section [{}] has no model name",
                path.display(),
                section.name
            )));
        }
        *selector_counts.entry(normalized_selector).or_insert(0usize) += 1;
        let conflicting_parameter_names = parameter_conflicts(&section.parameters);
        identities.push(ToolNandIdentity {
            family: Family::InnostorUfd.as_str(),
            controller_id: Some(controller_id.clone()),
            database_selector: section.name,
            nand_id: normalized_nand_id,
            nand_id_byte_aligned: true,
            model,
            aliases: Vec::new(),
            parameters: section.parameters,
            selection_unambiguous: conflicting_parameter_names.is_empty(),
            conflicting_parameter_names,
            artifact_references: Vec::new(),
            source_path: path.to_path_buf(),
            source_line: section.source_line,
        });
        if identities.len() > MAX_FIRSTCHIP_RECORDS {
            return Err(Error::Invalid(format!(
                "Innostor FlashDatabase {} exceeds {MAX_FIRSTCHIP_RECORDS} NAND records",
                path.display()
            )));
        }
    }
    if identities.is_empty() {
        return Err(Error::Invalid(format!(
            "Innostor FlashDatabase {} contains no NAND records",
            path.display()
        )));
    }
    let mut id_counts = BTreeMap::new();
    for identity in &identities {
        *id_counts.entry(identity.nand_id.clone()).or_insert(0usize) += 1;
    }
    for identity in &mut identities {
        if id_counts.get(&identity.nand_id).copied().unwrap_or(0) > 1
            || selector_counts
                .get(&identity.database_selector.to_ascii_lowercase())
                .copied()
                .unwrap_or(0)
                > 1
        {
            identity.selection_unambiguous = false;
        }
    }
    Ok(identities)
}

fn exactly_one_parameter_value(
    parameters: &[ToolNamedParameter],
    name: &str,
    path: &Path,
    section: &str,
    allow_empty: bool,
) -> Result<String> {
    let matches = parameters
        .iter()
        .filter(|parameter| parameter.name.eq_ignore_ascii_case(name))
        .collect::<Vec<_>>();
    if matches.len() != 1 || (!allow_empty && matches[0].value.trim().is_empty()) {
        return Err(Error::Invalid(format!(
            "structured vendor map {} section [{section}] must contain exactly one {}{name}",
            path.display(),
            if allow_empty { "" } else { "non-empty " }
        )));
    }
    Ok(matches[0].value.trim().to_string())
}

fn normalize_bounded_package_directory(value: &str, path: &Path, section: &str) -> Result<String> {
    let normalized = value.replace('\\', "/").trim_matches('/').to_string();
    if normalized.is_empty()
        || normalized.len() > 512
        || normalized
            .split('/')
            .any(|part| part.is_empty() || part == "." || part == ".." || part.contains(':'))
    {
        return Err(Error::Invalid(format!(
            "structured vendor map {} section [{section}] has an invalid bounded package directory",
            path.display()
        )));
    }
    Ok(normalized)
}

fn parse_chipsbank_controller_manifest(path: &Path, bytes: &[u8]) -> Result<Vec<RawFirmwareIndex>> {
    let sections = parse_bounded_ini_sections(path, bytes)?;
    let information = sections
        .iter()
        .filter(|section| section.name.eq_ignore_ascii_case("ICInfo"))
        .collect::<Vec<_>>();
    if information.len() != 1 {
        return Err(Error::Invalid(format!(
            "ChipsBank controller manifest {} must contain exactly one [ICInfo] section",
            path.display()
        )));
    }
    let information = information[0];
    let raw_count = exactly_one_parameter_value(
        &information.parameters,
        "ICCount",
        path,
        &information.name,
        false,
    )?;
    let count = raw_count.parse::<usize>().map_err(|_| {
        Error::Invalid(format!(
            "ChipsBank controller manifest {} has a non-decimal ICCount",
            path.display()
        ))
    })?;
    if count == 0 || count > 256 {
        return Err(Error::Invalid(format!(
            "ChipsBank controller manifest {} has an out-of-range ICCount",
            path.display()
        )));
    }
    let active = exactly_one_parameter_value(
        &information.parameters,
        "ActiveIC",
        path,
        &information.name,
        false,
    )?;
    let mut records = Vec::with_capacity(count * 2);
    let mut seen_names = BTreeSet::new();
    let mut saw_active = false;
    for index in 0..count {
        let name_key = format!("ICName_{index}");
        let id_key = format!("ICID_{index}");
        let name = exactly_one_parameter_value(
            &information.parameters,
            &name_key,
            path,
            &information.name,
            false,
        )?;
        let raw_id = exactly_one_parameter_value(
            &information.parameters,
            &id_key,
            path,
            &information.name,
            false,
        )?;
        raw_id.parse::<u16>().map_err(|_| {
            Error::Invalid(format!(
                "ChipsBank controller manifest {} has a non-decimal {id_key}",
                path.display()
            ))
        })?;
        if name.len() > 16
            || !name
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            return Err(Error::Invalid(format!(
                "ChipsBank controller manifest {} has an invalid {name_key}",
                path.display()
            )));
        }
        let normalized_name = name.to_ascii_lowercase();
        if !seen_names.insert(normalized_name.clone()) {
            return Err(Error::Invalid(format!(
                "ChipsBank controller manifest {} repeats controller {name}",
                path.display()
            )));
        }
        saw_active |= name.eq_ignore_ascii_case(&active);
        let controller_sections = sections
            .iter()
            .filter(|section| section.name.eq_ignore_ascii_case(&name))
            .collect::<Vec<_>>();
        if controller_sections.len() != 1 {
            return Err(Error::Invalid(format!(
                "ChipsBank controller manifest {} must contain exactly one [{name}] section",
                path.display()
            )));
        }
        let section = controller_sections[0];
        let code_directory = normalize_bounded_package_directory(
            &exactly_one_parameter_value(
                &section.parameters,
                "PathCodeFile",
                path,
                &section.name,
                false,
            )?,
            path,
            &section.name,
        )?;
        let scan_directory = normalize_bounded_package_directory(
            &exactly_one_parameter_value(
                &section.parameters,
                "PathScanFile",
                path,
                &section.name,
                false,
            )?,
            path,
            &section.name,
        )?;
        let database = normalize_bounded_package_directory(
            &exactly_one_parameter_value(
                &section.parameters,
                "CBMFlash",
                path,
                &section.name,
                false,
            )?,
            path,
            &section.name,
        )?;
        if !database.eq_ignore_ascii_case("flash/flash.cbm") {
            return Err(Error::Invalid(format!(
                "ChipsBank controller manifest {} section [{name}] does not select flash/flash.cbm",
                path.display()
            )));
        }
        let controller_id = Some(format!("chipsbank-cbm{normalized_name}"));
        records.push(RawFirmwareIndex {
            family: Family::ChipsbankUfd.as_str(),
            controller_id: controller_id.clone(),
            purpose: "controller-code-catalog",
            selector: name.clone(),
            declared_directory: code_directory,
            version: String::new(),
            source_path: path.to_path_buf(),
            source_line: section.source_line,
        });
        records.push(RawFirmwareIndex {
            family: Family::ChipsbankUfd.as_str(),
            controller_id,
            purpose: "controller-scan-catalog",
            selector: name,
            declared_directory: scan_directory,
            version: String::new(),
            source_path: path.to_path_buf(),
            source_line: section.source_line,
        });
    }
    if !saw_active {
        return Err(Error::Invalid(format!(
            "ChipsBank controller manifest {} selects an undeclared ActiveIC",
            path.display()
        )));
    }
    Ok(records)
}

fn parse_innostor_firmware_index(path: &Path, bytes: &[u8]) -> Result<Vec<RawFirmwareIndex>> {
    let mut records = Vec::new();
    for section in parse_bounded_ini_sections(path, bytes)? {
        if section.parameters.len() != 2
            || !section.parameters.iter().all(|parameter| {
                matches!(
                    parameter.name.to_ascii_lowercase().as_str(),
                    "usb" | "version"
                )
            })
        {
            return Err(Error::Invalid(format!(
                "Innostor firmware index {} section [{}] contains fields other than USB and Version",
                path.display(),
                section.name
            )));
        }
        let raw_directory =
            exactly_one_parameter_value(&section.parameters, "USB", path, &section.name, false)?;
        let version =
            exactly_one_parameter_value(&section.parameters, "Version", path, &section.name, true)?;
        let normalized = raw_directory
            .replace('\\', "/")
            .trim_matches('/')
            .to_string();
        let path_parts = normalized.split('/').collect::<Vec<_>>();
        if path_parts.len() < 4
            || !path_parts[0].eq_ignore_ascii_case("binary")
            || path_parts
                .iter()
                .any(|part| part.is_empty() || *part == "." || *part == ".." || part.contains(':'))
        {
            return Err(Error::Invalid(format!(
                "Innostor firmware index {} section [{}] has an invalid bounded USB directory",
                path.display(),
                section.name
            )));
        }
        let purpose = if path_parts[1].eq_ignore_ascii_case("sorting") {
            "sorting-first-execute"
        } else {
            "controller-runtime"
        };
        let controller_id = match path_parts[1].to_ascii_lowercase().as_str() {
            "is917" => Some("innostor-is917".to_string()),
            "is917cp" => Some("innostor-is917cp".to_string()),
            "sorting" => None,
            _ => {
                return Err(Error::Invalid(format!(
                    "Innostor firmware index {} section [{}] has an unknown controller directory",
                    path.display(),
                    section.name
                )));
            }
        };
        records.push(RawFirmwareIndex {
            family: Family::InnostorUfd.as_str(),
            controller_id,
            purpose,
            selector: section.name,
            declared_directory: normalized,
            version,
            source_path: path.to_path_buf(),
            source_line: section.source_line,
        });
        if records.len() > MAX_FIRSTCHIP_RECORDS {
            return Err(Error::Invalid(format!(
                "Innostor firmware index {} exceeds {MAX_FIRSTCHIP_RECORDS} records",
                path.display()
            )));
        }
    }
    if records.is_empty() {
        return Err(Error::Invalid(format!(
            "Innostor firmware index {} contains no records",
            path.display()
        )));
    }
    Ok(records)
}

fn trim_quoted_value(value: &str, path: &Path, line: usize) -> Result<String> {
    let value = value.trim();
    let quoted_start = value.starts_with('"');
    let quoted_end = value.ends_with('"');
    if quoted_start != quoted_end || (quoted_start && value.len() < 2) {
        return Err(Error::Invalid(format!(
            "structured vendor map {} line {line} has unmatched quotes",
            path.display()
        )));
    }
    let value = if quoted_start {
        &value[1..value.len() - 1]
    } else {
        value
    };
    if value.is_empty() || value.len() > 1024 {
        return Err(Error::Invalid(format!(
            "structured vendor map {} line {line} has an empty or oversized value",
            path.display()
        )));
    }
    Ok(value.to_string())
}

fn valid_exact_nand_id(value: &str) -> bool {
    value.len() == 12
        && value.as_bytes().iter().all(u8::is_ascii_hexdigit)
        && !value.eq_ignore_ascii_case("000000000000")
        && !value.eq_ignore_ascii_case("ffffffffffff")
}

fn parse_smi_force_map(path: &Path, bytes: &[u8]) -> Result<Vec<RawSmiAssignment>> {
    let controller_id = smi_controller_from_filename(path).ok_or_else(|| {
        Error::Invalid(format!(
            "SMI force-firmware map {} has no exact SM controller identifier",
            path.display()
        ))
    })?;
    let mut assignments = Vec::new();
    for (line_number, raw_line) in checked_ascii_lines(bytes, path)? {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with("//")
            || line.starts_with(';')
            || line.starts_with('#')
            || line.starts_with('[')
        {
            continue;
        }
        if line.len() < 6 || !line[..6].eq_ignore_ascii_case("FLASH_") {
            continue;
        }
        let (key, raw_value) = line.split_once('=').ok_or_else(|| {
            Error::Invalid(format!(
                "SMI force-firmware map {} line {line_number} has no assignment delimiter",
                path.display()
            ))
        })?;
        let key = key.trim();
        let suffix = key.get(6..).ok_or_else(|| {
            Error::Invalid(format!(
                "SMI force-firmware map {} line {line_number} has a truncated key",
                path.display()
            ))
        })?;
        if suffix.len() < 12 || !valid_exact_nand_id(&suffix[..12]) {
            return Err(Error::Invalid(format!(
                "SMI force-firmware map {} line {line_number} does not use an exact valid six-byte NAND id",
                path.display()
            )));
        }
        let key_suffix = match &suffix[12..] {
            "" => None,
            remainder if remainder.starts_with('_') => {
                let value = &remainder[1..];
                if value.is_empty()
                    || value.len() > 64
                    || !value
                        .as_bytes()
                        .iter()
                        .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
                {
                    return Err(Error::Invalid(format!(
                        "SMI force-firmware map {} line {line_number} has an invalid key suffix",
                        path.display()
                    )));
                }
                Some(value.to_ascii_lowercase())
            }
            _ => {
                return Err(Error::Invalid(format!(
                    "SMI force-firmware map {} line {line_number} has trailing bytes after its NAND id",
                    path.display()
                )));
            }
        };
        assignments.push(RawSmiAssignment {
            controller_id: controller_id.clone(),
            nand_id: suffix[..12].to_ascii_lowercase(),
            source_path: path.to_path_buf(),
            key_suffix,
            value: trim_quoted_value(raw_value, path, line_number)?,
            source_line: line_number,
        });
        if assignments.len() > MAX_SMI_ASSIGNMENTS {
            return Err(Error::Invalid(format!(
                "SMI force-firmware map {} exceeds {MAX_SMI_ASSIGNMENTS} assignments",
                path.display()
            )));
        }
    }
    Ok(assignments)
}

#[derive(Default)]
struct PendingAlcorIdentity {
    active: bool,
    database_selector: Option<String>,
    model: Option<String>,
    nand_id: Option<String>,
    source_line: usize,
}

fn finish_alcor_identity(
    path: &Path,
    pending: &mut PendingAlcorIdentity,
    identities: &mut Vec<ToolNandIdentity>,
) -> Result<()> {
    if !pending.active {
        return Ok(());
    }
    match (pending.model.take(), pending.nand_id.take()) {
        (Some(model), Some(nand_id)) => identities.push(ToolNandIdentity {
            family: Family::AlcorUfd.as_str(),
            controller_id: None,
            database_selector: pending
                .database_selector
                .take()
                .ok_or_else(|| Error::Invalid("Alcor identity selector is missing".to_string()))?,
            nand_id,
            nand_id_byte_aligned: true,
            model,
            aliases: Vec::new(),
            parameters: Vec::new(),
            conflicting_parameter_names: Vec::new(),
            selection_unambiguous: true,
            artifact_references: Vec::new(),
            source_path: path.to_path_buf(),
            source_line: pending.source_line,
        }),
        (None, None) => {
            pending.database_selector = None;
        }
        _ => {
            return Err(Error::Invalid(format!(
                "Alcor NAND identity section in {} does not contain both FlashName and FID",
                path.display()
            )));
        }
    }
    pending.active = false;
    Ok(())
}

fn parse_alcor_fid(value: &str, path: &Path, line: usize) -> Result<String> {
    let fields = value.split(',').map(str::trim).collect::<Vec<_>>();
    if fields.len() != 6 {
        return Err(Error::Invalid(format!(
            "Alcor FlashList {} line {line} FID must contain exactly six bytes",
            path.display()
        )));
    }
    let mut bytes = Vec::with_capacity(6);
    for field in fields {
        if field.len() != 4 || !field[..2].eq_ignore_ascii_case("0x") {
            return Err(Error::Invalid(format!(
                "Alcor FlashList {} line {line} has an invalid FID byte",
                path.display()
            )));
        }
        let byte = u8::from_str_radix(&field[2..], 16).map_err(|_| {
            Error::Invalid(format!(
                "Alcor FlashList {} line {line} has an invalid FID byte",
                path.display()
            ))
        })?;
        bytes.push(byte);
    }
    if bytes.iter().all(|byte| *byte == 0) || bytes.iter().all(|byte| *byte == 0xff) {
        return Err(Error::Invalid(format!(
            "Alcor FlashList {} line {line} has an empty FID",
            path.display()
        )));
    }
    Ok(hex::encode(bytes))
}

fn parse_alcor_nand_identities(path: &Path, bytes: &[u8]) -> Result<Vec<ToolNandIdentity>> {
    let mut identities = Vec::new();
    let mut pending = PendingAlcorIdentity::default();
    for (line_number, raw_line) in checked_ascii_lines(bytes, path)? {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            finish_alcor_identity(path, &mut pending, &mut identities)?;
            let section = &line[1..line.len() - 1];
            pending.active =
                !section.is_empty() && section.as_bytes().iter().all(u8::is_ascii_digit);
            pending.database_selector = pending.active.then(|| section.to_string());
            pending.source_line = line_number;
            continue;
        }
        if !pending.active {
            continue;
        }
        let (key, value) = line.split_once('=').ok_or_else(|| {
            Error::Invalid(format!(
                "Alcor FlashList {} line {line_number} has no assignment delimiter",
                path.display()
            ))
        })?;
        if key.trim().eq_ignore_ascii_case("FlashName") {
            if pending.model.is_some() {
                return Err(Error::Invalid(format!(
                    "Alcor FlashList {} line {line_number} repeats FlashName",
                    path.display()
                )));
            }
            pending.model = Some(trim_quoted_value(value, path, line_number)?);
        } else if key.trim().eq_ignore_ascii_case("FID") {
            if pending.nand_id.is_some() {
                return Err(Error::Invalid(format!(
                    "Alcor FlashList {} line {line_number} repeats FID",
                    path.display()
                )));
            }
            pending.nand_id = Some(parse_alcor_fid(value.trim(), path, line_number)?);
        }
    }
    finish_alcor_identity(path, &mut pending, &mut identities)?;
    Ok(identities)
}

fn alcor_flash_database_identities(
    path: &Path,
    database: &crate::alcor_au698x::FlashDatabase,
) -> Vec<ToolNandIdentity> {
    let mut groups = BTreeMap::<String, Vec<&crate::alcor_au698x::FlashDatabaseEntry>>::new();
    for entry in &database.entries {
        groups
            .entry(entry.nand_id_hex.clone())
            .or_default()
            .push(entry);
    }

    groups
        .into_iter()
        .map(|(nand_id, mut entries)| {
            entries.sort_by_key(|entry| entry.index);
            let first = entries[0];
            let source_line = first.index + 1;
            let mut aliases = BTreeSet::new();
            for entry in entries.iter().skip(1) {
                if entry.model != first.model {
                    aliases.insert(entry.model.clone());
                }
            }

            let mut entry_parameters = Vec::with_capacity(entries.len());
            let mut all_parameter_names = BTreeSet::new();
            for entry in &entries {
                let mut parameters = BTreeMap::<String, String>::new();
                parameters.insert(
                    "alcor_operational_input_hex".to_string(),
                    entry.operational_input.source_bytes_hex.clone(),
                );
                parameters.insert(
                    "alcor_operational_record_sha256".to_string(),
                    entry.operational_sha256.clone(),
                );
                for selection in &entry.controller_selections {
                    let generation = selection
                        .controller_id
                        .strip_prefix("alcor-ctl-")
                        .unwrap_or(selection.controller_id.as_str());
                    if let Some(module) = selection.runtime_module() {
                        parameters.insert(
                            format!("alcor_ctl_{generation}_runtime_module"),
                            module.to_string(),
                        );
                    } else if let Some(value) = &selection.runtime.value {
                        parameters.insert(
                            format!("alcor_ctl_{generation}_runtime_selector"),
                            value.clone(),
                        );
                    }
                    for (role, field) in [
                        ("auxiliary_1", &selection.auxiliary_1),
                        ("auxiliary_2", &selection.auxiliary_2),
                    ] {
                        if let Some(value) = &field.value {
                            parameters
                                .insert(format!("alcor_ctl_{generation}_{role}"), value.clone());
                        }
                    }
                }
                all_parameter_names.extend(parameters.keys().cloned());
                entry_parameters.push(parameters);
            }

            let mut parameters = vec![
                ToolNamedParameter {
                    name: "alcor_database_version".to_string(),
                    value: database.header.version.to_string(),
                    source_line,
                },
                ToolNamedParameter {
                    name: "alcor_database_entry_bytes".to_string(),
                    value: database.header.entry_bytes.to_string(),
                    source_line,
                },
                ToolNamedParameter {
                    name: "alcor_database_entry_indexes".to_string(),
                    value: entries
                        .iter()
                        .map(|entry| entry.index.to_string())
                        .collect::<Vec<_>>()
                        .join(","),
                    source_line,
                },
            ];
            let mut conflicts = Vec::new();
            for name in all_parameter_names {
                let values = entry_parameters
                    .iter()
                    .map(|entry| entry.get(&name).cloned())
                    .collect::<BTreeSet<_>>();
                if values.len() == 1 {
                    if let Some(Some(value)) = values.into_iter().next() {
                        if !value.contains('|') {
                            parameters.push(ToolNamedParameter {
                                name,
                                value,
                                source_line,
                            });
                            continue;
                        }
                    }
                }
                conflicts.push(name);
            }
            parameters.sort_by(|left, right| left.name.cmp(&right.name));
            conflicts.sort();
            conflicts.dedup();
            let selection_unambiguous = conflicts.is_empty();
            ToolNandIdentity {
                family: Family::AlcorUfd.as_str(),
                controller_id: None,
                database_selector: format!(
                    "afl-v{}:{}",
                    database.header.version,
                    entries
                        .iter()
                        .map(|entry| entry.index.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                ),
                nand_id,
                nand_id_byte_aligned: true,
                model: first.model.clone(),
                aliases: aliases.into_iter().collect(),
                parameters,
                conflicting_parameter_names: conflicts,
                selection_unambiguous,
                artifact_references: Vec::new(),
                source_path: path.to_path_buf(),
                source_line,
            }
        })
        .collect()
}

fn alcor_flash_database_selections(
    path: &Path,
    database: &crate::alcor_au698x::FlashDatabase,
) -> Result<Vec<RawAlcorSelection>> {
    let mut selections = Vec::new();
    for entry in &database.entries {
        let legacy_operational_fields_25ns_disabled =
            crate::alcor_au698x::derive_flash_database_operational_fields(
                entry,
                false,
                crate::alcor_au698x::FlashDatabaseConverter::LegacyAlcorMp130205,
            )?;
        let ufdapi_operational_fields_25ns_disabled =
            crate::alcor_au698x::derive_flash_database_operational_fields(
                entry,
                false,
                crate::alcor_au698x::FlashDatabaseConverter::UfdApiGen1310,
            )?;
        let object_14_25ns_enabled = crate::alcor_au698x::derive_flash_database_operational_fields(
            entry,
            true,
            crate::alcor_au698x::FlashDatabaseConverter::LegacyAlcorMp130205,
        )?
        .object_14();
        for selection in &entry.controller_selections {
            let Some(runtime_module) = selection.runtime_module() else {
                continue;
            };
            selections.push(RawAlcorSelection {
                controller_id: selection.controller_id.clone(),
                nand_id: entry.nand_id_hex.clone(),
                model: entry.model.clone(),
                database_selector: format!("afl-v{}:{}", database.header.version, entry.index),
                operational_record_sha256: entry.operational_sha256.clone(),
                operational_input: entry.operational_input.clone(),
                legacy_operational_fields_25ns_disabled: legacy_operational_fields_25ns_disabled
                    .clone(),
                ufdapi_operational_fields_25ns_disabled: ufdapi_operational_fields_25ns_disabled
                    .clone(),
                object_14_25ns_enabled,
                runtime_module: runtime_module.to_string(),
                auxiliary_1: selection.auxiliary_1.value.clone(),
                auxiliary_2: selection.auxiliary_2.value.clone(),
                source_path: path.to_path_buf(),
                source_line: entry.index + 1,
            });
        }
    }
    Ok(selections)
}

fn parse_alcor_module_mappings(
    path: &Path,
    bytes: &[u8],
    controller_id: &str,
) -> Result<Vec<RawAlcorModuleMapping>> {
    let valid_parameter_count = |count: usize| match controller_id {
        "alcor-ctl-10" => matches!(count, 8 | 9),
        "alcor-ctl-13" => count == 8,
        "alcor-ctl-90" | "alcor-ctl-96" => count == 6,
        "alcor-ctl-92" => count == 5,
        _ => false,
    };
    let mut in_module_section = false;
    let mut saw_module_section = false;
    let mut mappings = Vec::new();
    for (line_number, raw_line) in checked_ascii_lines(bytes, path)? {
        let line = raw_line.trim();
        if line.is_empty()
            || line.starts_with(';')
            || line.starts_with('#')
            || line.starts_with("//")
        {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            in_module_section = line[1..line.len() - 1].eq_ignore_ascii_case("MODULE_FETURE");
            saw_module_section |= in_module_section;
            continue;
        }
        if !in_module_section {
            continue;
        }
        let (module, raw_parameters) = line.split_once('=').ok_or_else(|| {
            Error::Invalid(format!(
                "Alcor module map {} line {line_number} has no assignment delimiter",
                path.display()
            ))
        })?;
        let module = module.trim();
        if module.is_empty()
            || module.len() > 255
            || module.contains(['/', '\\'])
            || !module.to_ascii_lowercase().ends_with(".bin")
        {
            return Err(Error::Invalid(format!(
                "Alcor module map {} line {line_number} has an invalid module name",
                path.display()
            )));
        }
        let raw_fields = raw_parameters.split(',').map(str::trim).collect::<Vec<_>>();
        if !valid_parameter_count(raw_fields.len()) {
            return Err(Error::Invalid(format!(
                "Alcor module map {} line {line_number} has {} parameters, which is not recovered for {controller_id}",
                path.display(),
                raw_fields.len()
            )));
        }
        let mut parameters = Vec::with_capacity(raw_fields.len());
        for field in raw_fields {
            if field.is_empty() || !field.as_bytes().iter().all(u8::is_ascii_digit) {
                return Err(Error::Invalid(format!(
                    "Alcor module map {} line {line_number} has a non-decimal parameter",
                    path.display()
                )));
            }
            parameters.push(field.parse::<u32>().map_err(|_| {
                Error::Invalid(format!(
                    "Alcor module map {} line {line_number} has an out-of-range parameter",
                    path.display()
                ))
            })? as u64);
        }
        mappings.push(RawAlcorModuleMapping {
            controller_id: controller_id.to_string(),
            module: module.to_string(),
            parameters,
            source_path: path.to_path_buf(),
            source_line: line_number,
        });
        if mappings.len() > MAX_ALCOR_MODULE_MAPPINGS {
            return Err(Error::Invalid(format!(
                "Alcor module map {} exceeds {MAX_ALCOR_MODULE_MAPPINGS} entries",
                path.display()
            )));
        }
    }
    if !saw_module_section {
        return Err(Error::Invalid(format!(
            "Alcor module map {} lacks [MODULE_FETURE]",
            path.display()
        )));
    }
    Ok(mappings)
}

fn parse_alcor_default_enable_25ns(path: &Path, bytes: &[u8]) -> Result<Option<RawAlcorSetting>> {
    let mut recognized_section = None;
    let mut setting = None;
    for (line_number, raw_line) in checked_ascii_lines(bytes, path)? {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            let section = line[1..line.len() - 1].trim();
            recognized_section = ["AlcorMP", "MAIN"]
                .iter()
                .any(|candidate| section.eq_ignore_ascii_case(candidate))
                .then(|| section.to_string());
            continue;
        }
        let Some(source_section) = recognized_section.as_ref() else {
            continue;
        };
        let Some((key, raw_value)) = line.split_once('=') else {
            return Err(Error::Invalid(format!(
                "Alcor settings {} line {line_number} has no assignment delimiter",
                path.display()
            )));
        };
        if !key.trim().eq_ignore_ascii_case("DefaultEnable25NS") {
            continue;
        }
        if setting.is_some() {
            return Err(Error::Invalid(format!(
                "Alcor settings {} repeats DefaultEnable25NS across recognized main sections",
                path.display()
            )));
        }
        let value = match raw_value.trim() {
            "0" => false,
            "1" => true,
            value => {
                return Err(Error::Invalid(format!(
                    "Alcor settings {} line {line_number} DefaultEnable25NS value {value:?} is not the recovered 0/1 form",
                    path.display()
                )));
            }
        };
        setting = Some(RawAlcorSetting {
            value,
            source_section: source_section.clone(),
            source_path: path.to_path_buf(),
            source_line: line_number,
        });
    }
    Ok(setting)
}

fn analyze_file(path: &Path, family: Option<Family>) -> Result<AnalyzedFile> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| Error::io(format!("open vendor tool {}", path.display()), Some(error)))?;
    let metadata = file
        .metadata()
        .map_err(|error| Error::io(format!("stat vendor tool {}", path.display()), Some(error)))?;
    if !metadata.is_file() || metadata.len() > MAX_TOOL_FILE_BYTES {
        return Err(Error::Invalid(format!(
            "vendor tool {} must be a regular file no larger than {MAX_TOOL_FILE_BYTES} bytes",
            path.display()
        )));
    }
    let retain_structured_text = structured_text_required(path, family);
    let retain_static_contract = static_contract_required(path, family);
    if (retain_structured_text || retain_static_contract)
        && metadata.len() > MAX_STRUCTURED_TEXT_BYTES
    {
        return Err(Error::Invalid(format!(
            "structured vendor analysis input {} exceeds {MAX_STRUCTURED_TEXT_BYTES} bytes",
            path.display()
        )));
    }

    let selected = PATTERNS
        .iter()
        .filter(|pattern| family.is_none_or(|family| pattern.family == family))
        .collect::<Vec<_>>();
    let selected_markers = MARKERS
        .iter()
        .filter(|marker| {
            marker
                .family
                .is_none_or(|marker_family| family.is_none_or(|family| marker_family == family))
        })
        .collect::<Vec<_>>();
    let mut hash = Sha256::new();
    let mut read_buffer = vec![0u8; READ_CHUNK_BYTES];
    let mut tail = Vec::new();
    let mut head = Vec::new();
    let mut offset = 0u64;
    let mut seen = BTreeSet::new();
    let mut marker_counts: BTreeMap<
        (&'static str, &'static str),
        (u64, u64, &'static MarkerPattern),
    > = BTreeMap::new();
    let mut seen_marker_offsets = BTreeSet::new();
    let mut findings = Vec::new();
    let mut structured_text = Vec::new();
    let mut static_contract_bytes = Vec::new();
    loop {
        let count = file.read(&mut read_buffer).map_err(|error| {
            Error::io(format!("read vendor tool {}", path.display()), Some(error))
        })?;
        if count == 0 {
            break;
        }
        if head.len() < 16 {
            let remaining = 16 - head.len();
            head.extend_from_slice(&read_buffer[..count.min(remaining)]);
        }
        hash.update(&read_buffer[..count]);
        if retain_structured_text {
            structured_text.extend_from_slice(&read_buffer[..count]);
        }
        if retain_static_contract {
            static_contract_bytes.extend_from_slice(&read_buffer[..count]);
        }
        let mut window = Vec::with_capacity(tail.len() + count);
        window.extend_from_slice(&tail);
        window.extend_from_slice(&read_buffer[..count]);
        let window_offset = offset.saturating_sub(tail.len() as u64);
        for pattern in &selected {
            if !binary_representation_allowed(pattern) {
                continue;
            }
            if window.len() < pattern.bytes.len() {
                continue;
            }
            for start in 0..=window.len() - pattern.bytes.len() {
                if window[start] & pattern.mask[0] != pattern.bytes[0] & pattern.mask[0] {
                    continue;
                }
                if pattern_matches(&window[start..start + pattern.bytes.len()], pattern) {
                    let absolute = window_offset + start as u64;
                    if seen.insert((pattern.id, absolute, "binary")) {
                        findings.push(ToolFinding {
                            id: pattern.id,
                            family: pattern.family.as_str(),
                            offset: absolute,
                            bytes_hex: hex::encode(&window[start..start + pattern.bytes.len()]),
                            representation: "binary",
                            classification: pattern.classification,
                            meaning: pattern.meaning,
                            source: pattern.source,
                        });
                    }
                }
            }
        }
        for (source_offsets, values) in source_literal_runs(&window) {
            for pattern in &selected {
                if !source_literal_representation_allowed(pattern) {
                    continue;
                }
                if values.len() < pattern.bytes.len() {
                    continue;
                }
                for command_start in 0..=values.len() - pattern.bytes.len() {
                    let command = &values[command_start..command_start + pattern.bytes.len()];
                    if !pattern_matches(command, pattern) {
                        continue;
                    }
                    let absolute = window_offset + source_offsets[command_start] as u64;
                    if seen.insert((pattern.id, absolute, "source-literal")) {
                        findings.push(ToolFinding {
                            id: pattern.id,
                            family: pattern.family.as_str(),
                            offset: absolute,
                            bytes_hex: hex::encode(command),
                            representation: "source-literal",
                            classification: pattern.classification,
                            meaning: pattern.meaning,
                            source: pattern.source,
                        });
                    }
                }
            }
        }
        for marker in &selected_markers {
            for (encoding, needle) in [
                ("ascii", marker_bytes(marker.value, false)),
                ("utf-16le", marker_bytes(marker.value, true)),
            ] {
                for start in marker_offsets(&window, &needle) {
                    let absolute = window_offset + start as u64;
                    if !seen_marker_offsets.insert((marker.id, encoding, absolute)) {
                        continue;
                    }
                    let entry = marker_counts
                        .entry((marker.id, encoding))
                        .or_insert((absolute, 0, marker));
                    entry.0 = entry.0.min(absolute);
                    entry.1 = entry.1.saturating_add(1);
                }
            }
        }
        offset = offset
            .checked_add(count as u64)
            .ok_or_else(|| Error::Invalid("vendor tool size overflow".into()))?;
        if offset > MAX_TOOL_FILE_BYTES {
            return Err(Error::Invalid(format!(
                "vendor tool {} grew beyond {MAX_TOOL_FILE_BYTES} bytes while reading",
                path.display()
            )));
        }
        let keep = window
            .len()
            .min(MAX_PATTERN_TEXT_BYTES.max(MAX_PATTERN_BYTES) - 1);
        tail.clear();
        tail.extend_from_slice(&window[window.len() - keep..]);
    }
    if offset != metadata.len() {
        return Err(Error::Invalid(format!(
            "vendor tool {} changed size while being analyzed",
            path.display()
        )));
    }
    findings.sort_by_key(|finding| (finding.offset, finding.id));
    let mut markers = marker_counts
        .into_iter()
        .map(
            |((id, encoding), (offset, occurrences, marker))| ToolMarker {
                id,
                family: marker
                    .family
                    .map_or("all-controller-families", Family::as_str),
                offset,
                occurrences,
                encoding,
                value: marker.value,
                meaning: marker.meaning,
            },
        )
        .collect::<Vec<_>>();
    markers.sort_by_key(|marker| (marker.offset, marker.id));
    let components = component_inventory(path, family);
    let path_components = lower_path_components(path);
    let filename = path_components
        .last()
        .map(String::as_str)
        .unwrap_or_default();
    let alcor_flash_database = if retain_structured_text
        && family_enabled(family, Family::AlcorUfd)
        && filename == "flashlist.afl"
    {
        Some(crate::alcor_au698x::decode_flash_database(
            &structured_text,
        )?)
    } else {
        None
    };
    let mut decoded_structured_text = None;
    let decoded_content = if retain_structured_text && firstchip_encrypted_database(path, family) {
        let (decoded, metadata) = decode_firstchip_config(&structured_text, path)?;
        decoded_structured_text = Some(decoded);
        Some(metadata)
    } else if retain_structured_text && alcor_ascii_hex_module(path, family) {
        let (decoded, metadata) = decode_alcor_ascii_hex(&structured_text, path)?;
        decoded_structured_text = Some(decoded);
        Some(metadata)
    } else if let Some(database) = &alcor_flash_database {
        Some(ToolDecodedContent {
            scheme: "alcor-ufdcom-xor-swap-stream-records",
            key_hex: hex::encode(crate::alcor_au698x::FLASH_DATABASE_KEY),
            block_bytes: database.header.entry_bytes,
            encrypted_block_bytes: crate::alcor_au698x::FLASH_DATABASE_HEADER_BYTES
                + database.header.entry_bytes * database.header.entry_count,
            trailing_cleartext_bytes: 0,
            text_encoding: "binary-records-with-authenticated-unparsed-suffix",
            decoded_size_bytes: database.header.entry_bytes * database.header.entry_count,
            decoded_sha256: database.decoded_entries_sha256.clone(),
        })
    } else if retain_structured_text
        && family_enabled(family, Family::ChipsbankUfd)
        && has_component(&path_components, "flash")
        && filename == "flash.cbm"
    {
        let (decoded, metadata) = decode_chipsbank_cbm(&structured_text, path)?;
        decoded_structured_text = Some(decoded);
        Some(metadata)
    } else {
        None
    };
    let structured_input = decoded_structured_text
        .as_deref()
        .unwrap_or(structured_text.as_slice());
    let smi_assignments = if retain_structured_text
        && family_enabled(family, Family::SiliconMotionUfd)
        && has_component(&path_components, "ufd_all_forcefw")
        && filename.ends_with(".ffw")
    {
        parse_smi_force_map(path, structured_input)?
    } else {
        Vec::new()
    };
    let alcor_scope = alcor_controller_scope(&path_components);
    let nand_identities = if let Some(database) = &alcor_flash_database {
        alcor_flash_database_identities(path, database)
    } else if retain_structured_text
        && family_enabled(family, Family::AlcorUfd)
        && filename == "flashlist.ini"
        && alcor_scope.is_none()
    {
        parse_alcor_nand_identities(path, structured_input)?
    } else if retain_structured_text
        && family_enabled(family, Family::FirstchipUfd)
        && has_component(&path_components, "config")
        && filename == "flash.bin"
    {
        parse_firstchip_nand_identities(path, structured_input)?
    } else if retain_structured_text
        && family_enabled(family, Family::InnostorUfd)
        && filename.contains("flashdatabase")
        && filename.ends_with(".ini")
    {
        parse_innostor_nand_identities(path, structured_input)?
    } else if retain_structured_text
        && family_enabled(family, Family::ChipsbankUfd)
        && has_component(&path_components, "flash")
        && filename == "flash.cbm"
    {
        parse_chipsbank_nand_identities(path, structured_input)?
    } else {
        Vec::new()
    };
    let alcor_selections = alcor_flash_database
        .as_ref()
        .map(|database| alcor_flash_database_selections(path, database))
        .transpose()?
        .unwrap_or_default();
    let alcor_default_enable_25ns = if retain_structured_text
        && family_enabled(family, Family::AlcorUfd)
        && filename == "alcormp.ini"
        && alcor_scope.is_none()
    {
        parse_alcor_default_enable_25ns(path, structured_input)?
    } else {
        None
    };
    let read_retry_records = if retain_structured_text
        && family_enabled(family, Family::FirstchipUfd)
        && has_component(&path_components, "config")
        && filename == "readretry.bin"
    {
        parse_firstchip_read_retry_records(path, structured_input)?
    } else {
        Vec::new()
    };
    let firmware_indices = if retain_structured_text
        && family_enabled(family, Family::ChipsbankUfd)
        && has_component(&path_components, "libin")
        && filename == "umptool.ini"
    {
        parse_chipsbank_controller_manifest(path, structured_input)?
    } else if retain_structured_text
        && family_enabled(family, Family::InnostorUfd)
        && filename.contains("fwindex")
        && filename.ends_with(".cfg")
    {
        parse_innostor_firmware_index(path, structured_input)?
    } else {
        Vec::new()
    };
    let module_mappings = if retain_structured_text
        && family_enabled(family, Family::AlcorUfd)
        && filename == "flashlist.ini"
        && alcor_scope.is_some()
    {
        parse_alcor_module_mappings(
            path,
            structured_input,
            alcor_scope.as_deref().ok_or_else(|| {
                Error::Invalid(format!(
                    "Alcor module map {} has no exact CTL generation scope",
                    path.display()
                ))
            })?,
        )?
    } else {
        Vec::new()
    };
    let sha256 = hex::encode(hash.finalize());
    let format = format_name(&head);
    let host_transport_contracts = if retain_static_contract {
        static_transport_contract(
            path,
            family,
            offset,
            &sha256,
            format,
            &static_contract_bytes,
        )
        .into_iter()
        .collect()
    } else {
        Vec::new()
    };
    Ok(AnalyzedFile {
        report: ToolFileAnalysis {
            path: path.to_path_buf(),
            size_bytes: offset,
            sha256,
            format,
            findings,
            markers,
            components,
            decoded_content,
        },
        smi_assignments,
        nand_identities,
        read_retry_records,
        firmware_indices,
        module_mappings,
        alcor_selections,
        alcor_default_enable_25ns,
        host_transport_contracts,
    })
}

fn collect_files(root: &Path) -> Result<Vec<PathBuf>> {
    let metadata = std::fs::symlink_metadata(root)
        .map_err(|error| Error::io(format!("stat vendor tool {}", root.display()), Some(error)))?;
    if metadata.file_type().is_symlink() {
        return Err(Error::Permission(format!(
            "vendor tool path {} is a symbolic link",
            root.display()
        )));
    }
    if metadata.is_file() {
        return Ok(vec![root.to_path_buf()]);
    }
    if !metadata.is_dir() {
        return Err(Error::Invalid(format!(
            "vendor tool path {} is neither a regular file nor a directory",
            root.display()
        )));
    }
    let mut pending = vec![root.to_path_buf()];
    let mut files = Vec::new();
    while let Some(directory) = pending.pop() {
        let entries = std::fs::read_dir(&directory).map_err(|error| {
            Error::io(
                format!("read vendor tool directory {}", directory.display()),
                Some(error),
            )
        })?;
        for entry in entries {
            let entry = entry.map_err(|error| {
                Error::io(
                    format!("read vendor tool directory {}", directory.display()),
                    Some(error),
                )
            })?;
            let path = entry.path();
            let kind = entry.file_type().map_err(|error| {
                Error::io(format!("stat vendor tool {}", path.display()), Some(error))
            })?;
            if kind.is_symlink() {
                return Err(Error::Permission(format!(
                    "vendor tool tree contains symbolic link {}",
                    path.display()
                )));
            }
            if kind.is_dir() {
                pending.push(path);
            } else if kind.is_file() {
                files.push(path);
                if files.len() > MAX_TOOL_FILES {
                    return Err(Error::Invalid(format!(
                        "vendor tool tree exceeds the {MAX_TOOL_FILES}-file analysis bound"
                    )));
                }
            } else {
                return Err(Error::Invalid(format!(
                    "vendor tool tree contains unsupported entry {}",
                    path.display()
                )));
            }
        }
    }
    files.sort();
    Ok(files)
}

type ArtifactIndex = BTreeMap<String, Vec<ToolResolvedArtifact>>;

fn build_artifact_index(files: &[AnalyzedFile]) -> ArtifactIndex {
    let mut index = ArtifactIndex::new();
    for file in files {
        let Some(filename) = file
            .report
            .path
            .file_name()
            .and_then(|value| value.to_str())
        else {
            continue;
        };
        index
            .entry(filename.to_ascii_lowercase())
            .or_default()
            .push(ToolResolvedArtifact {
                path: file.report.path.clone(),
                size_bytes: file.report.size_bytes,
                sha256: file.report.sha256.clone(),
            });
    }
    for candidates in index.values_mut() {
        candidates.sort_by(|left, right| left.path.cmp(&right.path));
    }
    index
}

fn normalized_declared_path(value: &str) -> String {
    value
        .replace('\\', "/")
        .trim_start_matches('/')
        .to_ascii_lowercase()
}

fn artifact_basename(value: &str) -> Option<String> {
    let normalized = normalized_declared_path(value);
    let basename = normalized.rsplit('/').next()?;
    let extension = basename.rsplit_once('.')?.1;
    if !matches!(extension, "bin" | "dll" | "ebi" | "ffw" | "dbf") {
        return None;
    }
    Some(basename.to_string())
}

fn resolve_artifact(value: &str, index: &ArtifactIndex) -> ToolArtifactReference {
    let normalized = normalized_declared_path(value);
    let basename = normalized.rsplit('/').next().unwrap_or_default();
    let all_candidates = index.get(basename).cloned().unwrap_or_default();
    let suffix_candidates = if normalized.contains('/') {
        all_candidates
            .iter()
            .filter(|candidate| {
                candidate
                    .path
                    .to_string_lossy()
                    .replace('\\', "/")
                    .to_ascii_lowercase()
                    .ends_with(&normalized)
            })
            .cloned()
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let candidates = if suffix_candidates.is_empty() {
        all_candidates
    } else {
        suffix_candidates
    };
    let resolution = match candidates.as_slice() {
        [] => "missing",
        [_] => "unique",
        [first, rest @ ..]
            if rest.iter().all(|candidate| {
                candidate.size_bytes == first.size_bytes && candidate.sha256 == first.sha256
            }) =>
        {
            "identical-content"
        }
        _ => "ambiguous",
    };
    ToolArtifactReference {
        declared_path: value.to_string(),
        resolution,
        candidates,
    }
}

fn resolve_smi_artifact(
    value: &str,
    controller_id: &str,
    index: &ArtifactIndex,
) -> ToolArtifactReference {
    let global = resolve_artifact(value, index);
    if !matches!(global.resolution, "ambiguous") {
        return global;
    }
    let Some(controller) = controller_id.strip_prefix("smi-sm") else {
        return global;
    };
    let scoped_components = [format!("sm{controller}"), format!("ufd_{controller}")];
    let candidates = global
        .candidates
        .iter()
        .filter(|candidate| {
            lower_path_components(&candidate.path)
                .iter()
                .any(|component| scoped_components.contains(component))
        })
        .cloned()
        .collect::<Vec<_>>();
    if candidates.is_empty() {
        return global;
    }
    let resolution = match candidates.as_slice() {
        [_] => "unique",
        [first, rest @ ..]
            if rest.iter().all(|candidate| {
                candidate.size_bytes == first.size_bytes && candidate.sha256 == first.sha256
            }) =>
        {
            "identical-content"
        }
        _ => "ambiguous",
    };
    ToolArtifactReference {
        declared_path: value.to_string(),
        resolution,
        candidates,
    }
}

fn group_smi_bindings(
    files: &[AnalyzedFile],
    artifact_index: &ArtifactIndex,
) -> Vec<ToolNandBinding> {
    let mut grouped: BTreeMap<(PathBuf, String, String), Vec<RawSmiAssignment>> = BTreeMap::new();
    for assignment in files
        .iter()
        .flat_map(|file| file.smi_assignments.iter().cloned())
    {
        grouped
            .entry((
                assignment.source_path.clone(),
                assignment.controller_id.clone(),
                assignment.nand_id.clone(),
            ))
            .or_default()
            .push(assignment);
    }
    grouped
        .into_iter()
        .map(
            |((source_path, controller_id, nand_id), mut raw_assignments)| {
                raw_assignments.sort_by_key(|assignment| assignment.source_line);
                let mut values: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
                let assignments = raw_assignments
                    .into_iter()
                    .map(|assignment| {
                        let conflict_key = assignment
                            .key_suffix
                            .clone()
                            .unwrap_or_else(|| "<bare>".to_string());
                        values
                            .entry(conflict_key)
                            .or_default()
                            .insert(assignment.value.clone());
                        let artifact = artifact_basename(&assignment.value).map(|_| {
                            resolve_smi_artifact(
                                &assignment.value,
                                &assignment.controller_id,
                                artifact_index,
                            )
                        });
                        ToolTupleAssignment {
                            key_suffix: assignment.key_suffix,
                            value: assignment.value,
                            source_line: assignment.source_line,
                            artifact,
                        }
                    })
                    .collect::<Vec<_>>();
                let conflicting_key_suffixes = values
                    .into_iter()
                    .filter_map(|(key, values)| (values.len() > 1).then_some(key))
                    .collect::<Vec<_>>();
                ToolNandBinding {
                    family: Family::SiliconMotionUfd.as_str(),
                    controller_id,
                    nand_id,
                    source_path,
                    selection_unambiguous: conflicting_key_suffixes.is_empty(),
                    conflicting_key_suffixes,
                    assignments,
                }
            },
        )
        .collect()
}

fn resolve_alcor_module_mappings(
    files: &[AnalyzedFile],
    artifact_index: &ArtifactIndex,
) -> Vec<ToolModuleMapping> {
    let mut mappings = files
        .iter()
        .flat_map(|file| file.module_mappings.iter().cloned())
        .map(|mapping| ToolModuleMapping {
            family: Family::AlcorUfd.as_str(),
            controller_id: mapping.controller_id,
            artifact: resolve_artifact(&mapping.module, artifact_index),
            module: mapping.module,
            parameters: mapping.parameters,
            source_path: mapping.source_path,
            source_line: mapping.source_line,
        })
        .collect::<Vec<_>>();
    mappings.sort_by(|left, right| {
        (&left.source_path, left.source_line).cmp(&(&right.source_path, right.source_line))
    });
    mappings
}

fn alcor_flash_database_converter_source(
    report: &ToolFileAnalysis,
) -> Option<ToolAlcorConverterSource> {
    if report.format != "portable-executable" {
        return None;
    }
    if report.sha256 == crate::alcor_au698x::LEGACY_FLASH_DATABASE_SELECTOR_SOURCE_SHA256 {
        return Some(ToolAlcorConverterSource {
            implementation: "legacy-alcormp-selector",
            converter: crate::alcor_au698x::FlashDatabaseConverter::LegacyAlcorMp130205,
            source_path: report.path.clone(),
            source_sha256: report.sha256.clone(),
            routine_va_hex: format!(
                "0x{:08x}",
                crate::alcor_au698x::LEGACY_FLASH_DATABASE_SELECTOR_VA
            ),
            selector_table_va_hex: Some(format!(
                "0x{:08x}",
                crate::alcor_au698x::LEGACY_FLASH_DATABASE_SELECTOR_TABLE_VA
            )),
            recovered_contract: "legacy version-4 AFL object layout and object-0x26 limit",
        });
    }
    if report.sha256 == crate::alcor_au698x::FLASH_DATABASE_CONVERTER_SOURCE_SHA256 {
        return Some(ToolAlcorConverterSource {
            implementation: "ufdapi-gen-converter",
            converter: crate::alcor_au698x::FlashDatabaseConverter::UfdApiGen1310,
            source_path: report.path.clone(),
            source_sha256: report.sha256.clone(),
            routine_va_hex: format!("0x{:08x}", crate::alcor_au698x::FLASH_DATABASE_CONVERTER_VA),
            selector_table_va_hex: None,
            recovered_contract: "UfdApi version-4 AFL object layout and object-0x24 limit",
        });
    }
    None
}

fn resolve_alcor_flash_database_converter_sources(
    files: &[AnalyzedFile],
) -> (
    &'static str,
    Option<crate::alcor_au698x::FlashDatabaseConverter>,
    Vec<ToolAlcorConverterSource>,
) {
    let mut sources = files
        .iter()
        .filter_map(|file| alcor_flash_database_converter_source(&file.report))
        .collect::<Vec<_>>();
    sources.sort_by(|left, right| {
        (&left.source_sha256, &left.source_path).cmp(&(&right.source_sha256, &right.source_path))
    });
    let converters = sources
        .iter()
        .map(|source| source.converter)
        .collect::<BTreeSet<_>>();
    let resolution = match (sources.len(), converters.len()) {
        (0, _) => "missing",
        (1, 1) => "unique",
        (_, 1) => "identical-content",
        (_, _) => "ambiguous",
    };
    let converter = (converters.len() == 1)
        .then(|| converters.iter().next().copied())
        .flatten();
    (resolution, converter, sources)
}

fn resolve_alcor_candidate_tuples(
    files: &[AnalyzedFile],
    identities: &[ToolNandIdentity],
    module_mappings: &[ToolModuleMapping],
) -> Result<Vec<ToolAlcorCandidateTuple>> {
    let identity_resolution = identities
        .iter()
        .filter(|identity| identity.family == Family::AlcorUfd.as_str())
        .map(|identity| (identity.nand_id.as_str(), identity.selection_unambiguous))
        .collect::<BTreeMap<_, _>>();
    let settings = files
        .iter()
        .filter_map(|file| file.alcor_default_enable_25ns.as_ref())
        .collect::<Vec<_>>();
    let setting_values = settings
        .iter()
        .map(|setting| setting.value)
        .collect::<BTreeSet<_>>();
    let (package_setting_resolution, package_setting_value) = match setting_values.len() {
        0 => ("missing", None),
        1 if settings.len() == 1 => ("unique", setting_values.iter().next().copied()),
        1 => ("identical-values", setting_values.iter().next().copied()),
        _ => ("ambiguous", None),
    };
    let package_setting_source = package_setting_value.and_then(|value| {
        settings
            .iter()
            .find(|setting| setting.value == value)
            .copied()
    });
    let (
        flash_database_converter_resolution,
        flash_database_converter,
        flash_database_converter_sources,
    ) = resolve_alcor_flash_database_converter_sources(files);
    let flash_database_converter_resolved = flash_database_converter.is_some();
    let mut tuples = files
        .iter()
        .flat_map(|file| file.alcor_selections.iter())
        .map(|selection| {
            let default_enable_25ns_required = selection.operational_input.record_39 <= 0x19;
            let (default_enable_25ns_resolution, default_enable_25ns) =
                if default_enable_25ns_required {
                    (package_setting_resolution, package_setting_value)
                } else {
                    ("not-used", None)
                };
            let mut operational_fields = flash_database_converter.map(|converter| match converter {
                crate::alcor_au698x::FlashDatabaseConverter::LegacyAlcorMp130205 => {
                    selection
                        .legacy_operational_fields_25ns_disabled
                        .clone()
                }
                crate::alcor_au698x::FlashDatabaseConverter::UfdApiGen1310 => selection
                    .ufdapi_operational_fields_25ns_disabled
                    .clone(),
            });
            if default_enable_25ns == Some(true) {
                if let Some(fields) = operational_fields.as_mut() {
                    fields.set_default_enable_25ns(true, selection.object_14_25ns_enabled);
                }
            }
            let operational_resolved = flash_database_converter_resolved
                && (!default_enable_25ns_required || default_enable_25ns.is_some());
            let feature_candidates = module_mappings
                .iter()
                .filter(|mapping| {
                    mapping.controller_id == selection.controller_id
                        && mapping
                            .module
                            .eq_ignore_ascii_case(&selection.runtime_module)
                })
                .cloned()
                .collect::<Vec<_>>();
            let mut module_feature_resolution = match feature_candidates.as_slice() {
                [] => "missing",
                [_] => "unique",
                _ => "ambiguous",
            };
            let mut module_feature_error = None;
            let mut parsed_module_feature = None;
            let mut controller_adjusted_module_feature = None;
            if let [candidate] = feature_candidates.as_slice() {
                let parsed = (|| -> Result<_> {
                    let generation = selection
                        .controller_id
                        .strip_prefix("alcor-ctl-")
                        .filter(|value| value.len() == 2)
                        .ok_or_else(|| {
                            Error::Invalid(format!(
                                "Alcor candidate controller id {} has no exact generation",
                                selection.controller_id
                            ))
                        })?;
                    let generation = u8::from_str_radix(generation, 16).map_err(|_| {
                        Error::Invalid(format!(
                            "Alcor candidate controller id {} has an invalid generation",
                            selection.controller_id
                        ))
                    })?;
                    crate::alcor_au698x::validate_module_feature_parameter_count(
                        generation,
                        candidate.parameters.len(),
                    )?;
                    let feature = crate::alcor_au698x::parse_module_feature_parameters(
                        &candidate.parameters,
                    )?;
                    let controller_limit = if matches!(generation, 0x10 | 0x13) {
                        None
                    } else {
                        Some(
                            operational_fields
                                .as_ref()
                                .ok_or_else(|| {
                                    Error::Invalid(
                                        "Alcor non-CTL10/13 module feature requires a uniquely resolved AFL converter"
                                            .into(),
                                    )
                                })?
                                .controller_module_limit(),
                        )
                    };
                    let adjusted = crate::alcor_au698x::apply_module_feature_controller_limit(
                        &feature,
                        generation,
                        controller_limit,
                    )?;
                    Ok((feature, adjusted))
                })();
                match parsed {
                    Ok((feature, adjusted)) => {
                        parsed_module_feature = Some(feature);
                        controller_adjusted_module_feature = Some(adjusted);
                    }
                    Err(error) => {
                        module_feature_resolution = "invalid";
                        module_feature_error = Some(error.to_string());
                    }
                }
            }
            let artifact_resolved = matches!(
                feature_candidates.as_slice(),
                [candidate]
                    if matches!(candidate.artifact.resolution, "unique" | "identical-content")
            );
            let selection_unambiguous = identity_resolution
                .get(selection.nand_id.as_str())
                .copied()
                .unwrap_or(false)
                && module_feature_resolution == "unique"
                && controller_adjusted_module_feature.is_some()
                && artifact_resolved
                && operational_resolved
                && flash_database_converter_resolved;
            Ok(ToolAlcorCandidateTuple {
                family: Family::AlcorUfd.as_str(),
                controller_id: selection.controller_id.clone(),
                nand_id: selection.nand_id.clone(),
                model: selection.model.clone(),
                database_selector: selection.database_selector.clone(),
                operational_record_sha256: selection.operational_record_sha256.clone(),
                runtime_module: selection.runtime_module.clone(),
                auxiliary_1: selection.auxiliary_1.clone(),
                auxiliary_2: selection.auxiliary_2.clone(),
                operational_input: selection.operational_input.clone(),
                default_enable_25ns_required,
                default_enable_25ns_resolution,
                default_enable_25ns,
                default_enable_25ns_source_path: default_enable_25ns
                    .and(package_setting_source)
                    .map(|setting| setting.source_path.clone()),
                default_enable_25ns_source_line: default_enable_25ns
                    .and(package_setting_source)
                    .map(|setting| setting.source_line),
                default_enable_25ns_source_section: default_enable_25ns
                    .and(package_setting_source)
                    .map(|setting| setting.source_section.clone()),
                operational_fields: operational_resolved
                    .then_some(operational_fields)
                    .flatten(),
                module_feature_resolution,
                module_feature_error,
                module_feature_candidates: feature_candidates,
                parsed_module_feature,
                controller_adjusted_module_feature,
                selection_unambiguous,
                flash_database_converter_resolution,
                flash_database_converter_sources: flash_database_converter_sources.clone(),
                source_path: selection.source_path.clone(),
                source_line: selection.source_line,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    tuples.sort_by(|left, right| {
        (
            &left.nand_id,
            &left.controller_id,
            &left.database_selector,
            &left.runtime_module,
        )
            .cmp(&(
                &right.nand_id,
                &right.controller_id,
                &right.database_selector,
                &right.runtime_module,
            ))
    });
    Ok(tuples)
}

fn resolve_identity_artifacts(identities: &mut [ToolNandIdentity], artifact_index: &ArtifactIndex) {
    for identity in identities.iter_mut() {
        let mut references = Vec::new();
        let mut seen_declared_paths = BTreeSet::new();
        for parameter in &identity.parameters {
            let parameter_name = parameter.name.to_ascii_lowercase();
            let is_artifact = if identity.family == Family::FirstchipUfd.as_str() {
                matches!(
                    parameter_name.as_str(),
                    "extcodefilename"
                        | "scancodefilename"
                        | "mpcodefilename"
                        | "randseedfilename"
                        | "binscriptfilename"
                )
            } else if identity.family == Family::ChipsbankUfd.as_str() {
                matches!(parameter_name.as_str(), "code_file" | "scan_file")
            } else if identity.family == Family::AlcorUfd.as_str() {
                parameter_name.starts_with("alcor_ctl_")
                    && parameter_name.ends_with("_runtime_module")
            } else {
                false
            };
            if !is_artifact {
                continue;
            }
            let declared = parameter.value.trim();
            if declared.is_empty() || declared == "0" {
                continue;
            }
            if !seen_declared_paths.insert(declared.to_ascii_lowercase()) {
                continue;
            }
            let artifact = resolve_artifact(declared, artifact_index);
            if artifact.resolution == "missing"
                || (matches!(
                    identity.family,
                    family if family == Family::FirstchipUfd.as_str()
                        || family == Family::AlcorUfd.as_str()
                ) && artifact.resolution == "ambiguous")
            {
                identity.selection_unambiguous = false;
            }
            references.push(artifact);
        }
        identity.artifact_references = references;
    }
}

fn resolve_firmware_indices(files: &[AnalyzedFile]) -> Vec<ToolFirmwareIndexRecord> {
    let mut records = Vec::new();
    for raw in files
        .iter()
        .flat_map(|file| file.firmware_indices.iter().cloned())
    {
        let needle = format!(
            "/{}/",
            raw.declared_directory
                .replace('\\', "/")
                .trim_matches('/')
                .to_ascii_lowercase()
        );
        let mut artifacts = Vec::new();
        for file in files {
            let normalized_path = file
                .report
                .path
                .to_string_lossy()
                .replace('\\', "/")
                .to_ascii_lowercase();
            let Some(position) = normalized_path.rfind(&needle) else {
                continue;
            };
            let remainder = &normalized_path[position + needle.len()..];
            if remainder.is_empty() || remainder.contains('/') {
                continue;
            }
            let Some(component) = file.report.components.iter().find(|component| {
                if component.family != raw.family {
                    return false;
                }
                match raw.purpose {
                    "controller-code-catalog" => component.role == "nand-operation-module",
                    "controller-scan-catalog" => component.role == "scan-sort-module",
                    _ => matches!(
                        component.role,
                        "controller-stage-one-code"
                            | "controller-stage-two-code"
                            | "flash-translation-layer-code"
                            | "controller-initializer"
                            | "sorting-loader"
                    ),
                }
            }) else {
                continue;
            };
            artifacts.push(ToolFirmwareArtifact {
                role: component.role,
                path: file.report.path.clone(),
                size_bytes: file.report.size_bytes,
                sha256: file.report.sha256.clone(),
            });
        }
        artifacts.sort_by(|left, right| (&left.role, &left.path).cmp(&(&right.role, &right.path)));
        let (required_roles, allow_multiple): (&[&'static str], bool) = match raw.purpose {
            "controller-code-catalog" => (&["nand-operation-module"], true),
            "controller-scan-catalog" => (&["scan-sort-module"], true),
            "sorting-first-execute" => (&["sorting-loader"], false),
            _ => (
                &[
                    "controller-stage-one-code",
                    "controller-stage-two-code",
                    "flash-translation-layer-code",
                ],
                false,
            ),
        };
        let mut missing_required_roles = Vec::new();
        let mut duplicate_roles = Vec::new();
        for role in required_roles {
            let count = artifacts
                .iter()
                .filter(|artifact| artifact.role == *role)
                .count();
            if count == 0 {
                missing_required_roles.push(*role);
            } else if count > 1 && !allow_multiple {
                duplicate_roles.push(*role);
            }
        }
        let selection_unambiguous = missing_required_roles.is_empty() && duplicate_roles.is_empty();
        records.push(ToolFirmwareIndexRecord {
            family: raw.family,
            controller_id: raw.controller_id,
            purpose: raw.purpose,
            selector: raw.selector,
            declared_directory: raw.declared_directory,
            version: raw.version,
            source_path: raw.source_path,
            source_line: raw.source_line,
            artifacts,
            missing_required_roles,
            duplicate_roles,
            selection_unambiguous,
        });
    }
    records.sort_by(|left, right| {
        (&left.source_path, left.source_line).cmp(&(&right.source_path, right.source_line))
    });
    records
}

/// Recursively analyze regular files under `root`. Unmatched files are
/// included only when requested, keeping the default output useful for large
/// factory packages with thousands of NAND-specific payloads.
pub fn analyze(
    root: &Path,
    family_filter: Option<&str>,
    include_unmatched: bool,
) -> Result<ToolAnalysis> {
    let family =
        match family_filter {
            Some(value) => Some(family_from_str(value).ok_or_else(|| {
                Error::Usage(format!("unknown canonical controller family {value}"))
            })?),
            None => None,
        };
    let paths = collect_files(root)?;
    let scanned_files = paths.len();
    let mut analyzed_files = Vec::with_capacity(paths.len());
    for path in paths {
        analyzed_files.push(analyze_file(&path, family)?);
    }
    let artifact_index = build_artifact_index(&analyzed_files);
    let nand_binding_records = group_smi_bindings(&analyzed_files, &artifact_index);
    let mut nand_identity_records = analyzed_files
        .iter()
        .flat_map(|file| file.nand_identities.iter().cloned())
        .collect::<Vec<_>>();
    nand_identity_records.sort_by(|left, right| {
        (&left.source_path, left.source_line).cmp(&(&right.source_path, right.source_line))
    });
    resolve_identity_artifacts(&mut nand_identity_records, &artifact_index);
    let mut read_retry_record_records = analyzed_files
        .iter()
        .flat_map(|file| file.read_retry_records.iter().cloned())
        .collect::<Vec<_>>();
    read_retry_record_records.sort_by(|left, right| {
        (&left.source_path, left.source_line).cmp(&(&right.source_path, right.source_line))
    });
    let module_mapping_records = resolve_alcor_module_mappings(&analyzed_files, &artifact_index);
    let alcor_candidate_tuple_records = resolve_alcor_candidate_tuples(
        &analyzed_files,
        &nand_identity_records,
        &module_mapping_records,
    )?;
    let firmware_index_record_records = resolve_firmware_indices(&analyzed_files);
    let mut host_transport_contract_records = analyzed_files
        .iter()
        .flat_map(|file| file.host_transport_contracts.iter().cloned())
        .collect::<Vec<_>>();
    host_transport_contract_records.sort_by(|left, right| left.source_path.cmp(&right.source_path));
    let artifact_resolutions = nand_binding_records
        .iter()
        .flat_map(|binding| binding.assignments.iter())
        .filter_map(|assignment| assignment.artifact.as_ref())
        .map(|artifact| artifact.resolution)
        .chain(
            module_mapping_records
                .iter()
                .map(|mapping| mapping.artifact.resolution),
        )
        .chain(
            nand_identity_records
                .iter()
                .flat_map(|identity| identity.artifact_references.iter())
                .map(|artifact| artifact.resolution),
        )
        .collect::<Vec<_>>();

    let mut files = Vec::new();
    let mut matched_files = 0usize;
    let mut findings = 0usize;
    let mut markers = 0usize;
    let mut components = 0usize;
    for analysis in analyzed_files {
        let has_structured_records = !analysis.smi_assignments.is_empty()
            || !analysis.nand_identities.is_empty()
            || !analysis.read_retry_records.is_empty()
            || !analysis.firmware_indices.is_empty()
            || !analysis.module_mappings.is_empty()
            || !analysis.alcor_selections.is_empty()
            || analysis.alcor_default_enable_25ns.is_some()
            || !analysis.host_transport_contracts.is_empty();
        let report = analysis.report;
        if !report.findings.is_empty()
            || !report.markers.is_empty()
            || !report.components.is_empty()
            || has_structured_records
        {
            matched_files += 1;
            findings = findings
                .checked_add(report.findings.len())
                .ok_or_else(|| Error::Invalid("vendor tool finding count overflow".into()))?;
            markers = markers
                .checked_add(report.markers.len())
                .ok_or_else(|| Error::Invalid("vendor tool marker count overflow".into()))?;
            components = components
                .checked_add(report.components.len())
                .ok_or_else(|| Error::Invalid("vendor tool component count overflow".into()))?;
        }
        if include_unmatched
            || !report.findings.is_empty()
            || !report.markers.is_empty()
            || !report.components.is_empty()
            || has_structured_records
            || scanned_files == 1
        {
            files.push(report);
        }
    }
    Ok(ToolAnalysis {
        schema: TOOL_ANALYSIS_SCHEMA,
        root: root.to_path_buf(),
        family_filter: family.map(|family| family.as_str().to_string()),
        candidate_family_scope: family.map_or_else(
            || Family::ALL.iter().copied().map(Family::as_str).collect(),
            |family| vec![family.as_str()],
        ),
        scanned_files,
        matched_files,
        findings,
        markers,
        components,
        nand_bindings: nand_binding_records.len(),
        ambiguous_nand_bindings: nand_binding_records
            .iter()
            .filter(|binding| !binding.selection_unambiguous)
            .count(),
        nand_identities: nand_identity_records.len(),
        read_retry_records: read_retry_record_records.len(),
        firmware_index_records: firmware_index_record_records.len(),
        module_mappings: module_mapping_records.len(),
        alcor_candidate_tuples: alcor_candidate_tuple_records.len(),
        ambiguous_alcor_candidate_tuples: alcor_candidate_tuple_records
            .iter()
            .filter(|record| !record.selection_unambiguous)
            .count(),
        host_transport_contracts: host_transport_contract_records.len(),
        unique_artifact_references: artifact_resolutions
            .iter()
            .filter(|resolution| **resolution == "unique")
            .count(),
        identical_content_artifact_references: artifact_resolutions
            .iter()
            .filter(|resolution| **resolution == "identical-content")
            .count(),
        ambiguous_artifact_references: artifact_resolutions
            .iter()
            .filter(|resolution| **resolution == "ambiguous")
            .count(),
        missing_artifact_references: artifact_resolutions
            .iter()
            .filter(|resolution| **resolution == "missing")
            .count(),
        static_matches_are_candidates_only: true,
        production_eligible: false,
        nand_binding_records,
        nand_identity_records,
        read_retry_record_records,
        firmware_index_record_records,
        module_mapping_records,
        alcor_candidate_tuple_records,
        host_transport_contract_records,
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use des::cipher::BlockCipherEncrypt;

    fn encrypt_firstchip_fixture(text: &str) -> (Vec<u8>, Vec<u8>) {
        let mut plaintext = vec![0xff, 0xfe];
        for code_unit in text.encode_utf16() {
            plaintext.extend_from_slice(&code_unit.to_le_bytes());
        }
        let encrypted_block_bytes = plaintext.len() / 8 * 8;
        let cipher = Des::new_from_slice(FIRSTCHIP_CONFIG_KEY).unwrap();
        let mut encoded = plaintext.clone();
        for chunk in encoded[..encrypted_block_bytes].chunks_exact_mut(8) {
            let mut block = des::cipher::Block::<Des>::default();
            block.copy_from_slice(chunk);
            cipher.encrypt_block(&mut block);
            chunk.copy_from_slice(&block);
        }
        (encoded, plaintext)
    }

    fn encode_chipsbank_fixture(text: &str) -> Vec<u8> {
        let (encoded_text, _, had_errors) = GBK.encode(text);
        assert!(!had_errors);
        let mut decoded = vec![0x12, 0x34, 0x56, 0x78];
        decoded.extend_from_slice(&encoded_text);
        decoded.extend_from_slice(&[0, 0, 0x9a, 0xbc, 0xde, 0xf0]);
        for (index, byte) in decoded.iter_mut().enumerate() {
            *byte ^= CHIPSBANK_CBM_XOR_KEY[index % CHIPSBANK_CBM_XOR_KEY.len()];
        }
        decoded.extend_from_slice(CHIPSBANK_CBM_MAGIC);
        decoded
    }

    #[test]
    fn accepts_only_recovered_alcor_main_setting_sections() {
        for section in ["AlcorMP", "MAIN"] {
            let contents = format!("[{section}]\r\nDefaultEnable25NS=0\r\n");
            let setting =
                parse_alcor_default_enable_25ns(Path::new("AlcorMP.ini"), contents.as_bytes())
                    .unwrap()
                    .unwrap();
            assert!(!setting.value);
            assert_eq!(setting.source_section, section);
            assert_eq!(setting.source_line, 2);
        }

        assert!(parse_alcor_default_enable_25ns(
            Path::new("AlcorMP.ini"),
            b"[Other]\r\nDefaultEnable25NS=0\r\n",
        )
        .unwrap()
        .is_none());
        assert!(parse_alcor_default_enable_25ns(
            Path::new("AlcorMP.ini"),
            b"[MAIN]\r\nDefaultEnable25NS=0\r\n[AlcorMP]\r\nDefaultEnable25NS=0\r\n",
        )
        .is_err());
    }

    #[test]
    fn binds_alcor_converter_provenance_only_to_exact_factory_hashes() {
        let report_for = |path: &str, sha256: &str| ToolFileAnalysis {
            path: PathBuf::from(path),
            size_bytes: 1,
            sha256: sha256.to_string(),
            format: "portable-executable",
            findings: Vec::new(),
            markers: Vec::new(),
            components: Vec::new(),
            decoded_content: None,
        };
        let legacy = alcor_flash_database_converter_source(&report_for(
            "AlcorMP.exe",
            crate::alcor_au698x::LEGACY_FLASH_DATABASE_SELECTOR_SOURCE_SHA256,
        ))
        .unwrap();
        assert_eq!(legacy.implementation, "legacy-alcormp-selector");
        assert_eq!(legacy.routine_va_hex, "0x00457e30");
        assert_eq!(legacy.selector_table_va_hex.as_deref(), Some("0x00458404"));

        let current = alcor_flash_database_converter_source(&report_for(
            "UfdApi_Gen.dll",
            crate::alcor_au698x::FLASH_DATABASE_CONVERTER_SOURCE_SHA256,
        ))
        .unwrap();
        assert_eq!(current.implementation, "ufdapi-gen-converter");
        assert_eq!(current.routine_va_hex, "0x10044438");
        assert!(current.selector_table_va_hex.is_none());

        assert!(alcor_flash_database_converter_source(&report_for(
            "UfdApi_Gen.dll",
            "0000000000000000000000000000000000000000000000000000000000000000",
        ))
        .is_none());
    }

    #[test]
    fn extracts_public_protocol_constants_across_read_boundaries() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("primary-source-sequences.bin");
        let mut bytes = vec![0x41; READ_CHUNK_BYTES - 8];
        bytes.extend_from_slice(&[0x06, 0x05, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        bytes.extend_from_slice(&[0x81, 0, 0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]);
        std::fs::write(&path, &bytes).unwrap();
        let report = analyze(&path, None, false).unwrap();
        assert_eq!(report.scanned_files, 1);
        assert_eq!(report.matched_files, 1);
        assert!(report.files[0]
            .findings
            .iter()
            .any(|finding| finding.id == "phison-version-page"));
        assert!(report.files[0].findings.iter().any(|finding| {
            finding.id == "alcor-rebuild-config-write" && finding.classification == "state-changing"
        }));
        assert!(!report.production_eligible);
    }

    #[test]
    fn family_filter_excludes_other_protocols() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("protocol.bin");
        std::fs::write(
            &path,
            [
                &[0xf0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02][..],
                &[0xfa, 0x00, 0, 0, 0, 0, 0, 0][..],
            ]
            .concat(),
        )
        .unwrap();
        let report = analyze(&path, Some("silicon-motion-ufd"), false).unwrap();
        assert_eq!(report.findings, 1);
        assert_eq!(report.files[0].findings[0].id, "smi-sm32x-identity-page");
    }

    #[test]
    fn recognizes_official_sandisk_dynamic_logical_command_constructors() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("lpinstaller-constructor.bin");
        std::fs::write(
            &path,
            [
                &[0x6a, 0x00, 0x68, 0xff, 0, 0, 0, 0x6a, 0x01, 0x6a, 0x20][..],
                &[0x6a, 0x00, 0x68, 0xff, 0, 0, 0, 0x6a, 0x00, 0x6a, 0x22][..],
                &[0x6a, 0x00, 0x68, 0xff, 0, 0, 0, 0x6a, 0x00, 0x6a, 0x42][..],
            ]
            .concat(),
        )
        .unwrap();
        let report = analyze(&path, Some("sandisk-cruzer"), false).unwrap();
        let ids = report.files[0]
            .findings
            .iter()
            .map(|finding| finding.id)
            .collect::<BTreeSet<_>>();
        assert!(ids.contains("sandisk-u3-x86-domain-round"));
        assert!(ids.contains("sandisk-u3-x86-set-domains"));
        assert!(ids.contains("sandisk-u3-x86-cd-write"));
        assert_eq!(report.findings, 3);
        assert!(report.files[0].findings.iter().all(|finding| {
            finding.family == "sandisk-cruzer"
                && finding.representation == "binary"
                && finding.meaning.contains("not")
                && finding.source == SANDISK_OFFICIAL_TOOL_SOURCE
        }));
    }

    #[test]
    fn zero_heavy_u3_source_templates_are_not_binary_padding_matches() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("padding.bin");
        std::fs::write(&path, [0xff, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).unwrap();
        let report = analyze(&path, Some("sandisk-cruzer"), false).unwrap();
        assert_eq!(report.findings, 0);
    }

    #[test]
    fn classifies_public_u3_source_literals_as_logical_operations() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("u3_commands.c");
        std::fs::write(
            &path,
            br#"uint8_t security[12] = { 0xff, 0xA2, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t reset[12] = { 0xff, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };"#,
        )
        .unwrap();
        let report = analyze(&path, Some("sandisk-cruzer"), false).unwrap();
        assert!(report.files[0].findings.iter().any(|finding| {
            finding.id == "sandisk-u3-enable-security"
                && finding.representation == "source-literal"
                && finding.classification == "state-changing-logical-security"
        }));
        assert!(report.files[0]
            .findings
            .iter()
            .any(|finding| finding.id == "sandisk-u3-reset"));
    }

    #[test]
    fn generic_research_markers_apply_with_every_family_filter() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("factory-vocabulary.bin");
        std::fs::write(&path, b"NAND ID\0Bad Block\0ECC\0Read Retry\0").unwrap();
        let report = analyze(&path, Some("smsc-ufd"), false).unwrap();
        assert!(report.files[0].markers.iter().any(|marker| {
            marker.id == "research-nand-id" && marker.family == "all-controller-families"
        }));
        assert!(report.files[0]
            .markers
            .iter()
            .any(|marker| marker.id == "research-read-retry"));
    }

    #[test]
    fn every_registered_family_has_a_static_inventory_marker() {
        let covered = MARKERS
            .iter()
            .filter_map(|marker| marker.family)
            .map(Family::as_str)
            .collect::<BTreeSet<_>>();
        let registered = Family::ALL
            .iter()
            .copied()
            .map(Family::as_str)
            .collect::<BTreeSet<_>>();
        assert_eq!(covered, registered);
    }

    #[test]
    fn extracts_exact_smi_nand_bindings_without_hiding_conflicts() {
        let directory = tempfile::tempdir().unwrap();
        let maps = directory.path().join("UFD_ALL_ForceFW");
        let payloads = directory.path().join("payloads");
        let duplicate_payloads = directory.path().join("duplicate-payloads");
        std::fs::create_dir_all(&maps).unwrap();
        std::fs::create_dir_all(&payloads).unwrap();
        std::fs::create_dir_all(&duplicate_payloads).unwrap();
        std::fs::write(payloads.join("SM3281BB_ISP_A.BIN"), b"isp-a").unwrap();
        std::fs::write(duplicate_payloads.join("SM3281BB_ISP_A.BIN"), b"isp-a").unwrap();
        std::fs::write(payloads.join("SM3281BB_ISP_B.BIN"), b"isp-b").unwrap();
        std::fs::write(
            maps.join("SM3281BB.FFW"),
            b"[ForceFW]\r\n\
//FLASH_4548A7937E50_ISP=ignored.bin\r\n\
;FLASH_4548A793_ISP=legacy-prefix.bin\r\n\
FLASH_4548A7937E50_ISP=\"SM3281BB_ISP_A.BIN\"\r\n\
FLASH_4548A7937E50_RETRY=1\r\n\
FLASH_4548A7937E50_ISP=\"SM3281BB_ISP_B.BIN\"\r\n",
        )
        .unwrap();

        let report = analyze(directory.path(), Some("silicon-motion-ufd"), false).unwrap();
        assert_eq!(report.schema, TOOL_ANALYSIS_SCHEMA);
        assert_eq!(report.nand_bindings, 1);
        let binding = &report.nand_binding_records[0];
        assert_eq!(binding.controller_id, "smi-sm3281bb");
        assert_eq!(binding.nand_id, "4548a7937e50");
        assert_eq!(binding.assignments.len(), 3);
        assert_eq!(binding.conflicting_key_suffixes, ["isp"]);
        assert!(!binding.selection_unambiguous);
        let resolutions = binding
            .assignments
            .iter()
            .filter_map(|assignment| assignment.artifact.as_ref())
            .map(|artifact| artifact.resolution)
            .collect::<Vec<_>>();
        assert_eq!(resolutions, ["identical-content", "unique"]);
        assert!(report.files.iter().any(|file| {
            file.components
                .iter()
                .any(|component| component.role == "force-firmware-map")
        }));
    }

    #[test]
    fn rejects_active_smi_prefix_ids_in_structured_maps() {
        let directory = tempfile::tempdir().unwrap();
        let maps = directory.path().join("UFD_ALL_ForceFW");
        std::fs::create_dir_all(&maps).unwrap();
        std::fs::write(
            maps.join("SM3257ENAA.FFW"),
            b"[ForceFW]\r\nFLASH_45D79882_ISP=SM3257ENAAISP.BIN\r\n",
        )
        .unwrap();
        assert!(analyze(directory.path(), Some("silicon-motion-ufd"), false).is_err());
    }

    #[test]
    fn decodes_firstchip_databases_and_preserves_ambiguous_selectors() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config");
        let code = directory.path().join("code/3532");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::create_dir_all(&code).unwrap();
        std::fs::write(code.join("extcode_sample.bin"), b"controller payload").unwrap();

        let mut flash = "[454C98A37651_2]\r\n\
Name=Sample NAND two-bank\r\n\
Name2=Sample Alias\r\n\
CellNum=2\r\n\
CellNum=3\r\n\
ExtCodeFileName=extcode_sample.bin\r\n\
[454C98A37651_4]\r\n\
Name=Sample NAND four-bank\r\n\
CellNum=2\r\n\
[B58444434AA00]\r\n\
Name=Odd vendor identifier\r\n\
Remark=保留\r\n"
            .to_string();
        while (2 + flash.encode_utf16().count() * 2) % 8 != 4 {
            flash.push(';');
        }
        let (flash_encoded, flash_plaintext) = encrypt_firstchip_fixture(&flash);
        std::fs::write(config.join("Flash.bin"), flash_encoded).unwrap();

        let read_retry = "[ReadRetry_7]\r\n\
ReadRetryMode=0\r\n\
RegAddr=b0,b1\r\n\
RegValue=38,45,,5b,4a,,\r\n\
Remark=読出し再試行\r\n";
        let (read_retry_encoded, _) = encrypt_firstchip_fixture(read_retry);
        std::fs::write(config.join("ReadRetry.bin"), read_retry_encoded).unwrap();

        let report = analyze(directory.path(), Some("firstchip-ufd"), false).unwrap();
        assert_eq!(report.nand_identities, 3);
        assert_eq!(report.read_retry_records, 1);
        assert_eq!(report.read_retry_record_records[0].id, "7");
        assert!(report.read_retry_record_records[0]
            .parameters
            .iter()
            .any(|parameter| parameter.name == "Remark" && parameter.value == "読出し再試行"));

        let two_bank = report
            .nand_identity_records
            .iter()
            .find(|identity| identity.database_selector == "454c98a37651_2")
            .unwrap();
        assert_eq!(two_bank.nand_id, "454c98a37651");
        assert_eq!(two_bank.aliases, ["Sample Alias"]);
        assert_eq!(two_bank.conflicting_parameter_names, ["cellnum"]);
        assert!(!two_bank.selection_unambiguous);
        assert_eq!(two_bank.artifact_references.len(), 1);
        assert_eq!(two_bank.artifact_references[0].resolution, "unique");
        assert!(
            !report
                .nand_identity_records
                .iter()
                .find(|identity| identity.database_selector == "454c98a37651_4")
                .unwrap()
                .selection_unambiguous
        );

        let odd = report
            .nand_identity_records
            .iter()
            .find(|identity| identity.database_selector == "b58444434aa00")
            .unwrap();
        assert!(!odd.nand_id_byte_aligned);
        assert!(!odd.selection_unambiguous);
        assert!(odd
            .parameters
            .iter()
            .any(|parameter| { parameter.name == "Remark" && parameter.value == "保留" }));

        let flash_file = report
            .files
            .iter()
            .find(|file| file.path.file_name().and_then(|name| name.to_str()) == Some("Flash.bin"))
            .unwrap();
        let decoded = flash_file.decoded_content.as_ref().unwrap();
        assert_eq!(decoded.trailing_cleartext_bytes, 4);
        assert_eq!(decoded.decoded_size_bytes, flash_plaintext.len());
        assert_eq!(
            decoded.decoded_sha256,
            hex::encode(Sha256::digest(&flash_plaintext))
        );
        assert_ne!(flash_file.sha256, decoded.decoded_sha256);
    }

    #[test]
    fn rejects_firstchip_database_when_des_output_has_no_utf16_bom() {
        let directory = tempfile::tempdir().unwrap();
        let config = directory.path().join("config");
        std::fs::create_dir_all(&config).unwrap();
        std::fs::write(config.join("Flash.bin"), [0u8; 16]).unwrap();
        assert!(analyze(directory.path(), Some("firstchip-ufd"), false).is_err());
    }

    #[test]
    fn decodes_chipsbank_cbmv1001_and_resolves_controller_catalogs() {
        let directory = tempfile::tempdir().unwrap();
        let flash_directory = directory.path().join("flash");
        let manifest_directory = directory.path().join("libin");
        let code_directory = directory.path().join("FirmWare/2199C/CodeFile");
        let scan_directory = directory.path().join("FirmWare/2199C/ScanFile");
        std::fs::create_dir_all(&flash_directory).unwrap();
        std::fs::create_dir_all(&manifest_directory).unwrap();
        std::fs::create_dir_all(&code_directory).unwrap();
        std::fs::create_dir_all(&scan_directory).unwrap();
        std::fs::write(code_directory.join("General_Test"), b"controller code").unwrap();
        std::fs::write(scan_directory.join("Nand_Scan_Test"), b"scan code").unwrap();

        let database = "[UNKNOWN_FLASH]\r\n\
SectionUniqueIdentity=1\r\n\
[2C64444BA900]\r\n\
SectionUniqueIdentity=2\r\n\
FLASHNAME_1CE=MT29F_TEST\r\n\
FLASHNAME_2CE=MT29F_TEST_2CE\r\n\
CELLNUM=2\r\n\
PAGEMASK_SP=5\r\n\
PLANE_OF_CHIP=2\r\n\
BANK_OF_CHIP=1\r\n\
BLOCK_OF_BANK=4096\r\n\
PAGE_OF_BLOCK=1024\r\n\
SECTOR_OF_PAGE=32\r\n\
SPARE_SIZE=2048\r\n\
RW_CYCLE=4\r\n\
SCAN_FILE=Nand_Scan_Test\r\n\
CODE_FILE=General_Test\r\n\
Remark=控制器数据库\r\n";
        std::fs::write(
            flash_directory.join("flash.cbm"),
            encode_chipsbank_fixture(database),
        )
        .unwrap();
        std::fs::write(
            manifest_directory.join("UmpTool.ini"),
            b"[SETTINGS]\r\n\
[ICInfo]\r\n\
ActiveIC=2199C\r\n\
ICCount=1\r\n\
ICID_0=34\r\n\
ICName_0=2199C\r\n\
[2199C]\r\n\
PathCodeFile=/FirmWare/2199C/CodeFile\r\n\
PathScanFile=/FirmWare/2199C/ScanFile\r\n\
CBMFlash=/flash/flash.cbm\r\n",
        )
        .unwrap();

        let report = analyze(directory.path(), Some("chipsbank-ufd"), false).unwrap();
        assert_eq!(report.schema, TOOL_ANALYSIS_SCHEMA);
        assert_eq!(report.nand_identities, 1);
        let identity = &report.nand_identity_records[0];
        assert_eq!(identity.nand_id, "2c64444ba900");
        assert_eq!(identity.model, "MT29F_TEST");
        assert_eq!(identity.aliases, ["MT29F_TEST_2CE"]);
        assert!(identity.selection_unambiguous);
        assert_eq!(identity.artifact_references.len(), 2);
        assert!(identity
            .artifact_references
            .iter()
            .all(|artifact| artifact.resolution == "unique"));
        assert_eq!(report.firmware_index_records, 2);
        assert!(report
            .firmware_index_record_records
            .iter()
            .all(|record| record.selection_unambiguous && record.artifacts.len() == 1));
        let decoded = report
            .files
            .iter()
            .find_map(|file| file.decoded_content.as_ref())
            .unwrap();
        assert_eq!(decoded.scheme, "chipsbank-cbmv1001-repeating-xor");
        assert_eq!(decoded.text_encoding, "GBK");
        assert_eq!(decoded.trailing_cleartext_bytes, 8);
    }

    #[test]
    fn rejects_chipsbank_database_with_wrong_format_magic() {
        let path = Path::new("flash/flash.cbm");
        let mut fixture = encode_chipsbank_fixture("[UNKNOWN_FLASH]\r\nValue=1\r\n");
        *fixture.last_mut().unwrap() ^= 1;
        assert!(decode_chipsbank_cbm(&fixture, path).is_err());
    }

    #[test]
    fn extracts_innostor_geometry_and_resolves_complete_firmware_bundles() {
        let directory = tempfile::tempdir().unwrap();
        let runtime = directory.path().join("binary/is917/GENNL_M2P/USB");
        let index = directory.path().join("binary/is917/FWINDEX");
        std::fs::create_dir_all(&runtime).unwrap();
        std::fs::create_dir_all(&index).unwrap();
        std::fs::write(runtime.join("is917pc1_V106.1000_1.bin"), b"pc1").unwrap();
        std::fs::write(runtime.join("is917pc2_V106.1000_2.bin"), b"pc2").unwrap();
        std::fs::write(runtime.join("is917nftl_V106.1000_3.bin"), b"nftl").unwrap();
        std::fs::write(
            index.join("FWINDEX_V1.06.cfg"),
            b"[GENNL_M2P]\r\n\
USB=\\binary\\is917\\GENNL_M2P\\USB\\\r\n\
Version=1000.M2\r\n\
[MISSING]\r\n\
USB=\\binary\\is917\\MISSING\\USB\\\r\n\
Version=FFFF.M2\r\n",
        )
        .unwrap();
        std::fs::write(
            directory.path().join("917_FlashDatabase_test.ini"),
            b"[FlashDB Version]\r\nVersion=test\r\nPJ=7\r\n\
[Sample-NAND-2C24444BA4]\r\n\
Vendor=Micron\r\n\
FlashID=2C24444BA4\r\n\
Feature=sample\r\n\
MLC=1\r\n\
Planes=2\r\n\
PageSize=8192\r\n\
Blocks=4096\r\n\
Die=1\r\n\
Pagesperblock=256\r\n\
Sparesize=640\r\n\
ColumnAddrCycles=2\r\n\
RowAddrCycles=3\r\n",
        )
        .unwrap();

        let report = analyze(directory.path(), Some("innostor-ufd"), false).unwrap();
        assert_eq!(report.schema, TOOL_ANALYSIS_SCHEMA);
        assert_eq!(report.nand_identities, 1);
        let identity = &report.nand_identity_records[0];
        assert_eq!(identity.controller_id.as_deref(), Some("innostor-is917"));
        assert_eq!(identity.nand_id, "2c24444ba4");
        assert_eq!(identity.model, "Sample-NAND");
        assert!(identity.selection_unambiguous);

        assert_eq!(report.firmware_index_records, 2);
        let complete = report
            .firmware_index_record_records
            .iter()
            .find(|record| record.selector == "GENNL_M2P")
            .unwrap();
        assert!(complete.selection_unambiguous);
        assert_eq!(complete.artifacts.len(), 3);
        assert_eq!(
            complete
                .artifacts
                .iter()
                .map(|artifact| artifact.role)
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "controller-stage-one-code",
                "controller-stage-two-code",
                "flash-translation-layer-code",
            ])
        );
        let missing = report
            .firmware_index_record_records
            .iter()
            .find(|record| record.selector == "MISSING")
            .unwrap();
        assert!(!missing.selection_unambiguous);
        assert_eq!(missing.missing_required_roles.len(), 3);
    }

    #[test]
    fn extracts_alcor_fids_and_raw_module_parameters() {
        let directory = tempfile::tempdir().unwrap();
        let ctl = directory.path().join("UfdApi_Gen/CTL/10");
        let modules = ctl.join("BIN");
        std::fs::create_dir_all(&modules).unwrap();
        let mut decoded_module = vec![0u8; crate::alcor_au698x::SECTOR_BYTES];
        decoded_module[crate::alcor_au698x::SECTOR_BYTES - 2..].copy_from_slice(&[0x55, 0xaa]);
        let encoded_module = decoded_module
            .chunks_exact(crate::alcor_au698x::ASCII_HEX_RECORD_BYTES)
            .map(hex::encode_upper)
            .collect::<Vec<_>>()
            .join("\r\n");
        std::fs::write(modules.join("10_02_K9G.BIN"), encoded_module).unwrap();
        std::fs::write(
            directory.path().join("FlashList.ini"),
            b"[FLASHLIST]\r\n[0]\r\nFlashName=JS29F08G08AANC1\r\nFID=0x89,0xD3,0x90,0x2E,0x64,0x52\r\n[TH58NVG]\r\nDrivingLevel=0x00\r\n",
        )
        .unwrap();
        std::fs::write(
            ctl.join("FlashList.ini"),
            b"[MODULE_FETURE]\r\n10_02_K9G.BIN=1,2,1,2048,0,0,4,4\r\n10_MISSING.BIN=1,1,0,2048,0,1,6,3,2\r\n",
        )
        .unwrap();

        let report = analyze(directory.path(), Some("alcor-ufd"), false).unwrap();
        assert_eq!(report.nand_identities, 1);
        assert_eq!(report.nand_identity_records[0].nand_id, "89d3902e6452");
        assert_eq!(report.nand_identity_records[0].model, "JS29F08G08AANC1");
        assert_eq!(report.module_mappings, 2);
        assert_eq!(
            report.module_mapping_records[0].controller_id,
            "alcor-ctl-10"
        );
        assert_eq!(
            report.module_mapping_records[0].parameters,
            [1, 2, 1, 2048, 0, 0, 4, 4]
        );
        assert_eq!(
            report.module_mapping_records[0].artifact.resolution,
            "unique"
        );
        assert_eq!(
            report.module_mapping_records[1].artifact.resolution,
            "missing"
        );
        let decoded = report.files.iter().find_map(|file| {
            (file.path.file_name().and_then(|name| name.to_str()) == Some("10_02_K9G.BIN"))
                .then_some(file.decoded_content.as_ref())
                .flatten()
        });
        assert_eq!(
            decoded.unwrap().scheme,
            "alcor-fixed-16-byte-ascii-hex-records"
        );
        assert_eq!(
            decoded.unwrap().decoded_size_bytes,
            crate::alcor_au698x::SECTOR_BYTES
        );
    }

    #[test]
    fn rejects_non_six_byte_alcor_fids() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("FlashList.ini");
        std::fs::write(
            &path,
            b"[0]\r\nFlashName=broken\r\nFID=0x89,0xD3,0x90,0x2E\r\n",
        )
        .unwrap();
        assert!(analyze(&path, Some("alcor-ufd"), false).is_err());
    }

    #[test]
    fn extracts_authenticated_chipsbank_physical_erase_contract() {
        let bytes = [
            hex::decode(
                "8b4c241485c975028bce8b7424208b50048b00568b742420568b74242056518b4c2420518b4c2420518b4c2420518bc8ffd2",
            )
            .unwrap(),
            hex::decode(
                "6a00884424108b44242050526a006a006a108d54241852c644241ceac644242be2",
            )
            .unwrap(),
            hex::decode(
                "8b4424142bc3c1f8023d800000008bf07c05be800000008b4c24108b1183c208528d4c241ce82508faff8b4424108b080fb691a95c00008b45105250568d3cb50000000057538d4c242ce8700afaff85c074a403df3b5c241475a55f",
            )
            .unwrap(),
            hex::decode("8b5424208b4c24280fafd66a01528d44243850e802feffff85c0742a")
                .unwrap(),
            b"-----------Erase Block-----------".to_vec(),
            b"Erase Block fail!\0Erase Block success!\0".to_vec(),
        ]
        .concat();
        let sha256 = hex::encode(Sha256::digest(&bytes));
        let contract = chipsbank_apdevice_command_contract(
            Path::new("Dll/APDeviceMP.dll"),
            bytes.len() as u64,
            &sha256,
            "portable-executable",
            &bytes,
        )
        .unwrap();
        assert_eq!(contract.vendor_commands.len(), 1);
        let erase = &contract.vendor_commands[0];
        assert_eq!(erase.name, "erase-physical-block-batch");
        assert_eq!(erase.subcommand_hex, Some("e2"));
        assert_eq!(erase.data_direction, "to-device");
        assert_eq!(erase.classification, "destructive-physical-erase");
        assert!(contract
            .evidence
            .iter()
            .any(|item| item.role == "erase-batch-128-dword-bound"));
        assert!(contract
            .evidence
            .iter()
            .any(|item| item.role == "erase-physical-address-dispatch"));
        assert!(!contract.production_eligible);

        let constructor_only = [
            hex::decode(
                "8b4c241485c975028bce8b7424208b50048b00568b742420568b74242056518b4c2420518b4c2420518b4c2420518bc8ffd2",
            )
            .unwrap(),
            hex::decode(
                "6a00884424108b44242050526a006a006a108d54241852c644241ceac644242be2",
            )
            .unwrap(),
        ]
        .concat();
        assert!(chipsbank_apdevice_command_contract(
            Path::new("Dll/APDeviceMP.dll"),
            constructor_only.len() as u64,
            &hex::encode(Sha256::digest(&constructor_only)),
            "portable-executable",
            &constructor_only,
        )
        .is_none());
    }

    #[test]
    fn extracts_bounded_alcor_host_transport_contract() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("UfdComLib.dll");
        let bytes = [
            &[0x4d, 0x5a][..],
            &[0x66, 0xc7, 0x44, 0x24, 0x2c, 0x2c, 0x00][..],
            &[0xc6, 0x44, 0x24, 0x33, 0x10][..],
            &[0xc7, 0x44, 0x24, 0x44, 0x30, 0x00, 0x00, 0x00][..],
            &[0x6a, 0x3c, 0xc1, 0xe2, 0x09][..],
            &[0x6a, 0x00, 0x8b, 0x54, 0x24, 0x14, 0x83, 0xec, 0x10][..],
            &[0x6a, 0x01, 0x8b, 0x54, 0x24, 0x14, 0x83, 0xec, 0x10][..],
            &[0x6a, 0x10, 0x89, 0x08][..],
            &[0x6a, 0x08, 0x89, 0x11][..],
            &[
                0x6a, 0x50, 0x51, 0x8d, 0x54, 0x24, 0x3c, 0x6a, 0x50, 0x52, 0x68, 0x14, 0xd0, 0x04,
                0x00,
            ][..],
            &[0x68, 0xfa, 0x00, 0x00, 0x00, 0x50, 0x6a, 0x01, 0x51][..],
        ]
        .concat();
        std::fs::write(&path, bytes).unwrap();

        let report = analyze(&path, Some("alcor-ufd"), false).unwrap();
        assert_eq!(report.host_transport_contracts, 1);
        let contract = &report.host_transport_contract_records[0];
        assert_eq!(contract.transport, "windows-scsi-pass-through-direct");
        assert_eq!(contract.ioctl_codes_hex, ["0004d014"]);
        assert_eq!(contract.timeout_seconds, [60]);
        assert_eq!(contract.retry_attempts, 1);
        assert_eq!(contract.transfer_unit_bytes, 512);
        assert_eq!(contract.cdb_lengths, [8, 16]);
        assert_eq!(contract.read_only_commands[0].cdb_length, 16);
        assert_eq!(contract.read_only_commands[0].transfer_bytes, 512);
        assert_eq!(contract.evidence.len(), 11);
        assert!(!contract.production_eligible);
        assert!(report.files[0]
            .components
            .iter()
            .any(|component| component.role == "host-transport-library"));
    }

    #[test]
    fn extracts_bounded_smi_ufdif_transport_contract() {
        let directory = tempfile::tempdir().unwrap();
        let dlllib = directory.path().join("DLLLIB");
        std::fs::create_dir_all(&dlllib).unwrap();
        let path = dlllib.join("UFDIF.dll");
        let mut bytes = vec![0u8; 0x1455ac];
        bytes[0..2].copy_from_slice(b"MZ");
        let signatures = [
            &[
                0x66, 0xc7, 0x85, 0x78, 0xff, 0xff, 0xff, 0x2c, 0x00, 0xc6, 0x85, 0x7b, 0xff, 0xff,
                0xff, 0x00, 0xc6, 0x85, 0x7c, 0xff, 0xff, 0xff, 0x01, 0xc6, 0x85, 0x7d, 0xff, 0xff,
                0xff, 0x00, 0xc6, 0x85, 0x7e, 0xff, 0xff, 0xff, 0x10,
            ][..],
            &[0xc6, 0x45, 0x80, 0x01][..],
            &[0xc6, 0x45, 0x80, 0x00][..],
            &[0xa1, 0xa8, 0x55, 0x14, 0x10, 0x89, 0x45, 0x88][..],
            &[0xc7, 0x45, 0x90, 0x30, 0x00, 0x00, 0x00][..],
            &[0x68, 0x14, 0xd0, 0x04, 0x00][..],
            &[0x83, 0xbd, 0x68, 0xff, 0xff, 0xff, 0x08][..],
        ];
        let mut offset = 0x100usize;
        for signature in signatures {
            bytes[offset..offset + signature.len()].copy_from_slice(signature);
            offset += signature.len() + 1;
        }
        bytes[0x1455a8..0x1455ac].copy_from_slice(&300u32.to_le_bytes());
        std::fs::write(&path, bytes).unwrap();

        let report = analyze(&path, Some("silicon-motion-ufd"), false).unwrap();
        let contract = &report.host_transport_contract_records[0];
        assert_eq!(contract.ioctl_codes_hex, ["0004d014"]);
        assert_eq!(contract.timeout_seconds, [300]);
        assert_eq!(contract.retry_attempts, 8);
        assert_eq!(contract.cdb_lengths, [16]);
        assert!(contract.read_only_commands.is_empty());
        assert!(!contract.production_eligible);
    }

    #[test]
    fn extracts_bounded_smi_factory_inquiry_contract() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("sm32Xtest_V58-8.exe");
        let bytes = [
            &[0x4d, 0x5a][..],
            &[0x66, 0xc7, 0x85, 0xb0, 0xf7, 0xff, 0xff, 0x2c, 0x00][..],
            &[
                0xc6, 0x85, 0xb6, 0xf7, 0xff, 0xff, 0x06, 0xc6, 0x85, 0xb7, 0xf7, 0xff, 0xff, 0x00,
                0xc6, 0x85, 0xb8, 0xf7, 0xff, 0xff, 0x01,
            ][..],
            &[0xc7, 0x85, 0xbc, 0xf7, 0xff, 0xff, 0x24, 0x00, 0x00, 0x00][..],
            &[0xc7, 0x85, 0xc0, 0xf7, 0xff, 0xff, 0x05, 0x00, 0x00, 0x00][..],
            &[
                0xc7, 0x85, 0xc4, 0xf7, 0xff, 0xff, 0x50, 0x00, 0x00, 0x00, 0xc7, 0x85, 0xc8, 0xf7,
                0xff, 0xff, 0x30, 0x00, 0x00, 0x00,
            ][..],
            &[
                0xc6, 0x85, 0xcc, 0xf7, 0xff, 0xff, 0x12, 0xc6, 0x85, 0xd0, 0xf7, 0xff, 0xff, 0x24,
            ][..],
            &[0x68, 0x04, 0xd0, 0x04, 0x00][..],
        ]
        .concat();
        std::fs::write(&path, bytes).unwrap();

        let report = analyze(&path, Some("silicon-motion-ufd"), false).unwrap();
        let contract = &report.host_transport_contract_records[0];
        assert_eq!(contract.transport, "windows-scsi-pass-through-buffered");
        assert_eq!(contract.timeout_seconds, [5]);
        assert_eq!(contract.read_only_commands[0].cdb_hex, "120000002400");
        assert_eq!(contract.read_only_commands[0].transfer_bytes, 36);
    }

    #[test]
    fn extracts_bounded_phison_getinfo_nand_id_contract() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("GetInfo.exe");
        let bytes = [
            &[0x4d, 0x5a][..],
            &[0x83, 0x7d, 0x0c, 0x10, 0x76][..],
            &[
                0xb9, 0x2c, 0x00, 0x00, 0x00, 0x8b, 0x55, 0x08, 0x66, 0x89, 0x0a,
            ][..],
            &[0xc6, 0x42, 0x07, 0x18][..],
            &[0xc7, 0x42, 0x18, 0x30, 0x00, 0x00, 0x00][..],
            &[0xc6, 0x45, 0xa8, 0x01][..],
            &[0xc6, 0x45, 0xa8, 0x00][..],
            &[0xc6, 0x45, 0xa8, 0x02][..],
            &[
                0xc6, 0x45, 0xe4, 0x06, 0xc6, 0x45, 0xe5, 0x56, 0x6a, 0x0a, 0x68, 0x00, 0x02, 0x00,
                0x00, 0x6a, 0x01,
            ][..],
            &[0x68, 0x04, 0xd0, 0x04, 0x00][..],
            &[0x68, 0x14, 0xd0, 0x04, 0x00][..],
            &[
                0x68, 0x50, 0x80, 0x00, 0x00, 0x6a, 0x00, 0x68, 0x12, 0x34, 0x56, 0x78,
            ][..],
        ]
        .concat();
        std::fs::write(&path, bytes).unwrap();

        let report = analyze(&path, Some("phison-ufd"), false).unwrap();
        let contract = &report.host_transport_contract_records[0];
        assert_eq!(contract.ioctl_codes_hex, ["0004d004", "0004d014"]);
        assert_eq!(contract.sense_bytes, 0x18);
        assert_eq!(contract.outer_buffer_bytes, 0x8050);
        assert_eq!(contract.timeout_seconds, [10]);
        assert_eq!(contract.cdb_lengths, [12, 16]);
        assert_eq!(
            contract.read_only_commands[0].cdb_hex,
            "065600000000000000000000"
        );
        assert_eq!(contract.read_only_commands[0].transfer_bytes, 512);
        assert!(!contract.production_eligible);
        assert!(report.files[0]
            .components
            .iter()
            .any(|component| component.role == "read-only-identity-tool"));
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symbolic_links() {
        use std::os::unix::fs::symlink;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target.bin");
        let link = directory.path().join("link.bin");
        std::fs::write(&target, b"MZ").unwrap();
        symlink(&target, &link).unwrap();
        assert!(analyze(&link, None, false).is_err());
    }
}
