//! Clean-room host contract recovered from the Alcor AU698x factory library.
//!
//! The command constructors in this module are intentionally tuple-neutral.
//! They reproduce the byte layout used by the exact factory library, but do
//! not authorize a command for any device. A production profile still has to
//! bind the controller, firmware, NAND identity, module, parameter page and
//! response signatures, followed by independent HIL qualification.

use crate::errors::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const SECTOR_BYTES: usize = 512;
pub const PARAMETER_PAGE_BYTES: usize = SECTOR_BYTES;
pub const ASCII_HEX_RECORD_BYTES: usize = 16;
pub const ASCII_HEX_RECORD_CHARS: usize = ASCII_HEX_RECORD_BYTES * 2;
pub const MAX_MODULE_SECTORS: usize = u8::MAX as usize;
pub const RAW_READ_TRAILER_SECTORS: usize = 2;
pub const FLASH_DATABASE_HEADER_BYTES: usize = SECTOR_BYTES;
pub const FLASH_DATABASE_ENTRY_BYTES_V4: usize = 0x296;
pub const FLASH_DATABASE_MAGIC: &[u8; 16] = b"ALCORFLASHCFG_SZ";
pub const FLASH_DATABASE_KEY: &[u8; 16] = b"ALCORFLASHCFG_SZ";
pub const FLASH_DATABASE_MODULE_SLOT_BYTES: usize = 0x20;
pub const FLASH_DATABASE_CTL84_FIELDS: [usize; 3] = [0x56, 0x76, 0x96];
pub const FLASH_DATABASE_CTL86_FIELDS: [usize; 3] = [0xb6, 0xd6, 0xf6];
pub const FLASH_DATABASE_CTL90_FIELDS: [usize; 3] = [0x116, 0x136, 0x156];
pub const FLASH_DATABASE_CTL92_FIELDS: [usize; 3] = [0x176, 0x196, 0x1b6];
pub const FLASH_DATABASE_CTL96_FIELDS: [usize; 3] = [0x1d6, 0x1f6, 0x216];
pub const FLASH_DATABASE_CTL10_13_FIELDS: [usize; 3] = [0x236, 0x256, 0x276];
pub const LEGACY_FLASH_DATABASE_SELECTOR_VA: u32 = 0x0045_7e30;
pub const LEGACY_FLASH_DATABASE_SELECTOR_TABLE_VA: u32 = 0x0045_8404;
pub const LEGACY_FLASH_DATABASE_SELECTOR_SOURCE_SHA256: &str =
    "837e3c480daefc85a5bb79a55e91d4c6eb2e762391b47096d248a4dd3f5c53f1";
pub const FLASH_DATABASE_CONVERTER_VA: u32 = 0x1004_4438;
pub const FLASH_DATABASE_CONVERTER_SOURCE_SHA256: &str =
    "a295ca70372edbbc59f3d33a7ff91e32a177b0240889d5633f9f67397421a6b1";
pub const PARAMETER_BUILDER_VA: u32 = 0x1002_be12;
pub const MODULE_FEATURE_PARSER_VA: u32 = 0x1004_4a81;
pub const LEGACY_MODULE_FEATURE_PARSER_VA: u32 = 0x0045_84c0;
pub const NORMAL_GEOMETRY_BUILDER_VA: u32 = 0x1001_f0a6;
pub const PARAMETER_BUILDER_SOURCE_SHA256: &str =
    "a295ca70372edbbc59f3d33a7ff91e32a177b0240889d5633f9f67397421a6b1";
const MAX_ASCII_MODULE_BYTES: usize = 8 * 1024 * 1024;
const MAX_FLASH_DATABASE_BYTES: usize = 64 * 1024 * 1024;
const MAX_FLASH_DATABASE_ENTRIES: usize = 100_000;
const MAX_FLASH_DATABASE_ENTRY_BYTES: usize = 4096;
const MODULE_TRAILER: [u8; 2] = [0x55, 0xaa];
const PARAMETER_PAGE_TRAILER: [u8; 2] = *b"JN";

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlashDatabaseHeader {
    pub unknown_words: [u32; 5],
    pub version: u32,
    pub entry_bytes: usize,
    pub entry_count: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlashDatabaseSelectedFieldStatus {
    Empty,
    Ascii,
    NonAscii,
    Unterminated,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlashDatabaseSelectedField {
    pub slot_offset: usize,
    pub status: FlashDatabaseSelectedFieldStatus,
    pub value: Option<String>,
}

/// Exact three-field selection made by the legacy selector at 0x00457e30 and
/// corroborated by the newer AFL converter at 0x10044438.
///
/// The factory executable assigns the first field to the runtime module name.
/// The two remaining names are retained as opaque auxiliary fields until their
/// downstream consumers are independently recovered.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlashDatabaseControllerSelection {
    pub controller_id: String,
    pub controller_generation_hex: String,
    pub runtime: FlashDatabaseSelectedField,
    pub auxiliary_1: FlashDatabaseSelectedField,
    pub auxiliary_2: FlashDatabaseSelectedField,
}

/// Exact numeric input region consumed by the legacy selector at 0x00457e30
/// and the newer AFL converter at 0x10044438.
///
/// Field names preserve the decoded AFL record offsets and integer widths.
/// They intentionally do not assign NAND geometry meanings that are not
/// established by the recovered data flow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlashDatabaseOperationalInput {
    pub source_offset: usize,
    pub source_bytes_hex: String,
    pub record_36_le: u16,
    pub record_38: u8,
    pub record_39: u8,
    pub record_3a_le: u32,
    pub record_3e: u8,
    pub record_3f_le: u16,
    pub record_41: u8,
    pub record_42: u8,
    pub record_43_le: u16,
    pub record_45_le: u16,
    pub record_47_le: u16,
    pub record_49_le: u16,
    pub record_4b: u8,
    pub record_4c: u8,
    pub record_4d: u8,
    pub record_4e: u8,
    pub record_4f: u8,
    pub record_50: u8,
    pub record_51: u8,
    pub record_52_le: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum FlashDatabaseConverter {
    LegacyAlcorMp130205,
    UfdApiGen1310,
}

/// Exact scalar output of the legacy AlcorMP AFL conversion at 0x00457e30.
///
/// The three CString fields at object offsets 0x00, 0x04 and 0x40..0x48 are
/// represented separately by [`FlashDatabaseEntry`] and
/// [`FlashDatabaseControllerSelection`].
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LegacyFlashDatabaseOperationalFields {
    pub default_enable_25ns: bool,
    pub object_0e: u8,
    pub object_0f: u8,
    pub object_10: u32,
    pub object_14: u8,
    pub object_18: u32,
    pub object_1c: u8,
    pub object_1e: u16,
    pub object_20: u8,
    pub object_21: u8,
    pub object_22: u16,
    pub object_24: u16,
    pub object_26: u16,
    pub object_28: u16,
    pub object_2a: u16,
    pub object_2c: u8,
    pub object_2d: u8,
    pub object_2e: u16,
    pub object_30: u8,
    pub object_31: u8,
    pub object_32: u8,
    pub object_34: bool,
    pub object_35: bool,
    pub object_36: bool,
    pub object_37: bool,
    pub object_38: bool,
    pub object_3c: u32,
    pub object_4c: u32,
    pub object_50: u8,
    pub object_51: u8,
    pub object_52: u8,
    pub object_54: u32,
}

/// Exact scalar output of UfdApi_Gen.dll's AFL conversion at 0x10044438.
///
/// This layout inserts four bytes before the legacy object's 0x2e field and
/// computes object 0x50 from object 0x24 rather than the legacy object 0x26.
/// Keeping it separate prevents a package version from silently changing NAND
/// geometry and controller limits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UfdApiFlashDatabaseOperationalFields {
    pub default_enable_25ns: bool,
    pub object_0e: u8,
    pub object_0f: u8,
    pub object_10: u32,
    pub object_14: u8,
    pub object_18: u32,
    pub object_1c: u8,
    pub object_1e: u16,
    pub object_20: u8,
    pub object_21: u8,
    pub object_22: u16,
    pub object_24: u16,
    pub object_28: u16,
    pub object_2a: u16,
    pub object_2c: u8,
    pub object_2d: u8,
    pub object_30: u16,
    pub object_32: u16,
    pub object_34: u8,
    pub object_35: u8,
    pub object_36: u8,
    pub object_38: bool,
    pub object_39: bool,
    pub object_3a: bool,
    pub object_3b: bool,
    pub object_3c: bool,
    pub object_40: u32,
    pub object_50: u32,
    pub object_54: u8,
    pub object_55: u8,
    pub object_56: u8,
    pub object_58: u32,
    pub object_60: u8,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "converter", content = "fields", rename_all = "kebab-case")]
pub enum FlashDatabaseOperationalFields {
    LegacyAlcorMp130205(LegacyFlashDatabaseOperationalFields),
    UfdApiGen1310(UfdApiFlashDatabaseOperationalFields),
}

impl FlashDatabaseOperationalFields {
    pub fn converter(&self) -> FlashDatabaseConverter {
        match self {
            Self::LegacyAlcorMp130205(_) => FlashDatabaseConverter::LegacyAlcorMp130205,
            Self::UfdApiGen1310(_) => FlashDatabaseConverter::UfdApiGen1310,
        }
    }

    pub fn object_14(&self) -> u8 {
        match self {
            Self::LegacyAlcorMp130205(fields) => fields.object_14,
            Self::UfdApiGen1310(fields) => fields.object_14,
        }
    }

    pub fn controller_module_limit(&self) -> u32 {
        match self {
            Self::LegacyAlcorMp130205(fields) => fields.object_4c,
            Self::UfdApiGen1310(fields) => fields.object_50,
        }
    }

    pub fn set_default_enable_25ns(&mut self, enabled: bool, object_14: u8) {
        match self {
            Self::LegacyAlcorMp130205(fields) => {
                fields.default_enable_25ns = enabled;
                fields.object_14 = object_14;
            }
            Self::UfdApiGen1310(fields) => {
                fields.default_enable_25ns = enabled;
                fields.object_14 = object_14;
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlashDatabaseEntry {
    pub index: usize,
    pub vendor: String,
    pub model: String,
    pub nand_id_hex: String,
    pub operational_input: FlashDatabaseOperationalInput,
    pub controller_selections: Vec<FlashDatabaseControllerSelection>,
    pub operational_sha256: String,
    pub record_sha256: String,
    #[serde(skip)]
    pub decoded_record: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FlashDatabase {
    pub header: FlashDatabaseHeader,
    pub entries: Vec<FlashDatabaseEntry>,
    pub decoded_entries_sha256: String,
    pub unparsed_suffix_bytes: usize,
    pub unparsed_suffix_sha256: String,
}

/// Exact output fields written by UfdApi_Gen.dll at 0x1002be12.
///
/// Names tied to object offsets intentionally remain opaque until their
/// upstream database-to-object conversion has been recovered. This prevents
/// a guessed NAND-geometry meaning from becoming a destructive contract.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ParameterPageFields {
    pub control_00: u8,
    pub object_02: u8,
    pub object_a8: u8,
    pub object_aa: u16,
    pub object_ac: u16,
    pub object_ae: u8,
    pub helper_10: u8,
    pub helper_11: u8,
    pub operation_code_102: u8,
    pub operation_argument: u16,
    pub object_105: u8,
    pub helper_10f: u8,
    pub address_words: Vec<u16>,
    #[serde(default)]
    pub feature_120: bool,
    #[serde(default)]
    pub feature_121: bool,
    #[serde(default)]
    pub controller_e3_signature: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub global_140: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_192: Option<u16>,
    pub object_194: u8,
    pub helper_195: u8,
    #[serde(default)]
    pub feature_19f: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub object_1a7: Option<u8>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_1a8: Option<u8>,
    pub object_mask_1ed_1ef: u16,
    pub normalized_object_1ee: u8,
}

/// Exact output of the `[MODULE_FETURE]` parser at 0x10044a81.
///
/// The factory DLL scans nine signed decimal shorts into a zeroed buffer. Its
/// shipped database also contains eight-field rows, so the ninth field remains
/// zero in those rows. Names stay tied to object offsets until a separate data
/// flow proves a NAND-geometry meaning.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ModuleFeature {
    pub supplied_parameters: usize,
    pub object_3e1: u8,
    pub object_3e2: u8,
    pub object_3e4: u8,
    pub object_3e8: u16,
    pub object_3ea: u8,
    pub object_3eb: u8,
    pub object_3ec: u8,
    pub object_3ed: u8,
    pub object_3ee: u8,
}

/// Inputs consumed by the normal-mode branch at 0x1001f0a6.
///
/// These field names deliberately preserve the factory object's offsets. The
/// caller must obtain them from an exact authenticated NAND/controller tuple;
/// this contract does not infer them from a product name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalGeometryInputs {
    pub object_5670f: u8,
    pub object_9e: u8,
    pub object_9f: bool,
    pub object_3a4: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_1fb9d: Option<u16>,
    pub object_3a8: u8,
    pub argument_0c: u8,
    pub argument_10_ce_mask: u32,
}

/// Runtime-only inputs for the normal-mode geometry branch in the exact 2013
/// UfdApi_Gen implementation. Database-owned object 0x3a4 and 0x3a8 values
/// are intentionally excluded and must come from the resolved AFL converter.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UfdApiNormalGeometryRuntimeInputs {
    pub object_5670f: u8,
    pub object_9e: u8,
    pub object_9f: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub helper_1fb9d: Option<u16>,
    pub argument_0c: u8,
    pub argument_10_ce_mask: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct NormalGeometry {
    pub object_a8: u8,
    pub object_a9: u8,
    pub object_aa: u16,
    pub object_ac: u16,
    pub object_ae: u8,
    pub object_b0: u32,
}

/// Upstream values consumed by the parameter-page address-list loop at
/// 0x1002c249..0x1002c672.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UfdApiAddressInputs {
    pub argument_18: u8,
    pub object_38a: u8,
    pub object_3e19: u8,
    pub helper_b4: u8,
    pub helper_b8: u8,
    #[serde(default)]
    pub object_348_bit_08: bool,
    #[serde(default)]
    pub object_37d2_words: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UfdApiAddressLayout {
    pub object_02: u8,
    pub effective_object_ae: u8,
    pub group_span: u16,
    pub populated_words: usize,
    pub address_words: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UfdApiMaskFields {
    pub object_mask_1ed_1ef: u16,
    pub normalized_object_1ee: u8,
}

fn alcor_xor_swap(state: &mut [u8; 256], left: usize, right: usize) {
    let first = state[left] ^ state[right];
    state[left] = first;
    let second = first ^ state[right];
    state[right] = second;
    let third = second ^ state[left];
    state[left] = third;
}

fn alcor_stream_cipher(input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.is_empty() || key.len() > 256 {
        return Err(Error::Invalid(
            "Alcor flash database cipher key has an invalid size".into(),
        ));
    }
    let mut state = [0u8; 256];
    for (index, byte) in state.iter_mut().enumerate() {
        *byte = index as u8;
    }
    let mut accumulator = 0u8;
    for index in 0..state.len() {
        accumulator = accumulator
            .wrapping_add(state[index])
            .wrapping_add(key[index % key.len()]);
        alcor_xor_swap(&mut state, index, usize::from(accumulator));
    }

    let mut left = 0u8;
    let mut right = 0u8;
    let mut output = Vec::with_capacity(input.len());
    for input_byte in input {
        left = left.wrapping_add(1);
        right = right.wrapping_add(state[usize::from(left)]);
        alcor_xor_swap(&mut state, usize::from(left), usize::from(right));
        let stream_index = state[usize::from(left)].wrapping_add(state[usize::from(right)]);
        output.push(*input_byte ^ state[usize::from(stream_index)]);
    }
    Ok(output)
}

fn flash_database_u32(header: &[u8], offset: usize) -> Result<u32> {
    let bytes = header
        .get(offset..offset + 4)
        .ok_or_else(|| Error::Invalid("Alcor flash database header is truncated".into()))?;
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
        Error::Invalid("Alcor flash database header word has an invalid size".into())
    })?))
}

fn fixed_ascii_prefix(field: &[u8], label: &str, index: usize) -> Result<String> {
    let terminator = field.iter().position(|byte| *byte == 0).ok_or_else(|| {
        Error::Invalid(format!(
            "Alcor flash database entry {index} {label} is not NUL terminated"
        ))
    })?;
    if terminator == 0
        || !field
            .iter()
            .all(|byte| *byte == 0 || matches!(*byte, 0x20..=0x7e))
    {
        return Err(Error::Invalid(format!(
            "Alcor flash database entry {index} {label} is not a bounded ASCII field"
        )));
    }
    String::from_utf8(field[..terminator].to_vec()).map_err(|_| {
        Error::Invalid(format!(
            "Alcor flash database entry {index} {label} is not ASCII"
        ))
    })
}

fn selected_ascii_field(
    record: &[u8],
    offset: usize,
    index: usize,
) -> Result<FlashDatabaseSelectedField> {
    let slot = record
        .get(offset..offset + FLASH_DATABASE_MODULE_SLOT_BYTES)
        .ok_or_else(|| {
            Error::Invalid(format!(
                "Alcor flash database entry {index} selector field at {offset:#x} is truncated"
            ))
        })?;
    let Some(terminator) = slot.iter().position(|byte| *byte == 0) else {
        return Ok(FlashDatabaseSelectedField {
            slot_offset: offset,
            status: FlashDatabaseSelectedFieldStatus::Unterminated,
            value: None,
        });
    };
    let prefix = &slot[..terminator];
    if !prefix.iter().all(|byte| matches!(*byte, 0x20..=0x7e)) {
        return Ok(FlashDatabaseSelectedField {
            slot_offset: offset,
            status: FlashDatabaseSelectedFieldStatus::NonAscii,
            value: None,
        });
    }
    let value = std::str::from_utf8(prefix)
        .map_err(|_| {
            Error::Invalid(format!(
                "Alcor flash database entry {index} selector field at {offset:#x} is not ASCII"
            ))
        })?
        .trim()
        .to_string();
    let status = if value.is_empty() {
        FlashDatabaseSelectedFieldStatus::Empty
    } else {
        FlashDatabaseSelectedFieldStatus::Ascii
    };
    Ok(FlashDatabaseSelectedField {
        slot_offset: offset,
        status,
        value: (!value.is_empty()).then_some(value),
    })
}

fn controller_selection(
    record: &[u8],
    index: usize,
    generation: u8,
    offsets: [usize; 3],
) -> Result<FlashDatabaseControllerSelection> {
    let generation_hex = format!("{generation:02x}");
    Ok(FlashDatabaseControllerSelection {
        controller_id: format!("alcor-ctl-{generation_hex}"),
        controller_generation_hex: generation_hex,
        runtime: selected_ascii_field(record, offsets[0], index)?,
        auxiliary_1: selected_ascii_field(record, offsets[1], index)?,
        auxiliary_2: selected_ascii_field(record, offsets[2], index)?,
    })
}

fn is_runtime_module_name(value: &str) -> bool {
    value.len() >= 5
        && value.to_ascii_lowercase().ends_with(".bin")
        && !matches!(value, "." | "..")
        && value
            .as_bytes()
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'_' | b'-' | b'.' | b' '))
}

impl FlashDatabaseControllerSelection {
    /// Return the selected runtime artifact only when it is a bounded filename.
    pub fn runtime_module(&self) -> Option<&str> {
        self.runtime
            .value
            .as_deref()
            .filter(|value| is_runtime_module_name(value))
    }
}

fn record_le_u16(record: &[u8], offset: usize, index: usize) -> Result<u16> {
    let bytes = record.get(offset..offset + 2).ok_or_else(|| {
        Error::Invalid(format!(
            "Alcor flash database entry {index} word at {offset:#x} is truncated"
        ))
    })?;
    Ok(u16::from_le_bytes(bytes.try_into().map_err(|_| {
        Error::Invalid(format!(
            "Alcor flash database entry {index} word at {offset:#x} has an invalid size"
        ))
    })?))
}

fn record_le_u32(record: &[u8], offset: usize, index: usize) -> Result<u32> {
    let bytes = record.get(offset..offset + 4).ok_or_else(|| {
        Error::Invalid(format!(
            "Alcor flash database entry {index} dword at {offset:#x} is truncated"
        ))
    })?;
    Ok(u32::from_le_bytes(bytes.try_into().map_err(|_| {
        Error::Invalid(format!(
            "Alcor flash database entry {index} dword at {offset:#x} has an invalid size"
        ))
    })?))
}

fn parse_flash_database_operational_input(
    record: &[u8],
    index: usize,
) -> Result<FlashDatabaseOperationalInput> {
    let source = record.get(0x36..0x56).ok_or_else(|| {
        Error::Invalid(format!(
            "Alcor flash database entry {index} operational input is truncated"
        ))
    })?;
    Ok(FlashDatabaseOperationalInput {
        source_offset: 0x36,
        source_bytes_hex: hex::encode(source),
        record_36_le: record_le_u16(record, 0x36, index)?,
        record_38: record[0x38],
        record_39: record[0x39],
        record_3a_le: record_le_u32(record, 0x3a, index)?,
        record_3e: record[0x3e],
        record_3f_le: record_le_u16(record, 0x3f, index)?,
        record_41: record[0x41],
        record_42: record[0x42],
        record_43_le: record_le_u16(record, 0x43, index)?,
        record_45_le: record_le_u16(record, 0x45, index)?,
        record_47_le: record_le_u16(record, 0x47, index)?,
        record_49_le: record_le_u16(record, 0x49, index)?,
        record_4b: record[0x4b],
        record_4c: record[0x4c],
        record_4d: record[0x4d],
        record_4e: record[0x4e],
        record_4f: record[0x4f],
        record_50: record[0x50],
        record_51: record[0x51],
        record_52_le: record_le_u32(record, 0x52, index)?,
    })
}

/// Reproduce every scalar assignment and derived branch in the exact
/// version-4 AFL entry conversion recovered at 0x00457e30 and 0x10044438.
///
/// `default_enable_25ns` is the value read from
/// `DefaultEnable25NS` in the package's recognized main settings section when
/// record byte 0x39 is at most 0x19. It is explicit because the encrypted
/// database alone cannot resolve that branch.
pub fn derive_flash_database_operational_fields(
    entry: &FlashDatabaseEntry,
    default_enable_25ns: bool,
    converter: FlashDatabaseConverter,
) -> Result<FlashDatabaseOperationalFields> {
    let input = &entry.operational_input;
    let [object_0e, object_0f] = input.record_36_le.to_be_bytes();
    let object_14 = match input.record_39 {
        0x00..=0x19 => u8::from(!default_enable_25ns),
        0x1a..=0x21 => 1,
        0x22..=0x29 => 7,
        0x2a..=0x32 => 2,
        0x33..=0x42 => 3,
        _ => 4,
    };
    let object_22 = input.record_43_le;
    let mut object_24 = input.record_45_le;
    if object_24 == 0x2000 && object_22 == 0x1000 && input.record_42 == 1 {
        object_24 = 0x1000;
    }
    if object_24 == 0x1000 && object_22 == 0x0800 && input.record_42 == 1 {
        object_24 = 0x0800;
    }
    let legacy_object_26 = if object_22.is_multiple_of(0x0400) {
        object_22
    } else {
        object_24
    };
    let legacy_object_4c = u32::from(input.record_42)
        .checked_mul(u32::from(legacy_object_26))
        .ok_or_else(|| Error::Invalid("Alcor legacy flash object 0x4c overflows".into()))?;
    let ufdapi_object_50 = u32::from(input.record_42)
        .checked_mul(u32::from(object_24))
        .ok_or_else(|| Error::Invalid("Alcor UfdApi flash object 0x50 overflows".into()))?;

    if input.record_4d > 3 {
        return Err(Error::Invalid(format!(
            "Alcor flash database entry {} record byte 0x4d value {} exceeds the recovered object-0x51 switch",
            entry.index, input.record_4d
        )));
    }
    let derived_object_51_55 = match input.record_4d {
        0 => 1,
        1 => 2,
        2 => input.record_42.wrapping_mul(2),
        3 => 4,
        _ => unreachable!(),
    };
    let (derived_object_52_56, derived_object_54_58) = match input.record_51 {
        1 => (1, 0x0000_0003),
        2 => (2, 0x0000_000c),
        3 | 5 => (3, 0x0000_0030),
        4 => (4, 0x0000_00c0),
        6 => (5, 0x0000_000f),
        7 => (5, u32::MAX),
        8 => (5, 0x0000_0700),
        _ => (0, 0x0000_00ff),
    };
    let nand_id = hex::decode(&entry.nand_id_hex).map_err(|_| {
        Error::Invalid(format!(
            "Alcor flash database entry {} has an invalid stored NAND id",
            entry.index
        ))
    })?;
    if nand_id.len() != 6 {
        return Err(Error::Invalid(format!(
            "Alcor flash database entry {} stored NAND id is not six bytes",
            entry.index
        )));
    }
    let mut feature_flags = 0u8;
    if entry.vendor == "SanDisk" && nand_id[2] & 0x03 != 0 {
        feature_flags |= 0x01;
    }
    if object_24 == 0x2000 && object_22 == 0x1000 && input.record_42 > 1 {
        feature_flags |= 0x02;
    }
    if object_24 == 0x1000 && object_22 == 0x0800 && input.record_42 > 1 {
        feature_flags |= 0x04;
    }

    let common = || {
        (
            default_enable_25ns,
            object_0e,
            object_0f,
            u32::from(input.record_38),
            object_14,
            input.record_3a_le,
            input.record_3e,
            input.record_3f_le,
            input.record_41,
            input.record_42,
            object_22,
            object_24,
            input.record_47_le,
            input.record_49_le,
            input.record_4b,
            input.record_4c,
        )
    };
    Ok(match converter {
        FlashDatabaseConverter::LegacyAlcorMp130205 => {
            let (
                default_enable_25ns,
                object_0e,
                object_0f,
                object_10,
                object_14,
                object_18,
                object_1c,
                object_1e,
                object_20,
                object_21,
                object_22,
                object_24,
                object_28,
                object_2a,
                object_2c,
                object_2d,
            ) = common();
            FlashDatabaseOperationalFields::LegacyAlcorMp130205(
                LegacyFlashDatabaseOperationalFields {
                    default_enable_25ns,
                    object_0e,
                    object_0f,
                    object_10,
                    object_14,
                    object_18,
                    object_1c,
                    object_1e,
                    object_20,
                    object_21,
                    object_22,
                    object_24,
                    object_26: legacy_object_26,
                    object_28,
                    object_2a,
                    object_2c,
                    object_2d,
                    object_2e: 0x0800,
                    object_30: input.record_4d,
                    object_31: input.record_4e,
                    object_32: input.record_51,
                    object_34: input.record_4f & 0x01 != 0,
                    object_35: input.record_4f & 0x02 != 0,
                    object_36: input.record_4f & 0x04 != 0,
                    object_37: input.record_4f & 0x08 != 0,
                    object_38: entry.model.contains("E2NAND"),
                    object_3c: input.record_52_le,
                    object_4c: legacy_object_4c,
                    object_50: feature_flags,
                    object_51: derived_object_51_55,
                    object_52: derived_object_52_56,
                    object_54: derived_object_54_58,
                },
            )
        }
        FlashDatabaseConverter::UfdApiGen1310 => {
            let (
                default_enable_25ns,
                object_0e,
                object_0f,
                object_10,
                object_14,
                object_18,
                object_1c,
                object_1e,
                object_20,
                object_21,
                object_22,
                object_24,
                object_28,
                object_2a,
                object_2c,
                object_2d,
            ) = common();
            FlashDatabaseOperationalFields::UfdApiGen1310(UfdApiFlashDatabaseOperationalFields {
                default_enable_25ns,
                object_0e,
                object_0f,
                object_10,
                object_14,
                object_18,
                object_1c,
                object_1e,
                object_20,
                object_21,
                object_22,
                object_24,
                object_28,
                object_2a,
                object_2c,
                object_2d,
                object_30: object_24,
                object_32: 0x0800,
                object_34: input.record_4d,
                object_35: input.record_4e,
                object_36: input.record_51,
                object_38: input.record_4f & 0x01 != 0,
                object_39: input.record_4f & 0x02 != 0,
                object_3a: input.record_4f & 0x04 != 0,
                object_3b: input.record_4f & 0x08 != 0,
                object_3c: entry.model.contains("E2NAND"),
                object_40: input.record_52_le,
                object_50: ufdapi_object_50,
                object_54: feature_flags,
                object_55: derived_object_51_55,
                object_56: derived_object_52_56,
                object_58: derived_object_54_58,
                object_60: if input.record_51 == 0xa2 { 2 } else { 1 },
            })
        }
    })
}

fn parse_flash_database_entry(index: usize, record: &[u8]) -> Result<FlashDatabaseEntry> {
    if record.len() < 66 {
        return Err(Error::Invalid(format!(
            "Alcor flash database entry {index} is shorter than its fixed identity fields"
        )));
    }
    let vendor = fixed_ascii_prefix(&record[..16], "vendor", index)?;
    let model = fixed_ascii_prefix(&record[16..48], "model", index)?;
    let nand_id = &record[48..54];
    if nand_id.iter().all(|byte| *byte == 0) || nand_id.iter().all(|byte| *byte == 0xff) {
        return Err(Error::Invalid(format!(
            "Alcor flash database entry {index} has an empty NAND id"
        )));
    }

    let controller_selections = [
        (0x10, FLASH_DATABASE_CTL10_13_FIELDS),
        (0x13, FLASH_DATABASE_CTL10_13_FIELDS),
        (0x84, FLASH_DATABASE_CTL84_FIELDS),
        (0x86, FLASH_DATABASE_CTL86_FIELDS),
        (0x90, FLASH_DATABASE_CTL90_FIELDS),
        (0x92, FLASH_DATABASE_CTL92_FIELDS),
        (0x96, FLASH_DATABASE_CTL96_FIELDS),
    ]
    .into_iter()
    .map(|(generation, offsets)| controller_selection(record, index, generation, offsets))
    .collect::<Result<Vec<_>>>()?;

    Ok(FlashDatabaseEntry {
        index,
        vendor,
        model,
        nand_id_hex: hex::encode(nand_id),
        operational_input: parse_flash_database_operational_input(record, index)?,
        controller_selections,
        operational_sha256: hex::encode(Sha256::digest(&record[54..])),
        record_sha256: hex::encode(Sha256::digest(record)),
        decoded_record: record.to_vec(),
    })
}

/// Decode the exact encrypted FlashList.afl representation used by the
/// factory UfdCom library. Unknown entry bytes are authenticated but are not
/// assigned guessed NAND geometry semantics.
pub fn decode_flash_database(source: &[u8]) -> Result<FlashDatabase> {
    if source.len() < FLASH_DATABASE_HEADER_BYTES || source.len() > MAX_FLASH_DATABASE_BYTES {
        return Err(Error::Invalid(format!(
            "Alcor flash database must occupy {FLASH_DATABASE_HEADER_BYTES}..={MAX_FLASH_DATABASE_BYTES} bytes"
        )));
    }
    let derived = alcor_stream_cipher(&source[..256], FLASH_DATABASE_KEY)?;
    let derived_key: [u8; 256] = derived.try_into().map_err(|_| {
        Error::Invalid("Alcor flash database derived key has an invalid size".into())
    })?;
    let decoded_header =
        alcor_stream_cipher(&source[256..FLASH_DATABASE_HEADER_BYTES], &derived_key)?;
    if decoded_header.get(..FLASH_DATABASE_MAGIC.len()) != Some(FLASH_DATABASE_MAGIC.as_slice()) {
        return Err(Error::Invalid(
            "Alcor flash database header magic does not match ALCORFLASHCFG_SZ".into(),
        ));
    }
    let unknown_words = [
        flash_database_u32(&decoded_header, 16)?,
        flash_database_u32(&decoded_header, 20)?,
        flash_database_u32(&decoded_header, 24)?,
        flash_database_u32(&decoded_header, 28)?,
        flash_database_u32(&decoded_header, 32)?,
    ];
    let version = flash_database_u32(&decoded_header, 36)?;
    let entry_bytes = usize::try_from(flash_database_u32(&decoded_header, 40)?)
        .map_err(|_| Error::Invalid("Alcor flash database entry size overflow".into()))?;
    let entry_count = usize::try_from(flash_database_u32(&decoded_header, 44)?)
        .map_err(|_| Error::Invalid("Alcor flash database entry count overflow".into()))?;
    if version != 4 {
        return Err(Error::Invalid(format!(
            "Alcor flash database version {version} is not the recovered version 4 layout"
        )));
    }
    if entry_bytes != FLASH_DATABASE_ENTRY_BYTES_V4 || entry_bytes > MAX_FLASH_DATABASE_ENTRY_BYTES
    {
        return Err(Error::Invalid(format!(
            "Alcor flash database version 4 entry size {entry_bytes} != {FLASH_DATABASE_ENTRY_BYTES_V4}"
        )));
    }
    if entry_count == 0 || entry_count > MAX_FLASH_DATABASE_ENTRIES {
        return Err(Error::Invalid(format!(
            "Alcor flash database entry count {entry_count} is outside 1..={MAX_FLASH_DATABASE_ENTRIES}"
        )));
    }
    let records_bytes = entry_bytes
        .checked_mul(entry_count)
        .ok_or_else(|| Error::Invalid("Alcor flash database record size overflow".into()))?;
    let records_end = FLASH_DATABASE_HEADER_BYTES
        .checked_add(records_bytes)
        .ok_or_else(|| Error::Invalid("Alcor flash database record end overflow".into()))?;
    if records_end > source.len() {
        return Err(Error::Invalid(format!(
            "Alcor flash database declares {records_bytes} record bytes but the input is truncated"
        )));
    }

    let mut entries = Vec::with_capacity(entry_count);
    let mut decoded_entries_hash = Sha256::new();
    for index in 0..entry_count {
        let start = FLASH_DATABASE_HEADER_BYTES + index * entry_bytes;
        let end = start + entry_bytes;
        let mut record_key = derived_key;
        record_key[0] = index as u8;
        record_key[255] = !(index as u8);
        let record = alcor_stream_cipher(&source[start..end], &record_key)?;
        decoded_entries_hash.update(&record);
        entries.push(parse_flash_database_entry(index, &record)?);
    }
    let suffix = &source[records_end..];
    Ok(FlashDatabase {
        header: FlashDatabaseHeader {
            unknown_words,
            version,
            entry_bytes,
            entry_count,
        },
        entries,
        decoded_entries_sha256: hex::encode(decoded_entries_hash.finalize()),
        unparsed_suffix_bytes: suffix.len(),
        unparsed_suffix_sha256: hex::encode(Sha256::digest(suffix)),
    })
}

fn put_be_u16(output: &mut [u8], offset: usize, value: u16) -> Result<()> {
    output
        .get_mut(offset..offset + 2)
        .ok_or_else(|| Error::Invalid("Alcor parameter page field is out of range".into()))?
        .copy_from_slice(&value.to_be_bytes());
    Ok(())
}

fn module_feature_u8(parameters: &[u64], index: usize) -> Result<u8> {
    u8::try_from(parameters[index]).map_err(|_| {
        Error::Invalid(format!(
            "Alcor module feature parameter {} exceeds its recovered byte field",
            index + 1
        ))
    })
}

/// Parse one exact five-, six-, eight- or nine-field `[MODULE_FETURE]` value.
///
/// Both recovered factory parsers zero nine shorts before using a nine-item
/// `%hd` format, so omitted trailing fields remain zero. Genuine controller
/// maps use five fields for CTL 92, six for CTL 90/96, eight for CTL 13 and
/// eight or nine for CTL 10. Negative values are rejected because the
/// authenticated packages contain only non-negative decimal inputs and
/// wrapping a negative geometry value would be unsafe.
pub fn parse_module_feature_parameters(parameters: &[u64]) -> Result<ModuleFeature> {
    if !matches!(parameters.len(), 5 | 6 | 8 | 9) {
        return Err(Error::Invalid(
            "Alcor module feature requires exactly five, six, eight or nine parameters".into(),
        ));
    }
    if parameters.iter().any(|value| *value > i16::MAX as u64) {
        return Err(Error::Invalid(
            "Alcor module feature parameter exceeds the recovered signed-short parser".into(),
        ));
    }

    let object_3e1 = module_feature_u8(parameters, 0)?;
    let object_3e2 = module_feature_u8(parameters, 1)?;
    let object_3e4 = module_feature_u8(parameters, 2)?;
    let object_3e8 = u16::try_from(parameters[3]).map_err(|_| {
        Error::Invalid("Alcor module feature parameter 4 exceeds its recovered word field".into())
    })?;
    let object_3ea = module_feature_u8(parameters, 4)?;
    let object_3eb = parameters
        .get(5)
        .map(|_| module_feature_u8(parameters, 5))
        .transpose()?
        .unwrap_or(0);
    let mut object_3ec = parameters
        .get(6)
        .map(|_| module_feature_u8(parameters, 6))
        .transpose()?
        .unwrap_or(0);
    let mut object_3ed = parameters
        .get(7)
        .map(|_| module_feature_u8(parameters, 7))
        .transpose()?
        .unwrap_or(0);
    let object_3ee = if parameters.len() == 9 {
        module_feature_u8(parameters, 8)?
    } else {
        0
    };
    if object_3ec == 0 {
        object_3ec = 4;
    }
    if object_3ed == 0 {
        object_3ed = 2;
    }
    if object_3e1 == 0 || object_3e2 == 0 || object_3e8 == 0 {
        return Err(Error::Invalid(
            "Alcor module feature violates the factory non-zero geometry fields".into(),
        ));
    }

    Ok(ModuleFeature {
        supplied_parameters: parameters.len(),
        object_3e1,
        object_3e2,
        object_3e4,
        object_3e8,
        object_3ea,
        object_3eb,
        object_3ec,
        object_3ed,
        object_3ee,
    })
}

/// Validate the parameter count shipped for one recovered controller map.
pub fn validate_module_feature_parameter_count(
    controller_generation: u8,
    parameter_count: usize,
) -> Result<()> {
    let valid = match controller_generation {
        0x10 => matches!(parameter_count, 8 | 9),
        0x13 => parameter_count == 8,
        0x90 | 0x96 => parameter_count == 6,
        0x92 => parameter_count == 5,
        _ => false,
    };
    if !valid {
        return Err(Error::Invalid(format!(
            "Alcor CTL {controller_generation:02x} module feature count {parameter_count} is not present in the authenticated legacy maps"
        )));
    }
    Ok(())
}

/// Apply the controller-dependent parameter-4 bound in the same parser.
///
/// CTL 0x10 and 0x13 retain the database value. Other generations cap it at
/// `object_3cc / object_3e2`, which requires the exact upstream object value.
pub fn apply_module_feature_controller_limit(
    feature: &ModuleFeature,
    controller_generation: u8,
    object_3cc: Option<u32>,
) -> Result<ModuleFeature> {
    if matches!(controller_generation, 0x10 | 0x13) {
        if object_3cc.is_some() {
            return Err(Error::Invalid(
                "Alcor CTL 10/13 module features must not supply object_3cc".into(),
            ));
        }
        return Ok(feature.clone());
    }
    let object_3cc = object_3cc.filter(|value| *value != 0).ok_or_else(|| {
        Error::Invalid("Alcor non-CTL10/13 module feature requires a non-zero object_3cc".into())
    })?;
    let bounded = object_3cc / u32::from(feature.object_3e2);
    let bounded = bounded.min(u32::from(feature.object_3e8));
    if bounded == 0 || bounded > u32::from(u16::MAX) {
        return Err(Error::Invalid(
            "Alcor controller-dependent module feature bound is outside its word field".into(),
        ));
    }
    let mut adjusted = feature.clone();
    adjusted.object_3e8 = bounded as u16;
    Ok(adjusted)
}

/// Reproduce the normal-mode geometry derivation at 0x1001f0a6.
pub fn derive_normal_geometry(
    feature: &ModuleFeature,
    inputs: &NormalGeometryInputs,
) -> Result<NormalGeometry> {
    if inputs.object_9e == 0 || inputs.object_3a8 == 0 || inputs.object_3a8 > 32 {
        return Err(Error::Invalid(
            "Alcor normal geometry inputs violate the recovered divisor/CE bounds".into(),
        ));
    }
    let object_a8 = (inputs.object_5670f / inputs.object_9e).max(1);
    let object_a9 = inputs.object_5670f.max(1);
    let selected_3a4 = if inputs.argument_0c & 0x04 != 0 || inputs.argument_0c == 0x02 {
        inputs
            .helper_1fb9d
            .filter(|value| *value != 0)
            .ok_or_else(|| {
                Error::Invalid(
                    "Alcor normal geometry flags require the non-zero 0x1001fb9d helper value"
                        .into(),
                )
            })?
    } else {
        if inputs.helper_1fb9d.is_some() {
            return Err(Error::Invalid(
                "Alcor normal geometry supplied an unused 0x1001fb9d helper value".into(),
            ));
        }
        inputs.object_3a4
    };
    if selected_3a4 == 0 {
        return Err(Error::Invalid(
            "Alcor normal geometry selected a zero object_3a4 value".into(),
        ));
    }
    let object_ac = u32::from(selected_3a4)
        .checked_mul(u32::from(feature.object_3e2))
        .and_then(|value| value.checked_mul(u32::from(feature.object_3e1)))
        .filter(|value| *value != 0 && *value <= u32::from(u16::MAX))
        .ok_or_else(|| {
            Error::Invalid("Alcor normal geometry object_ac overflows its word field".into())
        })? as u16;

    let base_ce_count = if inputs.argument_0c & 0x08 != 0 {
        (0..inputs.object_3a8)
            .filter(|index| inputs.argument_10_ce_mask & (1u32 << index) != 0)
            .count() as u16
    } else {
        let multiplier = if inputs.object_9f { 2u16 } else { 1u16 };
        u16::from(inputs.object_3a8) * multiplier
    };
    let object_ae = u8::try_from(base_ce_count)
        .ok()
        .filter(|value| *value != 0)
        .ok_or_else(|| {
            Error::Invalid("Alcor normal geometry object_ae is zero or overflows".into())
        })?;
    let object_b0 = u32::from(object_a9)
        .checked_mul(u32::from(feature.object_3e8))
        .ok_or_else(|| Error::Invalid("Alcor normal geometry object_b0 overflows".into()))?;

    Ok(NormalGeometry {
        object_a8,
        object_a9,
        object_aa: feature.object_3e8,
        object_ac,
        object_ae,
        object_b0,
    })
}

/// Combine an exact UfdApi AFL conversion with runtime observations and
/// reproduce the normal-mode geometry derivation at 0x1001f0a6.
pub fn derive_ufdapi_normal_geometry(
    feature: &ModuleFeature,
    operational: &FlashDatabaseOperationalFields,
    runtime: &UfdApiNormalGeometryRuntimeInputs,
) -> Result<NormalGeometry> {
    let FlashDatabaseOperationalFields::UfdApiGen1310(database) = operational else {
        return Err(Error::Invalid(
            "Alcor UfdApi normal geometry requires the exact UfdApi_Gen 13.10 AFL layout".into(),
        ));
    };
    derive_normal_geometry(
        feature,
        &NormalGeometryInputs {
            object_5670f: runtime.object_5670f,
            object_9e: runtime.object_9e,
            object_9f: runtime.object_9f,
            object_3a4: database.object_28,
            helper_1fb9d: runtime.helper_1fb9d,
            object_3a8: database.object_2c,
            argument_0c: runtime.argument_0c,
            argument_10_ce_mask: runtime.argument_10_ce_mask,
        },
    )
}

/// Reproduce the bounded address-word generator used by the exact 2013
/// parameter-page builder.
pub fn derive_ufdapi_address_layout(
    geometry: &NormalGeometry,
    inputs: &UfdApiAddressInputs,
) -> Result<UfdApiAddressLayout> {
    if geometry.object_aa == 0 || geometry.object_ae == 0 || geometry.object_a9 == 0 {
        return Err(Error::Invalid(
            "Alcor UfdApi address layout requires non-zero geometry".into(),
        ));
    }
    let object_02 = if inputs.argument_18 & 0x80 != 0 {
        geometry.object_a9
    } else {
        0x10
    };
    if object_02 == 0 || object_02 > 0x40 {
        return Err(Error::Invalid(
            "Alcor UfdApi address layout object_02 exceeds the recovered bound".into(),
        ));
    }
    let address_stride = 0x1000u16 / geometry.object_aa;
    if address_stride == 0 {
        return Err(Error::Invalid(
            "Alcor UfdApi address layout has a zero address stride".into(),
        ));
    }
    let populated_words = usize::from(object_02)
        .checked_add(usize::from(address_stride) - 1)
        .ok_or_else(|| Error::Invalid("Alcor UfdApi address count overflow".into()))?
        / usize::from(address_stride);
    let output_words = if inputs.object_348_bit_08 { 8 } else { 16 };
    if populated_words > output_words {
        return Err(Error::Invalid(format!(
            "Alcor UfdApi address layout needs {populated_words} words but the recovered branch emits {output_words}"
        )));
    }

    let effective_object_ae = if inputs.object_38a == 4 {
        (geometry.object_ae / 2).max(1)
    } else {
        geometry.object_ae
    };
    let group_span = if matches!(inputs.object_3e19, 1 | 2) {
        u16::from(geometry.object_ae)
            .checked_mul(u16::from(inputs.helper_b4))
            .and_then(|value| value.checked_mul(u16::from(inputs.helper_b8)))
            .filter(|value| *value != 0)
            .ok_or_else(|| {
                Error::Invalid("Alcor UfdApi address group span is zero or overflows".into())
            })?
    } else {
        u16::from(geometry.object_ae)
    };
    if group_span < u16::from(effective_object_ae) {
        return Err(Error::Invalid(
            "Alcor UfdApi address group span is smaller than the effective CE count".into(),
        ));
    }

    let mut address_words = vec![0u16; output_words];
    let mut current = if geometry.object_ae == 1 {
        2
    } else {
        group_span
    };
    if inputs.object_3e19 == 1 {
        let mut outer = 0usize;
        while outer < populated_words {
            let table_index = usize::from(current / group_span);
            let base = *inputs.object_37d2_words.get(table_index).ok_or_else(|| {
                Error::Invalid(format!(
                    "Alcor UfdApi address table lacks recovered index {table_index}"
                ))
            })?;
            let chunk = usize::from(effective_object_ae).min(populated_words - outer);
            for inner in 0..chunk {
                address_words[outer + inner] = base
                    .checked_add(u16::try_from(inner).map_err(|_| {
                        Error::Invalid("Alcor UfdApi address inner index overflows".into())
                    })?)
                    .ok_or_else(|| Error::Invalid("Alcor UfdApi address word overflows".into()))?;
            }
            outer = outer
                .checked_add(usize::from(effective_object_ae))
                .ok_or_else(|| {
                    Error::Invalid("Alcor UfdApi address outer index overflows".into())
                })?;
            current = current
                .checked_add(group_span)
                .ok_or_else(|| Error::Invalid("Alcor UfdApi address cursor overflows".into()))?;
        }
    } else {
        for (index, address) in address_words.iter_mut().take(populated_words).enumerate() {
            *address = current;
            current = current
                .checked_add(1)
                .ok_or_else(|| Error::Invalid("Alcor UfdApi address cursor overflows".into()))?;
            if (index + 1) % usize::from(effective_object_ae) == 0 {
                current = current
                    .checked_add(group_span - u16::from(effective_object_ae))
                    .ok_or_else(|| {
                        Error::Invalid("Alcor UfdApi address cursor overflows".into())
                    })?;
            }
        }
        if !inputs.object_37d2_words.is_empty() {
            return Err(Error::Invalid(
                "Alcor UfdApi non-mode-1 address layout supplied an unused object_37d2 table"
                    .into(),
            ));
        }
    }

    Ok(UfdApiAddressLayout {
        object_02,
        effective_object_ae,
        group_span,
        populated_words,
        address_words,
    })
}

/// Reproduce the object 0x361 normalization and object 0x364 pair-mask
/// compression written to parameter-page offsets 0x1ed..0x1ef.
pub fn derive_ufdapi_mask_fields(
    object_361: u8,
    object_364: u32,
    object_348_bit_08: bool,
) -> UfdApiMaskFields {
    let normalized_object_1ee = match object_361 {
        0x0c => 0x08,
        0x02 => 0x04,
        value => value,
    };
    let object_mask_1ed_1ef = if object_348_bit_08 {
        let mut compressed = 0u16;
        for pair in 0..16u32 {
            let source_mask = 0x03u32 << (pair * 2);
            if object_364 & source_mask == source_mask {
                compressed |= 1u16 << pair;
            }
        }
        compressed
    } else {
        object_364 as u16
    };
    UfdApiMaskFields {
        object_mask_1ed_1ef,
        normalized_object_1ee,
    }
}

/// Reproduce the 512-byte parameter page emitted by the authenticated 2013
/// UfdApi_Gen factory library. This function only encodes fully supplied
/// recovered fields; it does not infer them from a product name.
pub fn build_parameter_page(fields: &ParameterPageFields) -> Result<[u8; PARAMETER_PAGE_BYTES]> {
    if !matches!(fields.control_00, 0x10 | 0x11)
        || fields.object_02 > 0x40
        || fields.object_aa < 10
        || fields.object_ac == 0
        || fields.object_ae == 0
        || !matches!(fields.address_words.len(), 8 | 16)
        || fields.global_140 == Some(0)
        || fields.helper_192 == Some(0)
        || fields.object_1a7.is_some() != fields.helper_1a8.is_some()
    {
        return Err(Error::Invalid(
            "Alcor parameter-page fields violate the recovered factory bounds".into(),
        ));
    }
    let object_03 = (0x400u16 / fields.object_ac).min(8);
    if object_03 == 0 {
        return Err(Error::Invalid(
            "Alcor parameter-page object_ac exceeds the recovered divisor range".into(),
        ));
    }
    let adjusted_aa = fields.object_aa.checked_sub(10).ok_or_else(|| {
        Error::Invalid("Alcor parameter-page object_aa adjustment underflow".into())
    })?;
    let combined_ac_ae = fields
        .object_ac
        .checked_mul(u16::from(fields.object_ae))
        .ok_or_else(|| {
            Error::Invalid("Alcor parameter-page object_ac/object_ae product overflow".into())
        })?;

    let mut output = [0u8; PARAMETER_PAGE_BYTES];
    output[0x00] = fields.control_00;
    output[0x02] = fields.object_02;
    output[0x03] = object_03 as u8;
    put_be_u16(&mut output, 0x04, fields.object_ac)?;
    output[0x06] = fields.object_a8;
    output[0x08] = fields.object_ae;
    put_be_u16(&mut output, 0x0a, fields.object_aa)?;
    put_be_u16(&mut output, 0x0c, adjusted_aa)?;
    put_be_u16(&mut output, 0x0e, combined_ac_ae)?;
    output[0x10] = fields.helper_10;
    output[0x11] = fields.helper_11;
    put_be_u16(&mut output, 0x12, fields.operation_argument)?;

    output[0x100] = 0xa0;
    output[0x102] = fields.operation_code_102;
    put_be_u16(&mut output, 0x103, fields.operation_argument)?;
    output[0x105] = fields.object_105;
    output[0x10f] = fields.helper_10f;
    for (index, value) in fields.address_words.iter().enumerate() {
        put_be_u16(&mut output, 0x110 + index * 2, *value)?;
    }
    if fields.feature_120 {
        output[0x120] = 0x51;
    }
    if fields.feature_121 {
        output[0x121] = 0x51;
    }
    if fields.controller_e3_signature {
        output[0x122..0x128].copy_from_slice(&[0x00, 0x3e, 0xe9, 0xe1, 0x50, 0x0a]);
    }
    if let Some(value) = fields.global_140 {
        output[0x140] = value;
    }
    if let Some(value) = fields.helper_192 {
        put_be_u16(&mut output, 0x192, value)?;
    }
    output[0x194] = fields.object_194;
    output[0x195] = fields.helper_195;
    if fields.feature_19f {
        output[0x19f] = 0x51;
    }
    if let (Some(object), Some(helper)) = (fields.object_1a7, fields.helper_1a8) {
        output[0x1a7] = object;
        output[0x1a8] = helper;
    }
    output[0x1ed] = (fields.object_mask_1ed_1ef >> 8) as u8;
    output[0x1ee] = fields.normalized_object_1ee;
    output[0x1ef] = fields.object_mask_1ed_1ef as u8;
    output[0x1fe..0x200].copy_from_slice(&PARAMETER_PAGE_TRAILER);
    Ok(output)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServiceUpload {
    pub cdb: [u8; 8],
    pub module_sectors: u8,
    pub payload: Vec<u8>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RawPageAddress {
    pub chip_enable: u8,
    pub block: u16,
    pub page: u16,
    /// Factory-library byte 8. Its meaning is module-specific and must be
    /// supplied by the exact tuple rather than inferred by this module.
    pub module_argument: u8,
    /// Factory-library bytes 14..=15. Their meaning is module-specific.
    pub trailing_argument: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RawPageTransfer {
    pub cdb: [u8; 16],
    pub transfer_bytes: usize,
    pub page_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OperationStatus {
    pub detail: u32,
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Decode the exact Alcor factory-module representation.
///
/// Each record contains 32 hexadecimal characters followed by CRLF, except
/// that the final record may omit CRLF. Two factory files also carry a final
/// DOS EOF byte (0x1a), which is accepted only at the physical end of input.
/// The result must be sector-aligned and carry the 0x55aa module trailer.
pub fn decode_ascii_hex_module(source: &[u8]) -> Result<Vec<u8>> {
    if source.is_empty() || source.len() > MAX_ASCII_MODULE_BYTES {
        return Err(Error::Invalid(
            "Alcor ASCII-hex module has an invalid size".into(),
        ));
    }
    let source = source.strip_suffix(&[0x1a]).unwrap_or(source);
    if source.is_empty() {
        return Err(Error::Invalid(
            "Alcor ASCII-hex module contains no records".into(),
        ));
    }

    let mut decoded = Vec::with_capacity(source.len() / 2);
    let mut cursor = 0usize;
    let mut records = 0usize;
    while cursor < source.len() {
        let remaining = &source[cursor..];
        let line_end = remaining
            .windows(2)
            .position(|window| window == b"\r\n")
            .map(|relative| cursor + relative)
            .unwrap_or(source.len());
        let record = &source[cursor..line_end];
        if record.len() != ASCII_HEX_RECORD_CHARS {
            return Err(Error::Invalid(format!(
                "Alcor ASCII-hex module record {} has {} characters instead of {ASCII_HEX_RECORD_CHARS}",
                records + 1,
                record.len()
            )));
        }
        for pair in record.chunks_exact(2) {
            let high = hex_nibble(pair[0]).ok_or_else(|| {
                Error::Invalid(format!(
                    "Alcor ASCII-hex module record {} contains a non-hexadecimal character",
                    records + 1
                ))
            })?;
            let low = hex_nibble(pair[1]).ok_or_else(|| {
                Error::Invalid(format!(
                    "Alcor ASCII-hex module record {} contains a non-hexadecimal character",
                    records + 1
                ))
            })?;
            decoded.push((high << 4) | low);
        }
        records += 1;
        if line_end == source.len() {
            cursor = source.len();
        } else {
            cursor = line_end.checked_add(2).ok_or_else(|| {
                Error::Invalid("Alcor ASCII-hex module record offset overflow".into())
            })?;
            if cursor == source.len() {
                break;
            }
        }
    }
    validate_decoded_module(&decoded)?;
    Ok(decoded)
}

pub fn validate_decoded_module(module: &[u8]) -> Result<u8> {
    if module.is_empty()
        || !module.len().is_multiple_of(SECTOR_BYTES)
        || module.len() > MAX_MODULE_SECTORS * SECTOR_BYTES
    {
        return Err(Error::Invalid(format!(
            "Alcor decoded module must occupy 1..={MAX_MODULE_SECTORS} complete sectors"
        )));
    }
    if !module.ends_with(&MODULE_TRAILER) {
        return Err(Error::Invalid(
            "Alcor decoded module lacks its 55aa trailer".into(),
        ));
    }
    u8::try_from(module.len() / SECTOR_BYTES)
        .map_err(|_| Error::Invalid("Alcor decoded module sector count overflow".into()))
}

/// Append the exact 512-byte parameter page and construct FA 0A 00 N.
pub fn build_service_upload(module: &[u8], parameter_page: &[u8]) -> Result<ServiceUpload> {
    let module_sectors = validate_decoded_module(module)?;
    if parameter_page.len() != PARAMETER_PAGE_BYTES
        || !parameter_page.ends_with(&PARAMETER_PAGE_TRAILER)
    {
        return Err(Error::Invalid(
            "Alcor parameter page must be exactly 512 bytes and end with JN".into(),
        ));
    }
    let capacity = module
        .len()
        .checked_add(PARAMETER_PAGE_BYTES)
        .ok_or_else(|| Error::Invalid("Alcor service upload size overflow".into()))?;
    let mut payload = Vec::with_capacity(capacity);
    payload.extend_from_slice(module);
    payload.extend_from_slice(parameter_page);
    Ok(ServiceUpload {
        cdb: [0xfa, 0x0a, 0x00, module_sectors, 0, 0, 0, 0],
        module_sectors,
        payload,
    })
}

/// Validate the decoded module plus exact 512-byte parameter page persisted
/// as a runtime artifact. The returned upload includes the derived FA0A CDB.
pub fn validate_service_payload(payload: &[u8]) -> Result<ServiceUpload> {
    let module_bytes = payload
        .len()
        .checked_sub(PARAMETER_PAGE_BYTES)
        .filter(|length| *length != 0 && length.is_multiple_of(SECTOR_BYTES))
        .ok_or_else(|| {
            Error::Invalid(
                "Alcor service payload must contain module sectors plus one parameter sector"
                    .into(),
            )
        })?;
    build_service_upload(&payload[..module_bytes], &payload[module_bytes..])
}

pub fn physical_block_erase_cdb(chip_enable: u8, block: u16) -> [u8; 8] {
    let block = block.to_be_bytes();
    [0xfa, 0x0b, 0x11, chip_enable, block[0], block[1], 0, 0]
}

pub fn physical_block_range_erase_cdb(
    chip_enable: u8,
    first_block: u16,
    block_count: u16,
) -> Result<[u8; 8]> {
    if block_count == 0 {
        return Err(Error::Invalid(
            "Alcor physical range erase requires a non-zero block count".into(),
        ));
    }
    first_block.checked_add(block_count - 1).ok_or_else(|| {
        Error::Invalid("Alcor physical range erase exceeds the 16-bit block space".into())
    })?;
    let first = first_block.to_be_bytes();
    let count = block_count.to_be_bytes();
    Ok([
        0xfa,
        0x0b,
        0xa7,
        chip_enable,
        first[0],
        first[1],
        count[0],
        count[1],
    ])
}

pub fn operation_status_cdb() -> [u8; 8] {
    [0xfa, 0x0b, 0x06, 0, 0, 0, 0, 0]
}

fn raw_page_cdb(subcommand: u8, address: RawPageAddress, page_sectors: u8) -> Result<[u8; 16]> {
    if page_sectors == 0 {
        return Err(Error::Invalid(
            "Alcor raw page transfer requires a non-zero sector count".into(),
        ));
    }
    let block = address.block.to_be_bytes();
    let page = address.page.to_be_bytes();
    let trailing = address.trailing_argument.to_be_bytes();
    Ok([
        0xfa,
        0x0b,
        subcommand,
        address.chip_enable,
        block[0],
        block[1],
        page[0],
        page[1],
        address.module_argument,
        page_sectors,
        0,
        0,
        0,
        0,
        trailing[0],
        trailing[1],
    ])
}

pub fn raw_page_program(address: RawPageAddress, page_sectors: u8) -> Result<RawPageTransfer> {
    let page_bytes = usize::from(page_sectors)
        .checked_mul(SECTOR_BYTES)
        .ok_or_else(|| Error::Invalid("Alcor raw page program size overflow".into()))?;
    Ok(RawPageTransfer {
        cdb: raw_page_cdb(0x18, address, page_sectors)?,
        transfer_bytes: page_bytes,
        page_bytes,
    })
}

pub fn raw_page_read(address: RawPageAddress, page_sectors: u8) -> Result<RawPageTransfer> {
    let transfer_sectors = usize::from(page_sectors)
        .checked_add(RAW_READ_TRAILER_SECTORS)
        .filter(|sectors| *sectors <= usize::from(u8::MAX))
        .ok_or_else(|| Error::Invalid("Alcor raw page read sector count overflow".into()))?;
    let transfer_bytes = transfer_sectors
        .checked_mul(SECTOR_BYTES)
        .ok_or_else(|| Error::Invalid("Alcor raw page read size overflow".into()))?;
    Ok(RawPageTransfer {
        cdb: raw_page_cdb(0x19, address, page_sectors)?,
        transfer_bytes,
        page_bytes: usize::from(page_sectors) * SECTOR_BYTES,
    })
}

pub fn parse_operation_status(response: &[u8]) -> Result<OperationStatus> {
    if response.len() != SECTOR_BYTES {
        return Err(Error::Invalid(format!(
            "Alcor operation status must be one sector, got {} bytes",
            response.len()
        )));
    }
    let detail =
        u32::from(response[1]) | (u32::from(response[2]) << 8) | (u32::from(response[3]) << 16);
    if response[0] != 0 {
        return Err(Error::Invalid(format!(
            "Alcor operation status reports failure {:02x} with detail {detail:06x}",
            response[0]
        )));
    }
    Ok(OperationStatus { detail })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flash_database_fixture() -> Vec<u8> {
        let derived_key = std::array::from_fn::<_, 256, _>(|index| {
            (index as u8).wrapping_mul(17).wrapping_add(3)
        });
        let mut header = [0u8; 256];
        header[..FLASH_DATABASE_MAGIC.len()].copy_from_slice(FLASH_DATABASE_MAGIC);
        header[32..36].copy_from_slice(&1u32.to_le_bytes());
        header[36..40].copy_from_slice(&4u32.to_le_bytes());
        header[40..44].copy_from_slice(&(FLASH_DATABASE_ENTRY_BYTES_V4 as u32).to_le_bytes());
        header[44..48].copy_from_slice(&1u32.to_le_bytes());

        let mut entry = vec![0u8; FLASH_DATABASE_ENTRY_BYTES_V4];
        entry[..7].copy_from_slice(b"SanDisk");
        let model = b"SDTNPMCHEM-032G";
        entry[16..16 + model.len()].copy_from_slice(model);
        entry[48..54].copy_from_slice(&[0x45, 0x3c, 0xa6, 0x82, 0x7e, 0x56]);
        entry[0x36..0x56].copy_from_slice(
            &hex::decode("0100001900800000648002010400100020000100011001018119000508000000")
                .unwrap(),
        );
        let module = b"10_2A_SDMAHSM.BIN";
        entry[FLASH_DATABASE_CTL10_13_FIELDS[0]..FLASH_DATABASE_CTL10_13_FIELDS[0] + module.len()]
            .copy_from_slice(module);
        let auxiliary = b"10_SD24M_SM";
        entry[FLASH_DATABASE_CTL10_13_FIELDS[1]
            ..FLASH_DATABASE_CTL10_13_FIELDS[1] + auxiliary.len()]
            .copy_from_slice(auxiliary);
        entry[FLASH_DATABASE_CTL84_FIELDS[0]] = 0;
        entry[FLASH_DATABASE_CTL84_FIELDS[0] + 1..FLASH_DATABASE_CTL84_FIELDS[0] + 8]
            .copy_from_slice(b"4_STALE");

        let mut record_key = derived_key;
        record_key[0] = 0;
        record_key[255] = 0xff;
        let mut fixture = alcor_stream_cipher(&derived_key, FLASH_DATABASE_KEY).unwrap();
        fixture.extend_from_slice(&alcor_stream_cipher(&header, &derived_key).unwrap());
        fixture.extend_from_slice(&alcor_stream_cipher(&entry, &record_key).unwrap());
        fixture.extend_from_slice(b"opaque-tail");
        fixture
    }

    fn encoded_module(dos_eof: bool) -> Vec<u8> {
        let mut module = vec![0u8; SECTOR_BYTES];
        module[SECTOR_BYTES - 2..].copy_from_slice(&MODULE_TRAILER);
        let mut encoded = Vec::new();
        for (index, record) in module.chunks_exact(ASCII_HEX_RECORD_BYTES).enumerate() {
            if index != 0 {
                encoded.extend_from_slice(b"\r\n");
            }
            encoded.extend_from_slice(hex::encode_upper(record).as_bytes());
        }
        if dos_eof {
            encoded.push(0x1a);
        }
        encoded
    }

    #[test]
    fn decodes_exact_factory_ascii_hex_records() {
        let expected = {
            let mut value = vec![0u8; SECTOR_BYTES];
            value[SECTOR_BYTES - 2..].copy_from_slice(&MODULE_TRAILER);
            value
        };
        assert_eq!(
            decode_ascii_hex_module(&encoded_module(false)).unwrap(),
            expected
        );
        assert_eq!(
            decode_ascii_hex_module(&encoded_module(true)).unwrap(),
            expected
        );
    }

    #[test]
    fn rejects_malformed_or_incomplete_factory_modules() {
        let mut bare_lf = encoded_module(false);
        let cr = bare_lf.iter().position(|byte| *byte == b'\r').unwrap();
        bare_lf.remove(cr);
        assert!(decode_ascii_hex_module(&bare_lf).is_err());

        let mut invalid_hex = encoded_module(false);
        invalid_hex[0] = b'X';
        assert!(decode_ascii_hex_module(&invalid_hex).is_err());

        let mut bad_trailer = encoded_module(false);
        *bad_trailer.last_mut().unwrap() = b'0';
        assert!(decode_ascii_hex_module(&bad_trailer).is_err());
    }

    #[test]
    fn builds_authenticated_service_and_raw_nand_commands() {
        let module = decode_ascii_hex_module(&encoded_module(false)).unwrap();
        let mut parameter_page = vec![0u8; PARAMETER_PAGE_BYTES];
        parameter_page[PARAMETER_PAGE_BYTES - 2..].copy_from_slice(b"JN");
        let upload = build_service_upload(&module, &parameter_page).unwrap();
        assert_eq!(upload.cdb, [0xfa, 0x0a, 0, 1, 0, 0, 0, 0]);
        assert_eq!(upload.payload.len(), 2 * SECTOR_BYTES);
        assert_eq!(validate_service_payload(&upload.payload).unwrap(), upload);

        assert_eq!(
            physical_block_erase_cdb(2, 0x1234),
            [0xfa, 0x0b, 0x11, 2, 0x12, 0x34, 0, 0]
        );
        assert_eq!(
            physical_block_range_erase_cdb(1, 0x0100, 0x0200).unwrap(),
            [0xfa, 0x0b, 0xa7, 1, 0x01, 0x00, 0x02, 0x00]
        );

        let address = RawPageAddress {
            chip_enable: 3,
            block: 0x1234,
            page: 0x5678,
            module_argument: 0x9a,
            trailing_argument: 0xbcde,
        };
        let write = raw_page_program(address, 16).unwrap();
        assert_eq!(
            write.cdb,
            [0xfa, 0x0b, 0x18, 3, 0x12, 0x34, 0x56, 0x78, 0x9a, 16, 0, 0, 0, 0, 0xbc, 0xde,]
        );
        assert_eq!(write.transfer_bytes, 16 * SECTOR_BYTES);
        let read = raw_page_read(address, 16).unwrap();
        assert_eq!(read.cdb[2], 0x19);
        assert_eq!(read.transfer_bytes, 18 * SECTOR_BYTES);
        assert_eq!(read.page_bytes, 16 * SECTOR_BYTES);
    }

    #[test]
    fn fails_closed_on_operation_status() {
        let mut status = vec![0u8; SECTOR_BYTES];
        status[1..4].copy_from_slice(&[0x34, 0x12, 0x00]);
        assert_eq!(parse_operation_status(&status).unwrap().detail, 0x1234);
        status[0] = 1;
        assert!(parse_operation_status(&status).is_err());
        assert!(parse_operation_status(&status[..32]).is_err());
    }

    #[test]
    fn preserves_factory_xor_swap_alias_behavior() {
        let mut state = std::array::from_fn::<_, 256, _>(|index| index as u8);
        alcor_xor_swap(&mut state, 19, 19);
        assert_eq!(state[19], 0);
        alcor_xor_swap(&mut state, 20, 21);
        assert_eq!((state[20], state[21]), (21, 20));
    }

    #[test]
    fn decodes_bounded_encrypted_flash_database_records() {
        let database = decode_flash_database(&flash_database_fixture()).unwrap();
        assert_eq!(database.header.version, 4);
        assert_eq!(database.header.entry_bytes, FLASH_DATABASE_ENTRY_BYTES_V4);
        assert_eq!(database.header.entry_count, 1);
        assert_eq!(database.header.unknown_words, [0, 0, 0, 0, 1]);
        assert_eq!(database.unparsed_suffix_bytes, 11);
        assert_eq!(database.entries[0].vendor, "SanDisk");
        assert_eq!(database.entries[0].model, "SDTNPMCHEM-032G");
        assert_eq!(database.entries[0].nand_id_hex, "453ca6827e56");
        assert_eq!(
            database.entries[0].operational_input.source_bytes_hex,
            "0100001900800000648002010400100020000100011001018119000508000000"
        );
        let operational = derive_flash_database_operational_fields(
            &database.entries[0],
            false,
            FlashDatabaseConverter::LegacyAlcorMp130205,
        )
        .unwrap();
        let FlashDatabaseOperationalFields::LegacyAlcorMp130205(legacy) = &operational else {
            panic!("unexpected converter layout");
        };
        assert_eq!(legacy.object_0e, 0);
        assert_eq!(legacy.object_0f, 1);
        assert_eq!(legacy.object_14, 1);
        assert_eq!(legacy.object_18, 0x8000);
        assert_eq!(legacy.object_1c, 100);
        assert_eq!(legacy.object_1e, 640);
        assert_eq!(legacy.object_21, 4);
        assert_eq!(legacy.object_22, 0x1000);
        assert_eq!(legacy.object_24, 0x2000);
        assert_eq!(legacy.object_26, 0x1000);
        assert_eq!(legacy.object_4c, 0x4000);
        assert_eq!(legacy.object_50, 3);
        assert_eq!(legacy.object_51, 2);
        assert_eq!(legacy.object_52, 3);
        assert_eq!(legacy.object_54, 0x30);

        let modern = derive_flash_database_operational_fields(
            &database.entries[0],
            false,
            FlashDatabaseConverter::UfdApiGen1310,
        )
        .unwrap();
        let FlashDatabaseOperationalFields::UfdApiGen1310(modern) = &modern else {
            panic!("unexpected converter layout");
        };
        assert_eq!(modern.object_24, 0x2000);
        assert_eq!(modern.object_30, 0x2000);
        assert_eq!(modern.object_32, 0x0800);
        assert_eq!(modern.object_34, 1);
        assert_eq!(modern.object_35, 0x81);
        assert_eq!(modern.object_36, 5);
        assert_eq!(modern.object_40, 8);
        assert_eq!(modern.object_50, 0x8000);
        assert_eq!(modern.object_54, 3);
        assert_eq!(modern.object_55, 2);
        assert_eq!(modern.object_56, 3);
        assert_eq!(modern.object_58, 0x30);
        assert_eq!(modern.object_60, 1);
        assert_ne!(operational.controller_module_limit(), modern.object_50);
        assert_eq!(
            derive_flash_database_operational_fields(
                &database.entries[0],
                true,
                FlashDatabaseConverter::LegacyAlcorMp130205,
            )
            .unwrap()
            .object_14(),
            0
        );
        let selections = &database.entries[0].controller_selections;
        assert_eq!(selections.len(), 7);
        let ctl10 = selections
            .iter()
            .find(|selection| selection.controller_id == "alcor-ctl-10")
            .unwrap();
        assert_eq!(ctl10.runtime.slot_offset, 0x236);
        assert_eq!(ctl10.runtime_module(), Some("10_2A_SDMAHSM.BIN"));
        assert_eq!(ctl10.auxiliary_1.value.as_deref(), Some("10_SD24M_SM"));
        let ctl13 = selections
            .iter()
            .find(|selection| selection.controller_id == "alcor-ctl-13")
            .unwrap();
        assert_eq!(ctl13.runtime_module(), Some("10_2A_SDMAHSM.BIN"));
        let ctl84 = selections
            .iter()
            .find(|selection| selection.controller_id == "alcor-ctl-84")
            .unwrap();
        assert_eq!(ctl84.runtime.value, None);
        assert_eq!(
            ctl84.runtime.status,
            FlashDatabaseSelectedFieldStatus::Empty
        );
        assert_eq!(ctl84.runtime_module(), None);
    }

    #[test]
    fn rejects_flash_database_header_tampering() {
        let mut fixture = flash_database_fixture();
        fixture[256] ^= 0x80;
        assert!(decode_flash_database(&fixture).is_err());
        assert!(decode_flash_database(&fixture[..511]).is_err());
    }

    #[test]
    fn maps_factory_module_feature_fields_and_defaults() {
        let sandisk = parse_module_feature_parameters(&[1, 2, 0, 2048, 0, 1, 6, 6]).unwrap();
        assert_eq!(sandisk.supplied_parameters, 8);
        assert_eq!(sandisk.object_3e1, 1);
        assert_eq!(sandisk.object_3e2, 2);
        assert_eq!(sandisk.object_3e4, 0);
        assert_eq!(sandisk.object_3e8, 2048);
        assert_eq!(sandisk.object_3eb, 1);
        assert_eq!(sandisk.object_3ec, 6);
        assert_eq!(sandisk.object_3ed, 6);
        assert_eq!(sandisk.object_3ee, 0);

        let defaults = parse_module_feature_parameters(&[1, 1, 0, 1024, 0, 0, 0, 0, 9]).unwrap();
        assert_eq!(defaults.object_3ec, 4);
        assert_eq!(defaults.object_3ed, 2);
        assert_eq!(defaults.object_3ee, 9);

        let ctl92 = parse_module_feature_parameters(&[1, 2, 0, 1024, 0]).unwrap();
        assert_eq!(ctl92.supplied_parameters, 5);
        assert_eq!(ctl92.object_3eb, 0);
        assert_eq!(ctl92.object_3ec, 4);
        assert_eq!(ctl92.object_3ed, 2);
        assert_eq!(ctl92.object_3ee, 0);
        validate_module_feature_parameter_count(0x92, ctl92.supplied_parameters).unwrap();
        assert!(validate_module_feature_parameter_count(0x90, ctl92.supplied_parameters).is_err());
        validate_module_feature_parameter_count(0x96, 6).unwrap();
        validate_module_feature_parameter_count(0x13, 8).unwrap();
        assert!(validate_module_feature_parameter_count(0x84, 8).is_err());
        assert!(parse_module_feature_parameters(&[0, 1, 0, 1024, 0, 0, 4, 2]).is_err());
        assert!(parse_module_feature_parameters(&[1, 1, 0, 40_000, 0, 0, 4, 2]).is_err());
    }

    #[test]
    fn applies_controller_module_limit_and_normal_geometry() {
        let feature = parse_module_feature_parameters(&[1, 2, 0, 2048, 0, 1, 6, 6]).unwrap();
        assert_eq!(
            apply_module_feature_controller_limit(&feature, 0x10, None).unwrap(),
            feature
        );
        let bounded = apply_module_feature_controller_limit(&feature, 0x84, Some(2048)).unwrap();
        assert_eq!(bounded.object_3e8, 1024);
        assert!(apply_module_feature_controller_limit(&feature, 0x84, None).is_err());
        assert!(apply_module_feature_controller_limit(&feature, 0x10, Some(1)).is_err());

        let geometry = derive_normal_geometry(
            &feature,
            &NormalGeometryInputs {
                object_5670f: 4,
                object_9e: 2,
                object_9f: true,
                object_3a4: 256,
                helper_1fb9d: None,
                object_3a8: 2,
                argument_0c: 0,
                argument_10_ce_mask: 0,
            },
        )
        .unwrap();
        assert_eq!(geometry.object_a8, 2);
        assert_eq!(geometry.object_a9, 4);
        assert_eq!(geometry.object_aa, 2048);
        assert_eq!(geometry.object_ac, 512);
        assert_eq!(geometry.object_ae, 4);
        assert_eq!(geometry.object_b0, 8192);

        let masked = derive_normal_geometry(
            &feature,
            &NormalGeometryInputs {
                object_5670f: 1,
                object_9e: 2,
                object_9f: false,
                object_3a4: 256,
                helper_1fb9d: Some(128),
                object_3a8: 4,
                argument_0c: 0x0c,
                argument_10_ce_mask: 0b0101,
            },
        )
        .unwrap();
        assert_eq!(masked.object_a8, 1);
        assert_eq!(masked.object_ac, 256);
        assert_eq!(masked.object_ae, 2);

        let database = decode_flash_database(&flash_database_fixture()).unwrap();
        let modern = derive_flash_database_operational_fields(
            &database.entries[0],
            false,
            FlashDatabaseConverter::UfdApiGen1310,
        )
        .unwrap();
        let package_geometry = derive_ufdapi_normal_geometry(
            &feature,
            &modern,
            &UfdApiNormalGeometryRuntimeInputs {
                object_5670f: 4,
                object_9e: 2,
                object_9f: false,
                helper_1fb9d: None,
                argument_0c: 0,
                argument_10_ce_mask: 0,
            },
        )
        .unwrap();
        assert_eq!(package_geometry.object_a8, 2);
        assert_eq!(package_geometry.object_aa, 2048);
        assert_eq!(package_geometry.object_ac, 512);
        assert_eq!(package_geometry.object_ae, 16);

        let legacy = derive_flash_database_operational_fields(
            &database.entries[0],
            false,
            FlashDatabaseConverter::LegacyAlcorMp130205,
        )
        .unwrap();
        assert!(derive_ufdapi_normal_geometry(
            &feature,
            &legacy,
            &UfdApiNormalGeometryRuntimeInputs {
                object_5670f: 4,
                object_9e: 2,
                object_9f: false,
                helper_1fb9d: None,
                argument_0c: 0,
                argument_10_ce_mask: 0,
            },
        )
        .is_err());
    }

    #[test]
    fn derives_parameter_page_address_and_mask_fields() {
        let geometry = NormalGeometry {
            object_a8: 2,
            object_a9: 4,
            object_aa: 2048,
            object_ac: 512,
            object_ae: 4,
            object_b0: 8192,
        };
        let linear = derive_ufdapi_address_layout(
            &geometry,
            &UfdApiAddressInputs {
                argument_18: 0,
                object_38a: 0,
                object_3e19: 2,
                helper_b4: 2,
                helper_b8: 2,
                object_348_bit_08: false,
                object_37d2_words: Vec::new(),
            },
        )
        .unwrap();
        assert_eq!(linear.object_02, 0x10);
        assert_eq!(linear.effective_object_ae, 4);
        assert_eq!(linear.group_span, 16);
        assert_eq!(linear.populated_words, 8);
        assert_eq!(
            &linear.address_words[..8],
            &[16, 17, 18, 19, 32, 33, 34, 35]
        );
        assert!(linear.address_words[8..].iter().all(|value| *value == 0));

        let table = derive_ufdapi_address_layout(
            &geometry,
            &UfdApiAddressInputs {
                argument_18: 0,
                object_38a: 0,
                object_3e19: 1,
                helper_b4: 2,
                helper_b8: 2,
                object_348_bit_08: true,
                object_37d2_words: vec![0, 100, 200],
            },
        )
        .unwrap();
        assert_eq!(
            table.address_words,
            [100, 101, 102, 103, 200, 201, 202, 203]
        );

        let mask = derive_ufdapi_mask_fields(0x0c, 0b11_01_11, true);
        assert_eq!(mask.normalized_object_1ee, 8);
        assert_eq!(mask.object_mask_1ed_1ef, 0b101);
        let uncompressed = derive_ufdapi_mask_fields(2, 0x1234_abcd, false);
        assert_eq!(uncompressed.normalized_object_1ee, 4);
        assert_eq!(uncompressed.object_mask_1ed_1ef, 0xabcd);
    }

    fn parameter_fields() -> ParameterPageFields {
        ParameterPageFields {
            control_00: 0x11,
            object_02: 0x20,
            object_a8: 3,
            object_aa: 0x1234,
            object_ac: 0x0200,
            object_ae: 2,
            helper_10: 0x40,
            helper_11: 0x22,
            operation_code_102: 0x19,
            operation_argument: 0x4567,
            object_105: 0x89,
            helper_10f: 0xab,
            address_words: (0..16).map(|value| 0x1000 + value).collect(),
            feature_120: true,
            feature_121: true,
            controller_e3_signature: true,
            global_140: Some(0x7f),
            helper_192: Some(0x018f),
            object_194: 0x12,
            helper_195: 0x34,
            feature_19f: true,
            object_1a7: Some(0x56),
            helper_1a8: Some(0x78),
            object_mask_1ed_1ef: 0x9abc,
            normalized_object_1ee: 8,
        }
    }

    #[test]
    fn builds_exact_recovered_parameter_page_layout() {
        let page = build_parameter_page(&parameter_fields()).unwrap();
        assert_eq!(
            &page[..20],
            &[
                0x11, 0, 0x20, 2, 2, 0, 3, 0, 2, 0, 0x12, 0x34, 0x12, 0x2a, 4, 0, 0x40, 0x22, 0x45,
                0x67
            ]
        );
        assert_eq!(&page[0x100..0x106], &[0xa0, 0, 0x19, 0x45, 0x67, 0x89]);
        assert_eq!(
            &page[0x110..0x120],
            &[0x10, 0, 0x10, 1, 0x10, 2, 0x10, 3, 0x10, 4, 0x10, 5, 0x10, 6, 0x10, 7]
        );
        assert_eq!(
            &page[0x120..0x128],
            &[0x51, 0x51, 0, 0x3e, 0xe9, 0xe1, 0x50, 0x0a]
        );
        assert_eq!(&page[0x192..0x196], &[0x01, 0x8f, 0x12, 0x34]);
        assert_eq!(page[0x19f], 0x51);
        assert_eq!(&page[0x1a7..0x1a9], &[0x56, 0x78]);
        assert_eq!(&page[0x1ed..0x1f0], &[0x9a, 8, 0xbc]);
        assert_eq!(&page[0x1fe..], b"JN");
    }

    #[test]
    fn rejects_incomplete_parameter_page_fields() {
        let mut fields = parameter_fields();
        fields.address_words.truncate(9);
        assert!(build_parameter_page(&fields).is_err());
        fields.address_words.truncate(8);
        fields.object_ac = 0;
        assert!(build_parameter_page(&fields).is_err());
        fields.object_ac = 0x200;
        fields.object_1a7 = None;
        assert!(build_parameter_page(&fields).is_err());
    }
}
