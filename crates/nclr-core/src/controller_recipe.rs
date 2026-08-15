//! Declarative controller service protocol and durable physical-block state.
//!
//! Vendor opcodes are never inferred at run time. A production profile pins
//! one exact recipe artifact. This module validates that recipe, builds only
//! bounded CDBs, decodes signed responses, serializes controller metadata and
//! keeps the destructive state in a two-slot crash-consistent file.

use crate::controller_protocol::{family_from_recipe_str, support, Family};
use crate::errors::{Error, Result};
use crate::profile::{MetadataLayoutPolicy, NandGeometryPolicy, Profile, SystemBlockPolicy};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

pub const RECIPE_SCHEMA: u32 = 4;
pub const TRANSPORT_SCSI_COMMAND: &str = "scsi-command";
pub const TRANSPORT_USB_BOT: &str = "usb-bot";

fn transport_supports_cdb(transport: &str, length: usize) -> bool {
    match transport {
        TRANSPORT_SCSI_COMMAND => matches!(length, 6 | 10 | 12 | 16),
        TRANSPORT_USB_BOT => (6..=MAX_CDB_BYTES).contains(&length),
        _ => false,
    }
}
pub const STATE_SCHEMA: u32 = 1;
pub const MAX_RECIPE_BYTES: u64 = 4 * 1024 * 1024;
pub const MAX_CDB_BYTES: usize = 16;
pub const MAX_COMMAND_TRANSFER: u32 = 16 * 1024 * 1024;
pub const MAX_PHYSICAL_BLOCKS: u64 = 131_072;
const MAX_CONTEXT_PAYLOAD_FIELDS: usize = 32;
const MAX_VALUE_OPERATIONS: usize = 16;
const MAX_OPERATION_SEQUENCE_STEPS: usize = 64;
const STATE_SLOT_BYTES: u64 = 64 * 1024 * 1024;
const STATE_DATA_OFFSET: u64 = 4096;
const STATE_DESCRIPTOR_BYTES: usize = 512;
const STATE_FILE_BYTES: u64 = STATE_DATA_OFFSET + STATE_SLOT_BYTES * 2;
const STATE_MAGIC: &[u8; 8] = b"NCLRCSR1";

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TransferDirection {
    None,
    FromDevice,
    ToDevice,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Endian {
    #[default]
    Big,
    Little,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeValue {
    Channel,
    Chip,
    Lun,
    Plane,
    Block,
    Page,
    FlatBlock,
    PayloadBytes,
    Generation,
    UserBlocks,
    SpareBlocks,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum ValueOperation {
    Add { value: u64 },
    Subtract { value: u64 },
    Multiply { value: u64 },
    Divide { value: u64 },
    Modulo { value: u64 },
    XorModulo { value: u64 },
    And { mask: u64 },
    Or { mask: u64 },
    ShiftLeft { bits: u8 },
    ShiftRight { bits: u8 },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PayloadFieldBinding {
    pub offset: u32,
    pub width: u8,
    pub endian: Endian,
    pub value: RuntimeValue,
    #[serde(default)]
    pub operations: Vec<ValueOperation>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PayloadConstantBinding {
    pub offset: u32,
    pub width: u8,
    pub endian: Endian,
    pub value: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct FieldBinding {
    pub offset: u8,
    pub width: u8,
    pub endian: Endian,
    pub value: RuntimeValue,
    #[serde(default)]
    pub operations: Vec<ValueOperation>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct ResponseField {
    pub name: String,
    pub offset: u32,
    pub width: u8,
    pub endian: Endian,
    #[serde(default)]
    pub mask: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub equals: Option<u64>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct ResponseRule {
    #[serde(default)]
    pub min_bytes: u32,
    #[serde(default)]
    pub max_bytes: u32,
    #[serde(default)]
    pub prefix_hex: String,
    /// Offset of the command's logical payload inside the signed response.
    /// A zero `payload_bytes` value exposes the complete response.
    #[serde(default)]
    pub payload_offset: u32,
    #[serde(default)]
    pub payload_bytes: u32,
    #[serde(default)]
    pub fields: Vec<ResponseField>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum PayloadSource {
    Caller,
    Artifact {
        artifact_id: String,
        #[serde(default)]
        offset: u64,
        #[serde(default)]
        length: u64,
    },
    Bbt,
    Ftl,
    Capacity,
    Context {
        record_bytes: u32,
        repeat: u32,
        #[serde(default)]
        fill_byte: u8,
        #[serde(default)]
        constants: Vec<PayloadConstantBinding>,
        fields: Vec<PayloadFieldBinding>,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct CommandSpec {
    pub cdb_hex: String,
    pub direction: TransferDirection,
    #[serde(default)]
    pub transfer_bytes: u32,
    pub timeout_ms: u64,
    #[serde(default)]
    pub fields: Vec<FieldBinding>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<PayloadSource>,
    #[serde(default)]
    pub response: ResponseRule,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SequenceCapture {
    None,
    Payload,
    Fields,
    PayloadAndFields,
}

impl SequenceCapture {
    pub fn captures_payload(self) -> bool {
        matches!(self, Self::Payload | Self::PayloadAndFields)
    }

    pub fn captures_fields(self) -> bool {
        matches!(self, Self::Fields | Self::PayloadAndFields)
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct OperationStep {
    pub command: String,
    pub capture: SequenceCapture,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct OperationSequence {
    pub steps: Vec<OperationStep>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct IntegerLayout {
    pub offset: u32,
    pub width: u8,
    pub endian: Endian,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum ChecksumAlgorithm {
    Crc {
        width: u8,
        polynomial: u64,
        initial: u64,
        xor_out: u64,
        #[serde(default)]
        reflected: bool,
    },
    Sum {
        width: u8,
        #[serde(default)]
        twos_complement: bool,
    },
    Xor8,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ChecksumLayout {
    pub algorithm: ChecksumAlgorithm,
    pub offset: u32,
    pub endian: Endian,
    pub start: u32,
    pub length: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "kebab-case", tag = "kind")]
pub enum BlockAddressLayout {
    Flat {
        offset: u32,
        width: u8,
        endian: Endian,
    },
    Coordinates {
        channel: IntegerLayout,
        chip: IntegerLayout,
        lun: IntegerLayout,
        block: IntegerLayout,
    },
    CoordinatesWithPlane {
        channel: IntegerLayout,
        chip: IntegerLayout,
        lun: IntegerLayout,
        plane: IntegerLayout,
        block_in_plane: IntegerLayout,
    },
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct BbtLayout {
    /// Exact number of old BBT copies aggregated by the signed read-bbt
    /// response. The table must contain the union of every copy.
    pub copies: u32,
    pub count_offset: u32,
    pub count_width: u8,
    pub count_endian: Endian,
    pub entries_offset: u32,
    pub entry_stride: u32,
    pub address: BlockAddressLayout,
    pub state_offset: u32,
    #[serde(default)]
    pub factory_bad_values: Vec<u8>,
    #[serde(default)]
    pub runtime_bad_values: Vec<u8>,
    #[serde(default)]
    pub system_values: Vec<u8>,
    pub maximum_entries: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct MetadataTableLayout {
    #[serde(default)]
    pub header_hex: String,
    pub fill_byte: u8,
    pub entry_stride: u32,
    pub address: BlockAddressLayout,
    pub state_offset: u32,
    pub factory_bad_value: u8,
    pub quarantined_value: u8,
    pub system_value: u8,
    pub generation_offset: u32,
    pub generation_width: u8,
    pub generation_endian: Endian,
    pub count_offset: u32,
    pub count_width: u8,
    pub count_endian: Endian,
    pub checksum: ChecksumLayout,
    pub commit_offset: u32,
    pub prepare_value: u8,
    pub commit_value: u8,
    pub maximum_bytes: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct FtlPayloadLayout {
    #[serde(default)]
    pub header_hex: String,
    pub fill_byte: u8,
    pub generation_offset: u32,
    pub generation_width: u8,
    pub generation_endian: Endian,
    pub user_blocks_offset: u32,
    pub user_blocks_width: u8,
    pub user_blocks_endian: Endian,
    pub spare_blocks_offset: u32,
    pub spare_blocks_width: u8,
    pub spare_blocks_endian: Endian,
    pub bbt_sha256_offset: u32,
    pub checksum: ChecksumLayout,
    pub commit_offset: u32,
    pub prepare_value: u8,
    pub commit_value: u8,
    pub total_bytes: u32,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum CapacityValue {
    UserBlocks,
    UserBytes,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct CapacityPayloadLayout {
    #[serde(default)]
    pub header_hex: String,
    pub fill_byte: u8,
    pub value_offset: u32,
    pub value_width: u8,
    pub value_endian: Endian,
    pub value: CapacityValue,
    pub total_bytes: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct RecipePolicy {
    pub erase_retries: u8,
    pub block_batch_size: u32,
    pub status_poll_ms: u64,
    pub operation_timeout_ms: u64,
    #[serde(default)]
    pub qualification_pages: Vec<u32>,
    #[serde(default)]
    pub qualification_patterns: Vec<String>,
    pub erased_byte: u8,
    pub old_rbb_reuse: bool,
    #[serde(default)]
    pub enter_reenumerates: bool,
    #[serde(default)]
    pub loader_reenumerates: bool,
    #[serde(default)]
    pub exit_reenumerates: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service_loader_artifact_id: Option<String>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ControllerRecipe {
    pub schema: u32,
    pub family: String,
    pub controller_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub controller_identity_hex: Option<String>,
    pub firmware: String,
    pub nand_id: String,
    pub transport: String,
    #[serde(default)]
    pub commands: BTreeMap<String, CommandSpec>,
    /// Ordered wire commands for a logical operation. A sequence must contain
    /// its same-named target command exactly once. Device-to-host fragments
    /// are appended and decoded fields are merged only when explicitly
    /// captured.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub operation_sequences: BTreeMap<String, OperationSequence>,
    pub bbt: BbtLayout,
    pub bbt_output: MetadataTableLayout,
    pub ftl_output: FtlPayloadLayout,
    pub capacity_output: CapacityPayloadLayout,
    pub policy: RecipePolicy,
}

#[derive(Clone, Copy, Debug)]
pub struct ResolvedOperationStep<'a> {
    pub command_name: &'a str,
    pub command: &'a CommandSpec,
    pub capture: SequenceCapture,
    pub is_target: bool,
}

pub fn resolve_operation_steps<'a>(
    recipe: &'a ControllerRecipe,
    operation: &str,
) -> Result<Vec<ResolvedOperationStep<'a>>> {
    if let Some(sequence) = recipe.operation_sequences.get(operation) {
        return sequence
            .steps
            .iter()
            .map(|step| {
                let (command_name, command) = recipe
                    .commands
                    .get_key_value(&step.command)
                    .ok_or_else(|| {
                        Error::Invalid(format!(
                            "operation {operation} references absent command {}",
                            step.command
                        ))
                    })?;
                Ok(ResolvedOperationStep {
                    command_name,
                    command,
                    capture: step.capture,
                    is_target: command_name == operation,
                })
            })
            .collect();
    }
    let (command_name, command) = recipe
        .commands
        .get_key_value(operation)
        .ok_or_else(|| Error::Invalid(format!("command {operation} is absent")))?;
    let capture = if command.direction == TransferDirection::FromDevice {
        SequenceCapture::PayloadAndFields
    } else {
        SequenceCapture::None
    };
    Ok(vec![ResolvedOperationStep {
        command_name,
        command,
        capture,
        is_target: true,
    }])
}

#[derive(Default, Clone, Copy, Debug)]
pub struct CommandContext {
    pub channel: u64,
    pub chip: u64,
    pub lun: u64,
    pub plane: u64,
    pub block: u64,
    pub page: u64,
    pub flat_block: u64,
    pub payload_bytes: u64,
    pub generation: u64,
    pub user_blocks: u64,
    pub spare_blocks: u64,
}

impl CommandContext {
    fn value(self, source: RuntimeValue) -> u64 {
        match source {
            RuntimeValue::Channel => self.channel,
            RuntimeValue::Chip => self.chip,
            RuntimeValue::Lun => self.lun,
            RuntimeValue::Plane => self.plane,
            RuntimeValue::Block => self.block,
            RuntimeValue::Page => self.page,
            RuntimeValue::FlatBlock => self.flat_block,
            RuntimeValue::PayloadBytes => self.payload_bytes,
            RuntimeValue::Generation => self.generation,
            RuntimeValue::UserBlocks => self.user_blocks,
            RuntimeValue::SpareBlocks => self.spare_blocks,
        }
    }
}

pub fn load_reader(
    reader: &mut File,
    format: crate::artifact::ArtifactFormat,
) -> Result<ControllerRecipe> {
    reader
        .seek(SeekFrom::Start(0))
        .map_err(|e| Error::io("seek controller recipe", Some(e)))?;
    let metadata = reader
        .metadata()
        .map_err(|e| Error::io("stat controller recipe", Some(e)))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_RECIPE_BYTES {
        return Err(Error::Invalid(format!(
            "controller recipe must be a regular file in 1..={MAX_RECIPE_BYTES} bytes"
        )));
    }
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    reader
        .take(MAX_RECIPE_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|e| Error::io("read controller recipe", Some(e)))?;
    if raw.len() as u64 > MAX_RECIPE_BYTES {
        return Err(Error::Invalid(
            "controller recipe exceeded its size limit".into(),
        ));
    }
    match format {
        crate::artifact::ArtifactFormat::Json => serde_json::from_slice(&raw)
            .map_err(|e| Error::Invalid(format!("controller recipe JSON: {e}"))),
        crate::artifact::ArtifactFormat::Toml => {
            let text = std::str::from_utf8(&raw)
                .map_err(|e| Error::Invalid(format!("controller recipe TOML UTF-8: {e}")))?;
            toml::from_str(text).map_err(|e| Error::Invalid(format!("controller recipe TOML: {e}")))
        }
        other => Err(Error::Invalid(format!(
            "controller recipe has unsupported format {other:?}"
        ))),
    }
}

fn hex_bytes(value: &str, field: &str) -> Result<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Invalid(format!(
            "{field} must contain an even number of hexadecimal characters"
        )));
    }
    hex::decode(value).map_err(|e| Error::Invalid(format!("{field}: {e}")))
}

fn width_valid(width: u8) -> bool {
    matches!(width, 1 | 2 | 4 | 8)
}

fn range_fits(offset: u32, width: u8, len: u32) -> bool {
    offset
        .checked_add(u32::from(width))
        .is_some_and(|end| end <= len)
}

fn validate_sandisk_u3_command_scope(name: &str, cdb: &[u8]) -> Result<()> {
    if cdb.len() < 3 || cdb[0] != 0xff {
        return Ok(());
    }
    let command = (cdb[1], cdb[2]);
    let known_u3 = matches!(
        command,
        (0x00, 0x00)
            | (0x01, 0x01)
            | (0x03, 0x01)
            | (0x20..=0x25, 0x00)
            | (0x40..=0x42, 0x00)
            | (0xa0, 0x00)
            | (0xa2..=0xa4, 0x00)
            | (0xa6..=0xa7, 0x00)
    );
    if !known_u3 {
        return Ok(());
    }
    let allowed_identity =
        name == "read-controller-id" && matches!(command, (0x00, 0x00) | (0x03, 0x01));
    let allowed_reset = name == "reset-controller" && command == (0x01, 0x01);
    if allowed_identity || allowed_reset {
        return Ok(());
    }
    Err(Error::Invalid(format!(
        "command {name} assigns known SanDisk U3 logical-domain CDB ff {:02x} {:02x} to a raw NAND/metadata role",
        command.0, command.1
    )))
}

fn validate_artifact_payload(name: &str, command: &CommandSpec, profile: &Profile) -> Result<()> {
    let Some(PayloadSource::Artifact {
        artifact_id,
        offset,
        length,
    }) = command.payload.as_ref()
    else {
        return Ok(());
    };
    let artifact = profile
        .artifacts
        .iter()
        .find(|artifact| artifact.id == *artifact_id)
        .ok_or_else(|| {
            Error::Invalid(format!(
                "command {name} references undeclared artifact {artifact_id}"
            ))
        })?;
    if artifact.kind != crate::artifact::ArtifactKind::ServiceLoader {
        return Err(Error::Invalid(format!(
            "command {name} artifact {artifact_id} is not a service loader"
        )));
    }
    if profile
        .implementation
        .as_ref()
        .is_none_or(|implementation| {
            !implementation
                .artifact_ids
                .iter()
                .any(|id| id == artifact_id)
        })
    {
        return Err(Error::Invalid(format!(
            "command {name} artifact {artifact_id} is not a runtime artifact"
        )));
    }
    let payload_bytes = if *length == 0 {
        artifact.size_bytes.checked_sub(*offset)
    } else {
        offset
            .checked_add(*length)
            .filter(|end| *end <= artifact.size_bytes)
            .map(|_| *length)
    }
    .ok_or_else(|| {
        Error::Invalid(format!(
            "command {name} artifact {artifact_id} slice is out of range"
        ))
    })?;
    if payload_bytes != u64::from(command.transfer_bytes) {
        return Err(Error::Invalid(format!(
            "command {name} artifact payload has {payload_bytes} bytes but transfer_bytes is {}",
            command.transfer_bytes
        )));
    }
    Ok(())
}

fn validate_context_payload(name: &str, command: &CommandSpec) -> Result<()> {
    let Some(PayloadSource::Context {
        record_bytes,
        repeat,
        constants,
        fields,
        ..
    }) = command.payload.as_ref()
    else {
        return Ok(());
    };
    let payload_bytes = record_bytes
        .checked_mul(*repeat)
        .ok_or_else(|| Error::Invalid(format!("command {name} context payload size overflow")))?;
    if command.direction != TransferDirection::ToDevice
        || *record_bytes == 0
        || *repeat == 0
        || payload_bytes != command.transfer_bytes
        || fields
            .len()
            .checked_add(constants.len())
            .is_none_or(|count| count > MAX_CONTEXT_PAYLOAD_FIELDS)
    {
        return Err(Error::Invalid(format!(
            "command {name} has an invalid context-generated payload"
        )));
    }
    let mut occupied = BTreeSet::new();
    for constant in constants {
        if !(1..=8).contains(&constant.width)
            || constant
                .offset
                .checked_add(u32::from(constant.width))
                .is_none_or(|end| end > *record_bytes)
            || (constant.width < 8 && constant.value >= (1u64 << (u32::from(constant.width) * 8)))
        {
            return Err(Error::Invalid(format!(
                "command {name} has an invalid context payload constant"
            )));
        }
        for byte in constant.offset..constant.offset + u32::from(constant.width) {
            if !occupied.insert(byte) {
                return Err(Error::Invalid(format!(
                    "command {name} has overlapping context payload constants"
                )));
            }
        }
    }
    for field in fields {
        if !(1..=8).contains(&field.width)
            || field
                .offset
                .checked_add(u32::from(field.width))
                .is_none_or(|end| end > *record_bytes)
            || !value_operations_valid(&field.operations)
        {
            return Err(Error::Invalid(format!(
                "command {name} has an invalid context payload field"
            )));
        }
        for byte in field.offset..field.offset + u32::from(field.width) {
            if !occupied.insert(byte) {
                return Err(Error::Invalid(format!(
                    "command {name} has overlapping context payload fields"
                )));
            }
        }
    }
    Ok(())
}

fn validate_alcor_service_upload_contract(
    command_name: &str,
    command: &CommandSpec,
    transport: &str,
    enter_reenumerates: bool,
    loader_reenumerates: bool,
    artifact_id: &str,
    artifact_size: u64,
) -> Result<()> {
    let cdb = hex_bytes(&command.cdb_hex, &format!("command {command_name} cdb_hex"))?;
    let field = command.fields.first();
    let exact_field = field.is_some_and(|field| {
        field.offset == 3
            && field.width == 1
            && field.endian == Endian::Big
            && field.value == RuntimeValue::PayloadBytes
            && field.operations
                == [
                    ValueOperation::Divide { value: 512 },
                    ValueOperation::Subtract { value: 1 },
                ]
    });
    let exact_payload = matches!(
        command.payload.as_ref(),
        Some(PayloadSource::Artifact {
            artifact_id: id,
            offset: 0,
            length: 0,
        }) if id == artifact_id
    );
    let total_sectors = artifact_size.checked_div(crate::alcor_au698x::SECTOR_BYTES as u64);
    let exact_artifact_size = artifact_size >= (crate::alcor_au698x::SECTOR_BYTES * 2) as u64
        && artifact_size
            <= ((crate::alcor_au698x::MAX_MODULE_SECTORS + 1) * crate::alcor_au698x::SECTOR_BYTES)
                as u64
        && artifact_size.is_multiple_of(crate::alcor_au698x::SECTOR_BYTES as u64)
        && total_sectors.is_some_and(|sectors| (2..=256).contains(&sectors));
    if transport != TRANSPORT_USB_BOT
        || enter_reenumerates
        || loader_reenumerates
        || cdb != [0xfa, 0x0a, 0, 0, 0, 0, 0, 0]
        || command.direction != TransferDirection::ToDevice
        || command.timeout_ms != 60_000
        || command.fields.len() != 1
        || !exact_field
        || !exact_payload
        || !exact_artifact_size
        || u64::from(command.transfer_bytes) != artifact_size
    {
        return Err(Error::Invalid(
            format!("Alcor AU698x service upload command {command_name} must exactly reproduce FA 0A 00 N over USB BOT with the complete authenticated module-plus-parameter artifact"),
        ));
    }

    let derived = build_cdb(
        command,
        CommandContext {
            payload_bytes: artifact_size,
            ..CommandContext::default()
        },
    )?;
    let module_sectors = u8::try_from(total_sectors.unwrap() - 1)
        .map_err(|_| Error::Invalid("Alcor service module sector count overflow".into()))?;
    if derived != [0xfa, 0x0a, 0, module_sectors, 0, 0, 0, 0] {
        return Err(Error::Invalid(
            format!("Alcor AU698x service upload command {command_name} derives the wrong module-sector CDB"),
        ));
    }
    Ok(())
}

fn validate_operation_sequences(
    recipe: &ControllerRecipe,
    profile: &Profile,
    family: Family,
) -> Result<()> {
    let referenced_commands = recipe
        .operation_sequences
        .values()
        .flat_map(|sequence| sequence.steps.iter().map(|step| step.command.as_str()))
        .collect::<BTreeSet<_>>();
    for name in recipe
        .commands
        .keys()
        .filter(|name| name.starts_with("step-"))
    {
        if !referenced_commands.contains(name.as_str()) {
            return Err(Error::Invalid(format!(
                "controller recipe sequence command {name} is not referenced"
            )));
        }
    }

    for (operation, sequence) in &recipe.operation_sequences {
        if !recipe.commands.contains_key(operation)
            || !(2..=MAX_OPERATION_SEQUENCE_STEPS).contains(&sequence.steps.len())
        {
            return Err(Error::Invalid(format!(
                "operation {operation} has an invalid command sequence"
            )));
        }
        let mut command_names = BTreeSet::new();
        let mut target_count = 0usize;
        let mut output_bytes = 0u64;
        let mut output_fields = BTreeSet::new();
        for step in &sequence.steps {
            if step.command.is_empty() || !command_names.insert(step.command.as_str()) {
                return Err(Error::Invalid(format!(
                    "operation {operation} has an empty or duplicate sequence command"
                )));
            }
            if step.command == *operation {
                target_count += 1;
            }
            let command = recipe.commands.get(&step.command).ok_or_else(|| {
                Error::Invalid(format!(
                    "operation {operation} references absent command {}",
                    step.command
                ))
            })?;
            if (step.capture.captures_payload() || step.capture.captures_fields())
                && command.direction != TransferDirection::FromDevice
            {
                return Err(Error::Invalid(format!(
                    "operation {operation} captures output from non-read command {}",
                    step.command
                )));
            }
            if step.capture.captures_payload() {
                if command.response.payload_bytes == 0 {
                    return Err(Error::Invalid(format!(
                        "operation {operation} captures a variable payload from command {}",
                        step.command
                    )));
                }
                output_bytes = output_bytes
                    .checked_add(u64::from(command.response.payload_bytes))
                    .ok_or_else(|| {
                        Error::Invalid(format!(
                            "operation {operation} payload aggregation overflows"
                        ))
                    })?;
            }
            if step.capture.captures_fields() {
                for field in &command.response.fields {
                    if !output_fields.insert(field.name.as_str()) {
                        return Err(Error::Invalid(format!(
                            "operation {operation} captures duplicate response field {}",
                            field.name
                        )));
                    }
                }
            }

            let Some(PayloadSource::Artifact {
                artifact_id,
                offset: 0,
                length: 0,
            }) = command.payload.as_ref()
            else {
                continue;
            };
            let artifact = profile
                .artifacts
                .iter()
                .find(|artifact| artifact.id == *artifact_id)
                .ok_or_else(|| {
                    Error::Invalid(format!(
                        "operation {operation} artifact {artifact_id} is absent"
                    ))
                })?;
            if artifact.format == crate::artifact::ArtifactFormat::AlcorAu698xServicePayload {
                if family != Family::AlcorUfd
                    || artifact.kind != crate::artifact::ArtifactKind::ServiceLoader
                {
                    return Err(Error::Invalid(format!(
                        "operation {operation} uses an Alcor service payload outside an Alcor service-loader step"
                    )));
                }
                validate_alcor_service_upload_contract(
                    &step.command,
                    command,
                    &recipe.transport,
                    false,
                    false,
                    artifact_id,
                    artifact.size_bytes,
                )?;
            }
        }
        if target_count != 1 || output_bytes > u64::from(MAX_COMMAND_TRANSFER) {
            return Err(Error::Invalid(format!(
                "operation {operation} must contain its target once and stay within the aggregate transfer bound"
            )));
        }
    }
    Ok(())
}

pub fn validate(recipe: &ControllerRecipe, profile: &Profile) -> Result<()> {
    if recipe.schema != RECIPE_SCHEMA {
        return Err(Error::Invalid(format!(
            "controller recipe schema {} != {RECIPE_SCHEMA}",
            recipe.schema
        )));
    }
    let firmware = profile.firmware.min.as_deref();
    let nand = profile.nand_id.min.as_deref();
    if recipe.controller_id != profile.controller_id
        || Some(recipe.firmware.as_str()) != firmware
        || profile.firmware.max.as_deref() != firmware
        || Some(recipe.nand_id.as_str()) != nand
        || profile.nand_id.max.as_deref() != nand
    {
        return Err(Error::Permission(
            "controller recipe hardware tuple does not exactly match the profile".into(),
        ));
    }
    let family = family_from_recipe_str(&recipe.family).ok_or_else(|| {
        Error::Invalid(format!(
            "controller recipe family {} has no bounded recipe adapter",
            recipe.family
        ))
    })?;
    if recipe.family != family.recipe_str()
        || !matches!(
            recipe.transport.as_str(),
            TRANSPORT_SCSI_COMMAND | TRANSPORT_USB_BOT
        )
    {
        return Err(Error::Invalid(
            "controller recipe family or transport is unsupported".into(),
        ));
    }
    let required = [
        "read-nand-id",
        "read-bbt",
        "read-page",
        "erase-block",
        "read-status",
        "program-page",
        "prepare-bbt",
        "prepare-ftl",
        "set-capacity",
        "activate-metadata",
        "read-commit-state",
        "enter-service-mode",
        "exit-service-mode",
        "reset-controller",
    ];
    for name in required {
        if !recipe.commands.contains_key(name) {
            return Err(Error::Invalid(format!(
                "controller recipe is missing required command {name}"
            )));
        }
    }
    let bootstrap_identified = profile.controller_bootstrap.is_some();
    if bootstrap_identified {
        if profile
            .controller_bootstrap
            .as_ref()
            .is_none_or(|bootstrap| bootstrap.family != recipe.family)
            || !recipe.commands.contains_key("read-controller-id")
            || recipe.controller_identity_hex.is_none()
        {
            return Err(Error::Invalid(
                "bootstrap recipe requires the same family, controller_identity_hex and read-controller-id command"
                    .into(),
            ));
        }
    } else if recipe.controller_identity_hex.is_some()
        || recipe.commands.contains_key("read-controller-id")
    {
        return Err(Error::Invalid(
            "controller recipe identity fields require an exact profile bootstrap".into(),
        ));
    }
    if !support(family).identify && !bootstrap_identified {
        return Err(Error::Invalid(
            format!(
                "{} recipe requires an exact profile bootstrap because no fixed signed probe is available",
                family.as_str()
            ),
        ));
    }
    for (name, command) in &recipe.commands {
        let cdb = hex_bytes(&command.cdb_hex, &format!("command {name} cdb_hex"))?;
        if !transport_supports_cdb(&recipe.transport, cdb.len())
            || command.transfer_bytes > MAX_COMMAND_TRANSFER
            || !(100..=3_600_000).contains(&command.timeout_ms)
        {
            return Err(Error::Invalid(format!(
                "command {name} has an unsafe CDB, transfer size or timeout"
            )));
        }
        if family == Family::SandiskCruzer {
            validate_sandisk_u3_command_scope(name, &cdb)?;
        }
        match command.direction {
            TransferDirection::None
                if command.transfer_bytes != 0
                    || command.payload.is_some()
                    || command.response.min_bytes != 0
                    || command.response.max_bytes != 0 =>
            {
                return Err(Error::Invalid(format!(
                    "command {name} has data attached to a no-data transfer"
                )));
            }
            TransferDirection::FromDevice
                if command.transfer_bytes == 0
                    || command.payload.is_some()
                    || command.response.max_bytes > command.transfer_bytes =>
            {
                return Err(Error::Invalid(format!(
                    "command {name} has an invalid device-to-host transfer contract"
                )));
            }
            TransferDirection::ToDevice
                if command.transfer_bytes == 0
                    || command.payload.is_none()
                    || command.response.min_bytes != 0
                    || command.response.max_bytes != 0 =>
            {
                return Err(Error::Invalid(format!(
                    "command {name} has an invalid host-to-device transfer contract"
                )));
            }
            _ => {}
        }
        validate_artifact_payload(name, command, profile)?;
        validate_context_payload(name, command)?;
        let mut occupied = BTreeSet::new();
        for field in &command.fields {
            if field.offset == 0
                || !width_valid(field.width)
                || usize::from(field.offset) + usize::from(field.width) > cdb.len()
                || !value_operations_valid(&field.operations)
            {
                return Err(Error::Invalid(format!(
                    "command {name} has an out-of-range field binding or a variable opcode"
                )));
            }
            for byte in field.offset..field.offset + field.width {
                if !occupied.insert(byte) {
                    return Err(Error::Invalid(format!(
                        "command {name} has overlapping field bindings"
                    )));
                }
            }
        }
        validate_response(name, &command.response)?;
    }
    validate_operation_sequences(recipe, profile, family)?;
    require_command_contract(
        &recipe.commands,
        "read-nand-id",
        TransferDirection::FromDevice,
        None,
    )?;
    if bootstrap_identified {
        require_command_contract(
            &recipe.commands,
            "read-controller-id",
            TransferDirection::FromDevice,
            None,
        )?;
    }
    require_command_contract(
        &recipe.commands,
        "read-bbt",
        TransferDirection::FromDevice,
        None,
    )?;
    require_command_contract(
        &recipe.commands,
        "read-page",
        TransferDirection::FromDevice,
        None,
    )?;
    require_command_contract(
        &recipe.commands,
        "program-page",
        TransferDirection::ToDevice,
        Some("caller"),
    )?;
    require_erase_command_contract(&recipe.commands)?;
    require_command_contract(
        &recipe.commands,
        "prepare-bbt",
        TransferDirection::ToDevice,
        Some("bbt"),
    )?;
    require_command_contract(
        &recipe.commands,
        "prepare-ftl",
        TransferDirection::ToDevice,
        Some("ftl"),
    )?;
    require_command_contract(
        &recipe.commands,
        "set-capacity",
        TransferDirection::ToDevice,
        Some("capacity"),
    )?;
    require_response_fields(recipe, "read-status", &["busy", "failed", "service_mode"])?;
    for name in ["read-page", "program-page", "erase-block"] {
        require_physical_address_binding(recipe, name)?;
    }
    for name in ["read-page", "program-page"] {
        require_runtime_binding(recipe, name, RuntimeValue::Page)?;
    }
    require_runtime_binding(recipe, "activate-metadata", RuntimeValue::Generation)?;
    require_response_fields(
        recipe,
        "read-commit-state",
        &["busy", "failed", "generation", "committed"],
    )?;
    require_response_fields(
        recipe,
        "read-page",
        &[
            "ecc_known",
            "uncorrectable",
            "corrected_bits",
            "read_retries",
            "read_latency_ms",
        ],
    )?;
    for name in ["read-bbt", "read-status", "read-commit-state"] {
        if !resolve_operation_steps(recipe, name)?.iter().any(|step| {
            (step.capture.captures_payload() || step.capture.captures_fields())
                && !step.command.response.prefix_hex.is_empty()
        }) {
            return Err(Error::Invalid(format!(
                "operation {name} requires a non-empty response signature"
            )));
        }
    }
    if bootstrap_identified {
        let expected = exact_controller_identity_bytes(recipe)?;
        let read_controller = &recipe.commands["read-controller-id"];
        if read_controller.response.prefix_hex.is_empty()
            || read_controller.response.payload_bytes as usize != expected.len()
        {
            return Err(Error::Invalid(format!(
                "read-controller-id requires a signed payload of exactly {} bytes",
                expected.len()
            )));
        }
    }
    validate_bbt_layout(&recipe.bbt)?;
    let bbt_payload_bytes = operation_payload_bytes(recipe, "read-bbt")?;
    let bbt_end = u64::from(recipe.bbt.entries_offset)
        .checked_add(
            u64::from(recipe.bbt.maximum_entries)
                .checked_mul(u64::from(recipe.bbt.entry_stride))
                .ok_or_else(|| Error::Invalid("BBT response size overflow".into()))?,
        )
        .ok_or_else(|| Error::Invalid("BBT response size overflow".into()))?;
    if !range_fits(
        recipe.bbt.count_offset,
        recipe.bbt.count_width,
        bbt_payload_bytes,
    ) || bbt_end > u64::from(bbt_payload_bytes)
    {
        return Err(Error::Invalid(
            "old BBT layout exceeds the read-bbt response bounds".into(),
        ));
    }
    validate_metadata_layouts(
        &recipe.bbt_output,
        &recipe.ftl_output,
        &recipe.capacity_output,
    )?;
    if recipe.policy.erase_retries > 3
        || !(1..=4096).contains(&recipe.policy.block_batch_size)
        || !(10..=5000).contains(&recipe.policy.status_poll_ms)
        || !(1000..=86_400_000).contains(&recipe.policy.operation_timeout_ms)
        || recipe.policy.status_poll_ms >= recipe.policy.operation_timeout_ms
        || recipe.policy.erased_byte != 0xff
        || recipe.policy.old_rbb_reuse
        || recipe.policy.qualification_pages.is_empty()
        || recipe.policy.qualification_patterns.is_empty()
    {
        return Err(Error::Invalid(
            "controller recipe has an unsafe retry, batch, RBB reuse or qualification policy"
                .into(),
        ));
    }
    if recipe.policy.loader_reenumerates && !recipe.policy.enter_reenumerates {
        return Err(Error::Invalid(
            "loader re-enumeration requires entry re-enumeration".into(),
        ));
    }
    match &recipe.policy.service_loader_artifact_id {
        Some(id) => {
            let artifact = profile
                .artifacts
                .iter()
                .find(|artifact| artifact.id == *id)
                .ok_or_else(|| {
                    Error::Invalid(format!(
                        "service loader artifact {id} is absent from the profile"
                    ))
                })?;
            let valid_loader = artifact.kind == crate::artifact::ArtifactKind::ServiceLoader
                && match recipe.family.as_str() {
                    "phison-ufd" => {
                        recipe.policy.enter_reenumerates
                            && matches!(
                                artifact.format,
                                crate::artifact::ArtifactFormat::PhisonBtPram
                                    | crate::artifact::ArtifactFormat::PhisonBtPramExtended
                            )
                    }
                    "alcor-ufd" => {
                        !recipe.policy.loader_reenumerates
                            && artifact.format
                                == crate::artifact::ArtifactFormat::AlcorAu698xServicePayload
                            && recipe.commands["enter-service-mode"]
                                .payload
                                .as_ref()
                                .is_some_and(|payload| {
                                    matches!(
                                        payload,
                                        PayloadSource::Artifact {
                                            artifact_id,
                                            offset: 0,
                                            length: 0
                                        } if artifact_id == id
                                    )
                                })
                    }
                    _ => false,
                };
            if !valid_loader {
                return Err(Error::Invalid(
                    "service loader format, family or service-entry contract is invalid".into(),
                ));
            }
            if recipe.family == "alcor-ufd" {
                validate_alcor_service_upload_contract(
                    "enter-service-mode",
                    &recipe.commands["enter-service-mode"],
                    &recipe.transport,
                    recipe.policy.enter_reenumerates,
                    recipe.policy.loader_reenumerates,
                    id,
                    artifact.size_bytes,
                )?;
            }
        }
        None if recipe.policy.loader_reenumerates => {
            return Err(Error::Invalid(
                "loader re-enumeration requires service_loader_artifact_id".into(),
            ));
        }
        None => {}
    }
    let geometry = profile
        .geometry
        .as_ref()
        .ok_or_else(|| Error::Invalid("recipe requires NAND geometry".into()))?;
    let total = total_blocks(geometry)?;
    if total > MAX_PHYSICAL_BLOCKS {
        return Err(Error::Invalid(format!(
            "controller recipe geometry has {total} blocks, exceeding the durable evidence bound {MAX_PHYSICAL_BLOCKS}"
        )));
    }
    for (name, command) in &recipe.commands {
        for field in &command.fields {
            let maximum = match field.value {
                RuntimeValue::Channel => u64::from(geometry.channels.saturating_sub(1)),
                RuntimeValue::Chip => u64::from(geometry.chips_per_channel.saturating_sub(1)),
                RuntimeValue::Lun => u64::from(geometry.luns_per_chip.saturating_sub(1)),
                RuntimeValue::Plane => u64::from(geometry.planes_per_lun.saturating_sub(1)),
                RuntimeValue::Block => u64::from(geometry.blocks_per_lun.saturating_sub(1)),
                RuntimeValue::Page => u64::from(geometry.pages_per_block.saturating_sub(1)),
                RuntimeValue::FlatBlock => total.saturating_sub(1),
                RuntimeValue::PayloadBytes => u64::from(command.transfer_bytes),
                RuntimeValue::UserBlocks | RuntimeValue::SpareBlocks => total,
                RuntimeValue::Generation => continue,
            };
            for input in 0..=maximum {
                let encoded =
                    apply_value_operations(input, &field.operations).map_err(|error| {
                        Error::Invalid(format!(
                        "command {name} field {:?} cannot transform runtime value {input}: {error}",
                        field.value
                    ))
                    })?;
                if !integer_fits(field.width, encoded) {
                    return Err(Error::Invalid(format!(
                        "command {name} field {:?} cannot represent transformed runtime value {encoded}",
                        field.value
                    )));
                }
            }
        }
        if matches!(
            command.payload.as_ref(),
            Some(PayloadSource::Context { .. })
        ) {
            if let Some(PayloadSource::Context { fields, .. }) = command.payload.as_ref() {
                for field in fields {
                    let maximum = match field.value {
                        RuntimeValue::Channel => u64::from(geometry.channels.saturating_sub(1)),
                        RuntimeValue::Chip => {
                            u64::from(geometry.chips_per_channel.saturating_sub(1))
                        }
                        RuntimeValue::Lun => u64::from(geometry.luns_per_chip.saturating_sub(1)),
                        RuntimeValue::Plane => u64::from(geometry.planes_per_lun.saturating_sub(1)),
                        RuntimeValue::Block => u64::from(geometry.blocks_per_lun.saturating_sub(1)),
                        RuntimeValue::Page => u64::from(geometry.pages_per_block.saturating_sub(1)),
                        RuntimeValue::FlatBlock => total.saturating_sub(1),
                        RuntimeValue::PayloadBytes => u64::from(command.transfer_bytes),
                        RuntimeValue::UserBlocks | RuntimeValue::SpareBlocks => total,
                        RuntimeValue::Generation => continue,
                    };
                    for input in 0..=maximum {
                        let encoded = apply_value_operations(input, &field.operations).map_err(
                            |error| {
                                Error::Invalid(format!(
                                    "command {name} context field {:?} cannot transform runtime value {input}: {error}",
                                    field.value
                                ))
                            },
                        )?;
                        if !integer_fits(field.width, encoded) {
                            return Err(Error::Invalid(format!(
                                "command {name} context field {:?} cannot represent transformed runtime value {encoded}",
                                field.value
                            )));
                        }
                    }
                }
            }
            for flat in 0..total {
                build_context_payload(command, coordinate(flat, geometry)?).map_err(|error| {
                    Error::Invalid(format!(
                        "command {name} cannot encode physical block {flat}: {error}"
                    ))
                })?;
            }
        }
    }
    if u64::from(recipe.bbt.maximum_entries) < total {
        return Err(Error::Invalid(
            "old BBT response cannot represent every physical block".into(),
        ));
    }
    let page_transfer = geometry
        .page_bytes
        .checked_add(geometry.oob_bytes)
        .ok_or_else(|| Error::Invalid("page plus OOB transfer size overflow".into()))?;
    let program_transfer = recipe.commands["program-page"].transfer_bytes;
    if operation_payload_bytes(recipe, "read-page")? != page_transfer
        || !matches!(program_transfer, value if value == geometry.page_bytes || value == page_transfer)
    {
        return Err(Error::Invalid(format!(
            "read-page must expose page + OOB ({page_transfer}) and program-page must accept page data or page + OOB"
        )));
    }
    let expected_nand = exact_nand_id_bytes(&recipe.nand_id)?;
    let read_nand_bytes = operation_payload_bytes(recipe, "read-nand-id")?;
    if read_nand_bytes as usize != expected_nand.len() {
        return Err(Error::Invalid(format!(
            "read-nand-id payload length {} does not match exact NAND id length {}",
            read_nand_bytes,
            expected_nand.len()
        )));
    }
    let worst_bbt =
        u64::try_from(hex_bytes(&recipe.bbt_output.header_hex, "BBT output header")?.len())
            .unwrap_or(u64::MAX)
            .checked_add(
                total
                    .checked_mul(u64::from(recipe.bbt_output.entry_stride))
                    .ok_or_else(|| Error::Invalid("BBT maximum length overflow".into()))?,
            )
            .ok_or_else(|| Error::Invalid("BBT maximum length overflow".into()))?;
    if worst_bbt > u64::from(recipe.bbt_output.maximum_bytes)
        || recipe.commands["prepare-bbt"].transfer_bytes != recipe.bbt_output.maximum_bytes
        || recipe.commands["prepare-ftl"].transfer_bytes != recipe.ftl_output.total_bytes
        || recipe.commands["set-capacity"].transfer_bytes != recipe.capacity_output.total_bytes
    {
        return Err(Error::Invalid(
            "generated BBT, FTL or capacity payload does not match its fixed command transfer"
                .into(),
        ));
    }
    if recipe
        .policy
        .qualification_pages
        .iter()
        .any(|page| *page >= geometry.pages_per_block)
    {
        return Err(Error::Invalid(
            "qualification page is outside NAND geometry".into(),
        ));
    }
    for pattern in &recipe.policy.qualification_patterns {
        if !matches!(
            pattern.as_str(),
            "zero" | "one" | "checkerboard" | "inverse-checkerboard" | "prbs"
        ) {
            return Err(Error::Invalid(format!(
                "unsupported qualification pattern {pattern}"
            )));
        }
    }
    if recipe
        .commands
        .values()
        .any(|command| command.timeout_ms > recipe.policy.operation_timeout_ms)
    {
        return Err(Error::Invalid(
            "a command timeout exceeds the operation timeout".into(),
        ));
    }
    Ok(())
}

pub fn exact_nand_id_bytes(value: &str) -> Result<Vec<u8>> {
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex_bytes(value, "controller recipe nand_id")?;
    if bytes.is_empty()
        || bytes.len() > 32
        || bytes.iter().all(|byte| *byte == 0)
        || bytes.iter().all(|byte| *byte == 0xff)
    {
        return Err(Error::Invalid(
            "controller recipe nand_id must be 1..=32 non-empty identity bytes".into(),
        ));
    }
    Ok(bytes)
}

pub fn exact_controller_identity_bytes(recipe: &ControllerRecipe) -> Result<Vec<u8>> {
    exact_controller_identity_value(recipe.controller_identity_hex.as_deref())
}

fn exact_controller_identity_value(value: Option<&str>) -> Result<Vec<u8>> {
    let value = value.ok_or_else(|| {
        Error::Invalid("controller recipe controller_identity_hex is absent".into())
    })?;
    let value = value.strip_prefix("0x").unwrap_or(value);
    let bytes = hex_bytes(value, "controller recipe controller_identity_hex")?;
    if bytes.is_empty()
        || bytes.len() > 4096
        || bytes.iter().all(|byte| *byte == 0)
        || bytes.iter().all(|byte| *byte == 0xff)
    {
        return Err(Error::Invalid(
            "controller recipe controller_identity_hex must be 1..=4096 non-empty identity bytes"
                .into(),
        ));
    }
    Ok(bytes)
}

fn require_runtime_binding(
    recipe: &ControllerRecipe,
    operation: &str,
    value: RuntimeValue,
) -> Result<()> {
    if operation_runtime_bindings(recipe, operation)?.contains(&value) {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "operation {operation} has no {value:?} field binding"
        )))
    }
}

fn require_physical_address_binding(recipe: &ControllerRecipe, operation: &str) -> Result<()> {
    let values = operation_runtime_bindings(recipe, operation)?;
    let flat = values.contains(&RuntimeValue::FlatBlock);
    let coordinates = [
        RuntimeValue::Channel,
        RuntimeValue::Chip,
        RuntimeValue::Lun,
        RuntimeValue::Block,
    ]
    .into_iter()
    .all(|value| values.contains(&value));
    if flat ^ coordinates {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "operation {operation} must bind exactly one flat-block or complete channel/chip/lun/block address"
        )))
    }
}

fn operation_runtime_bindings(
    recipe: &ControllerRecipe,
    operation: &str,
) -> Result<BTreeSet<RuntimeValue>> {
    let mut values = BTreeSet::new();
    for step in resolve_operation_steps(recipe, operation)? {
        values.extend(runtime_bindings(step.command));
    }
    Ok(values)
}

fn runtime_bindings(command: &CommandSpec) -> BTreeSet<RuntimeValue> {
    let mut values = command
        .fields
        .iter()
        .map(|field| field.value)
        .collect::<BTreeSet<_>>();
    if let Some(PayloadSource::Context { fields, .. }) = command.payload.as_ref() {
        values.extend(fields.iter().map(|field| field.value));
    }
    values
}

fn require_response_fields(
    recipe: &ControllerRecipe,
    operation: &str,
    required: &[&str],
) -> Result<()> {
    let fields = resolve_operation_steps(recipe, operation)?
        .into_iter()
        .filter(|step| step.capture.captures_fields())
        .flat_map(|step| {
            step.command
                .response
                .fields
                .iter()
                .map(|field| field.name.as_str())
        })
        .collect::<BTreeSet<_>>();
    for name in required {
        if !fields.contains(name) {
            return Err(Error::Invalid(format!(
                "operation {operation} response is missing required field {name}"
            )));
        }
    }
    Ok(())
}

fn operation_payload_bytes(recipe: &ControllerRecipe, operation: &str) -> Result<u32> {
    let total = resolve_operation_steps(recipe, operation)?
        .into_iter()
        .filter(|step| step.capture.captures_payload())
        .try_fold(0u64, |total, step| {
            if step.command.response.payload_bytes == 0 {
                return Err(Error::Invalid(format!(
                    "operation {operation} has a variable captured payload"
                )));
            }
            total
                .checked_add(u64::from(step.command.response.payload_bytes))
                .ok_or_else(|| {
                    Error::Invalid(format!("operation {operation} payload size overflow"))
                })
        })?;
    u32::try_from(total)
        .map_err(|_| Error::Invalid(format!("operation {operation} payload exceeds u32")))
}

fn integer_fits(width: u8, value: u64) -> bool {
    width == 8 || value < (1u64 << (u32::from(width) * 8))
}

fn require_command_contract(
    commands: &BTreeMap<String, CommandSpec>,
    name: &str,
    direction: TransferDirection,
    payload: Option<&str>,
) -> Result<()> {
    let command = commands
        .get(name)
        .ok_or_else(|| Error::Invalid(format!("command {name} is absent")))?;
    let payload_matches = matches!(
        (payload, command.payload.as_ref()),
        (None, None)
            | (Some("caller"), Some(PayloadSource::Caller))
            | (Some("bbt"), Some(PayloadSource::Bbt))
            | (Some("ftl"), Some(PayloadSource::Ftl))
            | (Some("capacity"), Some(PayloadSource::Capacity))
    );
    if command.direction != direction || !payload_matches {
        return Err(Error::Invalid(format!(
            "command {name} has the wrong direction or payload source"
        )));
    }
    Ok(())
}

fn require_erase_command_contract(commands: &BTreeMap<String, CommandSpec>) -> Result<()> {
    let command = &commands["erase-block"];
    if matches!(
        (command.direction, command.payload.as_ref()),
        (TransferDirection::None, None)
            | (
                TransferDirection::ToDevice,
                Some(PayloadSource::Context { .. })
            )
    ) {
        Ok(())
    } else {
        Err(Error::Invalid(
            "command erase-block must use either a no-data CDB or a context-generated payload"
                .into(),
        ))
    }
}

fn validate_response(name: &str, response: &ResponseRule) -> Result<()> {
    if response.min_bytes > response.max_bytes || response.max_bytes > MAX_COMMAND_TRANSFER {
        return Err(Error::Invalid(format!(
            "command {name} has invalid response bounds"
        )));
    }
    let prefix = hex_bytes(
        &response.prefix_hex,
        &format!("command {name} response prefix"),
    )?;
    if prefix.len() > response.min_bytes as usize {
        return Err(Error::Invalid(format!(
            "command {name} response prefix exceeds min_bytes"
        )));
    }
    if (response.payload_bytes == 0 && response.payload_offset != 0)
        || (response.payload_bytes != 0
            && response
                .payload_offset
                .checked_add(response.payload_bytes)
                .is_none_or(|end| end > response.min_bytes))
    {
        return Err(Error::Invalid(format!(
            "command {name} has an invalid response payload window"
        )));
    }
    let mut names = BTreeSet::new();
    let mut occupied = BTreeSet::new();
    for field in &response.fields {
        let maximum = if field.width == 8 {
            u64::MAX
        } else {
            (1u64 << (u32::from(field.width) * 8)) - 1
        };
        if field.name.is_empty()
            || !names.insert(field.name.as_str())
            || !width_valid(field.width)
            || !range_fits(field.offset, field.width, response.min_bytes)
            || field.mask & !maximum != 0
            || field.equals.is_some_and(|value| {
                value > maximum || (field.mask != 0 && value & !field.mask != 0)
            })
        {
            return Err(Error::Invalid(format!(
                "command {name} has an invalid response field"
            )));
        }
        for byte in field.offset..field.offset + u32::from(field.width) {
            if !occupied.insert(byte) {
                return Err(Error::Invalid(format!(
                    "command {name} has overlapping response fields"
                )));
            }
        }
    }
    Ok(())
}

/// Validate a fixed, device-to-host identity command for use before a full
/// destructive recipe exists. Variable CDB fields, payload writes, partial
/// transfers and unsigned responses are intentionally forbidden.
pub fn validate_identity_command(name: &str, command: &CommandSpec) -> Result<()> {
    let cdb = hex_bytes(&command.cdb_hex, &format!("command {name} cdb_hex"))?;
    if !(6..=MAX_CDB_BYTES).contains(&cdb.len())
        || !command.fields.is_empty()
        || command.direction != TransferDirection::FromDevice
        || command.payload.is_some()
        || !(1..=64 * 1024).contains(&command.transfer_bytes)
        || !(100..=60_000).contains(&command.timeout_ms)
    {
        return Err(Error::Invalid(format!(
            "identity command {name} must be a fixed bounded device-to-host CDB"
        )));
    }
    if command.response.min_bytes != command.transfer_bytes
        || command.response.max_bytes != command.transfer_bytes
        || command.response.prefix_hex.is_empty()
        || command.response.payload_bytes == 0
    {
        return Err(Error::Invalid(format!(
            "identity command {name} requires one exact transfer length, a response signature and a payload window"
        )));
    }
    validate_response(name, &command.response)
}

fn validate_bbt_layout(layout: &BbtLayout) -> Result<()> {
    if !(1..=16).contains(&layout.copies)
        || !width_valid(layout.count_width)
        || layout.entry_stride == 0
        || layout.maximum_entries == 0
        || !address_layout_valid(&layout.address, layout.entry_stride)
        || layout.state_offset >= layout.entry_stride
        || !address_disjoint_from_state(&layout.address, layout.state_offset)
    {
        return Err(Error::Invalid("invalid old BBT response layout".into()));
    }
    if layout.factory_bad_values.is_empty()
        || layout.runtime_bad_values.is_empty()
        || layout.system_values.is_empty()
        || layout
            .factory_bad_values
            .iter()
            .any(|v| layout.runtime_bad_values.contains(v))
        || layout
            .factory_bad_values
            .iter()
            .any(|v| layout.system_values.contains(v))
        || layout
            .runtime_bad_values
            .iter()
            .any(|v| layout.system_values.contains(v))
    {
        return Err(Error::Invalid(
            "BBT FBB and RBB state values must be non-empty and disjoint".into(),
        ));
    }
    Ok(())
}

fn checksum_width(algorithm: &ChecksumAlgorithm) -> Option<u8> {
    match algorithm {
        ChecksumAlgorithm::Crc {
            width,
            polynomial,
            initial,
            xor_out,
            ..
        } if width_valid(*width)
            && *polynomial != 0
            && integer_fits(*width, *polynomial)
            && integer_fits(*width, *initial)
            && integer_fits(*width, *xor_out) =>
        {
            Some(*width)
        }
        ChecksumAlgorithm::Sum { width, .. } if width_valid(*width) => Some(*width),
        ChecksumAlgorithm::Xor8 => Some(1),
        _ => None,
    }
}

fn checksum_range_valid(layout: &ChecksumLayout, total: u32, commit_offset: u32) -> bool {
    layout.length != 0
        && layout
            .start
            .checked_add(layout.length)
            .is_some_and(|end| end <= total && !(layout.start..end).contains(&commit_offset))
}

fn ranges_disjoint(ranges: &[(u32, u32)]) -> bool {
    for (index, (left_start, left_width)) in ranges.iter().enumerate() {
        let Some(left_end) = left_start.checked_add(*left_width) else {
            return false;
        };
        for (right_start, right_width) in &ranges[index + 1..] {
            let Some(right_end) = right_start.checked_add(*right_width) else {
                return false;
            };
            if *left_start < right_end && *right_start < left_end {
                return false;
            }
        }
    }
    true
}

fn address_ranges(address: &BlockAddressLayout) -> Vec<(u32, u32)> {
    match address {
        BlockAddressLayout::Flat { offset, width, .. } => {
            vec![(*offset, u32::from(*width))]
        }
        BlockAddressLayout::Coordinates {
            channel,
            chip,
            lun,
            block,
        } => vec![
            (channel.offset, u32::from(channel.width)),
            (chip.offset, u32::from(chip.width)),
            (lun.offset, u32::from(lun.width)),
            (block.offset, u32::from(block.width)),
        ],
        BlockAddressLayout::CoordinatesWithPlane {
            channel,
            chip,
            lun,
            plane,
            block_in_plane,
        } => vec![
            (channel.offset, u32::from(channel.width)),
            (chip.offset, u32::from(chip.width)),
            (lun.offset, u32::from(lun.width)),
            (plane.offset, u32::from(plane.width)),
            (block_in_plane.offset, u32::from(block_in_plane.width)),
        ],
    }
}

fn address_layout_valid(address: &BlockAddressLayout, len: u32) -> bool {
    let ranges = address_ranges(address);
    ranges.iter().all(|(offset, width)| {
        u8::try_from(*width)
            .ok()
            .is_some_and(|width| width_valid(width) && range_fits(*offset, width, len))
    }) && ranges_disjoint(&ranges)
}

fn address_disjoint_from_state(address: &BlockAddressLayout, state_offset: u32) -> bool {
    let mut ranges = address_ranges(address);
    ranges.push((state_offset, 1));
    ranges_disjoint(&ranges)
}

fn validate_metadata_layouts(
    bbt: &MetadataTableLayout,
    ftl: &FtlPayloadLayout,
    capacity: &CapacityPayloadLayout,
) -> Result<()> {
    let header = hex_bytes(&bbt.header_hex, "BBT output header")?;
    let bbt_checksum_width = checksum_width(&bbt.checksum.algorithm)
        .ok_or_else(|| Error::Invalid("invalid BBT checksum algorithm".into()))?;
    if bbt.maximum_bytes == 0
        || bbt.maximum_bytes > MAX_COMMAND_TRANSFER
        || bbt.entry_stride == 0
        || !address_layout_valid(&bbt.address, bbt.entry_stride)
        || bbt.state_offset >= bbt.entry_stride
        || !address_disjoint_from_state(&bbt.address, bbt.state_offset)
        || !width_valid(bbt.generation_width)
        || !width_valid(bbt.count_width)
        || header.len() as u32 > bbt.maximum_bytes
        || !range_fits(
            bbt.generation_offset,
            bbt.generation_width,
            header.len() as u32,
        )
        || !range_fits(bbt.count_offset, bbt.count_width, header.len() as u32)
        || !range_fits(bbt.checksum.offset, bbt_checksum_width, header.len() as u32)
        || bbt.commit_offset >= header.len() as u32
        || bbt.prepare_value == bbt.commit_value
        || !ranges_disjoint(&[
            (bbt.generation_offset, u32::from(bbt.generation_width)),
            (bbt.count_offset, u32::from(bbt.count_width)),
            (bbt.checksum.offset, u32::from(bbt_checksum_width)),
            (bbt.commit_offset, 1),
        ])
        || !checksum_range_valid(&bbt.checksum, bbt.maximum_bytes, bbt.commit_offset)
    {
        return Err(Error::Invalid("invalid BBT output layout".into()));
    }
    let ftl_header = hex_bytes(&ftl.header_hex, "FTL output header")?;
    let total = ftl.total_bytes;
    let ftl_checksum_width = checksum_width(&ftl.checksum.algorithm)
        .ok_or_else(|| Error::Invalid("invalid FTL checksum algorithm".into()))?;
    if total == 0
        || total > MAX_COMMAND_TRANSFER
        || ftl_header.len() as u32 > total
        || !width_valid(ftl.generation_width)
        || !width_valid(ftl.user_blocks_width)
        || !width_valid(ftl.spare_blocks_width)
        || !range_fits(ftl.generation_offset, ftl.generation_width, total)
        || !range_fits(ftl.user_blocks_offset, ftl.user_blocks_width, total)
        || !range_fits(ftl.spare_blocks_offset, ftl.spare_blocks_width, total)
        || !range_fits(ftl.bbt_sha256_offset, 32, total)
        || !range_fits(ftl.checksum.offset, ftl_checksum_width, total)
        || ftl.commit_offset >= total
        || ftl.prepare_value == ftl.commit_value
        || !ranges_disjoint(&[
            (ftl.generation_offset, u32::from(ftl.generation_width)),
            (ftl.user_blocks_offset, u32::from(ftl.user_blocks_width)),
            (ftl.spare_blocks_offset, u32::from(ftl.spare_blocks_width)),
            (ftl.bbt_sha256_offset, 32),
            (ftl.checksum.offset, u32::from(ftl_checksum_width)),
            (ftl.commit_offset, 1),
        ])
        || !checksum_range_valid(&ftl.checksum, total, ftl.commit_offset)
    {
        return Err(Error::Invalid("invalid FTL output layout".into()));
    }
    let capacity_header = hex_bytes(&capacity.header_hex, "capacity output header")?;
    if capacity.total_bytes == 0
        || capacity.total_bytes > MAX_COMMAND_TRANSFER
        || capacity_header.len() as u32 > capacity.total_bytes
        || !width_valid(capacity.value_width)
        || !range_fits(
            capacity.value_offset,
            capacity.value_width,
            capacity.total_bytes,
        )
    {
        return Err(Error::Invalid("invalid capacity output layout".into()));
    }
    Ok(())
}

pub fn build_cdb(command: &CommandSpec, context: CommandContext) -> Result<Vec<u8>> {
    let mut cdb = hex_bytes(&command.cdb_hex, "command cdb_hex")?;
    for field in &command.fields {
        let value = apply_value_operations(context.value(field.value), &field.operations)?;
        put_integer(
            &mut cdb,
            usize::from(field.offset),
            field.width,
            field.endian,
            value,
        )?;
    }
    Ok(cdb)
}

fn value_operations_valid(operations: &[ValueOperation]) -> bool {
    operations.len() <= MAX_VALUE_OPERATIONS
        && operations.iter().all(|operation| match operation {
            ValueOperation::Divide { value }
            | ValueOperation::Modulo { value }
            | ValueOperation::XorModulo { value } => *value != 0,
            ValueOperation::ShiftLeft { bits } | ValueOperation::ShiftRight { bits } => *bits < 64,
            _ => true,
        })
}

fn apply_value_operations(mut value: u64, operations: &[ValueOperation]) -> Result<u64> {
    for operation in operations {
        value = match operation {
            ValueOperation::Add { value: operand } => value
                .checked_add(*operand)
                .ok_or_else(|| Error::Invalid("value operation addition overflow".into()))?,
            ValueOperation::Subtract { value: operand } => value
                .checked_sub(*operand)
                .ok_or_else(|| Error::Invalid("value operation subtraction underflow".into()))?,
            ValueOperation::Multiply { value: operand } => value
                .checked_mul(*operand)
                .ok_or_else(|| Error::Invalid("value operation multiplication overflow".into()))?,
            ValueOperation::Divide { value: operand } => value
                .checked_div(*operand)
                .ok_or_else(|| Error::Invalid("value operation division by zero".into()))?,
            ValueOperation::Modulo { value: operand } => value
                .checked_rem(*operand)
                .ok_or_else(|| Error::Invalid("value operation modulo by zero".into()))?,
            ValueOperation::XorModulo { value: operand } => {
                value
                    ^ value.checked_rem(*operand).ok_or_else(|| {
                        Error::Invalid("value operation xor-modulo by zero".into())
                    })?
            }
            ValueOperation::And { mask } => value & mask,
            ValueOperation::Or { mask } => value | mask,
            ValueOperation::ShiftLeft { bits } => {
                let factor = 1u64.checked_shl(u32::from(*bits)).ok_or_else(|| {
                    Error::Invalid("value operation left shift is out of range".into())
                })?;
                value
                    .checked_mul(factor)
                    .ok_or_else(|| Error::Invalid("value operation left shift overflow".into()))?
            }
            ValueOperation::ShiftRight { bits } => value
                .checked_shr(u32::from(*bits))
                .ok_or_else(|| Error::Invalid("value operation right shift overflow".into()))?,
        };
    }
    Ok(value)
}

pub fn build_context_payload(command: &CommandSpec, context: CommandContext) -> Result<Vec<u8>> {
    let Some(PayloadSource::Context {
        record_bytes,
        repeat,
        fill_byte,
        constants,
        fields,
    }) = command.payload.as_ref()
    else {
        return Err(Error::Invalid(
            "command has no context-generated payload".into(),
        ));
    };
    let record_bytes = usize::try_from(*record_bytes)
        .map_err(|_| Error::Invalid("context payload record is too large".into()))?;
    let repeat = usize::try_from(*repeat)
        .map_err(|_| Error::Invalid("context payload repeat is too large".into()))?;
    let total = record_bytes
        .checked_mul(repeat)
        .ok_or_else(|| Error::Invalid("context payload size overflow".into()))?;
    if total != command.transfer_bytes as usize || total > MAX_COMMAND_TRANSFER as usize {
        return Err(Error::Invalid(
            "context payload does not match command transfer length".into(),
        ));
    }
    let mut record = vec![*fill_byte; record_bytes];
    for constant in constants {
        put_integer(
            &mut record,
            constant.offset as usize,
            constant.width,
            constant.endian,
            constant.value,
        )?;
    }
    for field in fields {
        let value = apply_value_operations(context.value(field.value), &field.operations)?;
        put_integer(
            &mut record,
            field.offset as usize,
            field.width,
            field.endian,
            value,
        )?;
    }
    let mut payload = Vec::with_capacity(total);
    for _ in 0..repeat {
        payload.extend_from_slice(&record);
    }
    Ok(payload)
}

pub fn decode_response(command: &CommandSpec, data: &[u8]) -> Result<BTreeMap<String, u64>> {
    let rule = &command.response;
    if data.len() < rule.min_bytes as usize || data.len() > rule.max_bytes as usize {
        return Err(Error::Invalid(format!(
            "controller response length {} is outside {}..={}",
            data.len(),
            rule.min_bytes,
            rule.max_bytes
        )));
    }
    let prefix = hex_bytes(&rule.prefix_hex, "response prefix")?;
    if !data.starts_with(&prefix) {
        return Err(Error::Invalid(
            "controller response signature mismatch".into(),
        ));
    }
    let mut values = BTreeMap::new();
    for field in &rule.fields {
        let raw = get_integer(data, field.offset as usize, field.width, field.endian)?;
        let value = if field.mask == 0 {
            raw
        } else {
            raw & field.mask
        };
        if field.equals.is_some_and(|expected| value != expected) {
            return Err(Error::Invalid(format!(
                "controller response field {} is {value:#x}, expected {:#x}",
                field.name,
                field.equals.unwrap_or_default()
            )));
        }
        values.insert(field.name.clone(), value);
    }
    Ok(values)
}

pub fn response_payload<'a>(command: &CommandSpec, data: &'a [u8]) -> Result<&'a [u8]> {
    let response = &command.response;
    if response.payload_bytes == 0 {
        return Ok(data);
    }
    let start = response.payload_offset as usize;
    let end = start
        .checked_add(response.payload_bytes as usize)
        .ok_or_else(|| Error::Invalid("controller response payload window overflow".into()))?;
    data.get(start..end)
        .ok_or_else(|| Error::Invalid("controller response payload is truncated".into()))
}

fn put_integer(buf: &mut [u8], offset: usize, width: u8, endian: Endian, value: u64) -> Result<()> {
    let width = usize::from(width);
    let end = offset
        .checked_add(width)
        .ok_or_else(|| Error::Invalid("integer field overflow".into()))?;
    let target = buf
        .get_mut(offset..end)
        .ok_or_else(|| Error::Invalid("integer field is outside buffer".into()))?;
    if width < 8 && value >= (1u64 << (width * 8)) {
        return Err(Error::Invalid(format!(
            "value {value} does not fit in {width} bytes"
        )));
    }
    let bytes = match endian {
        Endian::Big => value.to_be_bytes(),
        Endian::Little => value.to_le_bytes(),
    };
    match endian {
        Endian::Big => target.copy_from_slice(&bytes[8 - width..]),
        Endian::Little => target.copy_from_slice(&bytes[..width]),
    }
    Ok(())
}

fn get_integer(buf: &[u8], offset: usize, width: u8, endian: Endian) -> Result<u64> {
    let width = usize::from(width);
    let end = offset
        .checked_add(width)
        .ok_or_else(|| Error::Invalid("integer field overflow".into()))?;
    let source = buf
        .get(offset..end)
        .ok_or_else(|| Error::Invalid("integer field is outside response".into()))?;
    let mut bytes = [0u8; 8];
    match endian {
        Endian::Big => bytes[8 - width..].copy_from_slice(source),
        Endian::Little => bytes[..width].copy_from_slice(source),
    }
    Ok(match endian {
        Endian::Big => u64::from_be_bytes(bytes),
        Endian::Little => u64::from_le_bytes(bytes),
    })
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum BlockDisposition {
    Unknown,
    FactoryBad,
    HistoricalRuntimeBad,
    SystemPreserved,
    SystemRebuild,
    Data,
    Erased,
    Qualified,
    Quarantined,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct BlockRecord {
    pub flat: u64,
    pub disposition: BlockDisposition,
    #[serde(default)]
    pub historical_rbb: bool,
    #[serde(default)]
    pub erase_attempts: u8,
    #[serde(default)]
    pub corrected_bits: u32,
    #[serde(default)]
    pub read_retries: u32,
    #[serde(default)]
    pub read_latency_ms: u32,
    #[serde(default)]
    pub failure: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct InFlight {
    pub operation: String,
    pub flat_block: u64,
    pub phase: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ControllerRunState {
    pub schema: u32,
    pub sequence: u64,
    pub plan_hash: String,
    pub profile_id: String,
    pub profile_sha256: String,
    pub recipe_sha256: String,
    pub controller_id: String,
    pub firmware: String,
    pub nand_id: String,
    pub service_mode: String,
    pub phase: String,
    #[serde(default)]
    pub old_bbt_sha256: String,
    #[serde(default)]
    pub new_bbt_sha256: String,
    #[serde(default)]
    pub generation: u64,
    #[serde(default)]
    pub user_blocks: u64,
    #[serde(default)]
    pub spare_blocks: u64,
    #[serde(default)]
    pub blocks: Vec<BlockRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub in_flight: Option<InFlight>,
}

impl ControllerRunState {
    pub fn new(plan_hash: &str, profile: &Profile, recipe_sha256: &str) -> Result<Self> {
        let profile_sha256 = profile
            .sha256
            .clone()
            .ok_or_else(|| Error::Invalid("profile digest is absent".into()))?;
        Ok(Self {
            schema: STATE_SCHEMA,
            sequence: 0,
            plan_hash: plan_hash.into(),
            profile_id: profile.id.clone(),
            profile_sha256,
            recipe_sha256: recipe_sha256.into(),
            controller_id: profile.controller_id.clone(),
            firmware: profile.firmware.min.clone().unwrap_or_default(),
            nand_id: profile.nand_id.min.clone().unwrap_or_default(),
            service_mode: "normal".into(),
            phase: "new".into(),
            old_bbt_sha256: String::new(),
            new_bbt_sha256: String::new(),
            generation: 0,
            user_blocks: 0,
            spare_blocks: 0,
            blocks: Vec::new(),
            in_flight: None,
        })
    }

    pub fn verify_binding(
        &self,
        plan_hash: &str,
        profile: &Profile,
        recipe_sha256: &str,
    ) -> Result<()> {
        if self.schema != STATE_SCHEMA
            || self.plan_hash != plan_hash
            || self.profile_id != profile.id
            || profile.sha256.as_deref() != Some(self.profile_sha256.as_str())
            || self.recipe_sha256 != recipe_sha256
            || self.controller_id != profile.controller_id
            || profile.firmware.min.as_deref() != Some(self.firmware.as_str())
            || profile.nand_id.min.as_deref() != Some(self.nand_id.as_str())
        {
            return Err(Error::Permission(
                "controller state binding mismatch".into(),
            ));
        }
        self.service_mode_transition_active()?;
        Ok(())
    }

    pub fn service_mode_transition_active(&self) -> Result<bool> {
        match self.service_mode.as_str() {
            "normal" => Ok(false),
            "entry-command-pending"
            | "entry-reenumerating"
            | "loader-command-pending"
            | "loader-reenumerating"
            | "in-service"
            | "exit-command-pending"
            | "exit-reenumerating" => Ok(true),
            value => Err(Error::Permission(format!(
                "controller state has unknown service mode {value}"
            ))),
        }
    }
}

#[derive(Clone, Debug)]
struct StateDescriptor {
    slot: usize,
    sequence: u64,
    length: u64,
    digest: [u8; 32],
}

fn descriptor_bytes(descriptor: &StateDescriptor) -> [u8; STATE_DESCRIPTOR_BYTES] {
    let mut out = [0u8; STATE_DESCRIPTOR_BYTES];
    out[..8].copy_from_slice(STATE_MAGIC);
    out[8] = descriptor.slot as u8;
    out[16..24].copy_from_slice(&descriptor.sequence.to_le_bytes());
    out[24..32].copy_from_slice(&descriptor.length.to_le_bytes());
    out[32..64].copy_from_slice(&descriptor.digest);
    let checksum = Sha256::digest(&out[..64]);
    out[64..96].copy_from_slice(&checksum);
    out
}

fn parse_descriptor(raw: &[u8], expected_slot: usize) -> Option<StateDescriptor> {
    if raw.len() != STATE_DESCRIPTOR_BYTES
        || &raw[..8] != STATE_MAGIC
        || raw[8] as usize != expected_slot
    {
        return None;
    }
    let checksum = Sha256::digest(&raw[..64]);
    if raw[64..96] != checksum[..] {
        return None;
    }
    let sequence = u64::from_le_bytes(raw[16..24].try_into().ok()?);
    let length = u64::from_le_bytes(raw[24..32].try_into().ok()?);
    if length == 0 || length > STATE_SLOT_BYTES {
        return None;
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&raw[32..64]);
    Some(StateDescriptor {
        slot: expected_slot,
        sequence,
        length,
        digest,
    })
}

fn descriptor_offset(slot: usize) -> u64 {
    (slot * STATE_DESCRIPTOR_BYTES) as u64
}
fn slot_offset(slot: usize) -> u64 {
    STATE_DATA_OFFSET + slot as u64 * STATE_SLOT_BYTES
}

pub fn load_state(file: &mut File) -> Result<Option<ControllerRunState>> {
    let len = file
        .metadata()
        .map_err(|e| Error::io("stat controller state", Some(e)))?
        .len();
    if len == 0 {
        return Ok(None);
    }
    if len != STATE_FILE_BYTES {
        return Err(Error::Invalid(
            "controller state file has an invalid size".into(),
        ));
    }
    let mut valid = Vec::new();
    let mut descriptors_uninitialized = true;
    for slot in 0..2 {
        let mut raw = [0u8; STATE_DESCRIPTOR_BYTES];
        file.seek(SeekFrom::Start(descriptor_offset(slot)))
            .and_then(|_| file.read_exact(&mut raw))
            .map_err(|e| Error::io("read controller state descriptor", Some(e)))?;
        descriptors_uninitialized &= raw.iter().all(|byte| *byte == 0);
        if let Some(descriptor) = parse_descriptor(&raw, slot) {
            let mut payload = vec![0u8; descriptor.length as usize];
            file.seek(SeekFrom::Start(slot_offset(slot)))
                .and_then(|_| file.read_exact(&mut payload))
                .map_err(|e| Error::io("read controller state slot", Some(e)))?;
            if Sha256::digest(&payload)[..] == descriptor.digest[..] {
                if let Ok(state) = serde_json::from_slice::<ControllerRunState>(&payload) {
                    if state.sequence == descriptor.sequence {
                        valid.push((descriptor.sequence, state));
                    }
                }
            }
        }
    }
    if valid.is_empty() && descriptors_uninitialized {
        // The first allocation can be interrupted before its first descriptor
        // is committed. No controller command is sent until store_state
        // returns, so an all-zero descriptor area is safely uninitialized.
        return Ok(None);
    }
    valid.sort_by_key(|(sequence, _)| *sequence);
    valid
        .pop()
        .map(|(_, state)| Some(state))
        .ok_or_else(|| Error::Invalid("controller state has no valid committed slot".into()))
}

pub fn store_state(file: &mut File, state: &mut ControllerRunState) -> Result<()> {
    let current = load_state(file)?;
    let next_sequence = current
        .as_ref()
        .map(|state| {
            state
                .sequence
                .checked_add(1)
                .ok_or_else(|| Error::Invalid("controller state sequence overflow".into()))
        })
        .transpose()?
        .unwrap_or(0);
    let slot = (next_sequence & 1) as usize;
    state.sequence = next_sequence;
    let payload = serde_json::to_vec(state)
        .map_err(|e| Error::Invalid(format!("serialize controller state: {e}")))?;
    if payload.is_empty() || payload.len() as u64 > STATE_SLOT_BYTES {
        return Err(Error::Invalid(
            "controller state exceeds its durable slot".into(),
        ));
    }
    if file
        .metadata()
        .map_err(|e| Error::io("stat controller state", Some(e)))?
        .len()
        == 0
    {
        file.set_len(STATE_FILE_BYTES)
            .map_err(|e| Error::io("allocate controller state", Some(e)))?;
    }
    file.seek(SeekFrom::Start(slot_offset(slot)))
        .and_then(|_| file.write_all(&payload))
        .and_then(|_| file.sync_data())
        .map_err(|e| Error::io("write controller state slot", Some(e)))?;
    let digest: [u8; 32] = Sha256::digest(&payload).into();
    let descriptor = descriptor_bytes(&StateDescriptor {
        slot,
        sequence: next_sequence,
        length: payload.len() as u64,
        digest,
    });
    file.seek(SeekFrom::Start(descriptor_offset(slot)))
        .and_then(|_| file.write_all(&descriptor))
        .and_then(|_| file.sync_all())
        .map_err(|e| Error::io("commit controller state descriptor", Some(e)))?;
    Ok(())
}

pub fn total_blocks(geometry: &NandGeometryPolicy) -> Result<u64> {
    u64::from(geometry.channels)
        .checked_mul(u64::from(geometry.chips_per_channel))
        .and_then(|v| v.checked_mul(u64::from(geometry.luns_per_chip)))
        .and_then(|v| v.checked_mul(u64::from(geometry.blocks_per_lun)))
        .ok_or_else(|| Error::Invalid("NAND total block count overflow".into()))
}

pub fn coordinate(flat: u64, geometry: &NandGeometryPolicy) -> Result<CommandContext> {
    let total = total_blocks(geometry)?;
    if flat >= total {
        return Err(Error::Invalid(format!(
            "physical block {flat} is outside geometry"
        )));
    }
    let blocks_per_lun = u64::from(geometry.blocks_per_lun);
    let luns_per_chip = u64::from(geometry.luns_per_chip);
    let chips_per_channel = u64::from(geometry.chips_per_channel);
    let block = flat % blocks_per_lun;
    let mut upper = flat / blocks_per_lun;
    let lun = upper % luns_per_chip;
    upper /= luns_per_chip;
    let chip = upper % chips_per_channel;
    let channel = upper / chips_per_channel;
    Ok(CommandContext {
        channel,
        chip,
        lun,
        plane: block % u64::from(geometry.planes_per_lun),
        block,
        flat_block: flat,
        ..CommandContext::default()
    })
}

fn decode_block_address(
    data: &[u8],
    base: usize,
    address: &BlockAddressLayout,
    geometry: &NandGeometryPolicy,
) -> Result<u64> {
    match address {
        BlockAddressLayout::Flat {
            offset,
            width,
            endian,
        } => get_integer(data, base + *offset as usize, *width, *endian),
        BlockAddressLayout::Coordinates {
            channel,
            chip,
            lun,
            block,
        } => {
            let read = |field: &IntegerLayout| {
                get_integer(
                    data,
                    base + field.offset as usize,
                    field.width,
                    field.endian,
                )
            };
            let channel = read(channel)?;
            let chip = read(chip)?;
            let lun = read(lun)?;
            let block = read(block)?;
            if channel >= u64::from(geometry.channels)
                || chip >= u64::from(geometry.chips_per_channel)
                || lun >= u64::from(geometry.luns_per_chip)
                || block >= u64::from(geometry.blocks_per_lun)
            {
                return Err(Error::Invalid(
                    "BBT entry contains an out-of-range NAND coordinate".into(),
                ));
            }
            channel
                .checked_mul(u64::from(geometry.chips_per_channel))
                .and_then(|value| value.checked_add(chip))
                .and_then(|value| value.checked_mul(u64::from(geometry.luns_per_chip)))
                .and_then(|value| value.checked_add(lun))
                .and_then(|value| value.checked_mul(u64::from(geometry.blocks_per_lun)))
                .and_then(|value| value.checked_add(block))
                .ok_or_else(|| Error::Invalid("BBT coordinate flattening overflow".into()))
        }
        BlockAddressLayout::CoordinatesWithPlane {
            channel,
            chip,
            lun,
            plane,
            block_in_plane,
        } => {
            let read = |field: &IntegerLayout| {
                get_integer(
                    data,
                    base + field.offset as usize,
                    field.width,
                    field.endian,
                )
            };
            let channel = read(channel)?;
            let chip = read(chip)?;
            let lun = read(lun)?;
            let plane = read(plane)?;
            let block_in_plane = read(block_in_plane)?;
            let planes = u64::from(geometry.planes_per_lun);
            if u64::from(geometry.blocks_per_lun) % planes != 0
                || channel >= u64::from(geometry.channels)
                || chip >= u64::from(geometry.chips_per_channel)
                || lun >= u64::from(geometry.luns_per_chip)
                || plane >= planes
                || block_in_plane >= u64::from(geometry.blocks_per_lun) / planes
            {
                return Err(Error::Invalid(
                    "BBT entry contains an out-of-range plane coordinate".into(),
                ));
            }
            let block = block_in_plane
                .checked_mul(planes)
                .and_then(|value| value.checked_add(plane))
                .ok_or_else(|| Error::Invalid("BBT plane address overflow".into()))?;
            channel
                .checked_mul(u64::from(geometry.chips_per_channel))
                .and_then(|value| value.checked_add(chip))
                .and_then(|value| value.checked_mul(u64::from(geometry.luns_per_chip)))
                .and_then(|value| value.checked_add(lun))
                .and_then(|value| value.checked_mul(u64::from(geometry.blocks_per_lun)))
                .and_then(|value| value.checked_add(block))
                .ok_or_else(|| Error::Invalid("BBT plane coordinate flattening overflow".into()))
        }
    }
}

fn encode_block_address(
    data: &mut [u8],
    base: usize,
    address: &BlockAddressLayout,
    flat: u64,
    geometry: &NandGeometryPolicy,
) -> Result<()> {
    let context = coordinate(flat, geometry)?;
    match address {
        BlockAddressLayout::Flat {
            offset,
            width,
            endian,
        } => put_integer(data, base + *offset as usize, *width, *endian, flat),
        BlockAddressLayout::Coordinates {
            channel,
            chip,
            lun,
            block,
        } => {
            for (field, value) in [
                (channel, context.channel),
                (chip, context.chip),
                (lun, context.lun),
                (block, context.block),
            ] {
                put_integer(
                    data,
                    base + field.offset as usize,
                    field.width,
                    field.endian,
                    value,
                )?;
            }
            Ok(())
        }
        BlockAddressLayout::CoordinatesWithPlane {
            channel,
            chip,
            lun,
            plane,
            block_in_plane,
        } => {
            let planes = u64::from(geometry.planes_per_lun);
            if u64::from(geometry.blocks_per_lun) % planes != 0 {
                return Err(Error::Invalid(
                    "blocks_per_lun is not divisible by planes_per_lun".into(),
                ));
            }
            for (field, value) in [
                (channel, context.channel),
                (chip, context.chip),
                (lun, context.lun),
                (plane, context.plane),
                (block_in_plane, context.block / planes),
            ] {
                put_integer(
                    data,
                    base + field.offset as usize,
                    field.width,
                    field.endian,
                    value,
                )?;
            }
            Ok(())
        }
    }
}

pub fn decode_old_bbt(
    data: &[u8],
    layout: &BbtLayout,
    geometry: &NandGeometryPolicy,
) -> Result<Vec<(u64, BlockDisposition)>> {
    let total = total_blocks(geometry)?;
    let count = get_integer(
        data,
        layout.count_offset as usize,
        layout.count_width,
        layout.count_endian,
    )?;
    if count > u64::from(layout.maximum_entries) || count > total {
        return Err(Error::Invalid(format!(
            "old BBT entry count {count} exceeds its bound"
        )));
    }
    let mut out = Vec::with_capacity(count as usize);
    let mut seen = BTreeSet::new();
    for index in 0..count {
        let base = u64::from(layout.entries_offset)
            .checked_add(
                index
                    .checked_mul(u64::from(layout.entry_stride))
                    .ok_or_else(|| Error::Invalid("BBT entry offset overflow".into()))?,
            )
            .ok_or_else(|| Error::Invalid("BBT entry offset overflow".into()))?;
        let base = usize::try_from(base)
            .map_err(|_| Error::Invalid("BBT entry offset does not fit memory".into()))?;
        let block = decode_block_address(data, base, &layout.address, geometry)?;
        let state = *data
            .get(base + layout.state_offset as usize)
            .ok_or_else(|| Error::Invalid("old BBT entry is truncated".into()))?;
        if block >= total || !seen.insert(block) {
            return Err(Error::Invalid(
                "old BBT contains an out-of-range or duplicate block".into(),
            ));
        }
        let disposition = if layout.factory_bad_values.contains(&state) {
            BlockDisposition::FactoryBad
        } else if layout.runtime_bad_values.contains(&state) {
            BlockDisposition::HistoricalRuntimeBad
        } else if layout.system_values.contains(&state) {
            BlockDisposition::SystemRebuild
        } else {
            return Err(Error::Invalid(format!(
                "old BBT contains unknown state {state:#x}"
            )));
        };
        out.push((block, disposition));
    }
    Ok(out)
}

fn checksum_value(algorithm: &ChecksumAlgorithm, data: &[u8]) -> Result<u64> {
    let width = checksum_width(algorithm)
        .ok_or_else(|| Error::Invalid("invalid checksum algorithm".into()))?;
    let bits = u32::from(width) * 8;
    let mask = if width == 8 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    Ok(match algorithm {
        ChecksumAlgorithm::Crc {
            polynomial,
            initial,
            xor_out,
            reflected,
            ..
        } => {
            let mut crc = *initial & mask;
            if *reflected {
                for byte in data {
                    crc ^= u64::from(*byte);
                    for _ in 0..8 {
                        crc = if crc & 1 != 0 {
                            (crc >> 1) ^ polynomial
                        } else {
                            crc >> 1
                        };
                    }
                }
            } else {
                let top = 1u64 << (bits - 1);
                for byte in data {
                    crc ^= u64::from(*byte) << (bits - 8);
                    for _ in 0..8 {
                        crc = (if crc & top != 0 {
                            (crc << 1) ^ polynomial
                        } else {
                            crc << 1
                        }) & mask;
                    }
                }
            }
            (crc ^ xor_out) & mask
        }
        ChecksumAlgorithm::Sum {
            twos_complement, ..
        } => {
            let sum = data
                .iter()
                .fold(0u64, |sum, byte| sum.wrapping_add(u64::from(*byte)))
                & mask;
            if *twos_complement {
                (!sum).wrapping_add(1) & mask
            } else {
                sum
            }
        }
        ChecksumAlgorithm::Xor8 => data.iter().fold(0u8, |value, byte| value ^ byte) as u64,
    })
}

fn write_checksum(data: &mut [u8], layout: &ChecksumLayout) -> Result<()> {
    let width = checksum_width(&layout.algorithm)
        .ok_or_else(|| Error::Invalid("invalid checksum algorithm".into()))?;
    put_integer(data, layout.offset as usize, width, layout.endian, 0)?;
    let start = layout.start as usize;
    let end = start
        .checked_add(layout.length as usize)
        .ok_or_else(|| Error::Invalid("checksum coverage overflow".into()))?;
    let covered = data
        .get(start..end)
        .ok_or_else(|| Error::Invalid("checksum coverage is outside payload".into()))?;
    let value = checksum_value(&layout.algorithm, covered)?;
    put_integer(data, layout.offset as usize, width, layout.endian, value)
}

fn digest_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

pub fn build_bbt(
    state: &ControllerRunState,
    layout: &MetadataTableLayout,
    geometry: &NandGeometryPolicy,
) -> Result<Vec<u8>> {
    let mut entries = state
        .blocks
        .iter()
        .filter(|block| {
            matches!(
                block.disposition,
                BlockDisposition::FactoryBad
                    | BlockDisposition::HistoricalRuntimeBad
                    | BlockDisposition::Quarantined
                    | BlockDisposition::SystemPreserved
                    | BlockDisposition::SystemRebuild
            )
        })
        .collect::<Vec<_>>();
    entries.sort_by_key(|block| block.flat);
    let header = hex_bytes(&layout.header_hex, "BBT output header")?;
    let length = header
        .len()
        .checked_add(
            entries
                .len()
                .checked_mul(layout.entry_stride as usize)
                .ok_or_else(|| Error::Invalid("BBT output length overflow".into()))?,
        )
        .ok_or_else(|| Error::Invalid("BBT output length overflow".into()))?;
    if length > layout.maximum_bytes as usize {
        return Err(Error::Invalid("new BBT exceeds recipe maximum".into()));
    }
    let mut out = vec![layout.fill_byte; layout.maximum_bytes as usize];
    out[..header.len()].copy_from_slice(&header);
    put_integer(
        &mut out,
        layout.generation_offset as usize,
        layout.generation_width,
        layout.generation_endian,
        state.generation,
    )?;
    put_integer(
        &mut out,
        layout.count_offset as usize,
        layout.count_width,
        layout.count_endian,
        entries.len() as u64,
    )?;
    for (index, block) in entries.into_iter().enumerate() {
        let base = header.len() + index * layout.entry_stride as usize;
        encode_block_address(&mut out, base, &layout.address, block.flat, geometry)?;
        out[base + layout.state_offset as usize] = match block.disposition {
            BlockDisposition::FactoryBad => layout.factory_bad_value,
            BlockDisposition::SystemPreserved | BlockDisposition::SystemRebuild => {
                layout.system_value
            }
            _ => layout.quarantined_value,
        };
    }
    out[layout.commit_offset as usize] = layout.prepare_value;
    write_checksum(&mut out, &layout.checksum)?;
    Ok(out)
}

pub fn build_ftl(
    state: &ControllerRunState,
    bbt: &[u8],
    bbt_layout: &MetadataTableLayout,
    layout: &FtlPayloadLayout,
) -> Result<Vec<u8>> {
    let header = hex_bytes(&layout.header_hex, "FTL output header")?;
    let mut out = vec![layout.fill_byte; layout.total_bytes as usize];
    out[..header.len()].copy_from_slice(&header);
    put_integer(
        &mut out,
        layout.generation_offset as usize,
        layout.generation_width,
        layout.generation_endian,
        state.generation,
    )?;
    put_integer(
        &mut out,
        layout.user_blocks_offset as usize,
        layout.user_blocks_width,
        layout.user_blocks_endian,
        state.user_blocks,
    )?;
    put_integer(
        &mut out,
        layout.spare_blocks_offset as usize,
        layout.spare_blocks_width,
        layout.spare_blocks_endian,
        state.spare_blocks,
    )?;
    let mut committed_bbt = bbt.to_vec();
    let commit = committed_bbt
        .get_mut(bbt_layout.commit_offset as usize)
        .ok_or_else(|| Error::Invalid("BBT commit marker is outside its payload".into()))?;
    *commit = bbt_layout.commit_value;
    let digest = Sha256::digest(&committed_bbt);
    let start = layout.bbt_sha256_offset as usize;
    out[start..start + 32].copy_from_slice(&digest);
    out[layout.commit_offset as usize] = layout.prepare_value;
    write_checksum(&mut out, &layout.checksum)?;
    Ok(out)
}

pub fn build_capacity(
    user_blocks: u64,
    block_bytes: u64,
    layout: &CapacityPayloadLayout,
) -> Result<Vec<u8>> {
    let header = hex_bytes(&layout.header_hex, "capacity output header")?;
    let mut out = vec![layout.fill_byte; layout.total_bytes as usize];
    out[..header.len()].copy_from_slice(&header);
    let value = match layout.value {
        CapacityValue::UserBlocks => user_blocks,
        CapacityValue::UserBytes => user_blocks
            .checked_mul(block_bytes)
            .ok_or_else(|| Error::Invalid("logical capacity overflow".into()))?,
    };
    put_integer(
        &mut out,
        layout.value_offset as usize,
        layout.value_width,
        layout.value_endian,
        value,
    )?;
    Ok(out)
}

pub fn metadata_digests(
    state: &ControllerRunState,
    recipe: &ControllerRecipe,
    geometry: &NandGeometryPolicy,
) -> Result<(String, String)> {
    let bbt = build_bbt(state, &recipe.bbt_output, geometry)?;
    let ftl = build_ftl(state, &bbt, &recipe.bbt_output, &recipe.ftl_output)?;
    let mut committed_bbt = bbt;
    committed_bbt[recipe.bbt_output.commit_offset as usize] = recipe.bbt_output.commit_value;
    let mut committed_ftl = ftl;
    committed_ftl[recipe.ftl_output.commit_offset as usize] = recipe.ftl_output.commit_value;
    Ok((digest_hex(&committed_bbt), digest_hex(&committed_ftl)))
}

pub fn classify_system_blocks(
    state: &mut ControllerRunState,
    geometry: &NandGeometryPolicy,
    metadata: &MetadataLayoutPolicy,
) -> Result<()> {
    let total = total_blocks(geometry)?;
    if state.blocks.is_empty() {
        state.blocks = (0..total)
            .map(|flat| BlockRecord {
                flat,
                disposition: BlockDisposition::Data,
                historical_rbb: false,
                erase_attempts: 0,
                corrected_bits: 0,
                read_retries: 0,
                read_latency_ms: 0,
                failure: String::new(),
            })
            .collect();
    }
    if state.blocks.len() as u64 != total
        || state
            .blocks
            .iter()
            .enumerate()
            .any(|(i, b)| b.flat != i as u64)
    {
        return Err(Error::Invalid(
            "controller state block map does not match geometry".into(),
        ));
    }
    for range in &metadata.system_block_ranges {
        let disposition = match range.policy {
            SystemBlockPolicy::Preserve => BlockDisposition::SystemPreserved,
            SystemBlockPolicy::RebuildBbt
            | SystemBlockPolicy::RebuildFtl
            | SystemBlockPolicy::RebuildControllerMetadata => BlockDisposition::SystemRebuild,
        };
        for flat in range.start..=range.end {
            state.blocks[flat as usize].disposition = disposition;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transport_preserves_exact_cdb_length_contract() {
        for length in [6, 10, 12, 16] {
            assert!(transport_supports_cdb(TRANSPORT_SCSI_COMMAND, length));
            assert!(transport_supports_cdb(TRANSPORT_USB_BOT, length));
        }
        assert!(!transport_supports_cdb(TRANSPORT_SCSI_COMMAND, 8));
        assert!(transport_supports_cdb(TRANSPORT_USB_BOT, 8));
        assert!(!transport_supports_cdb(TRANSPORT_USB_BOT, 5));
        assert!(!transport_supports_cdb(TRANSPORT_USB_BOT, 17));
        assert!(!transport_supports_cdb("unknown", 16));
    }

    #[test]
    fn sandisk_u3_logical_commands_cannot_claim_raw_roles() {
        let mut set_domains = [0u8; 12];
        set_domains[..3].copy_from_slice(&[0xff, 0x22, 0x00]);
        let error = validate_sandisk_u3_command_scope("erase-block", &set_domains).unwrap_err();
        assert!(error.to_string().contains("U3 logical-domain"));
        assert!(
            validate_sandisk_u3_command_scope("erase-block", &[0xff, 0x22, 0, 0, 0, 0]).is_err()
        );

        let mut chip_info = [0u8; 12];
        chip_info[..3].copy_from_slice(&[0xff, 0x03, 0x01]);
        validate_sandisk_u3_command_scope("read-controller-id", &chip_info).unwrap();
        assert!(validate_sandisk_u3_command_scope("read-nand-id", &chip_info).is_err());

        let mut reset = [0u8; 12];
        reset[..3].copy_from_slice(&[0xff, 0x01, 0x01]);
        validate_sandisk_u3_command_scope("reset-controller", &reset).unwrap();
        assert!(validate_sandisk_u3_command_scope("activate-metadata", &reset).is_err());

        let mut unknown = [0u8; 12];
        unknown[..3].copy_from_slice(&[0xff, 0x99, 0x00]);
        validate_sandisk_u3_command_scope("read-status", &unknown).unwrap();
    }

    #[test]
    fn artifact_payload_is_exact_and_runtime_bound() {
        let mut profile = Profile::default();
        profile.artifacts.push(crate::artifact::ArtifactSpec {
            id: "service-code".into(),
            role: "service-loader".into(),
            kind: crate::artifact::ArtifactKind::ServiceLoader,
            format: crate::artifact::ArtifactFormat::Opaque,
            controller_id: "controller".into(),
            firmware: "firmware".into(),
            nand_id: "nand".into(),
            sha256: "11".repeat(32),
            size_bytes: 128,
            source_url: Some("https://example.invalid/service-code".into()),
            terms_url: None,
            redistributable: true,
        });
        profile.implementation = Some(crate::profile::ImplementationPolicy {
            strategy: "runtime-artifact".into(),
            protocol_evidence_sha256: "22".repeat(32),
            source_reference: "https://example.invalid/design".into(),
            artifact_ids: vec!["service-code".into()],
        });
        let mut command = CommandSpec {
            cdb_hex: "f00000000000".into(),
            direction: TransferDirection::ToDevice,
            transfer_bytes: 32,
            timeout_ms: 1000,
            fields: Vec::new(),
            payload: Some(PayloadSource::Artifact {
                artifact_id: "service-code".into(),
                offset: 16,
                length: 32,
            }),
            response: ResponseRule::default(),
        };
        validate_artifact_payload("enter-service-mode", &command, &profile).unwrap();

        command.transfer_bytes = 31;
        assert!(validate_artifact_payload("enter-service-mode", &command, &profile).is_err());
        command.transfer_bytes = 32;
        profile
            .implementation
            .as_mut()
            .unwrap()
            .artifact_ids
            .clear();
        assert!(validate_artifact_payload("enter-service-mode", &command, &profile).is_err());
    }

    #[test]
    fn alcor_service_upload_is_byte_exact_and_non_reenumerating() {
        let mut command = CommandSpec {
            cdb_hex: "fa0a000000000000".into(),
            direction: TransferDirection::ToDevice,
            transfer_bytes: 1024,
            timeout_ms: 60_000,
            fields: vec![FieldBinding {
                offset: 3,
                width: 1,
                endian: Endian::Big,
                value: RuntimeValue::PayloadBytes,
                operations: vec![
                    ValueOperation::Divide { value: 512 },
                    ValueOperation::Subtract { value: 1 },
                ],
            }],
            payload: Some(PayloadSource::Artifact {
                artifact_id: "alcor-service".into(),
                offset: 0,
                length: 0,
            }),
            response: ResponseRule::default(),
        };
        validate_alcor_service_upload_contract(
            "enter-service-mode",
            &command,
            TRANSPORT_USB_BOT,
            false,
            false,
            "alcor-service",
            1024,
        )
        .unwrap();

        assert!(validate_alcor_service_upload_contract(
            "enter-service-mode",
            &command,
            TRANSPORT_SCSI_COMMAND,
            false,
            false,
            "alcor-service",
            1024,
        )
        .is_err());
        assert!(validate_alcor_service_upload_contract(
            "enter-service-mode",
            &command,
            TRANSPORT_USB_BOT,
            true,
            false,
            "alcor-service",
            1024,
        )
        .is_err());

        command.fields[0].operations.swap(0, 1);
        assert!(validate_alcor_service_upload_contract(
            "enter-service-mode",
            &command,
            TRANSPORT_USB_BOT,
            false,
            false,
            "alcor-service",
            1024,
        )
        .is_err());
    }

    #[test]
    fn cdb_fields_are_bounded_and_endian_correct() {
        let command = CommandSpec {
            cdb_hex: "06000000000000000000".into(),
            direction: TransferDirection::None,
            transfer_bytes: 0,
            timeout_ms: 1000,
            fields: vec![FieldBinding {
                offset: 2,
                width: 4,
                endian: Endian::Big,
                value: RuntimeValue::FlatBlock,
                operations: Vec::new(),
            }],
            payload: None,
            response: ResponseRule::default(),
        };
        let cdb = build_cdb(
            &command,
            CommandContext {
                flat_block: 0x0102_0304,
                ..CommandContext::default()
            },
        )
        .unwrap();
        assert_eq!(&cdb[2..6], &[1, 2, 3, 4]);
    }

    #[test]
    fn cdb_fields_apply_checked_value_operations() {
        let command = CommandSpec {
            cdb_hex: "fa0a000000000000".into(),
            direction: TransferDirection::ToDevice,
            transfer_bytes: 1536,
            timeout_ms: 60_000,
            fields: vec![FieldBinding {
                offset: 3,
                width: 1,
                endian: Endian::Big,
                value: RuntimeValue::PayloadBytes,
                operations: vec![ValueOperation::Subtract { value: 2048 }],
            }],
            payload: Some(PayloadSource::Caller),
            response: ResponseRule::default(),
        };
        assert!(build_cdb(
            &command,
            CommandContext {
                payload_bytes: 1536,
                ..CommandContext::default()
            }
        )
        .is_err());

        let mut command = command;
        command.fields[0].operations = vec![ValueOperation::Add { value: u64::MAX }];
        assert!(build_cdb(
            &command,
            CommandContext {
                payload_bytes: 1536,
                ..CommandContext::default()
            }
        )
        .is_err());

        command.fields[0].operations = vec![
            ValueOperation::Divide { value: 512 },
            ValueOperation::Subtract { value: 1 },
        ];
        assert_eq!(
            build_cdb(
                &command,
                CommandContext {
                    payload_bytes: 1536,
                    ..CommandContext::default()
                }
            )
            .unwrap(),
            [0xfa, 0x0a, 0, 2, 0, 0, 0, 0]
        );
    }

    #[test]
    fn context_payload_encodes_and_repeats_a_transformed_block_address() {
        let command = CommandSpec {
            cdb_hex: "ea0000000000000000000000000000e2".into(),
            direction: TransferDirection::ToDevice,
            transfer_bytes: 8,
            timeout_ms: 1000,
            fields: Vec::new(),
            payload: Some(PayloadSource::Context {
                record_bytes: 4,
                repeat: 2,
                fill_byte: 0,
                constants: Vec::new(),
                fields: vec![
                    PayloadFieldBinding {
                        offset: 0,
                        width: 3,
                        endian: Endian::Little,
                        value: RuntimeValue::FlatBlock,
                        operations: vec![
                            ValueOperation::Multiply { value: 0x100 },
                            ValueOperation::XorModulo { value: 0x400 },
                            ValueOperation::And { mask: 0x00ff_ffff },
                        ],
                    },
                    PayloadFieldBinding {
                        offset: 3,
                        width: 1,
                        endian: Endian::Little,
                        value: RuntimeValue::FlatBlock,
                        operations: vec![
                            ValueOperation::Multiply { value: 0x100 },
                            ValueOperation::Divide { value: 0x400 },
                            ValueOperation::And { mask: 0xff },
                        ],
                    },
                ],
            }),
            response: ResponseRule::default(),
        };
        let payload = build_context_payload(
            &command,
            CommandContext {
                flat_block: 0x123,
                ..CommandContext::default()
            },
        )
        .unwrap();
        assert_eq!(payload, [0x00, 0x20, 0x01, 0x48, 0x00, 0x20, 0x01, 0x48]);
        validate_context_payload("erase-block", &command).unwrap();
    }

    #[test]
    fn context_payload_rejects_zero_divisors_and_overlap() {
        let command = CommandSpec {
            cdb_hex: "ea0000000000000000000000000000e2".into(),
            direction: TransferDirection::ToDevice,
            transfer_bytes: 4,
            timeout_ms: 1000,
            fields: Vec::new(),
            payload: Some(PayloadSource::Context {
                record_bytes: 4,
                repeat: 1,
                fill_byte: 0,
                constants: Vec::new(),
                fields: vec![
                    PayloadFieldBinding {
                        offset: 0,
                        width: 4,
                        endian: Endian::Little,
                        value: RuntimeValue::FlatBlock,
                        operations: vec![ValueOperation::Divide { value: 0 }],
                    },
                    PayloadFieldBinding {
                        offset: 3,
                        width: 1,
                        endian: Endian::Little,
                        value: RuntimeValue::Block,
                        operations: Vec::new(),
                    },
                ],
            }),
            response: ResponseRule::default(),
        };
        assert!(validate_context_payload("erase-block", &command).is_err());
        assert!(build_context_payload(&command, CommandContext::default()).is_err());
    }

    #[test]
    fn context_payload_combines_constants_and_runtime_fields() {
        let command = CommandSpec {
            cdb_hex: "f1200000000000000000000100000000".into(),
            direction: TransferDirection::ToDevice,
            transfer_bytes: 8,
            timeout_ms: 1000,
            fields: Vec::new(),
            payload: Some(PayloadSource::Context {
                record_bytes: 8,
                repeat: 1,
                fill_byte: 0,
                constants: vec![PayloadConstantBinding {
                    offset: 2,
                    width: 2,
                    endian: Endian::Big,
                    value: 1,
                }],
                fields: vec![
                    PayloadFieldBinding {
                        offset: 0,
                        width: 1,
                        endian: Endian::Big,
                        value: RuntimeValue::FlatBlock,
                        operations: vec![ValueOperation::Divide { value: 0x400 }],
                    },
                    PayloadFieldBinding {
                        offset: 4,
                        width: 2,
                        endian: Endian::Big,
                        value: RuntimeValue::FlatBlock,
                        operations: vec![ValueOperation::Modulo { value: 0x400 }],
                    },
                ],
            }),
            response: ResponseRule::default(),
        };
        validate_context_payload("erase-block", &command).unwrap();
        assert_eq!(
            build_context_payload(
                &command,
                CommandContext {
                    flat_block: 0x923,
                    ..CommandContext::default()
                }
            )
            .unwrap(),
            [0x02, 0x00, 0x00, 0x01, 0x01, 0x23, 0x00, 0x00]
        );
    }

    #[test]
    fn two_slot_state_keeps_latest_valid_generation() {
        let mut file = tempfile::tempfile().unwrap();
        let mut state = ControllerRunState {
            schema: STATE_SCHEMA,
            sequence: 0,
            plan_hash: "p".into(),
            profile_id: "x".into(),
            profile_sha256: "a".repeat(64),
            recipe_sha256: "b".repeat(64),
            controller_id: "c".into(),
            firmware: "f".into(),
            nand_id: "n".into(),
            service_mode: "normal".into(),
            phase: "new".into(),
            old_bbt_sha256: String::new(),
            new_bbt_sha256: String::new(),
            generation: 0,
            user_blocks: 0,
            spare_blocks: 0,
            blocks: Vec::new(),
            in_flight: None,
        };
        store_state(&mut file, &mut state).unwrap();
        state.phase = "inventory-complete".into();
        store_state(&mut file, &mut state).unwrap();
        let loaded = load_state(&mut file).unwrap().unwrap();
        assert_eq!(loaded.sequence, 1);
        assert_eq!(loaded.phase, "inventory-complete");
    }

    #[test]
    fn service_resume_accepts_only_known_durable_states() {
        let mut state = ControllerRunState {
            schema: STATE_SCHEMA,
            sequence: 0,
            plan_hash: "p".into(),
            profile_id: "x".into(),
            profile_sha256: "a".repeat(64),
            recipe_sha256: "b".repeat(64),
            controller_id: "c".into(),
            firmware: "f".into(),
            nand_id: "n".into(),
            service_mode: "normal".into(),
            phase: "new".into(),
            old_bbt_sha256: String::new(),
            new_bbt_sha256: String::new(),
            generation: 0,
            user_blocks: 0,
            spare_blocks: 0,
            blocks: Vec::new(),
            in_flight: None,
        };
        assert!(!state.service_mode_transition_active().unwrap());
        for mode in [
            "entry-command-pending",
            "entry-reenumerating",
            "loader-command-pending",
            "loader-reenumerating",
            "in-service",
            "exit-command-pending",
            "exit-reenumerating",
        ] {
            state.service_mode = mode.into();
            assert!(state.service_mode_transition_active().unwrap());
        }
        state.service_mode = "unknown-service-state".into();
        assert!(state.service_mode_transition_active().is_err());
    }

    #[test]
    fn two_slot_state_falls_back_after_torn_latest_descriptor() {
        let mut file = tempfile::tempfile().unwrap();
        let mut state = ControllerRunState {
            schema: STATE_SCHEMA,
            sequence: 0,
            plan_hash: "p".into(),
            profile_id: "x".into(),
            profile_sha256: "a".repeat(64),
            recipe_sha256: "b".repeat(64),
            controller_id: "c".into(),
            firmware: "f".into(),
            nand_id: "n".into(),
            service_mode: "normal".into(),
            phase: "first".into(),
            old_bbt_sha256: String::new(),
            new_bbt_sha256: String::new(),
            generation: 0,
            user_blocks: 0,
            spare_blocks: 0,
            blocks: Vec::new(),
            in_flight: None,
        };
        store_state(&mut file, &mut state).unwrap();
        state.phase = "second".into();
        store_state(&mut file, &mut state).unwrap();
        file.seek(SeekFrom::Start(descriptor_offset(1))).unwrap();
        file.write_all(&[0u8; STATE_DESCRIPTOR_BYTES]).unwrap();
        file.sync_all().unwrap();
        let loaded = load_state(&mut file).unwrap().unwrap();
        assert_eq!(loaded.sequence, 0);
        assert_eq!(loaded.phase, "first");
    }

    #[test]
    fn allocated_state_without_a_committed_descriptor_is_uninitialized() {
        let mut file = tempfile::tempfile().unwrap();
        file.set_len(STATE_FILE_BYTES).unwrap();
        assert!(load_state(&mut file).unwrap().is_none());
    }

    #[test]
    fn initialized_state_with_corrupt_descriptors_is_rejected() {
        let mut file = tempfile::tempfile().unwrap();
        file.set_len(STATE_FILE_BYTES).unwrap();
        file.write_all(b"corrupt").unwrap();
        assert!(load_state(&mut file).is_err());
    }

    #[test]
    fn exact_nand_id_rejects_empty_bus_values() {
        assert_eq!(exact_nand_id_bytes("0x98de94827656").unwrap().len(), 6);
        assert!(exact_nand_id_bytes("000000").is_err());
        assert!(exact_nand_id_bytes("ffffff").is_err());
        assert!(exact_nand_id_bytes("xyz").is_err());
    }

    #[test]
    fn exact_controller_identity_rejects_missing_and_empty_values() {
        assert_eq!(
            exact_controller_identity_value(Some("0x8200263010")).unwrap(),
            [0x82, 0x00, 0x26, 0x30, 0x10]
        );
        assert!(exact_controller_identity_value(None).is_err());
        assert!(exact_controller_identity_value(Some("")).is_err());
        assert!(exact_controller_identity_value(Some("0000")).is_err());
        assert!(exact_controller_identity_value(Some("ffff")).is_err());
    }

    #[test]
    fn configurable_checksums_match_known_vectors() {
        let input = b"123456789";
        let crc32 = ChecksumAlgorithm::Crc {
            width: 4,
            polynomial: 0xedb8_8320,
            initial: 0xffff_ffff,
            xor_out: 0xffff_ffff,
            reflected: true,
        };
        assert_eq!(checksum_value(&crc32, input).unwrap(), 0xcbf4_3926);

        let crc16 = ChecksumAlgorithm::Crc {
            width: 2,
            polynomial: 0x1021,
            initial: 0xffff,
            xor_out: 0,
            reflected: false,
        };
        assert_eq!(checksum_value(&crc16, input).unwrap(), 0x29b1);

        let sum = ChecksumAlgorithm::Sum {
            width: 1,
            twos_complement: true,
        };
        assert_eq!(checksum_value(&sum, &[1, 2, 3]).unwrap(), 0xfa);
    }

    #[test]
    fn response_fields_must_be_disjoint_and_mask_representable() {
        let overlapping = ResponseRule {
            min_bytes: 4,
            max_bytes: 4,
            fields: vec![
                ResponseField {
                    name: "left".into(),
                    offset: 0,
                    width: 2,
                    ..ResponseField::default()
                },
                ResponseField {
                    name: "right".into(),
                    offset: 1,
                    width: 1,
                    ..ResponseField::default()
                },
            ],
            ..ResponseRule::default()
        };
        assert!(validate_response("test", &overlapping).is_err());

        let impossible_mask = ResponseRule {
            min_bytes: 1,
            max_bytes: 1,
            fields: vec![ResponseField {
                name: "status".into(),
                offset: 0,
                width: 1,
                mask: 0x1ff,
                ..ResponseField::default()
            }],
            ..ResponseRule::default()
        };
        assert!(validate_response("test", &impossible_mask).is_err());
    }

    #[test]
    fn response_payload_excludes_signed_envelope() {
        let command = CommandSpec {
            cdb_hex: "f00000000000".into(),
            direction: TransferDirection::FromDevice,
            transfer_bytes: 12,
            timeout_ms: 1000,
            fields: Vec::new(),
            payload: None,
            response: ResponseRule {
                min_bytes: 12,
                max_bytes: 12,
                prefix_hex: "4e43".into(),
                payload_offset: 4,
                payload_bytes: 8,
                fields: Vec::new(),
            },
        };
        let data = [b'N', b'C', 1, 0, 10, 11, 12, 13, 14, 15, 16, 17];
        decode_response(&command, &data).unwrap();
        assert_eq!(response_payload(&command, &data).unwrap(), &data[4..]);
    }

    #[test]
    fn generated_metadata_has_fixed_transfer_size_and_prepare_marker() {
        let state = ControllerRunState {
            schema: STATE_SCHEMA,
            sequence: 1,
            plan_hash: "p".into(),
            profile_id: "x".into(),
            profile_sha256: "a".repeat(64),
            recipe_sha256: "b".repeat(64),
            controller_id: "c".into(),
            firmware: "f".into(),
            nand_id: "n".into(),
            service_mode: "in-service".into(),
            phase: "qualification-complete".into(),
            old_bbt_sha256: String::new(),
            new_bbt_sha256: String::new(),
            generation: 7,
            user_blocks: 100,
            spare_blocks: 8,
            blocks: vec![
                BlockRecord {
                    flat: 0,
                    disposition: BlockDisposition::FactoryBad,
                    historical_rbb: false,
                    erase_attempts: 0,
                    corrected_bits: 0,
                    read_retries: 0,
                    read_latency_ms: 0,
                    failure: String::new(),
                },
                BlockRecord {
                    flat: 1,
                    disposition: BlockDisposition::Qualified,
                    historical_rbb: false,
                    erase_attempts: 1,
                    corrected_bits: 0,
                    read_retries: 0,
                    read_latency_ms: 0,
                    failure: String::new(),
                },
            ],
            in_flight: None,
        };
        let mut header = vec![0xff; 64];
        header[..4].copy_from_slice(b"NBBT");
        let layout = MetadataTableLayout {
            header_hex: hex::encode(header),
            fill_byte: 0xff,
            entry_stride: 8,
            address: BlockAddressLayout::Flat {
                offset: 0,
                width: 4,
                endian: Endian::Little,
            },
            state_offset: 4,
            factory_bad_value: 1,
            quarantined_value: 2,
            system_value: 3,
            generation_offset: 4,
            generation_width: 8,
            generation_endian: Endian::Little,
            count_offset: 12,
            count_width: 4,
            count_endian: Endian::Little,
            checksum: ChecksumLayout {
                algorithm: ChecksumAlgorithm::Crc {
                    width: 4,
                    polynomial: 0xedb8_8320,
                    initial: 0xffff_ffff,
                    xor_out: 0xffff_ffff,
                    reflected: true,
                },
                offset: 16,
                endian: Endian::Little,
                start: 0,
                length: 63,
            },
            commit_offset: 63,
            prepare_value: 0xff,
            commit_value: 0xa5,
            maximum_bytes: 80,
        };
        let geometry = NandGeometryPolicy {
            channels: 1,
            chips_per_channel: 1,
            luns_per_chip: 1,
            planes_per_lun: 1,
            blocks_per_lun: 16,
            pages_per_block: 16,
            page_bytes: 512,
            oob_bytes: 16,
            address_cycles: 3,
            bits_per_cell: 1,
            bad_block_marker_pages: vec![0],
            bad_block_marker_offsets: vec![0],
            randomizer: "none".into(),
            read_retry: "none".into(),
            ecc_layout: "test".into(),
        };
        let bbt = build_bbt(&state, &layout, &geometry).unwrap();
        assert_eq!(bbt.len(), 80);
        assert_eq!(bbt[63], 0xff);
        assert_eq!(u32::from_le_bytes(bbt[12..16].try_into().unwrap()), 1);
        assert_eq!(u32::from_le_bytes(bbt[64..68].try_into().unwrap()), 0);

        let capacity_layout = CapacityPayloadLayout {
            header_hex: "43415000".into(),
            fill_byte: 0,
            value_offset: 4,
            value_width: 8,
            value_endian: Endian::Big,
            value: CapacityValue::UserBytes,
            total_bytes: 12,
        };
        let capacity = build_capacity(100, 4096, &capacity_layout).unwrap();
        assert_eq!(&capacity[..4], b"CAP\0");
        assert_eq!(
            u64::from_be_bytes(capacity[4..12].try_into().unwrap()),
            409_600
        );
    }

    #[test]
    fn plane_address_roundtrips_to_flat_block() {
        let geometry = NandGeometryPolicy {
            channels: 2,
            chips_per_channel: 2,
            luns_per_chip: 2,
            planes_per_lun: 2,
            blocks_per_lun: 16,
            pages_per_block: 16,
            page_bytes: 512,
            oob_bytes: 16,
            address_cycles: 3,
            bits_per_cell: 1,
            bad_block_marker_pages: vec![0],
            bad_block_marker_offsets: vec![0],
            randomizer: "none".into(),
            read_retry: "none".into(),
            ecc_layout: "test".into(),
        };
        let byte = |offset| IntegerLayout {
            offset,
            width: 1,
            endian: Endian::Big,
        };
        let address = BlockAddressLayout::CoordinatesWithPlane {
            channel: byte(0),
            chip: byte(1),
            lun: byte(2),
            plane: byte(3),
            block_in_plane: byte(4),
        };
        let mut encoded = [0u8; 8];
        encode_block_address(&mut encoded, 0, &address, 119, &geometry).unwrap();
        assert_eq!(
            decode_block_address(&encoded, 0, &address, &geometry).unwrap(),
            119
        );
    }
}
