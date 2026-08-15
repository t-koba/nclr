//! Clean-room host-side contract for Silicon Motion UFDIF raw-flash commands.
//!
//! The layouts in this module were recovered from the named exports of the
//! exact genuine `UFDIF.dll` identified below. They describe the factory ABI;
//! they do not establish that an arbitrary SMI controller implements it. An
//! exact controller, firmware, NAND and service-artifact tuple is still
//! required before hardware execution can be authorized.

use crate::errors::{Error, Result};
use encoding_rs::GBK;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

pub const UFDIF_SOURCE_SHA256: &str =
    "5e8f951f1e729abcd66c33e42995e16c2ad43994919371245f87881b0ab6a5c5";
pub const REVIEWED_UFDIF_COMMAND_COUNT: usize = 53;
pub const FORCE_FLASH_SOURCE_SHA256: &str =
    "651cf8b3bc642289046d05aba4ccc8003977e5b3240661797c4edaecccc1b507";
pub const MEM_FILE_SOURCE_SHA256: &str =
    "a5de156e2b51d8664bc47870231f52b4c6e61bebf4ad600aee1696f1d6d9a744";
pub const SMIMPTOOL32_SOURCE_SHA256: &str =
    "9de3b5326a79eb446e0c8801f96fd1ad4ee0dfd5dd264cd2070664824f64455a";
pub const FORCE_FLASH_PARSER_ROUTINE_VA: u32 = 0x004e_2ed8;
pub const FORCE_FLASH_SCAN_FORMAT_VA: u32 = 0x006f_c380;
pub const FORCE_FLASH_SCAN_CALL_VA: u32 = 0x004e_35f7;
pub const FORCE_FLASH_HOST_POPULATE_VA: u32 = 0x004e_55c4;
pub const FORCE_FLASH_HOST_MIRROR_ROUTINE_VA: u32 = 0x004d_3031;
pub const FORCE_FLASH_HOST_RECORD_OFFSET: u32 = 0x001a_6ff0;
pub const FORCE_FLASH_HOST_MIRROR_OFFSET: u32 = 0x001a_7018;
pub const FORCE_FLASH_HOST_RECORD_BYTES: usize = 40;
pub const FORCE_FLASH_TYPE_PARAMETER_COUNT: usize = 7;
pub const FORCE_FLASH_SETTING_PARAMETER_COUNT: usize = 20;
pub const FORCE_FLASH_SETTING_HOST_BYTES: usize = 24;
pub const FORCE_FLASH_CONTROLLER_ADDRESS: u32 = 0xc000_1b80;
pub const FORCE_FLASH_CONTROLLER_SPAN_BYTES: usize = 28;
pub const SM3280_LOW_LEVEL_SCRIPT_SOURCE_SHA256: &str =
    "29d6e459119aef8fbac44eee06bf60f339e730a87bd48c64143f1fcf06e5c7d0";
pub const SM3280_LOW_LEVEL_IINFO_FILENAME_VA: u32 = 0x100a_e4d4;
pub const SM3280_LOW_LEVEL_IINFO_PATH_APPEND_CALL_VA: u32 = 0x1003_b23a;
pub const SM3280_LOW_LEVEL_IINFO_READ_CALL_VA: u32 = 0x1003_b297;
pub const SM3280_LOW_LEVEL_SET_INFO_CALL_VA: u32 = 0x1003_b2b3;
pub const SM3280_LOW_LEVEL_SET_INFO_WRAPPER_VA: u32 = 0x1005_9370;
pub const SM3280_LOW_LEVEL_SET_INFO_INDIRECT_CALL_VA: u32 = 0x1005_940c;
pub const SM3280_LOW_LEVEL_SET_INFO_FUNCTION_SLOT_VA: u32 = 0x100c_3348;
pub const SM3280_LOW_LEVEL_SET_INFO_RESOLUTION_STORE_VA: u32 = 0x1005_5d36;
pub const SM3280_LOW_LEVEL_IINFO_BYTES: usize = 1024;
pub const SMIMP_WRITE_RAM_BUFFER_ROUTINE_VA: u32 = 0x0054_0568;
pub const SMIMP_WRITE_RAM_BUFFER_TRANSPORT_CALL_VA: u32 = 0x0054_05c7;
pub const SMIMP_JUMP_ISP_ROUTINE_VA: u32 = 0x0050_6034;
pub const SMIMP_JUMP_ISP_TRANSPORT_CALL_VA: u32 = 0x0050_6124;
pub const SMIMP_DEFAULT_ISP_ENTRY_ADDRESS: u16 = 0xd000;
pub const SMIMP_IC_1B_ISP_ENTRY_ADDRESS: u16 = 0xc800;
pub const SMIMP_INTERNAL_IC_TABLE_ROW_BYTES: usize = 20;
pub const SMIMP_REVIEWED_32BIT_INTERNAL_IC_COUNT: usize = 7;
pub const SMIMP_SM3281BA_INTERNAL_IC_ROW_VA: u32 = 0x0071_c08c;
pub const SMIMP_SM3281BA_INTERNAL_IC_VERSION: u8 = 0x2c;
pub const SMIMP_SM3281BA_INTERNAL_IC_RAW_SECOND_FIELD: u16 = 0x2000;
pub const SMIMP_SM3281BA_CHIP_CODE: u16 = 0x3281;
pub const SMIMP_SM3281BA_NAME_POINTER_VA: u32 = 0x0072_7a84;
pub const SMIMP_SM3281BA_SHORT_NAME_POINTER_VA: u32 = 0x0072_7a90;
pub const SMIMP_SERVICE_ARTIFACT_LOADER_ROUTINE_VA: u32 = 0x0053_0c0e;
pub const SMIMP_SERVICE_ARTIFACT_TRANSPORT_CALL_VA: u32 = 0x0053_0fe8;
pub const SMIMP_SERVICE_ARTIFACT_MAX_BYTES: usize = 0x1_0000;
pub const SMIMP_SERVICE_ARTIFACT_32BIT_IC_MINIMUM: u8 = 0x28;
pub const SMIMP_SERVICE_ARTIFACT_32BIT_IC_MAXIMUM: u8 = 0x2e;
pub const SMIMP_SERVICE_ARTIFACT_32BIT_ADDRESS_BRANCH_VA: u32 = 0x0053_0eeb;
pub const SMIMP_FIND_INFO_CALLER_ROUTINE_VA: u32 = 0x0053_03a9;
pub const SMIMP_FIND_INFO_LOADER_CALL_VA: u32 = 0x0053_05f7;
pub const SMIMP_SM3281BA_FIND_INFO_ENTRY_ADDRESS: u32 = 0x0001_8c00;
pub const SMIMP_SORTING_COMMAND_CALLER_ROUTINE_VA: u32 = 0x0057_153c;
pub const SMIMP_SORTING_COMMAND_LOADER_CALL_VA: u32 = 0x0057_16e7;
pub const SMIMP_SM3281BA_SORTING_COMMAND_ENTRY_ADDRESS: u32 = 0x0000_9000;
pub const SMIMP_GEN_INFO_COMMAND_CALLER_ROUTINE_VA: u32 = 0x0057_483f;
pub const SMIMP_GEN_INFO_COMMAND_LOADER_CALL_VA: u32 = 0x0057_4b4e;
pub const SMIMP_SM3281BA_GEN_INFO_COMMAND_ENTRY_ADDRESS: u32 = 0x0001_0000;
pub const SMIMP_ROM_CODE_TRANSITION_ROUTINE_VA: u32 = 0x0051_7ab1;
pub const SMIMP_ROM_CODE_TRANSITION_TRANSPORT_CALL_VA: u32 = 0x0051_7bba;
pub const SMIMP_IGO2ROM_SOURCE_LOAD_ROUTINE_VA: u32 = 0x0052_1b9f;
pub const SMIMP_IGO2ROM_SOURCE_LOAD_CALL_VA: u32 = 0x0051_7b96;
pub const SMIMP_IGO2ROM_COMMAND_ROUTINE_VA: u32 = 0x0052_190b;
pub const SMIMP_IGO2ROM_COMMAND_CALL_VA: u32 = 0x0052_1d09;
pub const SMIMP_IGO2ROM_TRANSPORT_CALL_VA: u32 = 0x0052_1ac0;
pub const SMIMP_IGO2ROM_FILENAME_VA: u32 = 0x0070_25a8;
pub const SMIMP_SM3281BA_IGO2ROM_ENTRY_ADDRESS: u32 = 0x0001_8000;
pub const SMIMP_SM3281_DOWNLOAD_ISP_ROUTINE_VA: u32 = 0x0055_6195;
pub const SMIMP_SM3281_BUILD_MODIFIED_ISP_ROUTINE_VA: u32 = 0x0055_5b80;
pub const SMIMP_SM3281_GET_ISP_BLOCK_ROUTINE_VA: u32 = 0x0057_20d6;
pub const SMIMP_SM3281_ERASE_SYSTEM_BLOCK_ROUTINE_VA: u32 = 0x0057_23a0;
pub const SMIMP_SM3281_DOWNLOAD_SINGLE_ISP_ROUTINE_VA: u32 = 0x0055_2434;
pub const SMIMP_SM3281_VERIFY_SINGLE_ISP_ROUTINE_VA: u32 = 0x0055_f8a7;
pub const SMIMP_SM3281_FROM_DEVICE_TRANSPORT_VA: u32 = 0x0054_fec3;
pub const SMIMP_SM3281_TO_DEVICE_TRANSPORT_VA: u32 = 0x0054_ff15;
pub const SMIMP_SM3281_SYSTEM_BLOCK_CANDIDATES: usize = 3;
pub const SMIMP_SM3281_ISP_HEADER_BYTES: usize = 1024;
pub const SMIMP_SM3281_MAX_ISP_PAGE_BYTES: usize = 16 * 1024;
pub const SM3281BA_SANDISK_19NM_CONTROLLER_ID: &str = "smi-sm3281ba";
pub const SM3281BA_SANDISK_19NM_NAND_ID: &str = "4548a7937e50";
pub const SM3281BA_SANDISK_19NM_ISP_SOURCE_SHA256: &str =
    "78c70d483d1b4e8574d56335c326a15ba6390a3cb14f8e10a6f73c6333d7b19a";
pub const SM3281BA_SANDISK_19NM_ISP_BYTES: u64 = 245_760;
pub const SM3281BA_SORTING_COMMAND_SOURCE_SHA256: &str =
    "91c39baf277351cdb71cf22f2db63fe43f0358af51a2ea19e9dc1c1045cb4764";
pub const SM3281BA_SORTING_COMMAND_BYTES: u64 = 48_128;
pub const SM3281BA_GEN_INFO_COMMAND_SOURCE_SHA256: &str =
    "f5d53397204737548c05e3265255def1b5ef4d3ca697440314fb64a31f9fccc3";
pub const SM3281BA_GEN_INFO_COMMAND_BYTES: u64 = 49_152;
pub const SM3281BA_FIND_INFO_BLOCK_SOURCE_SHA256: &str =
    "765e86f4a7cfe15df7786fcf7b7e4dfeb12a40fd48bdcbd9db43987aa474c416";
pub const SM3281BA_FIND_INFO_BLOCK_BYTES: u64 = 11_264;
pub const SM3281BA_IGO2ROM_SOURCE_SHA256: &str =
    "8105b57fb93e3926a144dba90a569493697a463d2abd28410689f8aadfb41e9b";
pub const SM3281BA_IGO2ROM_BYTES: u64 = 2_048;
pub const SM3281BA_ISP_SETTING_REFERENCE_SIGNATURE_HEX: &str = "cf7700c0801b";
pub const SM3281BA_ISP_SETTING_REFERENCE_OFFSETS: [u32; 4] =
    [0x0000_0056, 0x0003_b080, 0x0003_b604, 0x0003_b89a];
pub const SCRIPT_SELECTION_ROUTINE_VA: u32 = 0x0056_c296;
pub const LOW_LEVEL_CELL_BRANCH_VA: u32 = 0x0056_c3a0;
pub const HIGH_LEVEL_CELL_BRANCH_VA: u32 = 0x0056_c48b;
pub const DIRECT_SET_READ_PARAMETERS_ROUTINE_VA: u32 = 0x1008_0450;
pub const DIRECT_READ_TRIGGER_ROUTINE_VA: u32 = 0x1008_0540;
pub const DIRECT_CHECK_STATUS_ROUTINE_VA: u32 = 0x1007_f750;
pub const DIRECT_CHECK_STATUS_WRAPPER_VA: u32 = 0x1005_9720;
pub const DIRECT_ERASE_FLASH_ROUTINE_VA: u32 = 0x1007_fef0;
pub const DIRECT_ERASE_FLASH_WRAPPER_VA: u32 = 0x1005_ace0;
pub const DIRECT_READ_ECC_TABLE_ROUTINE_VA: u32 = 0x1008_1140;
pub const DIRECT_READ_RETIRED_BLOCK_TABLE_ROUTINE_VA: u32 = 0x1008_1240;
pub const DIRECT_READ_PAGE_DATA_ROUTINE_VA: u32 = 0x1008_1340;
pub const DIRECT_READ_PAGE_DATA_WRAPPER_VA: u32 = 0x1005_c420;
pub const DIRECT_READ_PAGE_DATA_COMPARISON_CALLER_VA: u32 = 0x1002_5fd0;
pub const UFDIF_IMAGE_BASE: u32 = 0x1000_0000;
pub const SECTOR_BYTES: usize = 512;
pub const MAX_SECTORS: usize = u8::MAX as usize;
pub const MAX_SECTOR_TRANSFER_BYTES: usize = MAX_SECTORS * SECTOR_BYTES;
pub const MAX_RAM_TRANSFER_BYTES: usize = 2048;
pub const ECC_TABLE_CHUNK_BYTES: usize = 1024;
pub const MAX_ECC_TABLE_BYTES: usize = 8192;
pub const DIRECT_DATA_CHUNK_BYTES: usize = 16 * 1024;
pub const DIRECT_DATA_GRANULARITY_BYTES: usize = 1024;
pub const UFDIF_BAD_COLUMN_DATA_CHUNK_BYTES: usize = 8 * 1024;
pub const MAX_DIRECT_ECC_TABLE_BYTES: usize = 16 * 1024;
pub const FORCE_FLASH_PARAMETER_COUNT: usize = 27;
pub const RAW_RESEARCH_SYMBOL_COUNT: usize = 18;
pub const MAX_RETRY_TABLE_BYTES: usize = 1024;
pub const MAX_BLOCK_FAIL_BIT_TABLE_BYTES: usize = 2 * 1024;
pub const MAX_DIFF_PAGE_TABLE_BYTES: usize = 8 * 1024;

const MAX_FORCE_FLASH_BYTES: usize = 8 * 1024 * 1024;
const MAX_FORCE_FLASH_LINES: usize = 100_000;
const MAX_FORCE_FLASH_RECORDS: usize = 100_000;
const MAX_MEM_FILE_BYTES: usize = 1024 * 1024;
const MAX_MEM_FILE_LINES: usize = 10_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum NandCellMode {
    Mlc,
    Tlc,
}

impl NandCellMode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mlc => "mlc",
            Self::Tlc => "tlc",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DefaultScriptSelection {
    pub controller_id: String,
    pub cell_mode: NandCellMode,
    pub low_level_generic_name: &'static str,
    pub high_level_generic_name: &'static str,
    pub low_level_artifact_stem_prefix: String,
    pub high_level_artifact_stem_prefix: String,
    pub source_sha256: &'static str,
    pub selection_routine_va: u32,
    pub low_level_cell_branch_va: u32,
    pub high_level_cell_branch_va: u32,
}

fn explicit_cell_marker(value: &str) -> Result<NandCellMode> {
    let markers = value
        .split(|character: char| !character.is_ascii_alphanumeric())
        .filter_map(|token| match token.to_ascii_lowercase().as_str() {
            "mlc" => Some(NandCellMode::Mlc),
            "tlc" => Some(NandCellMode::Tlc),
            "qlc" => None,
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    match markers.len() {
        1 => Ok(*markers
            .iter()
            .next()
            .expect("one-element cell-mode set must have an element")),
        0 if value
            .split(|character: char| !character.is_ascii_alphanumeric())
            .any(|token| token.eq_ignore_ascii_case("qlc")) =>
        {
            Err(Error::Unsupported(
                "SMI reviewed script selection does not cover QLC NAND".into(),
            ))
        }
        0 => Err(Error::Invalid(format!(
            "SMI tuple label {value:?} has no explicit MLC or TLC marker"
        ))),
        _ => Err(Error::Invalid(format!(
            "SMI tuple label {value:?} has conflicting cell-mode markers"
        ))),
    }
}

/// Resolve the NAND cell mode only when independent package labels and the
/// first genuine ForceFlash positional value all agree.
pub fn resolve_cell_mode(
    primary_isp: &str,
    flash_folder: &str,
    force_flash_mode_code: u32,
) -> Result<NandCellMode> {
    let isp_mode = explicit_cell_marker(primary_isp)?;
    let folder_mode = explicit_cell_marker(flash_folder)?;
    let force_mode = match force_flash_mode_code {
        1 => NandCellMode::Mlc,
        2 => NandCellMode::Tlc,
        value => {
            return Err(Error::Unsupported(format!(
                "SMI ForceFlash cell-mode value 0x{value:x} is not recovered"
            )));
        }
    };
    if isp_mode != folder_mode || isp_mode != force_mode {
        return Err(Error::Invalid(format!(
            "SMI tuple cell-mode evidence disagrees: ISP={}, folder={}, ForceFlash={}",
            isp_mode.as_str(),
            folder_mode.as_str(),
            force_mode.as_str()
        )));
    }
    Ok(isp_mode)
}

/// Reproduce the default script-family branch recovered from the reviewed
/// SMIMPTool32 image. An exact FFW DLLHeader assignment takes precedence in
/// the package resolver and therefore does not call this function.
pub fn default_script_selection(
    controller_id: &str,
    cell_mode: NandCellMode,
) -> Result<DefaultScriptSelection> {
    let script_generation = match controller_id {
        "smi-sm3265ab" => "3265",
        "smi-sm3271ab" | "smi-sm3271ad" | "smi-sm3271ba" => "3271",
        "smi-sm3281ab" | "smi-sm3281ba" | "smi-sm3281bb" => "3280",
        _ => {
            return Err(Error::Unsupported(format!(
                "SMI default script generation is not recovered for {controller_id}"
            )));
        }
    };
    let (low_level_generic_name, high_level_generic_name) = match cell_mode {
        NandCellMode::Mlc => ("ScriptGP", "PretestGP"),
        NandCellMode::Tlc => ("ScriptGPTLC", "PretestGPTLC"),
    };
    Ok(DefaultScriptSelection {
        controller_id: controller_id.to_string(),
        cell_mode,
        low_level_generic_name,
        high_level_generic_name,
        low_level_artifact_stem_prefix: format!("{low_level_generic_name}{script_generation}"),
        high_level_artifact_stem_prefix: format!("{high_level_generic_name}{script_generation}"),
        source_sha256: SMIMPTOOL32_SOURCE_SHA256,
        selection_routine_va: SCRIPT_SELECTION_ROUTINE_VA,
        low_level_cell_branch_va: LOW_LEVEL_CELL_BRANCH_VA,
        high_level_cell_branch_va: HIGH_LEVEL_CELL_BRANCH_VA,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum DataDirection {
    ToDevice,
    FromDevice,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DataOutCommand {
    pub cdb: [u8; 16],
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DataInCommand {
    pub cdb: [u8; 16],
    pub transfer_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct DataInChunk {
    pub cdb: [u8; 16],
    pub transfer_bytes: usize,
    pub output_offset: usize,
    pub output_bytes: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct DirectFlashReadRequest {
    pub ce: u8,
    pub page_count: u16,
    pub start_page: u16,
    /// First 32-bit positional value in the reviewed factory ABI.
    pub first_window_value: u32,
    /// Second 32-bit positional value. The genuine constructor encodes the
    /// greater of this value and `first_window_value`.
    pub second_window_value: u32,
    pub discriminator: u8,
}

impl DirectFlashReadRequest {
    pub fn new(
        ce: u8,
        page_count: u16,
        start_page: u16,
        first_window_value: u32,
        second_window_value: u32,
        discriminator: u8,
    ) -> Result<Self> {
        if page_count == 0 {
            return Err(Error::Invalid(
                "SMI direct flash read page count must be nonzero".into(),
            ));
        }
        start_page
            .checked_add(page_count - 1)
            .ok_or_else(|| Error::Invalid("SMI direct flash page range exceeds u16".into()))?;
        Ok(Self {
            ce,
            page_count,
            start_page,
            first_window_value,
            second_window_value,
            discriminator,
        })
    }

    fn descriptor(self) -> Vec<u8> {
        let mut descriptor = vec![0u8; SECTOR_BYTES];
        let canonical_end = self.second_window_value.max(self.first_window_value);
        descriptor[0] = self.ce;
        descriptor[2..4].copy_from_slice(&self.page_count.to_be_bytes());
        descriptor[4..6].copy_from_slice(&self.start_page.to_be_bytes());
        descriptor[8..10].copy_from_slice(&(self.first_window_value as u16).to_be_bytes());
        descriptor[10..12].copy_from_slice(&(canonical_end as u16).to_be_bytes());
        descriptor[12..14].copy_from_slice(&((self.first_window_value >> 16) as u16).to_be_bytes());
        descriptor[14..16].copy_from_slice(&((canonical_end >> 16) as u16).to_be_bytes());
        descriptor
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct BadColumnWriteRequest {
    pub first_byte: u8,
    pub first_u16: u16,
    pub second_u16: u16,
    pub third_u16: u16,
    pub fourth_u16: u16,
    pub second_byte: u8,
    pub third_byte: u8,
}

impl BadColumnWriteRequest {
    fn descriptor(self, parameter_table: &[u8]) -> Result<Vec<u8>> {
        if parameter_table.len() > SECTOR_BYTES {
            return Err(Error::Invalid(format!(
                "SMI bad-column write parameter table exceeds {SECTOR_BYTES} bytes"
            )));
        }
        let mut descriptor = vec![0u8; SECTOR_BYTES];
        descriptor[..parameter_table.len()].copy_from_slice(parameter_table);
        descriptor[..16].fill(0);
        descriptor[0] = self.first_byte;
        descriptor[2..4].copy_from_slice(&self.first_u16.to_be_bytes());
        descriptor[4..6].copy_from_slice(&self.second_u16.to_be_bytes());
        descriptor[8..10].copy_from_slice(&self.third_u16.to_be_bytes());
        descriptor[10..12].copy_from_slice(&self.fourth_u16.max(self.third_u16).to_be_bytes());
        descriptor[12] = self.second_byte;
        descriptor[13] = self.third_byte;
        Ok(descriptor)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewedDirectTransportContract {
    pub source_sha256: &'static str,
    pub set_read_parameters_routine_va: u32,
    pub read_trigger_routine_va: u32,
    pub check_status_routine_va: u32,
    pub check_status_wrapper_va: u32,
    pub erase_flash_routine_va: u32,
    pub erase_flash_wrapper_va: u32,
    pub read_page_data_routine_va: u32,
    pub read_page_data_wrapper_va: u32,
    pub read_page_data_comparison_caller_va: u32,
    pub read_ecc_table_routine_va: u32,
    pub read_retired_block_table_routine_va: u32,
    pub raw_page_sequence: [&'static str; 3],
    pub raw_page_data_command: &'static str,
    pub physical_erase_command: &'static str,
    pub status_trigger_command: &'static str,
    pub ecc_table_command: &'static str,
    pub retired_block_table_command: &'static str,
}

pub fn reviewed_direct_transport_contract() -> ReviewedDirectTransportContract {
    ReviewedDirectTransportContract {
        source_sha256: SM3280_LOW_LEVEL_SCRIPT_SOURCE_SHA256,
        set_read_parameters_routine_va: DIRECT_SET_READ_PARAMETERS_ROUTINE_VA,
        read_trigger_routine_va: DIRECT_READ_TRIGGER_ROUTINE_VA,
        check_status_routine_va: DIRECT_CHECK_STATUS_ROUTINE_VA,
        check_status_wrapper_va: DIRECT_CHECK_STATUS_WRAPPER_VA,
        erase_flash_routine_va: DIRECT_ERASE_FLASH_ROUTINE_VA,
        erase_flash_wrapper_va: DIRECT_ERASE_FLASH_WRAPPER_VA,
        read_page_data_routine_va: DIRECT_READ_PAGE_DATA_ROUTINE_VA,
        read_page_data_wrapper_va: DIRECT_READ_PAGE_DATA_WRAPPER_VA,
        read_page_data_comparison_caller_va: DIRECT_READ_PAGE_DATA_COMPARISON_CALLER_VA,
        read_ecc_table_routine_va: DIRECT_READ_ECC_TABLE_ROUTINE_VA,
        read_retired_block_table_routine_va: DIRECT_READ_RETIRED_BLOCK_TABLE_ROUTINE_VA,
        raw_page_sequence: ["F5/24 data-out", "F5/25 data-out", "F4/37 data-in"],
        raw_page_data_command: "F4/37",
        physical_erase_command: "F5/20 data-out",
        status_trigger_command: "F5/18 data-out",
        ecc_table_command: "F4/33",
        retired_block_table_command: "F4/35",
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewedInfoUploadContract {
    pub source_sha256: &'static str,
    pub ufdif_source_sha256: &'static str,
    pub filename: &'static str,
    pub filename_va: u32,
    pub path_append_call_va: u32,
    pub file_read_call_va: u32,
    pub set_info_call_va: u32,
    pub set_info_wrapper_va: u32,
    pub set_info_indirect_call_va: u32,
    pub set_info_function_slot_va: u32,
    pub set_info_resolution_store_va: u32,
    pub transfer_bytes: usize,
    pub command: &'static str,
    pub host_info_upload_statically_proven: bool,
    pub force_flash_to_info_offsets_statically_proven: bool,
}

/// Return the authenticated `Iinfo.bin` to `LIB_SetInfo` call chain in the
/// reviewed SM3280-generation low-level script DLL.
pub fn reviewed_info_upload_contract() -> ReviewedInfoUploadContract {
    ReviewedInfoUploadContract {
        source_sha256: SM3280_LOW_LEVEL_SCRIPT_SOURCE_SHA256,
        ufdif_source_sha256: UFDIF_SOURCE_SHA256,
        filename: "Iinfo.bin",
        filename_va: SM3280_LOW_LEVEL_IINFO_FILENAME_VA,
        path_append_call_va: SM3280_LOW_LEVEL_IINFO_PATH_APPEND_CALL_VA,
        file_read_call_va: SM3280_LOW_LEVEL_IINFO_READ_CALL_VA,
        set_info_call_va: SM3280_LOW_LEVEL_SET_INFO_CALL_VA,
        set_info_wrapper_va: SM3280_LOW_LEVEL_SET_INFO_WRAPPER_VA,
        set_info_indirect_call_va: SM3280_LOW_LEVEL_SET_INFO_INDIRECT_CALL_VA,
        set_info_function_slot_va: SM3280_LOW_LEVEL_SET_INFO_FUNCTION_SLOT_VA,
        set_info_resolution_store_va: SM3280_LOW_LEVEL_SET_INFO_RESOLUTION_STORE_VA,
        transfer_bytes: SM3280_LOW_LEVEL_IINFO_BYTES,
        command: "F1/14 data-out",
        host_info_upload_statically_proven: true,
        force_flash_to_info_offsets_statically_proven: false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewedServiceArtifactContract {
    pub role: &'static str,
    pub filename: &'static str,
    pub size_bytes: u64,
    pub sha256: &'static str,
    pub marker_offset: u32,
    pub marker_ascii: &'static str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewedInternalIcMappingContract {
    pub source_sha256: &'static str,
    pub table_row_va: u32,
    pub table_row_bytes: usize,
    pub internal_ic_version: u8,
    pub raw_second_field: u16,
    pub chip_code: u16,
    pub controller_name_pointer_va: u32,
    pub controller_name: &'static str,
    pub short_name_pointer_va: u32,
    pub short_name: &'static str,
    pub mapping_statically_proven: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewedServiceArtifactLoadContract {
    pub role: &'static str,
    pub internal_ic_version: u8,
    pub host_routine_va: u32,
    pub command_constructor_call_va: u32,
    pub command_constructor_routine_va: u32,
    pub transport_call_va: u32,
    pub command: &'static str,
    pub address_layout: &'static str,
    pub entry_address: u32,
    pub source_size_bytes: u64,
    pub transfer_sectors: u8,
    pub mapping_statically_proven: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewedServiceLoaderContract {
    pub source_sha256: &'static str,
    pub write_ram_buffer_routine_va: u32,
    pub write_ram_buffer_transport_call_va: u32,
    pub write_ram_command: &'static str,
    pub write_ram_address_layout: &'static str,
    pub write_ram_transfer_alignment_bytes: usize,
    pub write_ram_maximum_sectors: usize,
    pub legacy_jump_isp_routine_va: u32,
    pub legacy_jump_isp_transport_call_va: u32,
    pub legacy_jump_isp_command: &'static str,
    pub legacy_default_entry_address: u16,
    pub legacy_ic_1b_entry_address: u16,
    pub service_artifact_loader_routine_va: u32,
    pub service_artifact_transport_call_va: u32,
    pub service_artifact_maximum_bytes: usize,
    pub service_artifact_32bit_ic_range: [u8; 2],
    pub service_artifact_32bit_address_branch_va: u32,
    pub host_command_constructors_statically_proven: bool,
    pub selected_artifact_chunk_map_statically_proven: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewedRomCodeTransitionContract {
    pub source_sha256: &'static str,
    pub internal_ic_version: u8,
    pub transition_routine_va: u32,
    pub transition_transport_call_va: u32,
    pub transition_command: &'static str,
    pub transition_flag_layout: &'static str,
    pub igo2rom_filename: &'static str,
    pub igo2rom_filename_va: u32,
    pub igo2rom_source_load_routine_va: u32,
    pub igo2rom_source_load_call_va: u32,
    pub igo2rom_command_routine_va: u32,
    pub igo2rom_command_call_va: u32,
    pub igo2rom_transport_call_va: u32,
    pub igo2rom_entry_address: u32,
    pub path_statically_proven: bool,
    pub command_statically_proven: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewedSm3281IspProgrammingContract {
    pub source_sha256: &'static str,
    pub download_isp_routine_va: u32,
    pub build_modified_isp_routine_va: u32,
    pub get_isp_block_routine_va: u32,
    pub erase_system_block_routine_va: u32,
    pub download_single_isp_routine_va: u32,
    pub verify_single_isp_routine_va: u32,
    pub from_device_transport_va: u32,
    pub to_device_transport_va: u32,
    pub system_block_candidate_count: usize,
    pub system_block_header_bytes: usize,
    pub maximum_isp_page_bytes: usize,
    pub discovery_markers: [&'static str; 3],
    pub discovery_command: &'static str,
    pub erase_command: &'static str,
    pub program_command: &'static str,
    pub verify_command: &'static str,
    pub command_constructors_statically_proven: bool,
    pub page_address_sequence_statically_proven: bool,
    pub composite_isp_modification_statically_proven: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewedControllerSettingReferenceContract {
    pub source_sha256: &'static str,
    pub source_size_bytes: u64,
    pub source_header_ascii: &'static str,
    pub source_version_ascii: &'static str,
    pub source_version_offset: u32,
    pub controller_symbol: &'static str,
    pub controller_address: u32,
    pub controller_span_bytes: usize,
    pub reference_signature_hex: &'static str,
    pub reference_offsets: [u32; 4],
    pub address_references_authenticated: bool,
    pub field_semantics_statically_proven: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ReviewedSm3281BaSandisk19nmContract {
    pub controller_id: &'static str,
    pub nand_id: &'static str,
    pub internal_ic: ReviewedInternalIcMappingContract,
    pub artifacts: [ReviewedServiceArtifactContract; 5],
    pub artifact_loads: [ReviewedServiceArtifactLoadContract; 4],
    pub rom_code_transition: ReviewedRomCodeTransitionContract,
    pub isp_programming: ReviewedSm3281IspProgrammingContract,
    pub info_upload: ReviewedInfoUploadContract,
    pub service_loader: ReviewedServiceLoaderContract,
    pub controller_setting: ReviewedControllerSettingReferenceContract,
    pub static_contract_complete: bool,
    pub production_eligible: bool,
}

pub fn reviewed_sm3281ba_internal_ic_mapping() -> ReviewedInternalIcMappingContract {
    reviewed_32bit_internal_ic_mappings()[4]
}

/// Return every controller row selected by the reviewed host's 32-bit
/// service-artifact address branch. The raw table fields are retained even
/// where a controller name does not match the table's family code.
pub fn reviewed_32bit_internal_ic_mappings(
) -> [ReviewedInternalIcMappingContract; SMIMP_REVIEWED_32BIT_INTERNAL_IC_COUNT] {
    [
        reviewed_internal_ic_mapping(ReviewedInternalIcRow {
            table_row_va: 0x0071_c03c,
            internal_ic_version: 0x28,
            raw_second_field: 0xffff,
            chip_code: 0x3280,
            controller_name_pointer_va: 0x0072_7a34,
            controller_name: "SM3280AB",
            short_name_pointer_va: 0x0072_7a40,
            short_name: "3280AB",
        }),
        reviewed_internal_ic_mapping(ReviewedInternalIcRow {
            table_row_va: 0x0071_c050,
            internal_ic_version: 0x29,
            raw_second_field: 0x2000,
            chip_code: 0x3280,
            controller_name_pointer_va: 0x0072_7a48,
            controller_name: "SM3280BA",
            short_name_pointer_va: 0x0072_7a54,
            short_name: "3280BA",
        }),
        reviewed_internal_ic_mapping(ReviewedInternalIcRow {
            table_row_va: 0x0071_c064,
            internal_ic_version: 0x2a,
            raw_second_field: 0x2000,
            chip_code: 0x3280,
            controller_name_pointer_va: 0x0072_7a5c,
            controller_name: "SM3280BB",
            short_name_pointer_va: 0x0072_7a68,
            short_name: "3280BB",
        }),
        reviewed_internal_ic_mapping(ReviewedInternalIcRow {
            table_row_va: 0x0071_c078,
            internal_ic_version: 0x2b,
            raw_second_field: 0x2000,
            chip_code: 0x3281,
            controller_name_pointer_va: 0x0072_7a70,
            controller_name: "SM3281AB",
            short_name_pointer_va: 0x0072_7a7c,
            short_name: "3281AB",
        }),
        reviewed_internal_ic_mapping(ReviewedInternalIcRow {
            table_row_va: SMIMP_SM3281BA_INTERNAL_IC_ROW_VA,
            internal_ic_version: SMIMP_SM3281BA_INTERNAL_IC_VERSION,
            raw_second_field: SMIMP_SM3281BA_INTERNAL_IC_RAW_SECOND_FIELD,
            chip_code: SMIMP_SM3281BA_CHIP_CODE,
            controller_name_pointer_va: SMIMP_SM3281BA_NAME_POINTER_VA,
            controller_name: "SM3281BA",
            short_name_pointer_va: SMIMP_SM3281BA_SHORT_NAME_POINTER_VA,
            short_name: "3281BA",
        }),
        reviewed_internal_ic_mapping(ReviewedInternalIcRow {
            table_row_va: 0x0071_c0a0,
            internal_ic_version: 0x2d,
            raw_second_field: 0x2000,
            chip_code: 0x3281,
            controller_name_pointer_va: 0x0072_7a98,
            controller_name: "SM3281BB",
            short_name_pointer_va: 0x0072_7aa4,
            short_name: "3281BB",
        }),
        reviewed_internal_ic_mapping(ReviewedInternalIcRow {
            table_row_va: 0x0071_c0b4,
            internal_ic_version: 0x2e,
            raw_second_field: 0x2000,
            chip_code: 0x3281,
            controller_name_pointer_va: 0x0072_7aac,
            controller_name: "SM3259AA",
            short_name_pointer_va: 0x0072_7ab8,
            short_name: "3259AA",
        }),
    ]
}

/// Reviewed row of the internal-IC mapping table (the SM32X host table
/// entry that statically proves a controller revision's service-artifact
/// address branch).
struct ReviewedInternalIcRow {
    table_row_va: u32,
    internal_ic_version: u8,
    raw_second_field: u16,
    chip_code: u16,
    controller_name_pointer_va: u32,
    controller_name: &'static str,
    short_name_pointer_va: u32,
    short_name: &'static str,
}

fn reviewed_internal_ic_mapping(row: ReviewedInternalIcRow) -> ReviewedInternalIcMappingContract {
    ReviewedInternalIcMappingContract {
        source_sha256: SMIMPTOOL32_SOURCE_SHA256,
        table_row_va: row.table_row_va,
        table_row_bytes: SMIMP_INTERNAL_IC_TABLE_ROW_BYTES,
        internal_ic_version: row.internal_ic_version,
        raw_second_field: row.raw_second_field,
        chip_code: row.chip_code,
        controller_name_pointer_va: row.controller_name_pointer_va,
        controller_name: row.controller_name,
        short_name_pointer_va: row.short_name_pointer_va,
        short_name: row.short_name,
        mapping_statically_proven: true,
    }
}

/// Resolve only controller revisions that have an exact row in the reviewed
/// host table and use its 32-bit service-artifact address branch.
pub fn reviewed_32bit_internal_ic_mapping_for_controller(
    controller_id: &str,
) -> Result<ReviewedInternalIcMappingContract> {
    let index = match controller_id {
        "smi-sm3280ab" => 0,
        "smi-sm3280ba" => 1,
        "smi-sm3280bb" => 2,
        "smi-sm3281ab" => 3,
        "smi-sm3281ba" => 4,
        "smi-sm3281bb" => 5,
        "smi-sm3259aa" => 6,
        _ => {
            return Err(Error::Unsupported(format!(
                "SMI controller {controller_id} has no reviewed 32-bit internal-IC mapping"
            )))
        }
    };
    Ok(reviewed_32bit_internal_ic_mappings()[index])
}

pub fn reviewed_sm3281ba_service_artifact_loads() -> [ReviewedServiceArtifactLoadContract; 4] {
    [
        ReviewedServiceArtifactLoadContract {
            role: "sortingcmd",
            internal_ic_version: SMIMP_SM3281BA_INTERNAL_IC_VERSION,
            host_routine_va: SMIMP_SORTING_COMMAND_CALLER_ROUTINE_VA,
            command_constructor_call_va: SMIMP_SORTING_COMMAND_LOADER_CALL_VA,
            command_constructor_routine_va: SMIMP_SERVICE_ARTIFACT_LOADER_ROUTINE_VA,
            transport_call_va: SMIMP_SERVICE_ARTIFACT_TRANSPORT_CALL_VA,
            command: "F1/0A data-out",
            address_layout: "CDB bytes 2..5 contain the 32-bit big-endian entry address",
            entry_address: SMIMP_SM3281BA_SORTING_COMMAND_ENTRY_ADDRESS,
            source_size_bytes: SM3281BA_SORTING_COMMAND_BYTES,
            transfer_sectors: 94,
            mapping_statically_proven: true,
        },
        ReviewedServiceArtifactLoadContract {
            role: "geninfocmd",
            internal_ic_version: SMIMP_SM3281BA_INTERNAL_IC_VERSION,
            host_routine_va: SMIMP_GEN_INFO_COMMAND_CALLER_ROUTINE_VA,
            command_constructor_call_va: SMIMP_GEN_INFO_COMMAND_LOADER_CALL_VA,
            command_constructor_routine_va: SMIMP_SERVICE_ARTIFACT_LOADER_ROUTINE_VA,
            transport_call_va: SMIMP_SERVICE_ARTIFACT_TRANSPORT_CALL_VA,
            command: "F1/0A data-out",
            address_layout: "CDB bytes 2..5 contain the 32-bit big-endian entry address",
            entry_address: SMIMP_SM3281BA_GEN_INFO_COMMAND_ENTRY_ADDRESS,
            source_size_bytes: SM3281BA_GEN_INFO_COMMAND_BYTES,
            transfer_sectors: 96,
            mapping_statically_proven: true,
        },
        ReviewedServiceArtifactLoadContract {
            role: "findinfoblock",
            internal_ic_version: SMIMP_SM3281BA_INTERNAL_IC_VERSION,
            host_routine_va: SMIMP_FIND_INFO_CALLER_ROUTINE_VA,
            command_constructor_call_va: SMIMP_FIND_INFO_LOADER_CALL_VA,
            command_constructor_routine_va: SMIMP_SERVICE_ARTIFACT_LOADER_ROUTINE_VA,
            transport_call_va: SMIMP_SERVICE_ARTIFACT_TRANSPORT_CALL_VA,
            command: "F1/0A data-out",
            address_layout: "CDB bytes 2..5 contain the 32-bit big-endian entry address",
            entry_address: SMIMP_SM3281BA_FIND_INFO_ENTRY_ADDRESS,
            source_size_bytes: SM3281BA_FIND_INFO_BLOCK_BYTES,
            transfer_sectors: 22,
            mapping_statically_proven: true,
        },
        ReviewedServiceArtifactLoadContract {
            role: "igo2rom",
            internal_ic_version: SMIMP_SM3281BA_INTERNAL_IC_VERSION,
            host_routine_va: SMIMP_IGO2ROM_SOURCE_LOAD_ROUTINE_VA,
            command_constructor_call_va: SMIMP_IGO2ROM_COMMAND_CALL_VA,
            command_constructor_routine_va: SMIMP_IGO2ROM_COMMAND_ROUTINE_VA,
            transport_call_va: SMIMP_IGO2ROM_TRANSPORT_CALL_VA,
            command: "F1/0A data-out",
            address_layout: "CDB bytes 2..5 contain the 32-bit big-endian entry address",
            entry_address: SMIMP_SM3281BA_IGO2ROM_ENTRY_ADDRESS,
            source_size_bytes: SM3281BA_IGO2ROM_BYTES,
            transfer_sectors: 4,
            mapping_statically_proven: true,
        },
    ]
}

pub fn reviewed_sm3281ba_rom_code_transition() -> ReviewedRomCodeTransitionContract {
    ReviewedRomCodeTransitionContract {
        source_sha256: SMIMPTOOL32_SOURCE_SHA256,
        internal_ic_version: SMIMP_SM3281BA_INTERNAL_IC_VERSION,
        transition_routine_va: SMIMP_ROM_CODE_TRANSITION_ROUTINE_VA,
        transition_transport_call_va: SMIMP_ROM_CODE_TRANSITION_TRANSPORT_CALL_VA,
        transition_command: "F0/2C no-data",
        transition_flag_layout:
            "CDB byte 2 is 0x80 only when the caller requests the alternate transition",
        igo2rom_filename: "IGO2ROM.bin",
        igo2rom_filename_va: SMIMP_IGO2ROM_FILENAME_VA,
        igo2rom_source_load_routine_va: SMIMP_IGO2ROM_SOURCE_LOAD_ROUTINE_VA,
        igo2rom_source_load_call_va: SMIMP_IGO2ROM_SOURCE_LOAD_CALL_VA,
        igo2rom_command_routine_va: SMIMP_IGO2ROM_COMMAND_ROUTINE_VA,
        igo2rom_command_call_va: SMIMP_IGO2ROM_COMMAND_CALL_VA,
        igo2rom_transport_call_va: SMIMP_IGO2ROM_TRANSPORT_CALL_VA,
        igo2rom_entry_address: SMIMP_SM3281BA_IGO2ROM_ENTRY_ADDRESS,
        path_statically_proven: true,
        command_statically_proven: true,
    }
}

pub fn reviewed_service_loader_contract() -> ReviewedServiceLoaderContract {
    ReviewedServiceLoaderContract {
        source_sha256: SMIMPTOOL32_SOURCE_SHA256,
        write_ram_buffer_routine_va: SMIMP_WRITE_RAM_BUFFER_ROUTINE_VA,
        write_ram_buffer_transport_call_va: SMIMP_WRITE_RAM_BUFFER_TRANSPORT_CALL_VA,
        write_ram_command: "F1/04 data-out",
        write_ram_address_layout:
            "CDB byte 2 is the caller RAM-address high byte, byte 3 is zero, and byte 11 is transfer_bytes/512",
        write_ram_transfer_alignment_bytes: SECTOR_BYTES,
        write_ram_maximum_sectors: MAX_SECTORS,
        legacy_jump_isp_routine_va: SMIMP_JUMP_ISP_ROUTINE_VA,
        legacy_jump_isp_transport_call_va: SMIMP_JUMP_ISP_TRANSPORT_CALL_VA,
        legacy_jump_isp_command: "F1/0A data-out with entry address in CDB bytes 2..3",
        legacy_default_entry_address: SMIMP_DEFAULT_ISP_ENTRY_ADDRESS,
        legacy_ic_1b_entry_address: SMIMP_IC_1B_ISP_ENTRY_ADDRESS,
        service_artifact_loader_routine_va: SMIMP_SERVICE_ARTIFACT_LOADER_ROUTINE_VA,
        service_artifact_transport_call_va: SMIMP_SERVICE_ARTIFACT_TRANSPORT_CALL_VA,
        service_artifact_maximum_bytes: SMIMP_SERVICE_ARTIFACT_MAX_BYTES,
        service_artifact_32bit_ic_range: [
            SMIMP_SERVICE_ARTIFACT_32BIT_IC_MINIMUM,
            SMIMP_SERVICE_ARTIFACT_32BIT_IC_MAXIMUM,
        ],
        service_artifact_32bit_address_branch_va:
            SMIMP_SERVICE_ARTIFACT_32BIT_ADDRESS_BRANCH_VA,
        host_command_constructors_statically_proven: true,
        selected_artifact_chunk_map_statically_proven: false,
    }
}

/// Return the authenticated host-side SM3281 ISP programming contract.
///
/// The CDB layouts and transfer bounds are statically recovered. The page
/// address list and the controller/NAND-specific ISP modifications remain
/// separate inputs and are deliberately not inferred by this contract.
pub fn reviewed_sm3281_isp_programming_contract() -> ReviewedSm3281IspProgrammingContract {
    ReviewedSm3281IspProgrammingContract {
        source_sha256: SMIMPTOOL32_SOURCE_SHA256,
        download_isp_routine_va: SMIMP_SM3281_DOWNLOAD_ISP_ROUTINE_VA,
        build_modified_isp_routine_va: SMIMP_SM3281_BUILD_MODIFIED_ISP_ROUTINE_VA,
        get_isp_block_routine_va: SMIMP_SM3281_GET_ISP_BLOCK_ROUTINE_VA,
        erase_system_block_routine_va: SMIMP_SM3281_ERASE_SYSTEM_BLOCK_ROUTINE_VA,
        download_single_isp_routine_va: SMIMP_SM3281_DOWNLOAD_SINGLE_ISP_ROUTINE_VA,
        verify_single_isp_routine_va: SMIMP_SM3281_VERIFY_SINGLE_ISP_ROUTINE_VA,
        from_device_transport_va: SMIMP_SM3281_FROM_DEVICE_TRANSPORT_VA,
        to_device_transport_va: SMIMP_SM3281_TO_DEVICE_TRANSPORT_VA,
        system_block_candidate_count: SMIMP_SM3281_SYSTEM_BLOCK_CANDIDATES,
        system_block_header_bytes: SMIMP_SM3281_ISP_HEADER_BYTES,
        maximum_isp_page_bytes: SMIMP_SM3281_MAX_ISP_PAGE_BYTES,
        discovery_markers: ["SM3280INFO", "SM3280ISP", "SMI_BACKUP_CID_HEADER"],
        discovery_command: "F0/01 data-in, 1024 bytes, CDB byte 9 = 0x1E",
        erase_command: "F0/05 no-data",
        program_command: "F1/01 data-out",
        verify_command: "F0/01 data-in",
        command_constructors_statically_proven: true,
        page_address_sequence_statically_proven: false,
        composite_isp_modification_statically_proven: false,
    }
}

pub fn reviewed_sm3281ba_sandisk_19nm_contract() -> ReviewedSm3281BaSandisk19nmContract {
    ReviewedSm3281BaSandisk19nmContract {
        controller_id: SM3281BA_SANDISK_19NM_CONTROLLER_ID,
        nand_id: SM3281BA_SANDISK_19NM_NAND_ID,
        internal_ic: reviewed_sm3281ba_internal_ic_mapping(),
        artifacts: [
            ReviewedServiceArtifactContract {
                role: "isp",
                filename: "SM3281BA_ISP_MLC_SD_19nm.BIN",
                size_bytes: SM3281BA_SANDISK_19NM_ISP_BYTES,
                sha256: SM3281BA_SANDISK_19NM_ISP_SOURCE_SHA256,
                marker_offset: 0,
                marker_ascii: "SM3280ISP",
            },
            ReviewedServiceArtifactContract {
                role: "sortingcmd",
                filename: "SortingCmd_Grp.bin",
                size_bytes: SM3281BA_SORTING_COMMAND_BYTES,
                sha256: SM3281BA_SORTING_COMMAND_SOURCE_SHA256,
                marker_offset: 0x7ff0,
                marker_ascii: "Sort210111-C01",
            },
            ReviewedServiceArtifactContract {
                role: "geninfocmd",
                filename: "GenInfoCmd_Grp.bin",
                size_bytes: SM3281BA_GEN_INFO_COMMAND_BYTES,
                sha256: SM3281BA_GEN_INFO_COMMAND_SOURCE_SHA256,
                marker_offset: 0xbff0,
                marker_ascii: "Sort210111-C01",
            },
            ReviewedServiceArtifactContract {
                role: "findinfoblock",
                filename: "FindInfoBlock_ALL.BIN",
                size_bytes: SM3281BA_FIND_INFO_BLOCK_BYTES,
                sha256: SM3281BA_FIND_INFO_BLOCK_SOURCE_SHA256,
                marker_offset: 0x13f0,
                marker_ascii: "SM3280FINDINFOB",
            },
            ReviewedServiceArtifactContract {
                role: "igo2rom",
                filename: "IGO2ROM.bin",
                size_bytes: SM3281BA_IGO2ROM_BYTES,
                sha256: SM3281BA_IGO2ROM_SOURCE_SHA256,
                marker_offset: 0x7f0,
                marker_ascii: "SM3280IGO2ROM",
            },
        ],
        artifact_loads: reviewed_sm3281ba_service_artifact_loads(),
        rom_code_transition: reviewed_sm3281ba_rom_code_transition(),
        isp_programming: reviewed_sm3281_isp_programming_contract(),
        info_upload: reviewed_info_upload_contract(),
        service_loader: reviewed_service_loader_contract(),
        controller_setting: ReviewedControllerSettingReferenceContract {
            source_sha256: SM3281BA_SANDISK_19NM_ISP_SOURCE_SHA256,
            source_size_bytes: SM3281BA_SANDISK_19NM_ISP_BYTES,
            source_header_ascii: "SM3280ISP",
            source_version_ascii: "210120-C02",
            source_version_offset: 0x800,
            controller_symbol: "sFlashSetting",
            controller_address: FORCE_FLASH_CONTROLLER_ADDRESS,
            controller_span_bytes: FORCE_FLASH_CONTROLLER_SPAN_BYTES,
            reference_signature_hex: SM3281BA_ISP_SETTING_REFERENCE_SIGNATURE_HEX,
            reference_offsets: SM3281BA_ISP_SETTING_REFERENCE_OFFSETS,
            address_references_authenticated: true,
            field_semantics_statically_proven: false,
        },
        static_contract_complete: false,
        production_eligible: false,
    }
}

/// Build the exact 32-bit-address F1/0A transfer emitted by the reviewed host
/// for service artifacts on internal IC revisions 0x28 through 0x2e.
pub fn load_service_artifact_32bit(
    internal_ic_version: u8,
    entry_address: u32,
    source: &[u8],
) -> Result<DataOutCommand> {
    if !(SMIMP_SERVICE_ARTIFACT_32BIT_IC_MINIMUM..=SMIMP_SERVICE_ARTIFACT_32BIT_IC_MAXIMUM)
        .contains(&internal_ic_version)
    {
        return Err(Error::Invalid(format!(
            "SMI internal IC version 0x{internal_ic_version:02x} does not use the reviewed 32-bit service-artifact address layout"
        )));
    }
    let sectors = sector_count(
        source.len(),
        SMIMP_SERVICE_ARTIFACT_MAX_BYTES,
        "service artifact",
    )?;
    let transfer_bytes = usize::from(sectors) * SECTOR_BYTES;
    let mut data = vec![0u8; transfer_bytes];
    data[..source.len()].copy_from_slice(source);
    let mut command_cdb = cdb(0xf1, 0x0a, sectors);
    command_cdb[2..6].copy_from_slice(&entry_address.to_be_bytes());
    Ok(DataOutCommand {
        cdb: command_cdb,
        data,
    })
}

/// Build the exact SM3281-generation ROM-code transition emitted after the
/// reviewed IGO2ROM upload. The ordinary path leaves byte 2 clear.
pub fn sm3281_rom_code_transition(alternate: bool) -> [u8; 16] {
    let mut command_cdb = cdb(0xf0, 0x2c, 0);
    if alternate {
        command_cdb[2] = 0x80;
    }
    command_cdb
}

/// Positional system-block fields consumed by the reviewed SM3281 host.
/// The three-bit routing selector is preserved without assigning an
/// undocumented die, plane or channel meaning to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Sm3281SystemBlockLocation {
    pub block: u16,
    pub routing_selector: u8,
}

impl Sm3281SystemBlockLocation {
    pub fn new(block: u16, routing_selector: u8) -> Result<Self> {
        if routing_selector > 7 {
            return Err(Error::Invalid(
                "SMI SM3281 system-block routing selector exceeds three bits".into(),
            ));
        }
        Ok(Self {
            block,
            routing_selector,
        })
    }
}

fn sm3281_isp_page_layout(page_kib: u8) -> Result<(u8, usize)> {
    let page_bytes = usize::from(page_kib)
        .checked_mul(1024)
        .ok_or_else(|| Error::Invalid("SMI SM3281 ISP page-size overflow".into()))?;
    if page_bytes == 0 || page_bytes > SMIMP_SM3281_MAX_ISP_PAGE_BYTES {
        return Err(Error::Invalid(format!(
            "SMI SM3281 ISP page size must be 1..={} KiB",
            SMIMP_SM3281_MAX_ISP_PAGE_BYTES / 1024
        )));
    }
    let sectors = page_kib
        .checked_mul(2)
        .ok_or_else(|| Error::Invalid("SMI SM3281 ISP page sector-count overflow".into()))?;
    Ok((sectors, page_bytes))
}

fn sm3281_isp_page_cdb(
    opcode: u8,
    location: Sm3281SystemBlockLocation,
    page: u16,
    sectors: u8,
) -> [u8; 16] {
    let mut command_cdb = cdb(opcode, 0x01, sectors);
    command_cdb[2..4].copy_from_slice(&location.block.to_be_bytes());
    command_cdb[4..6].copy_from_slice(&page.to_be_bytes());
    command_cdb[10] = 0x04 | (location.routing_selector << 4);
    command_cdb
}

/// Build one of the exact 1024-byte F0/01 reads used by the reviewed host to
/// locate `SM3280INFO`, `SM3280ISP` and backup-CID system blocks.
pub fn read_sm3281_system_block_header(
    location: Sm3281SystemBlockLocation,
    page: u16,
) -> DataInCommand {
    let mut command_cdb = sm3281_isp_page_cdb(0xf0, location, page, 2);
    command_cdb[9] = 0x1e;
    DataInCommand {
        cdb: command_cdb,
        transfer_bytes: SMIMP_SM3281_ISP_HEADER_BYTES,
    }
}

/// Build the exact F0/05 system-block erase emitted by `EraseSystemBlk`.
pub fn erase_sm3281_system_block(location: Sm3281SystemBlockLocation) -> [u8; 16] {
    let mut command_cdb = cdb(0xf0, 0x05, 0);
    command_cdb[2..4].copy_from_slice(&location.block.to_be_bytes());
    command_cdb[10] = 0x04 | (location.routing_selector << 4);
    command_cdb
}

/// Build the initial F1/01 ISP-page write from `DownloadSingleISP_SM3281`.
/// The genuine host consumes exactly 1024 source bytes and zero pads the rest
/// of the physical page before transfer.
pub fn download_sm3281_isp_header(
    location: Sm3281SystemBlockLocation,
    page: u16,
    page_kib: u8,
    header: &[u8],
) -> Result<DataOutCommand> {
    if header.len() != SMIMP_SM3281_ISP_HEADER_BYTES {
        return Err(Error::Invalid(format!(
            "SMI SM3281 ISP header must be exactly {SMIMP_SM3281_ISP_HEADER_BYTES} bytes"
        )));
    }
    let (sectors, page_bytes) = sm3281_isp_page_layout(page_kib)?;
    let mut data = vec![0u8; page_bytes];
    data[..header.len()].copy_from_slice(header);
    let mut command_cdb = sm3281_isp_page_cdb(0xf1, location, page, sectors);
    command_cdb[9] = 0x1c;
    Ok(DataOutCommand {
        cdb: command_cdb,
        data,
    })
}

/// Build a subsequent F1/01 ISP-page write from
/// `DownloadSingleISP_SM3281`. Short final source data is explicitly zero
/// padded to the physical page size, matching the reviewed host buffer.
pub fn download_sm3281_isp_page(
    location: Sm3281SystemBlockLocation,
    page: u16,
    ordinal: u16,
    page_kib: u8,
    source: &[u8],
) -> Result<DataOutCommand> {
    if ordinal == 0 {
        return Err(Error::Invalid(
            "SMI SM3281 subsequent ISP-page ordinal must be nonzero".into(),
        ));
    }
    let (sectors, page_bytes) = sm3281_isp_page_layout(page_kib)?;
    if source.is_empty() || source.len() > page_bytes {
        return Err(Error::Invalid(format!(
            "SMI SM3281 ISP-page source length must be in 1..={page_bytes} bytes"
        )));
    }
    let mut data = vec![0u8; page_bytes];
    data[..source.len()].copy_from_slice(source);
    let mut command_cdb = sm3281_isp_page_cdb(0xf1, location, page, sectors);
    command_cdb[8] = 0xe4;
    command_cdb[9] = 0x30;
    command_cdb[12..14].copy_from_slice(&ordinal.to_be_bytes());
    Ok(DataOutCommand {
        cdb: command_cdb,
        data,
    })
}

/// Build the first 1024-byte F0/01 verification read. This is the same CDB
/// layout used for system-block marker discovery.
pub fn verify_sm3281_isp_header(location: Sm3281SystemBlockLocation, page: u16) -> DataInCommand {
    read_sm3281_system_block_header(location, page)
}

/// Build a subsequent full-page F0/01 verification read from
/// `VerifySingleISP_SM3281`.
pub fn verify_sm3281_isp_page(
    location: Sm3281SystemBlockLocation,
    page: u16,
    page_kib: u8,
) -> Result<DataInCommand> {
    let (sectors, page_bytes) = sm3281_isp_page_layout(page_kib)?;
    let mut command_cdb = sm3281_isp_page_cdb(0xf0, location, page, sectors);
    command_cdb[7] = 0x04;
    command_cdb[9] = 0x12;
    Ok(DataInCommand {
        cdb: command_cdb,
        transfer_bytes: page_bytes,
    })
}

/// Authenticate and lower one of the exact reviewed SM3281BA service
/// artifacts whose host-side entry address has been recovered.
pub fn load_reviewed_sm3281ba_service_artifact(
    role: &str,
    source: &[u8],
) -> Result<DataOutCommand> {
    let tuple = reviewed_sm3281ba_sandisk_19nm_contract();
    let artifact = tuple
        .artifacts
        .iter()
        .find(|artifact| artifact.role.eq_ignore_ascii_case(role))
        .ok_or_else(|| Error::Invalid(format!("unknown reviewed SMI artifact role {role:?}")))?;
    let load = tuple
        .artifact_loads
        .iter()
        .find(|load| load.role.eq_ignore_ascii_case(role))
        .ok_or_else(|| {
            Error::Invalid(format!(
                "SMI artifact role {role:?} has no statically recovered host load mapping"
            ))
        })?;
    if source.len() as u64 != artifact.size_bytes || source.len() as u64 != load.source_size_bytes {
        return Err(Error::Invalid(format!(
            "SMI {} artifact size {} does not match the reviewed {} bytes",
            artifact.role,
            source.len(),
            artifact.size_bytes
        )));
    }
    let source_sha256 = hex::encode(Sha256::digest(source));
    if source_sha256 != artifact.sha256 {
        return Err(Error::Permission(format!(
            "SMI {} artifact bytes do not match the reviewed SHA-256",
            artifact.role
        )));
    }
    let command =
        load_service_artifact_32bit(load.internal_ic_version, load.entry_address, source)?;
    if command.cdb[11] != load.transfer_sectors {
        return Err(Error::Invalid(format!(
            "SMI {} artifact transfer-sector count does not match the reviewed host mapping",
            artifact.role
        )));
    }
    Ok(command)
}

pub fn authenticate_reviewed_service_artifact(
    expected: ReviewedServiceArtifactContract,
    filename: &str,
    size_bytes: u64,
    sha256: &str,
) -> Result<ReviewedServiceArtifactContract> {
    if !filename.eq_ignore_ascii_case(expected.filename) {
        return Err(Error::Invalid(format!(
            "SMI {} artifact filename {filename:?} does not match {:?}",
            expected.role, expected.filename
        )));
    }
    if size_bytes != expected.size_bytes {
        return Err(Error::Invalid(format!(
            "SMI {} artifact size {size_bytes} does not match {}",
            expected.role, expected.size_bytes
        )));
    }
    if !sha256.eq_ignore_ascii_case(expected.sha256) {
        return Err(Error::Permission(format!(
            "SMI {} artifact SHA-256 {sha256} does not match the reviewed source",
            expected.role
        )));
    }
    Ok(expected)
}

fn sector_count(length: usize, maximum: usize, label: &str) -> Result<u8> {
    if length == 0 || length > maximum {
        return Err(Error::Invalid(format!(
            "SMI {label} length must be in 1..={maximum} bytes"
        )));
    }
    let sectors = length
        .checked_add(SECTOR_BYTES - 1)
        .ok_or_else(|| Error::Invalid(format!("SMI {label} sector count overflow")))?
        / SECTOR_BYTES;
    u8::try_from(sectors)
        .map_err(|_| Error::Invalid(format!("SMI {label} exceeds the one-byte sector count")))
}

fn cdb(opcode: u8, subcommand: u8, sectors: u8) -> [u8; 16] {
    let mut cdb = [0u8; 16];
    cdb[0] = opcode;
    cdb[1] = subcommand;
    cdb[11] = sectors;
    cdb
}

fn fixed_descriptor_command(subcommand: u8, descriptor: Vec<u8>) -> Result<DataOutCommand> {
    if !descriptor.len().is_multiple_of(SECTOR_BYTES) {
        return Err(Error::Invalid(
            "SMI fixed descriptor is not sector aligned".into(),
        ));
    }
    let sectors = u8::try_from(descriptor.len() / SECTOR_BYTES)
        .map_err(|_| Error::Invalid("SMI fixed descriptor sector count overflow".into()))?;
    Ok(DataOutCommand {
        cdb: cdb(0xf1, subcommand, sectors),
        data: descriptor,
    })
}

fn fixed_scalar_command(subcommand: u8, values: &[u8]) -> Result<DataOutCommand> {
    if values.len() > SECTOR_BYTES {
        return Err(Error::Invalid(format!(
            "SMI F1/{subcommand:02X} scalar payload exceeds {SECTOR_BYTES} bytes"
        )));
    }
    let mut descriptor = vec![0u8; SECTOR_BYTES];
    descriptor[..values.len()].copy_from_slice(values);
    fixed_descriptor_command(subcommand, descriptor)
}

fn padded_payload(source: &[u8], maximum: usize, label: &str) -> Result<Vec<u8>> {
    if source.is_empty() || source.len() > maximum {
        return Err(Error::Invalid(format!(
            "SMI {label} length must be in 1..={maximum} bytes"
        )));
    }
    let transfer_bytes = source
        .len()
        .checked_add(SECTOR_BYTES - 1)
        .ok_or_else(|| Error::Invalid(format!("SMI {label} length overflow")))?
        / SECTOR_BYTES
        * SECTOR_BYTES;
    if transfer_bytes > maximum {
        return Err(Error::Invalid(format!(
            "SMI {label} padded length exceeds {maximum} bytes"
        )));
    }
    let mut data = vec![0u8; transfer_bytes];
    data[..source.len()].copy_from_slice(source);
    Ok(data)
}

fn padded_data_out_command(
    subcommand: u8,
    selector: Option<u8>,
    source: &[u8],
    maximum: usize,
    label: &str,
) -> Result<DataOutCommand> {
    let data = padded_payload(source, maximum, label)?;
    let sectors = u8::try_from(data.len() / SECTOR_BYTES)
        .map_err(|_| Error::Invalid(format!("SMI {label} sector count exceeds u8")))?;
    let mut command_cdb = cdb(0xf1, subcommand, sectors);
    if let Some(selector) = selector {
        command_cdb[2] = selector;
    }
    Ok(DataOutCommand {
        cdb: command_cdb,
        data,
    })
}

/// Build the exact `LIB_SetEraseFlashPara` F1/1F descriptor.
///
/// The genuine ABI exposes two one-byte values without semantic names. The
/// clean-room API retains that fact instead of guessing controller-specific
/// meanings.
pub fn set_erase_flash_parameters(values: [u8; 2]) -> Result<DataOutCommand> {
    let mut descriptor = vec![0u8; SECTOR_BYTES];
    descriptor[..2].copy_from_slice(&values);
    fixed_descriptor_command(0x1f, descriptor)
}

/// Build the exact `LIB_SetReadFlashPara` F1/24 descriptor.
pub fn set_read_flash_parameters(values: [u8; 6]) -> Result<DataOutCommand> {
    let mut descriptor = vec![0u8; SECTOR_BYTES];
    for (offset, value) in [0usize, 2, 4, 5, 6, 7].into_iter().zip(values) {
        descriptor[offset] = value;
    }
    fixed_descriptor_command(0x24, descriptor)
}

/// Build the exact direct-transport F5/24 parameter descriptor recovered
/// from the reviewed SM3280 low-level script.
pub fn direct_set_read_flash_parameters(values: [u8; 6]) -> DataOutCommand {
    let mut descriptor = vec![0u8; SECTOR_BYTES];
    for (offset, value) in [0usize, 2, 4, 5, 6, 7].into_iter().zip(values) {
        descriptor[offset] = value;
    }
    DataOutCommand {
        cdb: cdb(0xf5, 0x24, 1),
        data: descriptor,
    }
}

/// Build the exact `LIB_SetWriteFlashPara` F1/21 descriptor.
///
/// The first sector contains nine scalar ABI fields. The second sector is an
/// optional factory parameter table and is zero padded by this implementation
/// so the source buffer is never read past its declared length.
pub fn set_write_flash_parameters(
    values: [u8; 9],
    parameter_table: &[u8],
) -> Result<DataOutCommand> {
    if parameter_table.len() > SECTOR_BYTES {
        return Err(Error::Invalid(format!(
            "SMI write-flash parameter table exceeds {SECTOR_BYTES} bytes"
        )));
    }
    let mut descriptor = vec![0u8; 2 * SECTOR_BYTES];
    for (offset, value) in [0usize, 1, 2, 3, 5, 6, 7, 12, 13].into_iter().zip(values) {
        descriptor[offset] = value;
    }
    descriptor[SECTOR_BYTES..SECTOR_BYTES + parameter_table.len()].copy_from_slice(parameter_table);
    fixed_descriptor_command(0x21, descriptor)
}

/// Build the exact `LIB_SetEWRFlashPara` F1/34 descriptor.
pub fn set_ewr_flash_parameters(
    values: [u8; 16],
    parameter_table: &[u8],
) -> Result<DataOutCommand> {
    if parameter_table.len() > SECTOR_BYTES {
        return Err(Error::Invalid(format!(
            "SMI EWR parameter table exceeds {SECTOR_BYTES} bytes"
        )));
    }
    let mut descriptor = vec![0u8; 2 * SECTOR_BYTES];
    descriptor[..16].copy_from_slice(&values);
    descriptor[SECTOR_BYTES..SECTOR_BYTES + parameter_table.len()].copy_from_slice(parameter_table);
    fixed_descriptor_command(0x34, descriptor)
}

/// Build the exact `LIB_SetCEDiePlane` F1/35 descriptor.
pub fn set_ce_die_plane(values: [u8; 3]) -> Result<DataOutCommand> {
    let mut descriptor = vec![0u8; SECTOR_BYTES];
    descriptor[..3].copy_from_slice(&values);
    fixed_descriptor_command(0x35, descriptor)
}

/// Build the exact `LIB_SetECCValue` F1/1B descriptor.
pub fn set_ecc_value(values: [u8; 4]) -> Result<DataOutCommand> {
    let mut descriptor = vec![0u8; SECTOR_BYTES];
    descriptor[..4].copy_from_slice(&values);
    fixed_descriptor_command(0x1b, descriptor)
}

/// Build the exact `LIB_SetDriving` F1/11 descriptor.
pub fn set_driving(values: [u8; 3]) -> Result<DataOutCommand> {
    fixed_scalar_command(0x11, &values)
}

/// Build the exact `LIB_SetClockAndDutyCycle` F1/12 descriptor.
pub fn set_clock_and_duty_cycle(values: [u8; 4]) -> Result<DataOutCommand> {
    fixed_scalar_command(0x12, &values)
}

/// Build the exact `LIB_SetVoltage` F1/13 descriptor.
pub fn set_voltage(value: u8) -> Result<DataOutCommand> {
    fixed_scalar_command(0x13, &[value])
}

/// Build the exact `LIB_SetInfo` F1/14 transfer.
///
/// The genuine DLL rounds the transfer length to a sector while retaining the
/// caller's pointer. This implementation materializes the padding so it never
/// reads beyond the provided slice.
pub fn set_info(source: &[u8]) -> Result<DataOutCommand> {
    padded_data_out_command(0x14, None, source, MAX_SECTOR_TRANSFER_BYTES, "Info table")
}

/// Build the exact `LIB_SetSeedTable` F1/15 transfer.
pub fn set_seed_table(source: &[u8]) -> Result<DataOutCommand> {
    let data = padded_payload(source, MAX_RETRY_TABLE_BYTES, "seed table")?;
    let source_bytes = u16::try_from(source.len())
        .map_err(|_| Error::Invalid("SMI seed table length exceeds u16".into()))?;
    let mut command_cdb = cdb(
        0xf1,
        0x15,
        u8::try_from(data.len() / SECTOR_BYTES)
            .map_err(|_| Error::Invalid("SMI seed table sector count exceeds u8".into()))?,
    );
    command_cdb[2..4].copy_from_slice(&source_bytes.to_be_bytes());
    Ok(DataOutCommand {
        cdb: command_cdb,
        data,
    })
}

/// Build the exact `LIB_SetRBTimeout` F1/16 descriptor.
pub fn set_rb_timeout(value: u16) -> Result<DataOutCommand> {
    fixed_scalar_command(0x16, &value.to_be_bytes())
}

/// Build the exact `LIB_SetCheckRBMode` F1/17 descriptor.
pub fn set_check_rb_mode(value: u8) -> Result<DataOutCommand> {
    fixed_scalar_command(0x17, &[value])
}

/// Build the exact `LIB_SetForceCEtoLow` F1/19 descriptor.
pub fn set_force_ce_to_low(value: u8) -> Result<DataOutCommand> {
    fixed_scalar_command(0x19, &[value])
}

/// Build the exact `LIB_SetCESwitch` F1/1A descriptor.
pub fn set_ce_switch(values: [u8; 4]) -> Result<DataOutCommand> {
    fixed_scalar_command(0x1a, &values)
}

fn set_variable_table(subcommand: u8, selector: u8, source: &[u8]) -> Result<DataOutCommand> {
    padded_data_out_command(
        subcommand,
        Some(selector),
        source,
        MAX_SECTOR_TRANSFER_BYTES,
        "variable table",
    )
}

/// Build the exact `LIB_SetPageTable` F1/1C transfer.
pub fn set_page_table(selector: u8, source: &[u8]) -> Result<DataOutCommand> {
    set_variable_table(0x1c, selector, source)
}

/// Build the exact `LIB_SetSectorTable` F1/1D transfer.
pub fn set_sector_table(selector: u8, source: &[u8]) -> Result<DataOutCommand> {
    set_variable_table(0x1d, selector, source)
}

/// Build the exact `LIB_SetBadColTable` F1/26 transfer.
pub fn set_bad_column_table(selector: u8, source: &[u8]) -> Result<DataOutCommand> {
    padded_data_out_command(
        0x26,
        Some(selector),
        source,
        MAX_SECTOR_TRANSFER_BYTES,
        "bad-column table",
    )
}

/// Build the exact `LIB_SetBadColAddr` F1/27 transfer.
pub fn set_bad_column_addresses(source: &[u8]) -> Result<DataOutCommand> {
    padded_data_out_command(
        0x27,
        None,
        source,
        MAX_SECTOR_TRANSFER_BYTES,
        "bad-column address table",
    )
}

/// Build the exact `LIB_SetRetryTable` F1/30 transfer.
pub fn set_retry_table(values: [u8; 2], source: &[u8]) -> Result<DataOutCommand> {
    let mut command =
        padded_data_out_command(0x30, None, source, MAX_RETRY_TABLE_BYTES, "retry table")?;
    command.cdb[2..4].copy_from_slice(&values);
    Ok(command)
}

/// Build the exact `LIB_SendModifyInfo` F1/31 transfer.
pub fn send_modify_info(source: &[u8]) -> Result<DataOutCommand> {
    padded_data_out_command(
        0x31,
        None,
        source,
        MAX_SECTOR_TRANSFER_BYTES,
        "modify-info table",
    )
}

/// Build the exact `LIB_SendBlockFailBitTable` F1/32 sequence.
///
/// The genuine export always sends one or two 1 KiB chunks. Short final input
/// is explicitly zero padded here instead of exposing adjacent host memory.
pub fn send_block_fail_bit_table(source: &[u8]) -> Result<Vec<DataOutCommand>> {
    if source.is_empty() || source.len() > MAX_BLOCK_FAIL_BIT_TABLE_BYTES {
        return Err(Error::Invalid(format!(
            "SMI block-fail-bit table length must be in 1..={MAX_BLOCK_FAIL_BIT_TABLE_BYTES} bytes"
        )));
    }
    let chunk_count = source.len().div_ceil(1024);
    let mut commands = Vec::with_capacity(chunk_count);
    for index in 0..chunk_count {
        let source_start = index * 1024;
        let source_end = (source_start + 1024).min(source.len());
        let mut data = vec![0u8; 1024];
        data[..source_end - source_start].copy_from_slice(&source[source_start..source_end]);
        let mut command_cdb = cdb(0xf1, 0x32, 2);
        command_cdb[2] = index as u8;
        commands.push(DataOutCommand {
            cdb: command_cdb,
            data,
        });
    }
    Ok(commands)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FlashPageRange {
    pub ce: u8,
    pub start_page: u16,
    pub end_page: u16,
    pub start_sector: u16,
    pub end_sector: u16,
}

impl FlashPageRange {
    pub fn new(
        ce: u8,
        start_page: u16,
        end_page: u16,
        start_sector: u16,
        end_sector: u16,
    ) -> Result<Self> {
        if end_page < start_page {
            return Err(Error::Invalid(
                "SMI flash page range ends before it starts".into(),
            ));
        }
        if end_sector < start_sector {
            return Err(Error::Invalid(
                "SMI flash sector range ends before it starts".into(),
            ));
        }
        Ok(Self {
            ce,
            start_page,
            end_page,
            start_sector,
            end_sector,
        })
    }

    pub fn page_count(self) -> Result<u16> {
        self.end_page
            .checked_sub(self.start_page)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| Error::Invalid("SMI flash page count exceeds u16".into()))
    }

    fn descriptor(self) -> Result<Vec<u8>> {
        let mut descriptor = vec![0u8; SECTOR_BYTES];
        descriptor[0] = self.ce;
        descriptor[2..4].copy_from_slice(&self.page_count()?.to_be_bytes());
        descriptor[4..6].copy_from_slice(&self.start_page.to_be_bytes());
        descriptor[8..10].copy_from_slice(&self.start_sector.to_be_bytes());
        // The DLL chooses max(arg20, arg24), not the minimum. The typed
        // constructor already enforces monotonic input, making that result
        // canonical here.
        descriptor[10..12].copy_from_slice(&self.end_sector.to_be_bytes());
        Ok(descriptor)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FlashBlockRange {
    pub ce: u8,
    pub start_block: u16,
    pub block_count: u16,
}

impl FlashBlockRange {
    pub fn new(ce: u8, start_block: u16, block_count: u16) -> Result<Self> {
        if block_count == 0 {
            return Err(Error::Invalid(
                "SMI flash erase block count must be nonzero".into(),
            ));
        }
        start_block
            .checked_add(block_count - 1)
            .ok_or_else(|| Error::Invalid("SMI flash erase range exceeds u16".into()))?;
        Ok(Self {
            ce,
            start_block,
            block_count,
        })
    }
}

/// Build the exact `LIB_ReadFlash` F1/25 raw-read trigger.
pub fn read_flash(range: FlashPageRange) -> Result<DataOutCommand> {
    fixed_descriptor_command(0x25, range.descriptor()?)
}

/// Build the exact direct-transport F5/25 raw-read trigger recovered from
/// the reviewed SM3280 low-level script.
pub fn direct_read_flash(request: DirectFlashReadRequest) -> DataOutCommand {
    let mut command_cdb = cdb(0xf5, 0x25, 1);
    command_cdb[2] = request.discriminator;
    DataOutCommand {
        cdb: command_cdb,
        data: request.descriptor(),
    }
}

/// Build the exact F0/37 data-in sequence exported as
/// `LIB_BadColumnReadFlash` by the reviewed UFDIF image. Each command covers
/// at most 8 KiB, while the final command is rounded to 1 KiB and trimmed via
/// `output_bytes`.
pub fn read_bad_column_page_data(
    first: u16,
    second: u16,
    start_unit: u8,
    length: usize,
) -> Result<Vec<DataInChunk>> {
    if length == 0 {
        return Err(Error::Invalid(
            "SMI bad-column page-data read length must be nonzero".into(),
        ));
    }
    let maximum = (256usize - usize::from(start_unit))
        .checked_mul(DIRECT_DATA_GRANULARITY_BYTES)
        .ok_or_else(|| Error::Invalid("SMI bad-column page-data limit overflow".into()))?;
    if length > maximum {
        return Err(Error::Invalid(format!(
            "SMI bad-column page-data read length exceeds {maximum} bytes at start unit {start_unit}"
        )));
    }
    let transfer_total = length
        .checked_add(DIRECT_DATA_GRANULARITY_BYTES - 1)
        .ok_or_else(|| Error::Invalid("SMI bad-column page-data length overflow".into()))?
        / DIRECT_DATA_GRANULARITY_BYTES
        * DIRECT_DATA_GRANULARITY_BYTES;
    let mut commands = Vec::new();
    let mut transfer_offset = 0usize;
    let mut output_offset = 0usize;
    while transfer_offset < transfer_total {
        let transfer_bytes =
            (transfer_total - transfer_offset).min(UFDIF_BAD_COLUMN_DATA_CHUNK_BYTES);
        let output_bytes = (length - output_offset).min(transfer_bytes);
        let start_increment = transfer_offset / DIRECT_DATA_GRANULARITY_BYTES;
        let command_start = usize::from(start_unit)
            .checked_add(start_increment)
            .ok_or_else(|| Error::Invalid("SMI bad-column page-data start overflow".into()))?;
        let command_units = transfer_bytes / DIRECT_DATA_GRANULARITY_BYTES;
        let command_end = command_start
            .checked_add(command_units - 1)
            .ok_or_else(|| Error::Invalid("SMI bad-column page-data end overflow".into()))?;
        let mut command_cdb = cdb(
            0xf0,
            0x37,
            u8::try_from(transfer_bytes / SECTOR_BYTES).map_err(|_| {
                Error::Invalid("SMI bad-column page-data sector count exceeds u8".into())
            })?,
        );
        command_cdb[2..4].copy_from_slice(&first.to_be_bytes());
        command_cdb[4..6].copy_from_slice(&second.to_be_bytes());
        command_cdb[6] = u8::try_from(command_start)
            .map_err(|_| Error::Invalid("SMI bad-column page-data start exceeds u8".into()))?;
        command_cdb[7] = u8::try_from(command_end)
            .map_err(|_| Error::Invalid("SMI bad-column page-data end exceeds u8".into()))?;
        commands.push(DataInChunk {
            cdb: command_cdb,
            transfer_bytes,
            output_offset,
            output_bytes,
        });
        transfer_offset = transfer_offset
            .checked_add(transfer_bytes)
            .ok_or_else(|| Error::Invalid("SMI bad-column page-data offset overflow".into()))?;
        output_offset = output_offset
            .checked_add(output_bytes)
            .ok_or_else(|| Error::Invalid("SMI bad-column page-data output overflow".into()))?;
    }
    Ok(commands)
}

/// Build the exact F4/37 data-in sequence used by
/// `LIB_BadColumnReadFlash`. The genuine routine transfers at most 16 KiB per
/// command and rounds only the final command up to 1 KiB. `output_bytes`
/// records the bytes retained from each transfer, so padding is never exposed
/// as NAND data.
pub fn direct_read_page_data(
    first: u16,
    second: u16,
    start_unit: u8,
    length: usize,
) -> Result<Vec<DataInChunk>> {
    if length == 0 {
        return Err(Error::Invalid(
            "SMI direct page-data read length must be nonzero".into(),
        ));
    }
    let available_units = 256usize
        .checked_sub(usize::from(start_unit))
        .ok_or_else(|| Error::Invalid("SMI direct page-data start unit overflow".into()))?;
    let maximum = available_units
        .checked_mul(DIRECT_DATA_GRANULARITY_BYTES)
        .ok_or_else(|| Error::Invalid("SMI direct page-data limit overflow".into()))?;
    if length > maximum {
        return Err(Error::Invalid(format!(
            "SMI direct page-data read length exceeds {maximum} bytes at start unit {start_unit}"
        )));
    }
    let transfer_total = length
        .checked_add(DIRECT_DATA_GRANULARITY_BYTES - 1)
        .ok_or_else(|| Error::Invalid("SMI direct page-data length overflow".into()))?
        / DIRECT_DATA_GRANULARITY_BYTES
        * DIRECT_DATA_GRANULARITY_BYTES;
    let mut commands = Vec::new();
    let mut transfer_offset = 0usize;
    let mut output_offset = 0usize;
    while transfer_offset < transfer_total {
        let transfer_bytes = (transfer_total - transfer_offset).min(DIRECT_DATA_CHUNK_BYTES);
        let output_bytes = (length - output_offset).min(transfer_bytes);
        let start_increment = transfer_offset / DIRECT_DATA_GRANULARITY_BYTES;
        let command_start = usize::from(start_unit)
            .checked_add(start_increment)
            .ok_or_else(|| Error::Invalid("SMI direct page-data start overflow".into()))?;
        let command_units = transfer_bytes / DIRECT_DATA_GRANULARITY_BYTES;
        let command_end = command_start
            .checked_add(command_units - 1)
            .ok_or_else(|| Error::Invalid("SMI direct page-data end overflow".into()))?;
        let sectors = transfer_bytes / SECTOR_BYTES;
        let mut command_cdb = cdb(
            0xf4,
            0x37,
            u8::try_from(sectors).map_err(|_| {
                Error::Invalid("SMI direct page-data sector count exceeds u8".into())
            })?,
        );
        command_cdb[2..4].copy_from_slice(&first.to_be_bytes());
        command_cdb[4..6].copy_from_slice(&second.to_be_bytes());
        command_cdb[6] = u8::try_from(command_start)
            .map_err(|_| Error::Invalid("SMI direct page-data start exceeds u8".into()))?;
        command_cdb[7] = u8::try_from(command_end)
            .map_err(|_| Error::Invalid("SMI direct page-data end exceeds u8".into()))?;
        commands.push(DataInChunk {
            cdb: command_cdb,
            transfer_bytes,
            output_offset,
            output_bytes,
        });
        transfer_offset = transfer_offset
            .checked_add(transfer_bytes)
            .ok_or_else(|| Error::Invalid("SMI direct page-data offset overflow".into()))?;
        output_offset = output_offset
            .checked_add(output_bytes)
            .ok_or_else(|| Error::Invalid("SMI direct page-data output overflow".into()))?;
    }
    Ok(commands)
}

/// Build the F4/33 ECC-table sequence. The direct transport has a special
/// 512-byte form; larger requests are exact 1 KiB chunks up to 16 KiB.
pub fn direct_read_page_ecc_table(length: usize) -> Result<Vec<DataInChunk>> {
    if length == SECTOR_BYTES {
        let mut command_cdb = cdb(0xf4, 0x33, 1);
        command_cdb[2] = 0;
        return Ok(vec![DataInChunk {
            cdb: command_cdb,
            transfer_bytes: SECTOR_BYTES,
            output_offset: 0,
            output_bytes: SECTOR_BYTES,
        }]);
    }
    if length == 0
        || length > MAX_DIRECT_ECC_TABLE_BYTES
        || !length.is_multiple_of(ECC_TABLE_CHUNK_BYTES)
    {
        return Err(Error::Invalid(format!(
            "SMI direct ECC-table length must be {SECTOR_BYTES} or a nonzero multiple of {ECC_TABLE_CHUNK_BYTES} up to {MAX_DIRECT_ECC_TABLE_BYTES}"
        )));
    }
    Ok((0..length / ECC_TABLE_CHUNK_BYTES)
        .map(|index| {
            let mut command_cdb = cdb(0xf4, 0x33, 2);
            command_cdb[2] = index as u8;
            DataInChunk {
                cdb: command_cdb,
                transfer_bytes: ECC_TABLE_CHUNK_BYTES,
                output_offset: index * ECC_TABLE_CHUNK_BYTES,
                output_bytes: ECC_TABLE_CHUNK_BYTES,
            }
        })
        .collect())
}

pub fn direct_read_retired_block_fail_bit_table() -> DataInCommand {
    DataInCommand {
        cdb: cdb(0xf4, 0x35, 1),
        transfer_bytes: SECTOR_BYTES,
    }
}

/// Build the exact `LIB_WriteFlash` F1/23 raw-write trigger.
pub fn write_flash(range: FlashPageRange) -> Result<DataOutCommand> {
    fixed_descriptor_command(0x23, range.descriptor()?)
}

/// Build the exact `LIB_BadColumnWriteFlash` F1/33 descriptor.
pub fn bad_column_write_flash(
    request: BadColumnWriteRequest,
    parameter_table: &[u8],
) -> Result<DataOutCommand> {
    fixed_descriptor_command(0x33, request.descriptor(parameter_table)?)
}

/// Build the exact `LIB_WritePattern` F1/22 transfer.
pub fn write_pattern(source: &[u8]) -> Result<DataOutCommand> {
    padded_data_out_command(
        0x22,
        None,
        source,
        MAX_SECTOR_TRANSFER_BYTES,
        "write-pattern table",
    )
}

/// Build the exact `LIB_EraseFlash` F1/20 physical-block erase trigger.
pub fn erase_flash(range: FlashBlockRange) -> Result<DataOutCommand> {
    let mut descriptor = vec![0u8; SECTOR_BYTES];
    descriptor[0] = range.ce;
    descriptor[2..4].copy_from_slice(&range.block_count.to_be_bytes());
    descriptor[4..6].copy_from_slice(&range.start_block.to_be_bytes());
    fixed_descriptor_command(0x20, descriptor)
}

/// Build the exact direct-transport F5/20 physical erase request recovered
/// from the reviewed SM3280 low-level script. The reviewed wrapper always
/// supplies a full 512-byte factory parameter table. The constructor retains
/// bytes 16..511 exactly and replaces the command-owned 16-byte prefix.
pub fn direct_erase_flash(
    range: FlashBlockRange,
    factory_parameter_table: &[u8],
) -> Result<DataOutCommand> {
    if factory_parameter_table.len() != SECTOR_BYTES {
        return Err(Error::Invalid(format!(
            "SMI direct erase factory parameter table must be exactly {SECTOR_BYTES} bytes"
        )));
    }
    let mut descriptor = factory_parameter_table.to_vec();
    descriptor[..16].fill(0);
    descriptor[0] = range.ce;
    descriptor[2..4].copy_from_slice(&range.block_count.to_be_bytes());
    descriptor[4..6].copy_from_slice(&range.start_block.to_be_bytes());
    Ok(DataOutCommand {
        cdb: cdb(0xf5, 0x20, 1),
        data: descriptor,
    })
}

/// Build the exact `LIB_CheckStatus` F1/18 status trigger.
pub fn check_status(selector: u8) -> Result<DataOutCommand> {
    let mut descriptor = vec![0u8; SECTOR_BYTES];
    descriptor[0] = selector;
    fixed_descriptor_command(0x18, descriptor)
}

/// Build the exact direct-transport F5/18 status trigger recovered from the
/// reviewed SM3280 low-level script.
pub fn direct_check_status(selector: u8) -> DataOutCommand {
    let mut descriptor = vec![0u8; SECTOR_BYTES];
    descriptor[0] = selector;
    DataOutCommand {
        cdb: cdb(0xf5, 0x18, 1),
        data: descriptor,
    }
}

/// Build the exact `LIB_ResetFlash` F1/1E request.
pub fn reset_flash() -> Result<DataOutCommand> {
    fixed_descriptor_command(0x1e, vec![0u8; SECTOR_BYTES])
}

/// Build the exact `LIB_SendCopyBackSourceBlock` F1/29 descriptor.
pub fn send_copy_back_source_block(values: [u16; 2]) -> Result<DataOutCommand> {
    let mut descriptor = vec![0u8; SECTOR_BYTES];
    descriptor[..2].copy_from_slice(&values[0].to_be_bytes());
    descriptor[2..4].copy_from_slice(&values[1].to_be_bytes());
    fixed_descriptor_command(0x29, descriptor)
}

/// Build the exact `LIB_DoReadRetry` F1/38 request.
pub fn apply_read_retry(selector: u8) -> Result<DataOutCommand> {
    let mut descriptor = vec![0u8; SECTOR_BYTES];
    descriptor[0] = selector;
    fixed_descriptor_command(0x38, descriptor)
}

/// Build the exact `LIB_SetInCopyBackMode` F1/39 descriptor.
pub fn set_in_copy_back_mode(value: u8) -> Result<DataOutCommand> {
    fixed_scalar_command(0x39, &[value])
}

/// Build the exact `LIB_SetFindNewRetryTable` F1/40 descriptor.
pub fn set_find_new_retry_table(values: [u8; 2]) -> Result<DataOutCommand> {
    fixed_scalar_command(0x40, &values)
}

/// Build the exact `LIB_SetStrongTable` F1/41 transfer.
pub fn set_strong_table(source: &[u8]) -> Result<DataOutCommand> {
    padded_data_out_command(0x41, None, source, MAX_RETRY_TABLE_BYTES, "strong table")
}

/// Build the exact `LIB_SetFindNewRetryTableB0B7` F1/42 descriptor.
pub fn set_find_new_retry_table_b0_b7(values: [u8; 8]) -> Result<DataOutCommand> {
    fixed_scalar_command(0x42, &values)
}

/// Build the exact `LIB_SetDiffBlock` F1/37 descriptor.
pub fn set_diff_block(selector: u8, source: &[u8]) -> Result<DataOutCommand> {
    if source.is_empty() || source.len() > SECTOR_BYTES {
        return Err(Error::Invalid(format!(
            "SMI differential-block table length must be in 1..={SECTOR_BYTES} bytes"
        )));
    }
    let mut descriptor = vec![0u8; SECTOR_BYTES];
    descriptor[..source.len()].copy_from_slice(source);
    let mut command = fixed_descriptor_command(0x37, descriptor)?;
    command.cdb[2] = selector;
    Ok(command)
}

/// Build the exact `LIB_WriteDiffPageTable` F1/36 transfer.
pub fn write_diff_page_table(
    first: u16,
    second: u16,
    units_1k: u16,
    discriminator: u8,
    source: &[u8],
) -> Result<DataOutCommand> {
    if units_1k == 0 || usize::from(units_1k) * 1024 > MAX_DIFF_PAGE_TABLE_BYTES {
        return Err(Error::Invalid(format!(
            "SMI differential page-table units must describe 1..={MAX_DIFF_PAGE_TABLE_BYTES} bytes"
        )));
    }
    let transfer_bytes = usize::from(units_1k) * 1024;
    if source.is_empty() || source.len() > transfer_bytes {
        return Err(Error::Invalid(format!(
            "SMI differential page table source must be in 1..={transfer_bytes} bytes"
        )));
    }
    let mut data = vec![0u8; transfer_bytes];
    data[..source.len()].copy_from_slice(source);
    let sectors = u8::try_from(transfer_bytes / SECTOR_BYTES).map_err(|_| {
        Error::Invalid("SMI differential page-table sector count exceeds u8".into())
    })?;
    let mut command_cdb = cdb(0xf1, 0x36, sectors);
    command_cdb[2..4].copy_from_slice(&first.to_be_bytes());
    command_cdb[4..6].copy_from_slice(&second.to_be_bytes());
    command_cdb[6..8].copy_from_slice(&units_1k.to_be_bytes());
    command_cdb[8] = discriminator;
    Ok(DataOutCommand {
        cdb: command_cdb,
        data,
    })
}

/// Build the exact `LIB_EndSorting` F1/60 descriptor.
pub fn end_sorting() -> Result<DataOutCommand> {
    fixed_descriptor_command(0x60, vec![0u8; SECTOR_BYTES])
}

pub fn read_controller_ram(address: u16, length: usize) -> Result<DataInCommand> {
    let sectors = sector_count(length, MAX_RAM_TRANSFER_BYTES, "controller RAM read")?;
    let mut command_cdb = cdb(0xf0, 0x04, sectors);
    command_cdb[2..4].copy_from_slice(&address.to_be_bytes());
    Ok(DataInCommand {
        cdb: command_cdb,
        transfer_bytes: length,
    })
}

pub fn write_controller_ram(address: u16, source: &[u8]) -> Result<DataOutCommand> {
    let sectors = sector_count(source.len(), MAX_RAM_TRANSFER_BYTES, "controller RAM write")?;
    let mut command_cdb = cdb(0xf1, 0x04, sectors);
    command_cdb[2..4].copy_from_slice(&address.to_be_bytes());
    Ok(DataOutCommand {
        cdb: command_cdb,
        data: source.to_vec(),
    })
}

fn service_transition(subcommand: u8, discriminator: u8, source: &[u8]) -> Result<DataOutCommand> {
    let sectors = sector_count(
        source.len(),
        MAX_SECTOR_TRANSFER_BYTES,
        "service transition",
    )?;
    let mut command_cdb = cdb(0xf1, subcommand, sectors);
    command_cdb[2] = discriminator;
    Ok(DataOutCommand {
        cdb: command_cdb,
        data: source.to_vec(),
    })
}

pub fn call_uploaded_controller_code(source: &[u8]) -> Result<DataOutCommand> {
    service_transition(0x0a, 0xa0, source)
}

pub fn enter_boot_card_mode(source: &[u8]) -> Result<DataOutCommand> {
    service_transition(0x04, 0xc0, source)
}

fn fixed_read(subcommand: u8, bytes: usize) -> DataInCommand {
    DataInCommand {
        cdb: cdb(0xf0, subcommand, (bytes / SECTOR_BYTES) as u8),
        transfer_bytes: bytes,
    }
}

pub fn read_operation_info() -> DataInCommand {
    fixed_read(0x36, 1024)
}

pub fn read_metadata_ecc_table() -> DataInCommand {
    fixed_read(0x34, SECTOR_BYTES)
}

pub fn read_retired_block_fail_bit_table() -> DataInCommand {
    fixed_read(0x35, SECTOR_BYTES)
}

pub fn read_original_read_retry_table() -> DataInCommand {
    fixed_read(0x3a, 1024)
}

/// Build the exact `LIB_GetOriginalRetryTable` F0/38 read.
pub fn get_original_retry_table() -> DataInCommand {
    fixed_read(0x38, 1024)
}

/// Build the exact `LIB_GetOneSCountNumber` F0/39 read.
pub fn get_one_s_count_number() -> DataInCommand {
    fixed_read(0x39, SECTOR_BYTES)
}

pub fn read_original_bad_column_table(length: usize) -> Result<DataInCommand> {
    if length == 0 || length > MAX_SECTOR_TRANSFER_BYTES || !length.is_multiple_of(SECTOR_BYTES) {
        return Err(Error::Invalid(format!(
            "SMI original bad-column table length must be a nonzero multiple of {SECTOR_BYTES} up to {MAX_SECTOR_TRANSFER_BYTES}"
        )));
    }
    Ok(DataInCommand {
        cdb: cdb(0xf0, 0x31, (length / SECTOR_BYTES) as u8),
        transfer_bytes: length,
    })
}

pub fn read_page_ecc_table(length: usize) -> Result<Vec<DataInCommand>> {
    if length == 0 || length > MAX_ECC_TABLE_BYTES || !length.is_multiple_of(ECC_TABLE_CHUNK_BYTES)
    {
        return Err(Error::Invalid(format!(
            "SMI page ECC table length must be a nonzero multiple of {ECC_TABLE_CHUNK_BYTES} up to {MAX_ECC_TABLE_BYTES}"
        )));
    }
    Ok((0..length / ECC_TABLE_CHUNK_BYTES)
        .map(|index| {
            let mut command_cdb = cdb(0xf0, 0x33, 2);
            command_cdb[2] = index as u8;
            DataInCommand {
                cdb: command_cdb,
                transfer_bytes: ECC_TABLE_CHUNK_BYTES,
            }
        })
        .collect())
}

pub fn read_index(first: u16, second: u16, third: u16) -> DataInCommand {
    let mut command = fixed_read(0x32, SECTOR_BYTES);
    command.cdb[2..4].copy_from_slice(&first.to_be_bytes());
    command.cdb[4..6].copy_from_slice(&second.to_be_bytes());
    command.cdb[6..8].copy_from_slice(&third.to_be_bytes());
    command
}

pub fn write_index(first: u16, second: u16, third: u16, source: &[u8]) -> Result<DataOutCommand> {
    if source.len() != SECTOR_BYTES {
        return Err(Error::Invalid(format!(
            "SMI index write requires exactly {SECTOR_BYTES} bytes"
        )));
    }
    let mut command_cdb = cdb(0xf1, 0x28, 1);
    command_cdb[2..4].copy_from_slice(&first.to_be_bytes());
    command_cdb[4..6].copy_from_slice(&second.to_be_bytes());
    command_cdb[6..8].copy_from_slice(&third.to_be_bytes());
    let mut data = source.to_vec();
    data[..2].copy_from_slice(&first.to_be_bytes());
    data[2..4].copy_from_slice(&second.to_be_bytes());
    data[4..6].copy_from_slice(&third.to_be_bytes());
    Ok(DataOutCommand {
        cdb: command_cdb,
        data,
    })
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ForceFlashRecord {
    pub model: String,
    pub nand_id: [u8; 6],
    pub nand_id_hex: String,
    pub parameters: [u32; FORCE_FLASH_PARAMETER_COUNT],
    pub trailing_fields: Vec<String>,
    pub source_line: usize,
    pub source_record_sha256: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ForceFlashCopyRule {
    pub minimum_ic_version: u8,
    pub maximum_ic_version: u8,
    pub copied_bytes: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ForceFlashLayoutContract {
    pub source_sha256: &'static str,
    pub memory_map_source_sha256: &'static str,
    pub parser_routine_va: u32,
    pub scan_format_va: u32,
    pub scan_call_va: u32,
    pub host_populate_va: u32,
    pub host_mirror_routine_va: u32,
    pub parsed_parameter_count: usize,
    pub type_parameter_range: [usize; 2],
    pub setting_parameter_range: [usize; 2],
    pub type_copy_rules: [ForceFlashCopyRule; 3],
    pub type_copy_requires_host_flag: bool,
    pub setting_host_bytes: usize,
    pub setting_parser_written_bytes: usize,
    pub setting_clean_room_padding_policy: &'static str,
    pub host_record_offset: u32,
    pub host_record_bytes: usize,
    pub host_mirror_offset: u32,
    pub controller_symbol: &'static str,
    pub controller_address: u32,
    pub controller_span_bytes: usize,
    pub setting_copy_rules: [ForceFlashCopyRule; 4],
    pub force_flash_to_info_offsets_statically_proven: bool,
    pub controller_field_semantics_statically_proven: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EncodedForceFlashParameters {
    pub type_parameters_low_bytes: [u8; FORCE_FLASH_TYPE_PARAMETER_COUNT],
    pub setting_host_record: [u8; FORCE_FLASH_SETTING_HOST_BYTES],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LoweredForceFlashRecord {
    pub ic_version: u8,
    #[serde(flatten)]
    pub encoded: EncodedForceFlashParameters,
    pub active_setting_bytes: usize,
}

/// Return the exact host-side ForceFlash layout recovered from the reviewed
/// SMIMPTool32 image and its matching MemFile map.
pub fn force_flash_layout_contract() -> ForceFlashLayoutContract {
    ForceFlashLayoutContract {
        source_sha256: SMIMPTOOL32_SOURCE_SHA256,
        memory_map_source_sha256: MEM_FILE_SOURCE_SHA256,
        parser_routine_va: FORCE_FLASH_PARSER_ROUTINE_VA,
        scan_format_va: FORCE_FLASH_SCAN_FORMAT_VA,
        scan_call_va: FORCE_FLASH_SCAN_CALL_VA,
        host_populate_va: FORCE_FLASH_HOST_POPULATE_VA,
        host_mirror_routine_va: FORCE_FLASH_HOST_MIRROR_ROUTINE_VA,
        parsed_parameter_count: FORCE_FLASH_PARAMETER_COUNT,
        type_parameter_range: [0, FORCE_FLASH_TYPE_PARAMETER_COUNT],
        setting_parameter_range: [
            FORCE_FLASH_TYPE_PARAMETER_COUNT,
            FORCE_FLASH_PARAMETER_COUNT,
        ],
        type_copy_rules: [
            ForceFlashCopyRule {
                minimum_ic_version: 0x00,
                maximum_ic_version: 0x03,
                copied_bytes: 4,
            },
            ForceFlashCopyRule {
                minimum_ic_version: 0x04,
                maximum_ic_version: 0x05,
                copied_bytes: 7,
            },
            ForceFlashCopyRule {
                minimum_ic_version: 0x06,
                maximum_ic_version: u8::MAX,
                copied_bytes: 4,
            },
        ],
        type_copy_requires_host_flag: true,
        setting_host_bytes: FORCE_FLASH_SETTING_HOST_BYTES,
        setting_parser_written_bytes: 23,
        setting_clean_room_padding_policy:
            "zero byte 23 because the reviewed parser does not initialize it",
        host_record_offset: FORCE_FLASH_HOST_RECORD_OFFSET,
        host_record_bytes: FORCE_FLASH_HOST_RECORD_BYTES,
        host_mirror_offset: FORCE_FLASH_HOST_MIRROR_OFFSET,
        controller_symbol: "sFlashSetting",
        controller_address: FORCE_FLASH_CONTROLLER_ADDRESS,
        controller_span_bytes: FORCE_FLASH_CONTROLLER_SPAN_BYTES,
        setting_copy_rules: [
            ForceFlashCopyRule {
                minimum_ic_version: 0x00,
                maximum_ic_version: 0x07,
                copied_bytes: 8,
            },
            ForceFlashCopyRule {
                minimum_ic_version: 0x08,
                maximum_ic_version: 0x0d,
                copied_bytes: 17,
            },
            ForceFlashCopyRule {
                minimum_ic_version: 0x0e,
                maximum_ic_version: 0x36,
                copied_bytes: 24,
            },
            ForceFlashCopyRule {
                minimum_ic_version: 0x37,
                maximum_ic_version: u8::MAX,
                copied_bytes: 8,
            },
        ],
        force_flash_to_info_offsets_statically_proven: false,
        controller_field_semantics_statically_proven: false,
    }
}

fn force_flash_active_setting_bytes(ic_version: u8) -> usize {
    match ic_version {
        0x08..=0x0d => 17,
        0x0e..=0x36 => 24,
        0x00..=0x07 | 0x37..=u8::MAX => 8,
    }
}

/// Reproduce the overlapping one-byte-spaced `%X` stores used by the genuine
/// parser. This preserves the low byte of each positional value and the high
/// bytes of the final setting value. The parser never writes byte 23 of the
/// 24-byte setting record; the clean-room encoder deterministically zeroes it.
pub fn encode_force_flash_parameters(
    parameters: &[u32; FORCE_FLASH_PARAMETER_COUNT],
) -> EncodedForceFlashParameters {
    let mut type_storage = [0u8; FORCE_FLASH_TYPE_PARAMETER_COUNT + 3];
    for (offset, value) in parameters[..FORCE_FLASH_TYPE_PARAMETER_COUNT]
        .iter()
        .enumerate()
    {
        type_storage[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    let mut setting_host_record = [0u8; FORCE_FLASH_SETTING_HOST_BYTES];
    for (offset, value) in parameters[FORCE_FLASH_TYPE_PARAMETER_COUNT..]
        .iter()
        .enumerate()
    {
        setting_host_record[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }
    let mut type_parameters_low_bytes = [0u8; FORCE_FLASH_TYPE_PARAMETER_COUNT];
    type_parameters_low_bytes.copy_from_slice(&type_storage[..FORCE_FLASH_TYPE_PARAMETER_COUNT]);
    EncodedForceFlashParameters {
        type_parameters_low_bytes,
        setting_host_record,
    }
}

pub fn lower_force_flash_parameters(
    parameters: &[u32; FORCE_FLASH_PARAMETER_COUNT],
    ic_version: u8,
) -> LoweredForceFlashRecord {
    LoweredForceFlashRecord {
        ic_version,
        encoded: encode_force_flash_parameters(parameters),
        active_setting_bytes: force_flash_active_setting_bytes(ic_version),
    }
}

fn parse_hex_u32(value: &str, label: &str, line: usize) -> Result<u32> {
    if value.is_empty() || value.len() > 8 || !value.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::Invalid(format!(
            "SMI ForceFlash line {line} has invalid hexadecimal {label}"
        )));
    }
    u32::from_str_radix(value, 16).map_err(|_| {
        Error::Invalid(format!(
            "SMI ForceFlash line {line} hexadecimal {label} exceeds u32"
        ))
    })
}

/// Parse genuine `ForceFlash-*.SET` records without executing the MPTool.
///
/// The six-byte NAND ID is followed by the exact 27 `%X` fields consumed by
/// the recovered factory parser. Their controller-specific semantics remain
/// positional until each downstream use has been recovered.
pub fn parse_force_flash(bytes: &[u8]) -> Result<Vec<ForceFlashRecord>> {
    if bytes.is_empty() || bytes.len() > MAX_FORCE_FLASH_BYTES || bytes.contains(&0) {
        return Err(Error::Invalid(format!(
            "SMI ForceFlash input must be non-NUL CP936/GBK in 1..={MAX_FORCE_FLASH_BYTES} bytes"
        )));
    }
    let (text, had_errors) = GBK.decode_without_bom_handling(bytes);
    if had_errors {
        return Err(Error::Invalid(
            "SMI ForceFlash input is not valid CP936/GBK".into(),
        ));
    }
    let mut records = Vec::new();
    let mut recognized_section = false;
    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        if line_number > MAX_FORCE_FLASH_LINES {
            return Err(Error::Invalid(format!(
                "SMI ForceFlash input exceeds {MAX_FORCE_FLASH_LINES} lines"
            )));
        }
        let line = raw_line.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            recognized_section = line.eq_ignore_ascii_case("[2673-83AB-UFD]");
            continue;
        }
        if !recognized_section {
            continue;
        }
        let Some((raw_model, raw_value)) = line.split_once('=') else {
            return Err(Error::Invalid(format!(
                "SMI ForceFlash line {line_number} has no assignment delimiter"
            )));
        };
        let model = raw_model.trim();
        if model.is_empty() || model.len() > 1024 {
            return Err(Error::Invalid(format!(
                "SMI ForceFlash line {line_number} has an invalid model key"
            )));
        }
        let fields = raw_value.split(',').map(str::trim).collect::<Vec<_>>();
        if fields.len() < 6 || fields[..6].iter().any(|value| value.is_empty()) {
            continue;
        }
        let first_six_are_hex = fields[..6]
            .iter()
            .all(|value| value.len() <= 2 && value.as_bytes().iter().all(u8::is_ascii_hexdigit));
        if !first_six_are_hex {
            continue;
        }
        let required = 6 + FORCE_FLASH_PARAMETER_COUNT;
        if fields.len() < required {
            return Err(Error::Invalid(format!(
                "SMI ForceFlash line {line_number} has {} numeric fields; expected at least {required}",
                fields.len()
            )));
        }
        let mut nand_id = [0u8; 6];
        for (slot, value) in nand_id.iter_mut().zip(&fields[..6]) {
            *slot =
                u8::try_from(parse_hex_u32(value, "NAND ID byte", line_number)?).map_err(|_| {
                    Error::Invalid(format!(
                        "SMI ForceFlash line {line_number} NAND ID byte exceeds u8"
                    ))
                })?;
        }
        if nand_id == [0; 6] || nand_id == [0xff; 6] {
            return Err(Error::Invalid(format!(
                "SMI ForceFlash line {line_number} uses an empty NAND ID"
            )));
        }
        let mut parameters = [0u32; FORCE_FLASH_PARAMETER_COUNT];
        for (parameter_index, (slot, value)) in
            parameters.iter_mut().zip(&fields[6..required]).enumerate()
        {
            *slot = parse_hex_u32(value, &format!("parameter {parameter_index}"), line_number)?;
        }
        let record_text = format!("{model}={raw_value}");
        records.push(ForceFlashRecord {
            model: model.to_string(),
            nand_id,
            nand_id_hex: hex::encode(nand_id),
            parameters,
            trailing_fields: fields[required..]
                .iter()
                .map(|value| (*value).to_string())
                .collect(),
            source_line: line_number,
            source_record_sha256: hex::encode(Sha256::digest(record_text.as_bytes())),
        });
        if records.len() > MAX_FORCE_FLASH_RECORDS {
            return Err(Error::Invalid(format!(
                "SMI ForceFlash input exceeds {MAX_FORCE_FLASH_RECORDS} records"
            )));
        }
    }
    if records.is_empty() {
        return Err(Error::Invalid(
            "SMI ForceFlash input contains no recovered 27-field records".into(),
        ));
    }
    Ok(records)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct MemorySymbol {
    pub name: String,
    pub address: u32,
    pub source_line: usize,
}

pub fn parse_mem_file(bytes: &[u8]) -> Result<Vec<MemorySymbol>> {
    if bytes.is_empty() || bytes.len() > MAX_MEM_FILE_BYTES || bytes.contains(&0) {
        return Err(Error::Invalid(format!(
            "SMI MemFile input must be non-NUL ASCII in 1..={MAX_MEM_FILE_BYTES} bytes"
        )));
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| Error::Invalid("SMI MemFile input is not UTF-8/ASCII".into()))?;
    if !text.is_ascii() {
        return Err(Error::Invalid(
            "SMI MemFile input contains non-ASCII bytes".into(),
        ));
    }
    let mut in_mem_map = false;
    let mut symbols = Vec::new();
    for (index, raw_line) in text.lines().enumerate() {
        let line_number = index + 1;
        if line_number > MAX_MEM_FILE_LINES {
            return Err(Error::Invalid(format!(
                "SMI MemFile input exceeds {MAX_MEM_FILE_LINES} lines"
            )));
        }
        let line = raw_line.trim_end_matches('\r').trim();
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_mem_map = line.eq_ignore_ascii_case("[MemMap]");
            continue;
        }
        if !in_mem_map {
            continue;
        }
        let (name, raw_address) = line.split_once('=').ok_or_else(|| {
            Error::Invalid(format!(
                "SMI MemFile line {line_number} has no assignment delimiter"
            ))
        })?;
        let name = name.trim();
        if name.is_empty()
            || name.len() > 128
            || !name
                .as_bytes()
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || *byte == b'_')
        {
            return Err(Error::Invalid(format!(
                "SMI MemFile line {line_number} has an invalid symbol name"
            )));
        }
        let (decimal, comment) = raw_address.split_once(';').ok_or_else(|| {
            Error::Invalid(format!(
                "SMI MemFile line {line_number} lacks the hexadecimal address comment"
            ))
        })?;
        let address = decimal.trim().parse::<u32>().map_err(|_| {
            Error::Invalid(format!(
                "SMI MemFile line {line_number} has an invalid decimal address"
            ))
        })?;
        let comment = comment.trim();
        let hex_address = comment
            .strip_prefix("0x")
            .or_else(|| comment.strip_prefix("0X"))
            .ok_or_else(|| {
                Error::Invalid(format!(
                    "SMI MemFile line {line_number} lacks a 0x hexadecimal address"
                ))
            })?;
        let comment_address = u32::from_str_radix(hex_address, 16).map_err(|_| {
            Error::Invalid(format!(
                "SMI MemFile line {line_number} has an invalid hexadecimal address"
            ))
        })?;
        if address != comment_address {
            return Err(Error::Invalid(format!(
                "SMI MemFile line {line_number} decimal and hexadecimal addresses disagree"
            )));
        }
        symbols.push(MemorySymbol {
            name: name.to_string(),
            address,
            source_line: line_number,
        });
    }
    if symbols.is_empty() {
        return Err(Error::Invalid(
            "SMI MemFile input contains no [MemMap] symbols".into(),
        ));
    }
    Ok(symbols)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RawResearchMemoryContract {
    pub source_sha256: String,
    pub symbols: Vec<MemorySymbol>,
    pub symbols_with_overlay_definitions: Vec<String>,
    pub all_required_symbols_present: bool,
}

pub const RAW_RESEARCH_SYMBOLS: [(&str, u32); RAW_RESEARCH_SYMBOL_COUNT] = [
    ("DB_DCCM", 0xc000_0000),
    ("DLW_FPage", 0xc000_0404),
    ("DW_FBlock", 0xc000_041a),
    ("DW_ReadBuf", 0xc000_0430),
    ("DB_FlashID", 0xc000_0478),
    ("DLW_EraseFail", 0xc000_0494),
    ("DLW_ProgramFail", 0xc000_0498),
    ("DB_FSTATUS", 0xc000_04c1),
    ("DLW_PagePerPhyBlock", 0xc000_04cc),
    ("DB_ReadInfoSrc", 0xc000_0df0),
    ("sD_ReadInfo", 0xc000_0e00),
    ("DB_InfoDG", 0xc000_1b80),
    ("sFlashSetting", 0xc000_1b80),
    ("sFlashTypeFlag", 0xc000_1b9c),
    ("SparePool", 0xf000_7400),
    ("XB_ECCErrBitTable", 0xf000_7800),
    ("LinkInfo_START", 0xf000_7d00),
    ("XB_ReadEccStatus", 0xf000_7e3a),
];

/// Authenticate and extract the memory symbols needed to continue static
/// reconstruction of raw data, ECC, retired-block and FTL metadata access.
pub fn raw_research_memory_contract(bytes: &[u8]) -> Result<RawResearchMemoryContract> {
    let digest = hex::encode(Sha256::digest(bytes));
    if digest != MEM_FILE_SOURCE_SHA256 {
        return Err(Error::Permission(format!(
            "SMI MemFile SHA-256 {digest} does not match the reviewed source"
        )));
    }
    let symbols = parse_mem_file(bytes)?;
    let by_name = symbols
        .iter()
        .fold(BTreeMap::<&str, BTreeSet<u32>>::new(), |mut map, symbol| {
            map.entry(symbol.name.as_str())
                .or_default()
                .insert(symbol.address);
            map
        });
    for (name, expected) in RAW_RESEARCH_SYMBOLS {
        match by_name.get(name) {
            Some(addresses) if addresses.contains(&expected) => {}
            Some(addresses) => {
                return Err(Error::Invalid(format!(
                    "SMI MemFile symbol {name} has addresses {}, none equal expected 0x{expected:08x}",
                    addresses
                        .iter()
                        .map(|address| format!("0x{address:08x}"))
                        .collect::<Vec<_>>()
                        .join(", ")
                )));
            }
            None => {
                return Err(Error::Invalid(format!(
                    "SMI MemFile lacks required symbol {name}"
                )));
            }
        }
    }
    Ok(RawResearchMemoryContract {
        source_sha256: digest,
        symbols_with_overlay_definitions: by_name
            .iter()
            .filter_map(|(name, addresses)| (addresses.len() > 1).then_some((*name).to_string()))
            .collect(),
        symbols: symbols
            .into_iter()
            .filter(|symbol| {
                RAW_RESEARCH_SYMBOLS
                    .iter()
                    .any(|(name, _)| *name == symbol.name)
            })
            .collect(),
        all_required_symbols_present: true,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_exact_raw_read_descriptor() {
        let range = FlashPageRange::new(2, 0x1234, 0x1236, 3, 31).unwrap();
        let command = read_flash(range).unwrap();
        assert_eq!(
            command.cdb,
            [0xf1, 0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
        );
        assert_eq!(
            &command.data[..12],
            &[2, 0, 0, 3, 0x12, 0x34, 0, 0, 0, 3, 0, 31]
        );
        assert!(command.data[12..].iter().all(|value| *value == 0));
    }

    #[test]
    fn builds_exact_setup_descriptors() {
        let read = set_read_flash_parameters([1, 2, 3, 4, 5, 6]).unwrap();
        assert_eq!(&read.data[..8], &[1, 0, 2, 0, 3, 4, 5, 6]);
        assert_eq!(read.cdb[0..12], [0xf1, 0x24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);

        let direct = direct_set_read_flash_parameters([1, 2, 3, 4, 5, 6]);
        assert_eq!(&direct.data[..8], &[1, 0, 2, 0, 3, 4, 5, 6]);
        assert_eq!(
            direct.cdb[0..12],
            [0xf5, 0x24, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );

        let write = set_write_flash_parameters([1, 2, 3, 4, 5, 6, 7, 8, 9], &[0xaa]).unwrap();
        assert_eq!(
            &write.data[..14],
            &[1, 2, 3, 4, 0, 5, 6, 7, 0, 0, 0, 0, 8, 9]
        );
        assert_eq!(write.data[SECTOR_BYTES], 0xaa);
        assert_eq!(write.cdb[11], 2);
    }

    #[test]
    fn builds_exact_reviewed_direct_raw_read_sequence() {
        let request =
            DirectFlashReadRequest::new(2, 3, 0x1234, 0x0102_0304, 0x0506_0708, 9).unwrap();
        let trigger = direct_read_flash(request);
        assert_eq!(trigger.cdb[0..3], [0xf5, 0x25, 9]);
        assert_eq!(trigger.cdb[11], 1);
        assert_eq!(trigger.data[0], 2);
        assert_eq!(&trigger.data[2..6], &[0, 3, 0x12, 0x34]);
        assert_eq!(
            &trigger.data[8..16],
            &[0x03, 0x04, 0x07, 0x08, 0x01, 0x02, 0x05, 0x06]
        );

        let chunks = direct_read_page_data(0x1234, 0x5678, 4, 16 * 1024 + 513).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(
            chunks[0].cdb,
            [0xf4, 0x37, 0x12, 0x34, 0x56, 0x78, 4, 19, 0, 0, 0, 32, 0, 0, 0, 0,]
        );
        assert_eq!(chunks[0].transfer_bytes, 16 * 1024);
        assert_eq!(chunks[0].output_bytes, 16 * 1024);
        assert_eq!(
            chunks[1].cdb,
            [0xf4, 0x37, 0x12, 0x34, 0x56, 0x78, 20, 20, 0, 0, 0, 2, 0, 0, 0, 0,]
        );
        assert_eq!(chunks[1].transfer_bytes, 1024);
        assert_eq!(chunks[1].output_offset, 16 * 1024);
        assert_eq!(chunks[1].output_bytes, 513);
    }

    #[test]
    fn builds_exact_reviewed_direct_erase_and_status_commands() {
        let range = FlashBlockRange::new(3, 0x1234, 0x0021).unwrap();
        let mut factory_parameters = [0xa5; SECTOR_BYTES];
        factory_parameters[31] = 0x5a;
        let erase = direct_erase_flash(range, &factory_parameters).unwrap();
        assert_eq!(
            erase.cdb,
            [0xf5, 0x20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
        );
        assert_eq!(&erase.data[..6], &[3, 0, 0, 0x21, 0x12, 0x34]);
        assert!(erase.data[6..16].iter().all(|value| *value == 0));
        assert_eq!(erase.data[16], 0xa5);
        assert_eq!(erase.data[31], 0x5a);
        assert!(direct_erase_flash(range, &[0; SECTOR_BYTES - 1]).is_err());

        let status = direct_check_status(7);
        assert_eq!(
            status.cdb,
            [0xf5, 0x18, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0]
        );
        assert_eq!(status.data[0], 7);
        assert!(status.data[1..].iter().all(|value| *value == 0));
    }

    #[test]
    fn direct_raw_reads_reject_cdb_unit_wrap_and_ecc_truncation() {
        assert!(direct_read_page_data(0, 0, 255, 1025).is_err());
        assert!(direct_read_page_data(0, 0, 0, 256 * 1024).is_ok());
        assert!(direct_read_page_data(0, 0, 0, 256 * 1024 + 1).is_err());
        assert!(direct_read_page_ecc_table(512).is_ok());
        assert!(direct_read_page_ecc_table(1536).is_err());
        assert!(direct_read_page_ecc_table(16 * 1024).is_ok());
    }

    #[test]
    fn preserves_genuine_partial_table_rounding_without_overread() {
        let command = set_page_table(7, &[0xaa; 513]).unwrap();
        assert_eq!(command.cdb[0..3], [0xf1, 0x1c, 7]);
        assert_eq!(command.cdb[11], 2);
        assert_eq!(command.data.len(), 1024);
        assert!(command.data[513..].iter().all(|value| *value == 0));
    }

    #[test]
    fn builds_exact_power_timing_and_retry_setup_commands() {
        let driving = set_driving([1, 2, 3]).unwrap();
        assert_eq!(
            driving.cdb[0..12],
            [0xf1, 0x11, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]
        );
        assert_eq!(&driving.data[..4], &[1, 2, 3, 0]);

        let timeout = set_rb_timeout(0x1234).unwrap();
        assert_eq!(timeout.cdb[1], 0x16);
        assert_eq!(&timeout.data[..3], &[0x12, 0x34, 0]);

        let seed = set_seed_table(&[0xaa; 513]).unwrap();
        assert_eq!(seed.cdb[0..4], [0xf1, 0x15, 0x02, 0x01]);
        assert_eq!(seed.cdb[11], 2);
        assert_eq!(seed.data.len(), 1024);
        assert!(seed.data[513..].iter().all(|value| *value == 0));

        let retry = set_retry_table([4, 5], &[0xbb; 511]).unwrap();
        assert_eq!(retry.cdb[0..4], [0xf1, 0x30, 4, 5]);
        assert_eq!(retry.cdb[11], 1);
        assert_eq!(retry.data.len(), 512);
        assert_eq!(retry.data[511], 0);
    }

    #[test]
    fn builds_exact_generic_bad_column_read_sequence() {
        let chunks = read_bad_column_page_data(0x1234, 0x5678, 4, 8 * 1024 + 513).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(
            chunks[0].cdb,
            [0xf0, 0x37, 0x12, 0x34, 0x56, 0x78, 4, 11, 0, 0, 0, 16, 0, 0, 0, 0]
        );
        assert_eq!(chunks[0].transfer_bytes, 8 * 1024);
        assert_eq!(
            chunks[1].cdb,
            [0xf0, 0x37, 0x12, 0x34, 0x56, 0x78, 12, 12, 0, 0, 0, 2, 0, 0, 0, 0]
        );
        assert_eq!(chunks[1].transfer_bytes, 1024);
        assert_eq!(chunks[1].output_bytes, 513);
    }

    #[test]
    fn builds_exact_metadata_and_differential_table_sequences() {
        let source = vec![0x5a; 1025];
        let chunks = send_block_fail_bit_table(&source).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].cdb[0..3], [0xf1, 0x32, 0]);
        assert_eq!(chunks[1].cdb[0..3], [0xf1, 0x32, 1]);
        assert_eq!(chunks[0].cdb[11], 2);
        assert_eq!(chunks[1].data[0], 0x5a);
        assert!(chunks[1].data[1..].iter().all(|value| *value == 0));

        let diff = write_diff_page_table(0x1234, 0x5678, 2, 9, &[0xcc; 513]).unwrap();
        assert_eq!(
            diff.cdb,
            [0xf1, 0x36, 0x12, 0x34, 0x56, 0x78, 0, 2, 9, 0, 0, 4, 0, 0, 0, 0]
        );
        assert_eq!(diff.data.len(), 2048);
        assert!(diff.data[513..].iter().all(|value| *value == 0));
    }

    #[test]
    fn parses_recovered_force_flash_layout() {
        let mut values = vec!["EC", "1C", "98", "2F", "84", "C9"];
        values.extend(std::iter::repeat_n("1", FORCE_FLASH_PARAMETER_COUNT));
        let text = format!(
            "[2673-83AB-UFD]\r\nA0=Alias,ignored\r\nSamsung model={}\r\n",
            values.join(",")
        );
        let records = parse_force_flash(text.as_bytes()).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].nand_id_hex, "ec1c982f84c9");
        assert_eq!(records[0].parameters, [1; FORCE_FLASH_PARAMETER_COUNT]);
    }

    #[test]
    fn lowers_force_flash_with_the_reviewed_overlapping_scan_layout() {
        let parameters = [
            1,
            0,
            2,
            0,
            0,
            0x10,
            0xb4,
            0xf0,
            0x12,
            0x80,
            0xce,
            0xff,
            0,
            0x60,
            0,
            1,
            0xa0,
            0xb6,
            1,
            4,
            0,
            3,
            0,
            2,
            0,
            0x2c,
            0x1234_5678,
        ];
        let lowered = lower_force_flash_parameters(&parameters, 0x16);
        assert_eq!(
            lowered.encoded.type_parameters_low_bytes,
            [1, 0, 2, 0, 0, 0x10, 0xb4]
        );
        assert_eq!(
            &lowered.encoded.setting_host_record[..20],
            &[
                0xf0, 0x12, 0x80, 0xce, 0xff, 0, 0x60, 0, 1, 0xa0, 0xb6, 1, 4, 0, 3, 0, 2, 0, 0x2c,
                0x78,
            ]
        );
        assert_eq!(
            &lowered.encoded.setting_host_record[20..],
            &[0x56, 0x34, 0x12, 0]
        );
        assert_eq!(lowered.active_setting_bytes, 24);

        let contract = force_flash_layout_contract();
        assert_eq!(contract.setting_parameter_range, [7, 27]);
        assert_eq!(contract.type_copy_rules[1].copied_bytes, 7);
        assert!(contract.type_copy_requires_host_flag);
        assert_eq!(contract.setting_parser_written_bytes, 23);
        assert_eq!(contract.controller_address, 0xc000_1b80);
        assert_eq!(contract.controller_span_bytes, 28);
        assert!(!contract.force_flash_to_info_offsets_statically_proven);
        assert!(!contract.controller_field_semantics_statically_proven);
    }

    #[test]
    fn separates_authenticated_smi_upload_stages_from_unrecovered_field_semantics() {
        let upload = reviewed_info_upload_contract();
        assert_eq!(upload.filename, "Iinfo.bin");
        assert_eq!(upload.transfer_bytes, 1024);
        assert_eq!(upload.command, "F1/14 data-out");
        assert!(upload.host_info_upload_statically_proven);
        assert!(!upload.force_flash_to_info_offsets_statically_proven);

        let loader = reviewed_service_loader_contract();
        assert_eq!(loader.write_ram_command, "F1/04 data-out");
        assert_eq!(loader.legacy_default_entry_address, 0xd000);
        assert_eq!(loader.legacy_ic_1b_entry_address, 0xc800);
        assert_eq!(loader.service_artifact_loader_routine_va, 0x0053_0c0e);
        assert_eq!(loader.service_artifact_32bit_ic_range, [0x28, 0x2e]);
        assert!(loader.host_command_constructors_statically_proven);
        assert!(!loader.selected_artifact_chunk_map_statically_proven);
    }

    #[test]
    fn preserves_every_reviewed_32bit_internal_ic_table_row() {
        let mappings = reviewed_32bit_internal_ic_mappings();
        assert_eq!(mappings.len(), 7);
        assert_eq!(
            mappings
                .iter()
                .map(|mapping| (
                    mapping.internal_ic_version,
                    mapping.controller_name,
                    mapping.table_row_va,
                    mapping.raw_second_field,
                    mapping.chip_code,
                ))
                .collect::<Vec<_>>(),
            vec![
                (0x28, "SM3280AB", 0x0071_c03c, 0xffff, 0x3280),
                (0x29, "SM3280BA", 0x0071_c050, 0x2000, 0x3280),
                (0x2a, "SM3280BB", 0x0071_c064, 0x2000, 0x3280),
                (0x2b, "SM3281AB", 0x0071_c078, 0x2000, 0x3281),
                (0x2c, "SM3281BA", 0x0071_c08c, 0x2000, 0x3281),
                (0x2d, "SM3281BB", 0x0071_c0a0, 0x2000, 0x3281),
                (0x2e, "SM3259AA", 0x0071_c0b4, 0x2000, 0x3281),
            ]
        );
        assert_eq!(
            reviewed_32bit_internal_ic_mapping_for_controller("smi-sm3281bb")
                .unwrap()
                .internal_ic_version,
            0x2d
        );
        assert!(reviewed_32bit_internal_ic_mapping_for_controller("smi-sm3282aa").is_err());
    }

    #[test]
    fn binds_sm3281ba_to_the_reviewed_internal_ic_and_service_loads() {
        let mapping = reviewed_sm3281ba_internal_ic_mapping();
        assert_eq!(mapping.table_row_va, 0x0071_c08c);
        assert_eq!(mapping.table_row_bytes, 20);
        assert_eq!(mapping.internal_ic_version, 0x2c);
        assert_eq!(mapping.raw_second_field, 0x2000);
        assert_eq!(mapping.chip_code, 0x3281);
        assert_eq!(mapping.controller_name, "SM3281BA");
        assert_eq!(mapping.short_name, "3281BA");
        assert!(mapping.mapping_statically_proven);

        let loads = reviewed_sm3281ba_service_artifact_loads();
        assert_eq!(loads[0].role, "sortingcmd");
        assert_eq!(loads[0].entry_address, 0x0000_9000);
        assert_eq!(loads[0].transfer_sectors, 94);
        assert_eq!(loads[1].role, "geninfocmd");
        assert_eq!(loads[1].entry_address, 0x0001_0000);
        assert_eq!(loads[1].transfer_sectors, 96);
        assert_eq!(loads[2].role, "findinfoblock");
        assert_eq!(loads[2].entry_address, 0x0001_8c00);
        assert_eq!(loads[2].transfer_sectors, 22);
        assert_eq!(loads[3].role, "igo2rom");
        assert_eq!(loads[3].entry_address, 0x0001_8000);
        assert_eq!(loads[3].transfer_sectors, 4);
        assert!(loads.iter().all(|load| load.internal_ic_version == 0x2c));
        assert!(loads.iter().all(|load| load.mapping_statically_proven));

        let transition = reviewed_sm3281ba_rom_code_transition();
        assert_eq!(transition.igo2rom_filename, "IGO2ROM.bin");
        assert_eq!(transition.igo2rom_entry_address, 0x0001_8000);
        assert!(transition.path_statically_proven);
        assert!(transition.command_statically_proven);
        assert_eq!(
            sm3281_rom_code_transition(false),
            [0xf0, 0x2c, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(sm3281_rom_code_transition(true)[0..3], [0xf0, 0x2c, 0x80]);
    }

    #[test]
    fn builds_exact_reviewed_32bit_service_artifact_cdb() {
        let sorting = load_service_artifact_32bit(0x2c, 0x0000_9000, &[0x5a; 48_128]).unwrap();
        assert_eq!(
            sorting.cdb,
            [0xf1, 0x0a, 0, 0, 0x90, 0, 0, 0, 0, 0, 0, 94, 0, 0, 0, 0]
        );
        assert_eq!(sorting.data.len(), 48_128);

        let padded = load_service_artifact_32bit(0x28, 0x0001_8c00, &[0xa5; 513]).unwrap();
        assert_eq!(
            padded.cdb,
            [0xf1, 0x0a, 0, 1, 0x8c, 0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0]
        );
        assert_eq!(padded.data.len(), 1024);
        assert!(padded.data[513..].iter().all(|value| *value == 0));

        assert!(load_service_artifact_32bit(0x27, 0, &[1]).is_err());
        assert!(load_service_artifact_32bit(0x2f, 0, &[1]).is_err());
        assert!(load_service_artifact_32bit(0x2c, 0, &[]).is_err());
        assert!(
            load_service_artifact_32bit(0x2c, 0, &[0; SMIMP_SERVICE_ARTIFACT_MAX_BYTES + 1],)
                .is_err()
        );
        assert!(load_reviewed_sm3281ba_service_artifact("isp", &[1]).is_err());
    }

    #[test]
    fn builds_exact_reviewed_sm3281_isp_programming_commands() {
        let location = Sm3281SystemBlockLocation::new(0x1234, 3).unwrap();

        let discovery = read_sm3281_system_block_header(location, 0x5678);
        assert_eq!(
            discovery.cdb,
            [0xf0, 0x01, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 0x1e, 0x34, 2, 0, 0, 0, 0,]
        );
        assert_eq!(discovery.transfer_bytes, 1024);
        assert_eq!(verify_sm3281_isp_header(location, 0x5678), discovery);

        assert_eq!(
            erase_sm3281_system_block(location),
            [0xf0, 0x05, 0x12, 0x34, 0, 0, 0, 0, 0, 0, 0x34, 0, 0, 0, 0, 0,]
        );

        let header = download_sm3281_isp_header(location, 0x0102, 4, &[0xa5; 1024]).unwrap();
        assert_eq!(
            header.cdb,
            [0xf1, 0x01, 0x12, 0x34, 0x01, 0x02, 0, 0, 0, 0x1c, 0x34, 8, 0, 0, 0, 0,]
        );
        assert_eq!(header.data.len(), 4096);
        assert!(header.data[..1024].iter().all(|value| *value == 0xa5));
        assert!(header.data[1024..].iter().all(|value| *value == 0));

        let page = download_sm3281_isp_page(location, 0x0203, 0x0405, 4, &[0x5a; 1025]).unwrap();
        assert_eq!(
            page.cdb,
            [0xf1, 0x01, 0x12, 0x34, 0x02, 0x03, 0, 0, 0xe4, 0x30, 0x34, 8, 0x04, 0x05, 0, 0,]
        );
        assert_eq!(page.data.len(), 4096);
        assert_eq!(page.data[1024], 0x5a);
        assert!(page.data[1025..].iter().all(|value| *value == 0));

        let verify = verify_sm3281_isp_page(location, 0x0203, 4).unwrap();
        assert_eq!(
            verify.cdb,
            [0xf0, 0x01, 0x12, 0x34, 0x02, 0x03, 0, 0x04, 0, 0x12, 0x34, 8, 0, 0, 0, 0,]
        );
        assert_eq!(verify.transfer_bytes, 4096);
    }

    #[test]
    fn rejects_noncanonical_sm3281_isp_programming_inputs() {
        assert!(Sm3281SystemBlockLocation::new(0, 8).is_err());
        let location = Sm3281SystemBlockLocation::new(0, 0).unwrap();
        assert!(download_sm3281_isp_header(location, 0, 0, &[0; 1024]).is_err());
        assert!(download_sm3281_isp_header(location, 0, 1, &[0; 1023]).is_err());
        assert!(download_sm3281_isp_page(location, 0, 0, 1, &[1]).is_err());
        assert!(download_sm3281_isp_page(location, 0, 1, 17, &[1]).is_err());
        assert!(download_sm3281_isp_page(location, 0, 1, 1, &[]).is_err());
        assert!(download_sm3281_isp_page(location, 0, 1, 1, &[0; 1025]).is_err());
        assert!(verify_sm3281_isp_page(location, 0, 17).is_err());
    }

    #[test]
    fn authenticates_only_the_exact_reviewed_sm3281ba_service_artifacts() {
        let contract = reviewed_sm3281ba_sandisk_19nm_contract();
        assert_eq!(contract.controller_id, "smi-sm3281ba");
        assert_eq!(contract.nand_id, "4548a7937e50");
        assert_eq!(contract.internal_ic.internal_ic_version, 0x2c);
        assert_eq!(contract.artifacts.len(), 5);
        assert_eq!(contract.artifact_loads.len(), 4);
        assert_eq!(
            contract.isp_programming.download_isp_routine_va,
            0x0055_6195
        );
        assert_eq!(contract.isp_programming.system_block_candidate_count, 3);
        assert!(
            contract
                .isp_programming
                .command_constructors_statically_proven
        );
        assert!(
            !contract
                .isp_programming
                .composite_isp_modification_statically_proven
        );
        assert_eq!(
            contract.controller_setting.reference_offsets,
            [0x56, 0x3b080, 0x3b604, 0x3b89a]
        );
        assert!(contract.controller_setting.address_references_authenticated);
        assert!(
            !contract
                .controller_setting
                .field_semantics_statically_proven
        );
        assert!(!contract.static_contract_complete);
        assert!(!contract.production_eligible);

        let expected = contract.artifacts[0];
        authenticate_reviewed_service_artifact(
            expected,
            expected.filename,
            expected.size_bytes,
            expected.sha256,
        )
        .unwrap();
        assert!(authenticate_reviewed_service_artifact(
            expected,
            expected.filename,
            expected.size_bytes,
            &"00".repeat(32),
        )
        .is_err());
    }

    #[test]
    fn parses_and_cross_checks_mem_file_addresses() {
        let symbols = parse_mem_file(
            b"[MemMap]\r\nDW_ReadBuf=3221226544 ;0xC0000430\r\nDW_ReadBuf=3221226544 ;0xC0000430\r\n",
        )
        .unwrap();
        assert_eq!(symbols.len(), 2);
        assert_eq!(symbols[0].address, 0xc000_0430);
    }

    #[test]
    fn rejects_noncanonical_ranges_and_lengths() {
        assert!(FlashPageRange::new(0, 2, 1, 0, 0).is_err());
        assert!(FlashBlockRange::new(0, 0, 0).is_err());
        assert!(read_page_ecc_table(512).is_err());
        assert!(read_controller_ram(0, MAX_RAM_TRANSFER_BYTES + 1).is_err());
        assert!(set_seed_table(&[0; MAX_RETRY_TABLE_BYTES + 1]).is_err());
        assert!(set_strong_table(&[]).is_err());
        assert!(set_diff_block(0, &[0; SECTOR_BYTES + 1]).is_err());
        assert!(send_block_fail_bit_table(&[0; MAX_BLOCK_FAIL_BIT_TABLE_BYTES + 1]).is_err());
        assert!(write_diff_page_table(0, 0, 9, 0, &[1]).is_err());
    }

    #[test]
    fn resolves_reviewed_script_defaults_only_with_agreeing_evidence() {
        let mode = resolve_cell_mode("SM3281BA_ISP_MLC_SD_19nm.BIN", r"19nm\MLC\7DDK", 1).unwrap();
        assert_eq!(mode, NandCellMode::Mlc);
        let selection = default_script_selection("smi-sm3281ba", mode).unwrap();
        assert_eq!(selection.low_level_generic_name, "ScriptGP");
        assert_eq!(selection.low_level_artifact_stem_prefix, "ScriptGP3280");
        assert_eq!(selection.high_level_artifact_stem_prefix, "PretestGP3280");
        assert_eq!(selection.low_level_cell_branch_va, 0x0056_c3a0);
    }

    #[test]
    fn rejects_disagreeing_or_unrecovered_script_evidence() {
        assert!(resolve_cell_mode("ISP_MLC.BIN", r"20nm\TLC\A", 1).is_err());
        assert!(resolve_cell_mode("ISP_QLC.BIN", r"20nm\QLC\A", 3).is_err());
        assert!(default_script_selection("smi-sm9999aa", NandCellMode::Mlc).is_err());
    }
}
