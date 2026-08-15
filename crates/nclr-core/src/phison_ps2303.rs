//! Clean-room host contract for the Phison PS2251-03 (PS2303) PRAM loader.
//!
//! The BootROM transport is implemented in [`crate::controller_protocol`].
//! This module defines the protocol spoken after a digest-pinned nclr loader
//! has entered PRAM. It also parses ONFI parameter pages without consulting a
//! model-name table. Nothing in this module authorizes execution on hardware;
//! an exact profile and the normal production gate remain mandatory.

use crate::errors::{Error, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};

pub const LOADER_SCHEMA: u8 = 2;
pub const LOADER_SIGNATURE: &[u8; 8] = b"NCLR2303";
pub const LOADER_IDENTITY: &[u8; 8] = b"PS2303V2";
pub const REVIEWED_CONTROLLER_ID: &str = "phison-ps2303";
pub const RESPONSE_HEADER_BYTES: usize = 32;
pub const ONFI_PARAMETER_BYTES: usize = 256;
pub const ONFI_PARAMETER_COPIES: usize = 3;
pub const GEOMETRY_OVERRIDE_BYTES: usize = 40;
pub const MAX_RAW_PAGE_BYTES: usize = 0x9000 - RESPONSE_HEADER_BYTES;
pub const REVIEWED_LOADER_IMAGE_BYTES: usize = 12_800;
pub const REVIEWED_LOADER_IMAGE_SHA256: &str =
    "30a864283590d1acc4a3fa50b521f0ca78950c5958cc81adfd540e8d2e2586b6";
pub const REVIEWED_LOADER_SOURCE_BINARY_BYTES: usize = 11_874;
pub const REVIEWED_LOADER_SOURCE_BINARY_SHA256: &str =
    "5c429132251f389983c7164c0bbcdbbbcbd032fa1cb5f47a8164a72e1408e306";
const GEOMETRY_OVERRIDE_SIGNATURE: &[u8; 8] = b"NCLRGEO2";

const ONFI_CRC_BASE: u16 = 0x4f4e;
const ONFI_CRC_POLYNOMIAL: u16 = 0x8005;
const READ_TIMEOUT_MS: u64 = 60_000;
const MUTATION_TIMEOUT_MS: u64 = 300_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
#[repr(u8)]
pub enum LoaderCommand {
    ReadControllerId = 0x00,
    ReadNandId = 0x01,
    ReadOnfiParameters = 0x02,
    ConfigureGeometry = 0x03,
    ReadPage = 0x10,
    EraseBlock = 0x11,
    ReadStatus = 0x12,
    ProgramPage = 0x13,
    ExitToBootrom = 0x7e,
}

impl LoaderCommand {
    fn from_byte(value: u8) -> Option<Self> {
        Some(match value {
            0x00 => Self::ReadControllerId,
            0x01 => Self::ReadNandId,
            0x02 => Self::ReadOnfiParameters,
            0x03 => Self::ConfigureGeometry,
            0x10 => Self::ReadPage,
            0x11 => Self::EraseBlock,
            0x12 => Self::ReadStatus,
            0x13 => Self::ProgramPage,
            0x7e => Self::ExitToBootrom,
            _ => return None,
        })
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LoaderAddress {
    pub channel: u8,
    pub chip: u8,
    pub lun: u8,
    pub block: u32,
    pub page: u16,
}

/// Build one fixed-width nclr loader CDB.
///
/// Bytes 3-5 select channel, chip and LUN. Bytes 8-11 contain a big-endian
/// block number and bytes 12-13 a big-endian page number. Geometry comes from
/// either a CRC-valid ONFI parameter page or an exact-NAND-ID-bound override,
/// so the host never guesses a row address at command execution time.
pub fn loader_cdb(command: LoaderCommand, address: LoaderAddress) -> Result<[u8; 16]> {
    if address.channel > 1 || address.chip > 7 {
        return Err(Error::Invalid(
            "PS2303 loader channel must be 0..=1 and chip must be 0..=7".into(),
        ));
    }
    match command {
        LoaderCommand::ReadControllerId
        | LoaderCommand::ReadStatus
        | LoaderCommand::ExitToBootrom => {
            if address != LoaderAddress::default() {
                return Err(Error::Invalid(format!(
                    "PS2303 loader command {command:?} does not accept a NAND address"
                )));
            }
        }
        LoaderCommand::ReadNandId
        | LoaderCommand::ReadOnfiParameters
        | LoaderCommand::ConfigureGeometry => {
            if address.lun != 0 || address.block != 0 || address.page != 0 {
                return Err(Error::Invalid(format!(
                    "PS2303 loader command {command:?} accepts only a channel and chip"
                )));
            }
        }
        LoaderCommand::EraseBlock => {
            if address.page != 0 {
                return Err(Error::Invalid(
                    "PS2303 erase-block command does not accept a page".into(),
                ));
            }
        }
        LoaderCommand::ReadPage | LoaderCommand::ProgramPage => {}
    }
    let mut cdb = [0u8; 16];
    cdb[0] = 0xc7;
    cdb[1] = command as u8;
    cdb[2] = LOADER_SCHEMA;
    cdb[3] = address.channel;
    cdb[4] = address.chip;
    cdb[5] = address.lun;
    cdb[8..12].copy_from_slice(&address.block.to_be_bytes());
    cdb[12..14].copy_from_slice(&address.page.to_be_bytes());
    Ok(cdb)
}

/// Authenticate the reviewed reproducible loader build and its legacy
/// `BtPramCd` transfer structure. The image is generated locally; nclr does
/// not need to redistribute the compiled artifact.
pub fn validate_reviewed_loader_image(image: &[u8]) -> Result<()> {
    if image.len() != REVIEWED_LOADER_IMAGE_BYTES {
        return Err(Error::Invalid(format!(
            "PS2303 loader image has {} bytes; reviewed build has {REVIEWED_LOADER_IMAGE_BYTES}",
            image.len()
        )));
    }
    let digest = hex::encode(Sha256::digest(image));
    if digest != REVIEWED_LOADER_IMAGE_SHA256 {
        return Err(Error::Permission(format!(
            "PS2303 loader image SHA-256 {digest} does not match the reviewed build"
        )));
    }
    crate::controller_protocol::phison_pram_transfer_legacy(image)?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct LoaderResponse<'a> {
    pub command: LoaderCommand,
    pub busy: bool,
    pub failed: bool,
    pub service_mode: bool,
    pub ecc_known: bool,
    pub uncorrectable: bool,
    pub nand_status: u8,
    pub operation_sequence: u32,
    pub corrected_bits: u8,
    pub read_retries: u8,
    pub read_latency_ms: u32,
    pub payload: &'a [u8],
}

/// Validate the signed response envelope emitted by the clean-room loader.
pub fn parse_loader_response(
    data: &[u8],
    expected_command: LoaderCommand,
) -> Result<LoaderResponse<'_>> {
    if data.len() < RESPONSE_HEADER_BYTES {
        return Err(Error::Invalid(format!(
            "PS2303 loader response has {} bytes; expected at least {RESPONSE_HEADER_BYTES}",
            data.len()
        )));
    }
    if &data[..8] != LOADER_SIGNATURE || data[8] != LOADER_SCHEMA {
        return Err(Error::Invalid(
            "PS2303 loader response signature or schema does not match".into(),
        ));
    }
    let command = LoaderCommand::from_byte(data[9]).ok_or_else(|| {
        Error::Invalid(format!(
            "PS2303 loader returned unknown command {:02x}",
            data[9]
        ))
    })?;
    if command != expected_command {
        return Err(Error::Invalid(format!(
            "PS2303 loader returned {command:?} while {expected_command:?} was expected"
        )));
    }
    let payload_bytes = u32::from_le_bytes([data[16], data[17], data[18], data[19]]) as usize;
    if payload_bytes != data.len() - RESPONSE_HEADER_BYTES {
        return Err(Error::Invalid(format!(
            "PS2303 loader response declares {payload_bytes} payload bytes but transferred {}",
            data.len() - RESPONSE_HEADER_BYTES
        )));
    }
    let flags = data[10];
    if flags & !0x1f != 0 {
        return Err(Error::Invalid(format!(
            "PS2303 loader response has unknown flags {:02x}",
            flags
        )));
    }
    if data[20..25].iter().any(|value| *value > 1)
        || data[20] != u8::from(flags & 0x01 != 0)
        || data[21] != u8::from(flags & 0x02 != 0)
        || data[22] != u8::from(flags & 0x04 != 0)
        || data[23] != u8::from(flags & 0x08 != 0)
        || data[24] != u8::from(flags & 0x10 != 0)
        || data[31] != 0
    {
        return Err(Error::Invalid(
            "PS2303 loader response status fields are not canonical".into(),
        ));
    }
    if data[24] != 0 && data[23] == 0 {
        return Err(Error::Invalid(
            "PS2303 loader cannot report uncorrectable data without a known ECC verdict".into(),
        ));
    }
    Ok(LoaderResponse {
        command,
        busy: flags & 0x01 != 0,
        failed: flags & 0x02 != 0,
        service_mode: flags & 0x04 != 0,
        ecc_known: flags & 0x08 != 0,
        uncorrectable: flags & 0x10 != 0,
        nand_status: data[11],
        operation_sequence: u32::from_le_bytes([data[12], data[13], data[14], data[15]]),
        corrected_bits: data[25],
        read_retries: data[26],
        read_latency_ms: u32::from_le_bytes([data[27], data[28], data[29], data[30]]),
        payload: &data[RESPONSE_HEADER_BYTES..],
    })
}

pub trait LoaderTransport {
    fn read(&mut self, cdb: &[u8], length: usize, timeout_ms: u64) -> Result<Vec<u8>>;
    fn write(&mut self, cdb: &[u8], data: &[u8], timeout_ms: u64) -> Result<()>;
    fn no_data(&mut self, cdb: &[u8], timeout_ms: u64) -> Result<()>;
}

impl<T: LoaderTransport + ?Sized> LoaderTransport for &mut T {
    fn read(&mut self, cdb: &[u8], length: usize, timeout_ms: u64) -> Result<Vec<u8>> {
        (**self).read(cdb, length, timeout_ms)
    }

    fn write(&mut self, cdb: &[u8], data: &[u8], timeout_ms: u64) -> Result<()> {
        (**self).write(cdb, data, timeout_ms)
    }

    fn no_data(&mut self, cdb: &[u8], timeout_ms: u64) -> Result<()> {
        (**self).no_data(cdb, timeout_ms)
    }
}

pub fn inspect_controller<T: LoaderTransport>(
    transport: &mut T,
) -> Result<crate::controller_protocol::ControllerIdentity> {
    let data = transport.read(
        &crate::controller_protocol::phison_version_cdb(),
        crate::controller_protocol::PHISON_VERSION_PAGE_LEN,
        READ_TIMEOUT_MS,
    )?;
    let identity = crate::controller_protocol::parse_phison_version_page(&data)?;
    if identity.controller_id != REVIEWED_CONTROLLER_ID {
        return Err(Error::Permission(format!(
            "PS2303 loader contract does not apply to controller {}",
            identity.controller_id
        )));
    }
    Ok(identity)
}

/// Enter BootROM only after parsing the signed PS2251 version page. A `true`
/// result means that the transition command was sent and USB re-enumeration
/// is expected; `false` means the controller was already in BootROM.
pub fn enter_bootrom<T: LoaderTransport>(
    transport: &mut T,
    expected_firmware: &str,
) -> Result<bool> {
    let identity = inspect_controller(transport)?;
    if identity.firmware != expected_firmware {
        return Err(Error::Permission(format!(
            "PS2303 BootROM target firmware mismatch: expected {expected_firmware}, got {}",
            identity.firmware
        )));
    }
    match identity.mode.as_str() {
        "bootrom" => Ok(false),
        "firmware" => {
            transport.no_data(
                &crate::controller_protocol::phison_enter_bootrom_cdb(),
                READ_TIMEOUT_MS,
            )?;
            Ok(true)
        }
        mode => Err(Error::Permission(format!(
            "PS2303 BootROM entry is not valid from {mode} mode"
        ))),
    }
}

/// Transfer and start the exact reviewed loader after binding the live
/// BootROM identity to the caller's expected controller and firmware tuple.
pub fn load_reviewed_loader<T: LoaderTransport>(
    transport: &mut T,
    image: &[u8],
    expected_firmware: &str,
) -> Result<()> {
    validate_reviewed_loader_image(image)?;
    let identity = inspect_controller(transport)?;
    if identity.mode != "bootrom" || identity.firmware != expected_firmware {
        return Err(Error::Permission(format!(
            "PS2303 loader target mismatch: expected {REVIEWED_CONTROLLER_ID} fw {expected_firmware} in bootrom, got {} fw {} in {}",
            identity.controller_id, identity.firmware, identity.mode
        )));
    }
    for chunk in crate::controller_protocol::phison_pram_transfer_legacy(image)? {
        let end = chunk
            .offset
            .checked_add(chunk.length)
            .ok_or_else(|| Error::Invalid("PS2303 loader chunk range overflow".into()))?;
        let payload = image
            .get(chunk.offset..end)
            .ok_or_else(|| Error::Invalid("PS2303 loader chunk is outside the image".into()))?;
        transport.write(&chunk.cdb, payload, MUTATION_TIMEOUT_MS)?;
        let status = transport.read(
            &crate::controller_protocol::phison_transfer_status_cdb(),
            8,
            READ_TIMEOUT_MS,
        )?;
        crate::controller_protocol::validate_phison_transfer_ack(&status, chunk.expected_ack)?;
    }
    transport.no_data(
        &crate::controller_protocol::phison_run_pram_cdb(),
        READ_TIMEOUT_MS,
    )
}

#[cfg(target_os = "macos")]
impl LoaderTransport for crate::macos_scsi::ScsiDevice {
    fn read(&mut self, cdb: &[u8], length: usize, timeout_ms: u64) -> Result<Vec<u8>> {
        crate::macos_scsi::ScsiDevice::read_exact(self, cdb, length, timeout_ms)
    }

    fn write(&mut self, cdb: &[u8], data: &[u8], timeout_ms: u64) -> Result<()> {
        crate::macos_scsi::ScsiDevice::write_exact(self, cdb, data, timeout_ms)
    }

    fn no_data(&mut self, cdb: &[u8], timeout_ms: u64) -> Result<()> {
        crate::macos_scsi::ScsiDevice::execute_no_data(self, cdb, timeout_ms)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OperationStatus {
    pub command: LoaderCommand,
    pub nand_status: u8,
    pub operation_sequence: u32,
    pub ecc_known: bool,
    pub uncorrectable: bool,
    pub corrected_bits: u8,
    pub read_retries: u8,
    pub read_latency_ms: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RawPage {
    pub data_and_oob: Vec<u8>,
    pub status: OperationStatus,
}

/// Typed host session for the reviewed volatile loader. Constructing a
/// session authenticates the loader identity before any NAND command can be
/// issued. Every operation sequence and signed status envelope is checked.
pub struct LoaderSession<T: LoaderTransport> {
    transport: T,
    operation_sequence: u32,
}

impl<T: LoaderTransport> LoaderSession<T> {
    pub fn connect(mut transport: T) -> Result<Self> {
        let cdb = loader_cdb(LoaderCommand::ReadControllerId, LoaderAddress::default())?;
        let data = transport.read(
            &cdb,
            RESPONSE_HEADER_BYTES + LOADER_IDENTITY.len(),
            READ_TIMEOUT_MS,
        )?;
        let response = parse_loader_response(&data, LoaderCommand::ReadControllerId)?;
        Self::require_success(&response)?;
        if response.payload != LOADER_IDENTITY {
            return Err(Error::Permission(format!(
                "PS2303 loader identity {} does not match {}",
                hex::encode(response.payload),
                hex::encode(LOADER_IDENTITY)
            )));
        }
        Ok(Self {
            transport,
            operation_sequence: response.operation_sequence,
        })
    }

    pub fn into_inner(self) -> T {
        self.transport
    }

    fn require_success(response: &LoaderResponse<'_>) -> Result<()> {
        if !response.service_mode {
            return Err(Error::Permission(
                "PS2303 loader response does not confirm service mode".into(),
            ));
        }
        if response.busy {
            return Err(Error::Interrupted(
                "PS2303 loader operation is still busy".into(),
            ));
        }
        if response.failed {
            return Err(Error::Backend(format!(
                "PS2303 loader operation {:?} failed with NAND status {:02x}",
                response.command, response.nand_status
            )));
        }
        Ok(())
    }

    fn accept_incremented(&mut self, response: &LoaderResponse<'_>) -> Result<()> {
        let expected = self.operation_sequence.wrapping_add(1);
        if response.operation_sequence != expected {
            return Err(Error::Invalid(format!(
                "PS2303 loader operation sequence {} does not follow {}",
                response.operation_sequence, self.operation_sequence
            )));
        }
        self.operation_sequence = response.operation_sequence;
        Self::require_success(response)
    }

    fn status_from(response: &LoaderResponse<'_>) -> OperationStatus {
        OperationStatus {
            command: response.command,
            nand_status: response.nand_status,
            operation_sequence: response.operation_sequence,
            ecc_known: response.ecc_known,
            uncorrectable: response.uncorrectable,
            corrected_bits: response.corrected_bits,
            read_retries: response.read_retries,
            read_latency_ms: response.read_latency_ms,
        }
    }

    fn read_status(&mut self, incremented: bool) -> Result<OperationStatus> {
        let cdb = loader_cdb(LoaderCommand::ReadStatus, LoaderAddress::default())?;
        let data = self
            .transport
            .read(&cdb, RESPONSE_HEADER_BYTES, READ_TIMEOUT_MS)?;
        let response = parse_loader_response(&data, LoaderCommand::ReadStatus)?;
        if incremented {
            self.accept_incremented(&response)?;
        } else {
            if response.operation_sequence != self.operation_sequence {
                return Err(Error::Invalid(
                    "PS2303 status read changed the operation sequence".into(),
                ));
            }
            Self::require_success(&response)?;
        }
        Ok(Self::status_from(&response))
    }

    pub fn status(&mut self) -> Result<OperationStatus> {
        self.read_status(false)
    }

    pub fn read_nand_id(&mut self, channel: u8, chip: u8) -> Result<[u8; 6]> {
        let cdb = loader_cdb(
            LoaderCommand::ReadNandId,
            LoaderAddress {
                channel,
                chip,
                ..LoaderAddress::default()
            },
        )?;
        let data = self
            .transport
            .read(&cdb, RESPONSE_HEADER_BYTES + 6, READ_TIMEOUT_MS)?;
        let response = parse_loader_response(&data, LoaderCommand::ReadNandId)?;
        self.accept_incremented(&response)?;
        let id: [u8; 6] = response
            .payload
            .try_into()
            .map_err(|_| Error::Invalid("PS2303 loader NAND ID length mismatch".into()))?;
        if id.iter().all(|byte| *byte == 0) || id.iter().all(|byte| *byte == 0xff) {
            return Err(Error::Invalid(
                "PS2303 loader returned an empty NAND ID".into(),
            ));
        }
        Ok(id)
    }

    pub fn read_onfi_geometry(&mut self, channel: u8, chip: u8) -> Result<OnfiGeometry> {
        let cdb = loader_cdb(
            LoaderCommand::ReadOnfiParameters,
            LoaderAddress {
                channel,
                chip,
                ..LoaderAddress::default()
            },
        )?;
        let data = self.transport.read(
            &cdb,
            RESPONSE_HEADER_BYTES + ONFI_PARAMETER_BYTES * ONFI_PARAMETER_COPIES,
            READ_TIMEOUT_MS,
        )?;
        let response = parse_loader_response(&data, LoaderCommand::ReadOnfiParameters)?;
        self.accept_incremented(&response)?;
        parse_onfi_parameter_copies(response.payload)
    }

    pub fn configure_geometry(
        &mut self,
        channel: u8,
        chip: u8,
        geometry: &GeometryOverride,
    ) -> Result<OperationStatus> {
        let cdb = loader_cdb(
            LoaderCommand::ConfigureGeometry,
            LoaderAddress {
                channel,
                chip,
                ..LoaderAddress::default()
            },
        )?;
        let payload = geometry_override_payload(geometry)?;
        self.transport.write(&cdb, &payload, MUTATION_TIMEOUT_MS)?;
        self.read_status(true)
    }

    pub fn read_page(&mut self, address: LoaderAddress, raw_page_bytes: usize) -> Result<RawPage> {
        if !(1..=MAX_RAW_PAGE_BYTES).contains(&raw_page_bytes) {
            return Err(Error::Invalid(format!(
                "PS2303 raw page length must be in 1..={MAX_RAW_PAGE_BYTES}"
            )));
        }
        let cdb = loader_cdb(LoaderCommand::ReadPage, address)?;
        let data = self.transport.read(
            &cdb,
            RESPONSE_HEADER_BYTES + raw_page_bytes,
            READ_TIMEOUT_MS,
        )?;
        let response = parse_loader_response(&data, LoaderCommand::ReadPage)?;
        self.accept_incremented(&response)?;
        Ok(RawPage {
            data_and_oob: response.payload.to_vec(),
            status: Self::status_from(&response),
        })
    }

    pub fn erase_block(&mut self, address: LoaderAddress) -> Result<OperationStatus> {
        let cdb = loader_cdb(LoaderCommand::EraseBlock, address)?;
        self.transport.no_data(&cdb, MUTATION_TIMEOUT_MS)?;
        self.read_status(true)
    }

    pub fn program_page(
        &mut self,
        address: LoaderAddress,
        data_and_oob: &[u8],
    ) -> Result<OperationStatus> {
        if !(1..=MAX_RAW_PAGE_BYTES).contains(&data_and_oob.len()) {
            return Err(Error::Invalid(format!(
                "PS2303 raw page length must be in 1..={MAX_RAW_PAGE_BYTES}"
            )));
        }
        let cdb = loader_cdb(LoaderCommand::ProgramPage, address)?;
        self.transport
            .write(&cdb, data_and_oob, MUTATION_TIMEOUT_MS)?;
        self.read_status(true)
    }

    pub fn exit_to_bootrom(mut self) -> Result<T> {
        let cdb = loader_cdb(LoaderCommand::ExitToBootrom, LoaderAddress::default())?;
        self.transport.no_data(&cdb, READ_TIMEOUT_MS)?;
        Ok(self.transport)
    }
}

pub fn onfi_crc16(bytes: &[u8]) -> u16 {
    let mut crc = ONFI_CRC_BASE;
    for byte in bytes {
        crc ^= u16::from(*byte) << 8;
        for _ in 0..8 {
            crc = (crc << 1)
                ^ if crc & 0x8000 != 0 {
                    ONFI_CRC_POLYNOMIAL
                } else {
                    0
                };
        }
    }
    crc
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct GeometryOverride {
    pub page_bytes: u32,
    pub oob_bytes: u16,
    pub pages_per_block: u32,
    pub blocks_per_lun: u32,
    pub luns: u8,
    pub column_address_cycles: u8,
    pub row_address_cycles: u8,
    pub bits_per_cell: u8,
    pub expected_nand_id: [u8; 6],
}

impl GeometryOverride {
    pub fn validate(&self) -> Result<()> {
        let raw_bytes = usize::try_from(self.page_bytes)
            .ok()
            .and_then(|value| value.checked_add(usize::from(self.oob_bytes)))
            .ok_or_else(|| Error::Invalid("PS2303 geometry raw-page size overflow".into()))?;
        let total_rows = u64::from(self.blocks_per_lun)
            .checked_mul(u64::from(self.luns))
            .and_then(|value| value.checked_mul(u64::from(self.pages_per_block)))
            .ok_or_else(|| Error::Invalid("PS2303 geometry row count overflow".into()))?;
        let column_limit = 1u64
            .checked_shl(u32::from(self.column_address_cycles) * 8)
            .unwrap_or(0);
        let row_limit = 1u64
            .checked_shl(u32::from(self.row_address_cycles) * 8)
            .unwrap_or(0);
        if self.page_bytes < 2_048
            || self.oob_bytes == 0
            || self.pages_per_block == 0
            || self.blocks_per_lun == 0
            || self.luns == 0
            || !(1..=4).contains(&self.column_address_cycles)
            || !(1..=5).contains(&self.row_address_cycles)
            || !(1..=4).contains(&self.bits_per_cell)
            || raw_bytes > MAX_RAW_PAGE_BYTES
            || raw_bytes as u64 > column_limit
            || total_rows == 0
            || total_rows > row_limit
            || self.expected_nand_id.iter().all(|byte| *byte == 0)
            || self.expected_nand_id.iter().all(|byte| *byte == 0xff)
        {
            return Err(Error::Invalid(
                "PS2303 geometry override is outside the loader bounds".into(),
            ));
        }
        Ok(())
    }
}

/// Encode a non-ONFI geometry discovered from a digest-pinned vendor table.
/// The loader accepts it only when the live six-byte NAND ID is identical.
pub fn geometry_override_payload(geometry: &GeometryOverride) -> Result<[u8; 40]> {
    geometry.validate()?;
    let mut payload = [0u8; GEOMETRY_OVERRIDE_BYTES];
    payload[..8].copy_from_slice(GEOMETRY_OVERRIDE_SIGNATURE);
    payload[8..12].copy_from_slice(&geometry.page_bytes.to_le_bytes());
    payload[12..14].copy_from_slice(&geometry.oob_bytes.to_le_bytes());
    payload[14..18].copy_from_slice(&geometry.pages_per_block.to_le_bytes());
    payload[18..22].copy_from_slice(&geometry.blocks_per_lun.to_le_bytes());
    payload[22] = geometry.luns;
    payload[23] = geometry.column_address_cycles;
    payload[24] = geometry.row_address_cycles;
    payload[25] = geometry.bits_per_cell;
    payload[26..32].copy_from_slice(&geometry.expected_nand_id);
    let crc = onfi_crc16(&payload[..38]);
    payload[38..40].copy_from_slice(&crc.to_le_bytes());
    Ok(payload)
}

fn le16(data: &[u8], offset: usize) -> u16 {
    u16::from_le_bytes([data[offset], data[offset + 1]])
}

fn le32(data: &[u8], offset: usize) -> u32 {
    u32::from_le_bytes([
        data[offset],
        data[offset + 1],
        data[offset + 2],
        data[offset + 3],
    ])
}

fn onfi_string(data: &[u8]) -> String {
    String::from_utf8_lossy(data)
        .trim_matches(|character: char| character == '\0' || character == ' ')
        .to_string()
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OnfiGeometry {
    pub parameter_copy: u8,
    pub revision_bits: u16,
    pub manufacturer: String,
    pub model: String,
    pub jedec_manufacturer_id: u8,
    pub page_bytes: u32,
    pub oob_bytes: u16,
    pub pages_per_block: u32,
    pub blocks_per_lun: u32,
    pub luns: u8,
    pub column_address_cycles: u8,
    pub row_address_cycles: u8,
    pub bits_per_cell: u8,
    pub maximum_bad_blocks_per_lun: u16,
    pub ecc_bits_per_512_bytes: u8,
    pub planes_per_lun: u16,
    pub bus_width_16: bool,
}

impl OnfiGeometry {
    pub fn raw_page_bytes(&self) -> Result<usize> {
        usize::try_from(self.page_bytes)
            .ok()
            .and_then(|page| page.checked_add(usize::from(self.oob_bytes)))
            .filter(|bytes| *bytes <= MAX_RAW_PAGE_BYTES)
            .ok_or_else(|| {
                Error::Invalid(format!(
                    "ONFI raw page exceeds the PS2303 loader limit of {MAX_RAW_PAGE_BYTES} bytes"
                ))
            })
    }

    pub fn total_blocks_per_target(&self) -> Result<u64> {
        u64::from(self.blocks_per_lun)
            .checked_mul(u64::from(self.luns))
            .ok_or_else(|| Error::Invalid("ONFI target block count overflow".into()))
    }
}

fn parse_onfi_parameter_page(page: &[u8], copy: usize) -> Result<OnfiGeometry> {
    if page.len() != ONFI_PARAMETER_BYTES || &page[..4] != b"ONFI" {
        return Err(Error::Invalid(format!(
            "ONFI parameter copy {copy} has no ONFI signature"
        )));
    }
    let expected_crc = le16(page, 254);
    let actual_crc = onfi_crc16(&page[..254]);
    if expected_crc != actual_crc {
        return Err(Error::Invalid(format!(
            "ONFI parameter copy {copy} CRC {actual_crc:04x} != {expected_crc:04x}"
        )));
    }
    let page_bytes = le32(page, 80);
    let oob_bytes = le16(page, 84);
    let pages_per_block = le32(page, 92);
    let blocks_per_lun = le32(page, 96);
    let luns = page[100];
    let column_address_cycles = page[101] & 0x0f;
    let row_address_cycles = page[101] >> 4;
    let bits_per_cell = page[102];
    let interleaved_bits = page[113];
    if page_bytes < 2048
        || oob_bytes == 0
        || pages_per_block == 0
        || blocks_per_lun == 0
        || luns == 0
        || !(1..=4).contains(&column_address_cycles)
        || !(1..=5).contains(&row_address_cycles)
        || bits_per_cell == 0
        || interleaved_bits > 8
        || le16(page, 4) == 0
        || le16(page, 6) & 1 != 0
    {
        return Err(Error::Invalid(format!(
            "ONFI parameter copy {copy} has an invalid memory organization"
        )));
    }
    let geometry = OnfiGeometry {
        parameter_copy: u8::try_from(copy)
            .map_err(|_| Error::Invalid("ONFI parameter copy index overflow".into()))?,
        revision_bits: le16(page, 4),
        manufacturer: onfi_string(&page[32..44]),
        model: onfi_string(&page[44..64]),
        jedec_manufacturer_id: page[64],
        page_bytes,
        oob_bytes,
        pages_per_block,
        blocks_per_lun,
        luns,
        column_address_cycles,
        row_address_cycles,
        bits_per_cell,
        maximum_bad_blocks_per_lun: le16(page, 103),
        ecc_bits_per_512_bytes: page[112],
        planes_per_lun: 1u16 << interleaved_bits,
        bus_width_16: le16(page, 6) & 1 != 0,
    };
    geometry.raw_page_bytes()?;
    geometry.total_blocks_per_target()?;
    Ok(geometry)
}

/// Select the first independently CRC-valid ONFI parameter copy.
///
/// The loader returns all three mandatory copies. nclr deliberately refuses
/// bit-wise majority recovery here: a damaged parameter page must not silently
/// become destructive geometry.
pub fn parse_onfi_parameter_copies(data: &[u8]) -> Result<OnfiGeometry> {
    if data.len() != ONFI_PARAMETER_BYTES * ONFI_PARAMETER_COPIES {
        return Err(Error::Invalid(format!(
            "PS2303 loader ONFI payload has {} bytes; expected {}",
            data.len(),
            ONFI_PARAMETER_BYTES * ONFI_PARAMETER_COPIES
        )));
    }
    let mut failures = Vec::new();
    for (copy, page) in data.chunks_exact(ONFI_PARAMETER_BYTES).enumerate() {
        match parse_onfi_parameter_page(page, copy) {
            Ok(geometry) => return Ok(geometry),
            Err(error) => failures.push(error.to_string()),
        }
    }
    Err(Error::Invalid(format!(
        "no CRC-valid ONFI parameter copy: {}",
        failures.join("; ")
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn onfi_page() -> [u8; ONFI_PARAMETER_BYTES] {
        let mut page = [0u8; ONFI_PARAMETER_BYTES];
        page[..4].copy_from_slice(b"ONFI");
        page[4..6].copy_from_slice(&0x0200u16.to_le_bytes());
        page[32..38].copy_from_slice(b"Micron");
        page[44..51].copy_from_slice(b"MT29F32");
        page[64] = 0x2c;
        page[80..84].copy_from_slice(&8192u32.to_le_bytes());
        page[84..86].copy_from_slice(&448u16.to_le_bytes());
        page[92..96].copy_from_slice(&256u32.to_le_bytes());
        page[96..100].copy_from_slice(&2048u32.to_le_bytes());
        page[100] = 2;
        page[101] = 0x32;
        page[102] = 2;
        page[103..105].copy_from_slice(&80u16.to_le_bytes());
        page[112] = 8;
        page[113] = 1;
        let crc = onfi_crc16(&page[..254]);
        page[254..].copy_from_slice(&crc.to_le_bytes());
        page
    }

    #[test]
    fn builds_exact_loader_cdbs() {
        let cdb = loader_cdb(
            LoaderCommand::ReadPage,
            LoaderAddress {
                channel: 1,
                chip: 7,
                lun: 2,
                block: 0x0102_0304,
                page: 0x0506,
            },
        )
        .unwrap();
        assert_eq!(&cdb[..6], &[0xc7, 0x10, LOADER_SCHEMA, 1, 7, 2]);
        assert_eq!(&cdb[8..14], &[1, 2, 3, 4, 5, 6]);
        assert!(cdb[14..].iter().all(|byte| *byte == 0));
        assert!(loader_cdb(
            LoaderCommand::EraseBlock,
            LoaderAddress {
                page: 1,
                ..LoaderAddress::default()
            }
        )
        .is_err());
        assert!(loader_cdb(
            LoaderCommand::ConfigureGeometry,
            LoaderAddress {
                channel: 1,
                chip: 2,
                ..LoaderAddress::default()
            }
        )
        .is_ok());
        assert!(loader_cdb(
            LoaderCommand::ConfigureGeometry,
            LoaderAddress {
                block: 1,
                ..LoaderAddress::default()
            }
        )
        .is_err());
    }

    #[test]
    fn geometry_override_is_exact_id_bound_and_crc_protected() {
        let geometry = GeometryOverride {
            page_bytes: 8_192,
            oob_bytes: 448,
            pages_per_block: 256,
            blocks_per_lun: 2_048,
            luns: 2,
            column_address_cycles: 2,
            row_address_cycles: 3,
            bits_per_cell: 2,
            expected_nand_id: [0x2c, 0x64, 0x44, 0x4b, 0xa9, 0x00],
        };
        let payload = geometry_override_payload(&geometry).unwrap();
        assert_eq!(&payload[..8], b"NCLRGEO2");
        assert_eq!(&payload[26..32], &geometry.expected_nand_id);
        assert_eq!(
            onfi_crc16(&payload[..38]),
            u16::from_le_bytes([payload[38], payload[39]])
        );
        let mut invalid = geometry;
        invalid.expected_nand_id = [0; 6];
        assert!(geometry_override_payload(&invalid).is_err());
    }

    #[test]
    fn parses_signed_loader_response() {
        let mut response = vec![0u8; RESPONSE_HEADER_BYTES + 6];
        response[..8].copy_from_slice(LOADER_SIGNATURE);
        response[8] = LOADER_SCHEMA;
        response[9] = LoaderCommand::ReadNandId as u8;
        response[10] = 0x04;
        response[22] = 1;
        response[12..16].copy_from_slice(&7u32.to_le_bytes());
        response[16..20].copy_from_slice(&6u32.to_le_bytes());
        response[RESPONSE_HEADER_BYTES..].copy_from_slice(&[0x2c, 0x64, 1, 2, 3, 4]);
        let parsed = parse_loader_response(&response, LoaderCommand::ReadNandId).unwrap();
        assert!(parsed.service_mode);
        assert!(!parsed.failed);
        assert!(!parsed.ecc_known);
        assert!(!parsed.uncorrectable);
        assert_eq!(parsed.operation_sequence, 7);
        assert_eq!(parsed.payload, &[0x2c, 0x64, 1, 2, 3, 4]);
        response[10] = 0x80;
        assert!(parse_loader_response(&response, LoaderCommand::ReadNandId).is_err());

        response[10] = 0x14;
        response[24] = 1;
        assert!(parse_loader_response(&response, LoaderCommand::ReadNandId).is_err());
    }

    #[test]
    fn parses_the_first_crc_valid_onfi_copy() {
        let valid = onfi_page();
        let mut payload = [0u8; ONFI_PARAMETER_BYTES * ONFI_PARAMETER_COPIES];
        payload[..ONFI_PARAMETER_BYTES].copy_from_slice(&valid);
        payload[0] ^= 1;
        payload[ONFI_PARAMETER_BYTES..ONFI_PARAMETER_BYTES * 2].copy_from_slice(&valid);
        let geometry = parse_onfi_parameter_copies(&payload).unwrap();
        assert_eq!(geometry.parameter_copy, 1);
        assert_eq!(geometry.page_bytes, 8192);
        assert_eq!(geometry.oob_bytes, 448);
        assert_eq!(geometry.pages_per_block, 256);
        assert_eq!(geometry.blocks_per_lun, 2048);
        assert_eq!(geometry.total_blocks_per_target().unwrap(), 4096);
        assert_eq!(geometry.planes_per_lun, 2);
        assert_eq!(geometry.raw_page_bytes().unwrap(), 8640);
    }

    #[test]
    fn rejects_crc_damage_and_oversized_raw_pages() {
        let mut payload = [0u8; ONFI_PARAMETER_BYTES * ONFI_PARAMETER_COPIES];
        for page in payload.chunks_exact_mut(ONFI_PARAMETER_BYTES) {
            page.copy_from_slice(&onfi_page());
            page[80] ^= 1;
        }
        assert!(parse_onfi_parameter_copies(&payload).is_err());

        let mut page = onfi_page();
        page[6] = 1;
        let crc = onfi_crc16(&page[..254]);
        page[254..].copy_from_slice(&crc.to_le_bytes());
        for destination in payload.chunks_exact_mut(ONFI_PARAMETER_BYTES) {
            destination.copy_from_slice(&page);
        }
        assert!(parse_onfi_parameter_copies(&payload).is_err());

        let mut page = onfi_page();
        page[80..84].copy_from_slice(&65536u32.to_le_bytes());
        let crc = onfi_crc16(&page[..254]);
        page[254..].copy_from_slice(&crc.to_le_bytes());
        for destination in payload.chunks_exact_mut(ONFI_PARAMETER_BYTES) {
            destination.copy_from_slice(&page);
        }
        assert!(parse_onfi_parameter_copies(&payload).is_err());
    }
}
