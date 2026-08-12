//! Publicly documented controller-vendor protocol primitives.
//!
//! This module intentionally contains only commands whose byte layout and
//! response signature are supported by public source code. A USB VID is a
//! probe hint, never proof of a controller family. A successful built-in
//! identity path independently validates a family signature. Families without
//! a public fixed probe return no identity and require a digest-pinned runtime
//! recipe.

use crate::errors::{Error, Result};
use serde::Serialize;

/// Controller families for which nclr has at least a bounded identification
/// path. This is not the destructive-support matrix; see [`support`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Family {
    PhisonPs2251,
    AlcorAu698x,
    SiliconMotionUfd,
    SandiskCruzer,
    UsbestUt163,
}

impl Family {
    pub fn as_str(self) -> &'static str {
        match self {
            Family::PhisonPs2251 => "phison-ps2251",
            Family::AlcorAu698x => "alcor-au698x",
            Family::SiliconMotionUfd => "silicon-motion-ufd",
            Family::SandiskCruzer => "sandisk-cruzer",
            Family::UsbestUt163 => "usbest-ut163",
        }
    }
}

/// Parse a family from its canonical string.
pub fn family_from_str(value: &str) -> Option<Family> {
    match value {
        "phison-ps2251" => Some(Family::PhisonPs2251),
        "alcor-au698x" => Some(Family::AlcorAu698x),
        "silicon-motion-ufd" => Some(Family::SiliconMotionUfd),
        "sandisk-cruzer" => Some(Family::SandiskCruzer),
        "usbest-ut163" => Some(Family::UsbestUt163),
        _ => None,
    }
}

/// Whether the string names a known controller family (profile validation).
pub fn is_known_family(value: &str) -> bool {
    family_from_str(value).is_some()
}

/// Evidence-bounded support advertised for a family.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct FamilySupport {
    pub family: Family,
    pub identify: bool,
    pub recipe_identify: bool,
    pub nand_identify: bool,
    pub recipe_nand_identify: bool,
    pub service_entry_documented: bool,
    pub volatile_loader_documented: bool,
    pub recipe_engine: bool,
    pub physical_erase: bool,
    pub bbt_rebuild: bool,
    pub ftl_rebuild: bool,
    pub production_tuple_bundled: bool,
    pub reason: &'static str,
}

/// Compile-time implementation matrix. Destructive booleans describe the
/// bounded recipe engine, not availability for an arbitrary device. Runtime
/// execution still requires one authenticated exact-tuple production profile,
/// recipe and qualification report.
pub fn support(family: Family) -> FamilySupport {
    match family {
        Family::PhisonPs2251 => FamilySupport {
            family,
            identify: true,
            recipe_identify: true,
            nand_identify: true,
            recipe_nand_identify: true,
            service_entry_documented: true,
            volatile_loader_documented: true,
            recipe_engine: true,
            physical_erase: true,
            bbt_rebuild: true,
            ftl_rebuild: true,
            production_tuple_bundled: false,
            reason: "identification, BootROM/PRAM loading and the bounded physical/BBT/FTL recipe engine are implemented; an exact NAND burner recipe and independent HIL qualification are not bundled",
        },
        Family::AlcorAu698x => FamilySupport {
            family,
            identify: true,
            recipe_identify: true,
            nand_identify: true,
            recipe_nand_identify: true,
            service_entry_documented: false,
            volatile_loader_documented: false,
            recipe_engine: true,
            physical_erase: true,
            bbt_rebuild: true,
            ftl_rebuild: true,
            production_tuple_bundled: false,
            reason: "configuration/flash-ID identification and the bounded physical/BBT/FTL recipe engine are implemented; no exact destructive AU698x tuple recipe is bundled",
        },
        Family::SiliconMotionUfd => FamilySupport {
            family,
            identify: true,
            recipe_identify: true,
            nand_identify: false,
            recipe_nand_identify: true,
            service_entry_documented: false,
            volatile_loader_documented: false,
            recipe_engine: true,
            physical_erase: true,
            bbt_rebuild: true,
            ftl_rebuild: true,
            production_tuple_bundled: false,
            reason: "the bounded SMI32X identity-page read and physical/BBT/FTL recipe engine are implemented; NAND identity and destructive commands require an exact trace-derived recipe and HIL qualification",
        },
        Family::SandiskCruzer => FamilySupport {
            family,
            identify: false,
            recipe_identify: true,
            nand_identify: false,
            recipe_nand_identify: true,
            service_entry_documented: false,
            volatile_loader_documented: false,
            recipe_engine: true,
            physical_erase: true,
            bbt_rebuild: true,
            ftl_rebuild: true,
            production_tuple_bundled: false,
            reason: "SanDisk Cruzer proprietary controllers use exact USB/SCSI bootstrap selection followed by recipe-owned controller and NAND identity commands; destructive commands require an exact trace-derived recipe and HIL qualification",
        },
        Family::UsbestUt163 => FamilySupport {
            family,
            identify: true,
            recipe_identify: false,
            nand_identify: false,
            recipe_nand_identify: false,
            service_entry_documented: false,
            volatile_loader_documented: false,
            recipe_engine: false,
            physical_erase: false,
            bbt_rebuild: false,
            ftl_rebuild: false,
            production_tuple_bundled: false,
            reason: "USBest UT163 identification uses the controller-owned vendor-specific INQUIRY marker (\"U163\"); no public service CDB, NAND identity or service-mode entry is documented, so destructive commands are unavailable",
        },
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ControllerIdentity {
    pub family: Family,
    pub controller_id: String,
    pub firmware: String,
    pub nand_id: Option<String>,
    pub mode: String,
}

/// Execute the bounded read-only identification sequence for one hinted
/// family. The caller supplies the transport and the identification profile
/// that selected the family (vendor id hints + optional INQUIRY marker).
/// Every returned identity has a validated controller-owned signature; a
/// family without a public fixed probe returns `None` without issuing a
/// command.
pub fn identify_with(
    family: Family,
    marker: Option<&crate::profile::InquiryMarkerIdentify>,
    mut read: impl FnMut(&[u8], usize) -> Result<Vec<u8>>,
) -> Result<Option<ControllerIdentity>> {
    match family {
        Family::PhisonPs2251 => {
            let page = read(&phison_version_cdb(), PHISON_VERSION_PAGE_LEN)?;
            let mut identity = parse_phison_version_page(&page)?;
            let nand = read(&phison_nand_id_cdb(), PHISON_NAND_ID_LEN)?;
            identity.nand_id = Some(parse_six_byte_nand_id(&nand, "Phison")?);
            Ok(Some(identity))
        }
        Family::AlcorAu698x => {
            let config = read(&alcor_config_read_cdb(), ALCOR_CONFIG_LEN)?;
            let mut identity = parse_alcor_config(&config)?;
            let nand = read(&alcor_flash_id_cdb(), ALCOR_FLASH_ID_LEN)?;
            identity.nand_id = Some(parse_six_byte_nand_id(&nand, "Alcor")?);
            Ok(Some(identity))
        }
        Family::SiliconMotionUfd => {
            let page = read(&smi_identity_cdb(), SMI_IDENTITY_LEN)?;
            Ok(Some(parse_smi_identity_page(&page)?))
        }
        // No public fixed vendor CDB is known for the proprietary SanDisk
        // Cruzer family. Identification is supplied by an authenticated
        // exact-tuple recipe after a read-only USB/SCSI bootstrap match.
        Family::SandiskCruzer => Ok(None),
        // USBest UT163: the controller embeds its identity in the standard
        // INQUIRY response's vendor-specific area (beyond the standard
        // data). No vendor CDB is sent, so a non-UT163 device answers
        // INQUIRY harmlessly and the marker simply does not match.
        Family::UsbestUt163 => {
            let marker = marker.ok_or_else(|| {
                Error::Invalid("USBest UT163 identification requires an inquiry marker".into())
            })?;
            let inquiry = read(&inquiry_cdb(marker.alloc_len), marker.alloc_len as usize)?;
            Ok(Some(parse_inquiry_marker(&inquiry, marker)?))
        }
    }
}

// Silicon Motion SM32X ----------------------------------------------------

pub const SMI_IDENTITY_LEN: usize = 1024;

/// Read-only identity-page command reproduced by the public sg_raw
/// transcript for SM3257/SMI32X media.
pub fn smi_identity_cdb() -> [u8; 12] {
    [0xF0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x02]
}

fn valid_iso_date(value: &str) -> bool {
    if value.len() != 10
        || value.as_bytes()[4] != b'-'
        || value.as_bytes()[7] != b'-'
        || !value
            .bytes()
            .enumerate()
            .all(|(index, byte)| matches!(index, 4 | 7) || byte.is_ascii_digit())
    {
        return false;
    }
    let year = value[..4].parse::<u16>().ok();
    let month = value[5..7].parse::<u8>().ok();
    let day = value[8..10].parse::<u8>().ok();
    matches!(year, Some(2000..=2100))
        && matches!(month, Some(1..=12))
        && matches!(day, Some(1..=31))
}

pub fn parse_smi_identity_page(data: &[u8]) -> Result<ControllerIdentity> {
    if data.len() != SMI_IDENTITY_LEN {
        return Err(Error::Invalid(format!(
            "SMI identity response must be {SMI_IDENTITY_LEN} bytes, got {}",
            data.len()
        )));
    }
    let region = &data[0x20..0x80];
    if region
        .iter()
        .any(|byte| *byte != 0 && !byte.is_ascii_graphic() && *byte != b' ')
    {
        return Err(Error::Invalid(
            "SMI identity response contains non-ASCII identity bytes".into(),
        ));
    }
    let meaningful = region
        .iter()
        .position(|byte| *byte == 0)
        .map_or(region, |end| &region[..end]);
    let text = String::from_utf8_lossy(meaningful);
    let fields = text.split_whitespace().collect::<Vec<_>>();
    let family = fields
        .iter()
        .position(|field| *field == "SMI32X")
        .ok_or_else(|| Error::Invalid("SMI32X response signature is absent".into()))?;
    let controller = fields[..family]
        .iter()
        .rev()
        .find(|field| {
            field.starts_with("SM3")
                && field.len() >= 6
                && field
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        .ok_or_else(|| Error::Invalid("SMI controller part number is absent".into()))?;
    let firmware = fields[..family]
        .iter()
        .find(|field| valid_iso_date(field))
        .ok_or_else(|| Error::Invalid("SMI firmware date is absent".into()))?;
    Ok(ControllerIdentity {
        family: Family::SiliconMotionUfd,
        controller_id: format!("smi-{}", controller.to_ascii_lowercase()),
        firmware: (*firmware).into(),
        nand_id: None,
        mode: "firmware".into(),
    })
}

// INQUIRY marker identification (e.g. USBest UT163) ------------------------

/// Standard INQUIRY CDB (no EVPD) with an explicit allocation length.
/// Requesting more than the 36-byte standard data exposes the
/// vendor-specific area where the UT163 controller embeds its marker.
pub fn inquiry_cdb(alloc_len: u16) -> [u8; 6] {
    [0x12, 0, 0, (alloc_len >> 8) as u8, alloc_len as u8, 0]
}

/// Whether a standard INQUIRY response carries the declared marker. The
/// marker is searched only in the vendor-specific area (past the standard
/// data) so a device whose product string merely contains the marker text
/// does not match.
fn has_inquiry_marker(data: &[u8], marker: &str, standard_len: u16) -> bool {
    if data.len() < standard_len as usize {
        return false;
    }
    let vendor_area = &data[standard_len as usize..];
    vendor_area
        .windows(marker.len())
        .any(|window| window == marker.as_bytes())
}

/// Parse a controller identification from a standard INQUIRY response using
/// the declared vendor-specific marker. The controller-owned marker is
/// required; the standard vendor/product strings are reported as-is but
/// never drive the family decision on their own.
pub fn parse_inquiry_marker(
    data: &[u8],
    marker: &crate::profile::InquiryMarkerIdentify,
) -> Result<ControllerIdentity> {
    let standard_len = marker.standard_len as usize;
    if data.len() < standard_len {
        return Err(Error::Invalid(format!(
            "INQUIRY response is too short for the vendor area: {} bytes",
            data.len()
        )));
    }
    if !has_inquiry_marker(data, &marker.marker, marker.standard_len) {
        return Err(Error::Invalid(format!(
            "INQUIRY marker {} is absent",
            marker.marker
        )));
    }
    let ascii = |range: std::ops::Range<usize>| {
        String::from_utf8_lossy(&data[range])
            .trim()
            .to_string()
    };
    Ok(ControllerIdentity {
        family: Family::UsbestUt163,
        controller_id: "usbest-ut163".into(),
        // The product revision (bytes 32-35) is the firmware-provided
        // revision of the mass-storage firmware.
        firmware: ascii(32..36),
        nand_id: None,
        mode: "firmware".into(),
    })
}

// Phison PS2251 ------------------------------------------------------------

pub const PHISON_VERSION_PAGE_LEN: usize = 528;pub const PHISON_NAND_ID_LEN: usize = 512;

pub fn phison_version_cdb() -> [u8; 16] {
    let mut cdb = [0u8; 16];
    cdb[0] = 0x06;
    cdb[1] = 0x05;
    cdb
}

pub fn phison_nand_id_cdb() -> [u8; 12] {
    let mut cdb = [0u8; 12];
    cdb[0] = 0x06;
    cdb[1] = 0x56;
    cdb
}

pub fn phison_enter_bootrom_cdb() -> [u8; 16] {
    let mut cdb = [0u8; 16];
    cdb[0] = 0x06;
    cdb[1] = 0xBF;
    cdb
}

pub fn phison_run_pram_cdb() -> [u8; 16] {
    let mut cdb = [0u8; 16];
    cdb[0] = 0x06;
    cdb[1] = 0xB3;
    cdb
}

pub fn phison_transfer_status_cdb() -> [u8; 16] {
    let mut cdb = [0u8; 16];
    cdb[0] = 0x06;
    cdb[1] = 0xB0;
    cdb[4] = 8;
    cdb
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PhisonTransferChunk {
    pub cdb: [u8; 16],
    pub offset: usize,
    pub length: usize,
    pub expected_ack: u8,
}

const PHISON_PRAM_HEADER: usize = 0x200;
const PHISON_PRAM_MAX_IMAGE: usize = 1024 * 1024;

fn phison_pram_chunks(image: &[u8], body_len: usize) -> Result<Vec<PhisonTransferChunk>> {
    const MAX_BODY: usize = 0x8000;
    debug_assert_eq!(image.len(), PHISON_PRAM_HEADER + body_len);

    let mut header = [0u8; 16];
    header[0] = 0x06;
    header[1] = 0xB1;
    header[2] = 0x03;
    header[8] = 0x01;
    let mut chunks = vec![PhisonTransferChunk {
        cdb: header,
        offset: 0,
        length: PHISON_PRAM_HEADER,
        expected_ack: 0x55,
    }];

    let mut address = 0usize;
    while address < body_len {
        let length = (body_len - address).min(MAX_BODY);
        // The image builder pads to 512 bytes and command fields use
        // 512-byte units, so neither value may lose low address bits.
        if !address.is_multiple_of(0x200) || !length.is_multiple_of(0x200) {
            return Err(Error::Invalid(
                "Phison PRAM chunk is not 512-byte aligned".into(),
            ));
        }
        let command_address = u16::try_from(address >> 9)
            .map_err(|_| Error::Invalid("Phison PRAM command address overflow".into()))?;
        let command_length = u16::try_from(length >> 9)
            .map_err(|_| Error::Invalid("Phison PRAM command length overflow".into()))?;
        let mut cdb = [0u8; 16];
        cdb[0] = 0x06;
        cdb[1] = 0xB1;
        cdb[2] = 0x02;
        cdb[3..5].copy_from_slice(&command_address.to_be_bytes());
        cdb[7..9].copy_from_slice(&command_length.to_be_bytes());
        chunks.push(PhisonTransferChunk {
            cdb,
            offset: PHISON_PRAM_HEADER + address,
            length,
            expected_ack: 0xA5,
        });
        address += length;
    }
    Ok(chunks)
}

fn validate_phison_pram_marker(image: &[u8]) -> Result<()> {
    if image.len() < PHISON_PRAM_HEADER || &image[..8] != b"BtPramCd" {
        return Err(Error::Invalid("not a Phison BtPramCd image".into()));
    }
    if image.len() > PHISON_PRAM_MAX_IMAGE {
        return Err(Error::Invalid(format!(
            "Phison PRAM image exceeds {PHISON_PRAM_MAX_IMAGE} bytes"
        )));
    }
    Ok(())
}

/// Validate the legacy PS2303 `BtPramCd` header whose little-endian field at
/// 0x10 is a 1 KiB page count, then build its bounded transfer sequence.
pub fn phison_pram_transfer_legacy(image: &[u8]) -> Result<Vec<PhisonTransferChunk>> {
    validate_phison_pram_marker(image)?;
    let pages = u32::from_le_bytes([image[0x10], image[0x11], image[0x12], image[0x13]]);
    if pages == 0 || pages > 32 {
        return Err(Error::Invalid(format!(
            "Phison PRAM body page count {pages} is outside 1..=32"
        )));
    }
    let body_len = usize::try_from(pages)
        .ok()
        .and_then(|v| v.checked_mul(0x400))
        .ok_or_else(|| Error::Invalid("Phison PRAM body length overflow".into()))?;
    let expected_len = PHISON_PRAM_HEADER
        .checked_add(body_len)
        .ok_or_else(|| Error::Invalid("Phison PRAM image length overflow".into()))?;
    if image.len() != expected_len {
        return Err(Error::Invalid(format!(
            "Phison PRAM image length {} does not match header {}",
            image.len(),
            expected_len
        )));
    }

    phison_pram_chunks(image, body_len)
}

/// Validate the later MPALL segmented `BtPramCd` container used by PS2251-61,
/// PS2251-07 and PS2251-09 PRAM images. Its nonzero descriptor occupies the
/// first four header bytes; the exact image digest and controller tuple remain
/// the authority for whether the payload is a service loader rather than firmware.
pub fn phison_pram_transfer_extended(image: &[u8]) -> Result<Vec<PhisonTransferChunk>> {
    validate_phison_pram_marker(image)?;
    if image.len() < PHISON_PRAM_HEADER + 0x200 || !image.len().is_multiple_of(0x200) {
        return Err(Error::Invalid(
            "extended Phison PRAM image must contain a 512-byte-aligned body".into(),
        ));
    }
    if image[8..0x10].iter().any(|byte| *byte != 0)
        || image[0x10..0x14].iter().all(|byte| *byte == 0)
        || image[0x14..PHISON_PRAM_HEADER]
            .iter()
            .any(|byte| *byte != 0)
    {
        return Err(Error::Invalid(
            "extended Phison PRAM segment header is malformed".into(),
        ));
    }
    let body = &image[PHISON_PRAM_HEADER..];
    if body.iter().all(|byte| *byte == 0) || body.iter().all(|byte| *byte == 0xff) {
        return Err(Error::Invalid(
            "extended Phison PRAM body is uniform".into(),
        ));
    }
    phison_pram_chunks(image, body.len())
}

/// Build the transfer sequence for either authenticated `BtPramCd` layout.
/// Artifact verification selects one layout explicitly before this function is
/// reached; automatic detection here only keeps the runtime transport shared.
pub fn phison_pram_transfer(image: &[u8]) -> Result<Vec<PhisonTransferChunk>> {
    phison_pram_transfer_legacy(image).or_else(|legacy_error| {
        phison_pram_transfer_extended(image).map_err(|extended_error| {
            Error::Invalid(format!(
                "Phison PRAM matches neither legacy nor extended layout: {legacy_error}; {extended_error}"
            ))
        })
    })
}

pub fn validate_phison_transfer_ack(response: &[u8], expected: u8) -> Result<()> {
    if response.len() != 8 {
        return Err(Error::Invalid(format!(
            "Phison transfer status must be 8 bytes, got {}",
            response.len()
        )));
    }
    if response[0] != expected {
        return Err(Error::Invalid(format!(
            "Phison transfer acknowledgement {:02x} does not match {:02x}",
            response[0], expected
        )));
    }
    Ok(())
}

/// Enter PS2251 BootROM mode through an already identity-bound transport.
/// Returns `true` when the transition command was sent and `false` when the
/// controller was already in BootROM. The caller must expect USB
/// re-enumeration after a successful transition.
pub fn phison_enter_bootrom_with(
    mut read: impl FnMut(&[u8], usize) -> Result<Vec<u8>>,
    mut write: impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<bool> {
    let version = read(&phison_version_cdb(), PHISON_VERSION_PAGE_LEN)?;
    let identity = parse_phison_version_page(&version)?;
    match identity.mode.as_str() {
        "bootrom" => Ok(false),
        "firmware" => {
            write(&phison_enter_bootrom_cdb(), &[])?;
            Ok(true)
        }
        mode => Err(Error::Permission(format!(
            "Phison BootROM entry is not valid from {mode} mode"
        ))),
    }
}

/// Load and start one digest-pinned `BtPramCd` image in PS2251 BootROM.
///
/// This is the complete public clean-room transport sequence: verify the
/// signed version page and exact target, transfer header/body, validate the
/// acknowledgement after every chunk, then issue RUN PRAM. It deliberately
/// implements no NAND erase or metadata operation; those remain separate,
/// profile-certified driver primitives.
pub fn phison_load_pram_with(
    image: &[u8],
    expected_controller_id: &str,
    expected_firmware: &str,
    mut read: impl FnMut(&[u8], usize) -> Result<Vec<u8>>,
    mut write: impl FnMut(&[u8], &[u8]) -> Result<()>,
) -> Result<()> {
    let version = read(&phison_version_cdb(), PHISON_VERSION_PAGE_LEN)?;
    let identity = parse_phison_version_page(&version)?;
    if identity.mode != "bootrom"
        || identity.controller_id != expected_controller_id
        || identity.firmware != expected_firmware
    {
        return Err(Error::Permission(format!(
            "Phison PRAM target mismatch: expected {expected_controller_id} fw {expected_firmware} in bootrom, got {} fw {} in {}",
            identity.controller_id, identity.firmware, identity.mode
        )));
    }
    for chunk in phison_pram_transfer(image)? {
        let end = chunk
            .offset
            .checked_add(chunk.length)
            .ok_or_else(|| Error::Invalid("Phison PRAM chunk range overflow".into()))?;
        let payload = image
            .get(chunk.offset..end)
            .ok_or_else(|| Error::Invalid("Phison PRAM chunk is outside image".into()))?;
        write(&chunk.cdb, payload)?;
        let status = read(&phison_transfer_status_cdb(), 8)?;
        validate_phison_transfer_ack(&status, chunk.expected_ack)?;
    }
    write(&phison_run_pram_cdb(), &[])
}

/// Parse the Phison vendor version page. `VR` at 0x17a and the big-endian
/// chip type at 0x17e are the independent signature used by both public
/// PS2251-03 implementations.
pub fn parse_phison_version_page(data: &[u8]) -> Result<ControllerIdentity> {
    if data.len() < 0x180 {
        return Err(Error::Invalid(format!(
            "Phison version page is too short: {} bytes",
            data.len()
        )));
    }
    if &data[0x17A..0x17C] != b"VR" {
        return Err(Error::Invalid(
            "Phison version page signature VR is absent".into(),
        ));
    }
    let chip = u16::from_be_bytes([data[0x17E], data[0x17F]]);
    if chip == 0 || chip == u16::MAX {
        return Err(Error::Invalid("invalid Phison chip type".into()));
    }
    let firmware = format!("{:02x}.{:02x}.{:02x}", data[0x94], data[0x95], data[0x96]);
    let mode = match &data[0xA0..0xA8] {
        b" PRAM   " => "bootrom",
        b" FW BURN" => "burner",
        b" HV TEST" => "hardware-verify",
        _ => "firmware",
    };
    Ok(ControllerIdentity {
        family: Family::PhisonPs2251,
        controller_id: format!("phison-ps{chip:04x}"),
        firmware,
        nand_id: None,
        mode: mode.into(),
    })
}

pub fn parse_six_byte_nand_id(data: &[u8], context: &str) -> Result<String> {
    if data.len() < 6 {
        return Err(Error::Invalid(format!(
            "{context} NAND id response is too short: {} bytes",
            data.len()
        )));
    }
    let id = &data[..6];
    if id.iter().all(|b| *b == 0) || id.iter().all(|b| *b == 0xFF) {
        return Err(Error::Invalid(format!(
            "{context} returned an empty NAND id"
        )));
    }
    Ok(hex::encode(id))
}

// Alcor AU698x -------------------------------------------------------------

pub const ALCOR_CONFIG_LEN: usize = 512;
pub const ALCOR_FLASH_ID_LEN: usize = 10;

pub fn alcor_config_read_cdb() -> [u8; 10] {
    [0x82, 0x51, 0x01, 0, 0, 0, 0, 0, 0, 0]
}

pub fn alcor_flash_id_cdb() -> [u8; 8] {
    [0xFA, 0, 0, 0, 0, 0, 0, 0]
}

/// Parse the bounded prefix and USB descriptors from the public AU698x
/// configuration-read response. The response starts with 0x99,0x07 in the
/// observed protocol and carries little-endian USB VID/PID/bcdDevice fields.
pub fn parse_alcor_config(data: &[u8]) -> Result<ControllerIdentity> {
    if data.len() != ALCOR_CONFIG_LEN {
        return Err(Error::Invalid(format!(
            "Alcor config response must be 512 bytes, got {}",
            data.len()
        )));
    }
    if data[..2] != [0x99, 0x07] {
        return Err(Error::Invalid(
            "Alcor config signature 99 07 is absent".into(),
        ));
    }
    let vid = u16::from_le_bytes([data[12], data[13]]);
    let pid = u16::from_le_bytes([data[14], data[15]]);
    let bcd = u16::from_le_bytes([data[16], data[17]]);
    if vid == 0 || vid == u16::MAX || pid == 0 || pid == u16::MAX {
        return Err(Error::Invalid(
            "Alcor config contains an invalid USB VID/PID".into(),
        ));
    }
    validate_alcor_descriptors(data)?;
    Ok(ControllerIdentity {
        family: Family::AlcorAu698x,
        controller_id: format!("alcor-au698x-{vid:04x}:{pid:04x}"),
        firmware: format!("{bcd:04x}"),
        nand_id: None,
        mode: "firmware".into(),
    })
}

fn validate_alcor_descriptors(data: &[u8]) -> Result<()> {
    let vendor_len = data[22] as usize;
    if vendor_len < 2 || !vendor_len.is_multiple_of(2) || data[23] != 0x03 {
        return Err(Error::Invalid(
            "invalid Alcor USB vendor string descriptor".into(),
        ));
    }
    let product = 22usize
        .checked_add(vendor_len)
        .ok_or_else(|| Error::Invalid("Alcor descriptor offset overflow".into()))?;
    if product + 2 > data.len() {
        return Err(Error::Invalid(
            "Alcor vendor string descriptor is truncated".into(),
        ));
    }
    let product_len = data[product] as usize;
    if product_len < 2
        || !product_len.is_multiple_of(2)
        || data[product + 1] != 0x03
        || product + product_len > data.len()
    {
        return Err(Error::Invalid(
            "invalid Alcor USB product string descriptor".into(),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::InquiryMarkerIdentify;

    fn ut163_marker_profile() -> InquiryMarkerIdentify {
        InquiryMarkerIdentify {
            marker: "U163".into(),
            alloc_len: 96,
            standard_len: 36,
        }
    }

    #[test]
    fn family_names_round_trip() {
        for family in [
            Family::PhisonPs2251,
            Family::AlcorAu698x,
            Family::SiliconMotionUfd,
            Family::SandiskCruzer,
            Family::UsbestUt163,
        ] {
            assert_eq!(family_from_str(family.as_str()), Some(family));
        }
        assert_eq!(family_from_str("bogus"), None);
        assert!(!is_known_family("bogus"));
    }

    /// The Imation Flash Drive Mini (USBest UT163) INQUIRY vendor area as
    /// measured on hardware: "1.00" revision followed by the
    /// "UtffU163A1BM" vendor-specific marker.
    fn imation_ut163_inquiry() -> Vec<u8> {
        let mut data = vec![0u8; 96];
        data[8..16].copy_from_slice(b"Imation ");
        data[16..32].copy_from_slice(b"Flash Drive     ");
        data[32..36].copy_from_slice(b"1.00");
        data[36..48].copy_from_slice(b"UtffU163A1BM");
        data
    }

    #[test]
    fn ut163_parses_from_vendor_specific_inquiry_marker() {
        let inquiry = imation_ut163_inquiry();
        let identity = parse_inquiry_marker(&inquiry, &ut163_marker_profile()).unwrap();
        assert_eq!(identity.family, Family::UsbestUt163);
        assert_eq!(identity.controller_id, "usbest-ut163");
        assert_eq!(identity.firmware, "1.00");
        assert_eq!(identity.nand_id, None);
    }

    #[test]
    fn ut163_rejects_missing_or_misplaced_marker() {
        // No marker at all.
        let mut plain = vec![0u8; 96];
        plain[8..16].copy_from_slice(b"Generic ");
        plain[16..32].copy_from_slice(b"USB Flash Disk  ");
        plain[32..36].copy_from_slice(b"8.07");
        assert!(parse_inquiry_marker(&plain, &ut163_marker_profile()).is_err());

        // "U163" only in the standard (36-byte) product area must not match:
        // the marker lives in the vendor-specific area beyond it.
        let mut std_area = [0u8; 96];
        std_area[16..32].copy_from_slice(b"U163 Flash Drive");
        assert!(parse_inquiry_marker(&std_area, &ut163_marker_profile()).is_err());
        // Truncated response is rejected, not misparsed.
        assert!(parse_inquiry_marker(&[0u8; 20], &ut163_marker_profile()).is_err());
    }

    #[test]
    fn inquiry_cdb_requests_the_full_vendor_area() {
        assert_eq!(inquiry_cdb(96), [0x12, 0, 0, 0, 0x60, 0]);
        assert_eq!(inquiry_cdb(252), [0x12, 0, 0, 0x00, 0xFC, 0]);
    }

    #[test]
    fn phison_cdbs_are_exact_and_zero_padded() {
        assert_eq!(&phison_version_cdb()[..2], &[0x06, 0x05]);
        assert_eq!(&phison_nand_id_cdb()[..2], &[0x06, 0x56]);
        assert_eq!(&phison_enter_bootrom_cdb()[..2], &[0x06, 0xBF]);
        assert_eq!(&phison_run_pram_cdb()[..2], &[0x06, 0xB3]);
        assert!(phison_version_cdb()[2..].iter().all(|b| *b == 0));
        assert_eq!(phison_transfer_status_cdb()[4], 8);
    }

    #[test]
    fn builds_bounded_phison_pram_transfer() {
        let body_len = 0x8000usize;
        let mut image = vec![0u8; 0x200 + body_len];
        image[..8].copy_from_slice(b"BtPramCd");
        image[0x10..0x14].copy_from_slice(&32u32.to_le_bytes());
        let chunks = phison_pram_transfer(&image).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0].length, 0x200);
        assert_eq!(chunks[0].expected_ack, 0x55);
        assert_eq!(chunks[0].cdb[2], 0x03);
        assert_eq!(chunks[1].offset, 0x200);
        assert_eq!(chunks[1].length, 0x8000);
        assert_eq!(&chunks[1].cdb[3..5], &[0, 0]);
        assert_eq!(&chunks[1].cdb[7..9], &[0, 0x40]);
        assert_eq!(chunks[1].expected_ack, 0xA5);
        validate_phison_transfer_ack(&[0x55, 0, 0, 0, 0, 0, 0, 0], 0x55).unwrap();
        assert!(validate_phison_transfer_ack(&[0xA5; 8], 0x55).is_err());
    }

    #[test]
    fn builds_segmented_mpall_pram_transfer() {
        let mut image = vec![0u8; 0x200 + 0x1c000];
        image[..8].copy_from_slice(b"BtPramCd");
        image[0x10..0x14].copy_from_slice(&[0x10, 0x10, 0x06, 0x00]);
        image[0x200] = 0x5a;
        let chunks = phison_pram_transfer_extended(&image).unwrap();
        assert_eq!(chunks.len(), 5);
        assert_eq!(chunks[0].length, 0x200);
        assert_eq!(chunks[1].length, 0x8000);
        assert_eq!(chunks[4].length, 0x4000);
        assert_eq!(chunks[4].offset, 0x18200);
        assert_eq!(&chunks[4].cdb[3..5], &0x00c0u16.to_be_bytes());
        assert_eq!(&chunks[4].cdb[7..9], &0x0020u16.to_be_bytes());
    }

    #[test]
    fn accepts_observed_extended_mpall_pram_shapes() {
        for (descriptor, body_len, chunk_count) in [
            ([0x0c, 0x08, 0x0a, 0x00], 0x18000, 4),
            ([0x10, 0x10, 0x06, 0x00], 0x1c000, 5),
            ([0x14, 0x10, 0x0e, 0x18], 0x3e000, 9),
        ] {
            let mut image = vec![0u8; 0x200 + body_len];
            image[..8].copy_from_slice(b"BtPramCd");
            image[0x10..0x14].copy_from_slice(&descriptor);
            image[0x200] = 1;
            assert_eq!(
                phison_pram_transfer_extended(&image).unwrap().len(),
                chunk_count
            );
        }
    }

    #[test]
    fn extended_mpall_pram_rejects_bank_and_uniform_payloads() {
        let mut image = vec![0u8; 0x400];
        image[..8].copy_from_slice(b"BtPramCd");
        image[0x10] = 0x10;
        assert!(phison_pram_transfer_extended(&image).is_err());
        image[0x200] = 1;
        image[0x20] = 1;
        assert!(phison_pram_transfer_extended(&image).is_err());
    }

    #[test]
    fn accepts_observed_mpall_burner_page_counts() {
        for pages in [31u32, 32u32] {
            let mut image = vec![0u8; 0x200 + pages as usize * 0x400];
            image[..8].copy_from_slice(b"BtPramCd");
            image[0x10..0x14].copy_from_slice(&pages.to_le_bytes());
            let chunks = phison_pram_transfer(&image).unwrap();
            assert_eq!(chunks[0].length, 0x200);
            assert_eq!(
                chunks.iter().map(|chunk| chunk.length).sum::<usize>(),
                image.len()
            );
        }
    }

    #[test]
    fn rejects_malformed_phison_pram_images() {
        assert!(phison_pram_transfer(&[0; 0x200]).is_err());
        let mut bad = vec![0u8; 0x200 + 0x400];
        bad[..8].copy_from_slice(b"BtPramCd");
        bad[0x10..0x14].copy_from_slice(&2u32.to_le_bytes());
        assert!(phison_pram_transfer(&bad).is_err());
        bad[0x10..0x14].copy_from_slice(&0u32.to_le_bytes());
        assert!(phison_pram_transfer(&bad).is_err());
    }

    #[test]
    fn parses_signed_phison_page() {
        let mut page = vec![0u8; PHISON_VERSION_PAGE_LEN];
        page[0x94..0x97].copy_from_slice(&[1, 3, 0x53]);
        page[0xA0..0xA8].copy_from_slice(b" PRAM   ");
        page[0x17A..0x17C].copy_from_slice(b"VR");
        page[0x17E..0x180].copy_from_slice(&0x2303u16.to_be_bytes());
        let id = parse_phison_version_page(&page).unwrap();
        assert_eq!(id.controller_id, "phison-ps2303");
        assert_eq!(id.firmware, "01.03.53");
        assert_eq!(id.mode, "bootrom");
        assert!(id.nand_id.is_none());
        page[0x17A] = 0;
        assert!(parse_phison_version_page(&page).is_err());
    }

    #[test]
    fn rejects_empty_nand_ids() {
        assert_eq!(
            parse_six_byte_nand_id(&[0x98, 0xDE, 1, 2, 3, 4], "test").unwrap(),
            "98de01020304"
        );
        assert!(parse_six_byte_nand_id(&[0; 6], "test").is_err());
        assert!(parse_six_byte_nand_id(&[0xFF; 6], "test").is_err());
    }

    #[test]
    fn parses_bounded_alcor_config() {
        let mut config = vec![0u8; ALCOR_CONFIG_LEN];
        config[..2].copy_from_slice(&[0x99, 0x07]);
        config[12..14].copy_from_slice(&0x058Fu16.to_le_bytes());
        config[14..16].copy_from_slice(&0x6387u16.to_le_bytes());
        config[16..18].copy_from_slice(&0x0102u16.to_le_bytes());
        config[22] = 4;
        config[23] = 3;
        config[24..26].copy_from_slice(b"A\0");
        config[26] = 4;
        config[27] = 3;
        config[28..30].copy_from_slice(b"B\0");
        let id = parse_alcor_config(&config).unwrap();
        assert_eq!(id.controller_id, "alcor-au698x-058f:6387");
        assert_eq!(id.firmware, "0102");
        config[0] = 0;
        assert!(parse_alcor_config(&config).is_err());
    }

    #[test]
    fn destructive_recipe_engine_is_compiled_for_every_supported_family() {
        for family in [
            Family::PhisonPs2251,
            Family::AlcorAu698x,
            Family::SiliconMotionUfd,
            Family::SandiskCruzer,
        ] {
            let s = support(family);
            assert!(s.recipe_engine);
            assert!(s.recipe_nand_identify);
            assert!(s.physical_erase);
            assert!(s.bbt_rebuild);
            assert!(s.ftl_rebuild);
            assert!(!s.production_tuple_bundled);
        }
    }

    #[test]
    fn sandisk_probe_never_guesses_a_vendor_command() {
        let mut called = false;
        let identity = identify_with(Family::SandiskCruzer, None, |_, _| {
            called = true;
            Err(Error::Invalid("unexpected transport call".into()))
        })
        .unwrap();
        assert!(identity.is_none());
        assert!(!called);
    }

    #[test]
    fn phison_probe_sequence_is_bounded_and_signed() {
        let mut calls = Vec::<(Vec<u8>, usize)>::new();
        let identity = identify_with(Family::PhisonPs2251, None, |cdb, len| {
            calls.push((cdb.to_vec(), len));
            if cdb == phison_version_cdb() {
                let mut page = vec![0u8; PHISON_VERSION_PAGE_LEN];
                page[0x94..0x97].copy_from_slice(&[1, 3, 0x53]);
                page[0x17A..0x17C].copy_from_slice(b"VR");
                page[0x17E..0x180].copy_from_slice(&0x2303u16.to_be_bytes());
                Ok(page)
            } else {
                let mut nand = vec![0u8; PHISON_NAND_ID_LEN];
                nand[..6].copy_from_slice(&[0x98, 0xDE, 0x94, 0x82, 0x76, 0x56]);
                Ok(nand)
            }
        })
        .unwrap()
        .unwrap();
        assert_eq!(identity.controller_id, "phison-ps2303");
        assert_eq!(identity.nand_id.as_deref(), Some("98de94827656"));
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], (phison_version_cdb().to_vec(), 528));
        assert_eq!(calls[1], (phison_nand_id_cdb().to_vec(), 512));
    }

    #[test]
    fn smi_probe_uses_the_documented_identity_page() {
        let mut calls = Vec::new();
        let identity = identify_with(Family::SiliconMotionUfd, None, |cdb, len| {
            calls.push((cdb.to_vec(), len));
            let mut page = vec![0u8; SMI_IDENTITY_LEN];
            let signature = b"  2013-02-26  SM3257ENLTBA   SMI32X";
            page[0x20..0x20 + signature.len()].copy_from_slice(signature);
            Ok(page)
        })
        .unwrap()
        .unwrap();
        assert_eq!(calls, vec![(smi_identity_cdb().to_vec(), 1024)]);
        assert_eq!(identity.controller_id, "smi-sm3257enltba");
        assert_eq!(identity.firmware, "2013-02-26");
        assert!(identity.nand_id.is_none());

        let mut invalid = vec![0u8; SMI_IDENTITY_LEN];
        let signature = b"  2013-02-26  SM3257ENLTBA   UNKNOWN";
        invalid[0x20..0x20 + signature.len()].copy_from_slice(signature);
        assert!(parse_smi_identity_page(&invalid).is_err());
    }
}
