//! Standard SD card register parsing used by the native erase path.
//!
//! This module intentionally handles only protocol-defined information. It
//! does not infer an internal flash controller or any vendor service command
//! from CID/CSD/SCR values.

use crate::errors::{Error, Result};
use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Addressing {
    Byte,
    Block,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct CsdEraseInfo {
    pub structure: u8,
    pub addressing: Addressing,
    pub erase_command_class: bool,
}

/// Decode the protocol fields needed before CMD32/CMD33 may be used.
/// Linux exposes the raw 128-bit CSD as exactly 32 hexadecimal characters.
pub fn parse_csd_erase_info(csd: &str) -> Result<CsdEraseInfo> {
    let csd = csd.trim();
    if csd.len() != 32 || !csd.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Invalid(
            "SD CSD must contain exactly 128 hexadecimal bits".into(),
        ));
    }
    let raw = hex::decode(csd).map_err(|error| Error::Invalid(format!("SD CSD: {error}")))?;
    let structure = raw[0] >> 6;
    let addressing = match structure {
        0 => Addressing::Byte,
        // CSD v2 and v3 identify block-addressed SDHC/SDXC and SDUC cards.
        1 | 2 => Addressing::Block,
        _ => {
            return Err(Error::Invalid(format!(
                "SD CSD structure {structure} is not defined"
            )))
        }
    };
    // CCC is CSD bits 95:84. Class 5 is the standard erase command class.
    let command_classes = (u16::from(raw[4]) << 4) | u16::from(raw[5] >> 4);
    Ok(CsdEraseInfo {
        structure,
        addressing,
        erase_command_class: command_classes & (1 << 5) != 0,
    })
}

/// Compute the inclusive CMD32/CMD33 arguments for the complete 512-byte
/// sector range. SDSC uses the byte address of each sector's first byte;
/// block-addressed cards use the sector number directly.
pub fn full_range_erase_arguments(
    sectors: u64,
    addressing: Addressing,
    erase_size_bytes: u64,
) -> Result<(u32, u32)> {
    const SECTOR_BYTES: u64 = 512;
    if sectors == 0 {
        return Err(Error::Invalid("SD card has no addressable sectors".into()));
    }
    if erase_size_bytes < SECTOR_BYTES || !erase_size_bytes.is_multiple_of(SECTOR_BYTES) {
        return Err(Error::Invalid(
            "SD erase size is absent or not 512-byte aligned".into(),
        ));
    }
    let erase_sectors = erase_size_bytes / SECTOR_BYTES;
    if !sectors.is_multiple_of(erase_sectors) {
        return Err(Error::Unsupported(format!(
            "the complete SD user range ({sectors} sectors) is not aligned to the card erase size ({erase_sectors} sectors)"
        )));
    }
    let last_sector = sectors - 1;
    let end = match addressing {
        Addressing::Byte => last_sector.checked_mul(SECTOR_BYTES).ok_or_else(|| {
            Error::Unsupported("SDSC byte address exceeds the CMD33 argument".into())
        })?,
        Addressing::Block => last_sector,
    };
    let end = u32::try_from(end)
        .map_err(|_| Error::Unsupported("SD user range exceeds the CMD33 argument".into()))?;
    Ok((0, end))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csd_structure_selects_byte_or_block_addressing_and_checks_erase_class() {
        let sdsc = parse_csd_erase_info("00000000020000000000000000000000").unwrap();
        assert_eq!(sdsc.structure, 0);
        assert_eq!(sdsc.addressing, Addressing::Byte);
        assert!(sdsc.erase_command_class);

        let sdhc = parse_csd_erase_info("40000000020000000000000000000000").unwrap();
        assert_eq!(sdhc.addressing, Addressing::Block);
        assert!(sdhc.erase_command_class);

        let sduc = parse_csd_erase_info("80000000020000000000000000000000").unwrap();
        assert_eq!(sduc.structure, 2);
        assert_eq!(sduc.addressing, Addressing::Block);

        let no_erase = parse_csd_erase_info("40000000000000000000000000000000").unwrap();
        assert!(!no_erase.erase_command_class);
        assert!(parse_csd_erase_info("c0000000020000000000000000000000").is_err());
        assert!(parse_csd_erase_info("40").is_err());
    }

    #[test]
    fn full_range_arguments_cover_old_and_new_sd_addressing() {
        let one_gib_sectors = 1_073_741_824 / 512;
        assert_eq!(
            full_range_erase_arguments(one_gib_sectors, Addressing::Byte, 512).unwrap(),
            (0, 0x3fff_fe00)
        );
        assert_eq!(
            full_range_erase_arguments(one_gib_sectors, Addressing::Block, 512).unwrap(),
            (0, 0x001f_ffff)
        );
        assert!(full_range_erase_arguments(1025, Addressing::Byte, 1024).is_err());
        assert!(full_range_erase_arguments(0, Addressing::Block, 512).is_err());
        assert!(
            full_range_erase_arguments(u64::from(u32::MAX) + 2, Addressing::Block, 512).is_err()
        );
    }
}
