//! Complete physical-page sweeps used by erase verification and salvage.
//!
//! The reader visits every declared block and page exactly once in stable
//! flat-block/page order. A failed read is represented explicitly; it is
//! never replaced with a successful blank result. Salvage images use a fixed
//! raw-page stride and write zero-filled bytes for unreadable pages, while the
//! mandatory page map records that those bytes are holes rather than media
//! data.

use crate::errors::{Error, Result};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::io::{Seek, SeekFrom, Write};

pub const MAP_SCHEMA: &str = "nclr.physical-map.v1";

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum PhysicalDisposition {
    #[default]
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

impl PhysicalDisposition {
    fn code(self) -> u8 {
        match self {
            Self::Unknown => 0,
            Self::FactoryBad => 1,
            Self::HistoricalRuntimeBad => 2,
            Self::SystemPreserved => 3,
            Self::SystemRebuild => 4,
            Self::Data => 5,
            Self::Erased => 6,
            Self::Qualified => 7,
            Self::Quarantined => 8,
        }
    }

    /// Only declared FBB, preserved controller blocks and unknown reservation
    /// are excluded from the erased-byte requirement. They are still read and
    /// accounted for by a complete sweep.
    pub fn expected_erased(self) -> bool {
        !matches!(
            self,
            Self::Unknown | Self::FactoryBad | Self::SystemPreserved
        )
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SweepGeometry {
    pub blocks: u64,
    pub channels: u32,
    pub chips_per_channel: u32,
    pub luns_per_chip: u32,
    pub planes_per_lun: u32,
    pub blocks_per_lun: u32,
    pub pages_per_block: u32,
    pub page_bytes: u32,
    pub oob_bytes: u32,
}

impl SweepGeometry {
    pub fn page_stride(self) -> Result<usize> {
        usize::try_from(self.page_bytes)
            .ok()
            .and_then(|value| value.checked_add(self.oob_bytes as usize))
            .filter(|value| *value > 0)
            .ok_or_else(|| Error::Invalid("physical page stride overflow".into()))
    }

    pub fn total_pages(self) -> Result<u64> {
        self.blocks
            .checked_mul(u64::from(self.pages_per_block))
            .ok_or_else(|| Error::Invalid("physical page count overflow".into()))
    }

    pub fn image_bytes(self) -> Result<u64> {
        self.total_pages()?
            .checked_mul(self.page_stride()? as u64)
            .ok_or_else(|| Error::Invalid("physical image size overflow".into()))
    }

    fn page_geometry(self, flat_block: u64, page: u32) -> Result<PhysicalPageGeometry> {
        if flat_block >= self.blocks || page >= self.pages_per_block {
            return Err(Error::Invalid(
                "physical page coordinate is outside sweep geometry".into(),
            ));
        }
        let blocks_per_lun = u64::from(self.blocks_per_lun);
        let luns_per_chip = u64::from(self.luns_per_chip);
        let chips_per_channel = u64::from(self.chips_per_channel);
        let block = flat_block % blocks_per_lun;
        let mut upper = flat_block / blocks_per_lun;
        let lun = upper % luns_per_chip;
        upper /= luns_per_chip;
        let chip = upper % chips_per_channel;
        let channel = upper / chips_per_channel;
        Ok(PhysicalPageGeometry {
            channel,
            chip,
            lun,
            plane: block % u64::from(self.planes_per_lun),
            block,
            page,
        })
    }

    fn validate(self, dispositions: &[PhysicalDisposition]) -> Result<()> {
        let topology_blocks = u64::from(self.channels)
            .checked_mul(u64::from(self.chips_per_channel))
            .and_then(|value| value.checked_mul(u64::from(self.luns_per_chip)))
            .and_then(|value| value.checked_mul(u64::from(self.blocks_per_lun)));
        if self.blocks == 0
            || self.channels == 0
            || self.chips_per_channel == 0
            || self.luns_per_chip == 0
            || self.planes_per_lun == 0
            || self.blocks_per_lun == 0
            || !self.blocks_per_lun.is_multiple_of(self.planes_per_lun)
            || self.pages_per_block == 0
            || self.page_bytes == 0
            || self.blocks != dispositions.len() as u64
            || topology_blocks != Some(self.blocks)
        {
            return Err(Error::Invalid(
                "physical sweep geometry or disposition count is invalid".into(),
            ));
        }
        self.page_stride()?;
        self.image_bytes()?;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PhysicalPageGeometry {
    pub channel: u64,
    pub chip: u64,
    pub lun: u64,
    pub plane: u64,
    pub block: u64,
    pub page: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PageMetrics {
    pub corrected_bits: u64,
    pub read_retries: u64,
    pub read_latency_ms: u64,
    pub uncorrectable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PageRead {
    pub raw: Vec<u8>,
    pub metrics: PageMetrics,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BlockSweepSummary {
    pub flat_block: u64,
    pub channel: u64,
    pub chip: u64,
    pub lun: u64,
    pub plane: u64,
    pub block: u64,
    pub disposition: PhysicalDisposition,
    pub pages: u64,
    pub readable_pages: u64,
    pub unreadable_pages: u64,
    pub uncorrectable_pages: u64,
    pub non_erased_pages: u64,
    pub non_erased_bytes: u64,
    pub maximum_corrected_bits: u64,
    pub maximum_read_retries: u64,
    pub maximum_read_latency_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SweepSummary {
    pub total_blocks: u64,
    pub total_pages: u64,
    pub readable_pages: u64,
    pub unreadable_pages: u64,
    pub uncorrectable_pages: u64,
    pub target_pages: u64,
    pub target_readable_pages: u64,
    pub target_unreadable_pages: u64,
    pub target_uncorrectable_pages: u64,
    pub excluded_unreadable_pages: u64,
    pub target_non_erased_pages: u64,
    pub target_non_erased_bytes: u64,
    pub excluded_non_erased_pages: u64,
    pub all_addresses_readable: bool,
    pub all_pages_correctable: bool,
    pub erased_scope_verified: bool,
    pub ordered_sweep_sha256: String,
    pub image_sha256: Option<String>,
    pub image_bytes: Option<u64>,
    pub blocks: Vec<BlockSweepSummary>,
}

#[derive(Serialize)]
struct MapHeader {
    schema: &'static str,
    record: &'static str,
    geometry: SweepGeometry,
    page_stride: usize,
    image_bytes: u64,
    erased_byte: u8,
    unreadable_fill: &'static str,
    order: &'static str,
}

#[derive(Serialize)]
struct MapPage<'a> {
    schema: &'static str,
    record: &'static str,
    flat_block: u64,
    page: u32,
    geometry: PhysicalPageGeometry,
    disposition: PhysicalDisposition,
    expected_erased: bool,
    image_offset: u64,
    data_length: u32,
    oob_length: u32,
    read_status: &'static str,
    ecc_status: &'static str,
    sha256: Option<String>,
    non_erased_bytes: Option<u64>,
    corrected_bits: Option<u64>,
    read_retries: Option<u64>,
    read_latency_ms: Option<u64>,
    uncorrectable: Option<bool>,
    error: Option<&'a str>,
}

fn write_json_line(writer: &mut dyn Write, value: &impl Serialize) -> Result<()> {
    serde_json::to_writer(&mut *writer, value)
        .map_err(|error| Error::Invalid(format!("physical map serialization: {error}")))?;
    writer
        .write_all(b"\n")
        .map_err(|error| Error::io("write physical page map", Some(error)))
}

fn bounded_error(error: &Error) -> String {
    const MAX_CHARS: usize = 160;
    let message = error.to_string();
    if message.chars().count() <= MAX_CHARS {
        return message;
    }
    let prefix = message.chars().take(MAX_CHARS).collect::<String>();
    format!(
        "{prefix} [truncated sha256={}]",
        hex::encode(Sha256::digest(message.as_bytes()))
    )
}

pub trait WriteSeek: Write + Seek {}

impl<T: Write + Seek> WriteSeek for T {}

/// Visit every physical page. When both output writers are supplied, a raw
/// salvage image and its mandatory page map are generated. Supplying only one
/// writer is invalid because unreadable holes must never be mistaken for data.
pub fn sweep_physical_pages(
    geometry: SweepGeometry,
    dispositions: &[PhysicalDisposition],
    erased_byte: u8,
    mut image: Option<&mut dyn WriteSeek>,
    mut map: Option<&mut dyn Write>,
    mut read_page: impl FnMut(u64, u32) -> Result<PageRead>,
    mut progress: impl FnMut(u64, u64) -> Result<()>,
) -> Result<SweepSummary> {
    geometry.validate(dispositions)?;
    if image.is_some() != map.is_some() {
        return Err(Error::Invalid(
            "physical salvage requires both image and page-map outputs".into(),
        ));
    }
    let page_stride = geometry.page_stride()?;
    let total_pages = geometry.total_pages()?;
    let image_bytes = geometry.image_bytes()?;
    if let Some(writer) = image.as_mut() {
        if writer
            .seek(SeekFrom::End(0))
            .map_err(|error| Error::io("seek physical image", Some(error)))?
            != 0
        {
            return Err(Error::Permission(
                "physical image output must be a new empty file".into(),
            ));
        }
        writer
            .seek(SeekFrom::Start(0))
            .map_err(|error| Error::io("rewind physical image", Some(error)))?;
    }
    if let Some(writer) = map.as_mut() {
        write_json_line(
            *writer,
            &MapHeader {
                schema: MAP_SCHEMA,
                record: "header",
                geometry,
                page_stride,
                image_bytes,
                erased_byte,
                unreadable_fill: "00",
                order: "flat-block-major,page-minor,data-then-oob",
            },
        )?;
    }

    let mut sweep_hash = Sha256::new();
    let mut image_hash = image.as_ref().map(|_| Sha256::new());
    let mut readable_pages = 0u64;
    let mut unreadable_pages = 0u64;
    let mut uncorrectable_pages = 0u64;
    let mut target_pages = 0u64;
    let mut target_readable_pages = 0u64;
    let mut target_unreadable_pages = 0u64;
    let mut target_uncorrectable_pages = 0u64;
    let mut excluded_unreadable_pages = 0u64;
    let mut target_non_erased_pages = 0u64;
    let mut target_non_erased_bytes = 0u64;
    let mut excluded_non_erased_pages = 0u64;
    let zero_fill = vec![0u8; page_stride];
    let mut blocks = Vec::with_capacity(dispositions.len());
    let mut completed_pages = 0u64;
    let mut last_progress = std::time::Instant::now();

    for (flat_index, disposition) in dispositions.iter().copied().enumerate() {
        let flat = flat_index as u64;
        let expected_erased = disposition.expected_erased();
        let block_geometry = geometry.page_geometry(flat, 0)?;
        let mut block = BlockSweepSummary {
            flat_block: flat,
            channel: block_geometry.channel,
            chip: block_geometry.chip,
            lun: block_geometry.lun,
            plane: block_geometry.plane,
            block: block_geometry.block,
            disposition,
            pages: u64::from(geometry.pages_per_block),
            ..BlockSweepSummary::default()
        };
        if expected_erased {
            target_pages = target_pages.saturating_add(u64::from(geometry.pages_per_block));
        }
        for page in 0..geometry.pages_per_block {
            let page_geometry = geometry.page_geometry(flat, page)?;
            if crate::signal::requested() {
                return Err(Error::Interrupted(
                    "physical page sweep was interrupted".into(),
                ));
            }
            let page_index = flat
                .checked_mul(u64::from(geometry.pages_per_block))
                .and_then(|value| value.checked_add(u64::from(page)))
                .ok_or_else(|| Error::Invalid("physical page index overflow".into()))?;
            let offset = page_index
                .checked_mul(page_stride as u64)
                .ok_or_else(|| Error::Invalid("physical image offset overflow".into()))?;
            sweep_hash.update(flat.to_le_bytes());
            sweep_hash.update(page.to_le_bytes());
            sweep_hash.update([disposition.code(), u8::from(expected_erased)]);
            match read_page(flat, page) {
                Ok(read) => {
                    if read.raw.len() != page_stride {
                        return Err(Error::Invalid(format!(
                            "physical page {flat}:{page} returned {} bytes, expected {page_stride}",
                            read.raw.len()
                        )));
                    }
                    let non_erased =
                        read.raw.iter().filter(|byte| **byte != erased_byte).count() as u64;
                    let digest = hex::encode(Sha256::digest(&read.raw));
                    readable_pages = readable_pages.saturating_add(1);
                    block.readable_pages = block.readable_pages.saturating_add(1);
                    block.maximum_corrected_bits = block
                        .maximum_corrected_bits
                        .max(read.metrics.corrected_bits);
                    block.maximum_read_retries =
                        block.maximum_read_retries.max(read.metrics.read_retries);
                    block.maximum_read_latency_ms = block
                        .maximum_read_latency_ms
                        .max(read.metrics.read_latency_ms);
                    if expected_erased {
                        target_readable_pages = target_readable_pages.saturating_add(1);
                        if read.metrics.uncorrectable {
                            target_uncorrectable_pages =
                                target_uncorrectable_pages.saturating_add(1);
                        }
                        if non_erased > 0 {
                            target_non_erased_pages = target_non_erased_pages.saturating_add(1);
                            target_non_erased_bytes =
                                target_non_erased_bytes.saturating_add(non_erased);
                            block.non_erased_pages = block.non_erased_pages.saturating_add(1);
                            block.non_erased_bytes =
                                block.non_erased_bytes.saturating_add(non_erased);
                        }
                    } else if non_erased > 0 {
                        excluded_non_erased_pages = excluded_non_erased_pages.saturating_add(1);
                        block.non_erased_pages = block.non_erased_pages.saturating_add(1);
                        block.non_erased_bytes = block.non_erased_bytes.saturating_add(non_erased);
                    }
                    if read.metrics.uncorrectable {
                        uncorrectable_pages = uncorrectable_pages.saturating_add(1);
                        block.uncorrectable_pages = block.uncorrectable_pages.saturating_add(1);
                    }
                    sweep_hash.update([1]);
                    sweep_hash.update(hex::decode(&digest).expect("SHA-256 is valid hex"));
                    sweep_hash.update(read.metrics.corrected_bits.to_le_bytes());
                    sweep_hash.update(read.metrics.read_retries.to_le_bytes());
                    sweep_hash.update(read.metrics.read_latency_ms.to_le_bytes());
                    sweep_hash.update([u8::from(read.metrics.uncorrectable)]);
                    if let Some(hasher) = image_hash.as_mut() {
                        hasher.update(&read.raw);
                    }
                    if let Some(writer) = image.as_mut() {
                        writer
                            .write_all(&read.raw)
                            .map_err(|error| Error::io("write physical image", Some(error)))?;
                    }
                    if let Some(writer) = map.as_mut() {
                        write_json_line(
                            *writer,
                            &MapPage {
                                schema: MAP_SCHEMA,
                                record: "page",
                                flat_block: flat,
                                page,
                                geometry: page_geometry,
                                disposition,
                                expected_erased,
                                image_offset: offset,
                                data_length: geometry.page_bytes,
                                oob_length: geometry.oob_bytes,
                                read_status: "ok",
                                ecc_status: if read.metrics.uncorrectable {
                                    "uncorrectable"
                                } else {
                                    "correctable"
                                },
                                sha256: Some(digest),
                                non_erased_bytes: Some(non_erased),
                                corrected_bits: Some(read.metrics.corrected_bits),
                                read_retries: Some(read.metrics.read_retries),
                                read_latency_ms: Some(read.metrics.read_latency_ms),
                                uncorrectable: Some(read.metrics.uncorrectable),
                                error: None,
                            },
                        )?;
                    }
                }
                Err(error) => {
                    let message = bounded_error(&error);
                    unreadable_pages = unreadable_pages.saturating_add(1);
                    block.unreadable_pages = block.unreadable_pages.saturating_add(1);
                    if expected_erased {
                        target_unreadable_pages = target_unreadable_pages.saturating_add(1);
                    } else {
                        excluded_unreadable_pages = excluded_unreadable_pages.saturating_add(1);
                    }
                    sweep_hash.update([0]);
                    sweep_hash.update(Sha256::digest(message.as_bytes()));
                    if let Some(hasher) = image_hash.as_mut() {
                        hasher.update(&zero_fill);
                    }
                    if let Some(writer) = image.as_mut() {
                        writer
                            .write_all(&zero_fill)
                            .map_err(|error| Error::io("write physical image hole", Some(error)))?;
                    }
                    if let Some(writer) = map.as_mut() {
                        write_json_line(
                            *writer,
                            &MapPage {
                                schema: MAP_SCHEMA,
                                record: "page",
                                flat_block: flat,
                                page,
                                geometry: page_geometry,
                                disposition,
                                expected_erased,
                                image_offset: offset,
                                data_length: geometry.page_bytes,
                                oob_length: geometry.oob_bytes,
                                read_status: "read-error",
                                ecc_status: "unknown",
                                sha256: None,
                                non_erased_bytes: None,
                                corrected_bits: None,
                                read_retries: None,
                                read_latency_ms: None,
                                uncorrectable: None,
                                error: Some(&message),
                            },
                        )?;
                    }
                }
            }
            completed_pages = completed_pages.saturating_add(1);
            if completed_pages == 1
                || completed_pages == total_pages
                || completed_pages.is_multiple_of(256)
                || last_progress.elapsed() >= std::time::Duration::from_secs(5)
            {
                progress(completed_pages, total_pages)?;
                last_progress = std::time::Instant::now();
            }
        }
        blocks.push(block);
    }

    if let Some(writer) = image.as_mut() {
        writer
            .flush()
            .map_err(|error| Error::io("flush physical image", Some(error)))?;
    }
    if let Some(writer) = map.as_mut() {
        writer
            .flush()
            .map_err(|error| Error::io("flush physical page map", Some(error)))?;
    }
    Ok(SweepSummary {
        total_blocks: geometry.blocks,
        total_pages,
        readable_pages,
        unreadable_pages,
        uncorrectable_pages,
        target_pages,
        target_readable_pages,
        target_unreadable_pages,
        target_uncorrectable_pages,
        excluded_unreadable_pages,
        target_non_erased_pages,
        target_non_erased_bytes,
        excluded_non_erased_pages,
        all_addresses_readable: unreadable_pages == 0,
        all_pages_correctable: uncorrectable_pages == 0,
        erased_scope_verified: target_readable_pages == target_pages
            && target_unreadable_pages == 0
            && target_uncorrectable_pages == 0
            && target_non_erased_pages == 0,
        ordered_sweep_sha256: hex::encode(sweep_hash.finalize()),
        image_sha256: image_hash.map(|hasher| hex::encode(hasher.finalize())),
        image_bytes: image.as_ref().map(|_| image_bytes),
        blocks,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn complete_sweep_verifies_every_target_page() {
        let geometry = SweepGeometry {
            blocks: 2,
            channels: 1,
            chips_per_channel: 1,
            luns_per_chip: 1,
            planes_per_lun: 1,
            blocks_per_lun: 2,
            pages_per_block: 2,
            page_bytes: 4,
            oob_bytes: 2,
        };
        let dispositions = [PhysicalDisposition::Data, PhysicalDisposition::FactoryBad];
        let mut visited = Vec::new();
        let summary = sweep_physical_pages(
            geometry,
            &dispositions,
            0xff,
            None,
            None,
            |flat, page| {
                visited.push((flat, page));
                let raw = if flat == 0 {
                    vec![0xff; 6]
                } else {
                    vec![0x11; 6]
                };
                Ok(PageRead {
                    raw,
                    metrics: PageMetrics::default(),
                })
            },
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(visited, vec![(0, 0), (0, 1), (1, 0), (1, 1)]);
        assert!(summary.all_addresses_readable);
        assert!(summary.erased_scope_verified);
        assert_eq!(summary.excluded_non_erased_pages, 2);
    }

    #[test]
    fn salvage_image_marks_unreadable_holes_in_map() {
        let geometry = SweepGeometry {
            blocks: 1,
            channels: 1,
            chips_per_channel: 1,
            luns_per_chip: 1,
            planes_per_lun: 1,
            blocks_per_lun: 1,
            pages_per_block: 2,
            page_bytes: 4,
            oob_bytes: 2,
        };
        let mut image = Cursor::new(Vec::new());
        let mut map = Vec::new();
        let summary = sweep_physical_pages(
            geometry,
            &[PhysicalDisposition::Data],
            0xff,
            Some(&mut image),
            Some(&mut map),
            |_flat, page| {
                if page == 0 {
                    Ok(PageRead {
                        raw: vec![1, 2, 3, 4, 5, 6],
                        metrics: PageMetrics::default(),
                    })
                } else {
                    Err(Error::Io("injected read error".into(), None))
                }
            },
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(image.into_inner(), vec![1, 2, 3, 4, 5, 6, 0, 0, 0, 0, 0, 0]);
        assert_eq!(summary.unreadable_pages, 1);
        assert!(!summary.all_addresses_readable);
        assert!(!summary.erased_scope_verified);
        let text = String::from_utf8(map).unwrap();
        assert!(text.contains("\"record\":\"header\""));
        assert!(text.contains("\"data_length\":4"));
        assert!(text.contains("\"oob_length\":2"));
        assert!(text.contains(
            "\"geometry\":{\"channel\":0,\"chip\":0,\"lun\":0,\"plane\":0,\"block\":0,\"page\":0}"
        ));
        assert!(text.contains("\"read_status\":\"read-error\""));
        assert!(text.contains("\"ecc_status\":\"unknown\""));
    }

    #[test]
    fn salvage_requires_both_outputs_and_empty_image() {
        let geometry = SweepGeometry {
            blocks: 1,
            channels: 1,
            chips_per_channel: 1,
            luns_per_chip: 1,
            planes_per_lun: 1,
            blocks_per_lun: 1,
            pages_per_block: 1,
            page_bytes: 1,
            oob_bytes: 0,
        };
        let mut image = Cursor::new(vec![1]);
        assert!(sweep_physical_pages(
            geometry,
            &[PhysicalDisposition::Data],
            0xff,
            Some(&mut image),
            None,
            |_flat, _page| unreachable!(),
            |_, _| Ok(()),
        )
        .is_err());
    }

    #[test]
    fn uncorrectable_page_is_read_but_cannot_verify_erasure() {
        let summary = sweep_physical_pages(
            SweepGeometry {
                blocks: 1,
                channels: 1,
                chips_per_channel: 1,
                luns_per_chip: 1,
                planes_per_lun: 1,
                blocks_per_lun: 1,
                pages_per_block: 1,
                page_bytes: 4,
                oob_bytes: 0,
            },
            &[PhysicalDisposition::Data],
            0xff,
            None,
            None,
            |_flat, _page| {
                Ok(PageRead {
                    raw: vec![0xff; 4],
                    metrics: PageMetrics {
                        uncorrectable: true,
                        ..PageMetrics::default()
                    },
                })
            },
            |_, _| Ok(()),
        )
        .unwrap();
        assert_eq!(summary.readable_pages, 1);
        assert_eq!(summary.uncorrectable_pages, 1);
        assert_eq!(summary.target_uncorrectable_pages, 1);
        assert!(!summary.all_pages_correctable);
        assert!(!summary.erased_scope_verified);
    }

    #[test]
    fn complete_sweep_reports_bounded_progress_and_excluded_read_errors() {
        let mut progress = Vec::new();
        let summary = sweep_physical_pages(
            SweepGeometry {
                blocks: 2,
                channels: 1,
                chips_per_channel: 1,
                luns_per_chip: 1,
                planes_per_lun: 1,
                blocks_per_lun: 2,
                pages_per_block: 256,
                page_bytes: 1,
                oob_bytes: 0,
            },
            &[
                PhysicalDisposition::Data,
                PhysicalDisposition::SystemPreserved,
            ],
            0xff,
            None,
            None,
            |flat, _page| {
                if flat == 1 {
                    Err(Error::Io("excluded read error".into(), None))
                } else {
                    Ok(PageRead {
                        raw: vec![0xff],
                        metrics: PageMetrics::default(),
                    })
                }
            },
            |done, total| {
                progress.push((done, total));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(summary.excluded_unreadable_pages, 256);
        assert_eq!(summary.target_unreadable_pages, 0);
        assert_eq!(progress.first(), Some(&(1, 512)));
        assert_eq!(progress.last(), Some(&(512, 512)));
        assert!(progress.len() <= 4);
    }

    #[test]
    fn sweep_rejects_a_topology_that_does_not_cover_every_flat_block() {
        let geometry = SweepGeometry {
            blocks: 2,
            channels: 1,
            chips_per_channel: 1,
            luns_per_chip: 1,
            planes_per_lun: 1,
            blocks_per_lun: 1,
            pages_per_block: 1,
            page_bytes: 1,
            oob_bytes: 0,
        };
        let result = sweep_physical_pages(
            geometry,
            &[PhysicalDisposition::Data, PhysicalDisposition::Data],
            0xff,
            None,
            None,
            |_flat, _page| unreachable!(),
            |_, _| Ok(()),
        );
        assert!(result.is_err());
    }
}
