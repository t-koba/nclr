//! Strict USB Mass Storage Bulk-Only Transport trace decoding.
//!
//! The decoder consumes raw bulk endpoint payloads emitted by Wireshark's
//! `usb.frame.data` field. It validates CBW/CSW framing and tags, bounds the
//! declared transfer length, and emits one normalized record per command.

use crate::errors::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const CBW_SIGNATURE: &[u8; 4] = b"USBC";
const CSW_SIGNATURE: &[u8; 4] = b"USBS";
const CBW_LEN: usize = 31;
const CSW_LEN: usize = 13;
const MAX_BOT_TRANSFER: u32 = 64 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct DeviceKey {
    bus: String,
    device: String,
}

#[derive(Clone, Debug)]
pub struct UsbPayloadFrame {
    pub frame: u64,
    pub time_epoch: String,
    pub bus: String,
    pub device: String,
    pub endpoint: u8,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Pending {
    frame_cbw: u64,
    time_epoch: String,
    endpoint_out: u8,
    tag: u32,
    transfer_length: u32,
    direction_in: bool,
    lun: u8,
    cdb: Vec<u8>,
    payload: Vec<u8>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BotTraceRecord {
    pub seq: u64,
    pub frame_cbw: u64,
    pub frame_csw: u64,
    pub time_epoch: String,
    pub bus: String,
    pub device: String,
    pub tag: u32,
    pub lun: u8,
    pub transfer_length: u32,
    pub transferred_length: u32,
    pub residue: u32,
    pub dir: String,
    pub opcode: u64,
    pub cdb_hex: String,
    pub payload_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_hex: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_out_hex: Option<String>,
    pub status: String,
}

#[derive(Default)]
pub struct BotDecoder {
    pending: BTreeMap<DeviceKey, Pending>,
    next_seq: u64,
    ignored_payloads: u64,
}

impl BotDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn ignored_payloads(&self) -> u64 {
        self.ignored_payloads
    }

    pub fn feed(
        &mut self,
        frame: UsbPayloadFrame,
        include_payload: bool,
    ) -> Result<Option<BotTraceRecord>> {
        let key = DeviceKey {
            bus: frame.bus.clone(),
            device: frame.device.clone(),
        };

        if let Some(pending) = self.pending.get(&key) {
            if matching_csw(&frame, pending) {
                let pending = self.pending.remove(&key).expect("pending BOT command");
                return self.complete(frame, pending, include_payload).map(Some);
            }
            let cannot_be_input_payload = !pending.direction_in
                || pending.payload.len().saturating_add(frame.data.len())
                    > pending.transfer_length as usize;
            if frame.data.len() == CSW_LEN
                && frame.data.starts_with(CSW_SIGNATURE)
                && frame.endpoint & 0x80 != 0
                && cannot_be_input_payload
            {
                let pending = self.pending.remove(&key).expect("pending BOT command");
                return self.complete(frame, pending, include_payload).map(Some);
            }
            if frame.data.starts_with(CBW_SIGNATURE)
                && frame.data.len() == CBW_LEN
                && frame.endpoint & 0x80 == 0
                && pending.payload.len() == pending.transfer_length as usize
            {
                return Err(Error::Invalid(format!(
                    "USB BOT frame {} starts a new CBW before the previous CSW",
                    frame.frame
                )));
            }
        } else if frame.data.starts_with(CBW_SIGNATURE) {
            self.pending.insert(key, parse_cbw(&frame)?);
            return Ok(None);
        } else if frame.data.starts_with(CSW_SIGNATURE) {
            return Err(Error::Invalid(format!(
                "USB BOT frame {} contains a CSW without a preceding CBW",
                frame.frame
            )));
        } else {
            self.ignored_payloads += 1;
            return Ok(None);
        }

        let pending = self.pending.get_mut(&key).expect("checked pending command");
        let endpoint_in = frame.endpoint & 0x80 != 0;
        let expected_endpoint = if pending.direction_in {
            endpoint_in
        } else {
            frame.endpoint == pending.endpoint_out
        };
        if !expected_endpoint {
            self.ignored_payloads += 1;
            return Ok(None);
        }
        let new_len = pending
            .payload
            .len()
            .checked_add(frame.data.len())
            .ok_or_else(|| Error::Invalid("USB BOT payload length overflow".into()))?;
        if new_len > pending.transfer_length as usize {
            return Err(Error::Invalid(format!(
                "USB BOT frame {} exceeds CBW transfer length {}",
                frame.frame, pending.transfer_length
            )));
        }
        pending.payload.extend_from_slice(&frame.data);
        Ok(None)
    }

    fn complete(
        &mut self,
        frame: UsbPayloadFrame,
        pending: Pending,
        include_payload: bool,
    ) -> Result<BotTraceRecord> {
        if frame.data.len() != CSW_LEN {
            return Err(Error::Invalid(format!(
                "USB BOT frame {} has CSW signature but length {} != {CSW_LEN}",
                frame.frame,
                frame.data.len()
            )));
        }
        if frame.endpoint & 0x80 == 0 {
            return Err(Error::Invalid(format!(
                "USB BOT frame {} carries a CSW on an OUT endpoint",
                frame.frame
            )));
        }
        let tag = u32::from_le_bytes(frame.data[4..8].try_into().expect("fixed CSW tag"));
        if tag != pending.tag {
            return Err(Error::Invalid(format!(
                "USB BOT frame {} CSW tag {tag:#010x} does not match CBW tag {:#010x}",
                frame.frame, pending.tag
            )));
        }
        let residue = u32::from_le_bytes(frame.data[8..12].try_into().expect("fixed CSW residue"));
        if residue > pending.transfer_length {
            return Err(Error::Invalid(format!(
                "USB BOT frame {} residue {} exceeds transfer length {}",
                frame.frame, residue, pending.transfer_length
            )));
        }
        let expected_transferred = pending.transfer_length - residue;
        if pending.payload.len() as u32 != expected_transferred {
            return Err(Error::Invalid(format!(
                "USB BOT frame {} payload length {} does not equal transfer length {} minus residue {}",
                frame.frame,
                pending.payload.len(),
                pending.transfer_length,
                residue
            )));
        }
        let status = match frame.data[12] {
            0 => "ok",
            1 => "command-failed",
            2 => "phase-error",
            value => {
                return Err(Error::Invalid(format!(
                    "USB BOT frame {} has reserved CSW status {value}",
                    frame.frame
                )));
            }
        };
        let payload_hex = include_payload.then(|| hex::encode(&pending.payload));
        let record = BotTraceRecord {
            seq: self.next_seq,
            frame_cbw: pending.frame_cbw,
            frame_csw: frame.frame,
            time_epoch: pending.time_epoch,
            bus: frame.bus,
            device: frame.device,
            tag,
            lun: pending.lun,
            transfer_length: pending.transfer_length,
            transferred_length: pending.payload.len() as u32,
            residue,
            dir: if pending.transfer_length == 0 {
                "none".into()
            } else if pending.direction_in {
                "in".into()
            } else {
                "out".into()
            },
            opcode: u64::from(pending.cdb[0]),
            cdb_hex: hex::encode(&pending.cdb),
            payload_sha256: format!("sha256:{}", hex::encode(Sha256::digest(&pending.payload))),
            response_hex: if pending.direction_in {
                payload_hex.clone()
            } else {
                None
            },
            data_out_hex: if pending.direction_in {
                None
            } else {
                payload_hex
            },
            status: status.into(),
        };
        self.next_seq += 1;
        Ok(record)
    }

    pub fn finish(self) -> Result<()> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let incomplete = self
            .pending
            .values()
            .map(|p| format!("frame {} tag {:#010x}", p.frame_cbw, p.tag))
            .collect::<Vec<_>>()
            .join(", ");
        Err(Error::Invalid(format!(
            "USB BOT capture ended with incomplete commands: {incomplete}"
        )))
    }
}

fn matching_csw(frame: &UsbPayloadFrame, pending: &Pending) -> bool {
    if frame.data.len() != CSW_LEN
        || !frame.data.starts_with(CSW_SIGNATURE)
        || frame.endpoint & 0x80 == 0
    {
        return false;
    }
    let tag = u32::from_le_bytes(frame.data[4..8].try_into().expect("fixed CSW tag"));
    let residue = u32::from_le_bytes(frame.data[8..12].try_into().expect("fixed CSW residue"));
    tag == pending.tag
        && residue <= pending.transfer_length
        && pending.payload.len() as u32 == pending.transfer_length - residue
        && frame.data[12] <= 2
}

fn parse_cbw(frame: &UsbPayloadFrame) -> Result<Pending> {
    if frame.data.len() != CBW_LEN {
        return Err(Error::Invalid(format!(
            "USB BOT frame {} has CBW signature but length {} != {CBW_LEN}",
            frame.frame,
            frame.data.len()
        )));
    }
    if frame.endpoint & 0x80 != 0 {
        return Err(Error::Invalid(format!(
            "USB BOT frame {} carries a CBW on an IN endpoint",
            frame.frame
        )));
    }
    let tag = u32::from_le_bytes(frame.data[4..8].try_into().expect("fixed CBW tag"));
    let transfer_length = u32::from_le_bytes(
        frame.data[8..12]
            .try_into()
            .expect("fixed CBW transfer length"),
    );
    if transfer_length > MAX_BOT_TRANSFER {
        return Err(Error::Invalid(format!(
            "USB BOT frame {} declares transfer length {} above the {} byte limit",
            frame.frame, transfer_length, MAX_BOT_TRANSFER
        )));
    }
    let flags = frame.data[12];
    if flags & 0x7f != 0 {
        return Err(Error::Invalid(format!(
            "USB BOT frame {} sets reserved CBW flags {flags:#04x}",
            frame.frame
        )));
    }
    let lun = frame.data[13];
    if lun & 0xf0 != 0 {
        return Err(Error::Invalid(format!(
            "USB BOT frame {} sets reserved CBW LUN bits {lun:#04x}",
            frame.frame
        )));
    }
    let cdb_len_field = frame.data[14];
    if cdb_len_field & 0xe0 != 0 {
        return Err(Error::Invalid(format!(
            "USB BOT frame {} sets reserved CBW CDB-length bits {cdb_len_field:#04x}",
            frame.frame
        )));
    }
    let cdb_len = usize::from(cdb_len_field & 0x1f);
    if !(1..=16).contains(&cdb_len) {
        return Err(Error::Invalid(format!(
            "USB BOT frame {} has invalid CDB length {cdb_len}",
            frame.frame
        )));
    }
    Ok(Pending {
        frame_cbw: frame.frame,
        time_epoch: frame.time_epoch.clone(),
        endpoint_out: frame.endpoint,
        tag,
        transfer_length,
        direction_in: flags & 0x80 != 0,
        lun: lun & 0x0f,
        cdb: frame.data[15..15 + cdb_len].to_vec(),
        payload: Vec::with_capacity((transfer_length as usize).min(64 * 1024)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(number: u64, endpoint: u8, data: Vec<u8>) -> UsbPayloadFrame {
        UsbPayloadFrame {
            frame: number,
            time_epoch: "1.25".into(),
            bus: "1".into(),
            device: "2".into(),
            endpoint,
            data,
        }
    }

    fn cbw(tag: u32, length: u32, input: bool, cdb: &[u8]) -> Vec<u8> {
        let mut value = vec![0u8; CBW_LEN];
        value[..4].copy_from_slice(CBW_SIGNATURE);
        value[4..8].copy_from_slice(&tag.to_le_bytes());
        value[8..12].copy_from_slice(&length.to_le_bytes());
        value[12] = if input { 0x80 } else { 0 };
        value[14] = cdb.len() as u8;
        value[15..15 + cdb.len()].copy_from_slice(cdb);
        value
    }

    fn csw(tag: u32, residue: u32, status: u8) -> Vec<u8> {
        let mut value = vec![0u8; CSW_LEN];
        value[..4].copy_from_slice(CSW_SIGNATURE);
        value[4..8].copy_from_slice(&tag.to_le_bytes());
        value[8..12].copy_from_slice(&residue.to_le_bytes());
        value[12] = status;
        value
    }

    #[test]
    fn decodes_complete_in_command_and_redacts_payload() {
        let mut decoder = BotDecoder::new();
        decoder
            .feed(
                frame(1, 0x02, cbw(7, 4, true, &[0x12, 0, 0, 0, 4, 0])),
                false,
            )
            .unwrap();
        decoder
            .feed(frame(2, 0x81, vec![1, 2, 3, 4]), false)
            .unwrap();
        let record = decoder
            .feed(frame(3, 0x81, csw(7, 0, 0)), false)
            .unwrap()
            .unwrap();
        assert_eq!(record.opcode, 0x12);
        assert_eq!(record.transferred_length, 4);
        assert!(record.response_hex.is_none());
        assert_eq!(
            record.payload_sha256,
            "sha256:9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a"
        );
        decoder.finish().unwrap();
    }

    #[test]
    fn includes_payload_only_when_requested() {
        let mut decoder = BotDecoder::new();
        decoder
            .feed(frame(1, 0x02, cbw(9, 2, false, &[0x2a; 10])), true)
            .unwrap();
        decoder
            .feed(frame(2, 0x02, vec![0xaa, 0xbb]), true)
            .unwrap();
        let record = decoder
            .feed(frame(3, 0x81, csw(9, 0, 0)), true)
            .unwrap()
            .unwrap();
        assert_eq!(record.data_out_hex.as_deref(), Some("aabb"));
        assert!(record.response_hex.is_none());
    }

    #[test]
    fn rejects_tag_length_status_and_incomplete_sequences() {
        let mut tag = BotDecoder::new();
        tag.feed(frame(1, 0x02, cbw(1, 0, false, &[0x00])), false)
            .unwrap();
        assert!(tag.feed(frame(2, 0x81, csw(2, 0, 0)), false).is_err());

        let mut length = BotDecoder::new();
        length
            .feed(frame(1, 0x02, cbw(1, 2, true, &[0x12])), false)
            .unwrap();
        assert!(length.feed(frame(2, 0x81, vec![1, 2, 3]), false).is_err());

        let mut status = BotDecoder::new();
        status
            .feed(frame(1, 0x02, cbw(1, 0, false, &[0x00])), false)
            .unwrap();
        assert!(status.feed(frame(2, 0x81, csw(1, 0, 3)), false).is_err());

        let mut incomplete = BotDecoder::new();
        incomplete
            .feed(frame(1, 0x02, cbw(1, 0, false, &[0x00])), false)
            .unwrap();
        assert!(incomplete.finish().is_err());
    }
}
