//! Stable fingerprint computation.
//!
//! The fingerprint hashes a normalized subset of identity fields with
//! SHA-256, excluding unstable fields: kernel-assigned paths/numbers,
//! mount state, holder state and the fingerprint itself.

use super::{DeviceIdentity, MmcInfo, ScsiInfo, UsbInfo};
use serde::Serialize;

#[derive(Serialize)]
struct StableFields<'a> {
    transport: &'a str,
    physical_path: &'a str,
    capacity_bytes: u64,
    logical_block_size: u32,
    removable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    mmc: Option<MmcStable<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    usb: Option<UsbStable<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    scsi: Option<ScsiStable<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sim: Option<SimStable<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    mac: Option<MacStable<'a>>,
}

#[derive(Serialize)]
struct MmcStable<'a> {
    cid: &'a str,
    csd: &'a str,
    scr: &'a str,
    manfid: &'a str,
    oemid: &'a str,
    name: &'a str,
    serial: &'a str,
    date: &'a str,
    host: &'a str,
    kind: &'a str,
}

#[derive(Serialize)]
struct UsbStable<'a> {
    vid: &'a str,
    pid: &'a str,
    bcd_device: &'a str,
    serial: &'a str,
    manufacturer: &'a str,
    product: &'a str,
    port_chain: &'a str,
}

#[derive(Serialize)]
struct ScsiStable<'a> {
    vendor: &'a str,
    model: &'a str,
    rev: &'a str,
}

#[derive(Serialize)]
struct SimStable<'a> {
    id: &'a str,
    blocks: u32,
    user_blocks: u32,
    pages_per_block: u32,
    page_bytes: u32,
}

/// macOS-specific stable fields (diskutil does not expose VID/PID).
#[derive(Serialize)]
struct MacStable<'a> {
    protocol: &'a str,
    serial: &'a str,
    media_name: &'a str,
    uuid: &'a str,
    media_type: &'a str,
}

pub fn compute(identity: &DeviceIdentity) -> String {
    let mmc = identity.mmc.as_ref().map(|m: &MmcInfo| MmcStable {
        cid: &m.cid,
        csd: &m.csd,
        scr: &m.scr,
        manfid: &m.manfid,
        oemid: &m.oemid,
        name: &m.name,
        serial: &m.serial,
        date: &m.date,
        host: &m.host,
        kind: &m.kind,
    });
    let usb = identity.usb.as_ref().map(|u: &UsbInfo| UsbStable {
        vid: &u.vid,
        pid: &u.pid,
        bcd_device: &u.bcd_device,
        serial: &u.serial,
        manufacturer: &u.manufacturer,
        product: &u.product,
        port_chain: &u.port_chain,
    });
    let scsi = identity.scsi.as_ref().map(|s: &ScsiInfo| ScsiStable {
        vendor: &s.vendor,
        model: &s.model,
        rev: &s.rev,
    });
    let sim = identity.sim.as_ref().map(|s| SimStable {
        id: &s.id,
        blocks: s.blocks,
        user_blocks: s.user_blocks,
        pages_per_block: s.pages_per_block,
        page_bytes: s.page_bytes,
    });
    let mac = identity.mac.as_ref().map(|m| MacStable {
        protocol: &m.protocol,
        serial: &m.serial,
        media_name: &m.media_name,
        uuid: &m.uuid,
        media_type: &m.media_type,
    });

    let stable = StableFields {
        transport: &identity.transport,
        physical_path: &identity.physical_path,
        capacity_bytes: identity.capacity_bytes,
        logical_block_size: identity.logical_block_size,
        removable: identity.removable,
        mmc,
        usb,
        scsi,
        sim,
        mac,
    };
    let json = serde_json::to_vec(&stable).expect("fingerprint serialization cannot fail");
    crate::digest(&json)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::{DeviceIdentity, MmcInfo};

    fn base() -> DeviceIdentity {
        let mut d = DeviceIdentity::new("usb-msd", "/dev/sdb", "usb:1-3.2");
        d.capacity_bytes = 32_010_928_128;
        d.usb = Some(UsbInfo {
            vid: "13fe".into(),
            pid: "5500".into(),
            serial: "ABC123".into(),
            bcd_device: "1.00".into(),
            manufacturer: "King".into(),
            product: "Data".into(),
            port_chain: "1-3.2".into(),
        });
        d
    }

    #[test]
    fn fingerprint_changes_with_identity() {
        let a = compute(&base());
        let mut b = base();
        b.capacity_bytes += 1;
        assert_ne!(a, compute(&b));
        let mut c = base();
        c.usb.as_mut().unwrap().serial = "DIFFERENT".into();
        assert_ne!(a, compute(&c));
    }

    #[test]
    fn fingerprint_stable_and_hex() {
        let a = base();
        let b = base();
        assert_eq!(compute(&a), compute(&b));
        let fp = compute(&a);
        assert!(fp.starts_with("sha256:"));
        assert_eq!(fp.len(), "sha256:".len() + 64);
    }

    #[test]
    fn mmc_fingerprint_uses_cid() {
        let mut d = DeviceIdentity::new("mmc", "/dev/mmcblk0", "mmc-host:mmc0/slot0");
        d.mmc = Some(MmcInfo {
            cid: "AAAA".into(),
            csd: "BBBB".into(),
            scr: "CCCC".into(),
            manfid: "0x03".into(),
            oemid: "0x5344".into(),
            name: "TEST".into(),
            serial: "1".into(),
            date: "2026/01".into(),
            host: "mmc0".into(),
            kind: "SD".into(),
        });
        let a = compute(&d);
        d.mmc.as_mut().unwrap().cid = "DIFF".into();
        assert_ne!(a, compute(&d));
    }
}
