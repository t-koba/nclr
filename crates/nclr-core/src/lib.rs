//! nclr - NAND media erase / reinitialize CLI.
//!
//! Phase 0 (Safe Core) + Phase 1 (LBA C1) implementation.
//! Linux uses SG_IO for controller recipes and macOS uses Apple SCSITask;
//! both platforms also support the LBA path. See README.md for the support
//! matrix.

pub mod alcor_au698x;
pub mod artifact;
pub mod backend;
pub mod backend_common;
pub mod config;
pub mod confirm;
pub mod controller;
pub mod controller_probe;
pub mod controller_protocol;
pub mod controller_recipe;
pub mod device;
pub mod errors;
pub mod events;
pub mod grade;
pub mod journal;
pub mod lba;
pub mod lock;
#[cfg(target_os = "macos")]
mod macos_iokit;
#[cfg(target_os = "macos")]
pub mod macos_scsi;
#[cfg(target_os = "macos")]
pub mod macos_usb_bot;
pub mod phison_ps2303;
pub mod physical;
pub mod plan;
pub mod powercycle;
pub mod profile;
pub mod report;
pub mod safety;
pub mod scsi;
pub mod sd;
pub mod signal;
pub mod sim;
pub mod smi_ufdif;
pub mod usb_bot;
pub mod vendor_tool;

pub const SCHEMA_DEVICE: &str = "nclr.device.v1";
pub const SCHEMA_PLAN: &str = "nclr.plan.v1";
pub const SCHEMA_REPORT: &str = "nclr.report.v1";
pub const BACKEND_API: u32 = 1;
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Hash a normalized string with SHA-256 and format as `sha256:<hex>`.
pub fn digest(data: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(data);
    format!("sha256:{}", hex::encode(h.finalize()))
}

/// SHA-256 of the canonical JSON of a serde value.
pub fn digest_json(value: &serde_json::Value) -> String {
    let mut buf = Vec::with_capacity(4096);
    let mut ser = serde_json::Serializer::new(&mut buf);
    // Canonical serialization: keys sort ascending (BTreeMap), so the
    // digest is independent of insertion order.
    serde::Serialize::serialize(value, &mut ser).expect("json serialization cannot fail");
    digest(&buf)
}
