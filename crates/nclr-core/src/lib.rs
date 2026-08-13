//! nclr - NAND media erase / reinitialize CLI.
//!
//! Phase 0 (Safe Core) + Phase 1 (LBA C1) implementation.
//! Target platform is Linux (x86_64/arm64); macOS is supported for
//! development and for the LBA path. See README.md for the support matrix.

pub mod artifact;
pub mod backend;
pub mod backend_common;
pub mod config;
pub mod confirm;
pub mod controller;
pub mod controller_protocol;
pub mod controller_recipe;
pub mod device;
pub mod errors;
pub mod events;
pub mod grade;
pub mod journal;
pub mod lba;
pub mod lock;
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
pub mod usb_bot;

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
