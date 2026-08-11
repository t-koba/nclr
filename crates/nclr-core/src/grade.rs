//! Erase-reach grade (C), residual risk and health grade (H).
//! The three values are computed independently.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum CGrade {
    C0,
    C1,
    C2,
    C3,
    C4,
}

impl CGrade {
    pub fn from_level(level: &str) -> Option<CGrade> {
        match level {
            "lba" => Some(CGrade::C1),
            "device" => Some(CGrade::C2),
            "controller" => Some(CGrade::C3),
            "physical" => Some(CGrade::C4),
            _ => None,
        }
    }

    /// Parse a grade string ("C1".."C4") or a level name.
    pub fn parse(s: &str) -> Option<CGrade> {
        let s = s.trim().to_ascii_uppercase();
        match s.as_str() {
            "C0" => Some(CGrade::C0),
            "C1" => Some(CGrade::C1),
            "C2" => Some(CGrade::C2),
            "C3" => Some(CGrade::C3),
            "C4" => Some(CGrade::C4),
            _ => CGrade::from_level(s.to_ascii_lowercase().as_str()),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            CGrade::C0 => "C0",
            CGrade::C1 => "C1",
            CGrade::C2 => "C2",
            CGrade::C3 => "C3",
            CGrade::C4 => "C4",
        }
    }
}

impl std::fmt::Display for CGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum Residual {
    NoneKnown,
    DocumentedExclusion,
    Unreachable,
    EraseFailed,
    UnknownScope,
}

impl Residual {
    pub fn as_str(&self) -> &'static str {
        match self {
            Residual::NoneKnown => "none-known",
            Residual::DocumentedExclusion => "documented-exclusion",
            Residual::Unreachable => "unreachable",
            Residual::EraseFailed => "erase-failed",
            Residual::UnknownScope => "unknown-scope",
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum HGrade {
    H0,
    H1,
    H2,
    H3,
}

impl HGrade {
    pub fn as_str(&self) -> &'static str {
        match self {
            HGrade::H0 => "H0",
            HGrade::H1 => "H1",
            HGrade::H2 => "H2",
            HGrade::H3 => "H3",
        }
    }
}

impl std::fmt::Display for HGrade {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Evidence collected by the LBA C1 recipe (recipe L1).
#[derive(Debug, Clone, Default)]
pub struct LbaC1Evidence {
    /// Full logical space was overwritten (PRBS + zero).
    pub full_overwrite: bool,
    /// Measured write/verify throughput (MB/s).
    pub throughput_mbps: Option<f64>,
    /// Measured flush latency (ms).
    pub flush_latency_ms: Option<u64>,
    /// PRBS read-back after power cycle matched.
    pub prbs_verify: bool,
    /// Zero read-back after power cycle matched.
    pub zero_verify: bool,
    /// No partition/filesystem signatures remain.
    pub signature_free: bool,
    /// All flushes succeeded.
    pub flush_ok: bool,
    /// Power cycle was actually performed (device or sim).
    pub power_cycled: bool,
    /// Any I/O error or mismatch encountered.
    pub io_errors: u64,
}

/// Health evidence for H-grade computation.
#[derive(Debug, Clone, Default)]
pub struct HealthEvidence {
    pub capacity_stable: bool,
    pub all_reads_ok: bool,
    pub flush_ok: bool,
    pub power_cycle_consistent: bool,
    pub no_uncorrectable: bool,
    /// Minimum spare reserve ratio satisfied (physical backends only).
    pub spare_ok: bool,
    pub weak_blocks: u64,
    pub new_bad_blocks: u64,
}

/// Result of the C-grade computation for the LBA path.
#[derive(Debug, Clone)]
pub struct GradeResult {
    pub grade: CGrade,
    /// false when required evidence for the grade is missing.
    pub qualified: bool,
    pub residual: Residual,
}

pub fn compute_lba_c1(e: &LbaC1Evidence) -> GradeResult {
    if !e.full_overwrite {
        return GradeResult {
            grade: CGrade::C0,
            qualified: false,
            residual: Residual::UnknownScope,
        };
    }
    if e.io_errors > 0 {
        return GradeResult {
            grade: CGrade::C1,
            qualified: false,
            residual: Residual::EraseFailed,
        };
    }
    let base = e.prbs_verify && e.zero_verify && e.signature_free && e.flush_ok;
    // C1 requires power-cycle read verification per spec; without it the
    // grade is not fully qualified (result becomes `degraded`).
    let qualified = base && e.power_cycled;
    let residual = if !e.power_cycled {
        Residual::DocumentedExclusion
    } else if base {
        Residual::NoneKnown
    } else {
        Residual::EraseFailed
    };
    GradeResult {
        grade: CGrade::C1,
        qualified,
        residual,
    }
}

pub fn compute_health(e: &HealthEvidence) -> HGrade {
    if !e.capacity_stable || !e.all_reads_ok || !e.flush_ok || e.new_bad_blocks > 0 {
        return HGrade::H0;
    }
    if e.power_cycle_consistent && e.no_uncorrectable && e.spare_ok && e.weak_blocks == 0 {
        HGrade::H2
    } else {
        HGrade::H1
    }
}

/// Evidence for the C2 (Device User Area Erased) grade: a documented device
/// internal erase (SCSI SANITIZE BLOCK ERASE / CRYPTO ERASE, SD full-range
/// ERASE, or a documented FORMAT UNIT) plus post-erase verification.
#[derive(Debug, Clone, Default)]
pub struct DeviceEraseEvidence {
    /// The device erase command was accepted and completed.
    pub erase_completed: bool,
    /// The erase scope (D0-D2) is documented (backend capability metadata),
    /// not merely assumed from GOOD status.
    pub scope_documented: bool,
    /// Full logical space reads back as the documented blank value.
    pub blank_verify: bool,
    /// No partition/filesystem signatures remain.
    pub signature_free: bool,
    /// Power cycle performed after the erase.
    pub power_cycled: bool,
    /// Capacity and re-enumeration stable after the erase.
    pub capacity_stable: bool,
    /// An UNMAP/discard was used instead of a real erase: this is never C2
    /// evidence (discard alone must not grant C2 or above).
    pub discard_only: bool,
    /// Any I/O error or verification mismatch encountered.
    pub io_errors: u64,
}

pub fn compute_device_c2(e: &DeviceEraseEvidence) -> GradeResult {
    if !e.erase_completed || e.io_errors > 0 {
        return GradeResult {
            grade: CGrade::C0,
            qualified: false,
            residual: Residual::EraseFailed,
        };
    }
    // A discard/UNMAP alone is auxiliary and must not grant C2.
    if e.discard_only {
        return GradeResult {
            grade: CGrade::C0,
            qualified: false,
            residual: Residual::UnknownScope,
        };
    }
    if !e.scope_documented {
        return GradeResult {
            grade: CGrade::C0,
            qualified: false,
            residual: Residual::UnknownScope,
        };
    }
    let qualified = e.blank_verify && e.signature_free && e.power_cycled && e.capacity_stable;
    let residual = if qualified {
        // D3/D4 remain outside the reach of standard device operations.
        Residual::Unreachable
    } else {
        Residual::EraseFailed
    };
    GradeResult {
        grade: CGrade::C2,
        qualified,
        residual,
    }
}

/// Evidence for the C3 (Controller Reinitialized) grade: the controller's
/// BBT, logical capacity, spare pool and FTL were rebuilt from fresh results
/// and the old management state was invalidated.
#[derive(Debug, Clone, Default)]
pub struct ControllerReinitEvidence {
    /// Old BBT (all copies/generations) captured before any erase.
    pub old_bbt_captured: bool,
    /// Old RBBs were individually attempted; per-block results recorded.
    pub old_rbb_erase_attempted: bool,
    /// Number of old RBBs whose erase failed (stays quarantined).
    pub old_rbb_erase_failed: u64,
    /// Number of blocks whose final erase failed (test data remains on
    /// quarantined blocks only).
    pub final_erase_failed: u64,
    /// Old BBT generation captured before any erase.
    pub old_bbt_generation: Option<u64>,
    /// New BBT/FTL generations committed by the rebuild.
    pub new_bbt_generation: Option<u64>,
    pub new_ftl_generation: Option<u64>,
    /// Factory bad block count from the old BBT.
    pub fbb_count: Option<u64>,
    /// Old RBB count from the old BBT.
    pub rbb_count: Option<u64>,
    /// Old RBBs successfully erased (individually attempted).
    pub old_rbb_erased: u64,
    /// Measured LBA throughput (MB/s) from the qualification sweep.
    pub throughput_mbps: Option<f64>,
    /// Measured flush latency (ms).
    pub flush_latency_ms: Option<u64>,
    /// FBB marker(s) preserved.
    pub fbb_preserved: bool,
    /// New BBT committed (fresh build, not a copy of the old BBT).
    pub new_bbt_committed: bool,
    /// New FTL committed with a fresh generation; old FTL invalidated.
    pub ftl_rebuilt: bool,
    /// Capacity stable across the power cycle (equal to the committed value).
    pub capacity_stable: bool,
    /// Spare pool meets the profile minimum after the rebuild.
    pub spare_ok: bool,
    /// Weak/failed blocks were isolated from the user pool.
    pub weak_isolated: bool,
    /// Number of blocks actually isolated by qualification.
    pub isolated_blocks: u64,
    /// Power cycle performed after the rebuild.
    pub power_cycled: bool,
    /// Any I/O error encountered.
    pub io_errors: u64,
    /// Capacity committed by the rebuild (for post-cycle stability checks).
    pub expected_capacity_bytes: Option<u64>,
}

pub fn compute_controller_c3(e: &ControllerReinitEvidence) -> GradeResult {
    // Core chain: without these, no C3.
    if !e.old_bbt_captured || !e.new_bbt_committed || !e.ftl_rebuilt || e.io_errors > 0 {
        return GradeResult {
            grade: CGrade::C0,
            qualified: false,
            residual: Residual::EraseFailed,
        };
    }
    if !e.old_rbb_erase_attempted || !e.fbb_preserved || !e.weak_isolated {
        return GradeResult {
            grade: CGrade::C0,
            qualified: false,
            residual: Residual::UnknownScope,
        };
    }
    let qualified = e.capacity_stable && e.spare_ok && e.power_cycled;
    let residual = if e.old_rbb_erase_failed + e.final_erase_failed > 0 {
        Residual::EraseFailed
    } else if qualified {
        // Physical-scope completeness (C4) is not certified here.
        Residual::NoneKnown
    } else {
        Residual::EraseFailed
    };
    GradeResult {
        grade: CGrade::C3,
        qualified,
        residual,
    }
}

/// Evidence for the C4 (Physical Scope Accounted) grade: every non-FBB
/// physical block that could hold user data was enumerated, categorized and
/// erased with per-block results recorded.
#[derive(Debug, Clone, Default)]
pub struct PhysicalScopeEvidence {
    /// Every non-FBB block was enumerated and categorized.
    pub enumeration_complete: bool,
    /// Total data-bearing blocks enumerated (user + spare + obsolete + old RBB).
    pub blocks_enumerated: u64,
    /// Blocks whose erase succeeded.
    pub blocks_erased: u64,
    /// Blocks whose erase failed (individually recorded, residual).
    pub blocks_erase_failed: u64,
    /// A complete raw page + OOB sweep was performed after the final erase
    /// and before rebuilding controller metadata.
    pub physical_sweep_complete: bool,
    /// All declared physical addresses, including excluded FBB/preserved
    /// blocks, and the aggregate read/ECC verdict for that address space.
    pub physical_pages: u64,
    pub physical_readable_pages: u64,
    pub physical_unreadable_pages: u64,
    pub physical_uncorrectable_pages: u64,
    pub ordered_sweep_sha256: Option<String>,
    /// Pages in the declared erased scope and their read/blank verdicts.
    pub target_pages: u64,
    pub target_readable_pages: u64,
    pub target_unreadable_pages: u64,
    pub target_uncorrectable_pages: u64,
    pub target_non_erased_pages: u64,
    /// Pages outside the erased scope (FBB/preserved/unknown) that could not
    /// be read. They remain visible as a separate physical-read limitation.
    pub excluded_unreadable_pages: u64,
    /// Old RBBs were individually attempted.
    pub old_rbb_erase_attempted: bool,
    /// FBB markers preserved.
    pub fbb_preserved: bool,
    /// Blocks whose category could not be determined (left untouched,
    /// residual unknown-scope).
    pub unknown_reservation: u64,
    /// A Protected Area (D5) exists that cannot be authenticated to: it is
    /// documented as unreachable and excluded from the erased scope.
    pub protected_area: bool,
    /// New BBT/FTL committed (fresh build, old generation invalidated).
    pub bbt_ftl_rebuilt: bool,
    /// Old BBT generation captured before any erase.
    pub old_bbt_generation: Option<u64>,
    /// New BBT/FTL generations committed by the rebuild.
    pub new_bbt_generation: Option<u64>,
    pub new_ftl_generation: Option<u64>,
    /// Factory bad block count from the old BBT.
    pub fbb_count: Option<u64>,
    /// Old RBB count from the old BBT.
    pub rbb_count: Option<u64>,
    /// Old RBBs successfully erased.
    pub old_rbb_erased: u64,
    /// Measured LBA throughput (MB/s) from the qualification sweep.
    pub throughput_mbps: Option<f64>,
    /// Measured flush latency (ms).
    pub flush_latency_ms: Option<u64>,
    /// Capacity stable across the power cycle.
    pub capacity_stable: bool,
    /// Spare pool meets the profile minimum.
    pub spare_ok: bool,
    /// Power cycle performed after the rebuild.
    pub power_cycled: bool,
    /// Any I/O error encountered.
    pub io_errors: u64,
    /// Capacity committed by the rebuild (for post-cycle stability checks).
    pub expected_capacity_bytes: Option<u64>,
}

pub fn compute_physical_c4(e: &PhysicalScopeEvidence) -> GradeResult {
    let sweep_digest_valid = e.ordered_sweep_sha256.as_deref().is_some_and(|digest| {
        digest.len() == 64 && digest.bytes().all(|byte| byte.is_ascii_hexdigit())
    });
    let sweep_accounted = e.physical_pages > 0
        && e.physical_readable_pages
            .saturating_add(e.physical_unreadable_pages)
            == e.physical_pages
        && e.target_pages <= e.physical_pages
        && e.target_unreadable_pages
            .saturating_add(e.excluded_unreadable_pages)
            == e.physical_unreadable_pages
        && e.target_uncorrectable_pages <= e.physical_uncorrectable_pages;
    if !e.enumeration_complete
        || !e.physical_sweep_complete
        || !sweep_accounted
        || !sweep_digest_valid
        || !e.bbt_ftl_rebuilt
        || e.io_errors > 0
    {
        return GradeResult {
            grade: CGrade::C0,
            qualified: false,
            residual: Residual::UnknownScope,
        };
    }
    if !e.old_rbb_erase_attempted || !e.fbb_preserved {
        return GradeResult {
            grade: CGrade::C0,
            qualified: false,
            residual: Residual::UnknownScope,
        };
    }
    // Every enumerated data-bearing block must have an individual erase
    // result; failures keep the grade at C4 but with an erase-failed
    // residual (the reach scope is still fully accounted).
    let all_accounted = e.blocks_erased + e.blocks_erase_failed == e.blocks_enumerated;
    let all_target_pages_verified = e.target_pages == e.target_readable_pages
        && e.target_unreadable_pages == 0
        && e.target_uncorrectable_pages == 0
        && e.target_non_erased_pages == 0;
    let qualified = all_accounted && e.capacity_stable && e.spare_ok && e.power_cycled;
    let residual = if e.unknown_reservation > 0 {
        Residual::UnknownScope
    } else if e.protected_area {
        // The protected area retains data we cannot reach without
        // authentication: documented exclusion from the erased scope.
        Residual::DocumentedExclusion
    } else if e.blocks_erase_failed > 0
        || e.target_unreadable_pages > 0
        || e.target_uncorrectable_pages > 0
        || e.target_non_erased_pages > 0
    {
        Residual::EraseFailed
    } else if qualified && all_target_pages_verified {
        Residual::NoneKnown
    } else {
        Residual::EraseFailed
    };
    GradeResult {
        grade: CGrade::C4,
        qualified: qualified && all_target_pages_verified,
        residual,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c0_when_no_overwrite() {
        let g = compute_lba_c1(&LbaC1Evidence::default());
        assert_eq!(g.grade, CGrade::C0);
        assert!(!g.qualified);
    }

    #[test]
    fn c1_qualified_when_all_evidence() {
        let e = LbaC1Evidence {
            full_overwrite: true,
            prbs_verify: true,
            zero_verify: true,
            signature_free: true,
            flush_ok: true,
            power_cycled: true,
            io_errors: 0,
            throughput_mbps: Some(100.0),
            flush_latency_ms: Some(1),
        };
        let g = compute_lba_c1(&e);
        assert_eq!(g.grade, CGrade::C1);
        assert!(g.qualified);
        assert_eq!(g.residual, Residual::NoneKnown);
    }

    #[test]
    fn c1_not_qualified_without_power_cycle() {
        let e = LbaC1Evidence {
            full_overwrite: true,
            prbs_verify: true,
            zero_verify: true,
            signature_free: true,
            flush_ok: true,
            power_cycled: false,
            io_errors: 0,
            throughput_mbps: Some(100.0),
            flush_latency_ms: Some(1),
        };
        let g = compute_lba_c1(&e);
        assert_eq!(g.grade, CGrade::C1);
        assert!(!g.qualified);
        assert_eq!(g.residual, Residual::DocumentedExclusion);
    }

    #[test]
    fn io_errors_map_to_erase_failed() {
        let e = LbaC1Evidence {
            full_overwrite: true,
            io_errors: 3,
            power_cycled: true,
            ..Default::default()
        };
        let g = compute_lba_c1(&e);
        assert_eq!(g.residual, Residual::EraseFailed);
        assert!(!g.qualified);
    }

    #[test]
    fn health_grades() {
        assert_eq!(
            compute_health(&HealthEvidence {
                capacity_stable: false,
                ..Default::default()
            }),
            HGrade::H0
        );
        let ok = HealthEvidence {
            capacity_stable: true,
            all_reads_ok: true,
            flush_ok: true,
            power_cycle_consistent: true,
            no_uncorrectable: true,
            spare_ok: true,
            weak_blocks: 0,
            new_bad_blocks: 0,
        };
        assert_eq!(compute_health(&ok), HGrade::H2);
        let weak = HealthEvidence {
            weak_blocks: 2,
            ..ok.clone()
        };
        assert_eq!(compute_health(&weak), HGrade::H1);
    }

    #[test]
    fn grade_levels() {
        assert_eq!(CGrade::from_level("lba"), Some(CGrade::C1));
        assert_eq!(CGrade::from_level("physical"), Some(CGrade::C4));
        assert_eq!(CGrade::from_level("bogus"), None);
        // Grade-string parsing (used for --min-level and plan minimum_level).
        assert_eq!(CGrade::parse("C1"), Some(CGrade::C1));
        assert_eq!(CGrade::parse("c2"), Some(CGrade::C2));
        assert_eq!(CGrade::parse("device"), Some(CGrade::C2));
        assert_eq!(CGrade::parse("bogus"), None);
    }

    fn c2_ok_evidence() -> DeviceEraseEvidence {
        DeviceEraseEvidence {
            erase_completed: true,
            scope_documented: true,
            blank_verify: true,
            signature_free: true,
            power_cycled: true,
            capacity_stable: true,
            discard_only: false,
            io_errors: 0,
        }
    }

    #[test]
    fn c2_qualified_with_full_evidence() {
        let g = compute_device_c2(&c2_ok_evidence());
        assert_eq!(g.grade, CGrade::C2);
        assert!(g.qualified);
        assert_eq!(g.residual, Residual::Unreachable);
    }

    #[test]
    fn c2_rejected_for_discard_only() {
        let mut e = c2_ok_evidence();
        e.discard_only = true;
        let g = compute_device_c2(&e);
        assert_eq!(g.grade, CGrade::C0);
        assert!(!g.qualified, "discard alone must not grant C2");
    }

    #[test]
    fn c2_requires_documented_scope() {
        let mut e = c2_ok_evidence();
        e.scope_documented = false;
        let g = compute_device_c2(&e);
        assert_eq!(g.grade, CGrade::C0);
        assert!(!g.qualified);
        assert_eq!(g.residual, Residual::UnknownScope);
    }

    #[test]
    fn c2_requires_verification() {
        let mut e = c2_ok_evidence();
        e.blank_verify = false;
        let g = compute_device_c2(&e);
        assert_eq!(g.grade, CGrade::C2);
        assert!(!g.qualified);
        assert_eq!(g.residual, Residual::EraseFailed);
    }

    #[test]
    fn c2_erase_failed_is_c0() {
        let mut e = c2_ok_evidence();
        e.erase_completed = false;
        e.io_errors = 1;
        let g = compute_device_c2(&e);
        assert_eq!(g.grade, CGrade::C0);
        assert!(!g.qualified);
    }

    fn c3_ok_evidence() -> ControllerReinitEvidence {
        ControllerReinitEvidence {
            old_bbt_captured: true,
            old_rbb_erase_attempted: true,
            old_rbb_erase_failed: 0,
            final_erase_failed: 0,
            fbb_preserved: true,
            new_bbt_committed: true,
            ftl_rebuilt: true,
            capacity_stable: true,
            spare_ok: true,
            weak_isolated: true,
            isolated_blocks: 0,
            power_cycled: true,
            io_errors: 0,
            expected_capacity_bytes: Some(221184),
            old_bbt_generation: Some(1),
            new_bbt_generation: Some(2),
            new_ftl_generation: Some(2),
            fbb_count: Some(2),
            rbb_count: Some(3),
            old_rbb_erased: 3,
            throughput_mbps: Some(120.0),
            flush_latency_ms: Some(1),
        }
    }

    #[test]
    fn c3_qualified_with_full_evidence() {
        let g = compute_controller_c3(&c3_ok_evidence());
        assert_eq!(g.grade, CGrade::C3);
        assert!(g.qualified);
        assert_eq!(g.residual, Residual::NoneKnown);
    }

    #[test]
    fn c3_requires_old_bbt_capture() {
        let mut e = c3_ok_evidence();
        e.old_bbt_captured = false;
        let g = compute_controller_c3(&e);
        assert_eq!(g.grade, CGrade::C0);
        assert!(!g.qualified);
    }

    #[test]
    fn c3_requires_fresh_ftl() {
        let mut e = c3_ok_evidence();
        e.ftl_rebuilt = false;
        let g = compute_controller_c3(&e);
        assert_eq!(g.grade, CGrade::C0);
        assert!(!g.qualified);
    }

    #[test]
    fn c3_old_rbb_failures_are_residual() {
        let mut e = c3_ok_evidence();
        e.old_rbb_erase_failed = 1;
        let g = compute_controller_c3(&e);
        assert_eq!(g.grade, CGrade::C3);
        assert!(g.qualified);
        assert_eq!(g.residual, Residual::EraseFailed);
    }

    #[test]
    fn c3_unstable_capacity_is_not_qualified() {
        let mut e = c3_ok_evidence();
        e.capacity_stable = false;
        let g = compute_controller_c3(&e);
        assert_eq!(g.grade, CGrade::C3);
        assert!(!g.qualified);
    }

    #[test]
    fn c3_never_exceeds_c3() {
        // Even with perfect evidence the grade is C3 (physical scope is a
        // Phase 4 certification).
        let g = compute_controller_c3(&c3_ok_evidence());
        assert_eq!(g.grade, CGrade::C3);
    }

    fn c4_ok_evidence() -> PhysicalScopeEvidence {
        PhysicalScopeEvidence {
            enumeration_complete: true,
            blocks_enumerated: 59,
            blocks_erased: 59,
            blocks_erase_failed: 0,
            physical_sweep_complete: true,
            physical_pages: 15_616,
            physical_readable_pages: 15_616,
            physical_unreadable_pages: 0,
            physical_uncorrectable_pages: 0,
            ordered_sweep_sha256: Some("0".repeat(64)),
            target_pages: 15_104,
            target_readable_pages: 15_104,
            target_unreadable_pages: 0,
            target_uncorrectable_pages: 0,
            target_non_erased_pages: 0,
            excluded_unreadable_pages: 0,
            old_rbb_erase_attempted: true,
            fbb_preserved: true,
            unknown_reservation: 0,
            protected_area: false,
            bbt_ftl_rebuilt: true,
            old_bbt_generation: Some(1),
            new_bbt_generation: Some(2),
            new_ftl_generation: Some(2),
            fbb_count: Some(2),
            rbb_count: Some(3),
            old_rbb_erased: 3,
            throughput_mbps: Some(120.0),
            flush_latency_ms: Some(1),
            capacity_stable: true,
            spare_ok: true,
            power_cycled: true,
            io_errors: 0,
            expected_capacity_bytes: Some(221184),
        }
    }

    #[test]
    fn c4_unknown_reservation_is_unknown_scope() {
        let mut e = c4_ok_evidence();
        e.unknown_reservation = 2;
        let g = compute_physical_c4(&e);
        assert_eq!(g.grade, CGrade::C4);
        assert!(g.qualified);
        assert_eq!(g.residual, Residual::UnknownScope);
    }

    #[test]
    fn c4_protected_area_is_documented_exclusion() {
        let mut e = c4_ok_evidence();
        e.protected_area = true;
        let g = compute_physical_c4(&e);
        assert_eq!(g.grade, CGrade::C4);
        assert!(g.qualified);
        assert_eq!(g.residual, Residual::DocumentedExclusion);
    }

    #[test]
    fn c4_qualified_with_full_evidence() {
        let g = compute_physical_c4(&c4_ok_evidence());
        assert_eq!(g.grade, CGrade::C4);
        assert!(g.qualified);
        assert_eq!(g.residual, Residual::NoneKnown);
    }

    #[test]
    fn c4_requires_complete_enumeration() {
        let mut e = c4_ok_evidence();
        e.enumeration_complete = false;
        let g = compute_physical_c4(&e);
        assert_eq!(g.grade, CGrade::C0);
        assert!(!g.qualified);
    }

    #[test]
    fn c4_requires_all_blocks_accounted() {
        let mut e = c4_ok_evidence();
        e.blocks_erased = 58; // one block unaccounted
        let g = compute_physical_c4(&e);
        assert_eq!(g.grade, CGrade::C4);
        assert!(!g.qualified);
    }

    #[test]
    fn c4_requires_complete_physical_page_sweep() {
        let mut e = c4_ok_evidence();
        e.physical_sweep_complete = false;
        let g = compute_physical_c4(&e);
        assert_eq!(g.grade, CGrade::C0);
        assert!(!g.qualified);

        let mut e = c4_ok_evidence();
        e.target_readable_pages -= 1;
        e.target_unreadable_pages = 1;
        e.physical_readable_pages -= 1;
        e.physical_unreadable_pages = 1;
        let g = compute_physical_c4(&e);
        assert_eq!(g.grade, CGrade::C4);
        assert!(!g.qualified);
        assert_eq!(g.residual, Residual::EraseFailed);
    }

    #[test]
    fn c4_erase_failures_are_residual() {
        let mut e = c4_ok_evidence();
        e.blocks_erased = 58;
        e.blocks_erase_failed = 1;
        let g = compute_physical_c4(&e);
        assert_eq!(g.grade, CGrade::C4);
        assert!(g.qualified);
        assert_eq!(g.residual, Residual::EraseFailed);
    }

    #[test]
    fn c4_requires_fresh_ftl() {
        let mut e = c4_ok_evidence();
        e.bbt_ftl_rebuilt = false;
        let g = compute_physical_c4(&e);
        assert_eq!(g.grade, CGrade::C0);
    }
}
