//! Execution evidence report.

use crate::grade::{CGrade, HGrade, Residual};
use serde::Serialize;
use serde_json::Value;

#[derive(Serialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ResultStatus {
    Ok,
    Degraded,
    Unsupported,
    Failed,
    Interrupted,
}

impl ResultStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            ResultStatus::Ok => "ok",
            ResultStatus::Degraded => "degraded",
            ResultStatus::Unsupported => "unsupported",
            ResultStatus::Failed => "failed",
            ResultStatus::Interrupted => "interrupted",
        }
    }
}

#[derive(Serialize, Clone, Debug)]
pub struct CoverageEntry {
    pub domain: String,
    /// JSON field name ("final", per the report schema).
    #[serde(rename = "final")]
    pub final_state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attempted: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub erased: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub residual: Option<bool>,
}

#[derive(Serialize, Clone, Debug)]
pub struct ActionRecord {
    pub id: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub errors: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Serialize, Clone, Debug)]
pub struct PostCheck {
    pub recipe: String,
    pub passed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub power_cycle_performed: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<Value>,
}

#[derive(Serialize, Clone, Debug)]
pub struct Report {
    pub schema: String,
    pub result: String,
    pub requested_level: String,
    pub achieved_grade: String,
    pub grade_qualified: bool,
    pub residual: String,
    pub health_grade: String,
    pub device_before: Value,
    pub device_after: Value,
    pub coverage: Vec<CoverageEntry>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ftl: Option<Value>,
    pub postcheck: PostCheck,
    pub final_state: String,
    pub plan_id: String,
    pub plan_hash: String,
    pub backend: Value,
    pub actions: Vec<ActionRecord>,
    pub tool: Value,
    pub times: Value,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_file: Option<String>,
    /// How to resume an interrupted run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence_sha256: Option<String>,
    pub report_hash: String,
}

impl Report {
    pub fn new(plan: &crate::plan::Plan) -> Report {
        let now = crate::journal::utc_now_rfc3339();
        Report {
            schema: crate::SCHEMA_REPORT.to_string(),
            result: ResultStatus::Unsupported.as_str().to_string(),
            requested_level: plan.requested_level.clone(),
            achieved_grade: CGrade::C0.as_str().to_string(),
            grade_qualified: false,
            residual: Residual::UnknownScope.as_str().to_string(),
            health_grade: HGrade::H0.as_str().to_string(),
            device_before: serde_json::json!({}),
            device_after: serde_json::json!({}),
            coverage: Vec::new(),
            ftl: None,
            postcheck: PostCheck {
                recipe: "L1".into(),
                passed: false,
                power_cycle_performed: None,
                details: None,
            },
            final_state: "undetermined".to_string(),
            plan_id: plan.id.clone(),
            plan_hash: plan.plan_hash.clone(),
            backend: serde_json::to_value(&plan.backend).unwrap_or(serde_json::json!({})),
            actions: Vec::new(),
            tool: serde_json::json!({
                "name": "nclr",
                "version": crate::VERSION,
                "build_digest": binary_digest(),
            }),
            times: serde_json::json!({
                "start": now,
                "end": now,
                "duration_ms": 0,
            }),
            warnings: Vec::new(),
            errors: Vec::new(),
            state_file: None,
            resume: None,
            evidence_file: None,
            evidence_sha256: None,
            report_hash: String::new(),
        }
    }

    pub fn compute_hash(&self) -> String {
        let mut v = serde_json::to_value(self).expect("report serialization cannot fail");
        v.as_object_mut()
            .expect("report is an object")
            .remove("report_hash");
        crate::digest_json(&v)
    }

    /// Human-readable summary (stderr / non-JSON mode).
    pub fn summary(&self) -> String {
        format!(
            "result={} grade={} qualified={} residual={} health={} final={}",
            self.result,
            self.achieved_grade,
            self.grade_qualified,
            self.residual,
            self.health_grade,
            self.final_state
        )
    }
}

/// SHA-256 of the running binary (fallback: a deterministic version marker).
fn binary_digest() -> String {
    std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::read(p).ok())
        .map(|d| crate::digest(&d))
        .unwrap_or_else(|| crate::digest(env!("CARGO_PKG_VERSION").as_bytes()))
}

/// Summary (redacted) report (full vs summary reports):
/// identity fields are shortened, only the grades/residual/final state are shown.
#[derive(Serialize, Clone, Debug)]
pub struct SummaryReport {
    pub schema: String,
    pub result: String,
    pub achieved_grade: String,
    pub residual: String,
    pub health_grade: String,
    pub final_state: String,
    pub plan_id: String,
    pub report_hash: String,
}

impl SummaryReport {
    pub fn from_report(r: &Report) -> SummaryReport {
        SummaryReport {
            schema: "nclr.summary.v1".into(),
            result: r.result.clone(),
            achieved_grade: r.achieved_grade.clone(),
            residual: r.residual.clone(),
            health_grade: r.health_grade.clone(),
            final_state: r.final_state.clone(),
            plan_id: r.plan_id.clone(),
            report_hash: r.report_hash.clone(),
        }
    }

    pub fn one_line(&self) -> String {
        format!(
            "result={} grade={} residual={} health={} final={}",
            self.result, self.achieved_grade, self.residual, self.health_grade, self.final_state
        )
    }
}

/// Default coverage for the LBA C1 path.
pub fn lba_coverage(errors: u64) -> Vec<CoverageEntry> {
    let d0 = CoverageEntry {
        domain: "D0".into(),
        final_state: if errors == 0 {
            "erased".into()
        } else {
            "erase-failed".into()
        },
        count: None,
        attempted: None,
        erased: None,
        failed: (errors > 0).then_some(errors),
        residual: Some(errors > 0),
    };
    let mut coverage = vec![d0];
    for domain in ["D1", "D2", "D3", "D4"] {
        coverage.push(CoverageEntry {
            domain: domain.into(),
            final_state: "unreachable".into(),
            count: None,
            attempted: None,
            erased: None,
            failed: None,
            residual: Some(true),
        });
    }
    coverage
}

/// Coverage for the C2 (device erase) path: D0-D2 are erased per the
/// documented plan scope; D3/D4 remain unreachable.
pub fn device_erase_coverage(
    erase_completed: bool,
    blank_verify: bool,
    errors: u64,
    plan: &crate::plan::Plan,
) -> Vec<CoverageEntry> {
    let final_for = |id: &str| -> String {
        if !erase_completed {
            return "erase-failed".into();
        }
        let planned_erased = plan
            .domains
            .iter()
            .find(|d| d.id == id)
            .map(|d| d.planned != "unreachable")
            .unwrap_or(false);
        if !planned_erased {
            return "unreachable".into();
        }
        if blank_verify && errors == 0 {
            "erased".into()
        } else {
            "erase-failed".into()
        }
    };
    ["D0", "D1", "D2", "D3", "D4"]
        .iter()
        .map(|id| CoverageEntry {
            domain: (*id).into(),
            final_state: final_for(id),
            count: None,
            attempted: None,
            erased: None,
            failed: None,
            residual: Some(final_for(id) == "erase-failed" || final_for(id) == "unreachable"),
        })
        .collect()
}

/// D5 (Protected Area) coverage derived from the plan's domains: present and
/// unreachable when the device exposes a protected area without the means to
/// authenticate to it.
pub fn d5_coverage(plan: &crate::plan::Plan) -> Option<CoverageEntry> {
    let d5 = plan.domains.iter().find(|d| d.id == "D5")?;
    if d5.state == "not-applicable" {
        return None;
    }
    Some(CoverageEntry {
        domain: "D5".into(),
        final_state: "unreachable".into(),
        count: None,
        attempted: None,
        erased: None,
        failed: None,
        residual: Some(true),
    })
}

/// Coverage for the C4 (physical scope) path: all data-bearing blocks
/// individually erased (failures recorded), D4 rebuilt.
pub fn physical_coverage(
    blocks_erase_failed: u64,
    old_rbb_erase_attempted: bool,
    rbb_count: Option<u64>,
    old_rbb_erased: u64,
    old_rbb_erase_failed: u64,
    unknown_reservation: u64,
    bbt_ftl_rebuilt: bool,
) -> Vec<CoverageEntry> {
    let rebuilt_ok = bbt_ftl_rebuilt;
    let mk = |id: &str, final_state: &str| CoverageEntry {
        domain: id.into(),
        final_state: final_state.into(),
        count: None,
        attempted: None,
        erased: None,
        failed: None,
        residual: Some(final_state != "erased" && final_state != "rebuilt"),
    };
    let d0_d2 = if blocks_erase_failed > 0 {
        "erase-failed"
    } else {
        "erased"
    };
    let old_rbb_attempted = old_rbb_erased.checked_add(old_rbb_erase_failed);
    let old_rbb_accounted = old_rbb_erase_attempted
        && rbb_count
            .zip(old_rbb_attempted)
            .is_some_and(|(total, attempted)| total == attempted);
    let coverage = vec![
        mk("D0", d0_d2),
        mk("D1", d0_d2),
        mk("D2", d0_d2),
        CoverageEntry {
            domain: "D3".into(),
            final_state: if old_rbb_accounted
                && blocks_erase_failed == 0
                && old_rbb_erase_failed == 0
            {
                "erased".into()
            } else {
                "erase-failed".into()
            },
            count: rbb_count,
            attempted: if old_rbb_erase_attempted {
                old_rbb_attempted
            } else {
                None
            },
            erased: old_rbb_erase_attempted.then_some(old_rbb_erased),
            failed: old_rbb_erase_attempted.then_some(old_rbb_erase_failed),
            residual: Some(
                !old_rbb_accounted || blocks_erase_failed > 0 || old_rbb_erase_failed > 0,
            ),
        },
        mk(
            "D4",
            if rebuilt_ok {
                "rebuilt"
            } else {
                "erase-failed"
            },
        ),
        CoverageEntry {
            domain: "D-unknown".into(),
            final_state: if unknown_reservation > 0 {
                "unreachable".into()
            } else {
                "not-applicable".into()
            },
            count: Some(unknown_reservation),
            attempted: None,
            erased: None,
            failed: None,
            residual: Some(unknown_reservation > 0),
        },
    ];
    coverage
}
/// Coverage for the C3 (controller reinitialization) path: D0-D2 erased by
/// the controller erase, D3 per-block erased (old RBB), D4 rebuilt
/// (BBT/FTL/spare). D5-D7 preserved.
pub fn controller_coverage(
    evidence: &crate::grade::ControllerReinitEvidence,
) -> Vec<CoverageEntry> {
    let rebuilt_ok = evidence.new_bbt_committed && evidence.ftl_rebuilt && evidence.io_errors == 0;
    let old_rbb_attempted = evidence
        .old_rbb_erased
        .checked_add(evidence.old_rbb_erase_failed);
    let old_rbb_accounted = evidence.old_rbb_erase_attempted
        && evidence
            .rbb_count
            .zip(old_rbb_attempted)
            .is_some_and(|(total, attempted)| total == attempted);
    let mk = |id: &str, final_state: &str| CoverageEntry {
        domain: id.into(),
        final_state: final_state.into(),
        count: None,
        attempted: None,
        erased: None,
        failed: None,
        residual: Some(final_state != "erased"),
    };
    vec![
        mk(
            "D0",
            if rebuilt_ok && evidence.final_erase_failed == 0 {
                "erased"
            } else {
                "erase-failed"
            },
        ),
        mk(
            "D1",
            if rebuilt_ok && evidence.final_erase_failed == 0 {
                "erased"
            } else {
                "erase-failed"
            },
        ),
        mk(
            "D2",
            if rebuilt_ok && evidence.final_erase_failed == 0 {
                "erased"
            } else {
                "erase-failed"
            },
        ),
        CoverageEntry {
            domain: "D3".into(),
            final_state: if old_rbb_accounted && evidence.old_rbb_erase_failed == 0 {
                "erased".into()
            } else {
                "erase-failed".into()
            },
            count: evidence.rbb_count,
            attempted: if evidence.old_rbb_erase_attempted {
                old_rbb_attempted
            } else {
                None
            },
            erased: evidence
                .old_rbb_erase_attempted
                .then_some(evidence.old_rbb_erased),
            failed: evidence
                .old_rbb_erase_attempted
                .then_some(evidence.old_rbb_erase_failed),
            residual: Some(!old_rbb_accounted || evidence.old_rbb_erase_failed > 0),
        },
        mk(
            "D4",
            if rebuilt_ok {
                "rebuilt"
            } else {
                "erase-failed"
            },
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_plan() -> crate::plan::Plan {
        crate::plan::Plan {
            schema: crate::SCHEMA_PLAN.into(),
            id: "test-plan".into(),
            created: "1970-01-01T00:00:00Z".into(),
            device: crate::plan::PlanDevice {
                fingerprint: "test-fingerprint".into(),
                physical_path: "test-path".into(),
                capacity_bytes: 512,
            },
            requested_level: "lba".into(),
            minimum_level: "C1".into(),
            backend: crate::plan::PlanBackend {
                id: "test".into(),
                version: "1".into(),
                profile: None,
                profile_sha256: None,
                trust: "production".into(),
                sha256: None,
                artifacts: Vec::new(),
            },
            domains: Vec::new(),
            actions: Vec::new(),
            fallback: Vec::new(),
            expected_grade: "C1".into(),
            expected_residual: "unreachable".into(),
            no_fallback: false,
            aggressive_lba: false,
            fallback_plan: None,
            power: None,
            safety: None,
            plan_hash: "test-plan-hash".into(),
        }
    }

    #[test]
    fn new_report_does_not_claim_the_final_state_before_postcheck() {
        let report = Report::new(&test_plan());
        assert_eq!(report.final_state, "undetermined");
        assert!(!report.postcheck.passed);
    }

    #[test]
    fn report_self_hash_excludes_only_the_hash_field() {
        let mut report = Report::new(&test_plan());
        let initial = report.compute_hash();
        report.report_hash = "ignored-self-hash".into();
        assert_eq!(report.compute_hash(), initial);

        report.result = "ok".into();
        assert_ne!(report.compute_hash(), initial);
    }

    #[test]
    fn lba_coverage_marks_every_internal_domain_unreachable() {
        let coverage = lba_coverage(0);
        assert_eq!(coverage.len(), 5);
        assert_eq!(coverage[0].domain, "D0");
        assert_eq!(coverage[0].final_state, "erased");
        for (entry, domain) in coverage[1..].iter().zip(["D1", "D2", "D3", "D4"]) {
            assert_eq!(entry.domain, domain);
            assert_eq!(entry.final_state, "unreachable");
            assert_eq!(entry.residual, Some(true));
        }
    }

    #[test]
    fn controller_coverage_keeps_old_rbb_results_separate_from_rebuild() {
        let coverage = controller_coverage(&crate::grade::ControllerReinitEvidence {
            new_bbt_committed: true,
            ftl_rebuilt: true,
            old_rbb_erase_attempted: true,
            rbb_count: Some(3),
            old_rbb_erased: 2,
            old_rbb_erase_failed: 1,
            ..Default::default()
        });
        let d3 = coverage.iter().find(|entry| entry.domain == "D3").unwrap();
        assert_eq!(d3.final_state, "erase-failed");
        assert_eq!(d3.count, Some(3));
        assert_eq!(d3.attempted, Some(3));
        assert_eq!(d3.erased, Some(2));
        assert_eq!(d3.failed, Some(1));

        let rebuild_failed = controller_coverage(&crate::grade::ControllerReinitEvidence {
            old_rbb_erase_attempted: true,
            rbb_count: Some(3),
            old_rbb_erased: 3,
            ..Default::default()
        });
        let d3 = rebuild_failed
            .iter()
            .find(|entry| entry.domain == "D3")
            .unwrap();
        assert_eq!(d3.final_state, "erased");
        assert_eq!(d3.residual, Some(false));
    }
}
