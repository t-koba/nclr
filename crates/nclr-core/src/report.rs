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
            final_state: "raw-uninitialized".to_string(),
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
    let mut d0 = CoverageEntry {
        domain: "D0".into(),
        final_state: "erased".into(),
        count: None,
        attempted: None,
        erased: None,
        failed: None,
        residual: None,
    };
    let mut d3 = CoverageEntry {
        domain: "D3".into(),
        final_state: "unknown".into(),
        count: None,
        attempted: None,
        erased: None,
        failed: None,
        residual: None,
    };
    if errors > 0 {
        d0.final_state = "erase-failed".into();
        d0.failed = Some(errors);
        d0.residual = Some(true);
    }
    d3.final_state = "unreachable".into();
    d3.residual = Some(true);
    vec![d0, d3]
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
    vec![
        mk("D0", d0_d2),
        mk("D1", d0_d2),
        mk("D2", d0_d2),
        mk(
            "D3",
            if blocks_erase_failed > 0 {
                "erase-failed"
            } else {
                "erased"
            },
        ),
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
    ]
}
/// Coverage for the C3 (controller reinitialization) path: D0-D2 erased by
/// the controller erase, D3 per-block erased (old RBB), D4 rebuilt
/// (BBT/FTL/spare). D5-D7 preserved.
pub fn controller_coverage(
    new_bbt_committed: bool,
    ftl_rebuilt: bool,
    old_rbb_erase_failed: u64,
    io_errors: u64,
) -> Vec<CoverageEntry> {
    let rebuilt_ok = new_bbt_committed && ftl_rebuilt && io_errors == 0;
    let d3_final = if old_rbb_erase_failed > 0 || !rebuilt_ok {
        "erase-failed"
    } else {
        "erased"
    };
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
        mk("D0", if rebuilt_ok { "erased" } else { "erase-failed" }),
        mk("D1", if rebuilt_ok { "erased" } else { "erase-failed" }),
        mk("D2", if rebuilt_ok { "erased" } else { "erase-failed" }),
        mk("D3", d3_final),
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
