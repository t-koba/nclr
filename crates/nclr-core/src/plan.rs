//! Plan model, planning algorithm and plan validation.

use crate::device::DeviceIdentity;
use crate::errors::{Error, Result};
use crate::grade::CGrade;
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ActionKind {
    ReadOnly,
    StateChangingReversible,
    DestructiveResumable,
    DestructiveNonResumable,
    PowerCycle,
}

impl ActionKind {
    pub fn destructive(&self) -> bool {
        matches!(
            self,
            ActionKind::DestructiveResumable | ActionKind::DestructiveNonResumable
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum PowerCycleMethod {
    /// Sim backend handles power cycling internally.
    SimInternal,
    /// An external, pre-approved power control command.
    External,
    /// No power control available; evidence incomplete (documented exclusion).
    None,
}

#[derive(Clone, Debug)]
pub struct PlanAction {
    pub seq: u32,
    pub id: String,
    pub kind: ActionKind,
    pub method: Option<PowerCycleMethod>,
    pub params: Option<Value>,
    /// Per-action backend timeout (seconds), enforced by the runner when
    /// present; falls back to the run-time --backend-timeout otherwise.
    pub timeout_secs: Option<u64>,
    /// Action retry budget. Always 0: a timed-out or failed action is never
    /// resent without a status query.
    pub retries: Option<u32>,
}

impl<'de> Deserialize<'de> for PlanAction {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            seq: u32,
            id: String,
            kind: ActionKind,
            destructive: bool,
            #[serde(default)]
            method: Option<PowerCycleMethod>,
            #[serde(default)]
            params: Option<Value>,
            #[serde(default)]
            timeout_secs: Option<u64>,
            #[serde(default)]
            retries: Option<u32>,
        }

        let wire = Wire::deserialize(d)?;
        if wire.destructive != wire.kind.destructive() {
            return Err(serde::de::Error::custom(format!(
                "action {} destructive flag does not match kind",
                wire.id
            )));
        }
        Ok(PlanAction {
            seq: wire.seq,
            id: wire.id,
            kind: wire.kind,
            method: wire.method,
            params: wire.params,
            timeout_secs: wire.timeout_secs,
            retries: wire.retries,
        })
    }
}

impl serde::Serialize for PlanAction {
    fn serialize<S: serde::Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let mut st = s.serialize_struct("PlanAction", 8)?;
        st.serialize_field("seq", &self.seq)?;
        st.serialize_field("id", &self.id)?;
        st.serialize_field("kind", &self.kind)?;
        // An explicit destructive flag is required by the plan schema; it
        // is derived from the action kind so the two can never drift.
        st.serialize_field("destructive", &self.kind.destructive())?;
        if let Some(m) = &self.method {
            st.serialize_field("method", m)?;
        }
        if let Some(p) = &self.params {
            st.serialize_field("params", p)?;
        }
        if let Some(t) = &self.timeout_secs {
            st.serialize_field("timeout_secs", t)?;
        }
        if let Some(r) = &self.retries {
            st.serialize_field("retries", r)?;
        }
        st.end()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PlanDevice {
    pub fingerprint: String,
    pub physical_path: String,
    pub capacity_bytes: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PlanBackend {
    pub id: String,
    pub version: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    /// Digest of the profile file used (self-digest, sha256 line excluded);
    /// absent when no profile was matched at plan time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_sha256: Option<String>,
    pub trust: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sha256: Option<String>,
    /// Content-addressed runtime artifacts pinned by the controller profile.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub artifacts: Vec<crate::artifact::ArtifactSpec>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct PlanDomain {
    pub id: String,
    pub state: String,
    pub planned: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct FallbackEntry {
    pub from: String,
    pub to: String,
    pub condition: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct Plan {
    pub schema: String,
    pub id: String,
    pub created: String,
    pub device: PlanDevice,
    pub requested_level: String,
    pub minimum_level: String,
    pub backend: PlanBackend,
    pub domains: Vec<PlanDomain>,
    pub actions: Vec<PlanAction>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback: Vec<FallbackEntry>,
    pub expected_grade: String,
    pub expected_residual: String,
    #[serde(default)]
    pub no_fallback: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub aggressive_lba: bool,
    /// When set (C2 plans), the full L1 plan executed if the device erase is
    /// unavailable and fallback is allowed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fallback_plan: Option<Value>,
    /// Power requirements for the plan.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub power: Option<Value>,
    /// Safety confirmation checklist.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety: Option<Value>,
    pub plan_hash: String,
}

fn is_false(b: &bool) -> bool {
    !*b
}

impl Plan {
    /// Serialize without the self hash.
    fn to_canonical_value(&self) -> Value {
        let mut v = serde_json::to_value(self).expect("plan serialization cannot fail");
        v.as_object_mut()
            .expect("plan is an object")
            .remove("plan_hash");
        v
    }

    pub fn compute_hash(&self) -> String {
        crate::digest_json(&self.to_canonical_value())
    }

    pub fn refresh_hash(&mut self) {
        let h = self.compute_hash();
        self.plan_hash = h;
    }

    pub fn action(&self, id: &str) -> Option<&PlanAction> {
        self.actions.iter().find(|a| a.id == id)
    }
}

/// Planning inputs.
pub struct PlanOptions {
    /// Effective planning level (may be raised by a site-policy floor).
    pub level: String,
    /// The user's original level, reported as `requested_level`.
    pub user_level: Option<String>,
    pub min_level: Option<String>,
    pub no_fallback: bool,
    pub aggressive_lba: bool,
    pub power_cycle: Option<String>,
    pub backend_id: Option<String>,
    /// Backend timeout (seconds) embedded into each planned action; None
    /// defers to the run-time --backend-timeout flag.
    pub timeout_secs: Option<u64>,
}

/// Capabilities reported by the backend probe.
#[derive(Debug, Clone, Default)]
pub struct BackendCapabilities {
    pub capabilities: Vec<String>,
    /// Documented erase coverage (e.g. ["D0","D1","D2"]). A device erase
    /// whose scope is not documented is never C2 evidence.
    pub erase_coverage: Vec<String>,
    /// The documented device erase method, e.g. "sanitize-block-erase",
    /// "sd-full-range-erase", "format-unit".
    pub erase_method: Option<String>,
    /// Controller reinit rebuilds (e.g. ["BBT","FTL","spare"]).
    pub rebuilds: Vec<String>,
    /// Matched controller profile id (exact match, production trust).
    pub controller_profile: Option<String>,
    /// Capacity policy from the matched profile (bin/minimum spare/ratio).
    pub capacity_policy: Option<Value>,
    /// The family holds a certified physical-scope (C4) validation
    /// (independent physical confirmation).
    pub physical_certified: bool,
    /// Protected Area (D5) size in bytes (0 = none).
    pub protected_area_bytes: u64,
    pub grade_ceiling: String,
}

impl BackendCapabilities {
    pub fn has(&self, cap: &str) -> bool {
        self.capabilities.iter().any(|c| c == cap)
    }

    /// A usable, documented device-level erase of the user area.
    pub fn erase_user_area(&self) -> bool {
        self.has("ERASE_USER_AREA")
            && self.erase_method.is_some()
            && !self.erase_coverage.is_empty()
    }

    /// A usable, documented controller reinitialization (exact profile
    /// match, production trust, declared rebuilds).
    pub fn controller_reinit(&self) -> bool {
        self.has("CONTROLLER_REINITIALIZE")
            && self.controller_profile.is_some()
            && !self.rebuilds.is_empty()
    }

    /// A certified physical-scope backend (C4): full block enumeration and
    /// per-block erase results, independently validated.
    pub fn physical_scope(&self) -> bool {
        self.has("PHYSICAL_SCOPE") && self.controller_reinit() && self.physical_certified
    }
}

/// Build a plan for the given device and options.
/// - `best`: C4 (certified physical scope) > C3 > C2 > C1.
/// - `physical`: requires C4; fails at plan time when unavailable.
/// - `controller`: requires C3; fails at plan time when unavailable.
/// - `device`: requires C2; fails at plan time when unavailable.
/// - `lba`: pure C1 LBA recipe.
pub fn plan(
    device: &DeviceIdentity,
    opts: &PlanOptions,
    backend: &PlanBackend,
    caps: &BackendCapabilities,
) -> Result<Plan> {
    let level = opts.level.as_str();
    match level {
        "best" | "physical" | "controller" | "device" | "lba" => {}
        other => {
            return Err(Error::Usage(format!("unknown level: {other}")));
        }
    }

    let power_cycle = if device.is_sim() {
        PowerCycleMethod::SimInternal
    } else if opts.power_cycle.is_some() {
        PowerCycleMethod::External
    } else {
        PowerCycleMethod::None
    };

    let use_physical = caps.physical_scope() && (level == "best" || level == "physical");
    if level == "physical" && !caps.physical_scope() {
        return Err(Error::Unsupported(format!(
            "requested physical (C4) cannot be planned: no certified physical-scope backend matches this device (backend {}, profile {}, certified={})",
            backend.id,
            caps.controller_profile.as_deref().unwrap_or("(none)"),
            caps.physical_certified
        )));
    }
    if use_physical {
        return enforce_minimum(plan_c4(device, opts, backend, caps, &power_cycle)?);
    }
    let use_controller = caps.controller_reinit() && (level == "best" || level == "controller");
    if level == "controller" && !caps.controller_reinit() {
        return Err(Error::Unsupported(format!(
            "requested controller (C3) cannot be planned: no production controller profile matches this device (backend {}, profile {})",
            backend.id,
            caps.controller_profile.as_deref().unwrap_or("(none)")
        )));
    }
    if use_controller {
        return enforce_minimum(plan_c3(device, opts, backend, caps, &power_cycle)?);
    }
    let use_device_erase = caps.erase_user_area() && (level == "best" || level == "device");
    if level == "device" && !caps.erase_user_area() {
        return Err(Error::Unsupported(format!(
            "requested device (C2) cannot be planned: the backend {} has no documented device-level erase (capability ERASE_USER_AREA + coverage + method)",
            backend.id
        )));
    }
    if use_device_erase {
        return enforce_minimum(plan_c2(device, opts, backend, caps, &power_cycle)?);
    }
    enforce_minimum(plan_l1(
        device,
        opts,
        backend,
        &power_cycle,
        caps.protected_area_bytes > 0,
    )?)
}

fn enforce_minimum(plan: Plan) -> Result<Plan> {
    let expected = CGrade::parse(&plan.expected_grade)
        .ok_or_else(|| Error::Invalid("generated plan expected_grade is invalid".into()))?;
    let minimum = CGrade::parse(&plan.minimum_level)
        .ok_or_else(|| Error::Invalid("generated plan minimum_level is invalid".into()))?;
    if expected < minimum {
        return Err(Error::Unsupported(format!(
            "planned reach {} is below the required minimum {}",
            expected.as_str(),
            minimum.as_str()
        )));
    }
    Ok(plan)
}

#[allow(clippy::too_many_arguments)]
fn new_plan_base(
    device: &DeviceIdentity,
    opts: &PlanOptions,
    backend: &PlanBackend,
    minimum_level: String,
    domains: Vec<PlanDomain>,
    expected_grade: &str,
    actions: Vec<PlanAction>,
    fallback: Vec<FallbackEntry>,
    fallback_plan: Option<Value>,
    power: Value,
) -> Plan {
    let mut plan = Plan {
        schema: crate::SCHEMA_PLAN.to_string(),
        id: new_plan_id(&device.fingerprint, &backend.id),
        created: crate::journal::utc_now_rfc3339(),
        device: PlanDevice {
            fingerprint: device.fingerprint.clone(),
            physical_path: device.physical_path.clone(),
            capacity_bytes: device.capacity_bytes,
        },
        requested_level: opts
            .user_level
            .clone()
            .unwrap_or_else(|| opts.level.clone()),
        minimum_level,
        backend: backend.clone(),
        domains,
        actions,
        fallback,
        expected_grade: expected_grade.to_string(),
        expected_residual: "unreachable".to_string(),
        no_fallback: opts.no_fallback,
        aggressive_lba: opts.aggressive_lba,
        fallback_plan,
        power: Some(power),
        // Safety confirmation checklist: every plan is
        // executed under these interlocks; the operator acknowledges the
        // plan fingerprint before any destructive action.
        safety: Some(serde_json::json!({
            "checks": [
                "device-unmounted",
                "not-system-disk",
                "no-kernel-holders",
                "not-read-only",
                "whole-device",
                "exact-fingerprint-match",
                "plan-acknowledged"
            ],
        })),
        plan_hash: String::new(),
    };
    plan.refresh_hash();
    plan
}

/// Minimum grade from --min-level, defaulting to `default`.
/// Power requirements block derived from the planned power-cycle method
/// (required power, direct port, USB hub, external
/// control, power-cycle count, UPS, temperature limit).
fn power_block(method: &PowerCycleMethod) -> Value {
    match method {
        PowerCycleMethod::SimInternal => serde_json::json!({
            "power_required_w": null,
            "direct_port_recommended": false,
            "external_power_control": "sim-internal",
            "power_cycle_required": 0,
            "ups_recommended": false,
            "usb_hub_allowed": false,
            "temp_limit_c": null,
            "note": "simulated device: internal power cycling",
        }),
        PowerCycleMethod::External => serde_json::json!({
            "power_required_w": null,
            "direct_port_recommended": true,
            "external_power_control": "external",
            "power_cycle_required": 2,
            "ups_recommended": true,
            "usb_hub_allowed": false,
            "temp_limit_c": null,
            "note": "external power control (--power-cycle) required",
        }),
        PowerCycleMethod::None => serde_json::json!({
            "power_required_w": null,
            "direct_port_recommended": false,
            "external_power_control": "none",
            "power_cycle_required": 2,
            "ups_recommended": true,
            "usb_hub_allowed": false,
            "temp_limit_c": null,
            "note": "no power control available; power-cycle verification will be skipped (documented exclusion)",
        }),
    }
}

fn min_level_of(opts: &PlanOptions, default: &str) -> Result<String> {
    match opts.min_level.as_deref() {
        Some(m) => {
            let g = CGrade::parse(m)
                .ok_or_else(|| Error::Usage(format!("unknown --min-level: {m}")))?;
            Ok(g.as_str().to_string())
        }
        None => Ok(default.to_string()),
    }
}

/// C1 plan: the L1 recipe (PRBS + zero + power-cycle + verify + signatures).
fn plan_l1(
    device: &DeviceIdentity,
    opts: &PlanOptions,
    backend: &PlanBackend,
    power_cycle: &PowerCycleMethod,
    protected_area: bool,
) -> Result<Plan> {
    let minimum_level = min_level_of(opts, "C1")?;

    let mut actions = vec![
        PlanAction {
            seq: 1,
            id: "inventory".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 2,
            id: "lba-prbs-write".into(),
            kind: ActionKind::DestructiveResumable,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 3,
            id: "flush".into(),
            kind: ActionKind::StateChangingReversible,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 4,
            id: "power-cycle".into(),
            kind: ActionKind::PowerCycle,
            method: Some(power_cycle.clone()),
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 5,
            id: "lba-prbs-verify".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
    ];
    // Research option: extra churn passes (finite) to encourage GC; C1 ceiling.
    let mut seq = 6u32;
    if opts.aggressive_lba {
        for pass in 0..2 {
            actions.push(PlanAction {
                seq,
                id: format!("lba-prbs-write-churn-{pass}"),
                kind: ActionKind::DestructiveResumable,
                method: None,
                params: None,
                timeout_secs: opts.timeout_secs,
                retries: Some(0),
            });
            seq += 1;
            actions.push(PlanAction {
                seq,
                id: format!("lba-prbs-verify-churn-{pass}"),
                kind: ActionKind::ReadOnly,
                method: None,
                params: None,
                timeout_secs: opts.timeout_secs,
                retries: Some(0),
            });
            seq += 1;
        }
    }
    actions.extend([
        PlanAction {
            seq,
            id: "lba-zero-write".into(),
            kind: ActionKind::DestructiveResumable,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: seq + 1,
            id: "flush".into(),
            kind: ActionKind::StateChangingReversible,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: seq + 2,
            id: "power-cycle".into(),
            kind: ActionKind::PowerCycle,
            method: Some(power_cycle.clone()),
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: seq + 3,
            id: "lba-zero-verify".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: seq + 4,
            id: "signature-check".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: seq + 5,
            id: "postcheck-l1".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
    ]);

    Ok(new_plan_base(
        device,
        opts,
        backend,
        minimum_level,
        domains_for_lba(protected_area),
        "C1",
        actions,
        vec![FallbackEntry {
            from: "lba-prbs-write".into(),
            to: "lba-zero-write".into(),
            condition: "write-error".into(),
        }],
        None,
        power_block(power_cycle),
    ))
}

/// C2 plan: documented device-level erase, blank verification, signature
/// check, power cycle and post-check. No LBA overwrite is layered on top
/// (a documented device erase covers D0-D2).
fn plan_c2(
    device: &DeviceIdentity,
    opts: &PlanOptions,
    backend: &PlanBackend,
    caps: &BackendCapabilities,
    power_cycle: &PowerCycleMethod,
) -> Result<Plan> {
    let minimum_level = min_level_of(opts, "C2")?;
    let actions = vec![
        PlanAction {
            seq: 1,
            id: "inventory".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 2,
            id: "device-user-area-erase".into(),
            kind: ActionKind::DestructiveResumable,
            method: None,
            params: Some(serde_json::json!({
                "method": caps.erase_method,
                "coverage": caps.erase_coverage,
            })),
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 3,
            id: "blank-verify".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 4,
            id: "signature-check".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 5,
            id: "power-cycle".into(),
            kind: ActionKind::PowerCycle,
            method: Some(power_cycle.clone()),
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 6,
            id: "postcheck-p2".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
    ];

    // Fallback: if the device erase is unavailable, fall back to the full L1
    // recipe (embedded plan). Reaches C1 at most.
    let fallback_capable = caps.has("LBA_PRBS_WRITE");
    let fallback_plan = if opts.no_fallback || !fallback_capable {
        None
    } else {
        let fb_opts = PlanOptions {
            level: "best".to_string(),
            user_level: None,
            min_level: None,
            no_fallback: false,
            aggressive_lba: opts.aggressive_lba,
            power_cycle: opts.power_cycle.clone(),
            backend_id: opts.backend_id.clone(),
            timeout_secs: opts.timeout_secs,
        };
        let fb = plan_l1(
            device,
            &fb_opts,
            backend,
            power_cycle,
            caps.protected_area_bytes > 0,
        )?;
        Some(serde_json::to_value(fb).expect("fallback plan serialization"))
    };

    Ok(new_plan_base(
        device,
        opts,
        backend,
        minimum_level,
        domains_for_device_erase(
            &caps.erase_coverage,
            caps.erase_method.as_deref(),
            caps.protected_area_bytes > 0,
        ),
        "C2",
        actions,
        if fallback_capable {
            vec![FallbackEntry {
                from: "device-user-area-erase".into(),
                to: "lba".into(),
                condition: "device-erase-unavailable".into(),
            }]
        } else {
            Vec::new()
        },
        fallback_plan,
        power_block(power_cycle),
    ))
}

/// C3 plan: controller reinitialization (service mode, old RBB erase,
/// physical qualification, new BBT/FTL/spare rebuild) per the matched
/// production profile. Capability downgrade is resolved before planning;
/// execution never changes erase methods after entering service mode.
fn plan_c3(
    device: &DeviceIdentity,
    opts: &PlanOptions,
    backend: &PlanBackend,
    caps: &BackendCapabilities,
    power_cycle: &PowerCycleMethod,
) -> Result<Plan> {
    let minimum_level = min_level_of(opts, "C3")?;
    let actions = vec![
        PlanAction {
            seq: 1,
            id: "inventory".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 2,
            id: "capture-old-bbt".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 3,
            id: "enter-service-mode".into(),
            kind: ActionKind::StateChangingReversible,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 4,
            id: "erase-old-rbb".into(),
            kind: ActionKind::DestructiveResumable,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 5,
            id: "qualify-blocks".into(),
            kind: ActionKind::DestructiveResumable,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 6,
            id: "final-erase".into(),
            kind: ActionKind::DestructiveResumable,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 7,
            id: "rebuild-bbt-ftl".into(),
            kind: ActionKind::DestructiveResumable,
            method: None,
            params: Some(serde_json::json!({
                "capacity_policy": caps.capacity_policy,
            })),
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 8,
            id: "exit-service-mode".into(),
            kind: ActionKind::StateChangingReversible,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 9,
            id: "power-cycle".into(),
            kind: ActionKind::PowerCycle,
            method: Some(power_cycle.clone()),
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 10,
            id: "re-enumeration".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 11,
            id: "postcheck-c3".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
    ];

    Ok(new_plan_base(
        device,
        opts,
        backend,
        minimum_level,
        domains_for_controller(caps.protected_area_bytes > 0),
        "C3",
        actions,
        Vec::new(),
        None,
        power_block(power_cycle),
    ))
}

/// C4 plan: certified physical scope. Every non-FBB data-bearing block is
/// enumerated, categorized and erased with per-block results; then the
/// controller rebuild (BBT/FTL/spare) completes the reinitialization.
/// Capability downgrade is resolved before planning; execution never changes
/// erase methods after physical-media operations begin.
fn plan_c4(
    device: &DeviceIdentity,
    opts: &PlanOptions,
    backend: &PlanBackend,
    caps: &BackendCapabilities,
    power_cycle: &PowerCycleMethod,
) -> Result<Plan> {
    let minimum_level = min_level_of(opts, "C4")?;
    let actions = vec![
        PlanAction {
            seq: 1,
            id: "inventory".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 2,
            id: "capture-old-bbt".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 3,
            id: "enter-service-mode".into(),
            kind: ActionKind::StateChangingReversible,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 4,
            id: "enumerate-blocks".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 5,
            id: "erase-old-rbb".into(),
            kind: ActionKind::DestructiveResumable,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 6,
            id: "erase-data-blocks".into(),
            kind: ActionKind::DestructiveResumable,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 7,
            id: "qualify-blocks".into(),
            kind: ActionKind::DestructiveResumable,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 8,
            id: "final-erase".into(),
            kind: ActionKind::DestructiveResumable,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 9,
            id: "verify-physical-erasure".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 10,
            id: "rebuild-bbt-ftl".into(),
            kind: ActionKind::DestructiveResumable,
            method: None,
            params: Some(serde_json::json!({
                "capacity_policy": caps.capacity_policy,
            })),
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 11,
            id: "exit-service-mode".into(),
            kind: ActionKind::StateChangingReversible,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 12,
            id: "power-cycle".into(),
            kind: ActionKind::PowerCycle,
            method: Some(power_cycle.clone()),
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 13,
            id: "re-enumeration".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 14,
            id: "postcheck-c4".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs: opts.timeout_secs,
            retries: Some(0),
        },
    ];

    Ok(new_plan_base(
        device,
        opts,
        backend,
        minimum_level,
        domains_for_controller(caps.protected_area_bytes > 0),
        "C4",
        actions,
        Vec::new(),
        None,
        power_block(power_cycle),
    ))
}

/// Read-only physical salvage workflow. Entering and leaving controller
/// service mode may reset/re-enumerate the device, but no erase, program or
/// metadata command is present in this plan. The output file descriptors are
/// supplied separately by the trusted core and are not embedded as paths.
pub fn plan_salvage(
    device: &DeviceIdentity,
    backend: &PlanBackend,
    timeout_secs: Option<u64>,
    protected_area: bool,
) -> Result<Plan> {
    if backend.profile.is_none() {
        return Err(Error::Unsupported(
            "physical salvage requires an exact production controller profile".into(),
        ));
    }
    let actions = vec![
        PlanAction {
            seq: 1,
            id: "inventory".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 2,
            id: "capture-old-bbt".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 3,
            id: "enter-service-mode".into(),
            kind: ActionKind::StateChangingReversible,
            method: None,
            params: None,
            timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 4,
            id: "enumerate-blocks".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 5,
            id: "salvage-physical".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 6,
            id: "exit-service-mode".into(),
            kind: ActionKind::StateChangingReversible,
            method: None,
            params: None,
            timeout_secs,
            retries: Some(0),
        },
        PlanAction {
            seq: 7,
            id: "re-enumeration".into(),
            kind: ActionKind::ReadOnly,
            method: None,
            params: None,
            timeout_secs,
            retries: Some(0),
        },
    ];
    let opts = PlanOptions {
        level: "salvage".into(),
        user_level: Some("salvage".into()),
        min_level: Some("C0".into()),
        no_fallback: true,
        aggressive_lba: false,
        power_cycle: None,
        backend_id: Some(backend.id.clone()),
        timeout_secs,
    };
    let domains = domains_for_controller(protected_area)
        .into_iter()
        .map(|mut domain| {
            domain.planned = if domain.id == "D7" {
                "not-applicable".into()
            } else {
                "physical-read-salvage".into()
            };
            domain
        })
        .collect();
    Ok(new_plan_base(
        device,
        &opts,
        backend,
        "C0".into(),
        domains,
        "C0",
        actions,
        Vec::new(),
        None,
        serde_json::json!({
            "power_cycle_required": 0,
            "note": "physical salvage is read-only; controller service-mode transitions may re-enumerate the device",
        }),
    ))
}

fn domains_for_controller(protected_area: bool) -> Vec<PlanDomain> {
    vec![
        PlanDomain {
            id: "D0".into(),
            state: "present".into(),
            planned: "controller-erase".into(),
        },
        PlanDomain {
            id: "D1".into(),
            state: "present".into(),
            planned: "controller-erase".into(),
        },
        PlanDomain {
            id: "D2".into(),
            state: "present".into(),
            planned: "controller-erase".into(),
        },
        PlanDomain {
            id: "D3".into(),
            state: "present".into(),
            planned: "per-block-erase".into(),
        },
        PlanDomain {
            id: "D4".into(),
            state: "present".into(),
            planned: "bbt-ftl-rebuild".into(),
        },
        d5_domain(protected_area),
        PlanDomain {
            id: "D6".into(),
            state: "present".into(),
            planned: "preserved-nonuser".into(),
        },
        PlanDomain {
            id: "D7".into(),
            state: "not-applicable".into(),
            planned: "preserved".into(),
        },
    ]
}

fn domains_for_lba(protected_area: bool) -> Vec<PlanDomain> {
    vec![
        PlanDomain {
            id: "D0".into(),
            state: "present".into(),
            planned: "lba-prbs+zero".into(),
        },
        PlanDomain {
            id: "D1".into(),
            state: "possible".into(),
            planned: "unreachable".into(),
        },
        PlanDomain {
            id: "D2".into(),
            state: "possible".into(),
            planned: "unreachable".into(),
        },
        PlanDomain {
            id: "D3".into(),
            state: "possible".into(),
            planned: "unreachable".into(),
        },
        PlanDomain {
            id: "D4".into(),
            state: "possible".into(),
            planned: "unreachable".into(),
        },
        d5_domain(protected_area),
        PlanDomain {
            id: "D6".into(),
            state: "present".into(),
            planned: "preserved-nonuser".into(),
        },
        PlanDomain {
            id: "D7".into(),
            state: "not-applicable".into(),
            planned: "preserved".into(),
        },
    ]
}

/// D5 (Protected Area) domain: present + unreachable when a protected area
/// exists and cannot be accessed without authentication.
fn d5_domain(protected_area: bool) -> PlanDomain {
    if protected_area {
        PlanDomain {
            id: "D5".into(),
            state: "present".into(),
            planned: "unreachable".into(),
        }
    } else {
        PlanDomain {
            id: "D5".into(),
            state: "not-applicable".into(),
            planned: "preserved".into(),
        }
    }
}

/// C2 plan domains: the documented device erase covers D0-D2.
fn domains_for_device_erase(
    coverage: &[String],
    method: Option<&str>,
    protected_area: bool,
) -> Vec<PlanDomain> {
    let method = method.unwrap_or("device-erase");
    let covered = |id: &str| coverage.iter().any(|c| c == id);
    vec![
        PlanDomain {
            id: "D0".into(),
            state: "present".into(),
            planned: if covered("D0") {
                method.into()
            } else {
                "unreachable".into()
            },
        },
        PlanDomain {
            id: "D1".into(),
            state: if covered("D1") {
                "present".into()
            } else {
                "possible".into()
            },
            planned: if covered("D1") {
                method.into()
            } else {
                "unreachable".into()
            },
        },
        PlanDomain {
            id: "D2".into(),
            state: if covered("D2") {
                "present".into()
            } else {
                "possible".into()
            },
            planned: if covered("D2") {
                method.into()
            } else {
                "unreachable".into()
            },
        },
        PlanDomain {
            id: "D3".into(),
            state: "possible".into(),
            planned: "unreachable".into(),
        },
        PlanDomain {
            id: "D4".into(),
            state: "possible".into(),
            planned: "unreachable".into(),
        },
        d5_domain(protected_area),
        PlanDomain {
            id: "D6".into(),
            state: "present".into(),
            planned: "preserved-nonuser".into(),
        },
        PlanDomain {
            id: "D7".into(),
            state: "not-applicable".into(),
            planned: "preserved".into(),
        },
    ]
}

fn new_plan_id(fingerprint: &str, backend: &str) -> String {
    static PLAN_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let sequence = PLAN_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let raw = format!(
        "{fingerprint}|{backend}|{nanos}|{}|{sequence}",
        std::process::id()
    );
    crate::digest(raw.as_bytes())[7..19].to_string()
}

/// Parse and validate a plan document from JSON.
pub fn validate(json: &Value) -> Result<Plan> {
    let plan: Plan = serde_json::from_value(json.clone())
        .map_err(|e| Error::Invalid(format!("plan schema: {e}")))?;
    if plan.schema != crate::SCHEMA_PLAN {
        return Err(Error::Invalid(format!(
            "plan schema mismatch: {}",
            plan.schema
        )));
    }
    let expected = plan.compute_hash();
    if plan.plan_hash != expected {
        return Err(Error::Invalid(
            "plan hash does not match plan content (tampered?)".into(),
        ));
    }
    validate_invariants(&plan)?;
    Ok(plan)
}

fn is_sha256(value: &str) -> bool {
    value
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn expected_recipe(plan: &Plan) -> Option<Vec<(&'static str, ActionKind)>> {
    use ActionKind::{
        DestructiveResumable as D, PowerCycle as P, ReadOnly as R, StateChangingReversible as S,
    };
    let recipe = match (plan.expected_grade.as_str(), plan.requested_level.as_str()) {
        ("C0", "salvage") => vec![
            ("inventory", R),
            ("capture-old-bbt", R),
            ("enter-service-mode", S),
            ("enumerate-blocks", R),
            ("salvage-physical", R),
            ("exit-service-mode", S),
            ("re-enumeration", R),
        ],
        ("C1", _) => {
            let mut actions = vec![
                ("inventory", R),
                ("lba-prbs-write", D),
                ("flush", S),
                ("power-cycle", P),
                ("lba-prbs-verify", R),
            ];
            if plan.aggressive_lba {
                actions.extend([
                    ("lba-prbs-write-churn-0", D),
                    ("lba-prbs-verify-churn-0", R),
                    ("lba-prbs-write-churn-1", D),
                    ("lba-prbs-verify-churn-1", R),
                ]);
            }
            actions.extend([
                ("lba-zero-write", D),
                ("flush", S),
                ("power-cycle", P),
                ("lba-zero-verify", R),
                ("signature-check", R),
                ("postcheck-l1", R),
            ]);
            actions
        }
        ("C2", _) => vec![
            ("inventory", R),
            ("device-user-area-erase", D),
            ("blank-verify", R),
            ("signature-check", R),
            ("power-cycle", P),
            ("postcheck-p2", R),
        ],
        ("C3", _) => vec![
            ("inventory", R),
            ("capture-old-bbt", R),
            ("enter-service-mode", S),
            ("erase-old-rbb", D),
            ("qualify-blocks", D),
            ("final-erase", D),
            ("rebuild-bbt-ftl", D),
            ("exit-service-mode", S),
            ("power-cycle", P),
            ("re-enumeration", R),
            ("postcheck-c3", R),
        ],
        ("C4", _) => vec![
            ("inventory", R),
            ("capture-old-bbt", R),
            ("enter-service-mode", S),
            ("enumerate-blocks", R),
            ("erase-old-rbb", D),
            ("erase-data-blocks", D),
            ("qualify-blocks", D),
            ("final-erase", D),
            ("verify-physical-erasure", R),
            ("rebuild-bbt-ftl", D),
            ("exit-service-mode", S),
            ("power-cycle", P),
            ("re-enumeration", R),
            ("postcheck-c4", R),
        ],
        _ => return None,
    };
    Some(recipe)
}

fn validate_invariants(plan: &Plan) -> Result<()> {
    if plan.id.len() != 12 || !plan.id.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Invalid("plan id must be 12 hex characters".into()));
    }
    if !is_sha256(&plan.device.fingerprint) || !is_sha256(&plan.plan_hash) {
        return Err(Error::Invalid(
            "plan fingerprint and plan_hash must be sha256 values".into(),
        ));
    }
    if plan.device.physical_path.is_empty() || plan.device.capacity_bytes == 0 {
        return Err(Error::Invalid(
            "plan device physical_path and nonzero capacity are required".into(),
        ));
    }
    if plan.backend.id.is_empty() || plan.backend.trust != "production" {
        return Err(Error::Invalid(
            "plan backend must be identified and production-trusted".into(),
        ));
    }
    if !plan
        .backend
        .id
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(Error::Invalid("plan backend id is invalid".into()));
    }
    let backend_digest = plan
        .backend
        .sha256
        .as_deref()
        .ok_or_else(|| Error::Invalid("plan backend digest is required".into()))?;
    if backend_digest.len() != 64 || !backend_digest.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(Error::Invalid(
            "plan backend digest must be 64 hex characters".into(),
        ));
    }
    if let Some(profile_digest) = plan.backend.profile_sha256.as_deref() {
        if !is_sha256(profile_digest)
            && (profile_digest.len() != 64
                || !profile_digest.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(Error::Invalid(
                "plan profile digest must be a sha256 value".into(),
            ));
        }
    } else if plan.backend.profile.is_some() {
        return Err(Error::Invalid(
            "plan profile digest is required when a profile is selected".into(),
        ));
    }
    let mut artifact_ids = std::collections::BTreeSet::new();
    let mut artifact_roles = std::collections::BTreeSet::new();
    for artifact in &plan.backend.artifacts {
        crate::artifact::validate_spec(artifact)?;
        if !artifact_ids.insert(artifact.id.as_str())
            || !artifact_roles.insert(artifact.role.as_str())
        {
            return Err(Error::Invalid(
                "plan backend artifacts require unique ids and roles".into(),
            ));
        }
    }
    if !matches!(
        plan.requested_level.as_str(),
        "best" | "physical" | "controller" | "device" | "lba" | "salvage"
    ) {
        return Err(Error::Invalid("plan requested_level is invalid".into()));
    }
    let expected_grade = CGrade::parse(&plan.expected_grade)
        .ok_or_else(|| Error::Invalid("plan expected_grade is invalid".into()))?;
    let minimum_grade = CGrade::parse(&plan.minimum_level)
        .ok_or_else(|| Error::Invalid("plan minimum_level is invalid".into()))?;
    if expected_grade < minimum_grade {
        return Err(Error::Invalid(
            "plan expected_grade is below minimum_level".into(),
        ));
    }
    if plan.actions.is_empty() {
        return Err(Error::Invalid("plan actions must not be empty".into()));
    }
    for (index, action) in plan.actions.iter().enumerate() {
        if action.seq != index as u32 + 1 || action.id.is_empty() {
            return Err(Error::Invalid(
                "plan action sequence must be contiguous and ids nonempty".into(),
            ));
        }
        if action.retries.unwrap_or(0) != 0 {
            return Err(Error::Invalid(
                "plan actions may not retry destructive commands implicitly".into(),
            ));
        }
        if action.timeout_secs == Some(0) {
            return Err(Error::Invalid(
                "plan action timeout must be greater than zero".into(),
            ));
        }
        if matches!(&action.kind, ActionKind::PowerCycle) != action.method.is_some() {
            return Err(Error::Invalid(
                "only power-cycle actions may declare a power-cycle method".into(),
            ));
        }
        if action.params.is_some()
            && !matches!(
                action.id.as_str(),
                "device-user-area-erase" | "rebuild-bbt-ftl"
            )
        {
            return Err(Error::Invalid(format!(
                "plan action {} may not declare params",
                action.id
            )));
        }
    }

    let recipe = expected_recipe(plan)
        .ok_or_else(|| Error::Invalid("plan expected_grade has no executable recipe".into()))?;
    if recipe.len() != plan.actions.len()
        || recipe
            .iter()
            .zip(&plan.actions)
            .any(|((id, kind), action)| action.id != *id || &action.kind != kind)
    {
        return Err(Error::Invalid(format!(
            "plan actions do not match the {} recipe",
            plan.expected_grade
        )));
    }

    let expected_domains = ["D0", "D1", "D2", "D3", "D4", "D5", "D6", "D7"];
    if plan.domains.len() != expected_domains.len()
        || expected_domains.iter().any(|expected| {
            plan.domains
                .iter()
                .filter(|domain| domain.id == *expected)
                .count()
                != 1
        })
    {
        return Err(Error::Invalid(
            "plan must describe each domain D0 through D7 exactly once".into(),
        ));
    }

    if let Some(value) = plan.fallback_plan.as_ref() {
        let fallback =
            validate(value).map_err(|e| Error::Invalid(format!("embedded fallback plan: {e}")))?;
        if fallback.device.fingerprint != plan.device.fingerprint
            || fallback.device.physical_path != plan.device.physical_path
            || fallback.device.capacity_bytes != plan.device.capacity_bytes
            || fallback.backend.id != plan.backend.id
            || fallback.backend.sha256 != plan.backend.sha256
        {
            return Err(Error::Invalid(
                "fallback plan device and backend must match the parent plan".into(),
            ));
        }
        let fallback_grade = CGrade::parse(&fallback.expected_grade)
            .ok_or_else(|| Error::Invalid("fallback expected_grade is invalid".into()))?;
        if fallback_grade >= expected_grade {
            return Err(Error::Invalid(
                "fallback plan must have a strictly lower expected grade".into(),
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device;

    fn file_device() -> DeviceIdentity {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("img");
        std::fs::write(&f, vec![0u8; 65536]).unwrap();
        device::identify(f.to_str().unwrap()).unwrap()
    }

    fn backend() -> PlanBackend {
        PlanBackend {
            id: "lba".into(),
            version: "2.0.0".into(),
            profile: None,
            profile_sha256: None,
            trust: "production".into(),
            sha256: Some("0".repeat(64)),
            artifacts: Vec::new(),
        }
    }

    fn caps_l1() -> BackendCapabilities {
        BackendCapabilities {
            capabilities: vec!["LBA_PRBS_WRITE".into()],
            erase_coverage: Vec::new(),
            erase_method: None,
            rebuilds: Vec::new(),
            controller_profile: None,
            capacity_policy: None,
            physical_certified: false,
            protected_area_bytes: 0,
            grade_ceiling: "C1".into(),
        }
    }

    fn caps_device_erase() -> BackendCapabilities {
        BackendCapabilities {
            capabilities: vec!["ERASE_USER_AREA".into(), "LBA_PRBS_WRITE".into()],
            erase_coverage: vec!["D0".into(), "D1".into(), "D2".into()],
            erase_method: Some("sanitize-block-erase".into()),
            rebuilds: Vec::new(),
            controller_profile: None,
            capacity_policy: None,
            physical_certified: false,
            protected_area_bytes: 0,
            grade_ceiling: "C2".into(),
        }
    }

    fn caps_controller() -> BackendCapabilities {
        BackendCapabilities {
            capabilities: vec![
                "CONTROLLER_REINITIALIZE".into(),
                "ERASE_USER_AREA".into(),
                "LBA_PRBS_WRITE".into(),
            ],
            erase_coverage: vec!["D0".into(), "D1".into(), "D2".into()],
            erase_method: Some("sanitize-block-erase".into()),
            rebuilds: vec!["BBT".into(), "FTL".into(), "spare".into()],
            controller_profile: Some("sim-controller-1".into()),
            capacity_policy: Some(serde_json::json!({
                "bin_bytes": 0,
                "minimum_spare_blocks": 4,
                "spare_ratio": 0.05,
            })),
            physical_certified: false,
            protected_area_bytes: 0,
            grade_ceiling: "C3".into(),
        }
    }

    fn caps_physical() -> BackendCapabilities {
        let mut c = caps_controller();
        c.capabilities.push("PHYSICAL_SCOPE".into());
        c.physical_certified = true;
        c.grade_ceiling = "C4".into();
        c
    }

    #[test]
    fn controller_plan_does_not_embed_unexecutable_fallback() {
        let device = file_device();
        let mut caps = caps_controller();
        caps.capabilities
            .retain(|cap| cap == "CONTROLLER_REINITIALIZE");
        caps.erase_coverage.clear();
        caps.erase_method = None;
        let plan = plan(
            &device,
            &PlanOptions {
                level: "controller".into(),
                user_level: None,
                min_level: None,
                no_fallback: false,
                aggressive_lba: false,
                power_cycle: None,
                backend_id: Some("controller".into()),
                timeout_secs: None,
            },
            &backend(),
            &caps,
        )
        .unwrap();
        assert!(plan.fallback.is_empty());
        assert!(plan.fallback_plan.is_none());
    }

    fn opts() -> PlanOptions {
        PlanOptions {
            level: "best".into(),
            user_level: None,
            min_level: None,
            no_fallback: false,
            aggressive_lba: false,
            power_cycle: None,
            backend_id: None,
            timeout_secs: None,
        }
    }

    #[test]
    fn plan_roundtrip_and_hash() {
        let dev = file_device();
        let mut p = plan(&dev, &opts(), &backend(), &caps_l1()).unwrap();
        let json = serde_json::to_value(&p).unwrap();
        let p2 = validate(&json).unwrap();
        assert_eq!(p2.id, p.id);
        assert_eq!(p2.expected_grade, "C1");
        assert_eq!(p2.actions.len(), 11);
        assert_eq!(p2.actions[0].id, "inventory");
        assert_eq!(p2.actions[3].kind, ActionKind::PowerCycle);
        assert_eq!(p2.actions[3].method, Some(PowerCycleMethod::None));
        assert_eq!(p2.device.fingerprint, dev.fingerprint);

        // Tampering breaks the hash.
        let mut tampered = json.clone();
        tampered
            .as_object_mut()
            .unwrap()
            .insert("requested_level".into(), "lba".into());
        assert!(validate(&tampered).is_err());

        // The explicit destructive marker is part of the external schema and
        // must agree with the action kind; it cannot be ignored as an unknown
        // field during deserialization.
        let mut false_marker = json.clone();
        false_marker["actions"][1]["destructive"] = serde_json::json!(false);
        assert!(validate(&false_marker).is_err());

        let mut unknown = json.clone();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(validate(&unknown).is_err());

        // A recomputed hash cannot make a write action masquerade as
        // read-only: the executable recipe binds every action id to its kind.
        let mut disguised = p.clone();
        disguised.actions[1].kind = ActionKind::ReadOnly;
        disguised.refresh_hash();
        assert!(validate(&serde_json::to_value(disguised).unwrap()).is_err());

        // Refresh hash restores validity.
        p.refresh_hash();
        let json2 = serde_json::to_value(&p).unwrap();
        assert!(validate(&json2).is_ok());
    }

    #[test]
    fn plan_ids_are_unique_within_one_timestamp_tick() {
        let dev = file_device();
        let first = plan(&dev, &opts(), &backend(), &caps_l1()).unwrap();
        let second = plan(&dev, &opts(), &backend(), &caps_l1()).unwrap();
        assert_ne!(first.id, second.id);
        assert_ne!(first.plan_hash, second.plan_hash);
    }

    #[test]
    fn plan_requires_supported_level() {
        let dev = file_device();
        let mut o = opts();
        o.level = "physical".into();
        let e = plan(&dev, &o, &backend(), &caps_l1()).unwrap_err();
        assert!(e.exit_code() == 2, "expected unsupported exit code");
        o.level = "bogus".into();
        let e = plan(&dev, &o, &backend(), &caps_l1()).unwrap_err();
        assert!(e.exit_code() == 64, "expected usage exit code");
    }

    #[test]
    fn plan_rejects_unreachable_minimum_level() {
        let dev = file_device();
        let mut o = opts();
        o.level = "lba".into();
        o.min_level = Some("C2".into());
        let error = plan(&dev, &o, &backend(), &caps_l1()).unwrap_err();
        assert_eq!(error.exit_code(), crate::errors::exit::UNSUPPORTED);
    }

    #[test]
    fn plan_power_cycle_methods() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("sim.img");
        let spec = crate::sim::SimSpec::default();
        crate::sim::create(&f, &spec).unwrap();
        let dev = device::identify(f.to_str().unwrap()).unwrap();
        assert!(dev.is_sim());
        let p = plan(&dev, &opts(), &backend(), &caps_l1()).unwrap();
        let pc = p.actions.iter().find(|a| a.id == "power-cycle").unwrap();
        assert_eq!(pc.method, Some(PowerCycleMethod::SimInternal));

        let mut o = opts();
        o.power_cycle = Some("echo".into());
        let f2 = dir.path().join("plain.img");
        std::fs::write(&f2, vec![0u8; 65536]).unwrap();
        let dev2 = device::identify(f2.to_str().unwrap()).unwrap();
        let p2 = plan(&dev2, &o, &backend(), &caps_l1()).unwrap();
        let pc2 = p2.actions.iter().find(|a| a.id == "power-cycle").unwrap();
        assert_eq!(pc2.method, Some(PowerCycleMethod::External));
    }

    #[test]
    fn aggressive_lba_adds_churn() {
        let dev = file_device();
        let mut o = opts();
        o.aggressive_lba = true;
        let p = plan(&dev, &o, &backend(), &caps_l1()).unwrap();
        assert_eq!(p.actions.len(), 15);
    }

    #[test]
    fn device_level_plans_c2_when_capable() {
        let dev = file_device();
        let mut o = opts();
        o.level = "device".into();
        let p = plan(&dev, &o, &backend(), &caps_device_erase()).unwrap();
        assert_eq!(p.expected_grade, "C2");
        assert_eq!(p.minimum_level, "C2");
        let ids: Vec<&str> = p.actions.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "inventory",
                "device-user-area-erase",
                "blank-verify",
                "signature-check",
                "power-cycle",
                "postcheck-p2",
            ]
        );
        // No LBA overwrite layered on top.
        assert!(!ids.iter().any(|id| id.starts_with("lba-prbs-write")));
        // The device erase carries the documented scope and method.
        let de = p.actions[1].params.as_ref().unwrap();
        assert_eq!(de["method"], "sanitize-block-erase");
        assert_eq!(de["coverage"], serde_json::json!(["D0", "D1", "D2"]));
        // Fallback to LBA is embedded.
        assert!(p.fallback_plan.is_some());
        let fb = validate(p.fallback_plan.as_ref().unwrap()).unwrap();
        assert_eq!(fb.expected_grade, "C1");
    }

    #[test]
    fn device_level_fails_without_capability() {
        let dev = file_device();
        let mut o = opts();
        o.level = "device".into();
        let e = plan(&dev, &o, &backend(), &caps_l1()).unwrap_err();
        assert_eq!(
            e.exit_code(),
            2,
            "C2 must be unplannable without device erase"
        );
    }

    #[test]
    fn best_uses_device_erase_when_capable_else_l1() {
        let dev = file_device();
        let p = plan(&dev, &opts(), &backend(), &caps_device_erase()).unwrap();
        assert_eq!(p.expected_grade, "C2");
        let p2 = plan(&dev, &opts(), &backend(), &caps_l1()).unwrap();
        assert_eq!(p2.expected_grade, "C1");
    }

    #[test]
    fn lba_level_is_always_l1() {
        let dev = file_device();
        let mut o = opts();
        o.level = "lba".into();
        let p = plan(&dev, &o, &backend(), &caps_device_erase()).unwrap();
        assert_eq!(p.expected_grade, "C1");
        assert!(p.fallback_plan.is_none());
    }

    #[test]
    fn no_fallback_drops_embedded_plan() {
        let dev = file_device();
        let mut o = opts();
        o.level = "device".into();
        o.no_fallback = true;
        let p = plan(&dev, &o, &backend(), &caps_device_erase()).unwrap();
        assert!(p.fallback_plan.is_none());
    }

    #[test]
    fn discard_only_capability_is_not_device_erase() {
        let caps = BackendCapabilities {
            capabilities: vec!["UNMAP".into()],
            erase_coverage: Vec::new(),
            erase_method: None,
            rebuilds: Vec::new(),
            controller_profile: None,
            capacity_policy: None,
            physical_certified: false,
            protected_area_bytes: 0,
            grade_ceiling: "C1".into(),
        };
        assert!(!caps.erase_user_area());
        // Coverage without a method is not usable either.
        let caps2 = BackendCapabilities {
            capabilities: vec!["ERASE_USER_AREA".into()],
            erase_coverage: vec!["D0".into()],
            erase_method: None,
            rebuilds: Vec::new(),
            controller_profile: None,
            capacity_policy: None,
            physical_certified: false,
            protected_area_bytes: 0,
            grade_ceiling: "C1".into(),
        };
        assert!(!caps2.erase_user_area());
    }

    #[test]
    fn controller_level_plans_c3_when_profile_matches() {
        let dev = file_device();
        let mut o = opts();
        o.level = "controller".into();
        let p = plan(&dev, &o, &backend(), &caps_controller()).unwrap();
        assert_eq!(p.expected_grade, "C3");
        assert_eq!(p.minimum_level, "C3");
        let ids: Vec<&str> = p.actions.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "inventory",
                "capture-old-bbt",
                "enter-service-mode",
                "erase-old-rbb",
                "qualify-blocks",
                "final-erase",
                "rebuild-bbt-ftl",
                "exit-service-mode",
                "power-cycle",
                "re-enumeration",
                "postcheck-c3",
            ]
        );
        // Once controller processing starts, switching erase methods is not
        // a safe fallback. Capability downgrade happens before planning.
        assert!(p.fallback.is_empty());
        assert!(p.fallback_plan.is_none());
        let serialized = serde_json::to_value(&p).unwrap();
        assert!(serialized.get("fallback").is_none());
        assert_eq!(validate(&serialized).unwrap().expected_grade, "C3");
        // D3/D4 planned within controller scope.
        let d3 = p.domains.iter().find(|d| d.id == "D3").unwrap();
        assert_eq!(d3.planned, "per-block-erase");
        let d4 = p.domains.iter().find(|d| d.id == "D4").unwrap();
        assert_eq!(d4.planned, "bbt-ftl-rebuild");
    }

    #[test]
    fn controller_level_fails_without_profile() {
        let dev = file_device();
        let mut o = opts();
        o.level = "controller".into();
        let e = plan(&dev, &o, &backend(), &caps_device_erase()).unwrap_err();
        assert_eq!(e.exit_code(), 2, "C3 must be unplannable without a profile");
    }

    #[test]
    fn best_prefers_controller_over_device_over_lba() {
        let dev = file_device();
        let p = plan(&dev, &opts(), &backend(), &caps_controller()).unwrap();
        assert_eq!(p.expected_grade, "C3");
        let p2 = plan(&dev, &opts(), &backend(), &caps_device_erase()).unwrap();
        assert_eq!(p2.expected_grade, "C2");
        let p3 = plan(&dev, &opts(), &backend(), &caps_l1()).unwrap();
        assert_eq!(p3.expected_grade, "C1");
    }

    #[test]
    fn physical_level_fails_without_certification() {
        let dev = file_device();
        let mut o = opts();
        o.level = "physical".into();
        // Controller-capable but not physically certified -> exit 2.
        let e = plan(&dev, &o, &backend(), &caps_controller()).unwrap_err();
        assert_eq!(e.exit_code(), 2);
        assert!(e
            .to_string()
            .contains("no certified physical-scope backend"));
    }

    #[test]
    fn physical_level_plans_c4_when_certified() {
        let dev = file_device();
        let mut o = opts();
        o.level = "physical".into();
        let p = plan(&dev, &o, &backend(), &caps_physical()).unwrap();
        assert_eq!(p.expected_grade, "C4");
        assert_eq!(p.minimum_level, "C4");
        let ids: Vec<&str> = p.actions.iter().map(|a| a.id.as_str()).collect();
        assert_eq!(
            ids,
            vec![
                "inventory",
                "capture-old-bbt",
                "enter-service-mode",
                "enumerate-blocks",
                "erase-old-rbb",
                "erase-data-blocks",
                "qualify-blocks",
                "final-erase",
                "verify-physical-erasure",
                "rebuild-bbt-ftl",
                "exit-service-mode",
                "power-cycle",
                "re-enumeration",
                "postcheck-c4",
            ]
        );
        assert!(p.fallback.is_empty());
        assert!(p.fallback_plan.is_none());
        let serialized = serde_json::to_value(&p).unwrap();
        assert!(serialized.get("fallback").is_none());
        assert_eq!(validate(&serialized).unwrap().expected_grade, "C4");
    }

    #[test]
    fn salvage_plan_is_a_fixed_read_only_physical_recipe() {
        let dev = file_device();
        let mut backend = backend();
        backend.id = "controller".into();
        backend.profile = Some("test-controller".into());
        backend.profile_sha256 = Some("1".repeat(64));
        let p = plan_salvage(&dev, &backend, Some(30), false).unwrap();
        assert_eq!(p.requested_level, "salvage");
        assert_eq!(p.expected_grade, "C0");
        assert_eq!(p.minimum_level, "C0");
        assert!(p.actions.iter().all(|action| !action.kind.destructive()));
        let ids = p
            .actions
            .iter()
            .map(|action| action.id.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            ids,
            vec![
                "inventory",
                "capture-old-bbt",
                "enter-service-mode",
                "enumerate-blocks",
                "salvage-physical",
                "exit-service-mode",
                "re-enumeration",
            ]
        );
        let validated = validate(&serde_json::to_value(&p).unwrap()).unwrap();
        assert_eq!(validated.plan_hash, p.plan_hash);
        assert_eq!(validated.requested_level, "salvage");
    }

    #[test]
    fn protected_area_marks_d5_unreachable() {
        let dev = file_device();
        let mut caps = caps_l1();
        caps.protected_area_bytes = 2 * 8 * 512;
        let p = plan(&dev, &opts(), &backend(), &caps).unwrap();
        let d5 = p.domains.iter().find(|d| d.id == "D5").unwrap();
        assert_eq!(d5.state, "present");
        assert_eq!(d5.planned, "unreachable");
        // Without a protected area, D5 is not-applicable.
        let p2 = plan(&dev, &opts(), &backend(), &caps_l1()).unwrap();
        let d52 = p2.domains.iter().find(|d| d.id == "D5").unwrap();
        assert_eq!(d52.state, "not-applicable");
    }

    #[test]
    fn best_prefers_physical_over_controller() {
        let dev = file_device();
        let p = plan(&dev, &opts(), &backend(), &caps_physical()).unwrap();
        assert_eq!(p.expected_grade, "C4");
        let p2 = plan(&dev, &opts(), &backend(), &caps_controller()).unwrap();
        assert_eq!(p2.expected_grade, "C3");
    }
}
