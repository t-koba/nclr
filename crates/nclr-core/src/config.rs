//! Site policy configuration.
//!
//! The default behavior must be safe with no config file. When present,
//! `/etc/nclr/nclr.toml` (or `--config FILE`) limits the site policy to:
//! allowed backends, a minimum planning level, spare-ratio bounds and a
//! power-cycle command allowlist. Nothing else.

use crate::errors::{Error, Result};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct SpareRatioBounds {
    #[serde(default)]
    pub min: Option<f64>,
    #[serde(default)]
    pub max: Option<f64>,
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct PowerCyclePolicy {
    #[serde(default)]
    pub allowlist: Vec<String>,
}

#[derive(Deserialize, Clone, Debug, Default)]
#[serde(deny_unknown_fields)]
pub struct SiteConfig {
    #[serde(default)]
    pub allowed_backends: Option<Vec<String>>,
    #[serde(default)]
    pub minimum_level: Option<String>,
    #[serde(default)]
    pub spare_ratio: Option<SpareRatioBounds>,
    #[serde(default)]
    pub power_cycle: Option<PowerCyclePolicy>,
}

impl SiteConfig {
    pub fn allowed_backends(&self) -> &[String] {
        self.allowed_backends.as_deref().unwrap_or(&[])
    }
    pub fn spare_ratio_bounds(&self) -> Option<(f64, f64)> {
        self.spare_ratio
            .as_ref()
            .map(|b| (b.min.unwrap_or(0.0), b.max.unwrap_or(1.0)))
    }
    pub fn power_cycle_allowlist(&self) -> &[String] {
        self.power_cycle
            .as_ref()
            .map(|p| p.allowlist.as_slice())
            .unwrap_or(&[])
    }
    /// True when the site policy constrains backends.
    pub fn restricts_backends(&self) -> bool {
        self.allowed_backends.is_some()
    }
    /// True when the site policy constrains power-cycle commands.
    pub fn restricts_power_cycle(&self) -> bool {
        self.power_cycle.is_some()
    }

    /// Enforce policy constraints that must also apply to imported plans.
    pub fn enforce_plan(&self, plan: &crate::plan::Plan) -> Result<()> {
        if self.restricts_backends()
            && !self
                .allowed_backends()
                .iter()
                .any(|backend| backend == &plan.backend.id)
        {
            return Err(Error::Permission(format!(
                "backend {} is not allowed by the site policy",
                plan.backend.id
            )));
        }
        if let Some(floor) = self
            .minimum_level
            .as_deref()
            .and_then(crate::grade::CGrade::parse)
        {
            let expected = crate::grade::CGrade::parse(&plan.expected_grade)
                .ok_or_else(|| Error::Invalid("plan expected_grade is invalid".into()))?;
            let plan_minimum = crate::grade::CGrade::parse(&plan.minimum_level)
                .ok_or_else(|| Error::Invalid("plan minimum_level is invalid".into()))?;
            if expected < floor || plan_minimum < floor {
                return Err(Error::Permission(format!(
                    "plan does not enforce the site minimum level {}",
                    floor.as_str()
                )));
            }
        }
        if let Some((lo, hi)) = self.spare_ratio_bounds() {
            enforce_spare_ratio(plan, lo, hi)?;
        }
        Ok(())
    }
}

fn enforce_spare_ratio(plan: &crate::plan::Plan, lo: f64, hi: f64) -> Result<()> {
    for action in plan
        .actions
        .iter()
        .filter(|action| action.id == "rebuild-bbt-ftl")
    {
        let ratio = action
            .params
            .as_ref()
            .and_then(|params| params.get("capacity_policy"))
            .and_then(|policy| policy.get("spare_ratio"))
            .and_then(serde_json::Value::as_f64)
            .ok_or_else(|| {
                Error::Permission(
                    "controller plan does not declare a numeric spare ratio required by site policy"
                        .into(),
                )
            })?;
        if !ratio.is_finite() || ratio < lo || ratio > hi {
            return Err(Error::Permission(format!(
                "plan spare ratio {ratio} is outside the site policy range {lo}..={hi}"
            )));
        }
    }
    if let Some(fallback) = plan.fallback_plan.as_ref() {
        let fallback = crate::plan::validate(fallback)?;
        enforce_spare_ratio(&fallback, lo, hi)?;
    }
    Ok(())
}

/// Default config location (root) and the env override.
pub fn default_path() -> Option<PathBuf> {
    let p = PathBuf::from("/etc/nclr/nclr.toml");
    p.is_file().then_some(p)
}

/// Load the site config from an explicit path (or the default location when
/// `path` is None). An absent default is permissive; a missing explicit path
/// is an error because silently ignoring `--config` would disable policy.
pub fn load(path: Option<&Path>) -> Result<SiteConfig> {
    let explicit = path.is_some();
    let path = path.map(Path::to_path_buf).or_else(default_path);
    let Some(path) = path else {
        return Ok(SiteConfig::default());
    };
    if !path.is_file() {
        if explicit {
            return Err(Error::Invalid(format!(
                "site config {} is not a regular file",
                path.display()
            )));
        }
        return Ok(SiteConfig::default());
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::io(format!("site config read {}", path.display()), Some(e)))?;
    let cfg: SiteConfig = toml::from_str(&raw)
        .map_err(|e| Error::Invalid(format!("site config {}: {e}", path.display())))?;
    if let Some(level) = cfg.minimum_level.as_deref() {
        if crate::grade::CGrade::parse(level).is_none() {
            return Err(Error::Invalid(format!(
                "site config {}: invalid minimum_level {level}",
                path.display()
            )));
        }
    }
    if let Some(backends) = &cfg.allowed_backends {
        for backend in backends {
            if backend.is_empty()
                || !backend
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
            {
                return Err(Error::Invalid(format!(
                    "site config {}: invalid backend id {backend}",
                    path.display()
                )));
            }
        }
    }
    if let Some(policy) = &cfg.power_cycle {
        if policy
            .allowlist
            .iter()
            .any(|command| command.trim().is_empty())
        {
            return Err(Error::Invalid(format!(
                "site config {}: power-cycle allowlist entries must not be empty",
                path.display()
            )));
        }
    }
    if let Some((lo, hi)) = cfg.spare_ratio_bounds() {
        if !lo.is_finite()
            || !hi.is_finite()
            || !(0.0..=1.0).contains(&lo)
            || !(0.0..=1.0).contains(&hi)
        {
            return Err(Error::Invalid(format!(
                "site config {}: spare_ratio bounds must be finite values from 0 to 1",
                path.display()
            )));
        }
        if lo > hi {
            return Err(Error::Invalid(format!(
                "site config {}: spare_ratio.min ({lo}) must not exceed max ({hi})",
                path.display()
            )));
        }
    }
    Ok(cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_default_config_is_permissive() {
        let cfg = SiteConfig::default();
        assert!(!cfg.restricts_backends());
        assert!(!cfg.restricts_power_cycle());
        assert!(cfg.allowed_backends().is_empty());
    }

    #[test]
    fn missing_explicit_config_is_rejected() {
        assert!(load(Some(Path::new("/nonexistent/nclr.toml"))).is_err());
    }

    #[test]
    fn parses_site_policy() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("nclr.toml");
        std::fs::write(
            &path,
            "allowed_backends = [\"sim\", \"lba\"]\n\
             minimum_level = \"device\"\n\
             [spare_ratio]\nmin = 0.03\nmax = 0.10\n\
             [power_cycle]\nallowlist = [\"/usr/local/bin/hubctl\", \"true\"]\n",
        )
        .unwrap();
        let cfg = load(Some(&path)).unwrap();
        assert_eq!(cfg.allowed_backends(), &["sim", "lba"]);
        assert_eq!(cfg.minimum_level.as_deref(), Some("device"));
        assert_eq!(cfg.spare_ratio_bounds(), Some((0.03, 0.10)));
        assert!(cfg.restricts_backends());
        assert!(cfg.restricts_power_cycle());
        assert!(cfg.power_cycle_allowlist().contains(&"true".to_string()));
    }

    #[test]
    fn invalid_toml_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.toml");
        std::fs::write(&path, "allowed_backends = [").unwrap();
        assert!(load(Some(&path)).is_err());
    }

    #[test]
    fn policy_typos_and_invalid_values_are_rejected() {
        let dir = tempfile::tempdir().unwrap();
        for (name, contents) in [
            ("unknown.toml", "allowed_backend = [\"sim\"]\n"),
            ("level.toml", "minimum_level = \"bogus\"\n"),
            ("ratio.toml", "[spare_ratio]\nmin = -0.1\nmax = 0.2\n"),
            ("backend.toml", "allowed_backends = [\"../sim\"]\n"),
            ("power.toml", "[power_cycle]\nallowlist = [\"   \"]\n"),
        ] {
            let path = dir.path().join(name);
            std::fs::write(&path, contents).unwrap();
            assert!(load(Some(&path)).is_err(), "{name} must be rejected");
        }
    }

    #[test]
    fn explicitly_empty_allowlists_deny_all() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.toml");
        std::fs::write(
            &path,
            "allowed_backends = []\n[power_cycle]\nallowlist = []\n",
        )
        .unwrap();
        let cfg = load(Some(&path)).unwrap();
        assert!(cfg.restricts_backends());
        assert!(cfg.restricts_power_cycle());
        assert!(cfg.allowed_backends().is_empty());
        assert!(cfg.power_cycle_allowlist().is_empty());
    }
}
