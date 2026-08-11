//! Power cycle control.
//!
//! - `SimInternal`: the sim backend performs power cycling itself.
//! - `External`: a pre-approved external command (`--power-cycle CMD`).
//! - `None`: no power control available; the plan records the evidence gap
//!   and the report is `degraded` with residual `documented-exclusion`.

use crate::errors::{Error, Result};
use crate::plan::PowerCycleMethod;
use std::process::Command;

/// Perform a power cycle with the given method.
pub fn power_cycle(method: &PowerCycleMethod, cmd: Option<&str>) -> Result<()> {
    match method {
        PowerCycleMethod::SimInternal => Err(Error::Invalid(
            "sim-internal power cycle must be dispatched to the sim backend".into(),
        )),
        PowerCycleMethod::External => {
            let cmd = cmd.ok_or_else(|| Error::Usage("--power-cycle command missing".into()))?;
            let status = Command::new("sh")
                .arg("-c")
                .arg(cmd)
                .status()
                .map_err(|e| Error::io("cannot execute power cycle command", Some(e)))?;
            if !status.success() {
                return Err(Error::io(
                    format!("power cycle command exited with {status}"),
                    None,
                ));
            }
            Ok(())
        }
        PowerCycleMethod::None => Err(Error::io(
            "no power control configured; power cycle cannot be performed",
            None,
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn external_command_runs() {
        power_cycle(&PowerCycleMethod::External, Some("true")).unwrap();
        assert!(power_cycle(&PowerCycleMethod::External, Some("false")).is_err());
    }

    #[test]
    fn none_is_an_error() {
        assert!(power_cycle(&PowerCycleMethod::None, None).is_err());
    }
}
