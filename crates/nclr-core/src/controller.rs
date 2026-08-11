//! Controller service-mode state machine and recovery selection.
//! Pure logic, platform-independent; the vendor
//! backend drives the transitions with its ioctls, the sim backend with the
//! NAND model.

use serde::{Deserialize, Serialize};

/// Service-mode lifecycle for a controller reinitialization run.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceModeState {
    /// Normal operating mode; no service operations allowed.
    Normal,
    /// Entering service mode (in-flight; not yet confirmed).
    Entering,
    /// In service mode: physical/FTL operations are permitted.
    InService,
    /// Exiting service mode (in-flight; not yet confirmed).
    Exiting,
    /// Service mode could not be exited cleanly; recovery required.
    Stuck,
}

impl ServiceModeState {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceModeState::Normal => "normal",
            ServiceModeState::Entering => "entering",
            ServiceModeState::InService => "in-service",
            ServiceModeState::Exiting => "exiting",
            ServiceModeState::Stuck => "stuck",
        }
    }

    /// Whether the state permits destructive service operations.
    pub fn permits_service_operations(&self) -> bool {
        matches!(self, ServiceModeState::InService)
    }
}

/// Allowed transitions; anything else is a protocol error.
pub fn transition(
    state: ServiceModeState,
    event: ServiceModeEvent,
) -> Result<ServiceModeState, String> {
    use ServiceModeEvent::*;
    use ServiceModeState::*;
    let next = match (state, event) {
        (Normal, Enter) => Entering,
        (Entering, EnterConfirmed) => InService,
        (Entering, EnterFailed) => Normal,
        (InService, ExitRequested) => Exiting,
        (Exiting, ExitConfirmed) => Normal,
        (Exiting, ExitFailed) => Stuck,
        (Stuck, Recovered) => Normal,
        _ => {
            return Err(format!(
                "illegal service-mode transition {state:?} -- {event:?}"
            ));
        }
    };
    Ok(next)
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceModeEvent {
    Enter,
    EnterConfirmed,
    EnterFailed,
    ExitRequested,
    ExitConfirmed,
    ExitFailed,
    Recovered,
}

/// Recovery procedure selection for a stuck service mode
/// ("service-mode recovery").
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecoveryAction {
    /// Issue the profile's controller reset command (device stays attached).
    ControllerReset,
    /// USB reset via kernel (unbind/rebind) or external power control.
    UsbReset,
    /// Full power cycle via external control (`--power-cycle`).
    PowerCycle,
    /// Firmware bootstrap reload (profile-defined).
    FirmwareBootstrap,
    /// No automated recovery available; manual procedure required.
    Manual,
}

/// Pick the recovery procedure from the profile's declared method.
pub fn select_recovery(method: &str) -> RecoveryAction {
    match method {
        "service-mode-exit+reset" => RecoveryAction::ControllerReset,
        "usb-reset" => RecoveryAction::UsbReset,
        "power-cycle" => RecoveryAction::PowerCycle,
        "firmware-bootstrap" => RecoveryAction::FirmwareBootstrap,
        _ => RecoveryAction::Manual,
    }
}

/// Whether a recovery action can be attempted automatically (without
/// external involvement beyond `--power-cycle`).
pub fn automated(method: &str) -> bool {
    !matches!(select_recovery(method), RecoveryAction::Manual)
}

/// Re-enumeration tracking for service mode: the device
/// identity may legitimately change while in service mode; the run nonce
/// anchors the tracking so another same-model device on a different port is
/// never mistaken for ours.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub struct ReenumTrack {
    /// Nonce recorded in the journal before entering service mode.
    pub nonce: String,
    /// Allowed identity changes documented by the profile, e.g.
    /// ["service-mode-vid", "service-mode-pid"].
    pub allowed_changes: Vec<String>,
}

impl ReenumTrack {
    pub fn new(nonce: &str, allowed_changes: Vec<String>) -> ReenumTrack {
        ReenumTrack {
            nonce: nonce.to_string(),
            allowed_changes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn happy_path_lifecycle() {
        use ServiceModeEvent::*;
        use ServiceModeState::*;
        let s = transition(Normal, Enter).unwrap();
        assert_eq!(s, Entering);
        assert!(!s.permits_service_operations());
        let s = transition(s, EnterConfirmed).unwrap();
        assert_eq!(s, InService);
        assert!(s.permits_service_operations());
        let s = transition(s, ExitRequested).unwrap();
        assert_eq!(s, Exiting);
        let s = transition(s, ExitConfirmed).unwrap();
        assert_eq!(s, Normal);
        assert!(!s.permits_service_operations());
    }

    #[test]
    fn exit_failure_leads_to_stuck_then_recovery() {
        use ServiceModeEvent::*;
        use ServiceModeState::*;
        let s = transition(transition(InService, ExitRequested).unwrap(), ExitFailed).unwrap();
        assert_eq!(s, Stuck);
        let s = transition(s, Recovered).unwrap();
        assert_eq!(s, Normal);
    }

    #[test]
    fn illegal_transitions_rejected() {
        assert!(transition(ServiceModeState::Normal, ServiceModeEvent::ExitRequested).is_err());
        assert!(transition(ServiceModeState::InService, ServiceModeEvent::Enter).is_err());
    }

    #[test]
    fn recovery_selection() {
        assert_eq!(
            select_recovery("service-mode-exit+reset"),
            RecoveryAction::ControllerReset
        );
        assert_eq!(select_recovery("usb-reset"), RecoveryAction::UsbReset);
        assert_eq!(select_recovery("power-cycle"), RecoveryAction::PowerCycle);
        assert_eq!(
            select_recovery("firmware-bootstrap"),
            RecoveryAction::FirmwareBootstrap
        );
        assert_eq!(select_recovery("unknown-method"), RecoveryAction::Manual);
        assert!(automated("usb-reset"));
        assert!(!automated("unknown-method"));
    }
}
