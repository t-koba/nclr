//! Signal handling: first SIGINT requests a safe stop at the next safe
//! boundary; a second SIGINT forces termination of the child.
//! SIGTERM triggers journal fsync on the next opportunity.

use std::sync::atomic::{AtomicU32, Ordering};

pub static SIGNAL_STATE: AtomicU32 = AtomicU32::new(0);

const STATE_CLEAN: u32 = 0;
const STATE_SAFE_STOP: u32 = 1;
const STATE_FORCE: u32 = 2;

extern "C" fn on_signal(sig: libc::c_int) {
    match sig {
        libc::SIGINT => {
            let prev = SIGNAL_STATE.fetch_add(1, Ordering::SeqCst);
            if prev >= 2 {
                SIGNAL_STATE.store(STATE_FORCE, Ordering::SeqCst);
            }
        }
        libc::SIGTERM => {
            // Request safe stop (journal fsync happens at next boundary).
            SIGNAL_STATE.store(STATE_SAFE_STOP, Ordering::SeqCst);
        }
        _ => {}
    }
}

/// Install handlers for SIGINT/SIGTERM.
pub fn install() {
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = on_signal as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
        libc::sigaction(libc::SIGTERM, &sa, std::ptr::null_mut());
    }
}

pub fn requested() -> bool {
    SIGNAL_STATE.load(Ordering::SeqCst) >= STATE_SAFE_STOP
}

pub fn forced() -> bool {
    SIGNAL_STATE.load(Ordering::SeqCst) >= STATE_FORCE
}

pub fn clear() {
    SIGNAL_STATE.store(STATE_CLEAN, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_transitions() {
        clear();
        assert!(!requested());
        SIGNAL_STATE.store(STATE_SAFE_STOP, Ordering::SeqCst);
        assert!(requested());
        assert!(!forced());
        SIGNAL_STATE.store(STATE_FORCE, Ordering::SeqCst);
        assert!(forced());
        clear();
    }
}
