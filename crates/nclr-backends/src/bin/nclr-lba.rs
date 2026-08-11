//! Standard LBA backend: probe/plan/run/status/recover
//! over the inherited device FD. Executes the L1 recipe actions.

use nclr::backend::{BackendEvents, FD_DEVICE, PROTOCOL_API};
use nclr::backend_common;
use nclr::errors::Result;
use nclr::lba::LbaDevice;
use nclr::VERSION;
use serde_json::json;
use std::os::fd::FromRawFd;

fn main() {
    let invocation = match nclr::backend::parse_backend_args() {
        Ok(i) => i,
        Err(e) => {
            eprintln!("nclr-lba: {e}");
            std::process::exit(64);
        }
    };
    let mut events = BackendEvents::open(invocation.events_fd);

    let request = match nclr::backend::read_request(invocation.request_fd) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("nclr-lba: {e}");
            std::process::exit(78);
        }
    };

    let device_fd = unsafe { std::fs::File::from_raw_fd(FD_DEVICE) };
    let is_file = match device_fd.metadata() {
        Ok(m) => m.is_file(),
        Err(e) => backend_common::respond_err(
            "lba",
            &nclr::errors::Error::io("fstat of the inherited device fd", Some(e)),
        ),
    };
    let owned: std::os::fd::OwnedFd = device_fd.into();
    let mut dev = match LbaDevice::from_fd(owned, is_file) {
        Ok(d) => d,
        Err(e) => {
            backend_common::respond_err("lba", &e);
        }
    };

    let op = invocation.op.as_str();
    let result: Result<serde_json::Value> = (|| match op {
        "probe" | "plan" => Ok(backend_common::probe_result_body(
            "lba",
            &dev,
            backend_common::lba_caps(),
            "C1",
        )),
        "run" => {
            let action = request
                .get("action")
                .and_then(|v| v.as_str())
                .ok_or_else(|| nclr::errors::Error::Usage("run requires action".into()))?;
            let seed = request.get("seed").and_then(|v| v.as_str());
            let params = request.get("params");
            let action_result =
                backend_common::dispatch_lba_action(action, seed, params, &mut dev, &mut events)?;
            Ok(json!({
                "api": PROTOCOL_API,
                "ok": true,
                "backend": "lba",
                "version": VERSION,
                "action": action,
                "action_results": [action_result],
            }))
        }
        "status" => {
            let sample = match backend_common::sample_read(&mut dev, &mut events) {
                Ok(s) => s,
                Err(e) => backend_common::respond_err("lba", &e),
            };
            Ok(json!({
                "api": PROTOCOL_API,
                "ok": true,
                "backend": "lba",
                "version": VERSION,
                "device": {
                    "capacity_bytes": dev.capacity_bytes(),
                    "logical_block_size": dev.block_size(),
                },
                "state": "ready",
                "sample": sample,
            }))
        }
        "recover" => Ok(json!({
            "api": PROTOCOL_API,
            "ok": true,
            "backend": "lba",
            "state": "ready",
            "recovery": {
                "automated": false,
                "method": "power-cycle",
                "manual": "power-cycle the device, then run nclr resume",
            },
        })),
        other => Err(nclr::errors::Error::Usage(format!(
            "unknown lba op: {other}"
        ))),
    })();

    match result {
        Ok(v) => {
            if let Err(e) = nclr::backend::write_response(&v) {
                eprintln!("nclr-lba: {e}");
                std::process::exit(74);
            }
        }
        Err(e) => {
            if op == "run" {
                backend_common::respond_action_err("lba", &e);
            }
            backend_common::respond_err("lba", &e);
        }
    }
}
