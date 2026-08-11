//! Backend exec protocol tests: FD inheritance, request passing, JSON roundtrip.

use nclr::backend::{self, BackendHandle, Request};
use std::os::fd::{AsRawFd, OwnedFd};

fn temp_backend(name: &str, script: &str) -> (BackendHandle, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(format!("nclr-{name}"));
    std::fs::write(&path, script).unwrap();
    let mut perms = std::fs::metadata(&path).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(&path, perms).unwrap();
    // A manifest declares the trust state; without one a binary outside the
    // shipped set is research-state and refused for destructive runs.
    let manifest = format!(
        "schema = 2\nid = \"{name}\"\nexec = \"nclr-{name}\"\napi = 2\ntrust = \"production\"\noperations = [\"probe\", \"plan\", \"run\", \"status\", \"recover\"]\n"
    );
    std::fs::write(dir.path().join(format!("{name}.toml")), manifest).unwrap();
    // Do not rely on the NCLR_BACKEND_DIR env var: parallel tests would race.
    let handle = backend::find(name, &[dir.path().to_path_buf()]).unwrap();
    let dir_path = dir.path().to_path_buf();
    std::mem::forget(dir);
    (handle, dir_path)
}

#[test]
fn echo_backend_receives_request_and_device_fd() {
    let script = r#"#!/bin/sh
cat <&4
"#;
    let (handle, _keepalive) = temp_backend("echo1", script);

    let dir = tempfile::tempdir().unwrap();
    let devfile = dir.path().join("dev.bin");
    std::fs::write(&devfile, b"DEVICE-DATA").unwrap();
    let f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&devfile)
        .unwrap();
    let device_fd = OwnedFd::from(f);

    let resp = backend::call(
        &handle,
        "probe",
        &device_fd,
        None,
        &Request {
            api: 2,
            op: "probe".into(),
            action: None,
            seed: None,
            device_is_file: Some(true),
            limits: None,
            params: None,
            device: None,
            extra_fds: Vec::new(),
        },
        &[],
        None,
    )
    .unwrap();
    // The echo backend copies the request JSON back, proving the request fd
    // was received intact.
    assert_eq!(resp.value["op"], "probe");
    assert_eq!(resp.value["api"], 2);
    assert_eq!(resp.value["device_is_file"], true);
}

#[test]
fn backend_rejects_invalid_json() {
    let script = "#!/bin/sh\necho 'this is not json'\n";
    let (handle, _keepalive) = temp_backend("echo2", script);
    let f = tempfile::tempfile().unwrap();
    let device_fd = OwnedFd::from(f);
    let err = backend::call(
        &handle,
        "probe",
        &device_fd,
        None,
        &Request {
            api: 2,
            op: "probe".into(),
            action: None,
            seed: None,
            device_is_file: Some(false),
            limits: None,
            params: None,
            device: None,
            extra_fds: Vec::new(),
        },
        &[],
        None,
    )
    .expect_err("expected a backend error");
    assert!(err.to_string().contains("invalid JSON"));
}

#[test]
fn extra_fds_are_inherited_at_fixed_numbers() {
    // A backend that reports fstat results for the protocol fds 3-7 proves
    // that extra fds (sg/usbfs roles) arrive at FD_EXTRA_BASE..
    let script = r#"#!/bin/sh
python3 - <<'PYEOF'
import os, json
def ok(fd):
    try:
        st = os.fstat(fd)
        return st.st_size
    except OSError:
        return None
print(json.dumps({
    "api": 2,
    "device": ok(3),
    "events": ok(5),
    "sg": ok(6),
    "usbfs": ok(7),
}))
PYEOF
"#;
    let (handle, _keepalive) = temp_backend("echoextra", script);
    let devfile = tempfile::tempfile().unwrap();
    let device_fd = OwnedFd::from(devfile);
    let sgfile = tempfile::tempfile().unwrap();
    sgfile.set_len(777).unwrap();
    let sg_fd = OwnedFd::from(sgfile);
    let resp = backend::call(
        &handle,
        "probe",
        &device_fd,
        None,
        &Request {
            api: 2,
            op: "probe".into(),
            action: None,
            seed: None,
            device_is_file: Some(true),
            limits: None,
            params: None,
            device: None,
            extra_fds: vec![nclr::backend::ExtraFd {
                fd: nclr::backend::FD_EXTRA_BASE,
                role: "sg".into(),
            }],
        },
        &[(sg_fd.as_raw_fd(), "sg".to_string())],
        None,
    )
    .unwrap();
    assert_eq!(resp.value["device"].as_i64(), Some(0), "device fd 3");
    assert_eq!(resp.value["sg"].as_i64(), Some(777), "extra sg fd 6");
    // fd 7 may legitimately hold another inherited fd; only the sg role
    // (fd 6) is asserted.
}

#[test]
fn extra_fd_declaration_must_match_inherited_roles() {
    let (handle, _keepalive) = temp_backend(
        "badextra",
        "#!/bin/sh\nprintf '%s\\n' '{\"api\":2,\"ok\":true}'\n",
    );
    let device_fd = OwnedFd::from(tempfile::tempfile().unwrap());
    let extra_fd = OwnedFd::from(tempfile::tempfile().unwrap());
    let err = backend::call(
        &handle,
        "probe",
        &device_fd,
        None,
        &Request {
            api: 2,
            op: "probe".into(),
            action: None,
            seed: None,
            device_is_file: Some(true),
            limits: None,
            params: None,
            device: None,
            extra_fds: vec![nclr::backend::ExtraFd {
                fd: nclr::backend::FD_EXTRA_BASE + 1,
                role: "sg".into(),
            }],
        },
        &[(extra_fd.as_raw_fd(), "sg".into())],
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("extra_fds declaration"));
}

#[test]
fn missing_backend_is_backend_error() {
    let err = backend::find(
        "does-not-exist",
        &[tempfile::tempdir().unwrap().path().to_path_buf()],
    )
    .unwrap_err();
    assert_eq!(err.exit_code(), 69);
}

#[test]
fn manifest_digest_mismatch_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("nclr-m1");
    std::fs::write(&bin, b"#!/bin/sh\necho hi").unwrap();
    let mut perms = std::fs::metadata(&bin).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(&bin, perms).unwrap();
    let manifest = format!(
        "schema = 2\nid = \"m1\"\nexec = \"nclr-m1\"\napi = 2\ntrust = \"production\"\noperations = [\"probe\"]\nsha256 = \"{}\"\n",
        "00".repeat(32)
    );
    std::fs::write(dir.path().join("m1.toml"), manifest).unwrap();
    let err = backend::find("m1", &[dir.path().to_path_buf()]).unwrap_err();
    assert!(err.to_string().contains("digest mismatch"));
}

#[test]
fn request_fd_is_read_only() {
    let script = r#"#!/bin/sh
python3 - <<'PYEOF'
import json, os
try:
    os.write(4, b"x")
    writable = True
except OSError:
    writable = False
print(json.dumps({"api": 2, "writable": writable}))
PYEOF
"#;
    let (handle, _keepalive) = temp_backend("readonly-request", script);
    let device_fd = OwnedFd::from(tempfile::tempfile().unwrap());
    let response = backend::call(
        &handle,
        "probe",
        &device_fd,
        None,
        &Request {
            api: 2,
            op: "probe".into(),
            action: None,
            seed: None,
            device_is_file: Some(true),
            limits: None,
            params: None,
            device: None,
            extra_fds: Vec::new(),
        },
        &[],
        None,
    )
    .unwrap();
    assert_eq!(response.value["writable"], false);
}

#[test]
fn manifest_contract_is_strictly_validated() {
    let dir = tempfile::tempdir().unwrap();
    let bin = dir.path().join("nclr-contract");
    std::fs::write(&bin, b"#!/bin/sh\necho '{\"api\":2}'\n").unwrap();
    let mut perms = std::fs::metadata(&bin).unwrap().permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(&bin, perms).unwrap();

    let manifest = "schema = 2\nid = \"contract\"\nexec = \"nclr-contract\"\napi = 1\ntrust = \"production\"\noperations = [\"probe\"]\n";
    std::fs::write(dir.path().join("contract.toml"), manifest).unwrap();
    let err = backend::find("contract", &[dir.path().to_path_buf()]).unwrap_err();
    assert!(err.to_string().contains("api must be 2"));

    let manifest = "schema = 2\nid = \"contract\"\nexec = \"nclr-contract\"\napi = 2\ntrust = \"experimental\"\noperations = [\"probe\"]\n";
    std::fs::write(dir.path().join("contract.toml"), manifest).unwrap();
    let err = backend::find("contract", &[dir.path().to_path_buf()]).unwrap_err();
    assert!(err.to_string().contains("requires production"));
}

#[test]
fn response_api_mismatch_is_rejected() {
    let script = "#!/bin/sh\necho '{\"api\":1,\"ok\":true}'\n";
    let (handle, _keepalive) = temp_backend("wrong-api", script);
    let device_fd = OwnedFd::from(tempfile::tempfile().unwrap());
    let err = backend::call(
        &handle,
        "probe",
        &device_fd,
        None,
        &Request {
            api: 2,
            op: "probe".into(),
            action: None,
            seed: None,
            device_is_file: Some(true),
            limits: None,
            params: None,
            device: None,
            extra_fds: Vec::new(),
        },
        &[],
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("response api"));
}

#[test]
fn oversized_response_is_rejected_without_unbounded_capture() {
    let script = "#!/bin/sh\nawk 'BEGIN { for (i = 0; i < 1024; i++) printf \"x\" }'\n";
    let (handle, _keepalive) = temp_backend("oversized", script);
    let device_fd = OwnedFd::from(tempfile::tempfile().unwrap());
    let err = backend::call(
        &handle,
        "probe",
        &device_fd,
        None,
        &Request {
            api: 2,
            op: "probe".into(),
            action: None,
            seed: None,
            device_is_file: Some(true),
            limits: Some(serde_json::json!({ "max_response_bytes": 64 })),
            params: None,
            device: None,
            extra_fds: Vec::new(),
        },
        &[],
        None,
    )
    .unwrap_err();
    assert!(err.to_string().contains("exceeded the 64 byte limit"));
}

#[test]
fn plan_seed_is_stable_across_actions() {
    let a = backend::plan_seed("sha256:abc");
    let b = backend::plan_seed("sha256:abc");
    assert_eq!(a, b);
}
