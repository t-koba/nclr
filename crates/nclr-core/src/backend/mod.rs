//! Backend execution protocol.
//!
//! The core opens and validates the device FD, writes the request to a
//! sealed anonymous temp FD, then spawns
//! `nclr-<id> <op> --request-fd 4 --device-fd 3 [--events-fd 5]`.
//! The protocol convention fixes fd 3 = device, 4 = request, 5 = events.
//! Backends must not open any device path themselves.

use crate::errors::{Error, Result};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const FD_DEVICE: i32 = 3;
pub const FD_REQUEST: i32 = 4;
pub const FD_EVENTS: i32 = 5;
/// Additional device FDs (sg, usbfs, ...) are handed over starting at 6.
pub const FD_EXTRA_BASE: i32 = 6;
pub const PROTOCOL_API: u32 = crate::BACKEND_API;

/// An additional device fd passed to the backend.
#[derive(serde::Serialize, Clone, Debug)]
pub struct ExtraFd {
    /// Descriptor number in the child protocol namespace (6 + index).
    pub fd: i32,
    pub role: String,
}

#[derive(Debug, Clone)]
pub struct BackendHandle {
    pub id: String,
    pub path: PathBuf,
    pub version: String,
    pub trust: String,
    pub sha256: String,
    pub profile: Option<String>,
    /// Profile directory declared by the manifest.
    pub profile_dir: Option<PathBuf>,
    /// Operations declared by the manifest (or the built-in protocol set).
    pub operations: Vec<String>,
}

fn sha256_file(path: &Path) -> Result<String> {
    let data =
        std::fs::read(path).map_err(|e| Error::io(format!("read {}", path.display()), Some(e)))?;
    let mut h = Sha256::new();
    h.update(&data);
    Ok(hex::encode(h.finalize()))
}

/// Backend ids shipped with the core. A manifest-less binary with any other
/// id defaults to `research` trust and cannot perform destructive work.
const BUILTIN_BACKENDS: [&str; 5] = ["sim", "scsi", "sd-native", "lba", "controller"];
const BACKEND_OPERATIONS: [&str; 5] = ["probe", "plan", "run", "status", "recover"];
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;

fn manifest_string<'a>(manifest: &'a toml::Value, key: &str) -> Result<&'a str> {
    manifest
        .get(key)
        .and_then(|v| v.as_str())
        .ok_or_else(|| Error::Invalid(format!("backend manifest: {key} is required")))
}

fn manifest_operations(manifest: &toml::Value) -> Result<Vec<String>> {
    let values = manifest
        .get("operations")
        .and_then(|v| v.as_array())
        .ok_or_else(|| Error::Invalid("backend manifest: operations is required".into()))?;
    if values.is_empty() {
        return Err(Error::Invalid(
            "backend manifest: operations must not be empty".into(),
        ));
    }
    let mut operations = Vec::with_capacity(values.len());
    for value in values {
        let op = value.as_str().ok_or_else(|| {
            Error::Invalid("backend manifest: every operation must be a string".into())
        })?;
        if !BACKEND_OPERATIONS.contains(&op) {
            return Err(Error::Invalid(format!(
                "backend manifest: unsupported operation {op}"
            )));
        }
        if operations.iter().any(|existing| existing == op) {
            return Err(Error::Invalid(format!(
                "backend manifest: duplicate operation {op}"
            )));
        }
        operations.push(op.to_string());
    }
    Ok(operations)
}

fn is_trusted_builtin_location(bin: &Path) -> bool {
    let Ok(bin) = std::fs::canonicalize(bin) else {
        return false;
    };
    let mut trusted_dirs = vec![PathBuf::from("/usr/libexec/nclr")];
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            trusted_dirs.push(parent.to_path_buf());
            if let Some(prefix) = parent.parent() {
                trusted_dirs.push(prefix.join("libexec/nclr"));
            }
        }
    }
    trusted_dirs.into_iter().any(|dir| {
        std::fs::canonicalize(dir)
            .ok()
            .is_some_and(|trusted| bin.parent() == Some(trusted.as_path()))
    })
}

/// Directories searched for backends and manifests.
pub fn search_dirs(explicit: &[PathBuf]) -> Vec<PathBuf> {
    let mut dirs = Vec::new();
    if let Ok(env) = std::env::var("NCLR_BACKEND_DIR") {
        dirs.push(PathBuf::from(env));
    }
    dirs.extend(explicit.iter().cloned());
    dirs.push(PathBuf::from("/usr/libexec/nclr"));
    if let Ok(exe) = std::env::current_exe() {
        if let Some(parent) = exe.parent() {
            dirs.push(parent.to_path_buf());
            // Prefix-relative discovery: the installer places backends under
            // <prefix>/libexec/nclr while the binary lives in <prefix>/bin.
            if let Some(prefix_bin) = parent.parent() {
                dirs.push(prefix_bin.join("libexec/nclr"));
            }
        }
    }
    dirs
}

/// Locate a backend by id, validating its manifest when present.
pub fn find(id: &str, dirs: &[PathBuf]) -> Result<BackendHandle> {
    if id.is_empty()
        || !id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
    {
        return Err(Error::Invalid(format!("invalid backend id: {id}")));
    }
    for dir in dirs {
        let bin = dir.join(format!("nclr-{id}"));
        if !bin.is_file() {
            continue;
        }
        // Manifest is optional; when present, trust and digest are validated.
        let manifest_path = dir.join(format!("{id}.toml"));
        let (trust, sha256, profile, version, profile_dir, operations) = if manifest_path.is_file()
        {
            let m = std::fs::read_to_string(&manifest_path)
                .map_err(|e| Error::Invalid(format!("manifest read: {e}")))?;
            let toml: toml::Value =
                toml::from_str(&m).map_err(|e| Error::Invalid(format!("manifest parse: {e}")))?;
            if manifest_string(&toml, "id")? != id {
                return Err(Error::Invalid(format!(
                    "backend {id} manifest id does not match"
                )));
            }
            let expected_exec = format!("nclr-{id}");
            if manifest_string(&toml, "exec")? != expected_exec {
                return Err(Error::Invalid(format!(
                    "backend {id} manifest exec must be {expected_exec}"
                )));
            }
            if toml.get("api").and_then(|v| v.as_integer()) != Some(PROTOCOL_API as i64) {
                return Err(Error::Invalid(format!(
                    "backend {id} manifest api must be {PROTOCOL_API}"
                )));
            }
            let trust = manifest_string(&toml, "trust")?.to_string();
            if trust != "production" {
                return Err(Error::Backend(format!(
                    "backend {id} trust is {trust}; destructive execution requires production"
                )));
            }
            let operations = manifest_operations(&toml)?;
            let declared = toml
                .get("sha256")
                .and_then(|v| v.as_str())
                .map(String::from);
            let actual = sha256_file(&bin)?;
            if let Some(d) = &declared {
                if d.len() != 64 || !d.bytes().all(|b| b.is_ascii_hexdigit()) {
                    return Err(Error::Invalid(format!(
                        "backend {id} manifest sha256 must be 64 hex characters"
                    )));
                }
                if !d.eq_ignore_ascii_case(&actual) {
                    return Err(Error::Invalid(format!(
                        "backend {id} digest mismatch: manifest {d}, binary {actual}"
                    )));
                }
            }
            let profile = toml
                .get("profile")
                .and_then(|v| v.as_str())
                .map(String::from);
            let version = toml
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown")
                .to_string();
            let profile_dir = toml.get("profile_dir").and_then(|v| v.as_str()).map(|p| {
                let p = PathBuf::from(p);
                if p.is_absolute() {
                    p
                } else {
                    dir.join(p)
                }
            });
            (trust, actual, profile, version, profile_dir, operations)
        } else {
            // Builtin backends shipped with the core are production-trusted;
            // any other manifest-less binary in the search path cannot
            // claim production on its own (spec §710: trust is declared,
            // never inferred from an executable name).
            if BUILTIN_BACKENDS.contains(&id) && is_trusted_builtin_location(&bin) {
                (
                    "production".to_string(),
                    sha256_file(&bin)?,
                    None,
                    crate::VERSION.to_string(),
                    None,
                    BACKEND_OPERATIONS.iter().map(|op| op.to_string()).collect(),
                )
            } else {
                return Err(Error::Backend(format!(
                    "backend {id} has no manifest in a trusted built-in location"
                )));
            }
        };
        return Ok(BackendHandle {
            id: id.to_string(),
            path: bin,
            version,
            trust,
            sha256,
            profile,
            profile_dir,
            operations,
        });
    }
    Err(Error::Backend(format!(
        "backend nclr-{id} not found in {} (use NCLR_BACKEND_DIR or --backend-dir)",
        dirs.iter()
            .map(|d| d.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

/// Request payload shared by all backend ops.
#[derive(serde::Serialize)]
pub struct Request {
    pub api: u32,
    pub op: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_is_file: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<Value>,
    /// Action parameters (e.g. scratch-test range).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub params: Option<Value>,
    /// Core-resolved device identity. Vendor backends use USB VID only as a
    /// bounded probe hint; they still validate a controller-owned response
    /// signature before accepting the family.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<crate::device::DeviceIdentity>,
    /// Additional device fds (roles like "sg", "usbfs").
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub extra_fds: Vec<ExtraFd>,
}

/// Result of a backend call (parsed final response JSON).
#[derive(Debug)]
pub struct BackendResponse {
    pub value: Value,
}

impl BackendResponse {
    pub fn ok(&self) -> bool {
        self.value
            .get("ok")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
    }
    pub fn capabilities(&self) -> Vec<String> {
        self.value
            .get("capabilities")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn grade_ceiling(&self) -> String {
        self.value
            .get("grade_ceiling")
            .and_then(|v| v.as_str())
            .unwrap_or("C0")
            .to_string()
    }
    pub fn erase_coverage(&self) -> Vec<String> {
        self.value
            .get("erase_coverage")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn erase_method(&self) -> Option<String> {
        self.value
            .get("erase_method")
            .and_then(|v| v.as_str())
            .map(String::from)
    }
    pub fn rebuilds(&self) -> Vec<String> {
        self.value
            .get("rebuilds")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn controller_profile(&self) -> Option<String> {
        self.value
            .get("controller_profile")
            .and_then(|v| v.as_str())
            .map(String::from)
    }
    pub fn profile_sha256(&self) -> Option<String> {
        self.value
            .get("profile_sha256")
            .and_then(|v| v.as_str())
            .map(String::from)
    }
    pub fn artifacts(&self) -> Result<Vec<crate::artifact::ArtifactSpec>> {
        let Some(value) = self.value.get("artifacts") else {
            return Ok(Vec::new());
        };
        let artifacts: Vec<crate::artifact::ArtifactSpec> =
            serde_json::from_value(value.clone())
                .map_err(|e| Error::Invalid(format!("backend artifact declaration: {e}")))?;
        for artifact in &artifacts {
            crate::artifact::validate_spec(artifact)?;
        }
        Ok(artifacts)
    }
    pub fn capacity_policy(&self) -> Option<Value> {
        self.value.get("capacity_policy").cloned()
    }
    /// Protected Area (D5) size reported by the device, if any.
    pub fn protected_area_bytes(&self) -> u64 {
        self.value
            .get("protected_area_bytes")
            .and_then(|v| v.as_u64())
            .unwrap_or(0)
    }
    /// Whether the family holds a certified physical-scope (C4) validation.
    pub fn physical_certified(&self) -> bool {
        self.value
            .get("certification")
            .and_then(|v| v.as_str())
            .map(|c| c.eq_ignore_ascii_case("C4"))
            .unwrap_or(false)
    }
    pub fn message(&self) -> String {
        self.value
            .get("error")
            .and_then(|v| v.as_str())
            .unwrap_or("backend error")
            .to_string()
    }
}

/// Spawn the backend with the inherited FDs dup2'd onto the protocol fd
/// numbers. Returns the child with stdout captured.
fn spawn_backend(
    handle: &BackendHandle,
    op: &str,
    device_fd: &OwnedFd,
    request_fd: &OwnedFd,
    events_fd: Option<&OwnedFd>,
    extra_fds: &[(i32, String)],
) -> Result<std::process::Child> {
    let mut cmd = Command::new(&handle.path);
    cmd.arg(op)
        .arg("--request-fd")
        .arg(FD_REQUEST.to_string())
        .arg("--device-fd")
        .arg(FD_DEVICE.to_string());
    if events_fd.is_some() {
        cmd.arg("--events-fd").arg(FD_EVENTS.to_string());
    }
    cmd.stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());

    let dev = device_fd.as_raw_fd();
    let req = request_fd.as_raw_fd();
    let ev = events_fd.map(|f| f.as_raw_fd());
    // Extra fds land on FD_EXTRA_BASE.. (roles are described in the request).
    let extra: Vec<(i32, i32)> = extra_fds
        .iter()
        .enumerate()
        .map(|(i, (fd, _))| (*fd, FD_EXTRA_BASE + i as i32))
        .collect();

    use std::os::unix::process::CommandExt;
    unsafe {
        cmd.pre_exec(move || {
            let mut targets: Vec<(i32, i32)> = vec![(dev, FD_DEVICE), (req, FD_REQUEST)];
            if let Some(ev) = ev {
                targets.push((ev, FD_EVENTS));
            }
            targets.extend(extra.iter().cloned());
            // Sources may collide with the protocol dst numbers (e.g. the
            // request fd may already be 3). Stage every source to a high fd
            // first so no dup2 clobbers a source that is still needed.
            let mut staged: Vec<i32> = Vec::new();
            for (src, dst) in &targets {
                if *src < 0 {
                    continue;
                }
                // dup2(fd, fd) is a no-op that does NOT clear FD_CLOEXEC, and
                // our fds are opened with CLOEXEC. Clear it explicitly.
                if libc::fcntl(*src, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if *src != *dst {
                    let t = libc::fcntl(*src, libc::F_DUPFD, 10);
                    if t < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    staged.push(t);
                } else {
                    staged.push(-1);
                }
            }
            let mut staged_iter = staged.iter();
            for (src, dst) in &targets {
                if *src < 0 {
                    continue;
                }
                let from = match staged_iter.next() {
                    Some(-1) | None => *src,
                    Some(t) => *t,
                };
                if libc::dup2(from, *dst) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            for t in &staged {
                if *t >= 0 {
                    libc::close(*t);
                }
            }
            #[cfg(target_os = "linux")]
            {
                // Sandbox: no new privileges, no core dumps.
                libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                let rl = libc::rlimit {
                    rlim_cur: 0,
                    rlim_max: 0,
                };
                libc::setrlimit(libc::RLIMIT_CORE, &rl);
            }
            Ok(())
        });
    }

    cmd.spawn()
        .map_err(|e| Error::Backend(format!("cannot spawn {}: {e}", handle.path.display())))
}

/// Invoke a backend op once. `device_fd` is the pre-opened, validated FD;
/// `extra_fds` holds additional inherited device fds (sg, usbfs, ...).
pub fn call(
    handle: &BackendHandle,
    op: &str,
    device_fd: &OwnedFd,
    events_fd: Option<&OwnedFd>,
    request: &Request,
    extra_fds: &[(i32, String)],
    timeout_secs: Option<u64>,
) -> Result<BackendResponse> {
    if request.api != PROTOCOL_API || request.op != op {
        return Err(Error::Invalid(format!(
            "backend request envelope mismatch: api {}, op {} (expected api {PROTOCOL_API}, op {op})",
            request.api, request.op
        )));
    }
    if !handle.operations.iter().any(|declared| declared == op) {
        return Err(Error::Backend(format!(
            "backend {} manifest does not declare operation {op}",
            handle.id
        )));
    }
    if request.extra_fds.len() != extra_fds.len()
        || request
            .extra_fds
            .iter()
            .zip(extra_fds)
            .enumerate()
            .any(|(i, (declared, (_, role)))| {
                declared.fd != FD_EXTRA_BASE + i as i32 || declared.role != *role
            })
    {
        return Err(Error::Invalid(
            "backend extra_fds declaration does not match inherited descriptors".into(),
        ));
    }

    // Materialize the request, reopen it read-only, then unlink the name.
    // The child therefore receives a read-only request fd and cannot mutate
    // the request seen by the core or another backend invocation.
    let mut named = tempfile::NamedTempFile::new()
        .map_err(|e| Error::Backend(format!("cannot create request fd: {e}")))?;
    {
        use std::io::Write;
        let req_json = serde_json::to_vec(request)
            .map_err(|e| Error::Invalid(format!("request serialization: {e}")))?;
        named
            .write_all(&req_json)
            .map_err(|e| Error::Backend(format!("cannot write request fd: {e}")))?;
        named
            .flush()
            .map_err(|e| Error::Backend(format!("cannot flush request fd: {e}")))?;
    }
    let req_file = std::fs::File::open(named.path())
        .map_err(|e| Error::Backend(format!("cannot reopen request fd read-only: {e}")))?;
    named
        .close()
        .map_err(|e| Error::Backend(format!("cannot unlink request file: {e}")))?;
    let req_fd = OwnedFd::from(req_file);
    if std::env::var("NCLR_BACKEND_DEBUG").as_deref() == Ok("1") {
        eprintln!(
            "nclr-core: op={op} request_fd={} device_fd={} events={:?}",
            req_fd.as_raw_fd(),
            device_fd.as_raw_fd(),
            events_fd.map(|f| f.as_raw_fd())
        );
        let encoded = serde_json::to_vec(request)
            .map_err(|e| Error::Invalid(format!("request serialization: {e}")))?;
        eprintln!("nclr-core: request={}", String::from_utf8_lossy(&encoded));
    }

    let mut child = spawn_backend(handle, op, device_fd, &req_fd, events_fd, extra_fds)?;

    // The request fd is handed over; close our copy once the child exists so
    // the child sees EOF when done reading (fd 4 in the child is a dup).
    drop(req_fd);

    // Read the child stdout on a helper thread so the main thread can
    // enforce a deadline. On expiry the child
    // is killed and the call returns an `Interrupted` (resumable) error:
    // nothing is ever resent without a device status query.
    use std::io::Read;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Backend("backend stdout was not captured".into()))?;
    let response_limit = request
        .limits
        .as_ref()
        .and_then(|v| v.get("max_response_bytes"))
        .and_then(|v| v.as_u64())
        .and_then(|v| usize::try_from(v).ok())
        .unwrap_or(MAX_RESPONSE_BYTES)
        .clamp(1, MAX_RESPONSE_BYTES);
    let (tx, rx) = std::sync::mpsc::channel::<std::io::Result<(Vec<u8>, bool)>>();
    let reader = std::thread::spawn(move || {
        let mut stdout = stdout;
        let mut captured = Vec::new();
        let mut chunk = [0u8; 8192];
        let mut oversized = false;
        let result = loop {
            match stdout.read(&mut chunk) {
                Ok(0) => break Ok((captured, oversized)),
                Ok(n) => {
                    let remaining = response_limit.saturating_sub(captured.len());
                    captured.extend_from_slice(&chunk[..n.min(remaining)]);
                    oversized |= n > remaining;
                }
                Err(e) => break Err(e),
            }
        };
        let _ = tx.send(result);
    });

    let deadline =
        timeout_secs.map(|s| std::time::Instant::now() + std::time::Duration::from_secs(s));
    let status = loop {
        if let Some(st) = child
            .try_wait()
            .map_err(|e| Error::Backend(format!("wait backend: {e}")))?
        {
            break st;
        }
        if let Some(d) = deadline {
            if std::time::Instant::now() >= d {
                let _ = child.kill();
                let _ = child.wait();
                let _ = rx.recv();
                let _ = reader.join();
                return Err(Error::Interrupted(format!(
                    "backend {} exceeded the {}s timeout; the device status must be re-queried before continuing",
                    handle.id, timeout_secs.unwrap_or(0)
                )));
            }
        }
        std::thread::sleep(std::time::Duration::from_millis(100));
    };
    let (stdout, oversized) = rx
        .recv()
        .map_err(|e| Error::Backend(format!("backend stdout thread: {e}")))?
        .map_err(|e| Error::Backend(format!("read backend stdout: {e}")))?;
    let _ = reader.join();
    if oversized {
        return Err(Error::Backend(format!(
            "backend {} response exceeded the {} byte limit",
            handle.id, response_limit
        )));
    }
    let stdout = String::from_utf8(stdout).map_err(|e| {
        Error::Backend(format!(
            "backend {} response is not valid UTF-8: {e}",
            handle.id
        ))
    })?;

    let value: Value = serde_json::from_str(stdout.trim())
        .map_err(|e| Error::Backend(format!("backend {} produced invalid JSON: {e}", handle.id)))?;
    if !status.success() {
        return Err(Error::Backend(format!(
            "backend {} exited with {status}",
            handle.id
        )));
    }
    if value.get("api").and_then(|v| v.as_u64()) != Some(PROTOCOL_API as u64) {
        return Err(Error::Backend(format!(
            "backend {} response api does not match {PROTOCOL_API}",
            handle.id
        )));
    }
    if let Some(reported) = value.get("backend").and_then(|v| v.as_str()) {
        if reported != handle.id {
            return Err(Error::Backend(format!(
                "backend identity mismatch: executed {}, response reports {reported}",
                handle.id
            )));
        }
    }
    Ok(BackendResponse { value })
}

/// Derive the PRBS seed from the plan hash. The same seed is used for both
/// the write and the verify action so the regenerated stream matches.
pub fn plan_seed(plan_hash: &str) -> String {
    format!("nclr-prbs:{plan_hash}")
}

/// Parsed invocation arguments for a backend process.
pub struct BackendInvocation {
    pub op: String,
    pub request_fd: i32,
    pub device_fd: i32,
    pub events_fd: Option<i32>,
}

/// Parse backend CLI args: `<op> --request-fd N --device-fd M [--events-fd K]`.
pub fn parse_backend_args() -> Result<BackendInvocation> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut op = None;
    let mut request_fd = None;
    let mut device_fd = None;
    let mut events_fd = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--request-fd" => {
                i += 1;
                request_fd = args.get(i).and_then(|s| s.parse().ok());
            }
            "--device-fd" => {
                i += 1;
                device_fd = args.get(i).and_then(|s| s.parse().ok());
            }
            "--events-fd" => {
                i += 1;
                events_fd = args.get(i).and_then(|s| s.parse().ok());
            }
            other => {
                if op.is_none() {
                    op = Some(other.to_string());
                } else {
                    return Err(Error::Usage(format!("unexpected backend arg: {other}")));
                }
            }
        }
        i += 1;
    }
    let op = op.ok_or_else(|| Error::Usage("missing backend op".into()))?;
    let request_fd = request_fd.ok_or_else(|| Error::Usage("missing --request-fd".into()))?;
    let device_fd = device_fd.ok_or_else(|| Error::Usage("missing --device-fd".into()))?;
    Ok(BackendInvocation {
        op,
        request_fd,
        device_fd,
        events_fd,
    })
}

/// Read the request JSON from the request fd (until EOF).
pub fn read_request(fd: i32) -> Result<Value> {
    use std::io::Read;
    let file = unsafe { std::fs::File::from_raw_fd(fd) };
    let mut s = String::new();
    (&file)
        .read_to_string(&mut s)
        .map_err(|e| Error::Backend(format!("cannot read request: {e}")))?;
    if std::env::var("NCLR_BACKEND_DEBUG").as_deref() == Ok("1") {
        eprintln!(
            "nclr-sim: request bytes ({}): {:?}",
            s.len(),
            s.chars().take(90).collect::<String>()
        );
    }
    serde_json::from_str(&s).map_err(|e| Error::Invalid(format!("backend request parse: {e}")))
}

/// Write the final response JSON to stdout.
pub fn write_response(value: &Value) -> Result<()> {
    let mut s = serde_json::to_string(value)
        .map_err(|e| Error::Invalid(format!("response serialization: {e}")))?;
    s.push('\n');
    use std::io::Write;
    let mut out = std::io::stdout().lock();
    out.write_all(s.as_bytes())
        .map_err(|e| Error::io("write response", Some(e)))
}

/// NDJSON event output for backend progress (fd 5, optional).
pub struct BackendEvents {
    file: Option<std::fs::File>,
    seq: u64,
}

impl BackendEvents {
    pub fn open(fd: Option<i32>) -> BackendEvents {
        let file = fd.map(|n| unsafe { std::fs::File::from_raw_fd(n) });
        BackendEvents { file, seq: 0 }
    }

    pub fn progress(
        &mut self,
        phase: &str,
        done: u64,
        total: u64,
        unit: &str,
    ) -> crate::errors::Result<()> {
        use std::io::Write;
        if let Some(f) = &mut self.file {
            let ev = serde_json::json!({
                "seq": self.seq,
                "phase": phase,
                "done": done,
                "total": total,
                "unit": unit,
            });
            self.seq += 1;
            let mut line = serde_json::to_vec(&ev)
                .map_err(|e| Error::Invalid(format!("event serialization: {e}")))?;
            line.push(b'\n');
            f.write_all(&line)
                .map_err(|e| Error::io("event fd write", Some(e)))?;
        }
        Ok(())
    }

    pub fn note(&mut self, phase: &str, message: &str) -> crate::errors::Result<()> {
        use std::io::Write;
        if let Some(f) = &mut self.file {
            let ev = serde_json::json!({
                "seq": self.seq,
                "phase": phase,
                "message": message,
            });
            self.seq += 1;
            let mut line = serde_json::to_vec(&ev)
                .map_err(|e| Error::Invalid(format!("event serialization: {e}")))?;
            line.push(b'\n');
            f.write_all(&line)
                .map_err(|e| Error::io("event fd write", Some(e)))?;
        }
        Ok(())
    }
}
