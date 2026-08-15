//! Backend execution protocol.
//!
//! The core opens and validates the device FD, writes the request to a
//! sealed anonymous temp FD, then spawns
//! `nclr-<id> <op> --request-fd 4 --device-fd 3 [--events-fd 5]`.
//! The protocol convention fixes fd 3 = device, 4 = request, 5 = events.
//! Backends must not open a device node themselves. The macOS controller
//! backend may resolve the inherited whole-disk descriptor to its IOKit
//! SCSITask service, while all block descriptors remain core-owned.

use crate::errors::{Error, Result};
use serde::Deserialize;
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

const MAX_BACKEND_BYTES: u64 = 1024 * 1024 * 1024;

fn sha256_file(path: &Path) -> Result<String> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|error| Error::io(format!("open backend {}", path.display()), Some(error)))?;
    let metadata = file
        .metadata()
        .map_err(|error| Error::io(format!("stat backend {}", path.display()), Some(error)))?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_BACKEND_BYTES {
        return Err(Error::Invalid(format!(
            "backend {} must be a non-empty regular file no larger than {MAX_BACKEND_BYTES} bytes",
            path.display()
        )));
    }
    use std::io::Read;
    let mut h = Sha256::new();
    let mut reader = file.take(MAX_BACKEND_BYTES + 1);
    let mut buffer = [0u8; 64 * 1024];
    let mut total = 0u64;
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| Error::io(format!("read backend {}", path.display()), Some(error)))?;
        if read == 0 {
            break;
        }
        total = total.saturating_add(read as u64);
        if total > MAX_BACKEND_BYTES {
            return Err(Error::Invalid(format!(
                "backend {} grew beyond {MAX_BACKEND_BYTES} bytes while reading",
                path.display()
            )));
        }
        h.update(&buffer[..read]);
    }
    Ok(hex::encode(h.finalize()))
}

/// Backend ids shipped with the core. A manifest-less binary with any other
/// id defaults to `research` trust and cannot perform destructive work.
const BUILTIN_BACKENDS: [&str; 5] = ["sim", "scsi", "sd-native", "lba", "controller"];
const BACKEND_OPERATIONS: [&str; 5] = ["probe", "plan", "run", "status", "recover"];
const MAX_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_RESPONSE_LIST_ITEMS: usize = 4096;
const MAX_RESPONSE_STRING_BYTES: usize = 256;
const MAX_RESPONSE_MESSAGE_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BackendManifest {
    schema: u32,
    id: String,
    exec: String,
    api: u32,
    version: String,
    trust: String,
    operations: Vec<String>,
    sha256: String,
    #[serde(default)]
    profile: Option<String>,
    #[serde(default)]
    profile_dir: Option<PathBuf>,
}

fn load_manifest(path: &Path) -> Result<BackendManifest> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options
        .open(path)
        .map_err(|error| Error::io(format!("open manifest {}", path.display()), Some(error)))?;
    let metadata = file
        .metadata()
        .map_err(|error| Error::io(format!("stat manifest {}", path.display()), Some(error)))?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(Error::Invalid(format!(
            "backend manifest {} must be a regular file no larger than {MAX_MANIFEST_BYTES} bytes",
            path.display()
        )));
    }
    use std::io::Read;
    let mut raw = Vec::with_capacity(metadata.len() as usize);
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|error| Error::io(format!("read manifest {}", path.display()), Some(error)))?;
    if raw.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(Error::Invalid(format!(
            "backend manifest {} grew beyond {MAX_MANIFEST_BYTES} bytes while reading",
            path.display()
        )));
    }
    let source = String::from_utf8(raw).map_err(|error| {
        Error::Invalid(format!(
            "backend manifest {} is not UTF-8: {error}",
            path.display()
        ))
    })?;
    let manifest: BackendManifest = toml::from_str(&source)
        .map_err(|error| Error::Invalid(format!("backend manifest {}: {error}", path.display())))?;
    if manifest.schema != 1 {
        return Err(Error::Invalid(format!(
            "backend manifest {} schema {} != 1",
            path.display(),
            manifest.schema
        )));
    }
    Ok(manifest)
}

fn manifest_operations(values: &[String]) -> Result<Vec<String>> {
    if values.is_empty() {
        return Err(Error::Invalid(
            "backend manifest: operations must not be empty".into(),
        ));
    }
    let mut operations = Vec::with_capacity(values.len());
    for value in values {
        let op = value.as_str();
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
            let manifest = load_manifest(&manifest_path)?;
            if manifest.id != id {
                return Err(Error::Invalid(format!(
                    "backend {id} manifest id does not match"
                )));
            }
            let expected_exec = format!("nclr-{id}");
            if manifest.exec != expected_exec {
                return Err(Error::Invalid(format!(
                    "backend {id} manifest exec must be {expected_exec}"
                )));
            }
            if manifest.api != PROTOCOL_API {
                return Err(Error::Invalid(format!(
                    "backend {id} manifest api must be {PROTOCOL_API}"
                )));
            }
            let trust = manifest.trust;
            if trust != "production" {
                return Err(Error::Backend(format!(
                    "backend {id} trust is {trust}; destructive execution requires production"
                )));
            }
            let operations = manifest_operations(&manifest.operations)?;
            let declared = manifest.sha256;
            let actual = sha256_file(&bin)?;
            if declared.len() != 64 || !declared.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Error::Invalid(format!(
                    "backend {id} manifest sha256 must be 64 hex characters"
                )));
            }
            if !declared.eq_ignore_ascii_case(&actual) {
                return Err(Error::Invalid(format!(
                    "backend {id} digest mismatch: manifest {declared}, binary {actual}"
                )));
            }
            let profile = manifest.profile;
            let version = manifest.version;
            if version.is_empty()
                || version.len() > 128
                || !version.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(Error::Invalid(format!(
                    "backend {id} manifest version is invalid"
                )));
            }
            let profile_dir =
                manifest
                    .profile_dir
                    .map(|p| if p.is_absolute() { p } else { dir.join(p) });
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
            .get("physical_certified")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || self
                .value
                .get("certification")
                .and_then(|v| v.as_str())
                .map(|c| c.eq_ignore_ascii_case("C4"))
                .unwrap_or(false)
    }
    pub fn message(&self) -> String {
        self.value
            .get("error")
            .and_then(|v| v.as_str())
            .or_else(|| {
                self.value
                    .get("action_results")
                    .and_then(Value::as_array)
                    .and_then(|results| results.first())
                    .and_then(|result| result.get("message"))
                    .and_then(Value::as_str)
            })
            .unwrap_or("backend error")
            .to_string()
    }
}

fn response_protocol_error(backend: &str, message: impl std::fmt::Display) -> Error {
    Error::io(
        format!("backend {backend} response protocol: {message}"),
        None,
    )
}

fn validate_response_string<'a>(backend: &str, field: &str, value: &'a Value) -> Result<&'a str> {
    let text = value
        .as_str()
        .ok_or_else(|| response_protocol_error(backend, format!("{field} must be a string")))?;
    if text.is_empty()
        || text.len() > MAX_RESPONSE_STRING_BYTES
        || !text.bytes().all(|byte| byte.is_ascii_graphic())
    {
        return Err(response_protocol_error(
            backend,
            format!("{field} must be non-empty printable ASCII no longer than {MAX_RESPONSE_STRING_BYTES} bytes"),
        ));
    }
    Ok(text)
}

fn validate_response_string_list(
    backend: &str,
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<()> {
    let values = object
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| response_protocol_error(backend, format!("{field} must be an array")))?;
    if values.len() > MAX_RESPONSE_LIST_ITEMS {
        return Err(response_protocol_error(
            backend,
            format!("{field} exceeds {MAX_RESPONSE_LIST_ITEMS} entries"),
        ));
    }
    let mut seen = std::collections::HashSet::with_capacity(values.len());
    for value in values {
        let item = validate_response_string(backend, field, value)?;
        if !seen.insert(item) {
            return Err(response_protocol_error(
                backend,
                format!("{field} contains duplicate value {item}"),
            ));
        }
    }
    Ok(())
}

fn validate_optional_response_string(
    backend: &str,
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<()> {
    match object.get(field) {
        Some(Value::Null) => Ok(()),
        Some(value) => validate_response_string(backend, field, value).map(|_| ()),
        None => Err(response_protocol_error(backend, format!("missing {field}"))),
    }
}

fn validate_optional_response_message(
    backend: &str,
    object: &serde_json::Map<String, Value>,
    field: &str,
) -> Result<()> {
    let Some(value) = object.get(field) else {
        return Ok(());
    };
    if value.is_null() {
        return Ok(());
    }
    let message = value.as_str().ok_or_else(|| {
        response_protocol_error(backend, format!("{field} must be a string when present"))
    })?;
    if message.len() > MAX_RESPONSE_MESSAGE_BYTES
        || message
            .chars()
            .any(|character| character == '\0' || character.is_control())
    {
        return Err(response_protocol_error(
            backend,
            format!(
                "{field} must contain no control characters and be no longer than {MAX_RESPONSE_MESSAGE_BYTES} bytes"
            ),
        ));
    }
    Ok(())
}

fn validate_probe_response(backend: &str, object: &serde_json::Map<String, Value>) -> Result<()> {
    validate_response_string_list(backend, object, "capabilities")?;
    validate_response_string_list(backend, object, "erase_coverage")?;
    validate_response_string_list(backend, object, "rebuilds")?;

    let grade = object
        .get("grade_ceiling")
        .ok_or_else(|| response_protocol_error(backend, "missing grade_ceiling"))?;
    let grade = validate_response_string(backend, "grade_ceiling", grade)?;
    if !matches!(grade, "C0" | "C1" | "C2" | "C3" | "C4") {
        return Err(response_protocol_error(
            backend,
            format!("invalid grade_ceiling {grade}"),
        ));
    }

    let coverage = object["erase_coverage"]
        .as_array()
        .expect("validated array");
    for value in coverage {
        let domain = value.as_str().expect("validated string");
        if !matches!(domain, "D0" | "D1" | "D2" | "D3" | "D4" | "D5") {
            return Err(response_protocol_error(
                backend,
                format!("invalid erase_coverage domain {domain}"),
            ));
        }
    }

    validate_optional_response_string(backend, object, "erase_method")?;
    validate_optional_response_string(backend, object, "controller_profile")?;
    validate_optional_response_string(backend, object, "certification")?;

    match object.get("profile_sha256") {
        Some(Value::Null) => {}
        Some(value) => {
            let digest = validate_response_string(backend, "profile_sha256", value)?;
            if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                return Err(response_protocol_error(
                    backend,
                    "profile_sha256 must be 64 hexadecimal characters",
                ));
            }
        }
        None => {
            return Err(response_protocol_error(backend, "missing profile_sha256"));
        }
    }

    match object.get("capacity_policy") {
        Some(Value::Null) => {}
        Some(value @ Value::Object(_)) => {
            let policy: crate::profile::CapacityPolicy = serde_json::from_value(value.clone())
                .map_err(|error| {
                    response_protocol_error(backend, format!("capacity_policy is invalid: {error}"))
                })?;
            crate::profile::validate_capacity_policy(&policy).map_err(|error| {
                response_protocol_error(backend, format!("capacity_policy is invalid: {error}"))
            })?;
        }
        _ => {
            return Err(response_protocol_error(
                backend,
                "capacity_policy must be an object or null",
            ));
        }
    }
    if object
        .get("protected_area_bytes")
        .and_then(Value::as_u64)
        .is_none()
    {
        return Err(response_protocol_error(
            backend,
            "protected_area_bytes must be an unsigned integer",
        ));
    }
    if !matches!(object.get("artifacts"), Some(Value::Array(_))) {
        return Err(response_protocol_error(
            backend,
            "artifacts must be an array",
        ));
    }
    if object
        .get("artifacts")
        .and_then(Value::as_array)
        .is_some_and(|values| values.len() > MAX_RESPONSE_LIST_ITEMS)
    {
        return Err(response_protocol_error(
            backend,
            format!("artifacts exceeds {MAX_RESPONSE_LIST_ITEMS} entries"),
        ));
    }
    let response = BackendResponse {
        value: Value::Object(object.clone()),
    };
    response.artifacts().map_err(|error| {
        response_protocol_error(backend, format!("invalid artifacts declaration: {error}"))
    })?;
    if let Some(value) = object.get("physical_certified") {
        if !value.is_boolean() {
            return Err(response_protocol_error(
                backend,
                "physical_certified must be a boolean",
            ));
        }
    }
    Ok(())
}

fn validate_run_response(
    backend: &str,
    object: &serde_json::Map<String, Value>,
    expected_action: &str,
    ok: bool,
) -> Result<()> {
    match object.get("action") {
        Some(value) => {
            let reported = validate_response_string(backend, "action", value)?;
            if reported != expected_action {
                return Err(response_protocol_error(
                    backend,
                    format!(
                        "action mismatch: requested {expected_action}, response reports {reported}"
                    ),
                ));
            }
        }
        None if ok => {
            return Err(response_protocol_error(
                backend,
                "successful run response is missing action",
            ));
        }
        None => {}
    }

    let results = object
        .get("action_results")
        .and_then(Value::as_array)
        .ok_or_else(|| response_protocol_error(backend, "action_results must be an array"))?;
    if results.len() != 1 {
        return Err(response_protocol_error(
            backend,
            "action_results must contain exactly one result",
        ));
    }
    let result = results[0].as_object().ok_or_else(|| {
        response_protocol_error(backend, "action_results entry must be an object")
    })?;
    let status = result
        .get("status")
        .ok_or_else(|| response_protocol_error(backend, "action result is missing status"))?;
    let status = validate_response_string(backend, "action result status", status)?;
    if !matches!(status, "ok" | "error" | "interrupted" | "partial" | "found") {
        return Err(response_protocol_error(
            backend,
            format!("invalid action result status {status}"),
        ));
    }
    for field in ["errors", "duration_ms"] {
        if result
            .get(field)
            .is_some_and(|value| !value.is_null() && value.as_u64().is_none())
        {
            return Err(response_protocol_error(
                backend,
                format!("action result {field} must be an unsigned integer when present"),
            ));
        }
    }
    for field in ["started", "completed"] {
        if result
            .get(field)
            .is_some_and(|value| !value.is_null() && !value.is_boolean())
        {
            return Err(response_protocol_error(
                backend,
                format!("action result {field} must be a boolean when present"),
            ));
        }
    }
    validate_optional_response_message(backend, result, "message")?;
    Ok(())
}

fn validate_status_response(backend: &str, object: &serde_json::Map<String, Value>) -> Result<()> {
    let state = object
        .get("state")
        .ok_or_else(|| response_protocol_error(backend, "status response is missing state"))?;
    let state = validate_response_string(backend, "state", state)?;
    if !matches!(state, "ready" | "in-progress" | "failed") {
        return Err(response_protocol_error(
            backend,
            format!("invalid device state {state}"),
        ));
    }

    let Some(sanitize) = object.get("sanitize") else {
        return Ok(());
    };
    let sanitize = sanitize
        .as_object()
        .ok_or_else(|| response_protocol_error(backend, "sanitize must be an object"))?;
    let completed = sanitize
        .get("completed")
        .and_then(Value::as_bool)
        .ok_or_else(|| response_protocol_error(backend, "sanitize.completed must be a boolean"))?;
    let failed = sanitize
        .get("failed")
        .and_then(Value::as_bool)
        .ok_or_else(|| response_protocol_error(backend, "sanitize.failed must be a boolean"))?;
    if completed && failed {
        return Err(response_protocol_error(
            backend,
            "sanitize cannot be both completed and failed",
        ));
    }
    let progress = sanitize
        .get("progress")
        .and_then(Value::as_u64)
        .ok_or_else(|| {
            response_protocol_error(backend, "sanitize.progress must be an unsigned integer")
        })?;
    if progress > 1000 {
        return Err(response_protocol_error(
            backend,
            "sanitize.progress exceeds 1000",
        ));
    }
    if sanitize
        .get("started")
        .is_some_and(|value| !value.is_boolean())
    {
        return Err(response_protocol_error(
            backend,
            "sanitize.started must be a boolean when present",
        ));
    }
    Ok(())
}

fn validate_backend_response(
    handle: &BackendHandle,
    op: &str,
    expected_action: Option<&str>,
    value: &Value,
) -> Result<()> {
    let object = value
        .as_object()
        .ok_or_else(|| response_protocol_error(&handle.id, "top-level value must be an object"))?;
    if object.get("api").and_then(Value::as_u64) != Some(PROTOCOL_API as u64) {
        return Err(response_protocol_error(
            &handle.id,
            format!("api does not match {PROTOCOL_API}"),
        ));
    }
    let ok = object
        .get("ok")
        .and_then(Value::as_bool)
        .ok_or_else(|| response_protocol_error(&handle.id, "ok must be a boolean"))?;
    let reported = object
        .get("backend")
        .ok_or_else(|| response_protocol_error(&handle.id, "missing backend"))?;
    let reported = validate_response_string(&handle.id, "backend", reported)?;
    if reported != handle.id {
        return Err(response_protocol_error(
            &handle.id,
            format!("identity mismatch: response reports {reported}"),
        ));
    }
    let version = object
        .get("version")
        .ok_or_else(|| response_protocol_error(&handle.id, "missing version"))?;
    let version = validate_response_string(&handle.id, "version", version)?;
    if version != handle.version {
        return Err(response_protocol_error(
            &handle.id,
            format!(
                "version mismatch: manifest declares {}, response reports {version}",
                handle.version
            ),
        ));
    }
    validate_optional_response_message(&handle.id, object, "error")?;

    if ok && matches!(op, "probe" | "plan") {
        validate_probe_response(&handle.id, object)?;
    }
    if op == "run" {
        let expected_action = expected_action
            .ok_or_else(|| Error::Invalid("run request must declare exactly one action".into()))?;
        validate_run_response(&handle.id, object, expected_action, ok)?;
    }
    if op == "status" {
        validate_status_response(&handle.id, object)?;
    }
    if !ok
        && object.get("error").and_then(Value::as_str).is_none()
        && object
            .get("action_results")
            .and_then(Value::as_array)
            .is_none()
        && object.get("state").and_then(Value::as_str) != Some("failed")
    {
        return Err(response_protocol_error(
            &handle.id,
            "ok=false requires error, action_results, or state=failed",
        ));
    }
    Ok(())
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
    let current_digest = sha256_file(&handle.path)?;
    if !current_digest.eq_ignore_ascii_case(&handle.sha256) {
        return Err(Error::Invalid(format!(
            "backend {} changed after it was selected",
            handle.id
        )));
    }
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
                if *src != *dst {
                    let t = libc::fcntl(*src, libc::F_DUPFD_CLOEXEC, 10);
                    if t < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    // The staged descriptor is used only until dup2 below.
                    // Keep the original source closed across exec so the
                    // backend receives only the documented protocol fds.
                    if libc::fcntl(*src, libc::F_SETFD, libc::FD_CLOEXEC) < 0 {
                        libc::close(t);
                        return Err(std::io::Error::last_os_error());
                    }
                    staged.push(t);
                } else {
                    // dup2(fd, fd) is a no-op and does not clear CLOEXEC.
                    if libc::fcntl(*src, libc::F_SETFD, 0) < 0 {
                        return Err(std::io::Error::last_os_error());
                    }
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
    if op == "run" {
        let action = request
            .action
            .as_deref()
            .ok_or_else(|| Error::Invalid("run request must declare exactly one action".into()))?;
        if action.is_empty()
            || action.len() > MAX_RESPONSE_STRING_BYTES
            || !action.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(Error::Invalid(
                "run request action must be non-empty printable ASCII".into(),
            ));
        }
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
        return Err(response_protocol_error(
            &handle.id,
            format!("exceeded the {response_limit} byte limit"),
        ));
    }
    let stdout = String::from_utf8(stdout)
        .map_err(|e| response_protocol_error(&handle.id, format!("is not valid UTF-8: {e}")))?;

    let value: Value = serde_json::from_str(stdout.trim())
        .map_err(|e| response_protocol_error(&handle.id, format!("is invalid JSON: {e}")))?;
    if !status.success() {
        return Err(Error::Backend(format!(
            "backend {} exited with {status}",
            handle.id
        )));
    }
    validate_backend_response(handle, op, request.action.as_deref(), &value)?;
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

    pub fn heartbeat(
        &mut self,
        phase: &str,
        progress: u64,
        unit: &str,
    ) -> crate::errors::Result<()> {
        use std::io::Write;
        if let Some(f) = &mut self.file {
            let ev = serde_json::json!({
                "seq": self.seq,
                "phase": phase,
                "heartbeat": true,
                "progress": progress,
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
}

#[cfg(test)]
mod tests {
    use super::BackendResponse;

    #[test]
    fn physical_certification_accepts_the_protocol_boolean_or_grade() {
        let boolean = BackendResponse {
            value: serde_json::json!({ "physical_certified": true }),
        };
        assert!(boolean.physical_certified());

        let grade = BackendResponse {
            value: serde_json::json!({ "certification": "C4" }),
        };
        assert!(grade.physical_certified());

        let absent = BackendResponse {
            value: serde_json::json!({ "certification": "C3" }),
        };
        assert!(!absent.physical_certified());
    }
}
