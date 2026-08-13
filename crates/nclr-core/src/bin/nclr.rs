//! nclr core CLI: ls / info / plan / run / check / salvage / resume / help.
//!
//! One process handles exactly one physical medium. Data goes to stdout,
//! diagnostics and progress to stderr, machine events to --events-fd.

use clap::{Parser, Subcommand};
use nclr::backend::{self, BackendHandle, BackendResponse, Request};
use nclr::confirm;
use nclr::device::{self, DeviceIdentity};
use nclr::errors::{self, Error, Result};
use nclr::grade::{compute_health, compute_lba_c1, CGrade, HealthEvidence, LbaC1Evidence};
use nclr::journal::Journal;
use nclr::plan::{self, Plan, PlanAction, PlanBackend, PowerCycleMethod};
use nclr::report::{ActionRecord, PostCheck, Report, ResultStatus};
use nclr::VERSION;
use serde_json::{json, Value};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "nclr", version = VERSION, about = "NAND media erase / reinitialize CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// List removable whole-disk candidates
    Ls {
        #[arg(short = 'j', long)]
        json: bool,
    },
    /// Read-only device identity and capability probe
    Info {
        #[arg(short = 'j', long)]
        json: bool,
        device: String,
        #[arg(long, hide = true)]
        backend_dir: Vec<PathBuf>,
    },
    /// Generate a normalized plan (read-only)
    Plan {
        #[arg(short = 'l', long, default_value = "best")]
        level: String,
        #[arg(long)]
        min_level: Option<String>,
        #[arg(long)]
        no_fallback: bool,
        #[arg(long)]
        aggressive_lba: bool,
        #[arg(long)]
        backend: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Backend call timeout in seconds (0 = disabled)
        #[arg(long, default_value_t = 0)]
        backend_timeout: u64,
        #[arg(long, hide = true)]
        backend_dir: Vec<PathBuf>,
        device: String,
    },
    /// Execute a plan against one device (destructive)
    Run {
        #[arg(short = 'l', long, default_value = "best")]
        level: String,
        #[arg(long)]
        min_level: Option<String>,
        #[arg(long)]
        no_fallback: bool,
        #[arg(long)]
        aggressive_lba: bool,
        #[arg(long)]
        backend: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, hide = true)]
        backend_dir: Vec<PathBuf>,
        /// Content-addressed controller artifact store (repeatable)
        #[arg(long)]
        artifact_dir: Vec<PathBuf>,
        #[arg(long)]
        plan: Option<PathBuf>,
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long)]
        events_fd: Option<i32>,
        #[arg(long)]
        unmount: bool,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        power_cycle: Option<String>,
        #[arg(long)]
        allow_nonremovable: bool,
        #[arg(long, hide = true)]
        evidence_dir: Option<PathBuf>,
        /// Backend call timeout in seconds (0 = disabled)
        #[arg(long, default_value_t = 0)]
        backend_timeout: u64,
        #[arg(short = 'j', long)]
        json: bool,
        /// Emit the redacted summary report instead of the full report
        #[arg(long)]
        summary: bool,
        #[arg(short = 'q', long)]
        quiet: bool,
        #[arg(short = 'v', long, action = clap::ArgAction::Count)]
        verbose: u8,
        device: Option<String>,
    },
    /// Non-destructive media assessment
    Check {
        #[arg(short = 'j', long)]
        json: bool,
        #[arg(long, hide = true)]
        backend_dir: Vec<PathBuf>,
        /// Bounded write test over an explicit range "START:SECTORS"
        /// (explicit opt-in; the device is restored afterwards).
        #[arg(long)]
        scratch_range: Option<String>,
        /// Skip the scratch-test confirmation prompt
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Backend call timeout in seconds (0 = disabled)
        #[arg(long, default_value_t = 0)]
        backend_timeout: u64,
        device: String,
    },
    /// Read every physical NAND page and OOB byte into a salvage image
    Salvage {
        device: String,
        /// New raw physical image file (block-major, page-minor, data + OOB)
        #[arg(long)]
        output: PathBuf,
        /// New NDJSON page map describing every image extent and read error
        #[arg(long)]
        map: PathBuf,
        #[arg(long)]
        backend: Option<String>,
        #[arg(long)]
        config: Option<PathBuf>,
        #[arg(long, hide = true)]
        backend_dir: Vec<PathBuf>,
        #[arg(long)]
        artifact_dir: Vec<PathBuf>,
        #[arg(long)]
        state: Option<PathBuf>,
        #[arg(long)]
        events_fd: Option<i32>,
        #[arg(long)]
        unmount: bool,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        allow_nonremovable: bool,
        /// Backend call timeout in seconds (0 = disabled)
        #[arg(long, default_value_t = 0)]
        backend_timeout: u64,
        #[arg(short = 'j', long)]
        json: bool,
    },
    /// Resume from a journal state file (positional STATE is the journal)
    Resume {
        #[arg(long)]
        config: Option<PathBuf>,
        /// Backend call timeout in seconds (0 = disabled)
        #[arg(long, default_value_t = 0)]
        backend_timeout: u64,
        #[arg(long)]
        events_fd: Option<i32>,
        #[arg(long)]
        yes: bool,
        #[arg(long)]
        unmount: bool,
        #[arg(long)]
        power_cycle: Option<String>,
        #[arg(long)]
        allow_nonremovable: bool,
        #[arg(long, hide = true)]
        evidence_dir: Option<PathBuf>,
        #[arg(long, hide = true)]
        backend_dir: Vec<PathBuf>,
        /// Content-addressed controller artifact store (repeatable)
        #[arg(long)]
        artifact_dir: Vec<PathBuf>,
        #[arg(short = 'j', long)]
        json: bool,
        /// Emit the redacted summary report instead of the full report
        #[arg(long)]
        summary: bool,
        state_file: PathBuf,
    },
}

#[derive(Clone)]
struct RunOptions {
    yes: bool,
    unmount: bool,
    allow_nonremovable: bool,
    no_fallback: bool,
    aggressive_lba: bool,
    power_cycle: Option<String>,
    state: Option<PathBuf>,
    events_fd: Option<i32>,
    backend_dir: Vec<PathBuf>,
    artifact_dir: Vec<PathBuf>,
    evidence_dir: Option<PathBuf>,
    backend_timeout: Option<u64>,
    quiet: bool,
    verbose: u8,
    json: bool,
    summary: bool,
}

struct OpenRun {
    device_path: String,
    identity: DeviceIdentity,
    handle: BackendHandle,
    device_fd: OwnedFd,
    journal: Journal,
    state_path: PathBuf,
    _lock: nclr::lock::DeviceLock,
    backend_extras: Vec<(OwnedFd, String)>,
}

/// Open controller-adjacent device nodes in the trusted core and pass only
/// inherited descriptors to backends. On Linux, an sg node is resolved from
/// the same sysfs SCSI object as the block target; other platforms have no
/// extra descriptor.
#[cfg(target_os = "linux")]
fn open_backend_extras(identity: &DeviceIdentity, write: bool) -> Result<Vec<(OwnedFd, String)>> {
    use std::os::unix::fs::{FileTypeExt, OpenOptionsExt};
    let mut extras = Vec::new();
    let scsi = identity.scsi.as_ref().ok_or_else(|| {
        Error::Permission(format!(
            "controller backend requires a SCSI identity for {}",
            identity.kernel_path
        ))
    })?;
    if scsi.sg_path.is_empty() {
        return Err(Error::Permission(format!(
            "controller backend requires an associated sg node for {}",
            identity.kernel_path
        )));
    }
    let block_name = identity
        .kernel_path
        .strip_prefix("/dev/")
        .unwrap_or(&identity.kernel_path);
    let resolved = device::linux_sg_path(block_name).ok_or_else(|| {
        Error::Permission(format!(
            "cannot resolve an sg node for {}",
            identity.kernel_path
        ))
    })?;
    if resolved != scsi.sg_path {
        return Err(Error::Permission(format!(
            "sg association changed: identity {} vs current {}",
            scsi.sg_path, resolved
        )));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(write)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&resolved)
        .map_err(|e| Error::io(format!("open associated sg node {resolved}"), Some(e)))?;
    let metadata = file
        .metadata()
        .map_err(|e| Error::io(format!("stat associated sg node {resolved}"), Some(e)))?;
    if !metadata.file_type().is_char_device() {
        return Err(Error::Permission(format!(
            "associated sg path is not a character device: {resolved}"
        )));
    }
    extras.push((OwnedFd::from(file), "sg".into()));
    Ok(extras)
}

#[cfg(not(target_os = "linux"))]
fn open_backend_extras(_identity: &DeviceIdentity, _write: bool) -> Result<Vec<(OwnedFd, String)>> {
    Ok(Vec::new())
}

#[cfg(target_os = "linux")]
fn reopen_controller_transport(
    physical_path: &str,
    allow_nonremovable: bool,
    destructive: bool,
    device_fd: &mut OwnedFd,
    extras: &mut Vec<(OwnedFd, String)>,
) -> Result<DeviceIdentity> {
    let matches = device::list_all_devices()?
        .into_iter()
        .filter(|identity| identity.physical_path == physical_path)
        .collect::<Vec<_>>();
    let identity = match matches.as_slice() {
        [] => {
            return Err(Error::Io(
                format!("no block device is present at USB path {physical_path}"),
                None,
            ))
        }
        [identity] => identity.clone(),
        _ => {
            return Err(Error::Permission(format!(
                "multiple block devices appeared at USB path {physical_path}"
            )))
        }
    };
    let options = nclr::safety::SafetyOptions {
        unmount: false,
        allow_nonremovable,
    };
    if destructive {
        nclr::safety::preflight(&identity, &options)?;
    } else {
        nclr::safety::preflight_read(&identity, &options)?;
    }
    let replacement_device = OwnedFd::from(device::open_raw(&identity.kernel_path, destructive)?);
    let mut replacement_extras = open_backend_extras(&identity, true)?;
    let replacement_sg = replacement_extras
        .pop()
        .ok_or_else(|| Error::Permission("re-enumerated controller has no sg fd".into()))?;
    let sg_index = extras
        .iter()
        .position(|(_, role)| role == "sg")
        .ok_or_else(|| Error::Invalid("controller backend extras lost the sg role".into()))?;
    extras[sg_index] = replacement_sg;
    *device_fd = replacement_device;
    Ok(identity)
}

#[cfg(not(target_os = "linux"))]
fn reopen_controller_transport(
    _physical_path: &str,
    _allow_nonremovable: bool,
    _destructive: bool,
    _device_fd: &mut OwnedFd,
    _extras: &mut Vec<(OwnedFd, String)>,
) -> Result<DeviceIdentity> {
    Err(Error::Unsupported(
        "controller re-enumeration requires Linux".into(),
    ))
}

fn extra_fd_request(extras: &[(OwnedFd, String)]) -> Vec<nclr::backend::ExtraFd> {
    extras
        .iter()
        .enumerate()
        .map(|(i, (_, role))| nclr::backend::ExtraFd {
            fd: nclr::backend::FD_EXTRA_BASE + i as i32,
            role: role.clone(),
        })
        .collect()
}

#[cfg(unix)]
fn open_controller_state(path: &Path) -> Result<OwnedFd> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| Error::io(format!("open controller state {}", path.display()), Some(e)))?;
    let metadata = file
        .metadata()
        .map_err(|e| Error::io(format!("stat controller state {}", path.display()), Some(e)))?;
    if !metadata.is_file()
        || metadata.uid() != nclr::journal::nix_uid()
        || metadata.mode() & 0o077 != 0
    {
        return Err(Error::Permission(format!(
            "controller state {} must be a regular 0600 file owned by the current user",
            path.display()
        )));
    }
    Ok(OwnedFd::from(file))
}

#[cfg(not(unix))]
fn open_controller_state(_path: &Path) -> Result<OwnedFd> {
    Err(Error::Unsupported(
        "controller state files require Unix file descriptor semantics".into(),
    ))
}

fn controller_state_path(journal_path: &Path) -> PathBuf {
    let name = journal_path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("nclr.state");
    journal_path.with_file_name(format!("{name}.controller"))
}

fn extra_fd_sources(extras: &[(OwnedFd, String)]) -> Vec<(i32, String)> {
    extras
        .iter()
        .map(|(fd, role)| (fd.as_raw_fd(), role.clone()))
        .collect()
}

fn open_plan_artifacts(plan: &Plan, explicit_stores: &[PathBuf]) -> Result<Vec<(OwnedFd, String)>> {
    let stores = nclr::artifact::search_stores(explicit_stores);
    let mut opened = Vec::with_capacity(plan.backend.artifacts.len());
    for spec in &plan.backend.artifacts {
        let (file, verified) = nclr::artifact::find_verified(spec, &stores)?;
        opened.push((OwnedFd::from(file), format!("artifact:{}", spec.id)));
        if verified.sha256.is_empty() {
            return Err(Error::Invalid(format!(
                "artifact {} verification returned an empty digest",
                spec.id
            )));
        }
    }
    Ok(opened)
}

fn main() {
    nclr::signal::install();
    // Standard Unix tool behavior: die with SIGPIPE instead of panicking
    // when stdout is a closed pipe (CLI compatibility).
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    // Map clap's default usage-error exit code (2) to the project's usage
    // exit code (64); --help/--version are normal (exit 0).
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(e) => {
            use clap::error::ErrorKind;
            if matches!(e.kind(), ErrorKind::DisplayHelp | ErrorKind::DisplayVersion) {
                let _ = e.print();
                std::process::exit(0);
            }
            let _ = e.print();
            std::process::exit(errors::exit::USAGE);
        }
    };
    let code = match cli.cmd {
        Cmd::Ls { json } => cmd_ls(json),
        Cmd::Info {
            json,
            device,
            backend_dir,
        } => cmd_info(&device, json, &backend_dir),
        Cmd::Plan {
            level,
            min_level,
            no_fallback,
            aggressive_lba,
            backend,
            config,
            backend_timeout,
            backend_dir,
            device,
        } => cmd_plan(
            &device,
            &level,
            min_level.as_deref(),
            no_fallback,
            aggressive_lba,
            backend.as_deref(),
            config.as_deref(),
            &backend_dir,
            backend_timeout,
        ),
        Cmd::Run {
            level,
            min_level,
            no_fallback,
            aggressive_lba,
            backend,
            config,
            backend_dir,
            artifact_dir,
            plan,
            state,
            events_fd,
            unmount,
            yes,
            power_cycle,
            allow_nonremovable,
            evidence_dir,
            backend_timeout,
            json,
            summary,
            quiet,
            verbose,
            device,
        } => cmd_run(
            device.as_deref(),
            plan.as_deref(),
            config.as_deref(),
            &RunOptions {
                yes,
                unmount,
                allow_nonremovable,
                no_fallback,
                aggressive_lba,
                power_cycle,
                state,
                events_fd,
                backend_dir,
                artifact_dir,
                evidence_dir,
                backend_timeout: if backend_timeout > 0 {
                    Some(backend_timeout)
                } else {
                    None
                },
                quiet,
                verbose,
                json,
                summary,
            },
            &level,
            min_level.as_deref(),
            backend.as_deref(),
        ),
        Cmd::Check {
            json,
            backend_dir,
            scratch_range,
            yes,
            config,
            backend_timeout,
            device,
        } => cmd_check(
            &device,
            json,
            &backend_dir,
            scratch_range.as_deref(),
            yes,
            config.as_deref(),
            if backend_timeout > 0 {
                Some(backend_timeout)
            } else {
                None
            },
        ),
        Cmd::Salvage {
            device,
            output,
            map,
            backend,
            config,
            backend_dir,
            artifact_dir,
            state,
            events_fd,
            unmount,
            yes,
            allow_nonremovable,
            backend_timeout,
            json,
        } => cmd_salvage(
            &device,
            &output,
            &map,
            backend.as_deref(),
            config.as_deref(),
            &RunOptions {
                yes,
                unmount,
                allow_nonremovable,
                no_fallback: true,
                aggressive_lba: false,
                power_cycle: None,
                state,
                events_fd,
                backend_dir,
                artifact_dir,
                evidence_dir: None,
                backend_timeout: (backend_timeout > 0).then_some(backend_timeout),
                quiet: false,
                verbose: 0,
                json,
                summary: false,
            },
        ),
        Cmd::Resume {
            events_fd,
            yes,
            unmount,
            power_cycle,
            allow_nonremovable,
            evidence_dir,
            backend_timeout,
            backend_dir,
            artifact_dir,
            config,
            json,
            summary,
            state_file,
        } => cmd_resume(
            config.as_deref(),
            &state_file,
            &RunOptions {
                yes,
                unmount,
                allow_nonremovable,
                no_fallback: false,
                aggressive_lba: false,
                power_cycle,
                state: None,
                events_fd,
                backend_dir,
                artifact_dir,
                evidence_dir,
                backend_timeout: if backend_timeout > 0 {
                    Some(backend_timeout)
                } else {
                    None
                },
                quiet: false,
                verbose: 0,
                json,
                summary,
            },
        ),
    };
    std::process::exit(code);
}

fn cmd_ls(json: bool) -> i32 {
    match device::list_candidates() {
        Ok(list) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &json!({ "schema": nclr::SCHEMA_DEVICE, "devices": list })
                    )
                    .unwrap()
                );
            } else {
                for d in &list {
                    println!("{}", d.kernel_path);
                }
            }
            0
        }
        Err(e) => {
            eprintln!("nclr: {e}");
            e.exit_code()
        }
    }
}

fn cmd_info(device_path: &str, json: bool, backend_dir: &[PathBuf]) -> i32 {
    match info_impl(device_path, backend_dir) {
        Ok(info) => {
            if json {
                println!("{}", serde_json::to_string_pretty(&info).unwrap());
            } else {
                let identity = &info.identity;
                println!("Device: {}", identity.kernel_path);
                println!("Transport: {}", identity.transport);
                println!(
                    "Capacity: {} ({} bytes)",
                    confirm::human_capacity(identity.capacity_bytes),
                    identity.capacity_bytes
                );
                println!("Fingerprint: {}", identity.fingerprint);
                println!("Mounted: {}", if identity.mounted { "yes" } else { "no" });
                if let Some(p) = &info.backend_probe {
                    println!("Backend: {} (trust {})", p.backend_id, p.trust);
                    println!("Grade ceiling: {}", p.grade_ceiling);
                    println!("Capabilities: {}", display_list(&p.capabilities));
                    if let Some(method) = &p.erase_method {
                        println!("Erase method: {method}");
                    }
                    if !p.erase_coverage.is_empty() {
                        println!("Erase coverage: {}", p.erase_coverage.join(", "));
                    }
                } else {
                    println!("Backend: (none)");
                }
                if let Some(c) = &info.controller_identify {
                    if let Some(v) = &c.vendor {
                        let vid = identity.usb.as_ref().map_or("", |usb| usb.vid.as_str());
                        println!("Vendor: {v} (VID {vid})");
                    }
                    if let Some(m) = &c.model {
                        println!("Model: {m}");
                    }
                    if c.controller_id == "unidentified" {
                        if let Some(e) = &c.probe_error {
                            println!("Controller: (unidentified: {e})");
                        } else {
                            println!("Controller: (unidentified)");
                        }
                    } else {
                        print!("Controller: {}", c.controller_id);
                        if c.firmware != "unidentified" {
                            print!(" (FW {})", c.firmware);
                        }
                        if let Some(n) = &c.nand_id {
                            print!(", NAND {n}");
                        }
                        println!();
                    }
                    if let Some(family) = &c.family_hint {
                        println!("Controller family candidate: {family} (not an identity)");
                    }
                    if let Some(capability) = &c.capability_probe {
                        println!(
                            "Controller match: {}",
                            capability.match_state.as_deref().unwrap_or("none")
                        );
                        println!(
                            "Controller destructive ready: {}",
                            if capability.destructive_ready {
                                "yes"
                            } else {
                                "no"
                            }
                        );
                        println!("Controller grade ceiling: {}", capability.grade_ceiling);
                        println!(
                            "Controller capabilities: {}",
                            display_list(&capability.capabilities)
                        );
                        if let Some(profile) = &capability.controller_profile {
                            println!("Controller profile: {profile}");
                        }
                        if !capability.required_artifacts.is_empty() {
                            println!(
                                "Required artifacts: {}",
                                capability
                                    .required_artifacts
                                    .iter()
                                    .map(|artifact| artifact.id.as_str())
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            );
                        }
                    }
                    if let Some(research) = &c.controller_research {
                        let candidates = research
                            .get("recipe_family_candidates")
                            .and_then(Value::as_array)
                            .map(|values| {
                                values
                                    .iter()
                                    .filter_map(Value::as_str)
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            })
                            .unwrap_or_default();
                        if !candidates.is_empty() {
                            println!("Controller recipe candidates: {candidates}");
                        }
                        println!(
                            "Controller support data: {}",
                            research
                                .get("selection")
                                .and_then(Value::as_str)
                                .unwrap_or("undetermined")
                        );
                    }
                }
                if let Some(research) = &info.sd_research {
                    println!(
                        "SD support data: {}",
                        research
                            .get("selection")
                            .and_then(Value::as_str)
                            .unwrap_or("undetermined")
                    );
                    println!(
                        "SD controller destructive ready: {}",
                        if research
                            .get("controller_destructive_ready")
                            .and_then(Value::as_bool)
                            .unwrap_or(false)
                        {
                            "yes"
                        } else {
                            "no"
                        }
                    );
                    if let Some(standard) = research.get("standard_full_user_erase") {
                        let available = standard
                            .get("candidate")
                            .and_then(Value::as_bool)
                            .unwrap_or(false);
                        println!(
                            "SD standard full-user erase candidate: {}",
                            if available { "yes" } else { "no" }
                        );
                        if !available {
                            if let Some(reason) = standard.get("reason").and_then(Value::as_str) {
                                println!("SD standard erase limitation: {reason}");
                            }
                        }
                    }
                }
                for warning in &info.warnings {
                    println!("Warning: {warning}");
                }
            }
            0
        }
        Err(e) => {
            eprintln!("nclr: {e}");
            e.exit_code()
        }
    }
}

use serde::{Deserialize, Serialize};

fn display_list(values: &[String]) -> String {
    if values.is_empty() {
        "(none)".into()
    } else {
        values.join(", ")
    }
}

#[derive(Serialize)]
struct InfoResult {
    identity: DeviceIdentity,
    backend_probe: Option<ProbeSummary>,
    controller_identify: Option<ControllerIdentify>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sd_research: Option<Value>,
    warnings: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct ProbeSummary {
    backend_id: String,
    version: String,
    trust: String,
    match_state: Option<String>,
    destructive_ready: bool,
    capabilities: Vec<String>,
    grade_ceiling: String,
    erase_coverage: Vec<String>,
    erase_method: Option<String>,
    rebuilds: Vec<String>,
    controller_profile: Option<String>,
    profile_sha256: Option<String>,
    capacity_policy: Option<Value>,
    protected_area_bytes: u64,
    certification: Option<String>,
    physical_certified: bool,
    required_artifacts: Vec<nclr::artifact::ArtifactSpec>,
}

/// Read-only controller identification result from the controller backend
/// probe (best effort: only vendor-owned USB VIDs are probed, and a missing
/// or failing probe is reported, never fatal).
#[derive(Serialize, Deserialize)]
struct ControllerIdentify {
    /// Vendor name resolved from the OS usb.ids database (lsusb/udev source,
    /// e.g. "Phison Electronics Corp."), falling back to the device's own
    /// iManufacturer claim. Informational branding only, never a
    /// controller-family claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    vendor: Option<String>,
    /// Model name resolved from the OS usb.ids database (e.g. "PS2232
    /// flash drive controller"), when the vid:pid pair is listed.
    #[serde(skip_serializing_if = "Option::is_none")]
    model: Option<String>,
    family_hint: Option<String>,
    controller_id: String,
    firmware: String,
    nand_id: Option<String>,
    service_mode: String,
    capability_probe: Option<ProbeSummary>,
    probe_error: Option<String>,
    /// Self-contained, read-only bootstrap tuple and the remaining evidence
    /// needed to add an unsupported controller. The backend never places
    /// raw media payload in this object.
    #[serde(skip_serializing_if = "Option::is_none")]
    controller_research: Option<Value>,
}

/// Resolve the vendor name for a USB device: first from the OS usb.ids
/// database (the same source lsusb and udev use), then from the device's
/// own iManufacturer string.
fn vendor_name(usb: &nclr::device::UsbInfo) -> Option<String> {
    let vid = u16::from_str_radix(usb.vid.trim_start_matches("0x"), 16).ok()?;
    nclr::profile::usb_ids_vendor(vid).or_else(|| {
        let claimed = usb.manufacturer.trim();
        if claimed.is_empty() {
            None
        } else {
            Some(claimed.to_string())
        }
    })
}

/// Resolve the model name from the OS usb.ids database, when listed.
fn model_name(usb: &nclr::device::UsbInfo) -> Option<String> {
    let vid = u16::from_str_radix(usb.vid.trim_start_matches("0x"), 16).ok()?;
    let pid = u16::from_str_radix(usb.pid.trim_start_matches("0x"), 16).ok()?;
    nclr::profile::usb_ids_model(vid, pid)
}

/// Brand the controller identification with the vendor/model names resolved
/// from the OS usb.ids database.
fn with_vendor(mut c: ControllerIdentify, identity: &DeviceIdentity) -> ControllerIdentify {
    if let Some(usb) = identity.usb.as_ref() {
        c.vendor = vendor_name(usb);
        c.model = model_name(usb);
    }
    c
}

fn local_family_hint(identity: &DeviceIdentity) -> Option<nclr::controller_protocol::Family> {
    let usb = identity.usb.as_ref()?;
    let vid = u16::from_str_radix(usb.vid.trim_start_matches("0x"), 16).ok()?;
    let profiles = nclr::profile::load_identify_profiles(&[]);
    nclr::profile::family_hint_from_vid(vid, &profiles)
}

/// Build a command-free research bundle from OS-provided identity. This is
/// intentionally available even when the Linux SG_IO backend is absent or
/// forbidden: it is the handoff needed to create an exact bootstrap profile
/// for a previously unsupported device.
fn local_controller_research(identity: &DeviceIdentity) -> Option<Value> {
    let usb = identity.usb.as_ref()?;
    let family_hint = local_family_hint(identity);
    let candidates = family_hint.map_or_else(
        || {
            nclr::controller_protocol::Family::ALL
                .iter()
                .copied()
                .filter(|family| nclr::controller_protocol::support(*family).recipe_engine)
                .map(nclr::controller_protocol::Family::recipe_str)
                .collect::<Vec<_>>()
        },
        |family| vec![family.recipe_str()],
    );
    let scsi = identity.scsi.as_ref();
    let mut missing = vec![
        "exact controller identity response",
        "exact NAND identity and geometry",
        "successful and failing factory-tool protocol traces",
        "service transition and runtime loader artifacts",
        "BBT, FTL, spare and commit metadata layouts",
        "independent HIL qualification and power-cut evidence",
    ];
    if scsi.is_none() {
        missing.insert(
            0,
            "SCSI INQUIRY vendor/product/revision from the active transport",
        );
    }
    Some(json!({
        "schema": 1,
        "selection": if family_hint.is_some() { "vendor-id-candidate-only" } else { "undetermined" },
        "recipe_family_candidates": candidates,
        "exact_bootstrap_observed": {
            "family": family_hint.map(nclr::controller_protocol::Family::recipe_str),
            "usb_vid": usb.vid,
            "usb_pid": usb.pid,
            "usb_bcd_device": usb.bcd_device,
            "usb_manufacturer": usb.manufacturer,
            "usb_product": usb.product,
            "usb_serial": usb.serial,
            "scsi_vendor": scsi.map_or("", |value| value.vendor.as_str()),
            "scsi_product": scsi.map_or("", |value| value.model.as_str()),
            "scsi_revision": scsi.map_or("", |value| value.rev.as_str()),
        },
        "identity_source": "operating-system-registry",
        "media_commands_sent": [],
        "unknown_vendor_commands_sent": false,
        "missing_for_production": missing,
    }))
}

/// Build a command-free native SD research bundle from the identity already
/// exposed by the operating system. Standard card registers identify the
/// card, not its internal flash controller; the missing controller-service
/// contract therefore remains explicit even when CID/CSD/SCR are complete.
fn local_sd_research(identity: &DeviceIdentity) -> Option<Value> {
    if identity.transport != device::TRANSPORT_MMC && identity.mmc.is_none() {
        return None;
    }
    let mmc = identity.mmc.as_ref();
    let mac = identity.mac.as_ref();
    let registers_complete = mmc.is_some_and(|card| {
        !card.cid.is_empty()
            && !card.csd.is_empty()
            && !card.scr.is_empty()
            && !card.kind.is_empty()
    });
    let selection = if registers_complete {
        "card-registers-complete"
    } else if mmc.is_some() {
        "card-registers-partial"
    } else {
        "os-identity-only"
    };
    let identity_source = if mmc.is_some() {
        "operating-system-mmc-registry"
    } else {
        "operating-system-disk-registry"
    };
    let standard_erase_analysis = match mmc {
        None => json!({
            "candidate": false,
            "reason": "raw CSD and erase-group size are not exposed by this operating-system path",
        }),
        Some(card) if card.kind != "SD" => json!({
            "candidate": false,
            "reason": "card kind is not exactly SD",
        }),
        Some(card) => match nclr::sd::parse_csd_erase_info(&card.csd) {
            Err(error) => json!({
                "candidate": false,
                "reason": error.to_string(),
            }),
            Ok(info) if !info.erase_command_class => json!({
                "candidate": false,
                "csd_structure": info.structure,
                "addressing": info.addressing,
                "erase_command_class": false,
                "reason": "CSD does not declare standard erase command class 5",
            }),
            Ok(info) if !identity.capacity_bytes.is_multiple_of(nclr::lba::SECTOR) => json!({
                "candidate": false,
                "csd_structure": info.structure,
                "addressing": info.addressing,
                "erase_command_class": true,
                "reason": "reported capacity is not 512-byte aligned",
            }),
            Ok(info) => match nclr::sd::full_range_erase_arguments(
                identity.capacity_bytes / nclr::lba::SECTOR,
                info.addressing,
                card.erase_size_bytes,
            ) {
                Ok((start, end)) => json!({
                    "candidate": true,
                    "csd_structure": info.structure,
                    "addressing": info.addressing,
                    "erase_command_class": true,
                    "cmd32_argument": start,
                    "cmd33_argument": end,
                    "erase_size_bytes": card.erase_size_bytes,
                }),
                Err(error) => json!({
                    "candidate": false,
                    "csd_structure": info.structure,
                    "addressing": info.addressing,
                    "erase_command_class": true,
                    "erase_size_bytes": card.erase_size_bytes,
                    "reason": error.to_string(),
                }),
            },
        },
    };
    Some(json!({
        "schema": 1,
        "selection": selection,
        "identity_source": identity_source,
        "controller_service_identity": "not-exposed-by-standard-sd-host-interface",
        "controller_destructive_ready": false,
        "standard_full_user_erase": standard_erase_analysis,
        "exact_card_observed": {
            "transport": identity.transport,
            "physical_path": identity.physical_path,
            "capacity_bytes": identity.capacity_bytes,
            "logical_block_size": identity.logical_block_size,
            "cid": mmc.map_or("", |card| card.cid.as_str()),
            "csd": mmc.map_or("", |card| card.csd.as_str()),
            "scr": mmc.map_or("", |card| card.scr.as_str()),
            "manufacturer_id": mmc.map_or("", |card| card.manfid.as_str()),
            "oem_id": mmc.map_or("", |card| card.oemid.as_str()),
            "product_name": mmc.map_or("", |card| card.name.as_str()),
            "serial": mmc.map_or("", |card| card.serial.as_str()),
            "manufacturing_date": mmc.map_or("", |card| card.date.as_str()),
            "host": mmc.map_or("", |card| card.host.as_str()),
            "card_kind": mmc.map_or("", |card| card.kind.as_str()),
            "erase_size_bytes": mmc.map_or(0, |card| card.erase_size_bytes),
            "preferred_erase_size_bytes": mmc.map_or(0, |card| card.preferred_erase_size_bytes),
            "mac_protocol": mac.map_or("", |value| value.protocol.as_str()),
            "mac_serial": mac.map_or("", |value| value.serial.as_str()),
            "mac_media_name": mac.map_or("", |value| value.media_name.as_str()),
            "mac_media_type": mac.map_or("", |value| value.media_type.as_str()),
        },
        "media_commands_sent": [],
        "unknown_vendor_commands_sent": false,
        "missing_for_production": [
            "exact internal controller and firmware identity",
            "documented or traced vendor service command contract and response signatures",
            "exact NAND identity, geometry, bus width, ECC and randomizer",
            "physical page and OOB addressing",
            "BBT, FTL, spare and commit metadata layouts",
            "successful and failing factory-tool protocol traces and runtime artifacts",
            "service transition, recovery and power-cut state machine",
            "independent HIL qualification and physical-reader evidence"
        ],
    }))
}

/// A ControllerIdentify for an unsuccessful or skipped probe.
fn unidentified_controller(
    identity: &DeviceIdentity,
    probe_error: Option<String>,
) -> ControllerIdentify {
    with_vendor(
        ControllerIdentify {
            vendor: None,
            model: None,
            family_hint: local_family_hint(identity).map(|family| family.as_str().to_string()),
            controller_id: "unidentified".into(),
            firmware: "unidentified".into(),
            nand_id: None,
            service_mode: "normal".into(),
            capability_probe: None,
            probe_error,
            controller_research: local_controller_research(identity),
        },
        identity,
    )
}

/// Open the device read-only, retrying briefly. A USB bridge that reset its
/// transport (NOT READY / ENOMEDIUM) usually recovers within a second.
fn open_raw_with_retry(device_path: &str, attempts: u32) -> Result<std::fs::File> {
    let mut last = None;
    for attempt in 0..attempts {
        match device::open_raw(device_path, false) {
            Ok(f) => return Ok(f),
            Err(e) => {
                last = Some(e);
                if attempt + 1 < attempts {
                    std::thread::sleep(std::time::Duration::from_millis(300));
                }
            }
        }
    }
    Err(last.unwrap_or_else(|| Error::io(format!("open {device_path}"), None)))
}

fn probe_summary(handle: &BackendHandle, response: &BackendResponse) -> Result<ProbeSummary> {
    let match_state = response
        .value
        .get("match")
        .and_then(Value::as_str)
        .map(str::to_string);
    Ok(ProbeSummary {
        backend_id: handle.id.clone(),
        version: handle.version.clone(),
        trust: handle.trust.clone(),
        destructive_ready: handle.id != "controller"
            || match_state.as_deref() == Some("exact-executable"),
        match_state,
        capabilities: response.capabilities(),
        grade_ceiling: response.grade_ceiling(),
        erase_coverage: response.erase_coverage(),
        erase_method: response.erase_method(),
        rebuilds: response.rebuilds(),
        controller_profile: response.controller_profile(),
        profile_sha256: response.profile_sha256(),
        capacity_policy: response.capacity_policy().filter(|value| !value.is_null()),
        protected_area_bytes: response.protected_area_bytes(),
        certification: response
            .value
            .get("certification")
            .and_then(Value::as_str)
            .map(str::to_string),
        physical_certified: response.physical_certified(),
        required_artifacts: response.artifacts()?,
    })
}

/// Identify the device and probe standard and controller capabilities.
fn info_impl(device_path: &str, backend_dir: &[PathBuf]) -> Result<InfoResult> {
    let identity = device::identify(device_path)?;
    let mut warnings = nclr::safety::preflight_soft(&identity);
    let site = nclr::config::load(None)?;
    let probe = match pick_backend(&identity, None, backend_dir, &site) {
        Ok(handle) => {
            let result = (|| -> Result<ProbeSummary> {
                let fd = device::open_raw(device_path, false)?;
                let owned = OwnedFd::from(fd);
                let extras = if handle.id == "controller" {
                    open_backend_extras(&identity, false)?
                } else {
                    Vec::new()
                };
                let extra_request = extra_fd_request(&extras);
                let extra_sources = extra_fd_sources(&extras);
                let response = backend::call(
                    &handle,
                    "probe",
                    &owned,
                    None,
                    &Request {
                        api: nclr::BACKEND_API,
                        op: "probe".into(),
                        action: None,
                        seed: None,
                        device_is_file: Some(device::is_regular_file(device_path)),
                        limits: req_limits(),
                        params: None,
                        device: Some(identity.clone()),
                        extra_fds: extra_request,
                    },
                    &extra_sources,
                    None,
                )?;
                if !response.ok() {
                    return Err(Error::Backend(response.message()));
                }
                probe_summary(&handle, &response)
            })();
            match result {
                Ok(probe) => Some(probe),
                Err(error) => {
                    warnings.push(format!("backend probe failed: {error}"));
                    None
                }
            }
        }
        Err(error) => {
            warnings.push(format!("backend probe skipped: {error}"));
            None
        }
    };
    let controller = if identity.usb.is_some() {
        match nclr::safety::deep_probe(&identity) {
            Ok(()) => controller_identify(&identity, device_path, backend_dir, &site),
            Err(error) => {
                warnings.push(format!(
                    "controller probe skipped by system-disk protection: {error}"
                ));
                Some(unidentified_controller(&identity, Some(error.to_string())))
            }
        }
    } else {
        None
    };
    let sd_research = local_sd_research(&identity);
    Ok(InfoResult {
        identity,
        backend_probe: probe,
        controller_identify: controller,
        sd_research,
        warnings,
    })
}

/// Best-effort read-only controller identification for USB mass storage
/// devices. Every result includes a command-free OS identity bundle; on
/// Linux, the optional backend may add a response-signed controller identity.
fn controller_identify(
    identity: &DeviceIdentity,
    device_path: &str,
    backend_dir: &[PathBuf],
    site: &nclr::config::SiteConfig,
) -> Option<ControllerIdentify> {
    // Only USB-attached devices carry a vendor VID that could select a
    // controller family; regular files and native SD have none.
    identity.usb.as_ref()?;
    // Respect the site policy: a controller probe that the policy forbids
    // (or would forbid for destructive use) is not attempted.
    if site.restricts_backends() && !site.allowed_backends().iter().any(|b| b == "controller") {
        return Some(unidentified_controller(
            identity,
            Some("controller backend disabled by site policy".into()),
        ));
    }
    let handle = match backend::find("controller", &backend::search_dirs(backend_dir)) {
        Ok(h) => h,
        Err(error) => return Some(unidentified_controller(identity, Some(error.to_string()))),
    };
    // The scsi probe just ran on this device. Some USB bridges (e.g. the
    // USBest UT163 in the Imation Flash Drive Mini) reset their transport
    // after a probe and briefly answer open() with ENOMEDIUM; retry a few
    // times before declaring the identification unavailable.
    let fd = match open_raw_with_retry(device_path, 4) {
        Ok(f) => f,
        Err(e) => return Some(unidentified_controller(identity, Some(e.to_string()))),
    };
    let device_fd = OwnedFd::from(fd);
    let extras = match open_backend_extras(identity, false) {
        Ok(e) => e,
        Err(e) => return Some(unidentified_controller(identity, Some(e.to_string()))),
    };
    let extra_request = extra_fd_request(&extras);
    let extra_sources = extra_fd_sources(&extras);
    let resp = match backend::call(
        &handle,
        "probe",
        &device_fd,
        None,
        &Request {
            api: nclr::BACKEND_API,
            op: "probe".into(),
            action: None,
            seed: None,
            device_is_file: Some(device::is_regular_file(device_path)),
            limits: req_limits(),
            params: None,
            device: Some(identity.clone()),
            extra_fds: extra_request,
        },
        &extra_sources,
        None,
    ) {
        Ok(r) => r,
        Err(e) => return Some(unidentified_controller(identity, Some(e.to_string()))),
    };
    if !resp.ok() {
        return Some(unidentified_controller(identity, Some(resp.message())));
    }
    let capability_probe = match probe_summary(&handle, &resp) {
        Ok(summary) => Some(summary),
        Err(error) => return Some(unidentified_controller(identity, Some(error.to_string()))),
    };
    let family_hint = resp
        .value
        .get("family_hint")
        .and_then(|v| v.as_str())
        .map(String::from)
        .or_else(|| local_family_hint(identity).map(|family| family.as_str().to_string()));
    let device = resp.value.get("device");
    let controller_id = device
        .and_then(|d| d.get("controller_id"))
        .and_then(|v| v.as_str())
        .unwrap_or("unidentified")
        .to_string();
    let firmware = device
        .and_then(|d| d.get("firmware"))
        .and_then(|v| v.as_str())
        .unwrap_or("unidentified")
        .to_string();
    let nand_id = device
        .and_then(|d| d.get("nand_id"))
        .and_then(|v| v.as_str())
        .filter(|s| *s != "unidentified")
        .map(String::from);
    let service_mode = device
        .and_then(|d| d.get("service_mode"))
        .and_then(|v| v.as_str())
        .unwrap_or("normal")
        .to_string();
    let probe_error = resp
        .value
        .get("probe_error")
        .and_then(|v| v.as_str())
        .map(String::from);
    let controller_research = resp
        .value
        .get("controller_research")
        .cloned()
        .or_else(|| local_controller_research(identity));
    Some(with_vendor(
        ControllerIdentify {
            vendor: None,
            model: None,
            family_hint,
            controller_id,
            firmware,
            nand_id,
            service_mode,
            capability_probe,
            probe_error,
            controller_research,
        },
        identity,
    ))
}

/// Level name for a C grade (site policy floor / requested levels).
fn level_name(g: CGrade) -> &'static str {
    match g {
        CGrade::C1 => "lba",
        CGrade::C2 => "device",
        CGrade::C3 => "controller",
        _ => "physical",
    }
}

/// The ceiling grade of a planning level keyword. "best" requests the
/// maximum achievable grade (C4) for floor comparisons.
fn level_ceiling(level: &str) -> Option<CGrade> {
    if level == "best" {
        Some(CGrade::C4)
    } else {
        CGrade::from_level(level)
    }
}

/// The higher of two level/min-level names (lexicographic grades).
fn max_level_str(a: &str, b: &str) -> &'static str {
    let ga = CGrade::parse(a).unwrap_or(CGrade::C0);
    let gb = CGrade::parse(b).unwrap_or(CGrade::C0);
    if ga >= gb {
        level_name(ga)
    } else {
        level_name(gb)
    }
}

/// Backend id for a device identity.
fn backend_id_for(identity: &DeviceIdentity) -> &'static str {
    if identity.is_sim() {
        return "sim";
    }
    if !device::is_regular_file(&identity.kernel_path) {
        #[cfg(target_os = "linux")]
        {
            // Native SD on an MMC host: standard SD commands are available.
            // The sysfs `type` attribute distinguishes SD cards ("SD") from
            // eMMC ("MMC") and other MMC devices; CMD32/33 are SD-only, so
            // eMMC must never reach the sd-native backend.
            if identity.transport == device::TRANSPORT_MMC
                && identity
                    .mmc
                    .as_ref()
                    .map(|m| m.kind == "SD")
                    .unwrap_or(false)
            {
                return "sd-native";
            }
            // USB mass storage (and opaque USB card readers): SCSI.
            if identity.transport == device::TRANSPORT_USB_MSD
                || identity.transport == device::TRANSPORT_SD_VIA_USB
            {
                return "scsi";
            }
        }
        // macOS and other platforms: plain LBA path (C1 ceiling).
    }
    "lba"
}

fn pick_backend(
    identity: &DeviceIdentity,
    forced: Option<&str>,
    backend_dir: &[PathBuf],
    site: &nclr::config::SiteConfig,
) -> Result<BackendHandle> {
    let id = match forced {
        Some(f) => f,
        None => backend_id_for(identity),
    };
    let expected = backend_id_for(identity);
    let compatible_controller = cfg!(target_os = "linux")
        && id == "controller"
        && matches!(
            identity.transport.as_str(),
            device::TRANSPORT_USB_MSD | device::TRANSPORT_SD_VIA_USB
        );
    if forced.is_some() && id != expected && !compatible_controller {
        return Err(Error::Usage(format!(
            "backend {id} does not match device transport (expected {expected})"
        )));
    }
    if site.restricts_backends() && !site.allowed_backends().iter().any(|b| b == id) {
        return Err(Error::Permission(format!(
            "backend {id} is not allowed by the site policy (allowed: {})",
            site.allowed_backends().join(", ")
        )));
    }
    backend::find(id, &backend::search_dirs(backend_dir))
}

#[allow(clippy::too_many_arguments)]
fn cmd_plan(
    device_path: &str,
    level: &str,
    min_level: Option<&str>,
    no_fallback: bool,
    aggressive_lba: bool,
    backend: Option<&str>,
    config: Option<&Path>,
    backend_dir: &[PathBuf],
    backend_timeout: u64,
) -> i32 {
    let site = match nclr::config::load(config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("nclr: {e}");
            return e.exit_code();
        }
    };
    match plan_impl(
        &PlanRequest {
            device_path,
            level,
            min_level,
            no_fallback,
            aggressive_lba,
            backend,
            backend_dir,
            backend_timeout,
            power_cycle: None,
        },
        &site,
    ) {
        Ok(p) => {
            println!("{}", serde_json::to_string_pretty(&p).unwrap());
            0
        }
        Err(e) => {
            eprintln!("nclr: {e}");
            e.exit_code()
        }
    }
}

/// Planning inputs bundled to keep the planner call sites tidy.
struct PlanRequest<'a> {
    device_path: &'a str,
    level: &'a str,
    min_level: Option<&'a str>,
    no_fallback: bool,
    aggressive_lba: bool,
    backend: Option<&'a str>,
    backend_dir: &'a [PathBuf],
    backend_timeout: u64,
    power_cycle: Option<&'a str>,
}

fn plan_impl(req: &PlanRequest, site: &nclr::config::SiteConfig) -> Result<Plan> {
    let identity = device::identify(req.device_path)?;
    let is_usb = matches!(
        identity.transport.as_str(),
        device::TRANSPORT_USB_MSD | device::TRANSPORT_SD_VIA_USB
    );
    let requires_controller = [
        Some(req.level),
        req.min_level,
        site.minimum_level.as_deref(),
    ]
    .into_iter()
    .flatten()
    .any(|level| matches!(level, "controller" | "physical" | "C3" | "C4"));
    // Controller/physical levels on a USB mass-storage target explicitly
    // select the vendor backend. The ordinary and best paths retain the
    // standards-based SCSI backend unless a controller profile is found or
    // the caller opts in with --backend controller.
    let requested_backend = req.backend.or({
        if requires_controller && is_usb {
            Some("controller")
        } else {
            None
        }
    });
    let try_controller_for_best = cfg!(target_os = "linux")
        && is_usb
        && req.backend.is_none()
        && req.level == "best"
        && (!site.restricts_backends()
            || site.allowed_backends().iter().any(|b| b == "controller"));
    let mut handle = if try_controller_for_best {
        // Absence of the optional vendor backend is not an error for `best`;
        // the standards backend remains a valid lower-reach candidate.
        pick_backend(&identity, Some("controller"), req.backend_dir, site)
            .or_else(|_| pick_backend(&identity, requested_backend, req.backend_dir, site))?
    } else {
        pick_backend(&identity, requested_backend, req.backend_dir, site)?
    };
    let fd = device::open_raw(req.device_path, false)?;
    let owned = OwnedFd::from(fd);
    let extras = if handle.id == "controller" {
        open_backend_extras(&identity, false)?
    } else {
        Vec::new()
    };
    let extra_request = extra_fd_request(&extras);
    let extra_sources = extra_fd_sources(&extras);
    let mut resp = backend::call(
        &handle,
        "probe",
        &owned,
        None,
        &Request {
            api: nclr::BACKEND_API,
            op: "probe".into(),
            action: None,
            seed: None,
            device_is_file: Some(device::is_regular_file(req.device_path)),
            limits: req_limits(),
            params: None,
            device: Some(identity.clone()),
            extra_fds: extra_request.clone(),
        },
        &extra_sources,
        if req.backend_timeout > 0 {
            Some(req.backend_timeout)
        } else {
            None
        },
    )?;
    if try_controller_for_best && resp.grade_ceiling() != "C3" && resp.grade_ceiling() != "C4" {
        handle = pick_backend(&identity, None, req.backend_dir, site)?;
        resp = backend::call(
            &handle,
            "probe",
            &owned,
            None,
            &Request {
                api: nclr::BACKEND_API,
                op: "probe".into(),
                action: None,
                seed: None,
                device_is_file: Some(device::is_regular_file(req.device_path)),
                limits: req_limits(),
                params: None,
                device: Some(identity.clone()),
                extra_fds: extra_request,
            },
            &extra_sources,
            if req.backend_timeout > 0 {
                Some(req.backend_timeout)
            } else {
                None
            },
        )?;
    }
    if !resp.ok() {
        return Err(Error::Backend(resp.message()));
    }
    let controller_profile = resp.controller_profile();
    let response_profile_sha256 = resp.profile_sha256();
    let response_artifacts = resp.artifacts()?;
    let mut caps = plan::BackendCapabilities {
        capabilities: resp.capabilities(),
        erase_coverage: resp.erase_coverage(),
        erase_method: resp.erase_method(),
        rebuilds: resp.rebuilds(),
        controller_profile: controller_profile.clone(),
        capacity_policy: resp.capacity_policy(),
        physical_certified: resp.physical_certified(),
        protected_area_bytes: resp.protected_area_bytes(),
        grade_ceiling: resp.grade_ceiling(),
    };
    // Site policy: clamp the profile spare ratio.
    if let (Some(policy), Some((lo, hi))) = (&mut caps.capacity_policy, site.spare_ratio_bounds()) {
        if let Some(r) = policy.get_mut("spare_ratio").and_then(|v| v.as_f64()) {
            let clamped = r.clamp(lo, hi);
            policy["spare_ratio"] = json!(clamped);
        }
    }
    // Site policy: minimum planning level floor. The requested level and
    // minimum level are validated first; invalid values are usage errors,
    // never silently coerced to C0.
    let floor = site.minimum_level.as_deref().and_then(CGrade::parse);
    let user = level_ceiling(req.level)
        .ok_or_else(|| Error::Usage(format!("invalid planning level: {}", req.level)))?;
    if let Some(m) = req.min_level {
        CGrade::parse(m)
            .ok_or_else(|| Error::Usage(format!("invalid minimum planning level: {m}")))?;
    }
    let effective_level = match floor {
        Some(f) if f > user => level_name(f).to_string(),
        _ => req.level.to_string(),
    };
    let plan_backend = PlanBackend {
        id: handle.id.clone(),
        version: handle.version.clone(),
        profile: controller_profile
            .clone()
            .or_else(|| handle.profile.clone()),
        profile_sha256: response_profile_sha256.or_else(|| {
            controller_profile
                .as_ref()
                .or(handle.profile.as_ref())
                .and_then(|pid| {
                    nclr::profile::find(pid, &nclr::profile::search_dirs(req.backend_dir)).ok()
                })
                .and_then(|p| p.sha256.clone())
        }),
        trust: handle.trust.clone(),
        sha256: Some(handle.sha256.clone()),
        artifacts: response_artifacts,
    };
    plan::plan(
        &identity,
        &plan::PlanOptions {
            level: effective_level.to_string(),
            user_level: Some(req.level.to_string()),
            min_level: match (req.min_level, floor) {
                (Some(m), Some(f)) => Some(max_level_str(m, f.as_str()).to_string()),
                (Some(m), None) => Some(m.to_string()),
                (None, Some(f)) => Some(f.as_str().to_string()),
                (None, None) => None,
            },
            no_fallback: req.no_fallback,
            aggressive_lba: req.aggressive_lba,
            power_cycle: req.power_cycle.map(String::from),
            backend_id: req.backend.map(String::from),
            timeout_secs: if req.backend_timeout > 0 {
                Some(req.backend_timeout)
            } else {
                None
            },
        },
        &plan_backend,
        &caps,
    )
}

// ---------------------------------------------------------------------------
// run / resume shared execution
// ---------------------------------------------------------------------------

fn cmd_run(
    device_arg: Option<&str>,
    plan_file: Option<&Path>,
    config: Option<&Path>,
    opts: &RunOptions,
    level: &str,
    min_level: Option<&str>,
    backend: Option<&str>,
) -> i32 {
    let site = match nclr::config::load(config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("nclr: {e}");
            return e.exit_code();
        }
    };
    if let Some(cmd) = &opts.power_cycle {
        if site.restricts_power_cycle() && !site.power_cycle_allowlist().iter().any(|a| a == cmd) {
            eprintln!(
                "nclr: permission denied: power-cycle command {cmd} is not allowed by the site policy"
            );
            return errors::exit::PERMISSION;
        }
    }
    let plan = match plan_file {
        Some(f) => match read_plan_file(f) {
            Ok(p) => p,
            Err(e) => {
                eprintln!("nclr: {e}");
                return e.exit_code();
            }
        },
        None => {
            let Some(dev) = device_arg else {
                eprintln!("nclr: usage: run requires DEVICE or --plan FILE");
                return errors::exit::USAGE;
            };
            match plan_impl(
                &PlanRequest {
                    device_path: dev,
                    level,
                    min_level,
                    no_fallback: opts.no_fallback,
                    aggressive_lba: opts.aggressive_lba,
                    backend,
                    backend_dir: &opts.backend_dir,
                    backend_timeout: opts.backend_timeout.unwrap_or(0),
                    power_cycle: opts.power_cycle.as_deref(),
                },
                &site,
            ) {
                Ok(p) => p,
                Err(e) => {
                    eprintln!("nclr: {e}");
                    return e.exit_code();
                }
            }
        }
    };
    // Reject an invalid embedded fallback plan before any device action.
    if let Err(e) = load_fallback_plan(&plan) {
        eprintln!("nclr: {e}");
        return e.exit_code();
    }
    if let Err(e) = site.enforce_plan(&plan) {
        eprintln!("nclr: {e}");
        return e.exit_code();
    }
    run_execute(plan, device_arg, opts, &site)
}

fn read_plan_file(path: &Path) -> Result<Plan> {
    let raw = if path.as_os_str() == "-" {
        use std::io::Read;
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| Error::io("read plan from stdin", Some(e)))?;
        s
    } else {
        std::fs::read_to_string(path)
            .map_err(|e| Error::io(format!("read plan {}", path.display()), Some(e)))?
    };
    if raw.len() > 16 * 1024 * 1024 {
        return Err(Error::Invalid("plan file too large".into()));
    }
    let value: Value =
        serde_json::from_str(&raw).map_err(|e| Error::Invalid(format!("plan JSON: {e}")))?;
    plan::validate(&value)
}

/// Parse a scratch range spec "START:SECTORS"; validates bounds.
fn parse_scratch_range(spec: Option<&str>, capacity_bytes: u64) -> Result<Option<(u64, u64)>> {
    let Some(spec) = spec else { return Ok(None) };
    let Some((start, count)) = spec.split_once(':') else {
        return Err(Error::Usage(
            "scratch range must be START:SECTORS (e.g. 0:1024)".into(),
        ));
    };
    let start: u64 = start
        .trim()
        .parse()
        .map_err(|_| Error::Usage("invalid scratch start".into()))?;
    let count: u64 = count
        .trim()
        .parse()
        .map_err(|_| Error::Usage("invalid scratch count".into()))?;
    // Bounded: the scratch test holds the range in memory to restore it.
    if count > 131_072 {
        return Err(Error::Usage(
            "scratch range too large (max 131072 sectors = 64 MiB)".into(),
        ));
    }
    let start_bytes = start
        .checked_mul(nclr::lba::SECTOR)
        .ok_or_else(|| Error::Usage("scratch start out of range".into()))?;
    let count_bytes = count
        .checked_mul(nclr::lba::SECTOR)
        .ok_or_else(|| Error::Usage("scratch count out of range".into()))?;
    if start_bytes
        .checked_add(count_bytes)
        .map(|end| end > capacity_bytes)
        .unwrap_or(true)
    {
        return Err(Error::Usage("scratch range exceeds device capacity".into()));
    }
    Ok(Some((start, count)))
}

/// Resolve the device path for a plan: explicit arg, file transport path,
/// or fingerprint discovery among candidates.
fn resolve_device_path(plan: &Plan, explicit: Option<&str>) -> Result<String> {
    if let Some(p) = explicit {
        return Ok(p.to_string());
    }
    if let Some(fp) = plan.device.physical_path.strip_prefix("file:") {
        if Path::new(fp).exists() {
            return Ok(fp.to_string());
        }
    }
    // Fingerprint discovery among removable block devices.
    let candidates = device::list_candidates()?;
    let matches: Vec<String> = candidates
        .iter()
        .filter(|d| d.fingerprint == plan.device.fingerprint)
        .map(|d| d.kernel_path.clone())
        .collect();
    match matches.len() {
        0 => Err(Error::Permission(
            "no device matching the plan fingerprint was found; attach it and retry".into(),
        )),
        1 => Ok(matches[0].clone()),
        _ => Err(Error::Permission(format!(
            "multiple devices match the plan fingerprint ({}); attach only one or pass the device path explicitly",
            matches.len()
        ))),
    }
}

/// Verify that the current device still matches the plan.
/// `accepted_fingerprints` contains the plan fingerprint and any post-commit
/// identities recorded in the journal (a controller rebuild may legitimately
/// change the capacity and therefore the fingerprint).
fn verify_plan_device(
    plan: &Plan,
    identity: &DeviceIdentity,
    accepted_fingerprints: &[String],
) -> Result<()> {
    if accepted_fingerprints.contains(&identity.fingerprint) {
        // The fingerprint binds capacity and physical path, so a match is a
        // full identity match.
        return Ok(());
    }
    if identity.fingerprint != plan.device.fingerprint {
        return Err(Error::Permission(format!(
            "device fingerprint mismatch: plan says {} but the device now reads {}",
            plan.device.fingerprint, identity.fingerprint
        )));
    }
    if identity.capacity_bytes != plan.device.capacity_bytes {
        return Err(Error::Permission(format!(
            "device capacity changed: plan {} bytes, device {} bytes",
            plan.device.capacity_bytes, identity.capacity_bytes
        )));
    }
    if identity.physical_path != plan.device.physical_path {
        return Err(Error::Permission(format!(
            "device physical path changed: plan {} vs device {}",
            plan.device.physical_path, identity.physical_path
        )));
    }
    Ok(())
}

struct ActionOutcome {
    record: ActionRecord,
    errors: u64,
    /// Raw first action_result (uniform/value/etc. for evidence grading).
    details: Option<Value>,
}

#[derive(Clone, Copy)]
struct BackendIo<'a> {
    device_fd: &'a OwnedFd,
    extras: &'a [(OwnedFd, String)],
    device_is_file: bool,
}

fn backend_io_for<'a>(
    device_fd: &'a OwnedFd,
    extras: &'a [(OwnedFd, String)],
    device_path: &str,
) -> BackendIo<'a> {
    BackendIo {
        device_fd,
        extras,
        device_is_file: device::is_regular_file(device_path),
    }
}

/// Execute one action via the backend.
/// One backend call per plan action. The arguments mirror the wire request
/// (action, seed, params, timeout) and the inherited fds; grouping them
/// would only hide the fd-passing contract.
fn run_backend_action(
    handle: &BackendHandle,
    io: BackendIo<'_>,
    events_fd: Option<&OwnedFd>,
    action: &PlanAction,
    plan_hash: &str,
    timeout: Option<u64>,
    params: Option<&serde_json::Value>,
) -> Result<BackendResponse> {
    let seed = if action.id.starts_with("lba-prbs") {
        Some(backend::plan_seed(plan_hash))
    } else {
        None
    };
    let mut merged_params = match action.params.clone() {
        Some(Value::Object(values)) => values,
        Some(_) => {
            return Err(Error::Invalid(format!(
                "action {} params must be a JSON object",
                action.id
            )))
        }
        None => serde_json::Map::new(),
    };
    if let Some(Value::Object(values)) = params {
        for (key, value) in values {
            merged_params.insert(key.clone(), value.clone());
        }
    } else if params.is_some() {
        return Err(Error::Invalid(format!(
            "runtime params for action {} must be a JSON object",
            action.id
        )));
    }
    merged_params.insert("plan_hash".into(), Value::String(plan_hash.into()));
    let response = backend::call(
        handle,
        "run",
        io.device_fd,
        events_fd,
        &Request {
            api: nclr::BACKEND_API,
            op: "run".into(),
            action: Some(action.id.clone()),
            seed,
            device_is_file: Some(io.device_is_file),
            limits: req_limits(),
            params: Some(Value::Object(merged_params)),
            device: None,
            extra_fds: extra_fd_request(io.extras),
        },
        &extra_fd_sources(io.extras),
        timeout,
    )?;
    if response.value.get("exit_code").and_then(Value::as_i64)
        == Some(i64::from(errors::exit::INTERRUPTED))
    {
        return Err(Error::Interrupted(response.message()));
    }
    Ok(response)
}

fn outcome_from_response(resp: &BackendResponse) -> ActionOutcome {
    let mut errors = 0u64;
    let mut status = "error".to_string();
    let mut message = None;
    let mut details = None;
    if let Some(results) = resp.value.get("action_results").and_then(|v| v.as_array()) {
        if let Some(r) = results.first() {
            if let Some(s) = r.get("status").and_then(|v| v.as_str()) {
                status = s.to_string();
            }
            if let Some(e) = r.get("errors").and_then(|v| v.as_u64()) {
                errors = e;
            }
            if let Some(m) = r.get("message").and_then(|v| v.as_str()) {
                message = Some(m.to_string());
            }
            details = Some(r.clone());
        }
    } else if let Some(m) = resp.value.get("error").and_then(|v| v.as_str()) {
        message = Some(m.to_string());
    }
    if status == "error" && errors == 0 {
        errors = 1;
    }
    ActionOutcome {
        record: ActionRecord {
            id: resp
                .value
                .get("action")
                .and_then(|v| v.as_str())
                .unwrap_or("?")
                .to_string(),
            status,
            retries: Some(0),
            errors: Some(errors),
            duration_ms: None,
            message,
        },
        errors,
        details,
    }
}

/// Evidence model selected by the plan's expected grade. A C2 plan that
/// falls back to L1 switches the variant mid-run.
enum GradeEvidence {
    Lba(LbaC1Evidence),
    Device(nclr::grade::DeviceEraseEvidence),
    Controller(nclr::grade::ControllerReinitEvidence),
    Physical(nclr::grade::PhysicalScopeEvidence),
}

impl GradeEvidence {
    fn power_cycled(&self) -> bool {
        match self {
            GradeEvidence::Lba(e) => e.power_cycled,
            GradeEvidence::Device(e) => e.power_cycled,
            GradeEvidence::Controller(e) => e.power_cycled,
            GradeEvidence::Physical(e) => e.power_cycled,
        }
    }
    fn compute(&self) -> nclr::grade::GradeResult {
        match self {
            GradeEvidence::Lba(e) => compute_lba_c1(e),
            GradeEvidence::Device(e) => nclr::grade::compute_device_c2(e),
            GradeEvidence::Controller(e) => nclr::grade::compute_controller_c3(e),
            GradeEvidence::Physical(e) => nclr::grade::compute_physical_c4(e),
        }
    }
    /// Health evidence derived from the completed actions.
    fn health(&self) -> HealthEvidence {
        match self {
            GradeEvidence::Lba(e) => HealthEvidence {
                capacity_stable: true,
                all_reads_ok: e.prbs_verify && e.zero_verify,
                flush_ok: e.flush_ok,
                power_cycle_consistent: e.power_cycled && e.prbs_verify && e.zero_verify,
                no_uncorrectable: e.io_errors == 0,
                spare_ok: true,
                weak_blocks: 0,
                new_bad_blocks: 0,
            },
            GradeEvidence::Device(e) => HealthEvidence {
                capacity_stable: e.capacity_stable,
                all_reads_ok: e.blank_verify && e.postcheck_reads_ok,
                flush_ok: e.postcheck_flush_ok,
                power_cycle_consistent: e.power_cycled && e.postcheck_reads_ok,
                no_uncorrectable: e.io_errors == 0,
                spare_ok: true,
                weak_blocks: 0,
                new_bad_blocks: 0,
            },
            GradeEvidence::Controller(e) => HealthEvidence {
                capacity_stable: e.capacity_stable,
                all_reads_ok: e.logical_reads_ok,
                flush_ok: e.flush_ok,
                power_cycle_consistent: e.power_cycled && e.capacity_stable && e.logical_reads_ok,
                no_uncorrectable: e.io_errors == 0,
                spare_ok: e.spare_ok,
                weak_blocks: e.isolated_blocks,
                new_bad_blocks: 0,
            },
            GradeEvidence::Physical(e) => HealthEvidence {
                capacity_stable: e.capacity_stable,
                all_reads_ok: e.logical_reads_ok,
                flush_ok: e.flush_ok,
                power_cycle_consistent: e.power_cycled && e.capacity_stable && e.logical_reads_ok,
                no_uncorrectable: e.io_errors == 0 && e.physical_uncorrectable_pages == 0,
                spare_ok: e.spare_ok,
                weak_blocks: e.isolated_blocks,
                new_bad_blocks: e.blocks_erase_failed,
            },
        }
    }
    /// Expected post-run capacity committed by a controller rebuild.
    fn expected_capacity_bytes(&self) -> Option<u64> {
        match self {
            GradeEvidence::Controller(e) => e.expected_capacity_bytes,
            GradeEvidence::Physical(e) => e.expected_capacity_bytes,
            _ => None,
        }
    }

    /// Constrain backend-reported capacity evidence with the core's final
    /// re-identification. A backend response alone cannot qualify stability.
    fn constrain_capacity_stability(&mut self, stable: bool) {
        match self {
            GradeEvidence::Device(e) => e.capacity_stable &= stable,
            GradeEvidence::Controller(e) => e.capacity_stable &= stable,
            GradeEvidence::Physical(e) => e.capacity_stable &= stable,
            GradeEvidence::Lba(_) => {}
        }
    }
}

fn load_fallback_plan(plan: &Plan) -> Result<Option<Plan>> {
    let Some(value) = plan.fallback_plan.as_ref() else {
        return Ok(None);
    };
    plan::validate(value)
        .map(Some)
        .map_err(|e| Error::Invalid(format!("fallback plan is invalid: {e}")))
}

/// The spare ratio declared in the plan's rebuild parameters.
fn plan_spare_ratio(plan: &Plan) -> f64 {
    plan.action("rebuild-bbt-ftl")
        .and_then(|a| a.params.as_ref())
        .and_then(|p| p.get("capacity_policy"))
        .and_then(|p| p.get("spare_ratio"))
        .and_then(|v| v.as_f64())
        .unwrap_or(0.0)
}

/// FTL/BTT summary for controller and physical evidence:
/// returns (report.ftl value, summary fields for details).
fn controller_summary(evidence: &GradeEvidence, plan: &Plan) -> (Option<Value>, Value) {
    let (rebuilt, bbt_gen, ftl_gen, old_gen, fbb, rbb, rbb_erased) = match evidence {
        GradeEvidence::Controller(e) => (
            e.new_bbt_committed && e.ftl_rebuilt,
            e.new_bbt_generation,
            e.new_ftl_generation,
            e.old_bbt_generation,
            e.fbb_count,
            e.rbb_count,
            e.old_rbb_erased,
        ),
        GradeEvidence::Physical(e) => (
            e.bbt_ftl_rebuilt,
            e.new_bbt_generation,
            e.new_ftl_generation,
            e.old_bbt_generation,
            e.fbb_count,
            e.rbb_count,
            e.old_rbb_erased,
        ),
        _ => return (None, Value::Null),
    };
    let ftl = json!({
        "rebuilt": rebuilt,
        "spare_ratio": plan_spare_ratio(plan),
        "bbt_generation": bbt_gen,
        "ftl_generation": ftl_gen,
    });
    let summary = json!({
        "old_bbt_generation": old_gen,
        "new_bbt_generation": bbt_gen,
        "new_ftl_generation": ftl_gen,
        "fbb_count": fbb,
        "rbb_count": rbb,
        "old_rbb_erased": rbb_erased,
    });
    (Some(ftl), summary)
}

/// Switch to the embedded fallback plan: record the switch in the journal,
/// reload the next-level fallback and rebind the current plan state.
/// Returns the error so the caller stops the run (never a silent skip).
fn switch_to_fallback(
    journal: &mut Journal,
    fallback_plan: &mut Option<Plan>,
    current: &mut std::rc::Rc<Plan>,
    skipping: &mut bool,
    evidence: &mut GradeEvidence,
    fb: &Plan,
) -> Result<()> {
    // Load and validate the next-level fallback first: a journal record of
    // a switch that never happened must not be left behind.
    let fb_owned = fb.clone();
    *fallback_plan = load_fallback_plan(fb)?;
    if let Err(je) = journal.record("fallback", "fallback-plan", |r| {
        r.plan_hash = Some(fb_owned.plan_hash.clone());
        r.plan = Some(serde_json::to_value(&fb_owned).unwrap());
    }) {
        return Err(Error::io(
            "journal",
            Some(std::io::Error::other(je.to_string())),
        ));
    }
    *current = std::rc::Rc::new(fb_owned);
    // The fallback plan's actions have never run: a resume skip anchored on
    // the previous plan's action id must not swallow them (the id does not
    // exist in the fallback plan, which would silently skip every action).
    *skipping = false;
    *evidence = new_evidence_for_plan(current);
    Ok(())
}

/// Fresh evidence for a plan, seeded with the documented device-erase scope
/// when the plan is a C2 plan (or the D5 exclusion for a C4 plan).
fn new_evidence_for_plan(plan: &Plan) -> GradeEvidence {
    if plan.expected_grade == "C4" {
        // A protected area (D5) documented in the plan is excluded from the
        // erased physical scope (residual documented-exclusion).
        let protected_area = plan
            .domains
            .iter()
            .find(|d| d.id == "D5")
            .map(|d| d.state == "present")
            .unwrap_or(false);
        let e = nclr::grade::PhysicalScopeEvidence {
            protected_area,
            ..Default::default()
        };
        return GradeEvidence::Physical(e);
    }
    if plan.expected_grade == "C3" {
        return GradeEvidence::Controller(nclr::grade::ControllerReinitEvidence::default());
    }
    if plan.expected_grade == "C2" {
        let mut e = nclr::grade::DeviceEraseEvidence::default();
        if let Some(action) = plan.action("device-user-area-erase") {
            let coverage = action
                .params
                .as_ref()
                .and_then(|p| p.get("coverage"))
                .and_then(|v| v.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false);
            e.scope_documented = coverage;
        }
        return GradeEvidence::Device(e);
    }
    GradeEvidence::Lba(LbaC1Evidence::default())
}

/// Apply one completed action's outcome to the running evidence. Also used
/// by `resume` to rebuild evidence from journal records.
/// Accumulate per-action outcome evidence. The expected capacity is the
/// planned device capacity, used to verify postcheck capacity stability.
#[allow(clippy::too_many_arguments)]
fn apply_outcome_to_evidence(
    evidence: &mut GradeEvidence,
    id: &str,
    status: &str,
    errs: u64,
    details: Option<&Value>,
    power_cycled: bool,
    expected_capacity_bytes: u64,
    health: &mut HealthEvidence,
) {
    let status_ok = status == "ok";
    match evidence {
        GradeEvidence::Lba(e) => {
            match id {
                "lba-prbs-write" | "lba-zero-write" => {
                    if status_ok && errs == 0 {
                        e.full_overwrite = true;
                    }
                }
                "lba-prbs-verify" => e.prbs_verify = status_ok && errs == 0,
                "lba-zero-verify" => e.zero_verify = status_ok && errs == 0,
                "flush" => {
                    e.flush_ok = status_ok && errs == 0;
                    health.flush_ok = e.flush_ok;
                    e.flush_latency_ms = details
                        .and_then(|d| d.get("flush_latency_ms"))
                        .and_then(|v| v.as_u64());
                }
                "signature-check" => e.signature_free = status_ok && errs == 0,
                "postcheck-l1" => {}
                _ => {}
            }
            // Health metrics: sweep throughput.
            if matches!(id, "lba-prbs-write" | "lba-prbs-verify") {
                e.throughput_mbps = details
                    .and_then(|d| d.get("throughput_mbps"))
                    .and_then(|v| v.as_f64());
            }
            if errs > 0 {
                e.io_errors += errs;
            }
            e.power_cycled = power_cycled;
        }
        GradeEvidence::Device(e) => {
            match id {
                "device-user-area-erase" => {
                    e.erase_completed = status_ok && errs == 0;
                }
                "blank-verify" => {
                    let uniform = details
                        .and_then(|d| d.get("uniform"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    let value = details
                        .and_then(|d| d.get("value"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let accepted_value = matches!(value, "0x00" | "0xff");
                    e.blank_verify = status_ok && errs == 0 && uniform && accepted_value;
                }
                "signature-check" => e.signature_free = status_ok && errs == 0,
                "postcheck-p2" => {
                    // Capacity stability is a real measurement: the backend
                    // re-queries the device geometry at postcheck time and
                    // it must match the planned capacity (spec §1169).
                    // Logical block size stability (§1170) is compared
                    // against the before-run identity after the run.
                    let measured = details
                        .and_then(|d| d.get("capacity_bytes"))
                        .and_then(|v| v.as_u64());
                    e.capacity_stable = status_ok && measured == Some(expected_capacity_bytes);
                    e.postcheck_reads_ok = status_ok
                        && details
                            .and_then(|d| d.get("all_reads_ok"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    e.postcheck_signature_free = status_ok
                        && details
                            .and_then(|d| d.get("signature_free"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    e.postcheck_flush_ok = status_ok
                        && details
                            .and_then(|d| d.get("flush_ok"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                }
                _ => {}
            }
            if errs > 0 {
                e.io_errors += errs;
            }
            e.power_cycled = power_cycled;
        }
        GradeEvidence::Controller(e) => {
            match id {
                "capture-old-bbt" => {
                    e.old_bbt_captured = status_ok && errs == 0;
                    e.old_bbt_sha256 = details
                        .and_then(|d| d.get("old_bbt_digest"))
                        .and_then(|v| v.as_str())
                        .map(str::to_owned);
                    e.old_bbt_copies = details
                        .and_then(|d| d.get("old_bbt_copies"))
                        .and_then(|v| v.as_u64());
                    e.old_bbt_generation = details
                        .and_then(|d| d.get("generation"))
                        .and_then(|v| v.as_u64());
                    e.fbb_count = details
                        .and_then(|d| d.get("fbb_count"))
                        .and_then(|v| v.as_u64());
                    e.rbb_count = details
                        .and_then(|d| d.get("old_rbb_count"))
                        .and_then(|v| v.as_u64());
                }
                "enter-service-mode" | "exit-service-mode" => {
                    if !status_ok {
                        e.io_errors += errs.max(1);
                    }
                }
                "erase-old-rbb" => {
                    // "partial" means attempted with some per-block failures
                    // (documented residual, not a protocol failure). The
                    // per-block failures are recorded separately and do not
                    // count as I/O errors.
                    let failed = details
                        .and_then(|d| d.get("failed"))
                        .and_then(|v| v.as_u64());
                    let erased = details
                        .and_then(|d| d.get("old_rbb_erased"))
                        .and_then(|v| v.as_u64())
                        .or_else(|| {
                            e.rbb_count
                                .zip(failed)
                                .and_then(|(total, failed)| total.checked_sub(failed))
                        });
                    let accounted = e.rbb_count.zip(erased).zip(failed).is_some_and(
                        |((total, erased), failed)| erased.checked_add(failed) == Some(total),
                    );
                    e.old_rbb_erase_attempted = matches!(status, "ok" | "partial") && accounted;
                    e.old_rbb_erase_failed = failed.unwrap_or(0);
                    e.old_rbb_erased = erased.unwrap_or(0);
                }
                "qualify-blocks" => {
                    // Qualification succeeded: weak/failed blocks were
                    // isolated from the user pool.
                    let qualified = details
                        .and_then(|d| d.get("qualified"))
                        .and_then(|v| v.as_u64());
                    let weak = details.and_then(|d| d.get("weak")).and_then(|v| v.as_u64());
                    let failed = details
                        .and_then(|d| d.get("failed"))
                        .and_then(|v| v.as_u64());
                    let qualification_total =
                        qualified
                            .zip(weak)
                            .zip(failed)
                            .and_then(|((qualified, weak), failed)| {
                                qualified.checked_add(weak)?.checked_add(failed)
                            });
                    e.weak_isolated = status_ok && qualification_total.is_some_and(|n| n > 0);
                    e.isolated_blocks = weak
                        .zip(failed)
                        .and_then(|(weak, failed)| weak.checked_add(failed))
                        .unwrap_or(u64::MAX);
                }
                "final-erase" => {
                    // Failures leave test data only on quarantined blocks;
                    // recorded as residual, not as an I/O error.
                    e.final_erase_failed = details
                        .and_then(|d| d.get("failed"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    e.fbb_preserved = details
                        .and_then(|d| d.get("fbb_preserved"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                }
                "rebuild-bbt-ftl" => {
                    e.new_bbt_committed = status_ok && errs == 0;
                    e.ftl_rebuilt = status_ok && errs == 0;
                    e.old_mapping_invalidated = details
                        .and_then(|d| d.get("old_mapping_invalidated"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    e.expected_capacity_bytes = details
                        .and_then(|d| d.get("capacity_bytes"))
                        .and_then(|v| v.as_u64());
                    e.new_bbt_generation = details
                        .and_then(|d| d.get("bbt_generation"))
                        .and_then(|v| v.as_u64());
                    e.new_ftl_generation = details
                        .and_then(|d| d.get("ftl_generation"))
                        .and_then(|v| v.as_u64());
                    e.spare_ok = details
                        .and_then(|d| d.get("spare_blocks"))
                        .and_then(|v| v.as_u64())
                        .map(|s| s > 0)
                        .unwrap_or(false);
                    // FBB protection is enforced by the backend; the sim model
                    // refuses FBB erases, so a successful run preserved it.
                }
                "re-enumeration" => {
                    // Service mode must have exited cleanly.
                    let in_service = details
                        .and_then(|d| d.get("service_mode"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    if in_service && status_ok {
                        e.io_errors += 1;
                    }
                }
                "postcheck-c3" => {
                    e.capacity_stable = details
                        .and_then(|d| d.get("capacity_stable"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    e.spare_ok = e.spare_ok
                        && details
                            .and_then(|d| d.get("spare_ok"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    e.logical_reads_ok = status_ok
                        && details
                            .and_then(|d| d.get("all_reads_ok"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    e.logical_blank_verified = status_ok
                        && details
                            .and_then(|d| d.get("blank_verified"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    e.signature_free = status_ok
                        && details
                            .and_then(|d| d.get("signature_free"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    e.flush_ok = status_ok
                        && details
                            .and_then(|d| d.get("flush_ok"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    e.flush_latency_ms = details
                        .and_then(|d| d.get("flush_latency_ms"))
                        .and_then(|v| v.as_u64());
                }
                _ => {}
            }
            if errs > 0 && id != "erase-old-rbb" && id != "final-erase" && id != "qualify-blocks" {
                e.io_errors += errs;
            }
            e.power_cycled = power_cycled;
        }
        GradeEvidence::Physical(e) => {
            match id {
                "enumerate-blocks" => {
                    let declared = details
                        .and_then(|d| d.get("total"))
                        .and_then(|v| v.as_u64());
                    let classified = details
                        .and_then(|d| d.get("categories"))
                        .and_then(|v| v.as_object())
                        .and_then(|categories| {
                            categories
                                .values()
                                .try_fold(0u64, |total, value| total.checked_add(value.as_u64()?))
                        });
                    e.blocks_declared = declared.unwrap_or(0);
                    e.blocks_classified = classified.unwrap_or(u64::MAX);
                    e.enumeration_complete = status_ok
                        && errs == 0
                        && declared.is_some_and(|total| total > 0)
                        && classified == declared;
                    // Only data-bearing blocks (non-FBB, non-unknown) are in
                    // the erase accounting.
                    e.blocks_enumerated = details
                        .and_then(|d| d.get("data_blocks"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    e.fbb_count = details
                        .and_then(|d| d.get("fbb_count"))
                        .and_then(|v| v.as_u64())
                        .or(e.fbb_count);
                    e.unknown_reservation = details
                        .and_then(|d| d.get("unknown"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                }
                "capture-old-bbt" => {
                    e.old_bbt_generation = details
                        .and_then(|d| d.get("generation"))
                        .and_then(|v| v.as_u64());
                    e.fbb_count = details
                        .and_then(|d| d.get("fbb_count"))
                        .and_then(|v| v.as_u64());
                    e.rbb_count = details
                        .and_then(|d| d.get("old_rbb_count"))
                        .and_then(|v| v.as_u64());
                    e.old_bbt_sha256 = details
                        .and_then(|d| d.get("old_bbt_digest"))
                        .and_then(|v| v.as_str())
                        .map(str::to_owned);
                    e.old_bbt_copies = details
                        .and_then(|d| d.get("old_bbt_copies"))
                        .and_then(|v| v.as_u64());
                    e.old_bbt_captured = status_ok
                        && errs == 0
                        && e.old_bbt_generation.is_some()
                        && e.fbb_count.is_some()
                        && e.rbb_count.is_some()
                        && e.old_bbt_copies.is_some_and(|copies| copies > 0)
                        && e.old_bbt_sha256.is_some();
                }
                "erase-old-rbb" => {
                    let failed = details
                        .and_then(|d| d.get("failed"))
                        .and_then(|v| v.as_u64());
                    let erased = details
                        .and_then(|d| d.get("old_rbb_erased"))
                        .and_then(|v| v.as_u64())
                        .or_else(|| {
                            e.rbb_count
                                .zip(failed)
                                .and_then(|(total, failed)| total.checked_sub(failed))
                        });
                    let accounted = e.rbb_count.zip(erased).zip(failed).is_some_and(
                        |((total, erased), failed)| erased.checked_add(failed) == Some(total),
                    );
                    e.old_rbb_erase_attempted = matches!(status, "ok" | "partial") && accounted;
                    e.old_rbb_erase_failed = failed.unwrap_or(0);
                    e.old_rbb_erased = erased.unwrap_or(0);
                }
                "erase-data-blocks" => {
                    e.blocks_erased = details
                        .and_then(|d| d.get("system_erased"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    e.blocks_erase_failed = 0;
                }
                "qualify-blocks" => {
                    let qualified = details
                        .and_then(|d| d.get("qualified"))
                        .and_then(|v| v.as_u64());
                    let weak = details.and_then(|d| d.get("weak")).and_then(|v| v.as_u64());
                    let failed = details
                        .and_then(|d| d.get("failed"))
                        .and_then(|v| v.as_u64());
                    let qualification_total =
                        qualified
                            .zip(weak)
                            .zip(failed)
                            .and_then(|((qualified, weak), failed)| {
                                qualified.checked_add(weak)?.checked_add(failed)
                            });
                    e.weak_isolated = status_ok && qualification_total.is_some_and(|n| n > 0);
                    e.isolated_blocks = weak
                        .zip(failed)
                        .and_then(|(weak, failed)| weak.checked_add(failed))
                        .unwrap_or(u64::MAX);
                }
                "final-erase" => {
                    e.blocks_erased = e.blocks_erased.saturating_add(
                        details
                            .and_then(|d| d.get("erased"))
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0),
                    );
                    e.blocks_erase_failed = e.blocks_erase_failed.saturating_add(
                        details
                            .and_then(|d| d.get("failed"))
                            .and_then(|v| v.as_u64())
                            .unwrap_or(0),
                    );
                    e.fbb_preserved = details
                        .and_then(|d| d.get("fbb_preserved"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                }
                "verify-physical-erasure" => {
                    let total_pages = details
                        .and_then(|d| d.get("total_pages"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let readable_pages = details
                        .and_then(|d| d.get("readable_pages"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let unreadable_pages = details
                        .and_then(|d| d.get("unreadable_pages"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    e.physical_sweep_complete = total_pages > 0
                        && readable_pages.saturating_add(unreadable_pages) == total_pages;
                    e.physical_pages = total_pages;
                    e.physical_readable_pages = readable_pages;
                    e.physical_unreadable_pages = unreadable_pages;
                    e.physical_uncorrectable_pages = details
                        .and_then(|d| d.get("uncorrectable_pages"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    e.ordered_sweep_sha256 = details
                        .and_then(|d| d.get("ordered_sweep_sha256"))
                        .and_then(|v| v.as_str())
                        .map(str::to_owned);
                    e.target_pages = details
                        .and_then(|d| d.get("target_pages"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    e.target_readable_pages = details
                        .and_then(|d| d.get("target_readable_pages"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    e.target_unreadable_pages = details
                        .and_then(|d| d.get("target_unreadable_pages"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(e.target_pages);
                    e.target_uncorrectable_pages = details
                        .and_then(|d| d.get("target_uncorrectable_pages"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(e.target_pages);
                    e.target_non_erased_pages = details
                        .and_then(|d| d.get("target_non_erased_pages"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(e.target_pages);
                    e.excluded_unreadable_pages = details
                        .and_then(|d| d.get("excluded_unreadable_pages"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or_else(|| {
                            unreadable_pages.saturating_sub(e.target_unreadable_pages)
                        });
                }
                "enter-service-mode" | "exit-service-mode" => {
                    if !status_ok {
                        e.io_errors += errs.max(1);
                    }
                }
                "rebuild-bbt-ftl" => {
                    e.bbt_ftl_rebuilt = status_ok && errs == 0;
                    e.old_mapping_invalidated = details
                        .and_then(|d| d.get("old_mapping_invalidated"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    e.expected_capacity_bytes = details
                        .and_then(|d| d.get("capacity_bytes"))
                        .and_then(|v| v.as_u64());
                    e.spare_ok = details
                        .and_then(|d| d.get("spare_blocks"))
                        .and_then(|v| v.as_u64())
                        .map(|s| s > 0)
                        .unwrap_or(false);
                    e.new_bbt_generation = details
                        .and_then(|d| d.get("bbt_generation"))
                        .and_then(|v| v.as_u64());
                    e.new_ftl_generation = details
                        .and_then(|d| d.get("ftl_generation"))
                        .and_then(|v| v.as_u64());
                }
                "re-enumeration" => {
                    let in_service = details
                        .and_then(|d| d.get("service_mode"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true);
                    if in_service && status_ok {
                        e.io_errors += 1;
                    }
                }
                "postcheck-c4" => {
                    e.capacity_stable = details
                        .and_then(|d| d.get("capacity_stable"))
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false);
                    e.spare_ok = e.spare_ok
                        && details
                            .and_then(|d| d.get("spare_ok"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    e.logical_reads_ok = status_ok
                        && details
                            .and_then(|d| d.get("all_reads_ok"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    e.logical_blank_verified = status_ok
                        && details
                            .and_then(|d| d.get("blank_verified"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    e.signature_free = status_ok
                        && details
                            .and_then(|d| d.get("signature_free"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    e.flush_ok = status_ok
                        && details
                            .and_then(|d| d.get("flush_ok"))
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);
                    e.flush_latency_ms = details
                        .and_then(|d| d.get("flush_latency_ms"))
                        .and_then(|v| v.as_u64());
                    let unknown = details
                        .and_then(|d| d.get("unknown_reservation"))
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    e.unknown_reservation = e.unknown_reservation.max(unknown);
                }
                _ => {}
            }
            if errs > 0
                && id != "erase-old-rbb"
                && id != "final-erase"
                && id != "erase-data-blocks"
                && id != "qualify-blocks"
                && id != "verify-physical-erasure"
            {
                e.io_errors += errs;
            }
            e.power_cycled = power_cycled;
        }
    }
}

/// Execute the plan actions (shared by run and resume). Supports C2 plans
/// (device erase with status monitoring) and the documented fallback to the
/// embedded L1 plan when the device erase is unavailable.
/// Append per-block evidence (NDJSON) for an action result.
fn write_evidence(
    path: Option<&Path>,
    plan_hash: &str,
    action_id: &str,
    details: Option<&Value>,
) -> Result<()> {
    let Some(path) = path else { return Ok(()) };
    let Some(details) = details else {
        return Ok(());
    };
    let Some(per_block) = details.get("per_block").and_then(|v| v.as_array()) else {
        return Ok(());
    };
    let format = details.get("per_block_format").cloned();
    use std::io::Write;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    const MAX_EVIDENCE_BYTES: u64 = 512 * 1024 * 1024;
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|e| Error::io(format!("open evidence {}", path.display()), Some(e)))?;
    let metadata = f
        .metadata()
        .map_err(|e| Error::io(format!("stat evidence {}", path.display()), Some(e)))?;
    if !metadata.is_file()
        || metadata.uid() != nclr::journal::nix_uid()
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_EVIDENCE_BYTES
    {
        return Err(Error::Permission(format!(
            "evidence {} must be a current-user 0600 regular file no larger than {MAX_EVIDENCE_BYTES} bytes",
            path.display()
        )));
    }
    let mut written = metadata.len();
    for rec in per_block {
        // The block identity is the record's physical coordinate: a flat
        // array form, an explicit `flat` field, or the `block` key used by
        // the block-level evidence records.
        let flat = rec
            .as_array()
            .and_then(|values| values.first())
            .and_then(|value| value.as_u64())
            .or_else(|| rec.get("flat").and_then(|value| value.as_u64()))
            .or_else(|| rec.get("block").and_then(|value| value.as_u64()));
        let line = serde_json::json!({
            "plan_hash": plan_hash,
            "action": action_id,
            "record_key": flat.map(|value| format!("{plan_hash}:{action_id}:{value}")),
            "format": format.clone(),
            "record": rec,
        });
        let mut b = serde_json::to_vec(&line)
            .map_err(|e| Error::Invalid(format!("evidence serialization: {e}")))?;
        b.push(b'\n');
        if written
            .checked_add(b.len() as u64)
            .is_none_or(|length| length > MAX_EVIDENCE_BYTES)
        {
            return Err(Error::Invalid(format!(
                "evidence {} would exceed {MAX_EVIDENCE_BYTES} bytes",
                path.display()
            )));
        }
        f.write_all(&b)
            .map_err(|e| Error::io(format!("write evidence {}", path.display()), Some(e)))?;
        written += b.len() as u64;
    }
    f.sync_all()
        .map_err(|e| Error::io(format!("sync evidence {}", path.display()), Some(e)))?;
    Ok(())
}

/// Resolve the evidence file path for a run (or None).
fn evidence_path_for(opts: &RunOptions, plan_id: &str) -> Result<Option<PathBuf>> {
    let Some(dir) = opts.evidence_dir.as_ref() else {
        return Ok(None);
    };
    std::fs::create_dir_all(dir).map_err(|e| {
        Error::io(
            format!("cannot create evidence dir {}", dir.display()),
            Some(e),
        )
    })?;
    Ok(Some(dir.join(format!("{plan_id}.blocks.ndjson"))))
}

/// SHA-256 of the evidence file (hex), if present.
fn evidence_digest(path: Option<&Path>) -> Result<Option<String>> {
    let Some(path) = path else {
        return Ok(None);
    };
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    const MAX_EVIDENCE_BYTES: u64 = 512 * 1024 * 1024;
    let mut file = match std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(Error::io(
                format!("cannot open evidence {}", path.display()),
                Some(error),
            ))
        }
    };
    let metadata = file
        .metadata()
        .map_err(|error| Error::io(format!("stat evidence {}", path.display()), Some(error)))?;
    if !metadata.is_file()
        || metadata.uid() != nclr::journal::nix_uid()
        || metadata.mode() & 0o077 != 0
        || metadata.len() > MAX_EVIDENCE_BYTES
    {
        return Err(Error::Permission(format!(
            "evidence {} is not a bounded current-user 0600 regular file",
            path.display()
        )));
    }
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    let mut chunk = [0u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut chunk)
            .map_err(|error| Error::io(format!("read evidence {}", path.display()), Some(error)))?;
        if read == 0 {
            break;
        }
        h.update(&chunk[..read]);
    }
    Ok(Some(hex::encode(h.finalize())))
}

#[allow(clippy::too_many_arguments)]
fn execute_plan_actions(
    plan: &Plan,
    handle: &BackendHandle,
    device_path: &str,
    device_fd: &mut OwnedFd,
    journal: &mut Journal,
    opts: &RunOptions,
    resume_after_seq: Option<u32>,
    initial_evidence: Option<GradeEvidence>,
    evidence_path: Option<&Path>,
    reenum_nonce: &str,
    accepted_fingerprints: &[String],
    backend_extras: &mut Vec<(OwnedFd, String)>,
) -> (
    ResultStatus,
    Vec<ActionRecord>,
    GradeEvidence,
    HealthEvidence,
    String,
) {
    let resuming = initial_evidence.is_some() || resume_after_seq.is_some();
    let destructive_workflow = plan.actions.iter().any(|action| action.kind.destructive());
    let event_output: Option<OwnedFd> = opts
        .events_fd
        .filter(|n| *n >= 0)
        .map(|n| unsafe { std::os::fd::OwnedFd::from_raw_fd(n) });
    let (events_owned, event_relay) = match nclr::events::EventRelay::start(event_output) {
        Ok(relay) => relay,
        Err(error) => {
            eprintln!("nclr: event relay startup failed: {error}");
            return (
                ResultStatus::Failed,
                Vec::new(),
                initial_evidence.unwrap_or_else(|| new_evidence_for_plan(plan)),
                HealthEvidence::default(),
                device_path.to_string(),
            );
        }
    };
    let events_clone = match events_owned
        .as_ref()
        .map(|file| file.try_clone())
        .transpose()
    {
        Ok(clone) => clone,
        Err(error) => {
            eprintln!("nclr: event fd clone failed: {error}");
            drop(events_owned);
            if let Some(relay) = event_relay {
                let _ = relay.finish();
            }
            return (
                ResultStatus::Failed,
                Vec::new(),
                initial_evidence.unwrap_or_else(|| new_evidence_for_plan(plan)),
                HealthEvidence::default(),
                device_path.to_string(),
            );
        }
    };
    let mut events = nclr::events::EventWriter::from_owned(events_clone);
    let events_ref = events_owned.as_ref();
    let mut actions: Vec<ActionRecord> = Vec::new();
    let mut health = HealthEvidence::default();
    let mut evidence = initial_evidence.unwrap_or_else(|| new_evidence_for_plan(plan));
    let device_is_file = device::is_regular_file(device_path);
    let mut runtime_device_path = device_path.to_string();
    let mut power_cycled = evidence.power_cycled();
    let mut fatal = None;
    let mut interrupted = false;
    let mut fallback_used = false;

    // Current plan under execution; switches to the embedded fallback plan
    // when a primary action fails and fallback is allowed. An invalid
    // fallback plan is a plan-integrity failure, never a silent skip.
    let mut fallback_plan: Option<Plan> = match load_fallback_plan(plan) {
        Ok(fb) => fb,
        Err(e) => {
            fatal = Some(e);
            None
        }
    };
    let mut current: std::rc::Rc<Plan> = std::rc::Rc::new(plan.clone());
    // Accepted identities grow while running: a controller rebuild commits a
    // possibly reduced capacity, which changes the fingerprint (recorded as
    // "capacity-committed"). The re-enumeration check must accept those.
    let mut accepted_identities: Vec<String> = accepted_fingerprints.to_vec();
    // Baseline identity anchors the physical-media check after a
    // re-enumeration: the same physical media may change its capacity (or,
    // with a certified profile, its reported identity), but it can never
    // turn into a different card.
    let baseline_identity = device::identify(device_path).ok();

    let mut skipping = resume_after_seq.is_some();

    'plans: while !current.actions.is_empty() {
        // Clone the action list so the fallback switch can reassign
        // `current` without aliasing the iterator.
        let action_list = current.actions.clone();
        for action in &action_list {
            if let Some(completed_seq) = resume_after_seq {
                // L1 deliberately contains two flush and two power-cycle
                // actions, so the action name cannot identify a resume
                // boundary. The immutable plan sequence can.
                if action.seq <= completed_seq {
                    continue;
                }
                skipping = false;
            }

            if nclr::signal::requested() {
                interrupted = true;
                break 'plans;
            }
            let action_started = std::time::Instant::now();

            let _ = events.emit("action", |e| e.action = Some(action.id.clone()));
            if !opts.quiet {
                eprintln!(
                    "nclr: action {}/{} {}",
                    action.seq,
                    current.actions.len(),
                    action.id
                );
            }
            if let Err(e) = journal.record("action", "action-started", |r| {
                r.action = Some(action.id.clone());
                r.plan_hash = Some(current.plan_hash.clone());
            }) {
                fatal = Some(Error::io(
                    "journal",
                    Some(std::io::Error::other(e.to_string())),
                ));
                break 'plans;
            }

            let outcome = match &action.kind {
                nclr::plan::ActionKind::PowerCycle => {
                    match action.method.as_ref().unwrap_or(&PowerCycleMethod::None) {
                        PowerCycleMethod::SimInternal => {
                            match run_backend_action(
                                handle,
                                backend_io_for(
                                    &*device_fd,
                                    backend_extras.as_slice(),
                                    &runtime_device_path,
                                ),
                                events_ref,
                                action,
                                &current.plan_hash,
                                action.timeout_secs.or(opts.backend_timeout),
                                None,
                            ) {
                                Ok(resp) if resp.ok() => {
                                    power_cycled = true;
                                    let mut o = outcome_from_response(&resp);
                                    if o.record.id == "?" {
                                        o.record.id = action.id.clone();
                                    }
                                    o
                                }
                                Ok(resp) => {
                                    power_cycled = false;
                                    let mut o = outcome_from_response(&resp);
                                    if o.record.id == "?" {
                                        o.record.id = action.id.clone();
                                    }
                                    o
                                }
                                // A backend timeout is a resumable
                                // interruption (exit 75), not a fatal
                                // failure: the run stops and resume
                                // re-queries the device state.
                                Err(Error::Interrupted(msg)) => {
                                    interrupted = true;
                                    if !opts.quiet {
                                        eprintln!("nclr: {msg}");
                                    }
                                    break 'plans;
                                }
                                Err(e) => {
                                    fatal = Some(e);
                                    break 'plans;
                                }
                            }
                        }
                        PowerCycleMethod::External => {
                            match nclr::powercycle::power_cycle(
                                &PowerCycleMethod::External,
                                opts.power_cycle.as_deref(),
                            ) {
                                Ok(()) => {
                                    power_cycled = true;
                                    ActionOutcome {
                                        record: ActionRecord {
                                            id: action.id.clone(),
                                            status: "ok".into(),
                                            retries: Some(0),
                                            errors: None,
                                            duration_ms: None,
                                            message: None,
                                        },
                                        errors: 0,
                                        details: None,
                                    }
                                }
                                Err(e) => {
                                    fatal = Some(e);
                                    break 'plans;
                                }
                            }
                        }
                        PowerCycleMethod::None => {
                            // A --power-cycle command at run time upgrades the
                            // plan's "none" method; otherwise the evidence gap
                            // is recorded as a documented exclusion.
                            if let Some(cmd) = &opts.power_cycle {
                                match nclr::powercycle::power_cycle(
                                    &PowerCycleMethod::External,
                                    Some(cmd),
                                ) {
                                    Ok(()) => {
                                        power_cycled = true;
                                        ActionOutcome {
                                            record: ActionRecord {
                                                id: action.id.clone(),
                                                status: "ok".into(),
                                                retries: Some(0),
                                                errors: None,
                                                duration_ms: None,
                                                message: Some(
                                                    "power cycle via --power-cycle".into(),
                                                ),
                                            },
                                            errors: 0,
                                            details: None,
                                        }
                                    }
                                    Err(e) => {
                                        fatal = Some(e);
                                        break 'plans;
                                    }
                                }
                            } else {
                                // Evidence gap: documented exclusion.
                                ActionOutcome {
                                    record: ActionRecord {
                                        id: action.id.clone(),
                                        status: "skipped".into(),
                                        retries: Some(0),
                                        errors: None,
                                        duration_ms: None,
                                        message: Some("no power control configured".into()),
                                    },
                                    errors: 0,
                                    details: None,
                                }
                            }
                        }
                    }
                }
                _ => {
                    // Device erase: start (IMMED) and monitor; all other
                    // actions are single backend calls.
                    // §1261-1263: a resumed run must not re-issue a
                    // self-running erase. Query the backend status first:
                    // an operation already running is monitored, a
                    // completed one is recorded, a failed one is reported
                    // (no unconditional retransmission, §1215/§1431). Only
                    // a backend without sanitize state (sd-native/lba)
                    // re-issues normally: their erase commands are
                    // idempotent full-range operations, so a re-issue is
                    // safe (§1255: safe re-execution is equivalent to
                    // verified state).
                    let mut resumed: Option<ActionOutcome> = None;
                    if resuming && action.id == "device-user-area-erase" {
                        match query_erase_state(
                            handle,
                            backend_io_for(
                                &*device_fd,
                                backend_extras.as_slice(),
                                &runtime_device_path,
                            ),
                            events_ref,
                            &mut events,
                            opts,
                            action,
                        ) {
                            Ok(EraseStateQuery::Verdict(o)) => resumed = Some(o),
                            Ok(EraseStateQuery::NoState) => {}
                            // The state query failed: re-issuing a
                            // destructive command with an unknown state is
                            // forbidden (§1215), so this is fatal on resume.
                            Ok(EraseStateQuery::QueryFailed) => {
                                fatal = Some(Error::Io(
                                    "cannot determine the device erase state on resume".into(),
                                    None,
                                ));
                                break 'plans;
                            }
                            // A stalled monitor is a resumable stop
                            // (exit 75): resume can re-query the state.
                            Err(Error::Interrupted(msg)) => {
                                interrupted = true;
                                if !opts.quiet {
                                    eprintln!("nclr: {msg}");
                                }
                                break 'plans;
                            }
                            Err(e) => {
                                fatal = Some(e);
                                break 'plans;
                            }
                        }
                    }
                    let action_result: Result<ActionOutcome> = if let Some(o) = resumed {
                        Ok(o)
                    } else if action.id == "device-user-area-erase" {
                        match run_backend_action(
                            handle,
                            backend_io_for(
                                &*device_fd,
                                backend_extras.as_slice(),
                                &runtime_device_path,
                            ),
                            events_ref,
                            action,
                            &current.plan_hash,
                            action.timeout_secs.or(opts.backend_timeout),
                            None,
                        ) {
                            Err(e) => Err(e),
                            Ok(resp) => {
                                if !resp.ok() {
                                    Err(Error::Backend(resp.message()))
                                } else {
                                    let started = resp
                                        .value
                                        .get("action_results")
                                        .and_then(|v| v.as_array())
                                        .and_then(|a| a.first())
                                        .and_then(|r| r.get("started"))
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);
                                    let completed_immediately = resp
                                        .value
                                        .get("action_results")
                                        .and_then(|v| v.as_array())
                                        .and_then(|a| a.first())
                                        .and_then(|r| r.get("completed"))
                                        .and_then(|v| v.as_bool())
                                        .unwrap_or(false);
                                    if started && !completed_immediately {
                                        monitor_device_erase(
                                            handle,
                                            backend_io_for(
                                                &*device_fd,
                                                backend_extras.as_slice(),
                                                &runtime_device_path,
                                            ),
                                            events_ref,
                                            &mut events,
                                            opts,
                                            action,
                                        )
                                    } else {
                                        let mut o = outcome_from_response(&resp);
                                        if o.record.id == "?" {
                                            o.record.id = action.id.clone();
                                        }
                                        Ok(o)
                                    }
                                }
                            }
                        }
                    } else if matches!(
                        action.id.as_str(),
                        "enter-service-mode" | "exit-service-mode"
                    ) && handle.id == "controller"
                    {
                        // Controller service entry may contain two USB reset
                        // boundaries: the vendor entry command and an optional
                        // RAM-loader start. The controller state file makes
                        // each boundary durable; the trusted core reopens only
                        // the block/sg nodes found at the original physical
                        // USB path and then repeats this action so the backend
                        // can advance to the next durable stage.
                        (|| -> Result<ActionOutcome> {
                            let mut transitions = 0u8;
                            loop {
                                let run_params = json!({ "nonce": reenum_nonce });
                                let resp = run_backend_action(
                                    handle,
                                    backend_io_for(
                                        &*device_fd,
                                        backend_extras.as_slice(),
                                        &runtime_device_path,
                                    ),
                                    events_ref,
                                    action,
                                    &current.plan_hash,
                                    action.timeout_secs.or(opts.backend_timeout),
                                    Some(&run_params),
                                )?;
                                if !resp.ok() {
                                    break Err(Error::Backend(resp.message()));
                                }
                                let awaiting = resp
                                    .value
                                    .get("action_results")
                                    .and_then(|v| v.as_array())
                                    .and_then(|values| values.first())
                                    .and_then(|value| value.get("awaiting_device"))
                                    .and_then(|v| v.as_bool())
                                    .unwrap_or(false);
                                if !awaiting {
                                    let mut outcome = outcome_from_response(&resp);
                                    if outcome.record.id == "?" {
                                        outcome.record.id = action.id.clone();
                                    }
                                    break Ok(outcome);
                                }

                                transitions = transitions.saturating_add(1);
                                let maximum_transitions = if action.id == "enter-service-mode" {
                                    2
                                } else {
                                    1
                                };
                                if transitions > maximum_transitions {
                                    break Err(Error::Invalid(
                                        "controller requested too many service-mode re-enumerations"
                                            .into(),
                                    ));
                                }
                                journal_awaiting_device(
                                journal,
                                &runtime_device_path,
                                "controller service-mode transition is awaiting USB re-enumeration",
                            );
                                if device_is_file {
                                    break Err(Error::Invalid(
                                    "a file-backed controller cannot request USB re-enumeration"
                                        .into(),
                                ));
                                }

                                let deadline = std::time::Instant::now()
                                    + std::time::Duration::from_secs(REENUM_WAIT_SECS);
                                let rebound = loop {
                                    match reopen_controller_transport(
                                        &plan.device.physical_path,
                                        opts.allow_nonremovable,
                                        destructive_workflow,
                                        device_fd,
                                        backend_extras,
                                    ) {
                                        Ok(identity) => break Ok(identity),
                                        Err(Error::Io(_, _))
                                            if std::time::Instant::now() < deadline =>
                                        {
                                            std::thread::sleep(std::time::Duration::from_millis(
                                                500,
                                            ));
                                        }
                                        Err(e) => break Err(e),
                                    }
                                }?;
                                if rebound.physical_path != plan.device.physical_path {
                                    break Err(Error::Permission(format!(
                                        "controller reappeared at {}, expected {}",
                                        rebound.physical_path, plan.device.physical_path
                                    )));
                                }
                                runtime_device_path = rebound.kernel_path.clone();
                                if !accepted_identities.contains(&rebound.fingerprint) {
                                    accepted_identities.push(rebound.fingerprint.clone());
                                }
                                journal
                                    .record("reidentify", "service-reenumerated", |record| {
                                        record.device = Some(rebound.fingerprint.clone());
                                        record.device_path = Some(rebound.kernel_path.clone());
                                        record.plan_hash = Some(current.plan_hash.clone());
                                        record.message = Some(format!(
                                            "controller service transition {} completed",
                                            transitions
                                        ));
                                    })
                                    .map_err(|e| {
                                        Error::io(
                                            "journal",
                                            Some(std::io::Error::other(e.to_string())),
                                        )
                                    })?;
                            }
                        })()
                    } else if action.id == "re-enumeration" {
                        // Re-enumeration after service mode / power cycle:
                        // the device may legitimately disappear and reappear.
                        // Wait (bounded), run the backend action with the run
                        // nonce, then re-identify the device to prove we
                        // still hold the same media (spec §836).
                        let deadline = std::time::Instant::now()
                            + std::time::Duration::from_secs(REENUM_WAIT_SECS);
                        let outcome: Option<ActionOutcome> = loop {
                            if handle.id == "controller" && !device_is_file {
                                match reopen_controller_transport(
                                    &plan.device.physical_path,
                                    opts.allow_nonremovable,
                                    destructive_workflow,
                                    device_fd,
                                    backend_extras,
                                ) {
                                    Ok(identity) => {
                                        runtime_device_path = identity.kernel_path.clone();
                                    }
                                    Err(Error::Io(_, _))
                                        if std::time::Instant::now() < deadline =>
                                    {
                                        std::thread::sleep(std::time::Duration::from_millis(500));
                                        continue;
                                    }
                                    Err(e) => {
                                        fatal = Some(e);
                                        break 'plans;
                                    }
                                }
                            }
                            if !device_is_file
                                && !std::path::Path::new(&runtime_device_path).exists()
                            {
                                if std::time::Instant::now() >= deadline {
                                    journal_awaiting_device(
                                        journal,
                                        &runtime_device_path,
                                        "device did not reappear within the re-enumeration window",
                                    );
                                    fatal = Some(Error::Io(
                                        format!(
                                            "device {runtime_device_path} did not reappear after re-enumeration"
                                        ),
                                        None,
                                    ));
                                    break 'plans;
                                }
                                std::thread::sleep(std::time::Duration::from_millis(500));
                                continue;
                            }
                            let run_params = json!({ "nonce": reenum_nonce });
                            match run_backend_action(
                                handle,
                                backend_io_for(
                                    &*device_fd,
                                    backend_extras.as_slice(),
                                    &runtime_device_path,
                                ),
                                events_ref,
                                action,
                                &current.plan_hash,
                                action.timeout_secs.or(opts.backend_timeout),
                                Some(&run_params),
                            ) {
                                Ok(r) => {
                                    // Backends that support tracking echo the
                                    // nonce; a mismatch means the device came
                                    // back as something else. A correct echo
                                    // anchors the re-enumeration (spec §836),
                                    // so VID/PID/serial changes recorded in
                                    // service mode are acceptable as long as
                                    // the device reappears on the same port
                                    // chain.
                                    let mut nonce_verified = false;
                                    // The nonce is echoed in the action
                                    // result; accept it at the response top
                                    // level as well for forward compat.
                                    let echo =
                                        r.value.get("nonce").and_then(|v| v.as_str()).or_else(
                                            || {
                                                r.value
                                                    .get("action_results")
                                                    .and_then(|v| v.as_array())
                                                    .and_then(|a| a.first())
                                                    .and_then(|ar| ar.get("nonce"))
                                                    .and_then(|v| v.as_str())
                                            },
                                        );
                                    if let Some(echo) = echo {
                                        if echo != reenum_nonce {
                                            journal_awaiting_device(
                                                journal,
                                                &runtime_device_path,
                                                "re-enumeration nonce mismatch",
                                            );
                                            fatal = Some(Error::Permission(format!(
                                                "re-enumeration nonce mismatch (expected {reenum_nonce}, got {echo})"
                                            )));
                                            break 'plans;
                                        }
                                        nonce_verified = true;
                                    }
                                    // Re-identify: the device must match the
                                    // plan (or an accepted post-commit
                                    // identity), or be the same media whose
                                    // identity changed during the rebuild.
                                    // For real devices a verified nonce plus
                                    // an unchanged port chain (physical path)
                                    // is the spec §836 tracking anchor, so
                                    // VID/PID/serial changes are accepted;
                                    // the sim/file family keeps the strict
                                    // physical-media check (a swapped image
                                    // must never pass). Anything else is a
                                    // swapped device and fatal.
                                    match device::identify(&runtime_device_path) {
                                        Ok(id) if accepted_identities.contains(&id.fingerprint) => {
                                            if let Err(error) = journal.record(
                                                "reidentify",
                                                "device-reenumerated",
                                                |record| {
                                                    record.device = Some(id.fingerprint.clone());
                                                    record.device_path =
                                                        Some(id.kernel_path.clone());
                                                    record.plan_hash =
                                                        Some(current.plan_hash.clone());
                                                },
                                            ) {
                                                fatal = Some(Error::io(
                                                    "journal",
                                                    Some(std::io::Error::other(error.to_string())),
                                                ));
                                                break 'plans;
                                            }
                                            let mut o = outcome_from_response(&r);
                                            if o.record.id == "?" {
                                                o.record.id = action.id.clone();
                                            }
                                            break Some(o);
                                        }
                                        Ok(id)
                                            if baseline_identity.as_ref().is_some_and(|b| {
                                                // The sim/file family is
                                                // strict ("file" is a plain
                                                // file, "file-sim" a sim
                                                // image); real devices use
                                                // the nonce+port-chain anchor.
                                                let strict = matches!(
                                                    b.transport.as_str(),
                                                    "file" | "file-sim"
                                                );
                                                if strict {
                                                    device::same_physical_media(b, &id)
                                                } else {
                                                    nonce_verified
                                                        && b.physical_path == id.physical_path
                                                }
                                            }) =>
                                        {
                                            if !accepted_identities.contains(&id.fingerprint) {
                                                accepted_identities.push(id.fingerprint.clone());
                                            }
                                            if let Err(je) = journal.record(
                                                "reidentify",
                                                "device-reenumerated",
                                                |rec| {
                                                    rec.device = Some(id.fingerprint);
                                                    rec.device_path = Some(id.kernel_path.clone());
                                                    rec.plan_hash = Some(current.plan_hash.clone());
                                                },
                                            ) {
                                                fatal = Some(Error::io(
                                                    "journal",
                                                    Some(std::io::Error::other(je.to_string())),
                                                ));
                                                break 'plans;
                                            }
                                            let mut o = outcome_from_response(&r);
                                            if o.record.id == "?" {
                                                o.record.id = action.id.clone();
                                            }
                                            break Some(o);
                                        }
                                        Ok(id) => {
                                            journal_awaiting_device(
                                                journal,
                                                &runtime_device_path,
                                                "device identity changed after re-enumeration",
                                            );
                                            fatal = Some(Error::Permission(format!(
                                                "device identity changed after re-enumeration ({})",
                                                id.fingerprint
                                            )));
                                            break 'plans;
                                        }
                                        Err(e) if device_is_file => {
                                            fatal = Some(e);
                                            break 'plans;
                                        }
                                        Err(_) => {
                                            if std::time::Instant::now() >= deadline {
                                                journal_awaiting_device(
                                                    journal,
                                                    &runtime_device_path,
                                                    "device did not reappear within the re-enumeration window",
                                                );
                                                fatal = Some(Error::Io(
                                                    format!(
                                                        "device {runtime_device_path} did not reappear after re-enumeration"
                                                    ),
                                                    None,
                                                ));
                                                break 'plans;
                                            }
                                            std::thread::sleep(std::time::Duration::from_millis(
                                                500,
                                            ));
                                            continue;
                                        }
                                    }
                                }
                                Err(e) => {
                                    if !device_is_file && std::time::Instant::now() < deadline {
                                        std::thread::sleep(std::time::Duration::from_millis(500));
                                        continue;
                                    }
                                    fatal = Some(e);
                                    break 'plans;
                                }
                            }
                        };
                        outcome.ok_or_else(|| {
                            Error::Backend("re-enumeration ended without a backend outcome".into())
                        })
                    } else {
                        match run_backend_action(
                            handle,
                            backend_io_for(
                                &*device_fd,
                                backend_extras.as_slice(),
                                &runtime_device_path,
                            ),
                            events_ref,
                            action,
                            &current.plan_hash,
                            action.timeout_secs.or(opts.backend_timeout),
                            None,
                        ) {
                            Ok(r) => {
                                let mut o = outcome_from_response(&r);
                                if o.record.id == "?" {
                                    o.record.id = action.id.clone();
                                }
                                Ok(o)
                            }
                            Err(e) => {
                                // LBA PRBS write failure with fallback
                                // allowed: continue with the zero path
                                // rather than aborting.
                                if action.id == "lba-prbs-write" && !current.no_fallback {
                                    fallback_used = true;
                                    if !opts.quiet {
                                        eprintln!("nclr: warning: lba-prbs-write failed; falling back to zero-only (degraded)");
                                    }
                                    Ok(ActionOutcome {
                                        record: ActionRecord {
                                            id: action.id.clone(),
                                            status: "fallback".into(),
                                            retries: Some(0),
                                            errors: Some(1),
                                            duration_ms: None,
                                            message: Some(e.to_string()),
                                        },
                                        errors: 1,
                                        details: None,
                                    })
                                } else {
                                    Err(e)
                                }
                            }
                        }
                    };

                    // A fallback-listed action that failed (at the transport
                    // OR the action level) switches to the embedded plan.
                    let fallback_entry = current.fallback.iter().any(|f| f.from == action.id);
                    let action_outcome = match action_result {
                        Ok(o) => o,
                        Err(Error::Interrupted(_)) => {
                            interrupted = true;
                            break 'plans;
                        }
                        Err(e) => {
                            // §1215: a timed-out destructive command may
                            // still be running inside the device (a
                            // blocking SANITIZE or a CMD38 that exceeded
                            // its busy budget). Ask the backend before
                            // falling back: an in-progress or completed
                            // erase is monitored/recorded, a status query
                            // failure still falls through to the error path.
                            let mut erase_verdict: Option<ActionOutcome> = None;
                            if action.id == "device-user-area-erase" {
                                match query_erase_state(
                                    handle,
                                    backend_io_for(
                                        &*device_fd,
                                        backend_extras.as_slice(),
                                        &runtime_device_path,
                                    ),
                                    events_ref,
                                    &mut events,
                                    opts,
                                    action,
                                ) {
                                    Ok(EraseStateQuery::Verdict(o)) => erase_verdict = Some(o),
                                    Ok(EraseStateQuery::NoState) => {}
                                    // Unknown device state after a failed
                                    // erase command: fall back without
                                    // re-issuing, but say so.
                                    Ok(EraseStateQuery::QueryFailed) => {
                                        if !opts.quiet {
                                            eprintln!(
                                                "nclr: warning: device erase state unknown after failure; falling back"
                                            );
                                        }
                                    }
                                    // A stalled monitor must never fall
                                    // back to writes against a possibly
                                    // running erase: stop resumably.
                                    Err(Error::Interrupted(msg)) => {
                                        interrupted = true;
                                        if !opts.quiet {
                                            eprintln!("nclr: {msg}");
                                        }
                                        break 'plans;
                                    }
                                    Err(se) => {
                                        if !opts.quiet {
                                            eprintln!(
                                                "nclr: warning: cannot query device erase state after failure: {se}"
                                            );
                                        }
                                    }
                                }
                            }
                            if let Some(o) = erase_verdict {
                                o
                            } else {
                                if !fallback_entry || current.no_fallback {
                                    fatal = Some(e);
                                    break 'plans;
                                }
                                let Some(fb) = fallback_plan.as_ref() else {
                                    fatal = Some(e);
                                    break 'plans;
                                };
                                let fb_owned = fb.clone();
                                fallback_used = true;
                                if !opts.quiet {
                                    eprintln!(
                                        "nclr: warning: {} failed ({e}); falling back to the embedded plan ({} ceiling)",
                                        action.id, fb_owned.expected_grade
                                    );
                                }
                                if let Err(fe) = switch_to_fallback(
                                    journal,
                                    &mut fallback_plan,
                                    &mut current,
                                    &mut skipping,
                                    &mut evidence,
                                    &fb_owned,
                                ) {
                                    fatal = Some(fe);
                                    break 'plans;
                                }
                                continue 'plans;
                            }
                        }
                    };
                    // A backend-reported interruption (e.g. a busy timeout
                    // mid-erase) is a resumable stop (exit 75): never fall
                    // back to writes against a possibly running erase.
                    if action_outcome.record.status == "interrupted" {
                        interrupted = true;
                        if !opts.quiet {
                            eprintln!(
                                "nclr: {}",
                                action_outcome
                                    .record
                                    .message
                                    .as_deref()
                                    .unwrap_or("device operation interrupted; resume to continue")
                            );
                        }
                        break 'plans;
                    }
                    if fallback_entry
                        && matches!(action_outcome.record.status.as_str(), "error" | "failed")
                    {
                        // Action-level failure of a fallback-listed action.
                        if current.no_fallback {
                            fatal = Some(Error::Backend(
                                action_outcome
                                    .record
                                    .message
                                    .clone()
                                    .unwrap_or_else(|| "action failed".into()),
                            ));
                            break 'plans;
                        }
                        let switch = if let Some(fb) = fallback_plan.as_ref() {
                            // Switch to the embedded fallback plan.
                            let fb_owned = fb.clone();
                            fallback_used = true;
                            if !opts.quiet {
                                eprintln!(
                                    "nclr: warning: {} failed ({}); falling back to the embedded plan ({} ceiling)",
                                    action.id,
                                    action_outcome
                                        .record
                                        .message
                                        .as_deref()
                                        .unwrap_or("action error"),
                                    fb_owned.expected_grade
                                );
                            }
                            if let Err(fe) = switch_to_fallback(
                                journal,
                                &mut fallback_plan,
                                &mut current,
                                &mut skipping,
                                &mut evidence,
                                &fb_owned,
                            ) {
                                fatal = Some(fe);
                                break 'plans;
                            }
                            true
                        } else {
                            // In-place fallback (e.g. L1 PRBS -> zero path):
                            // record it and continue with the next action.
                            fallback_used = true;
                            if !opts.quiet {
                                eprintln!(
                                    "nclr: warning: {} failed ({}); continuing degraded",
                                    action.id,
                                    action_outcome
                                        .record
                                        .message
                                        .as_deref()
                                        .unwrap_or("action error")
                                );
                            }
                            false
                        };
                        if switch {
                            continue 'plans;
                        }
                    }
                    // A controller/physical action-level error is an unsafe
                    // recovery boundary, not degraded evidence. Only the
                    // explicitly declared L1 PRBS-to-zero transition is an
                    // in-place fallback. Partial per-block outcomes use
                    // `partial` and remain available to the evidence model as
                    // documented residuals.
                    if matches!(action_outcome.record.status.as_str(), "error" | "failed")
                        && (matches!(current.expected_grade.as_str(), "C3" | "C4")
                            || current.requested_level == "salvage")
                        && !(action.id == "lba-prbs-write"
                            && fallback_entry
                            && !current.no_fallback
                            && fallback_plan.is_none())
                    {
                        fatal = Some(Error::Backend(
                            action_outcome
                                .record
                                .message
                                .clone()
                                .unwrap_or_else(|| format!("action {} failed", action.id)),
                        ));
                        break 'plans;
                    }
                    action_outcome
                }
            };

            // A3: record the per-action duration.
            let mut outcome = outcome;
            // A backend-reported interruption (e.g. a busy timeout
            // mid-erase) is a resumable stop (exit 75): never fall back to
            // writes against a possibly running erase. This covers every
            // action kind, including the power-cycle branches.
            if outcome.record.status == "interrupted" {
                interrupted = true;
                if !opts.quiet {
                    eprintln!(
                        "nclr: {}",
                        outcome
                            .record
                            .message
                            .as_deref()
                            .unwrap_or("device operation interrupted; resume to continue")
                    );
                }
                break 'plans;
            }
            outcome.record.duration_ms = Some(action_started.elapsed().as_millis() as u64);

            // Accumulate evidence.
            let id = action.id.as_str();
            let errs = outcome.errors;
            let status_ok = outcome.record.status == "ok";
            // Suppress duplicate degraded warnings when both the PRBS pass
            // and its zero-only fallback fail: the evidence below still
            // records each outcome, so this flag only gates the message.
            if id == "lba-prbs-write" && !status_ok && !fallback_used && !current.no_fallback {
                fallback_used = true;
                if !opts.quiet {
                    eprintln!("nclr: warning: lba-prbs-write failed; falling back to zero-only (degraded)");
                }
            }
            apply_outcome_to_evidence(
                &mut evidence,
                id,
                &outcome.record.status,
                errs,
                outcome.details.as_ref(),
                power_cycled,
                current.device.capacity_bytes,
                &mut health,
            );
            // A controller rebuild commits a possibly reduced capacity: the
            // identity fingerprint changes. Record the post-commit identity
            // so `resume` can re-match the device. A failure to
            // re-identify right after the commit is fatal: the
            // resume anchor would otherwise be missing silently.
            if id == "rebuild-bbt-ftl" && status_ok && errs == 0 {
                let after = match device::identify(&runtime_device_path) {
                    Ok(a) => a,
                    Err(e) => {
                        fatal = Some(e);
                        break 'plans;
                    }
                };
                if !accepted_identities.contains(&after.fingerprint) {
                    accepted_identities.push(after.fingerprint.clone());
                }
                if let Err(je) = journal.record("reidentify", "capacity-committed", |r| {
                    r.device = Some(after.fingerprint.clone());
                    r.plan_hash = Some(current.plan_hash.clone());
                }) {
                    fatal = Some(Error::io(
                        "journal",
                        Some(std::io::Error::other(je.to_string())),
                    ));
                    break 'plans;
                }
            }

            let _ = events.emit("action-done", |e| {
                e.action = Some(action.id.clone());
                // Weak-block count reported by the backend (e.g. qualify-blocks).
                if let Some(w) = outcome
                    .details
                    .as_ref()
                    .and_then(|d| d.get("weak"))
                    .and_then(|v| v.as_u64())
                {
                    e.weak = Some(w);
                }
            });
            if let Err(e) = write_evidence(
                evidence_path,
                &current.plan_hash,
                &action.id,
                outcome.details.as_ref(),
            ) {
                fatal = Some(e);
                break 'plans;
            }
            if let Err(e) = journal.record("action", "action-completed", |r| {
                r.action = Some(action.id.clone());
                r.action_status = Some(outcome.record.status.clone());
                r.action_errors = Some(errs);
                r.action_details = outcome.details.clone();
                r.plan_hash = Some(current.plan_hash.clone());
            }) {
                fatal = Some(Error::io(
                    "journal",
                    Some(std::io::Error::other(e.to_string())),
                ));
                break 'plans;
            }
            actions.push(outcome.record);

            // Test hook: stop cleanly after a chosen action (resume testing).
            if std::env::var("NCLR_TEST_HOOKS").as_deref() == Ok("1") {
                let stop_after_id = std::env::var("NCLR_TEST_STOP_AFTER")
                    .ok()
                    .is_some_and(|stop| stop == action.id);
                let stop_after_seq = std::env::var("NCLR_TEST_STOP_AFTER_SEQ")
                    .ok()
                    .and_then(|stop| stop.parse::<u32>().ok())
                    == Some(action.seq);
                if stop_after_id || stop_after_seq {
                    interrupted = true;
                    break 'plans;
                }
            }
        }
        break 'plans;
    }

    let mut status = if interrupted {
        ResultStatus::Interrupted
    } else if let Some(e) = fatal {
        eprintln!("nclr: fatal: {e}");
        ResultStatus::Failed
    } else {
        ResultStatus::Ok // refined later by the caller
    };
    let health = evidence.health();
    drop(events);
    drop(events_owned);
    if let Some(relay) = event_relay {
        if let Err(error) = relay.finish() {
            eprintln!("nclr: event relay failed: {error}");
            status = ResultStatus::Failed;
        }
    }
    (status, actions, evidence, health, runtime_device_path)
}

/// Heartbeat decision: emit a status heartbeat when the
/// long-running operation has produced no progress for `stall_secs`.
fn should_heartbeat(stall_secs: u64, threshold_secs: u64) -> bool {
    threshold_secs > 0 && stall_secs >= threshold_secs
}

/// Result of a device-erase state query (spec §1215: a timed-out or
/// interrupted destructive command may still be running inside the device).
enum EraseStateQuery {
    /// The backend reported an actionable sanitize verdict: completed,
    /// failed, or still running (which was monitored to completion).
    Verdict(ActionOutcome),
    /// The backend has no sanitize state (no self-running erase) or the
    /// erase has not started yet: a fresh command may be issued.
    NoState,
    /// The status query itself failed: the device state is unknown and a
    /// destructive command must not be re-issued blindly.
    QueryFailed,
}

/// Query the backend's sanitize state (spec §1215: a timed-out or
/// interrupted destructive command may still be running inside the
/// device). Returns an `EraseStateQuery` verdict; a transport failure of
/// the status call itself is propagated as `Err`.
fn query_erase_state(
    handle: &BackendHandle,
    io: BackendIo<'_>,
    events_fd: Option<&OwnedFd>,
    events: &mut nclr::events::EventWriter,
    opts: &RunOptions,
    action: &PlanAction,
) -> Result<EraseStateQuery> {
    let resp = backend::call(
        handle,
        "status",
        io.device_fd,
        events_fd,
        &Request {
            api: nclr::BACKEND_API,
            op: "status".into(),
            action: None,
            seed: None,
            device_is_file: Some(io.device_is_file),
            limits: req_limits(),
            params: None,
            device: None,
            extra_fds: extra_fd_request(io.extras),
        },
        &extra_fd_sources(io.extras),
        None,
    )?;
    if !resp.ok() {
        return Ok(EraseStateQuery::QueryFailed);
    }
    let Some(s) = resp.value.get("sanitize") else {
        return Ok(EraseStateQuery::NoState);
    };
    // A backend that can report sanitize state also reports whether the
    // erase has started; an explicit false means the erase never began and
    // a fresh command may be issued (a silent false would leave the device
    // parked in a monitor loop for an hour).
    if s.get("started").and_then(|v| v.as_bool()) == Some(false) {
        return Ok(EraseStateQuery::NoState);
    }
    let completed = s
        .get("completed")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let failed = s.get("failed").and_then(|v| v.as_bool()).unwrap_or(false);
    let progress = s.get("progress").and_then(|v| v.as_u64()).unwrap_or(0);
    let outcome = if completed {
        ActionOutcome {
            record: ActionRecord {
                id: action.id.clone(),
                status: "ok".into(),
                retries: Some(0),
                errors: None,
                duration_ms: None,
                message: Some("device erase was already completed (status)".into()),
            },
            errors: 0,
            details: Some(json!({ "completed": true, "progress": progress })),
        }
    } else if !failed {
        // Unknown state (including a failed status *query* reported as
        // unknown by the backend) is treated as still running and is
        // monitored; only a failed device verdict stops here.
        monitor_device_erase(handle, io, events_fd, events, opts, action)?
    } else {
        ActionOutcome {
            record: ActionRecord {
                id: action.id.clone(),
                status: "error".into(),
                retries: Some(0),
                errors: Some(1),
                duration_ms: None,
                message: Some(format!("device erase failed (status progress {progress})")),
            },
            errors: 1,
            details: None,
        }
    };
    Ok(EraseStateQuery::Verdict(outcome))
}

/// Poll the backend `status` op until the self-running device erase
/// completes or fails.
fn monitor_device_erase(
    handle: &BackendHandle,
    io: BackendIo<'_>,
    events_fd: Option<&OwnedFd>,
    events: &mut nclr::events::EventWriter,
    opts: &RunOptions,
    action: &PlanAction,
) -> Result<ActionOutcome> {
    let mut last_progress = 0u64;
    let mut last_progress_secs = std::time::Instant::now();
    // Stall detection: a real sanitize can legitimately take hours, but the
    // progress must advance at least once in a generous window; otherwise
    // the device (or the backend) is stuck and the run must not wait
    // forever.
    let mut last_progress_change = std::time::Instant::now();
    loop {
        if nclr::signal::requested() {
            return Err(Error::Interrupted(
                "interrupted while monitoring the device erase".into(),
            ));
        }
        let resp = backend::call(
            handle,
            "status",
            io.device_fd,
            events_fd,
            &Request {
                api: nclr::BACKEND_API,
                op: "status".into(),
                action: None,
                seed: None,
                device_is_file: Some(io.device_is_file),
                limits: req_limits(),

                params: None,
                device: None,
                extra_fds: extra_fd_request(io.extras),
            },
            &extra_fd_sources(io.extras),
            None,
        )?;
        if !resp.ok() {
            return Err(Error::Backend(format!(
                "device erase status failed: {}",
                resp.message()
            )));
        }
        let sanitize = resp.value.get("sanitize").ok_or_else(|| {
            Error::Backend(
                "device erase status omitted sanitize state after reporting an asynchronous start"
                    .into(),
            )
        })?;
        let progress = sanitize
            .get("progress")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let completed = sanitize
            .get("completed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let failed = sanitize
            .get("failed")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if progress != last_progress {
            last_progress = progress;
            last_progress_secs = std::time::Instant::now();
            last_progress_change = std::time::Instant::now();
            if !opts.quiet {
                eprintln!("nclr: device erase progress: {progress}/1000");
            }
        } else if should_heartbeat(last_progress_secs.elapsed().as_secs(), 30) {
            last_progress_secs = std::time::Instant::now();
            if !opts.quiet {
                eprintln!("nclr: device erase still running (progress {progress}/1000)");
            }
            let _ = events.heartbeat("device-erase", progress, "per-mille");
        }
        if last_progress_change.elapsed().as_secs() > MONITOR_STALL_SECS {
            // A stalled erase is a resumable condition, not a device
            // failure: report it as Interrupted so the run stops cleanly
            // (exit 75) and `resume` can re-query the device state instead
            // of falling back to writes against a possibly running erase.
            return Err(Error::Interrupted(format!(
                "device erase stalled: progress {progress}/1000 unchanged for {MONITOR_STALL_SECS}s"
            )));
        }
        if completed {
            return Ok(ActionOutcome {
                record: ActionRecord {
                    id: action.id.clone(),
                    status: "ok".into(),
                    retries: Some(0),
                    errors: Some(0),
                    duration_ms: None,
                    message: Some(format!("device erase completed (progress {progress}/1000)")),
                },
                errors: 0,
                details: Some(json!({ "progress": progress })),
            });
        }
        if failed {
            return Err(Error::io(
                "device erase failed (reported by the device)",
                None,
            ));
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
}

/// Advisory per-request limits for the backend protocol. Timeouts are
/// enforced by the core process boundary, not by this field, so
/// timeout_ms is intentionally absent.
fn req_limits() -> Option<Value> {
    Some(serde_json::json!({ "max_response_bytes": 16 * 1024 * 1024 }))
}

fn validate_events_fd(events_fd: Option<i32>) -> Result<()> {
    let Some(fd) = events_fd else {
        return Ok(());
    };
    if fd < 3 {
        return Err(Error::Usage(
            "--events-fd must not be stdin, stdout, or stderr".into(),
        ));
    }
    if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
        return Err(Error::Usage(format!(
            "--events-fd {fd} is not an open file descriptor"
        )));
    }
    Ok(())
}

/// Shared device setup: resolve, verify, safety, lock, open, backend.
fn open_for_run(
    plan: &Plan,
    device_arg: Option<&str>,
    opts: &RunOptions,
    site: &nclr::config::SiteConfig,
    accepted_fingerprints: &[String],
) -> Result<OpenRun> {
    validate_events_fd(opts.events_fd)?;
    let device_path = resolve_device_path(plan, device_arg)?;
    let mut identity = device::identify(&device_path)?;
    verify_plan_device(plan, &identity, accepted_fingerprints)?;

    let safety_opts = nclr::safety::SafetyOptions {
        unmount: opts.unmount,
        allow_nonremovable: opts.allow_nonremovable,
    };
    let destructive = plan.actions.iter().any(|action| action.kind.destructive());
    let safety = if destructive {
        nclr::safety::preflight(&identity, &safety_opts)?
    } else {
        nclr::safety::preflight_read(&identity, &safety_opts)?
    };
    if !safety.unmounted.is_empty() && !opts.quiet {
        eprintln!("nclr: unmounted: {}", safety.unmounted.join(", "));
    }
    if !safety.unmounted.is_empty() {
        // Never trust only the unmount command's exit status. Re-read mount,
        // holder, write-protect and identity state before opening for write.
        identity = device::identify(&device_path)?;
        verify_plan_device(plan, &identity, accepted_fingerprints)?;
        let post_unmount = nclr::safety::SafetyOptions {
            unmount: false,
            allow_nonremovable: opts.allow_nonremovable,
        };
        if destructive {
            nclr::safety::preflight(&identity, &post_unmount)?;
        } else {
            nclr::safety::preflight_read(&identity, &post_unmount)?;
        }
    }

    // flock-based mutual exclusion. The plan's physical path is stable
    // across controller-mode VID/PID/capacity changes, unlike its
    // fingerprint, so one lock continues to cover every re-enumerated node.
    // The lock is
    // returned to the caller and held for the entire run, covering the
    // destructive phase, not just setup.
    let _lock = nclr::lock::acquire(&format!("physical:{}", plan.device.physical_path))?;

    // The plan pins the backend implementation. Re-selecting from transport
    // here would silently replace a controller plan with the SCSI backend.
    let handle = pick_backend(
        &identity,
        Some(plan.backend.id.as_str()),
        &opts.backend_dir,
        site,
    )?;
    // Probe must confirm the backend matches the plan's backend.
    // A sim image stores controller service-mode state in the same file as
    // its NAND pages. Physical salvage remains free of erase/program
    // actions, but that file must be writable across short-lived backend
    // processes so the reversible service transition can be persisted.
    let transport_write =
        destructive || (plan.requested_level == "salvage" && device::is_regular_file(&device_path));
    let fd = device::open_raw(&device_path, transport_write)?;
    let device_fd = OwnedFd::from(fd);
    let mut extras = if handle.id == "controller" {
        open_backend_extras(&identity, true)?
    } else {
        Vec::new()
    };
    extras.extend(open_plan_artifacts(plan, &opts.artifact_dir)?);
    let extra_request = extra_fd_request(&extras);
    let extra_sources = extra_fd_sources(&extras);
    let resp = backend::call(
        &handle,
        "probe",
        &device_fd,
        None,
        &Request {
            api: nclr::BACKEND_API,
            op: "probe".into(),
            action: None,
            seed: None,
            device_is_file: Some(device::is_regular_file(&device_path)),
            limits: req_limits(),
            params: None,
            device: Some(identity.clone()),
            extra_fds: extra_request,
        },
        &extra_sources,
        None,
    )?;
    if !resp.ok() {
        return Err(Error::Backend(resp.message()));
    }
    if resp.controller_profile() != plan.backend.profile {
        return Err(Error::Permission(format!(
            "controller profile changed since planning: plan {:?} vs probe {:?}",
            plan.backend.profile,
            resp.controller_profile()
        )));
    }
    if resp.profile_sha256() != plan.backend.profile_sha256 {
        return Err(Error::Permission(
            "controller profile digest changed since planning".into(),
        ));
    }
    if resp.artifacts()? != plan.backend.artifacts {
        return Err(Error::Permission(
            "controller artifact requirements changed since planning".into(),
        ));
    }
    // Close the identify/open/probe race. A mount, holder, media swap or
    // geometry change that appeared during setup must stop the run before
    // confirmation and before any destructive backend action.
    let identity_after_probe = device::identify(&device_path)?;
    verify_plan_device(plan, &identity_after_probe, accepted_fingerprints)?;
    let final_safety = nclr::safety::SafetyOptions {
        unmount: false,
        allow_nonremovable: opts.allow_nonremovable,
    };
    if destructive {
        nclr::safety::preflight(&identity_after_probe, &final_safety)?;
    } else {
        nclr::safety::preflight_read(&identity_after_probe, &final_safety)?;
    }
    if identity_after_probe.fingerprint != identity.fingerprint {
        return Err(Error::Permission(
            "device identity changed while opening the backend".into(),
        ));
    }
    identity = identity_after_probe;
    if handle.id != plan.backend.id {
        return Err(Error::Permission(format!(
            "backend identity changed: plan {} vs probe {}",
            plan.backend.id, handle.id
        )));
    }
    // The plan records the backend digest (and the profile digest) at plan
    // time; executing with a different binary is refused so the evidence
    // cannot be attributed to the wrong tool.
    if let Some(planned_digest) = &plan.backend.sha256 {
        if !planned_digest.eq_ignore_ascii_case(&handle.sha256) {
            // The plan file is user-controlled: truncate on char
            // boundaries, never on raw byte indices.
            let trunc = |s: &str| s.chars().take(16).collect::<String>();
            return Err(Error::Permission(format!(
                "backend digest changed since planning: plan {} vs binary {}",
                trunc(planned_digest),
                trunc(&handle.sha256)
            )));
        }
    }
    if opts.verbose > 0 {
        eprintln!(
            "nclr: backend {} v{} trust {} digest {}",
            handle.id,
            handle.version,
            handle.trust,
            &handle.sha256[..12]
        );
    }

    let state_path = opts
        .state
        .clone()
        .unwrap_or_else(|| nclr::journal::default_state_dir().join(format!("{}.state", plan.id)));
    if handle.id == "controller" {
        let controller_path = controller_state_path(&state_path);
        extras.push((
            open_controller_state(&controller_path)?,
            "controller-state".into(),
        ));
    }
    let journal = Journal::open(&state_path)?;

    Ok(OpenRun {
        device_path,
        identity,
        handle,
        device_fd,
        journal,
        state_path,
        _lock,
        backend_extras: extras,
    })
}

fn run_execute(
    plan: Plan,
    device_arg: Option<&str>,
    opts: &RunOptions,
    site: &nclr::config::SiteConfig,
) -> i32 {
    let start = std::time::Instant::now();
    let result = run_execute_inner(&plan, device_arg, opts, site);
    let end = crate_duration_ms(start);
    match result {
        Ok((code, mut report)) => {
            report.times = json!({
                "start": report.times.get("start").cloned().unwrap_or(json!("")),
                "end": nclr::journal::utc_now_rfc3339(),
                "duration_ms": end,
            });
            report.report_hash = report.compute_hash();
            if opts.summary {
                let s = nclr::report::SummaryReport::from_report(&report);
                if opts.json {
                    println!("{}", serde_json::to_string_pretty(&s).unwrap());
                } else {
                    eprintln!("nclr: {}", s.one_line());
                }
            } else if opts.json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                eprintln!("nclr: completed: {}", report.summary());
            }
            code
        }
        Err(e) => {
            eprintln!("nclr: {e}");
            e.exit_code()
        }
    }
}

fn crate_duration_ms(start: std::time::Instant) -> u64 {
    start.elapsed().as_millis() as u64
}

/// Bounded wait for a device to reappear after a power cycle or service-mode
/// re-enumeration (spec §836: re-enumeration waits are finite).
const REENUM_WAIT_SECS: u64 = 30;

/// A self-running erase must advance its progress at least once in this
/// window; a sanitize can take hours, but zero movement for 60 minutes
/// means the device (or backend) is stuck.
const MONITOR_STALL_SECS: u64 = 3600;

/// Record a device-loss journal entry and stop waiting.
fn journal_awaiting_device(journal: &mut Journal, device_path: &str, message: &str) {
    if let Err(e) = journal.record("device", "awaiting-device", |r| {
        r.device_path = Some(device_path.to_string());
        r.message = Some(message.to_string());
    }) {
        eprintln!("nclr: journal awaiting-device record failed: {e}");
    }
}

/// A per-run nonce anchoring service-mode re-enumeration tracking.
fn new_reenum_nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{nanos:x}-{}", std::process::id())
}

fn run_execute_inner(
    plan: &Plan,
    device_arg: Option<&str>,
    opts: &RunOptions,
    site: &nclr::config::SiteConfig,
) -> Result<(i32, Report)> {
    let OpenRun {
        device_path,
        identity,
        handle,
        mut device_fd,
        mut journal,
        state_path,
        _lock,
        mut backend_extras,
    } = open_for_run(
        plan,
        device_arg,
        opts,
        site,
        std::slice::from_ref(&plan.device.fingerprint),
    )?;

    // Seed the journal with the plan.
    journal.record("plan", "locked", |r| {
        r.device = Some(identity.fingerprint.clone());
        r.device_path = Some(device_path.clone());
        r.plan_hash = Some(plan.plan_hash.clone());
        r.plan = Some(serde_json::to_value(plan).unwrap());
    })?;

    let mut report = Report::new(plan);
    report.device_before = json!({
        "fingerprint": identity.fingerprint,
        "capacity_bytes": identity.capacity_bytes,
        "kernel_path": identity.kernel_path,
    });
    report.state_file = Some(state_path.display().to_string());
    report.times =
        json!({ "start": nclr::journal::utc_now_rfc3339(), "end": "", "duration_ms": 0 });

    // Confirmation (never skipped for safety checks; only the prompt).
    if !opts.quiet {
        eprintln!(
            "nclr: target {}, {}, fingerprint {}",
            identity.kernel_path,
            confirm::human_capacity(identity.capacity_bytes),
            &identity.fingerprint[..24]
        );
        let destructive = plan.actions.iter().filter(|a| a.kind.destructive()).count();
        eprintln!("nclr: destructive actions: {destructive}");
    }
    confirm::confirm(&identity, opts.yes)?;

    // An interactive confirmation can take arbitrarily long. Re-run the
    // safety and identity checks at the actual destructive boundary so an
    // automount, new holder or media swap during the prompt is rejected.
    let ready = device::identify(&device_path)?;
    verify_plan_device(plan, &ready, std::slice::from_ref(&plan.device.fingerprint))?;
    nclr::safety::preflight(
        &ready,
        &nclr::safety::SafetyOptions {
            unmount: false,
            allow_nonremovable: opts.allow_nonremovable,
        },
    )?;
    if ready.fingerprint != identity.fingerprint {
        return Err(Error::Permission(
            "device identity changed during confirmation".into(),
        ));
    }

    // Execute actions.
    let evidence_path = evidence_path_for(opts, &plan.id)?;
    let (status, actions, mut evidence, mut health, final_device_path) = execute_plan_actions(
        plan,
        &handle,
        &device_path,
        &mut device_fd,
        &mut journal,
        opts,
        None,
        None,
        evidence_path.as_deref(),
        &new_reenum_nonce(),
        std::slice::from_ref(&plan.device.fingerprint),
        &mut backend_extras,
    );
    if let Some(p) = &evidence_path {
        if let Some(digest) = evidence_digest(Some(p))? {
            report.evidence_file = Some(p.display().to_string());
            report.evidence_sha256 = Some(digest);
        }
    }
    report.actions = actions;

    // Re-identify for device_after. A failure here (e.g. the medium vanished)
    // must not be replaced by the stale before-run identity: that would fake
    // the capacity-stability verdict.
    let identity_after = match device::identify(&final_device_path) {
        Ok(identity) => Some(identity),
        Err(error) if status == ResultStatus::Interrupted => {
            report.device_after = json!({
                "available": false,
                "kernel_path": final_device_path,
                "error": error.to_string(),
            });
            None
        }
        Err(error) => return Err(error),
    };
    if let Some(identity_after) = identity_after.as_ref() {
        report.device_after = json!({
            "fingerprint": identity_after.fingerprint,
            "capacity_bytes": identity_after.capacity_bytes,
            "kernel_path": identity_after.kernel_path,
        });
    }
    // Capacity stability for a controller rebuild compares against the
    // capacity committed by the rebuild (a planned shrink is not
    // instability). Sector size stability (§1170) is verified against the
    // before-run identity: a 512e->4Kn switch must not pass silently.
    health.capacity_stable = identity_after.as_ref().is_some_and(|identity_after| {
        (match evidence.expected_capacity_bytes() {
            Some(expected) => identity_after.capacity_bytes == expected,
            None => identity_after.capacity_bytes == identity.capacity_bytes,
        }) && identity_after.logical_block_size == identity.logical_block_size
    });
    evidence.constrain_capacity_stability(health.capacity_stable);

    // Grades.
    let grade_result = evidence.compute();
    let h = compute_health(&health);
    let achieved = grade_result.grade;
    let qualified = grade_result.qualified;
    let residual = grade_result.residual;
    let power_cycled = evidence.power_cycled();

    let min_grade = CGrade::parse(&plan.minimum_level).unwrap_or(CGrade::C1);
    let min_met = achieved >= min_grade;
    // Out-of-scope reach boundaries (unreachable) are documented, not a
    // residual risk; any other residual (erase-failed, unknown-scope, ...)
    // degrades the result.
    let residual_ok = matches!(
        residual,
        nclr::grade::Residual::NoneKnown | nclr::grade::Residual::Unreachable
    );
    let result = match status {
        ResultStatus::Interrupted => ResultStatus::Interrupted,
        ResultStatus::Failed => ResultStatus::Failed,
        _ => {
            if qualified && h >= nclr::grade::HGrade::H2 && min_met && residual_ok {
                ResultStatus::Ok
            } else {
                ResultStatus::Degraded
            }
        }
    };

    report.result = result.as_str().to_string();
    // Resume information for an interrupted run.
    if result == ResultStatus::Interrupted {
        report.resume = Some(json!({
            "command": "nclr resume",
            "state_file": state_path.display().to_string(),
            "device": device_path,
            "plan_id": plan.id,
        }));
    }
    report.achieved_grade = achieved.as_str().to_string();
    report.grade_qualified = qualified;
    report.residual = residual.as_str().to_string();
    report.health_grade = h.as_str().to_string();
    report.coverage = match &evidence {
        GradeEvidence::Lba(e) => nclr::report::lba_coverage(e.io_errors),
        GradeEvidence::Device(e) => nclr::report::device_erase_coverage(
            e.erase_completed,
            e.blank_verify,
            e.io_errors,
            plan,
        ),
        GradeEvidence::Controller(e) => nclr::report::controller_coverage(e),
        GradeEvidence::Physical(e) => nclr::report::physical_coverage(
            e.blocks_erase_failed,
            e.old_rbb_erase_attempted,
            e.rbb_count,
            e.old_rbb_erased,
            e.old_rbb_erase_failed,
            e.unknown_reservation,
            e.bbt_ftl_rebuilt,
        ),
    };
    if let Some(d5) = nclr::report::d5_coverage(plan) {
        report.coverage.push(d5);
    }
    report.postcheck = PostCheck {
        recipe: match &evidence {
            GradeEvidence::Physical(_) => "P1",
            GradeEvidence::Controller(_) => "P2",
            GradeEvidence::Device(_) => "P2",
            GradeEvidence::Lba(_) => "L1",
        }
        .into(),
        passed: qualified && h >= nclr::grade::HGrade::H2,
        power_cycle_performed: Some(power_cycled),
        details: Some(match &evidence {
            GradeEvidence::Lba(e) => json!({
                "full_overwrite": e.full_overwrite,
                "prbs_verify": e.prbs_verify,
                "zero_verify": e.zero_verify,
                "signature_free": e.signature_free,
                "flush_ok": e.flush_ok,
                "io_errors": e.io_errors,
                "power_cycle_performed": e.power_cycled,
                "throughput_mbps": e.throughput_mbps,
                "flush_latency_ms": e.flush_latency_ms,
                "min_level_met": min_met,
                "min_level": plan.minimum_level,
            }),
            GradeEvidence::Device(e) => json!({
                "erase_completed": e.erase_completed,
                "scope_documented": e.scope_documented,
                "blank_verify": e.blank_verify,
                "signature_free": e.signature_free,
                "capacity_stable": e.capacity_stable,
                "postcheck_reads_ok": e.postcheck_reads_ok,
                "postcheck_signature_free": e.postcheck_signature_free,
                "postcheck_flush_ok": e.postcheck_flush_ok,
                "power_cycle_performed": e.power_cycled,
                "io_errors": e.io_errors,
                "min_level_met": min_met,
                "min_level": plan.minimum_level,
            }),
            GradeEvidence::Controller(e) => json!({
                "old_bbt_captured": e.old_bbt_captured,
                "old_bbt_sha256": e.old_bbt_sha256,
                "old_bbt_copies": e.old_bbt_copies,
                "old_rbb_erase_attempted": e.old_rbb_erase_attempted,
                "old_rbb_erase_failed": e.old_rbb_erase_failed,
                "final_erase_failed": e.final_erase_failed,
                "fbb_preserved": e.fbb_preserved,
                "new_bbt_committed": e.new_bbt_committed,
                "ftl_rebuilt": e.ftl_rebuilt,
                "capacity_stable": e.capacity_stable,
                "logical_reads_ok": e.logical_reads_ok,
                "logical_blank_verified": e.logical_blank_verified,
                "signature_free": e.signature_free,
                "flush_ok": e.flush_ok,
                "spare_ok": e.spare_ok,
                "weak_isolated": e.weak_isolated,
                "power_cycle_performed": e.power_cycled,
                "expected_capacity_bytes": e.expected_capacity_bytes,
                "io_errors": e.io_errors,
                "min_level_met": min_met,
                "min_level": plan.minimum_level,
            }),
            GradeEvidence::Physical(e) => json!({
                "enumeration_complete": e.enumeration_complete,
                "blocks_declared": e.blocks_declared,
                "blocks_classified": e.blocks_classified,
                "blocks_enumerated": e.blocks_enumerated,
                "blocks_erased": e.blocks_erased,
                "blocks_erase_failed": e.blocks_erase_failed,
                "physical_sweep_complete": e.physical_sweep_complete,
                "physical_pages": e.physical_pages,
                "physical_readable_pages": e.physical_readable_pages,
                "physical_unreadable_pages": e.physical_unreadable_pages,
                "physical_uncorrectable_pages": e.physical_uncorrectable_pages,
                "ordered_sweep_sha256": e.ordered_sweep_sha256,
                "target_pages": e.target_pages,
                "target_readable_pages": e.target_readable_pages,
                "target_unreadable_pages": e.target_unreadable_pages,
                "target_uncorrectable_pages": e.target_uncorrectable_pages,
                "target_non_erased_pages": e.target_non_erased_pages,
                "excluded_unreadable_pages": e.excluded_unreadable_pages,
                "old_bbt_captured": e.old_bbt_captured,
                "old_bbt_sha256": e.old_bbt_sha256,
                "old_bbt_copies": e.old_bbt_copies,
                "old_rbb_erase_attempted": e.old_rbb_erase_attempted,
                "old_rbb_erase_failed": e.old_rbb_erase_failed,
                "fbb_preserved": e.fbb_preserved,
                "weak_isolated": e.weak_isolated,
                "unknown_reservation": e.unknown_reservation,
                "bbt_ftl_rebuilt": e.bbt_ftl_rebuilt,
                "capacity_stable": e.capacity_stable,
                "logical_reads_ok": e.logical_reads_ok,
                "logical_blank_verified": e.logical_blank_verified,
                "signature_free": e.signature_free,
                "flush_ok": e.flush_ok,
                "spare_ok": e.spare_ok,
                "power_cycle_performed": e.power_cycled,
                "expected_capacity_bytes": e.expected_capacity_bytes,
                "io_errors": e.io_errors,
                "min_level_met": min_met,
                "min_level": plan.minimum_level,
            }),
        }),
    };
    // A2/A4: FTL object and old/new BBT summary for controller paths.
    let (ftl, bbt_summary) = controller_summary(&evidence, plan);
    report.ftl = ftl;
    if bbt_summary != Value::Null {
        let details = report
            .postcheck
            .details
            .get_or_insert(serde_json::json!({}));
        if let Some(obj) = details.as_object_mut() {
            obj.insert("bbt_summary".into(), bbt_summary);
        }
    }
    report.final_state = if matches!(result, ResultStatus::Failed | ResultStatus::Interrupted)
        || !report.postcheck.passed
    {
        "undetermined".to_string()
    } else {
        "raw-uninitialized".to_string()
    };
    if !qualified {
        report.warnings.push(format!(
            "{achieved} evidence incomplete (qualified=false); see postcheck details"
        ));
    }
    if h < nclr::grade::HGrade::H2 {
        report
            .warnings
            .push(format!("health grade {h}; media may be degraded"));
    }
    if !power_cycled {
        report.warnings.push(
            "power cycle was not performed; power-cycle read verification is missing (residual documented-exclusion)"
                .into(),
        );
    }
    // Service-mode recovery: on failure the backend is asked for its
    // declared recovery procedure, which is surfaced in the report.
    if result == ResultStatus::Failed {
        match backend::call(
            &handle,
            "recover",
            &device_fd,
            None,
            &Request {
                api: nclr::BACKEND_API,
                op: "recover".into(),
                action: None,
                seed: None,
                device_is_file: Some(device::is_regular_file(&device_path)),
                limits: req_limits(),
                params: None,
                device: Some(identity.clone()),
                extra_fds: extra_fd_request(&backend_extras),
            },
            &extra_fd_sources(&backend_extras),
            opts.backend_timeout,
        ) {
            Ok(resp) if resp.ok() => {
                let recovery = resp
                    .value
                    .get("recovery")
                    .and_then(|v| v.as_str())
                    .unwrap_or("manual procedure");
                let automated = resp
                    .value
                    .get("automated")
                    .and_then(|v| v.as_bool())
                    .unwrap_or(false);
                report.warnings.push(format!(
                    "recovery required: {} (automated: {automated}); consult the backend's declared recovery method",
                    recovery
                ));
            }
            Ok(resp) => report
                .warnings
                .push(format!("recovery probe failed: {}", resp.message())),
            Err(e) => report.warnings.push(format!("recovery probe failed: {e}")),
        }
    }

    let journal_state = match result {
        ResultStatus::Interrupted => "interrupted",
        ResultStatus::Failed => "failed",
        ResultStatus::Ok => "completed",
        ResultStatus::Degraded => "degraded",
        ResultStatus::Unsupported => "unsupported",
    };
    journal.record("complete", journal_state, |r| {
        r.plan_hash = Some(plan.plan_hash.clone());
        r.message = Some(result.as_str().to_string());
    })?;

    let code = match result {
        ResultStatus::Ok => errors::exit::OK,
        ResultStatus::Degraded => errors::exit::DEGRADED,
        ResultStatus::Interrupted => errors::exit::INTERRUPTED,
        ResultStatus::Failed => errors::exit::DEVICE_IO,
        ResultStatus::Unsupported => errors::exit::UNSUPPORTED,
    };
    Ok((code, report))
}

// ---------------------------------------------------------------------------
// check
// ---------------------------------------------------------------------------

fn cmd_check(
    device_path: &str,
    json: bool,
    backend_dir: &[PathBuf],
    scratch_range: Option<&str>,
    yes: bool,
    config: Option<&Path>,
    backend_timeout: Option<u64>,
) -> i32 {
    let result = (|| -> Result<Value> {
        let identity = device::identify(device_path)?;
        let mut warnings = nclr::safety::preflight_soft(&identity);
        let scratch = parse_scratch_range(scratch_range, identity.capacity_bytes)?;
        if scratch.is_some() {
            // A bounded write test requires a clean device and explicit
            // confirmation.
            nclr::safety::preflight(&identity, &nclr::safety::SafetyOptions::default())?;
            if !yes {
                return Err(Error::Permission(
                    "scratch-range writes require --yes confirmation".into(),
                ));
            }
        }
        let site = nclr::config::load(config)?;
        let handle = pick_backend(&identity, None, backend_dir, &site)?;
        let fd = device::open_raw(device_path, scratch.is_some())?;
        let device_fd = OwnedFd::from(fd);
        let probe = backend::call(
            &handle,
            "probe",
            &device_fd,
            None,
            &Request {
                api: nclr::BACKEND_API,
                op: "probe".into(),
                action: None,
                seed: None,
                device_is_file: Some(device::is_regular_file(device_path)),
                limits: req_limits(),

                params: None,
                device: Some(identity.clone()),
                extra_fds: Vec::new(),
            },
            &[],
            None,
        )?;
        if !probe.ok() {
            return Err(Error::Backend(probe.message()));
        }
        let backend_summary = probe_summary(&handle, &probe)?;
        let sample = backend::call(
            &handle,
            "run",
            &device_fd,
            None,
            &Request {
                api: nclr::BACKEND_API,
                op: "run".into(),
                action: Some("sample-read".into()),
                seed: None,
                device_is_file: Some(device::is_regular_file(device_path)),
                limits: req_limits(),

                params: None,
                device: Some(identity.clone()),
                extra_fds: Vec::new(),
            },
            &[],
            None,
        )?;
        // Read-only SD vendor health query when the backend declares it. A
        // probe failure is diagnostic information, not a command error: it is
        // surfaced in `warnings` instead of being dropped.
        let vendor_health = if probe.capabilities().iter().any(|c| c == "SD_VENDOR_HEALTH") {
            match backend::call(
                &handle,
                "run",
                &device_fd,
                None,
                &Request {
                    api: nclr::BACKEND_API,
                    op: "run".into(),
                    action: Some("vendor-health".into()),
                    seed: None,
                    device_is_file: Some(device::is_regular_file(device_path)),
                    limits: req_limits(),

                    params: None,
                    device: Some(identity.clone()),
                    extra_fds: Vec::new(),
                },
                &[],
                None,
            ) {
                Ok(resp) if resp.ok() => Some(resp),
                Ok(resp) => {
                    warnings.push(format!("vendor-health probe failed: {}", resp.message()));
                    None
                }
                Err(e) => {
                    warnings.push(format!("vendor-health probe failed: {e}"));
                    None
                }
            }
        } else {
            None
        };
        let mut errors = Vec::new();
        if !sample.ok() {
            errors.push(json!({
                "action": "sample-read",
                "status": "error",
                "message": sample.message(),
            }));
        }
        let results = sample
            .value
            .get("action_results")
            .and_then(|v| v.as_array())
            .filter(|results| results.len() == 1)
            .ok_or_else(|| {
                Error::Invalid("sample-read response must contain exactly one action result".into())
            })?;
        let sample_result = &results[0];
        if let Some(status) = sample_result.get("status").and_then(Value::as_str) {
            if status != "ok" {
                errors.push(sample_result.clone());
            }
        }
        let samples = sample_result
            .get("samples")
            .and_then(Value::as_array)
            .filter(|samples| samples.len() == 3)
            .ok_or_else(|| {
                Error::Invalid("sample-read result must contain first/middle/last samples".into())
            })?;
        for sample_value in samples {
            let lba = sample_value
                .get("lba")
                .and_then(Value::as_u64)
                .ok_or_else(|| {
                    Error::Invalid("sample-read result contains an invalid LBA".into())
                })?;
            match (
                sample_value.get("sha256").and_then(Value::as_str),
                sample_value.get("error").and_then(Value::as_str),
            ) {
                (Some(digest), None)
                    if digest.strip_prefix("sha256:").is_some_and(|hex| {
                        hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
                    }) => {}
                (None, Some(message)) if !message.is_empty() => errors.push(json!({
                    "action": "sample-read",
                    "status": "error",
                    "lba": lba,
                    "message": message,
                })),
                _ => {
                    return Err(Error::Invalid(
                        "sample-read result must contain one valid SHA-256 or read error".into(),
                    ))
                }
            }
        }
        // Bounded scratch-range write test (explicit opt-in).
        let scratch_result = if let Some((start, count)) = &scratch {
            let resp = backend::call(
                &handle,
                "run",
                &device_fd,
                None,
                &Request {
                    api: nclr::BACKEND_API,
                    op: "run".into(),
                    action: Some("scratch-test".into()),
                    seed: None,
                    device_is_file: Some(device::is_regular_file(device_path)),
                    limits: req_limits(),
                    params: Some(json!({ "start": start, "count": count })),
                    device: Some(identity.clone()),
                    extra_fds: Vec::new(),
                },
                &[],
                backend_timeout,
            )?;
            if !resp.ok() {
                errors.push(json!({ "action": "scratch-test", "status": "error", "message": resp.message() }));
            }
            resp.value.get("action_results").cloned()
        } else {
            None
        };
        Ok(json!({
            "schema": "nclr.check.v1",
            "identity": identity,
            "backend": backend_summary,
            "warnings": warnings,
            "samples": sample.value.get("action_results"),
            "vendor_health": vendor_health.and_then(|v| v.value.get("action_results").cloned()),
            "scratch_test": scratch_result,
            "errors": errors,
        }))
    })();

    match result {
        Ok(v) => {
            let code = if v
                .get("errors")
                .and_then(|e| e.as_array())
                .map(|a| !a.is_empty())
                .unwrap_or(false)
            {
                errors::exit::DEVICE_IO
            } else {
                errors::exit::OK
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                let identity = v.get("identity").cloned().unwrap_or(json!({}));
                println!(
                    "Device: {}",
                    identity
                        .get("kernel_path")
                        .and_then(|x| x.as_str())
                        .unwrap_or("?")
                );
                println!(
                    "Transport: {}",
                    identity
                        .get("transport")
                        .and_then(|x| x.as_str())
                        .unwrap_or("?")
                );
                println!(
                    "Capacity: {}",
                    identity
                        .get("capacity_bytes")
                        .and_then(|x| x.as_u64())
                        .map(confirm::human_capacity)
                        .unwrap_or_else(|| "?".to_string())
                );
                println!(
                    "Fingerprint: {}",
                    identity
                        .get("fingerprint")
                        .and_then(|x| x.as_str())
                        .unwrap_or("?")
                );
                if let Some(backend) = v.get("backend") {
                    println!(
                        "Backend: {} (grade ceiling {})",
                        backend
                            .get("backend_id")
                            .and_then(Value::as_str)
                            .unwrap_or("?"),
                        backend
                            .get("grade_ceiling")
                            .and_then(Value::as_str)
                            .unwrap_or("?")
                    );
                    let capabilities = backend
                        .get("capabilities")
                        .and_then(Value::as_array)
                        .map(|values| {
                            values
                                .iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(", ")
                        })
                        .filter(|value| !value.is_empty())
                        .unwrap_or_else(|| "(none)".into());
                    println!("Capabilities: {capabilities}");
                }
                for w in v
                    .get("warnings")
                    .and_then(|x| x.as_array())
                    .unwrap_or(&vec![])
                {
                    println!("Warning: {}", w.as_str().unwrap_or(""));
                }
            }
            code
        }
        Err(e) => {
            eprintln!("nclr: {e}");
            e.exit_code()
        }
    }
}

// ---------------------------------------------------------------------------
// physical salvage
// ---------------------------------------------------------------------------

#[cfg(unix)]
fn create_salvage_output(path: &Path) -> Result<OwnedFd> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = std::fs::canonicalize(parent).map_err(|error| {
        Error::io(
            format!("resolve salvage output parent {}", parent.display()),
            Some(error),
        )
    })?;
    let name = path
        .file_name()
        .ok_or_else(|| Error::Usage("salvage output has no file name".into()))?;
    let resolved = parent.join(name);
    let file = std::fs::OpenOptions::new()
        .create_new(true)
        .read(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&resolved)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                Error::Permission(format!(
                    "refusing to overwrite salvage output {}",
                    resolved.display()
                ))
            } else {
                Error::io(
                    format!("create new salvage output {}", resolved.display()),
                    Some(error),
                )
            }
        })?;
    let metadata = file
        .metadata()
        .map_err(|error| Error::io(format!("stat {}", resolved.display()), Some(error)))?;
    if !metadata.is_file()
        || metadata.uid() != nclr::journal::nix_uid()
        || metadata.mode() & 0o077 != 0
        || metadata.len() != 0
    {
        return Err(Error::Permission(format!(
            "salvage output {} must be a new current-user 0600 regular file",
            resolved.display()
        )));
    }
    Ok(OwnedFd::from(file))
}

#[cfg(not(unix))]
fn create_salvage_output(_path: &Path) -> Result<OwnedFd> {
    Err(Error::Unsupported(
        "physical salvage output descriptors require Unix".into(),
    ))
}

fn digest_salvage_output(fd: OwnedFd, role: &str) -> Result<(u64, String)> {
    use sha2::{Digest, Sha256};
    use std::io::{Read, Seek, SeekFrom};
    let mut file = std::fs::File::from(fd);
    let size = file
        .metadata()
        .map_err(|error| Error::io(format!("stat salvage {role}"), Some(error)))?
        .len();
    file.seek(SeekFrom::Start(0))
        .map_err(|error| Error::io(format!("rewind salvage {role}"), Some(error)))?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| Error::io(format!("read salvage {role}"), Some(error)))?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok((size, hex::encode(hasher.finalize())))
}

fn take_salvage_output(extras: &mut Vec<(OwnedFd, String)>, role: &str) -> Result<OwnedFd> {
    let index = extras
        .iter()
        .position(|(_, candidate)| candidate == role)
        .ok_or_else(|| Error::Invalid(format!("salvage output role {role} is missing")))?;
    Ok(extras.remove(index).0)
}

#[derive(Debug)]
struct SalvageOutputBinding {
    image_path: PathBuf,
    image_device: u64,
    image_inode: u64,
    map_path: PathBuf,
    map_device: u64,
    map_inode: u64,
}

#[cfg(unix)]
fn salvage_fd_identity(fd: &OwnedFd, role: &str) -> Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let clone = fd
        .try_clone()
        .map_err(|error| Error::io(format!("clone salvage {role} descriptor"), Some(error)))?;
    let file = std::fs::File::from(clone);
    let metadata = file
        .metadata()
        .map_err(|error| Error::io(format!("stat salvage {role}"), Some(error)))?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err(Error::Permission(format!(
            "salvage {role} must be a regular file with exactly one link"
        )));
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn salvage_fd_identity(_fd: &OwnedFd, _role: &str) -> Result<(u64, u64)> {
    Err(Error::Unsupported(
        "salvage output identity requires Unix".into(),
    ))
}

fn bind_salvage_outputs(
    image_path: &Path,
    image_fd: &OwnedFd,
    map_path: &Path,
    map_fd: &OwnedFd,
) -> Result<SalvageOutputBinding> {
    let image_path = std::fs::canonicalize(image_path).map_err(|error| {
        Error::io(
            format!("resolve salvage image {}", image_path.display()),
            Some(error),
        )
    })?;
    let map_path = std::fs::canonicalize(map_path).map_err(|error| {
        Error::io(
            format!("resolve salvage page map {}", map_path.display()),
            Some(error),
        )
    })?;
    if image_path == map_path {
        return Err(Error::Usage(
            "salvage image and page map resolve to the same file".into(),
        ));
    }
    if image_path.to_str().is_none() || map_path.to_str().is_none() {
        return Err(Error::Invalid(
            "salvage output paths must be valid UTF-8 for the resume journal".into(),
        ));
    }
    let (image_device, image_inode) = salvage_fd_identity(image_fd, "physical image")?;
    let (map_device, map_inode) = salvage_fd_identity(map_fd, "physical page map")?;
    Ok(SalvageOutputBinding {
        image_path,
        image_device,
        image_inode,
        map_path,
        map_device,
        map_inode,
    })
}

fn journal_salvage_outputs(
    journal: &mut Journal,
    plan_hash: &str,
    binding: &SalvageOutputBinding,
    state: &str,
) -> Result<()> {
    journal.record("salvage", state, |record| {
        record.plan_hash = Some(plan_hash.to_owned());
        record.action_details = Some(json!({
            "image": {
                "path": binding.image_path,
                "device": binding.image_device,
                "inode": binding.image_inode,
            },
            "page_map": {
                "path": binding.map_path,
                "device": binding.map_device,
                "inode": binding.map_inode,
            },
        }));
    })
}

fn salvage_output_binding(
    state: &nclr::journal::JournalState,
    plan_hash: &str,
) -> Result<SalvageOutputBinding> {
    let details = state
        .records
        .iter()
        .rev()
        .find_map(|record| {
            (record.value.get("state").and_then(Value::as_str) == Some("outputs-created")
                && record.value.get("plan_hash").and_then(Value::as_str) == Some(plan_hash))
            .then(|| record.value.get("action_details"))
            .flatten()
        })
        .ok_or_else(|| Error::Invalid("salvage journal has no bound output files".into()))?;
    let read_output = |name: &str| -> Result<(PathBuf, u64, u64)> {
        let value = details
            .get(name)
            .and_then(Value::as_object)
            .ok_or_else(|| Error::Invalid(format!("salvage journal output {name} is invalid")))?;
        let path = value
            .get("path")
            .and_then(Value::as_str)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .ok_or_else(|| {
                Error::Invalid(format!("salvage journal output {name} path is invalid"))
            })?;
        let device = value.get("device").and_then(Value::as_u64).ok_or_else(|| {
            Error::Invalid(format!("salvage journal output {name} device is invalid"))
        })?;
        let inode = value
            .get("inode")
            .and_then(Value::as_u64)
            .filter(|inode| *inode > 0)
            .ok_or_else(|| {
                Error::Invalid(format!("salvage journal output {name} inode is invalid"))
            })?;
        Ok((path, device, inode))
    };
    let (image_path, image_device, image_inode) = read_output("image")?;
    let (map_path, map_device, map_inode) = read_output("page_map")?;
    if image_path == map_path || (image_device == map_device && image_inode == map_inode) {
        return Err(Error::Invalid(
            "salvage journal binds image and page map to the same file".into(),
        ));
    }
    Ok(SalvageOutputBinding {
        image_path,
        image_device,
        image_inode,
        map_path,
        map_device,
        map_inode,
    })
}

#[cfg(unix)]
fn reopen_salvage_output(
    path: &Path,
    expected_device: u64,
    expected_inode: u64,
    role: &str,
) -> Result<OwnedFd> {
    use std::io::{Seek, SeekFrom};
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|error| {
            Error::io(
                format!("reopen salvage {role} {}", path.display()),
                Some(error),
            )
        })?;
    let metadata = file
        .metadata()
        .map_err(|error| Error::io(format!("stat salvage {role}"), Some(error)))?;
    if !metadata.is_file()
        || metadata.uid() != nclr::journal::nix_uid()
        || metadata.mode() & 0o777 != 0o600
        || metadata.nlink() != 1
        || metadata.dev() != expected_device
        || metadata.ino() != expected_inode
    {
        return Err(Error::Permission(format!(
            "salvage {role} {} no longer matches the current-user 0600 inode bound in the journal",
            path.display()
        )));
    }
    file.set_len(0).map_err(|error| {
        Error::io(
            format!("truncate salvage {role} {}", path.display()),
            Some(error),
        )
    })?;
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        Error::io(
            format!("rewind salvage {role} {}", path.display()),
            Some(error),
        )
    })?;
    file.sync_all().map_err(|error| {
        Error::io(
            format!("sync truncated salvage {role} {}", path.display()),
            Some(error),
        )
    })?;
    Ok(OwnedFd::from(file))
}

#[cfg(not(unix))]
fn reopen_salvage_output(
    _path: &Path,
    _expected_device: u64,
    _expected_inode: u64,
    _role: &str,
) -> Result<OwnedFd> {
    Err(Error::Unsupported(
        "salvage output resume requires Unix".into(),
    ))
}

#[allow(clippy::too_many_arguments)]
fn finish_salvage_run(
    status: ResultStatus,
    actions: Vec<ActionRecord>,
    identity: &DeviceIdentity,
    handle: &BackendHandle,
    plan: &Plan,
    state_path: &Path,
    final_device_path: &str,
    output_path: &Path,
    map_path: &Path,
    mut backend_extras: Vec<(OwnedFd, String)>,
    recovery: Value,
) -> Result<(i32, Value)> {
    let image_fd = take_salvage_output(&mut backend_extras, "physical-image")?;
    let map_fd = take_salvage_output(&mut backend_extras, "physical-map")?;
    drop(backend_extras);

    let journal_state = nclr::journal::summarize(state_path)?;
    let output_epoch = journal_state
        .records
        .iter()
        .rev()
        .find(|record| {
            matches!(
                record.value.get("state").and_then(Value::as_str),
                Some("outputs-created" | "outputs-restarted")
            ) && record.value.get("plan_hash").and_then(Value::as_str)
                == Some(plan.plan_hash.as_str())
        })
        .and_then(|record| record.value.get("seq").and_then(Value::as_u64))
        .ok_or_else(|| Error::Invalid("salvage journal has no output epoch".into()))?;
    let salvage_details = journal_state.records.iter().rev().find_map(|record| {
        (record
            .value
            .get("seq")
            .and_then(Value::as_u64)
            .is_some_and(|seq| seq > output_epoch)
            && record.value.get("state").and_then(Value::as_str) == Some("action-completed")
            && record.value.get("plan_hash").and_then(Value::as_str)
                == Some(plan.plan_hash.as_str())
            && record.value.get("action").and_then(Value::as_str) == Some("salvage-physical"))
        .then(|| record.value.get("action_details").cloned())
        .flatten()
    });
    let (image_bytes, image_sha256) = digest_salvage_output(image_fd, "physical image")?;
    let (map_bytes, map_sha256) = digest_salvage_output(map_fd, "physical page map")?;
    if let Some(details) = salvage_details.as_ref() {
        let backend_bytes = details.get("image_bytes").and_then(Value::as_u64);
        let backend_digest = details.get("image_sha256").and_then(Value::as_str);
        if backend_bytes != Some(image_bytes) || backend_digest != Some(image_sha256.as_str()) {
            return Err(Error::Invalid(
                "physical image size or digest differs from the backend sweep".into(),
            ));
        }
    }
    let unreadable_pages = salvage_details
        .as_ref()
        .and_then(|details| details.get("unreadable_pages"))
        .and_then(Value::as_u64);
    let uncorrectable_pages = salvage_details
        .as_ref()
        .and_then(|details| details.get("uncorrectable_pages"))
        .and_then(Value::as_u64);
    let result_name = match status {
        ResultStatus::Interrupted => "interrupted",
        ResultStatus::Failed => "failed",
        _ if unreadable_pages == Some(0) && uncorrectable_pages == Some(0) => "complete",
        _ => "partial",
    };
    let code = match result_name {
        "complete" => errors::exit::OK,
        "partial" => errors::exit::DEGRADED,
        "interrupted" => errors::exit::INTERRUPTED,
        _ => errors::exit::DEVICE_IO,
    };
    Ok((
        code,
        json!({
            "schema": "nclr.salvage.v1",
            "result": result_name,
            "device_before": {
                "fingerprint": identity.fingerprint,
                "kernel_path": identity.kernel_path,
                "physical_path": identity.physical_path,
            },
            "device_after_path": final_device_path,
            "backend": {
                "id": handle.id,
                "version": handle.version,
                "sha256": handle.sha256,
                "profile": plan.backend.profile,
                "profile_sha256": plan.backend.profile_sha256,
            },
            "image": {
                "path": output_path,
                "bytes": image_bytes,
                "sha256": image_sha256,
                "layout": "flat-block-major,page-minor,data-then-oob",
            },
            "page_map": {
                "path": map_path,
                "bytes": map_bytes,
                "sha256": map_sha256,
                "schema": nclr::physical::MAP_SCHEMA,
            },
            "physical_read": salvage_details,
            "recovery": recovery,
            "actions": actions,
            "state_file": state_path,
        }),
    ))
}

fn salvage_plan_impl(
    device_path: &str,
    backend: Option<&str>,
    opts: &RunOptions,
    site: &nclr::config::SiteConfig,
) -> Result<Plan> {
    // The site's minimum erase grade is not a prerequisite for a read-only
    // acquisition. Backend allowlisting and exact-profile checks still
    // apply; only the unrelated C-grade floor is removed for this probe.
    let mut probe_site = site.clone();
    probe_site.minimum_level = None;
    let base = plan_impl(
        &PlanRequest {
            device_path,
            level: "controller",
            min_level: Some("C3"),
            no_fallback: true,
            aggressive_lba: false,
            backend,
            backend_dir: &opts.backend_dir,
            backend_timeout: opts.backend_timeout.unwrap_or(0),
            power_cycle: None,
        },
        &probe_site,
    )?;
    let identity = device::identify(device_path)?;
    let protected_area = base
        .domains
        .iter()
        .find(|domain| domain.id == "D5")
        .is_some_and(|domain| domain.state == "present");
    plan::plan_salvage(
        &identity,
        &base.backend,
        opts.backend_timeout,
        protected_area,
    )
}

fn cmd_salvage(
    device_path: &str,
    output_path: &Path,
    map_path: &Path,
    backend_id: Option<&str>,
    config: Option<&Path>,
    opts: &RunOptions,
) -> i32 {
    let result = (|| -> Result<(i32, Value)> {
        if output_path == map_path {
            return Err(Error::Usage(
                "salvage --output and --map must be different files".into(),
            ));
        }
        let site = nclr::config::load(config)?;
        let plan = salvage_plan_impl(device_path, backend_id, opts, &site)?;
        let OpenRun {
            device_path: runtime_device_path,
            identity,
            handle,
            mut device_fd,
            mut journal,
            state_path,
            _lock,
            mut backend_extras,
        } = open_for_run(
            &plan,
            Some(device_path),
            opts,
            &site,
            std::slice::from_ref(&plan.device.fingerprint),
        )?;

        journal.record("plan", "locked", |record| {
            record.device = Some(identity.fingerprint.clone());
            record.device_path = Some(runtime_device_path.clone());
            record.plan_hash = Some(plan.plan_hash.clone());
            record.plan = Some(serde_json::to_value(&plan).unwrap());
        })?;
        if !opts.quiet {
            eprintln!(
                "nclr: physical salvage target {}, {}, fingerprint {}",
                identity.kernel_path,
                confirm::human_capacity(identity.capacity_bytes),
                &identity.fingerprint[..24]
            );
            eprintln!(
                "nclr: output {} with page map {}",
                output_path.display(),
                map_path.display()
            );
        }
        confirm::confirm(&identity, opts.yes)?;
        let ready = device::identify(&runtime_device_path)?;
        verify_plan_device(
            &plan,
            &ready,
            std::slice::from_ref(&plan.device.fingerprint),
        )?;
        nclr::safety::preflight_read(
            &ready,
            &nclr::safety::SafetyOptions {
                unmount: false,
                allow_nonremovable: opts.allow_nonremovable,
            },
        )?;

        // Existing files are never overwritten. Destinations are created
        // only after confirmation and the final identity/safety check.
        let image_fd = create_salvage_output(output_path)?;
        let map_fd = match create_salvage_output(map_path) {
            Ok(file) => file,
            Err(error) => {
                drop(image_fd);
                let _ = std::fs::remove_file(output_path);
                return Err(error);
            }
        };
        let binding = match bind_salvage_outputs(output_path, &image_fd, map_path, &map_fd) {
            Ok(binding) => binding,
            Err(error) => {
                drop(image_fd);
                drop(map_fd);
                let _ = std::fs::remove_file(output_path);
                let _ = std::fs::remove_file(map_path);
                return Err(error);
            }
        };
        if let Err(error) =
            journal_salvage_outputs(&mut journal, &plan.plan_hash, &binding, "outputs-created")
        {
            drop(image_fd);
            drop(map_fd);
            let _ = std::fs::remove_file(output_path);
            let _ = std::fs::remove_file(map_path);
            return Err(error);
        }
        backend_extras.push((image_fd, "physical-image".into()));
        backend_extras.push((map_fd, "physical-map".into()));

        let (status, actions, _evidence, _health, final_device_path) = execute_plan_actions(
            &plan,
            &handle,
            &runtime_device_path,
            &mut device_fd,
            &mut journal,
            opts,
            None,
            None,
            None,
            &new_reenum_nonce(),
            std::slice::from_ref(&plan.device.fingerprint),
            &mut backend_extras,
        );
        let recovery = if matches!(status, ResultStatus::Failed | ResultStatus::Interrupted) {
            match backend::call(
                &handle,
                "recover",
                &device_fd,
                None,
                &Request {
                    api: nclr::BACKEND_API,
                    op: "recover".into(),
                    action: None,
                    seed: None,
                    device_is_file: Some(device::is_regular_file(&runtime_device_path)),
                    limits: req_limits(),
                    params: None,
                    device: Some(identity.clone()),
                    extra_fds: extra_fd_request(&backend_extras),
                },
                &extra_fd_sources(&backend_extras),
                opts.backend_timeout,
            ) {
                Ok(response) if response.ok() => json!({
                    "ok": true,
                    "method": response.value.get("recovery"),
                    "automated": response.value.get("automated"),
                }),
                Ok(response) => json!({ "ok": false, "error": response.message() }),
                Err(error) => json!({ "ok": false, "error": error.to_string() }),
            }
        } else {
            Value::Null
        };
        finish_salvage_run(
            status,
            actions,
            &identity,
            &handle,
            &plan,
            &state_path,
            &final_device_path,
            output_path,
            map_path,
            backend_extras,
            recovery,
        )
    })();

    match result {
        Ok((code, summary)) => {
            if opts.json {
                println!("{}", serde_json::to_string_pretty(&summary).unwrap());
            } else {
                eprintln!(
                    "nclr: salvage {}: image {}, map {}",
                    summary
                        .get("result")
                        .and_then(Value::as_str)
                        .unwrap_or("failed"),
                    output_path.display(),
                    map_path.display()
                );
            }
            code
        }
        Err(error) => {
            eprintln!("nclr: {error}");
            error.exit_code()
        }
    }
}

// ---------------------------------------------------------------------------
// resume
// ---------------------------------------------------------------------------

fn cmd_resume_salvage(
    state_file: &Path,
    opts: &RunOptions,
    site: &nclr::config::SiteConfig,
) -> i32 {
    let result = (|| -> Result<(i32, Value)> {
        let journal_state = nclr::journal::summarize(state_file)?;
        let plan_value = journal_state.plan.as_ref().ok_or_else(|| {
            Error::Invalid(format!(
                "journal {} does not embed a plan; cannot resume",
                state_file.display()
            ))
        })?;
        let plan = plan::validate(plan_value)?;
        if plan.requested_level != "salvage" {
            return Err(Error::Invalid(
                "salvage resume received a non-salvage plan".into(),
            ));
        }
        if journal_state.fallback_plan.is_some() {
            return Err(Error::Invalid(
                "salvage journal must not contain a fallback plan".into(),
            ));
        }
        site.enforce_plan(&plan)?;
        let binding = salvage_output_binding(&journal_state, &plan.plan_hash)?;

        let mut accepted_fingerprints = vec![plan.device.fingerprint.clone()];
        if let Some(fingerprint) = &journal_state.device_fingerprint {
            if !accepted_fingerprints.contains(fingerprint) {
                accepted_fingerprints.push(fingerprint.clone());
            }
        }
        for record in &journal_state.records {
            if matches!(
                record.value.get("state").and_then(Value::as_str),
                Some("capacity-committed" | "service-reenumerated" | "device-reenumerated")
            ) {
                if let Some(fingerprint) = record.value.get("device").and_then(Value::as_str) {
                    if !accepted_fingerprints
                        .iter()
                        .any(|known| known == fingerprint)
                    {
                        accepted_fingerprints.push(fingerprint.to_owned());
                    }
                }
            }
        }
        let reenumeration_pending = journal_state
            .records
            .iter()
            .rev()
            .find_map(|record| {
                let action = record.value.get("action").and_then(Value::as_str);
                if !matches!(
                    action,
                    Some("enter-service-mode" | "exit-service-mode" | "re-enumeration")
                ) {
                    return None;
                }
                match record.value.get("state").and_then(Value::as_str) {
                    Some("action-started") => Some(true),
                    Some("action-completed") => Some(false),
                    _ => None,
                }
            })
            .unwrap_or(false);
        let mut resume_device_path = journal_state
            .device_path
            .clone()
            .ok_or_else(|| Error::Invalid("salvage journal has no device path".into()))?;
        if reenumeration_pending && plan.backend.id == "controller" {
            let candidates = device::list_all_devices()?
                .into_iter()
                .filter(|identity| identity.physical_path == plan.device.physical_path)
                .collect::<Vec<_>>();
            let identity = match candidates.as_slice() {
                [identity] => identity,
                [] => {
                    return Err(Error::Interrupted(format!(
                        "controller is still absent from physical path {}; attach it and resume",
                        plan.device.physical_path
                    )))
                }
                _ => {
                    return Err(Error::Permission(format!(
                        "multiple devices are present at controller physical path {}",
                        plan.device.physical_path
                    )))
                }
            };
            resume_device_path = identity.kernel_path.clone();
            if !accepted_fingerprints.contains(&identity.fingerprint) {
                accepted_fingerprints.push(identity.fingerprint.clone());
            }
        }

        let mut resume_opts = opts.clone();
        resume_opts.state = Some(state_file.to_path_buf());
        let OpenRun {
            device_path,
            identity,
            handle,
            mut device_fd,
            mut journal,
            state_path,
            _lock,
            mut backend_extras,
        } = open_for_run(
            &plan,
            Some(&resume_device_path),
            &resume_opts,
            site,
            &accepted_fingerprints,
        )?;
        if !accepted_fingerprints.contains(&identity.fingerprint) {
            return Err(Error::Permission(format!(
                "salvage journal device does not match {}; refusing to resume",
                identity.fingerprint
            )));
        }

        let backend_status = backend::call(
            &handle,
            "status",
            &device_fd,
            None,
            &Request {
                api: nclr::BACKEND_API,
                op: "status".into(),
                action: None,
                seed: None,
                device_is_file: Some(device::is_regular_file(&device_path)),
                limits: req_limits(),
                params: None,
                device: Some(identity.clone()),
                extra_fds: extra_fd_request(&backend_extras),
            },
            &extra_fd_sources(&backend_extras),
            opts.backend_timeout,
        )?;
        if !backend_status.ok() {
            return Err(Error::Backend(format!(
                "backend status check failed: {}",
                backend_status.message()
            )));
        }
        if backend_status.value.get("state").and_then(Value::as_str) == Some("in-progress") {
            return Err(Error::Interrupted(
                "controller operation is still in progress; resume after it becomes ready".into(),
            ));
        }
        let in_service = backend_status
            .value
            .get("service_mode")
            .and_then(Value::as_bool)
            .or_else(|| {
                backend_status
                    .value
                    .get("controller")
                    .and_then(|value| value.get("service_mode"))
                    .and_then(Value::as_bool)
            })
            .ok_or_else(|| {
                Error::Invalid("salvage status did not report controller service mode".into())
            })?;

        if !opts.quiet {
            eprintln!(
                "nclr: restarting physical salvage plan {} on {}",
                plan.id, identity.kernel_path
            );
            eprintln!(
                "nclr: output {} with page map {}",
                binding.image_path.display(),
                binding.map_path.display()
            );
        }
        confirm::confirm(&identity, opts.yes)?;
        let ready = device::identify(&device_path)?;
        verify_plan_device(&plan, &ready, &accepted_fingerprints)?;
        nclr::safety::preflight_read(
            &ready,
            &nclr::safety::SafetyOptions {
                unmount: false,
                allow_nonremovable: opts.allow_nonremovable,
            },
        )?;

        journal_salvage_outputs(&mut journal, &plan.plan_hash, &binding, "outputs-restarted")?;
        let image_fd = reopen_salvage_output(
            &binding.image_path,
            binding.image_device,
            binding.image_inode,
            "physical image",
        )?;
        let map_fd = reopen_salvage_output(
            &binding.map_path,
            binding.map_device,
            binding.map_inode,
            "physical page map",
        )?;
        backend_extras.push((image_fd, "physical-image".into()));
        backend_extras.push((map_fd, "physical-map".into()));

        // The raw read is safe to repeat. Restart it from page zero so the
        // image, page map and their ordered digests always describe one
        // complete sweep. Service entry is repeated only when status proves
        // that the controller is currently in normal mode.
        let resume_after_seq = in_service
            .then(|| plan.action("enter-service-mode").map(|action| action.seq))
            .flatten();
        let (status, actions, _evidence, _health, final_device_path) = execute_plan_actions(
            &plan,
            &handle,
            &device_path,
            &mut device_fd,
            &mut journal,
            opts,
            resume_after_seq,
            None,
            None,
            &new_reenum_nonce(),
            &accepted_fingerprints,
            &mut backend_extras,
        );
        let recovery = if matches!(status, ResultStatus::Failed | ResultStatus::Interrupted) {
            match backend::call(
                &handle,
                "recover",
                &device_fd,
                None,
                &Request {
                    api: nclr::BACKEND_API,
                    op: "recover".into(),
                    action: None,
                    seed: None,
                    device_is_file: Some(device::is_regular_file(&device_path)),
                    limits: req_limits(),
                    params: None,
                    device: Some(identity.clone()),
                    extra_fds: extra_fd_request(&backend_extras),
                },
                &extra_fd_sources(&backend_extras),
                opts.backend_timeout,
            ) {
                Ok(response) if response.ok() => json!({
                    "ok": true,
                    "method": response.value.get("recovery"),
                    "automated": response.value.get("automated"),
                }),
                Ok(response) => json!({ "ok": false, "error": response.message() }),
                Err(error) => json!({ "ok": false, "error": error.to_string() }),
            }
        } else {
            Value::Null
        };
        finish_salvage_run(
            status,
            actions,
            &identity,
            &handle,
            &plan,
            &state_path,
            &final_device_path,
            &binding.image_path,
            &binding.map_path,
            backend_extras,
            recovery,
        )
    })();

    match result {
        Ok((code, summary)) => {
            if opts.json {
                println!("{}", serde_json::to_string_pretty(&summary).unwrap());
            } else {
                eprintln!(
                    "nclr: salvage {}: image {}, map {}",
                    summary
                        .get("result")
                        .and_then(Value::as_str)
                        .unwrap_or("failed"),
                    summary["image"]["path"].as_str().unwrap_or("(unknown)"),
                    summary["page_map"]["path"].as_str().unwrap_or("(unknown)")
                );
            }
            code
        }
        Err(error) => {
            eprintln!("nclr: {error}");
            error.exit_code()
        }
    }
}

fn cmd_resume(config: Option<&Path>, state_file: &Path, opts: &RunOptions) -> i32 {
    let site = match nclr::config::load(config) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("nclr: {e}");
            return e.exit_code();
        }
    };
    if let Some(cmd) = &opts.power_cycle {
        if site.restricts_power_cycle() && !site.power_cycle_allowlist().iter().any(|a| a == cmd) {
            eprintln!(
                "nclr: permission denied: power-cycle command {cmd} is not allowed by the site policy"
            );
            return errors::exit::PERMISSION;
        }
    }
    let resume_plan = match nclr::journal::summarize(state_file).and_then(|state| {
        state
            .plan
            .as_ref()
            .ok_or_else(|| {
                Error::Invalid(format!(
                    "journal {} does not embed a plan; cannot resume",
                    state_file.display()
                ))
            })
            .and_then(plan::validate)
    }) {
        Ok(plan) => plan,
        Err(error) => {
            eprintln!("nclr: {error}");
            return error.exit_code();
        }
    };
    if resume_plan.requested_level == "salvage" {
        return cmd_resume_salvage(state_file, opts, &site);
    }
    let result = (|| -> Result<(i32, Option<Report>)> {
        let journal_state = nclr::journal::summarize(state_file)?;
        let Some(plan_value) = &journal_state.plan else {
            return Err(Error::Invalid(format!(
                "journal {} does not embed a plan; cannot resume",
                state_file.display()
            )));
        };
        let mut plan = plan::validate(plan_value)?;
        site.enforce_plan(&plan)?;
        // A documented fallback (C2 -> L1) recorded in the journal becomes
        // the plan we resume with.
        if let Some(fb) = &journal_state.fallback_plan {
            plan = plan::validate(fb)?;
        }
        // Accepted identities: the plan-time fingerprint plus any post-commit
        // identities recorded by a controller rebuild (capacity change).
        let mut accepted_fingerprints = Vec::new();
        if let Some(fp) = &journal_state.device_fingerprint {
            accepted_fingerprints.push(fp.clone());
        }
        for r in &journal_state.records {
            if matches!(
                r.value.get("state").and_then(|v| v.as_str()),
                Some("capacity-committed" | "service-reenumerated" | "device-reenumerated")
            ) {
                if let Some(fp) = r.value.get("device").and_then(|v| v.as_str()) {
                    accepted_fingerprints.push(fp.to_string());
                }
            }
        }
        let reenumeration_pending = journal_state
            .records
            .iter()
            .rev()
            .find_map(|record| {
                let action = record.value.get("action").and_then(|v| v.as_str());
                if !matches!(
                    action,
                    Some("enter-service-mode" | "exit-service-mode" | "re-enumeration")
                ) {
                    return None;
                }
                match record.value.get("state").and_then(|v| v.as_str()) {
                    Some("action-started") => Some(true),
                    Some("action-completed") => Some(false),
                    _ => None,
                }
            })
            .unwrap_or(false);
        let mut resume_device_path = journal_state.device_path.clone().unwrap_or_default();
        if reenumeration_pending && plan.backend.id == "controller" {
            let candidates = device::list_all_devices()?
                .into_iter()
                .filter(|identity| identity.physical_path == plan.device.physical_path)
                .collect::<Vec<_>>();
            let identity = match candidates.as_slice() {
                [identity] => identity,
                [] => {
                    return Err(Error::Interrupted(format!(
                        "controller is still absent from physical path {}; attach it and resume",
                        plan.device.physical_path
                    )))
                }
                _ => {
                    return Err(Error::Permission(format!(
                        "multiple devices are present at controller physical path {}",
                        plan.device.physical_path
                    )))
                }
            };
            resume_device_path = identity.kernel_path.clone();
            if !accepted_fingerprints.contains(&identity.fingerprint) {
                accepted_fingerprints.push(identity.fingerprint.clone());
            }
        }
        let device_arg = if resume_device_path.is_empty() {
            None
        } else {
            Some(resume_device_path.as_str())
        };

        let start = std::time::Instant::now();
        let mut resume_opts = opts.clone();
        resume_opts.state = Some(state_file.to_path_buf());
        let OpenRun {
            device_path,
            identity,
            handle,
            mut device_fd,
            mut journal,
            state_path,
            _lock,
            mut backend_extras,
        } = open_for_run(
            &plan,
            device_arg,
            &resume_opts,
            &site,
            &accepted_fingerprints,
        )?;

        // Verify the journal device fingerprint matches the current device.
        if !accepted_fingerprints.contains(&identity.fingerprint) {
            return Err(Error::Permission(format!(
                "journal device fingerprint {} does not match device {}; refusing to resume",
                journal_state
                    .device_fingerprint
                    .as_deref()
                    .unwrap_or("(none)"),
                identity.fingerprint
            )));
        }

        if !opts.quiet {
            eprintln!(
                "nclr: resuming plan {} on {} at action {}",
                plan.id,
                identity.kernel_path,
                journal_state
                    .last_completed_action
                    .as_deref()
                    .unwrap_or("(start)")
            );
        }

        // Backend status check before continuing (resume safety).
        let status = backend::call(
            &handle,
            "status",
            &device_fd,
            None,
            &Request {
                api: nclr::BACKEND_API,
                op: "status".into(),
                action: None,
                seed: None,
                device_is_file: Some(device::is_regular_file(&device_path)),
                limits: req_limits(),
                params: None,
                device: Some(identity.clone()),
                extra_fds: extra_fd_request(&backend_extras),
            },
            &extra_fd_sources(&backend_extras),
            opts.backend_timeout,
        )?;
        if !status.ok() {
            return Err(Error::Backend(format!(
                "backend status check failed: {}",
                status.message()
            )));
        }

        confirm::confirm(&identity, opts.yes)?;

        let mut report = Report::new(&plan);
        report.device_before = json!({
            "fingerprint": identity.fingerprint,
            "capacity_bytes": identity.capacity_bytes,
            "kernel_path": identity.kernel_path,
        });
        report.state_file = Some(state_path.display().to_string());

        // Resume after the last action that completed in this plan generation,
        // rebuilding the evidence from the journal's action-completed records.
        let completed: Vec<&str> = journal_state
            .completed_by_plan
            .iter()
            .filter(|(hash, _)| hash == &plan.plan_hash)
            .map(|(_, action)| action.as_str())
            .collect();
        if completed.len() > plan.actions.len()
            || completed
                .iter()
                .zip(&plan.actions)
                .any(|(completed, planned)| *completed != planned.id)
        {
            return Err(Error::Invalid(format!(
                "journal completed actions are not an exact prefix of plan {}",
                plan.id
            )));
        }
        let resume_after_seq = completed
            .last()
            .and_then(|_| plan.actions.get(completed.len().saturating_sub(1)))
            .map(|action| action.seq);
        let mut initial_evidence = new_evidence_for_plan(&plan);
        let mut initial_health = HealthEvidence::default();
        let mut power_cycled = false;
        for r in &journal_state.records {
            if r.value.get("state").and_then(|v| v.as_str()) != Some("action-completed") {
                continue;
            }
            if r.value.get("plan_hash").and_then(|v| v.as_str()) != Some(plan.plan_hash.as_str()) {
                continue;
            }
            let id = r.value.get("action").and_then(|v| v.as_str()).unwrap_or("");
            let status = r
                .value
                .get("action_status")
                .and_then(|v| v.as_str())
                .unwrap_or("");
            let errs = r
                .value
                .get("action_errors")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let details = r.value.get("action_details").cloned();
            if id == "power-cycle" && status == "ok" {
                power_cycled = true;
            }
            apply_outcome_to_evidence(
                &mut initial_evidence,
                id,
                status,
                errs,
                details.as_ref(),
                power_cycled,
                plan.device.capacity_bytes,
                &mut initial_health,
            );
        }
        let evidence_path = evidence_path_for(opts, &plan.id)?;
        let (status, actions, mut evidence, health, final_device_path) = execute_plan_actions(
            &plan,
            &handle,
            &device_path,
            &mut device_fd,
            &mut journal,
            opts,
            resume_after_seq,
            Some(initial_evidence),
            evidence_path.as_deref(),
            &new_reenum_nonce(),
            &accepted_fingerprints,
            &mut backend_extras,
        );
        if let Some(p) = &evidence_path {
            if let Some(digest) = evidence_digest(Some(p))? {
                report.evidence_file = Some(p.display().to_string());
                report.evidence_sha256 = Some(digest);
            }
        }
        report.actions = actions;

        let identity_after = match device::identify(&final_device_path) {
            Ok(identity) => Some(identity),
            Err(error) if status == ResultStatus::Interrupted => {
                report.device_after = json!({
                    "available": false,
                    "kernel_path": final_device_path,
                    "error": error.to_string(),
                });
                None
            }
            Err(error) => return Err(error),
        };
        if let Some(identity_after) = identity_after.as_ref() {
            report.device_after = json!({
                "fingerprint": identity_after.fingerprint,
                "capacity_bytes": identity_after.capacity_bytes,
                "kernel_path": identity_after.kernel_path,
            });
        }
        let mut health = health;
        // Capacity stability for a controller rebuild compares against the
        // capacity committed by the rebuild (a planned shrink is not
        // instability). Sector size stability (§1170) is verified against
        // the before-run identity.
        health.capacity_stable = identity_after.as_ref().is_some_and(|identity_after| {
            (match evidence.expected_capacity_bytes() {
                Some(expected) => identity_after.capacity_bytes == expected,
                None => identity_after.capacity_bytes == identity.capacity_bytes,
            }) && identity_after.logical_block_size == identity.logical_block_size
        });
        evidence.constrain_capacity_stability(health.capacity_stable);

        let grade_result = evidence.compute();
        let h = compute_health(&health);
        // The minimum level for the resume: the original plan's floor (which
        // already reflected the site policy) is authoritative even when a
        // fallback plan with a lower default is being resumed.
        let original_plan_min = journal_state
            .plan
            .as_ref()
            .map(|pv| plan::validate(pv).map(|p| p.minimum_level))
            .transpose()?
            .unwrap_or_else(|| plan.minimum_level.clone());
        let min_grade = CGrade::parse(&original_plan_min).unwrap_or(CGrade::C1);
        let min_met = grade_result.grade >= min_grade;
        let residual_ok = matches!(
            grade_result.residual,
            nclr::grade::Residual::NoneKnown | nclr::grade::Residual::Unreachable
        );
        let result = match status {
            ResultStatus::Interrupted => ResultStatus::Interrupted,
            ResultStatus::Failed => ResultStatus::Failed,
            _ => {
                if grade_result.qualified && h >= nclr::grade::HGrade::H2 && min_met && residual_ok
                {
                    ResultStatus::Ok
                } else {
                    ResultStatus::Degraded
                }
            }
        };
        report.result = result.as_str().to_string();
        // Resume information for an interrupted run.
        if result == ResultStatus::Interrupted {
            report.resume = Some(json!({
                "command": "nclr resume",
                "state_file": state_file.display().to_string(),
                "device": device_path,
                "plan_id": plan.id,
            }));
        }
        report.achieved_grade = grade_result.grade.as_str().to_string();
        report.grade_qualified = grade_result.qualified;
        report.residual = grade_result.residual.as_str().to_string();
        report.health_grade = h.as_str().to_string();
        report.coverage = match &evidence {
            GradeEvidence::Lba(e) => nclr::report::lba_coverage(e.io_errors),
            GradeEvidence::Device(e) => nclr::report::device_erase_coverage(
                e.erase_completed,
                e.blank_verify,
                e.io_errors,
                &plan,
            ),
            GradeEvidence::Controller(e) => nclr::report::controller_coverage(e),
            GradeEvidence::Physical(e) => nclr::report::physical_coverage(
                e.blocks_erase_failed,
                e.old_rbb_erase_attempted,
                e.rbb_count,
                e.old_rbb_erased,
                e.old_rbb_erase_failed,
                e.unknown_reservation,
                e.bbt_ftl_rebuilt,
            ),
        };
        if let Some(d5) = nclr::report::d5_coverage(&plan) {
            report.coverage.push(d5);
        }
        report.postcheck = PostCheck {
            recipe: match &evidence {
                GradeEvidence::Physical(_) => "P1",
                GradeEvidence::Controller(_) => "P2",
                GradeEvidence::Device(_) => "P2",
                GradeEvidence::Lba(_) => "L1",
            }
            .into(),
            passed: grade_result.qualified && h >= nclr::grade::HGrade::H2,
            power_cycle_performed: Some(evidence.power_cycled()),
            details: Some(match &evidence {
                GradeEvidence::Lba(e) => json!({
                    "resumed": true,
                    "full_overwrite": e.full_overwrite,
                    "prbs_verify": e.prbs_verify,
                    "zero_verify": e.zero_verify,
                    "signature_free": e.signature_free,
                    "flush_ok": e.flush_ok,
                    "io_errors": e.io_errors,
                    "min_level_met": min_met,
                    "min_level": plan.minimum_level,
                }),
                GradeEvidence::Device(e) => json!({
                    "resumed": true,
                    "erase_completed": e.erase_completed,
                    "scope_documented": e.scope_documented,
                    "blank_verify": e.blank_verify,
                    "signature_free": e.signature_free,
                    "capacity_stable": e.capacity_stable,
                    "postcheck_reads_ok": e.postcheck_reads_ok,
                    "postcheck_signature_free": e.postcheck_signature_free,
                    "postcheck_flush_ok": e.postcheck_flush_ok,
                    "io_errors": e.io_errors,
                    "min_level_met": min_met,
                    "min_level": plan.minimum_level,
                }),
                GradeEvidence::Physical(e) => json!({
                    "resumed": true,
                    "enumeration_complete": e.enumeration_complete,
                    "blocks_declared": e.blocks_declared,
                    "blocks_classified": e.blocks_classified,
                    "blocks_enumerated": e.blocks_enumerated,
                    "blocks_erased": e.blocks_erased,
                    "blocks_erase_failed": e.blocks_erase_failed,
                    "physical_sweep_complete": e.physical_sweep_complete,
                    "physical_pages": e.physical_pages,
                    "physical_readable_pages": e.physical_readable_pages,
                    "physical_unreadable_pages": e.physical_unreadable_pages,
                    "physical_uncorrectable_pages": e.physical_uncorrectable_pages,
                    "ordered_sweep_sha256": e.ordered_sweep_sha256,
                    "target_pages": e.target_pages,
                    "target_readable_pages": e.target_readable_pages,
                    "target_unreadable_pages": e.target_unreadable_pages,
                    "target_uncorrectable_pages": e.target_uncorrectable_pages,
                    "target_non_erased_pages": e.target_non_erased_pages,
                    "excluded_unreadable_pages": e.excluded_unreadable_pages,
                    "old_bbt_captured": e.old_bbt_captured,
                    "old_bbt_sha256": e.old_bbt_sha256,
                    "old_bbt_copies": e.old_bbt_copies,
                    "old_rbb_erase_attempted": e.old_rbb_erase_attempted,
                    "old_rbb_erase_failed": e.old_rbb_erase_failed,
                    "fbb_preserved": e.fbb_preserved,
                    "weak_isolated": e.weak_isolated,
                    "unknown_reservation": e.unknown_reservation,
                    "bbt_ftl_rebuilt": e.bbt_ftl_rebuilt,
                    "capacity_stable": e.capacity_stable,
                    "logical_reads_ok": e.logical_reads_ok,
                    "logical_blank_verified": e.logical_blank_verified,
                    "signature_free": e.signature_free,
                    "flush_ok": e.flush_ok,
                    "spare_ok": e.spare_ok,
                    "expected_capacity_bytes": e.expected_capacity_bytes,
                    "io_errors": e.io_errors,
                    "min_level_met": min_met,
                    "min_level": plan.minimum_level,
                }),
                GradeEvidence::Controller(e) => json!({
                    "resumed": true,
                    "old_bbt_captured": e.old_bbt_captured,
                    "old_bbt_sha256": e.old_bbt_sha256,
                    "old_bbt_copies": e.old_bbt_copies,
                    "old_rbb_erase_attempted": e.old_rbb_erase_attempted,
                    "old_rbb_erase_failed": e.old_rbb_erase_failed,
                    "final_erase_failed": e.final_erase_failed,
                    "fbb_preserved": e.fbb_preserved,
                    "new_bbt_committed": e.new_bbt_committed,
                    "ftl_rebuilt": e.ftl_rebuilt,
                    "capacity_stable": e.capacity_stable,
                    "logical_reads_ok": e.logical_reads_ok,
                    "logical_blank_verified": e.logical_blank_verified,
                    "signature_free": e.signature_free,
                    "flush_ok": e.flush_ok,
                    "spare_ok": e.spare_ok,
                    "weak_isolated": e.weak_isolated,
                    "expected_capacity_bytes": e.expected_capacity_bytes,
                    "io_errors": e.io_errors,
                    "min_level_met": min_met,
                    "min_level": plan.minimum_level,
                }),
            }),
        };
        // A2/A4: FTL object and old/new BBT summary for controller paths.
        let (ftl, bbt_summary) = controller_summary(&evidence, &plan);
        report.ftl = ftl;
        if bbt_summary != Value::Null {
            let details = report
                .postcheck
                .details
                .get_or_insert(serde_json::json!({}));
            if let Some(obj) = details.as_object_mut() {
                obj.insert("bbt_summary".into(), bbt_summary);
            }
        }
        report.final_state = if matches!(result, ResultStatus::Failed | ResultStatus::Interrupted)
            || !report.postcheck.passed
        {
            "undetermined".to_string()
        } else {
            "raw-uninitialized".to_string()
        };
        report.times = json!({
            "start": report.times.get("start").cloned().unwrap_or(json!("")),
            "end": nclr::journal::utc_now_rfc3339(),
            "duration_ms": start.elapsed().as_millis() as u64,
        });
        report.report_hash = report.compute_hash();

        let code = match result {
            ResultStatus::Ok => errors::exit::OK,
            ResultStatus::Degraded => errors::exit::DEGRADED,
            ResultStatus::Interrupted => errors::exit::INTERRUPTED,
            ResultStatus::Failed => errors::exit::DEVICE_IO,
            ResultStatus::Unsupported => errors::exit::UNSUPPORTED,
        };
        Ok((code, Some(report)))
    })();

    match result {
        Ok((code, Some(report))) => {
            if opts.summary {
                let s = nclr::report::SummaryReport::from_report(&report);
                if opts.json {
                    println!("{}", serde_json::to_string_pretty(&s).unwrap());
                } else {
                    eprintln!("nclr: {}", s.one_line());
                }
            } else if opts.json {
                println!("{}", serde_json::to_string_pretty(&report).unwrap());
            } else {
                eprintln!("nclr: completed: {}", report.summary());
            }
            code
        }
        Ok((code, None)) => code,
        Err(e) => {
            eprintln!("nclr: {e}");
            e.exit_code()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        local_controller_research, local_sd_research, model_name, should_heartbeat,
        validate_events_fd, vendor_name,
    };
    use nclr::device::{DeviceIdentity, MmcInfo, ScsiInfo, UsbInfo};
    use std::os::fd::AsRawFd;

    #[test]
    fn heartbeat_threshold() {
        assert!(!should_heartbeat(0, 30));
        assert!(!should_heartbeat(29, 30));
        assert!(should_heartbeat(30, 30));
        assert!(should_heartbeat(120, 30));
        assert!(!should_heartbeat(30, 0), "disabled threshold");
    }

    #[test]
    fn event_destination_must_be_an_open_non_stdio_fd() {
        assert!(validate_events_fd(None).is_ok());
        assert!(validate_events_fd(Some(1)).is_err());
        assert!(validate_events_fd(Some(-1)).is_err());
        let file = tempfile::tempfile().unwrap();
        assert!(validate_events_fd(Some(file.as_raw_fd())).is_ok());
    }

    fn usb(vid: &str, pid: &str, manufacturer: &str) -> UsbInfo {
        UsbInfo {
            vid: vid.into(),
            pid: pid.into(),
            bcd_device: String::new(),
            serial: String::new(),
            manufacturer: manufacturer.into(),
            product: String::new(),
            port_chain: String::new(),
        }
    }

    #[test]
    fn vendor_name_uses_manufacturer_fallback_for_unknown_ids() {
        // usb.ids parsing is covered in profile tests with deterministic
        // data. This wrapper must remain useful when macOS has no usb.ids.
        let unknown = usb("ffff", "0000", "Some Brand");
        assert_eq!(vendor_name(&unknown).as_deref(), Some("Some Brand"));
        let absent = usb("ffff", "0000", "  ");
        assert_eq!(vendor_name(&absent), None);
    }

    #[test]
    fn model_name_is_absent_for_an_unlisted_id() {
        let unlisted = usb("ffff", "0000", "x");
        assert_eq!(model_name(&unlisted), None);
    }

    #[test]
    fn unsupported_usb_research_bundle_is_command_free_and_complete() {
        let mut identity = DeviceIdentity::new("usb-msd", "/dev/disk9", "usb:location-id:1");
        identity.usb = Some(UsbInfo {
            vid: "ffff".into(),
            pid: "1234".into(),
            bcd_device: "0102".into(),
            serial: "SERIAL".into(),
            manufacturer: "OEM".into(),
            product: "Flash".into(),
            port_chain: "location-id:00000001".into(),
        });
        identity.scsi = Some(ScsiInfo {
            vendor: "OEM".into(),
            model: "Flash Disk".into(),
            rev: "1.00".into(),
            sg_path: String::new(),
        });

        let bundle = local_controller_research(&identity).unwrap();
        assert_eq!(bundle["selection"], "undetermined");
        assert_eq!(bundle["media_commands_sent"].as_array().unwrap().len(), 0);
        assert_eq!(bundle["unknown_vendor_commands_sent"], false);
        assert_eq!(
            bundle["recipe_family_candidates"].as_array().unwrap().len(),
            nclr::controller_protocol::Family::ALL.len()
        );
        assert_eq!(bundle["exact_bootstrap_observed"]["usb_serial"], "SERIAL");
        assert_eq!(bundle["exact_bootstrap_observed"]["scsi_revision"], "1.00");
        assert!(bundle["missing_for_production"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| {
                value.as_str() == Some("independent HIL qualification and power-cut evidence")
            }));
    }

    #[test]
    fn native_sd_research_bundle_preserves_registers_without_claiming_controller_access() {
        let mut identity = DeviceIdentity::new("mmc", "/dev/mmcblk0", "mmc-host:mmc0");
        identity.capacity_bytes = 64 * 1024 * 1024 * 1024;
        identity.mmc = Some(MmcInfo {
            cid: "035344534433324780abcdef01234567".into(),
            csd: "400e00325b590000edc97f800a400000".into(),
            scr: "0235800100000000".into(),
            manfid: "0x03".into(),
            oemid: "SD".into(),
            name: "SD32G".into(),
            serial: "abcdef01".into(),
            date: "01/2025".into(),
            host: "mmc0".into(),
            kind: "SD".into(),
            erase_size_bytes: 512,
            preferred_erase_size_bytes: 4 * 1024 * 1024,
        });

        let bundle = local_sd_research(&identity).unwrap();
        assert_eq!(bundle["selection"], "card-registers-complete");
        assert_eq!(bundle["controller_destructive_ready"], false);
        assert_eq!(bundle["standard_full_user_erase"]["candidate"], true);
        assert_eq!(bundle["standard_full_user_erase"]["addressing"], "block");
        assert_eq!(bundle["exact_card_observed"]["card_kind"], "SD");
        assert_eq!(bundle["media_commands_sent"].as_array().unwrap().len(), 0);
        assert_eq!(bundle["unknown_vendor_commands_sent"], false);
        assert!(bundle["missing_for_production"]
            .as_array()
            .unwrap()
            .iter()
            .any(|value| value.as_str()
                == Some("independent HIL qualification and physical-reader evidence")));
    }
}

#[cfg(test)]
mod scratch_tests {
    use super::parse_scratch_range;

    #[test]
    fn scratch_overflow_is_a_usage_error() {
        // u64::MAX start would overflow start * 512 in debug builds.
        let err = parse_scratch_range(Some("18446744073709551615:1"), u64::MAX);
        assert!(
            err.is_err(),
            "overflowing start must be rejected, not panic"
        );
        let err = parse_scratch_range(Some("0:18446744073709551615"), u64::MAX);
        assert!(err.is_err(), "overflowing count must be rejected");
        // Normal ranges still work.
        let r = parse_scratch_range(Some("100:64"), 1024 * 1024)
            .unwrap()
            .unwrap();
        assert_eq!(r, (100, 64));
        // Past-capacity ranges are rejected.
        assert!(parse_scratch_range(Some("0:1000000"), 1024 * 1024).is_err());
    }
}
