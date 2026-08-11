//! nclr-lab: research tooling. Protocol inference and replay are separate
//! from destructive handlers. The artifact verifier is deliberately shared
//! with `nclr run` so both paths authenticate identical bytes. Write-command
//! brute forcing is prohibited; `replay` defaults to a dry run and refuses
//! write/unknown commands outside of it.
//!
//! Commands: artifact, cap, controller, decode, diff, infer, profile, recipe,
//! replay, trace.

use clap::{Parser, Subcommand};
use nclr::errors::{Error, Result};

#[derive(Parser)]
#[command(
    name = "nclr-lab",
    version,
    about = "research tooling for nclr profiles and vendor protocols"
)]
struct Cli {
    #[command(subcommand)]
    cmd: LabCmd,
}

#[derive(Subcommand)]
enum LabCmd {
    /// Acquire and verify pinned external controller artifacts
    Artifact(ArtifactArgs),
    /// Capture USB/MMC traces (Linux usbmon)
    Cap(CapArgs),
    /// Show the evidence-bounded controller-family support matrix
    Controller(ControllerArgs),
    /// Decode CDB / SCSI response / CMD56 byte sequences into a structure
    Decode(DecodeArgs),
    /// Compare two traces (success/failure/setting differences)
    Diff(DiffArgs),
    /// Infer length, endianness, checksum and sequence candidates
    Infer(InferArgs),
    /// Generate / validate controller profile templates
    Profile(ProfileArgs),
    /// Authenticate and validate a controller protocol recipe against a profile
    Recipe(RecipeArgs),
    /// Replay read-only commands from a trace (dry-run by default)
    Replay(ReplayArgs),
    /// Convert a pcapng USB BOT capture to normalized NDJSON
    Trace(TraceArgs),
}

#[derive(clap::Args)]
struct ArtifactArgs {
    #[command(subcommand)]
    cmd: ArtifactCmd,
}

#[derive(Subcommand)]
enum ArtifactCmd {
    /// Fetch the pinned HTTPS source into a content-addressed store
    Fetch {
        manifest: std::path::PathBuf,
        #[arg(long)]
        store: std::path::PathBuf,
        #[arg(long, default_value = "curl")]
        curl: std::path::PathBuf,
        #[arg(long)]
        accept_source_terms: bool,
    },
    /// Import already obtained bytes into a content-addressed store
    Import {
        manifest: std::path::PathBuf,
        source: std::path::PathBuf,
        #[arg(long)]
        store: std::path::PathBuf,
    },
    /// Verify bytes against a pinned manifest without executing them
    Verify {
        manifest: std::path::PathBuf,
        #[arg(long)]
        file: Option<std::path::PathBuf>,
        #[arg(long)]
        store: Option<std::path::PathBuf>,
    },
}

#[derive(clap::Args)]
struct ControllerArgs {
    /// Limit output to phison, alcor, smi or sandisk
    #[arg(long)]
    family: Option<String>,
}

#[derive(clap::Args)]
struct CapArgs {
    /// usbmon bus number (e.g. 1)
    #[arg(long)]
    bus: u32,
    /// Output file (default: stdout)
    #[arg(short, long)]
    output: Option<std::path::PathBuf>,
    /// Stop capture after this many seconds (default: until interrupted)
    #[arg(long)]
    duration: Option<u64>,
    /// tshark executable
    #[arg(long, default_value = "tshark")]
    tshark: std::path::PathBuf,
}

#[derive(clap::Args)]
struct DecodeArgs {
    /// Hex CDB, e.g. "12 00 00 00 60 00"
    cdb: String,
    /// Hex response bytes (optional)
    #[arg(long)]
    response: Option<String>,
    /// Opcode table lookup even when the CDB length is short
    #[arg(long)]
    lenient: bool,
}

#[derive(clap::Args)]
struct DiffArgs {
    /// First trace file (NDJSON)
    trace_a: std::path::PathBuf,
    /// Second trace file (NDJSON)
    trace_b: std::path::PathBuf,
    /// Only report sequence-level differences (not response bytes)
    #[arg(long)]
    summary: bool,
}

#[derive(clap::Args)]
struct InferArgs {
    /// Hex byte sequence
    bytes: String,
    /// Treat the sequence as a command (vs a response)
    #[arg(long)]
    command: bool,
}

#[derive(clap::Args)]
struct ProfileArgs {
    /// Generate a new profile template
    #[arg(long, conflicts_with = "check")]
    new: bool,
    /// Validate an existing profile file
    #[arg(long, conflicts_with = "new")]
    check: bool,
    /// Family name (for --new)
    #[arg(long)]
    family: Option<String>,
    /// Controller id (for --new)
    #[arg(long)]
    controller: Option<String>,
    /// Output file
    #[arg(short, long)]
    out: Option<std::path::PathBuf>,
    /// Profile file (for --check)
    file: Option<std::path::PathBuf>,
}

#[derive(clap::Args)]
struct ReplayArgs {
    /// Trace file (NDJSON)
    trace: std::path::PathBuf,
    /// Execute the read-only commands instead of printing them
    #[arg(long)]
    execute: bool,
    /// Confirm the device is a sacrificial test device
    #[arg(long)]
    confirm_sacrificial: bool,
    /// Device fd inherited from the shell (Linux SG_IO)
    #[arg(long, default_value = "3")]
    device_fd: i32,
}

#[derive(clap::Args)]
struct RecipeArgs {
    /// Exact production profile declaring the recipe artifact
    #[arg(long)]
    profile: std::path::PathBuf,
    /// Recipe bytes whose size and SHA-256 must match the profile
    #[arg(long)]
    file: std::path::PathBuf,
}

#[derive(clap::Args)]
struct TraceArgs {
    /// Input pcapng captured by USBPcap, usbmon or PacketLogger
    capture: std::path::PathBuf,
    /// Output NDJSON (default: stdout)
    #[arg(short, long)]
    output: Option<std::path::PathBuf>,
    /// tshark executable (auto-detected by default)
    #[arg(long)]
    tshark: Option<std::path::PathBuf>,
    /// Include raw IN/OUT payload bytes instead of only their digest
    #[arg(long, requires = "confirm_sensitive_payload")]
    include_payload: bool,
    /// Confirm that output may contain user data and credentials
    #[arg(long)]
    confirm_sensitive_payload: bool,
}

fn main() {
    // Die with SIGPIPE on a closed stdout pipe instead of panicking.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }
    let cli = Cli::parse();
    let code = match cli.cmd {
        LabCmd::Artifact(a) => cmd_artifact(&a),
        LabCmd::Cap(a) => cmd_cap(&a),
        LabCmd::Controller(a) => cmd_controller(&a),
        LabCmd::Decode(a) => cmd_decode(&a),
        LabCmd::Diff(a) => cmd_diff(&a),
        LabCmd::Infer(a) => cmd_infer(&a),
        LabCmd::Profile(a) => cmd_profile(&a),
        LabCmd::Recipe(a) => cmd_recipe(&a),
        LabCmd::Replay(a) => cmd_replay(&a),
        LabCmd::Trace(a) => cmd_trace(&a),
    };
    std::process::exit(code);
}

// ---------------------------------------------------------------------------
// artifact
// ---------------------------------------------------------------------------

fn cmd_artifact(args: &ArtifactArgs) -> i32 {
    use nclr::artifact;
    let result = (|| -> Result<artifact::VerifiedArtifact> {
        match &args.cmd {
            ArtifactCmd::Fetch {
                manifest,
                store,
                curl,
                accept_source_terms,
            } => {
                let manifest = artifact::load_manifest(manifest)?;
                artifact::fetch_with_curl(curl, store, &manifest.artifact, *accept_source_terms)
            }
            ArtifactCmd::Import {
                manifest,
                source,
                store,
            } => {
                let manifest = artifact::load_manifest(manifest)?;
                artifact::import_file(source, store, &manifest.artifact)
            }
            ArtifactCmd::Verify {
                manifest,
                file,
                store,
            } => {
                if file.is_some() == store.is_some() {
                    return Err(Error::Usage(
                        "artifact verify requires exactly one of --file or --store".into(),
                    ));
                }
                let manifest = artifact::load_manifest(manifest)?;
                if let Some(path) = file {
                    artifact::open_verified(path, &manifest.artifact).map(|(_, verified)| verified)
                } else {
                    artifact::find_verified(
                        &manifest.artifact,
                        std::slice::from_ref(store.as_ref().expect("checked store")),
                    )
                    .map(|(_, verified)| verified)
                }
            }
        }
    })();
    match result {
        Ok(verified) => match serde_json::to_string_pretty(&verified) {
            Ok(value) => {
                println!("{value}");
                0
            }
            Err(e) => {
                eprintln!("nclr-lab: artifact result serialization failed: {e}");
                70
            }
        },
        Err(e) => {
            eprintln!("nclr-lab: {e}");
            e.exit_code()
        }
    }
}

// ---------------------------------------------------------------------------
// controller
// ---------------------------------------------------------------------------

fn cmd_controller(args: &ControllerArgs) -> i32 {
    use nclr::controller_protocol::{support, Family};
    let families = match args.family.as_deref() {
        None => vec![
            Family::PhisonPs2251,
            Family::AlcorAu698x,
            Family::SiliconMotionUfd,
            Family::SandiskCruzer,
        ],
        Some("phison") | Some("phison-ps2251") => vec![Family::PhisonPs2251],
        Some("alcor") | Some("alcor-au698x") => vec![Family::AlcorAu698x],
        Some("smi") | Some("silicon-motion") | Some("silicon-motion-ufd") => {
            vec![Family::SiliconMotionUfd]
        }
        Some("sandisk") | Some("sandisk-cruzer") => vec![Family::SandiskCruzer],
        Some(other) => {
            eprintln!("nclr-lab: unknown controller family: {other}");
            return 64;
        }
    };
    let matrix: Vec<_> = families.into_iter().map(support).collect();
    match serde_json::to_string_pretty(&matrix) {
        Ok(value) => {
            println!("{value}");
            0
        }
        Err(e) => {
            eprintln!("nclr-lab: cannot serialize controller support: {e}");
            70
        }
    }
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let cleaned: String = s
        .chars()
        .filter(|c| !c.is_whitespace() && *c != ',' && *c != ':')
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(Error::Usage(
            "hex string must have an even number of digits".into(),
        ));
    }
    (0..cleaned.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&cleaned[i..i + 2], 16)
                .map_err(|_| Error::Usage(format!("invalid hex byte at {}", i / 2)))
        })
        .collect()
}

// ---------------------------------------------------------------------------
// cap
// ---------------------------------------------------------------------------

fn cmd_cap(args: &CapArgs) -> i32 {
    #[cfg(target_os = "linux")]
    {
        if args.output.as_ref().is_some_and(|path| path.exists()) {
            eprintln!("nclr-lab: refusing to overwrite an existing capture output");
            return 74;
        }
        let mut command = std::process::Command::new(&args.tshark);
        command
            .arg("-i")
            .arg(format!("usbmon{}", args.bus))
            .arg("-F")
            .arg("pcapng")
            .arg("-w")
            .arg(args.output.as_deref().unwrap_or(std::path::Path::new("-")))
            .stdin(std::process::Stdio::null())
            .stderr(std::process::Stdio::inherit());
        if args.output.is_some() {
            command.stdout(std::process::Stdio::null());
        } else {
            command.stdout(std::process::Stdio::inherit());
        }
        if let Some(duration) = args.duration {
            if duration == 0 || duration > 86_400 {
                eprintln!("nclr-lab: --duration must be in 1..=86400 seconds");
                return 64;
            }
            command.arg("-a").arg(format!("duration:{duration}"));
        }
        match command.status() {
            Ok(status) if status.success() => 0,
            Ok(status) => {
                eprintln!("nclr-lab: tshark capture failed with {status}");
                74
            }
            Err(e) => {
                eprintln!("nclr-lab: cannot execute {}: {e}", args.tshark.display());
                69
            }
        }
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = args;
        eprintln!("nclr-lab: trace capture requires Linux usbmon; this platform is not supported");
        69
    }
}

// ---------------------------------------------------------------------------
// trace
// ---------------------------------------------------------------------------

fn tshark_path(explicit: Option<&std::path::Path>) -> std::path::PathBuf {
    if let Some(path) = explicit {
        return path.to_path_buf();
    }
    if let Ok(path) = std::env::var("NCLR_TSHARK") {
        return path.into();
    }
    let mac = std::path::PathBuf::from("/Applications/Wireshark.app/Contents/MacOS/tshark");
    if mac.is_file() {
        mac
    } else {
        "tshark".into()
    }
}

fn parse_decimal(value: &str, field: &str, line: u64) -> Result<u64> {
    value.parse::<u64>().map_err(|_| {
        Error::Invalid(format!(
            "tshark line {line}: {field} is not an unsigned integer: {value:?}"
        ))
    })
}

fn parse_endpoint(value: &str, line: u64) -> Result<u8> {
    let parsed = if let Some(hex) = value.strip_prefix("0x") {
        u16::from_str_radix(hex, 16)
    } else {
        value.parse::<u16>()
    }
    .map_err(|_| Error::Invalid(format!("tshark line {line}: invalid endpoint {value:?}")))?;
    u8::try_from(parsed)
        .map_err(|_| Error::Invalid(format!("tshark line {line}: endpoint exceeds one byte")))
}

fn decode_tshark_rows<R: std::io::BufRead, W: std::io::Write>(
    reader: R,
    writer: &mut W,
    include_payload: bool,
) -> Result<(u64, u64)> {
    let mut decoder = nclr::usb_bot::BotDecoder::new();
    let mut records = 0u64;
    let mut last_frame = None;
    for (index, row) in reader.lines().enumerate() {
        let line_number = index as u64 + 1;
        let row = row.map_err(|e| Error::io("read tshark output", Some(e)))?;
        let fields = row.split('\t').collect::<Vec<_>>();
        if fields.len() != 8 {
            return Err(Error::Invalid(format!(
                "tshark line {line_number}: expected 8 tab-separated fields, got {}",
                fields.len()
            )));
        }
        let frame_number = parse_decimal(fields[0], "frame.number", line_number)?;
        if last_frame.is_some_and(|previous| frame_number <= previous) {
            return Err(Error::Invalid(format!(
                "tshark line {line_number}: frame numbers are not strictly increasing"
            )));
        }
        last_frame = Some(frame_number);
        if fields[1].is_empty() {
            return Err(Error::Invalid(format!(
                "tshark line {line_number}: frame.time_epoch is empty"
            )));
        }
        let bus = if fields[2].is_empty() {
            "darwin".to_string()
        } else {
            fields[2].to_string()
        };
        let device = match (fields[3], fields[4]) {
            ("", "") => {
                return Err(Error::Invalid(format!(
                    "tshark line {line_number}: both USB device address fields are empty"
                )));
            }
            (linux, "") => linux.to_string(),
            ("", darwin) => darwin.to_string(),
            (linux, darwin) if linux == darwin => linux.to_string(),
            (linux, darwin) => {
                return Err(Error::Invalid(format!(
                    "tshark line {line_number}: USB device addresses disagree ({linux} vs {darwin})"
                )));
            }
        };
        let endpoint_text = match (fields[5], fields[6]) {
            ("", "") => {
                return Err(Error::Invalid(format!(
                    "tshark line {line_number}: both USB endpoint fields are empty"
                )));
            }
            (linux, "") => linux,
            ("", darwin) => darwin,
            (linux, darwin) if linux == darwin => linux,
            (linux, darwin) => {
                return Err(Error::Invalid(format!(
                    "tshark line {line_number}: USB endpoints disagree ({linux} vs {darwin})"
                )));
            }
        };
        let data = parse_hex(fields[7]).map_err(|e| {
            Error::Invalid(format!(
                "tshark line {line_number}: invalid usb.frame.data: {e}"
            ))
        })?;
        if data.is_empty() {
            return Err(Error::Invalid(format!(
                "tshark line {line_number}: usb.frame.data is empty"
            )));
        }
        let frame = nclr::usb_bot::UsbPayloadFrame {
            frame: frame_number,
            time_epoch: fields[1].to_string(),
            bus,
            device,
            endpoint: parse_endpoint(endpoint_text, line_number)?,
            data,
        };
        if let Some(record) = decoder.feed(frame, include_payload)? {
            serde_json::to_writer(&mut *writer, &record)
                .map_err(|e| Error::Invalid(format!("serialize trace record: {e}")))?;
            writer
                .write_all(b"\n")
                .map_err(|e| Error::io("write normalized trace", Some(e)))?;
            records += 1;
        }
    }
    let ignored = decoder.ignored_payloads();
    decoder.finish()?;
    writer
        .flush()
        .map_err(|e| Error::io("flush normalized trace", Some(e)))?;
    Ok((records, ignored))
}

fn trace_to_temp(args: &TraceArgs) -> Result<(tempfile::NamedTempFile, u64, u64)> {
    use std::process::{Command, Stdio};
    let tshark = tshark_path(args.tshark.as_deref());
    let mut child = Command::new(&tshark)
        .arg("-r")
        .arg(&args.capture)
        .args([
            "-Y",
            "usb.transfer_type == 3 && usb.frame.data",
            "-T",
            "fields",
            "-E",
            "separator=/t",
            "-E",
            "occurrence=f",
            "-e",
            "frame.number",
            "-e",
            "frame.time_epoch",
            "-e",
            "usb.bus_id",
            "-e",
            "usb.device_address",
            "-e",
            "usb.darwin.device_address",
            "-e",
            "usb.endpoint_address",
            "-e",
            "usb.darwin.endpoint_address",
            "-e",
            "usb.frame.data",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| Error::io(format!("execute {}", tshark.display()), Some(e)))?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| Error::Io("cannot read tshark stdout".into(), None))?;
    let mut temp = tempfile::NamedTempFile::new()
        .map_err(|e| Error::io("create normalized trace temp file", Some(e)))?;
    let decoded = decode_tshark_rows(
        std::io::BufReader::new(stdout),
        temp.as_file_mut(),
        args.include_payload,
    );
    if let Err(e) = decoded {
        let _ = child.kill();
        let _ = child.wait();
        return Err(e);
    }
    let (records, ignored) = decoded.expect("checked decode result");
    let status = child
        .wait()
        .map_err(|e| Error::io("wait for tshark", Some(e)))?;
    if !status.success() {
        return Err(Error::Io(format!("tshark failed with {status}"), None));
    }
    if records == 0 {
        return Err(Error::Invalid(
            "capture contains no complete USB BOT commands".into(),
        ));
    }
    temp.as_file_mut()
        .sync_all()
        .map_err(|e| Error::io("sync normalized trace temp file", Some(e)))?;
    Ok((temp, records, ignored))
}

fn write_trace_output(
    mut temp: tempfile::NamedTempFile,
    output: Option<&std::path::Path>,
) -> Result<()> {
    use std::io::{Read, Seek, Write};
    temp.as_file_mut()
        .rewind()
        .map_err(|e| Error::io("rewind normalized trace", Some(e)))?;
    if let Some(path) = output {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new("."));
        let mut staged = tempfile::NamedTempFile::new_in(parent).map_err(|e| {
            Error::io(
                format!("create staged trace output in {}", parent.display()),
                Some(e),
            )
        })?;
        std::io::copy(temp.as_file_mut(), staged.as_file_mut())
            .map_err(|e| Error::io(format!("write trace output {}", path.display()), Some(e)))?;
        staged
            .as_file_mut()
            .flush()
            .map_err(|e| Error::io(format!("flush trace output {}", path.display()), Some(e)))?;
        staged
            .as_file_mut()
            .sync_all()
            .map_err(|e| Error::io(format!("sync trace output {}", path.display()), Some(e)))?;
        staged.persist_noclobber(path).map_err(|e| {
            Error::io(
                format!("persist trace output {}", path.display()),
                Some(e.error),
            )
        })?;
        std::fs::File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|e| {
                Error::io(
                    format!("sync trace output directory {}", parent.display()),
                    Some(e),
                )
            })?;
    } else {
        let mut stdout = std::io::stdout().lock();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let n = temp
                .as_file_mut()
                .read(&mut buffer)
                .map_err(|e| Error::io("read normalized trace", Some(e)))?;
            if n == 0 {
                break;
            }
            stdout
                .write_all(&buffer[..n])
                .map_err(|e| Error::io("write normalized trace to stdout", Some(e)))?;
        }
    }
    Ok(())
}

fn cmd_trace(args: &TraceArgs) -> i32 {
    if args.confirm_sensitive_payload && !args.include_payload {
        eprintln!(
            "nclr-lab: --confirm-sensitive-payload is meaningful only with --include-payload"
        );
        return 64;
    }
    let result = (|| -> Result<(u64, u64)> {
        let (temp, records, ignored) = trace_to_temp(args)?;
        write_trace_output(temp, args.output.as_deref())?;
        Ok((records, ignored))
    })();
    match result {
        Ok((records, ignored)) => {
            eprintln!(
                "nclr-lab: normalized {records} USB BOT commands; ignored {ignored} unrelated bulk payloads"
            );
            0
        }
        Err(e) => {
            eprintln!("nclr-lab: {e}");
            e.exit_code()
        }
    }
}

// ---------------------------------------------------------------------------
// decode
// ---------------------------------------------------------------------------

/// Decode a CDB into a structured description using the shared SCSI layer.
fn decode_cdb(cdb: &[u8], lenient: bool) -> String {
    let Some(op) = cdb.first().copied() else {
        return "empty CDB".to_string();
    };
    let name = opcode_name(op);
    let len = cdb.len();
    if !lenient && len < 6 {
        return format!("opcode 0x{op:02x} ({name}): CDB too short to decode ({len} bytes)");
    }
    if let Some(decoded) = decode_vendor_cdb(cdb) {
        return decoded;
    }
    match op {
        nclr::scsi::OP_INQUIRY => {
            let evpd = cdb.get(1).copied().unwrap_or(0) & 0x01 != 0;
            let page = cdb.get(2).copied().unwrap_or(0);
            let alloc = u16::from_be_bytes([
                cdb.get(3).copied().unwrap_or(0),
                cdb.get(4).copied().unwrap_or(0),
            ]);
            format!("INQUIRY evpd={evpd} page=0x{page:02x} alloc_len={alloc}")
        }
        nclr::scsi::OP_SANITIZE => {
            // SBC-4: service action in byte 1 bits 4-0, IMMED in bit 7.
            let b1 = cdb.get(1).copied().unwrap_or(0);
            let sa = b1 & 0x1F;
            let immed = b1 & 0x80 != 0;
            let sa_name = match sa {
                nclr::scsi::SA_SANITIZE_OVERWRITE => "OVERWRITE",
                nclr::scsi::SA_SANITIZE_BLOCK_ERASE => "BLOCK ERASE",
                nclr::scsi::SA_SANITIZE_CRYPTO_ERASE => "CRYPTOGRAPHIC ERASE",
                _ => "?",
            };
            format!("SANITIZE service_action={sa_name} immed={immed}")
        }
        nclr::scsi::OP_READ_CAPACITY_10 => "READ CAPACITY(10)".to_string(),
        nclr::scsi::OP_READ_CAPACITY_16 => "READ CAPACITY(16)".to_string(),
        nclr::scsi::OP_FORMAT_UNIT => "FORMAT UNIT".to_string(),
        nclr::scsi::OP_UNMAP => "UNMAP".to_string(),
        nclr::scsi::OP_RECEIVE_DIAGNOSTIC => {
            // SPC-4: byte 1 bit 0 is PCV; byte 2 is the page code.
            let pcv = cdb.get(1).copied().unwrap_or(0) & 0x01 != 0;
            let page = cdb.get(2).copied().unwrap_or(0);
            format!("RECEIVE DIAGNOSTIC RESULTS pcv={pcv} page=0x{page:02x}")
        }
        nclr::scsi::OP_REPORT_SUPPORTED_OPCODES => {
            let sa = cdb.get(1).copied().unwrap_or(0);
            format!("REPORT SUPPORTED OPERATION CODES sa=0x{sa:02x}")
        }
        _ => format!(
            "opcode 0x{op:02x} ({name}) len={len} arg=0x{:08x}",
            cdb.iter()
                .skip(1)
                .fold(0u32, |acc, b| (acc << 8) | *b as u32)
        ),
    }
}

fn decode_vendor_cdb(cdb: &[u8]) -> Option<String> {
    if let [0xff, command, subcommand, rest @ ..] = cdb {
        if cdb.len() == 12 {
            let description = match (*command, *subcommand) {
                (0x00, 0x00) => {
                    let property = u16::from_le_bytes([rest[0], rest[1]]);
                    let length = u16::from_le_bytes([rest[2], rest[3]]);
                    format!(
                        "SANDISK U3 READ PROPERTY id=0x{property:04x} length={length} (read-only logical U3 metadata)"
                    )
                }
                (0x01, 0x01) => {
                    "SANDISK U3 RESET/RECONNECT (state-changing logical U3 command)".into()
                }
                (0x03, 0x01) => {
                    "SANDISK U3 USB CHIP INFO (read-only controller identity; not NAND ID)".into()
                }
                (0x20, 0x00) => {
                    let sectors = u32::from_le_bytes(rest[1..5].try_into().ok()?);
                    let direction = match rest[5] {
                        0 => "down",
                        1 => "up",
                        _ => "invalid",
                    };
                    format!(
                        "SANDISK U3 ROUND DOMAIN SIZE sectors={sectors} direction={direction} (logical U3 configuration)"
                    )
                }
                (0x21, 0x00) => {
                    "SANDISK U3 GET DOMAINS (read-only logical partition metadata)".into()
                }
                (0x22, 0x00) => {
                    "SANDISK U3 SET DOMAINS (state-changing logical partition reconfiguration; not physical NAND erase)".into()
                }
                (0x23..=0x25, 0x00) => format!(
                    "SANDISK U3 CONFIG PRIVATE COMMAND 0x{command:02x} (logical configuration; raw NAND semantics prohibited)"
                ),
                (0x40..=0x41, 0x00) => format!(
                    "SANDISK U3 CD PRIVATE COMMAND 0x{command:02x} (logical CD domain; raw NAND semantics prohibited)"
                ),
                (0x42, 0x00) => {
                    let domain = rest[0];
                    let block = u32::from_be_bytes(rest[1..5].try_into().ok()?);
                    let count = u32::from_be_bytes(rest[5..9].try_into().ok()?);
                    format!(
                        "SANDISK U3 WRITE CD domain={domain} block={block} count={count} transfer_bytes={} (logical CD image; not raw NAND page program)",
                        u64::from(count) * 2048
                    )
                }
                (0xa0, 0x00) => {
                    "SANDISK U3 DATA PARTITION INFO (read-only logical/security metadata)".into()
                }
                (0xa2, 0x00) => "SANDISK U3 ENABLE SECURITY (state-changing)".into(),
                (0xa3, 0x00) => "SANDISK U3 ROUND SECURITY ZONE SIZE".into(),
                (0xa4, 0x00) => "SANDISK U3 UNLOCK DATA PARTITION (state-changing)".into(),
                (0xa6, 0x00) => "SANDISK U3 CHANGE PASSWORD (state-changing)".into(),
                (0xa7, 0x00) => "SANDISK U3 DISABLE SECURITY (state-changing)".into(),
                _ => return None,
            };
            return Some(description);
        }
    }
    match cdb {
        [0x06, 0x05, ..] => Some("PHISON VERSION PAGE (read-only identification)".into()),
        [0x06, 0x56, ..] => Some("PHISON NAND ID (read-only identification)".into()),
        [0x06, 0xBF, ..] => Some("PHISON ENTER BOOTROM (state-changing)".into()),
        [0x06, 0xB1, 0x03, ..] => {
            Some("PHISON PRAM HEADER TRANSFER bytes=512 (state-changing)".into())
        }
        [0x06, 0xB1, 0x02, ..] if cdb.len() >= 9 => {
            let address_units = u16::from_be_bytes([cdb[3], cdb[4]]);
            let length_units = u16::from_be_bytes([cdb[7], cdb[8]]);
            Some(format!(
                "PHISON PRAM BODY TRANSFER address_bytes={} transfer_bytes={} (state-changing)",
                u32::from(address_units) * 512,
                u32::from(length_units) * 512
            ))
        }
        [0x06, 0xB0, ..] if cdb.len() >= 5 => Some(format!(
            "PHISON PRAM TRANSFER STATUS response_bytes={} (read-only acknowledgement)",
            cdb[4]
        )),
        [0x06, 0xB3, ..] => Some("PHISON RUN PRAM (state-changing)".into()),
        [0x82, 0x51, 0x01, ..] => Some("ALCOR CONFIG READ (read-only identification)".into()),
        [0xFA, 0x00, ..] => Some("ALCOR FLASH ID (read-only identification)".into()),
        [0x81, 0x00, 0xFF, ..] => {
            Some("ALCOR CONFIG WRITE/REBUILD (state-changing, prohibited)".into())
        }
        [0xF0, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2] => {
            Some("SMI SM32X IDENTITY PAGE (read-only identification; not NAND ID)".into())
        }
        _ => None,
    }
}

fn opcode_name(op: u8) -> &'static str {
    match op {
        0x00 => "TEST UNIT READY",
        0x04 => "FORMAT UNIT",
        0x08 => "READ(6)",
        0x0A => "WRITE(6)",
        0x12 => "INQUIRY",
        0x1A => "MODE SENSE(6)",
        0x1C => "RECEIVE DIAGNOSTIC RESULTS",
        0x25 => "READ CAPACITY(10)",
        0x28 => "READ(10)",
        0x2A => "WRITE(10)",
        0x42 => "UNMAP",
        0x48 => "SANITIZE",
        0x9E => "READ CAPACITY(16)",
        0xA3 => "REPORT SUPPORTED OPERATION CODES",
        0xA6 => "MAINTENANCE(12)",
        _ => "UNKNOWN",
    }
}

fn cmd_decode(args: &DecodeArgs) -> i32 {
    match parse_hex(&args.cdb) {
        Err(e) => {
            eprintln!("nclr-lab: {e}");
            return 64;
        }
        Ok(cdb) => {
            println!("{}", decode_cdb(&cdb, args.lenient));
            if let Some(r) = &args.response {
                match parse_hex(r) {
                    Ok(resp) => println!("response: {} bytes", resp.len()),
                    Err(e) => {
                        eprintln!("nclr-lab: {e}");
                        return 64;
                    }
                }
            }
        }
    }
    0
}

// ---------------------------------------------------------------------------
// diff
// ---------------------------------------------------------------------------

/// A single trace record (NDJSON).
#[derive(serde::Deserialize)]
struct TraceRecord {
    seq: u64,
    #[serde(default)]
    opcode: Option<u64>,
    #[serde(default)]
    dir: Option<String>,
    #[serde(default)]
    cdb_hex: Option<String>,
    #[serde(default)]
    response_hex: Option<String>,
    #[serde(default)]
    status: Option<String>,
}

fn load_trace(path: &std::path::Path) -> Result<Vec<TraceRecord>> {
    let content = std::fs::read_to_string(path)
        .map_err(|e| Error::io(format!("trace read {}", path.display()), Some(e)))?;
    content
        .lines()
        .enumerate()
        .map(|(i, line)| {
            serde_json::from_str::<TraceRecord>(line).map_err(|e| {
                Error::Invalid(format!("trace {} line {}: {e}", path.display(), i + 1))
            })
        })
        .collect()
}

fn cmd_diff(args: &DiffArgs) -> i32 {
    let (a, b) = match (load_trace(&args.trace_a), load_trace(&args.trace_b)) {
        (Ok(a), Ok(b)) => (a, b),
        (Err(e), _) | (_, Err(e)) => {
            eprintln!("nclr-lab: {e}");
            return e.exit_code();
        }
    };
    let mut diffs = 0usize;
    let n = a.len().max(b.len());
    for i in 0..n {
        let ra = a.get(i);
        let rb = b.get(i);
        match (ra, rb) {
            (None, None) => {}
            (None, Some(rb)) => {
                println!("+ seq {} opcode {:?} (only in B)", rb.seq, rb.opcode);
                diffs += 1;
            }
            (Some(ra), None) => {
                println!("- seq {} opcode {:?} (only in A)", ra.seq, ra.opcode);
                diffs += 1;
            }
            (Some(ra), Some(rb)) => {
                let op_a = ra.opcode.or(parse_opcode(&ra.cdb_hex));
                let op_b = rb.opcode.or(parse_opcode(&rb.cdb_hex));
                if op_a != op_b {
                    println!("~ seq {}: opcode {:?} -> {:?}", ra.seq, op_a, op_b);
                    diffs += 1;
                } else if !args.summary && ra.response_hex != rb.response_hex {
                    let len_a = ra.response_hex.as_ref().map(|h| h.len()).unwrap_or(0);
                    let len_b = rb.response_hex.as_ref().map(|h| h.len()).unwrap_or(0);
                    println!(
                        "~ seq {}: response {} bytes -> {} bytes",
                        ra.seq, len_a, len_b
                    );
                    diffs += 1;
                } else if ra.status != rb.status {
                    println!(
                        "~ seq {}: status {:?} -> {:?}",
                        ra.seq, ra.status, rb.status
                    );
                    diffs += 1;
                }
            }
        }
    }
    println!(
        "diff: {diffs} differences ({} vs {} records)",
        a.len(),
        b.len()
    );
    0
}

fn parse_opcode(cdb_hex: &Option<String>) -> Option<u64> {
    let hex = cdb_hex.as_ref()?;
    parse_hex(hex)
        .ok()
        .and_then(|b| b.first().copied().map(u64::from))
}

// ---------------------------------------------------------------------------
// infer
// ---------------------------------------------------------------------------

fn cmd_infer(args: &InferArgs) -> i32 {
    let bytes = match parse_hex(&args.bytes) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("nclr-lab: {e}");
            return 64;
        }
    };
    if bytes.is_empty() {
        eprintln!("nclr-lab: infer requires a non-empty byte sequence");
        return 64;
    }
    println!("bytes: {} ({} bytes)", args.bytes, bytes.len());
    println!(
        "first byte (opcode/status): 0x{:02x} ({})",
        bytes[0], bytes[0] as char
    );
    if args.command {
        println!("command role: {}", decode_cdb(&bytes, true));
    }
    // Endianness candidates for a length field in the first 4 bytes.
    let head = &bytes[..bytes.len().min(8)];
    if head.len() >= 4 {
        let be = u32::from_be_bytes([head[0], head[1], head[2], head[3]]);
        let le = u32::from_le_bytes([head[0], head[1], head[2], head[3]]);
        println!("head u32 big-endian: {be} (0x{be:08x})");
        println!("head u32 little-endian: {le} (0x{le:08x})");
    }
    // Checksum candidates.
    let sum = bytes.iter().fold(0u64, |a, b| a + *b as u64);
    let xor = bytes.iter().fold(0u8, |a, b| a ^ b);
    println!("sum8: 0x{:02x}", (sum & 0xFF) as u8);
    println!("sum16: 0x{:04x}", (sum & 0xFFFF) as u16);
    println!("xor8: 0x{xor:02x}");
    if bytes.len() >= 2 {
        let crc = crc16(&bytes);
        println!("crc16/ccitt: 0x{crc:04x}");
    }
    // Sequence candidates: runs of equal length with a monotonic tail byte.
    if bytes.len() >= 4 {
        let last = bytes[bytes.len() - 1];
        let prev = bytes[bytes.len() - 2];
        println!(
            "tail: 0x{prev:02x} -> 0x{last:02x} ({} / monotonic if last == prev+1)",
            if last.wrapping_sub(prev) == 1 {
                "monotonic +1"
            } else {
                "not +1"
            }
        );
    }
    0
}

fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0xFFFF;
    for &b in data {
        crc ^= (b as u16) << 8;
        for _ in 0..8 {
            if crc & 0x8000 != 0 {
                crc = (crc << 1) ^ 0x1021;
            } else {
                crc <<= 1;
            }
        }
    }
    crc
}

// ---------------------------------------------------------------------------
// profile
// ---------------------------------------------------------------------------

const TEMPLATE: &str = r#"# nclr controller profile template.
# Fill in the identification ranges and trust state. Never add D1-D4 from a
# vendor data sheet or successful command alone: destructive execution needs
# exact hardware identity, compiled driver support and independent HIL evidence.
schema = 2
id = "{family}-{controller}"
controller_id = "{controller}"
firmware = { min = "1.0", max = "9.9" }
nand_id = { min = "", max = "" }
trust = "research"
simulated = false
operations = ["probe", "plan", "run", "status", "recover"]
coverage = ["D0"]
rebuilds = []
preserves = ["FBB-marker"]
capacity = { bin_bytes = 0, minimum_spare_blocks = 4, spare_ratio = 0.05 }
ecc = { strength = 40, min_margin = 8, max_read_retry = 4, max_read_latency_ms = 200 }
recovery = { method = "service-mode-exit+reset", timeout_ms = 30000 }
sd_vendor = { read_only_health = false, cmd56_arg = 0, block_len = 0 }
# Real trust = "production" profiles also require exact min=max identity,
# pinned protocol-trace and qualification-report artifacts, and all fields:
# implementation = { strategy = "clean-room", protocol_evidence_sha256 = "...", source_reference = "https://...", artifact_ids = ["protocol-recipe"] }
# geometry = { channels = 1, chips_per_channel = 1, luns_per_chip = 1, planes_per_lun = 2, blocks_per_lun = 1024, pages_per_block = 256, page_bytes = 8192, oob_bytes = 640, address_cycles = 5, bits_per_cell = 2, bad_block_marker_pages = [0, 1], bad_block_marker_offsets = [0], randomizer = "...", read_retry = "...", ecc_layout = "..." }
# metadata_layout = { bbt_format = "...", ftl_format = "...", spare_format = "...", commit_protocol = "...", system_block_ranges = [{ start = 0, end = 15, purpose = "controller-metadata", policy = "rebuild-controller-metadata" }] }
# qualification = { report_sha256 = "...", report_artifact_id = "qualification-report", independent_reader = "...", samples = 1, power_cut_cases = 1 }
# A production profile declares exactly one kind = "protocol-recipe",
# role = "runtime" JSON/TOML artifact. [[artifacts]] entries use the schema in
# docs/controller-artifact-workflow.md.
"#;

fn cmd_profile(args: &ProfileArgs) -> i32 {
    if args.check {
        let Some(file) = &args.file else {
            eprintln!("nclr-lab: --check requires a profile file argument");
            return 64;
        };
        return match nclr::profile::load(file) {
            Ok(p) => {
                println!(
                    "ok: {} (controller {}, trust {}, destructive_allowed={})",
                    p.id,
                    p.controller_id,
                    p.trust,
                    p.destructive_allowed()
                );
                0
            }
            Err(e) => {
                eprintln!("nclr-lab: {e}");
                e.exit_code()
            }
        };
    }
    if args.new {
        let family = args.family.clone().unwrap_or_else(|| "family".into());
        let controller = args
            .controller
            .clone()
            .unwrap_or_else(|| "controller".into());
        let rendered = TEMPLATE
            .replace("{family}", &family)
            .replace("{controller}", &controller);
        match &args.out {
            Some(path) => {
                if let Err(e) = std::fs::write(path, &rendered) {
                    eprintln!("nclr-lab: write {}: {e}", path.display());
                    return 74;
                }
                println!("wrote {}", path.display());
            }
            None => print!("{rendered}"),
        }
        return 0;
    }
    eprintln!("nclr-lab: profile requires --new or --check");
    64
}

// ---------------------------------------------------------------------------
// recipe
// ---------------------------------------------------------------------------

fn cmd_recipe(args: &RecipeArgs) -> i32 {
    let result = (|| -> Result<serde_json::Value> {
        let profile = nclr::profile::load(&args.profile)?;
        let recipes = profile
            .artifacts
            .iter()
            .filter(|artifact| {
                artifact.kind == nclr::artifact::ArtifactKind::ProtocolRecipe
                    && artifact.role == "runtime"
            })
            .collect::<Vec<_>>();
        let spec = match recipes.as_slice() {
            [recipe] => *recipe,
            _ => {
                return Err(Error::Invalid(format!(
                    "profile {} must declare exactly one runtime protocol recipe",
                    profile.id
                )))
            }
        };
        let (mut file, verified) = nclr::artifact::open_verified(&args.file, spec)?;
        let recipe = nclr::controller_recipe::load_reader(&mut file, spec.format.clone())?;
        nclr::controller_recipe::validate(&recipe, &profile)?;
        Ok(serde_json::json!({
            "ok": true,
            "profile": profile.id,
            "recipe": verified.id,
            "sha256": verified.sha256,
            "size_bytes": verified.size_bytes,
            "family": recipe.family,
            "controller_id": recipe.controller_id,
            "firmware": recipe.firmware,
            "nand_id": recipe.nand_id,
            "commands": recipe.commands.keys().collect::<Vec<_>>(),
            "enter_reenumerates": recipe.policy.enter_reenumerates,
            "loader_reenumerates": recipe.policy.loader_reenumerates,
            "exit_reenumerates": recipe.policy.exit_reenumerates,
        }))
    })();
    match result {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(rendered) => {
                println!("{rendered}");
                0
            }
            Err(error) => {
                eprintln!("nclr-lab: recipe result serialization failed: {error}");
                70
            }
        },
        Err(error) => {
            eprintln!("nclr-lab: {error}");
            error.exit_code()
        }
    }
}

// ---------------------------------------------------------------------------
// replay
// ---------------------------------------------------------------------------

/// Destructive or state-changing opcodes that are never replayed: FORMAT
/// UNIT, WRITE(6/10/12/16), WRITE AND VERIFY(10/12/16), WRITE SAME(10/16),
/// UNMAP and SANITIZE.
const REPLAY_WRITES: &[u64] = &[
    0x04, 0x0A, 0x2A, 0xAA, 0x8A, 0x2E, 0x8E, 0xAE, 0x41, 0x93, 0x42, 0x48,
];

/// Known read-only opcodes. Any opcode outside this set is unclassified and
/// must never be sent: an unclassified command is not proven read-only.
fn is_read_only_op(op: u64) -> bool {
    matches!(
        op,
        0x00 // TEST UNIT READY
            | 0x08 | 0x28 | 0x88 // READ(6/10/16)
            | 0x12 // INQUIRY
            | 0x1A // MODE SENSE(6)
            | 0x1C // RECEIVE DIAGNOSTIC RESULTS
            | 0x25 | 0x9E // READ CAPACITY(10/16)
            | 0x4D // LOG SENSE
            | 0xA3 // REPORT SUPPORTED OPERATION CODES
    )
}

/// Replay classification shared by the dry-run output and the execute path:
/// writes and unclassified opcodes are always skipped; a record with
/// neither an opcode nor a CDB is unclassified, never assumed to be a read.
enum ReplayClass {
    Skip(String),
    ReadOnly,
}

fn classify_replay(rec: &TraceRecord) -> ReplayClass {
    let op = match rec.opcode.or_else(|| parse_opcode(&rec.cdb_hex)) {
        Some(op) => op,
        None => {
            return ReplayClass::Skip("no opcode recorded (unclassified, never replayed)".into());
        }
    };
    if is_read_only_op(op) && !REPLAY_WRITES.contains(&op) {
        // Every whitelisted read-only command transfers data device->host
        // (or carries none); a record claiming the "out" direction is a
        // trace mis-recording and must never turn into a host->device
        // transfer.
        if rec.dir.as_deref() == Some("out") {
            return ReplayClass::Skip(format!(
                "opcode 0x{op:02x} is read-only but records an out direction (trace mis-recording, never replayed)"
            ));
        }
        ReplayClass::ReadOnly
    } else {
        ReplayClass::Skip(format!(
            "opcode 0x{op:02x} is a write or unclassified command (never replayed)"
        ))
    }
}

/// One trace record as a dry-run line.
fn replay_line(rec: &TraceRecord) -> String {
    let op = rec.opcode.or_else(|| parse_opcode(&rec.cdb_hex));
    match classify_replay(rec) {
        ReplayClass::Skip(reason) => format!("skip seq {}: {reason}", rec.seq),
        ReplayClass::ReadOnly => {
            let dir = rec.dir.as_deref().unwrap_or("?");
            format!(
                "seq {}: [{}] opcode 0x{:02x} (read-only, dry-run)",
                rec.seq,
                dir,
                op.unwrap_or(0)
            )
        }
    }
}

fn cmd_replay(args: &ReplayArgs) -> i32 {
    let trace = match load_trace(&args.trace) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("nclr-lab: {e}");
            return e.exit_code();
        }
    };
    // Safety boundaries: write/unknown commands are never replayed outside
    // a dry run, and a sacrificial-device confirmation is required to
    // execute at all.
    if !args.execute {
        println!("dry-run: {} records; use --execute with --confirm-sacrificial to send read-only commands", trace.len());
    } else if !args.confirm_sacrificial {
        eprintln!("nclr-lab: refusing to execute: this is a sacrificial test device? pass --confirm-sacrificial");
        return 77;
    }
    for rec in &trace {
        let op = rec.opcode.or_else(|| parse_opcode(&rec.cdb_hex));
        match classify_replay(rec) {
            ReplayClass::Skip(_) => {
                // Output formatting is owned by replay_line so dry-run and
                // execute produce identical lines for skipped records.
                println!("{}", replay_line(rec));
            }
            ReplayClass::ReadOnly => {
                if args.execute {
                    // Actual sending requires Linux SG_IO; read-only
                    // commands only (classified above).
                    let status = send_read_only(args.device_fd, rec);
                    println!(
                        "seq {}: sent opcode 0x{:02x}: {status}",
                        rec.seq,
                        op.unwrap_or(0)
                    );
                } else {
                    println!("{}", replay_line(rec));
                }
            }
        }
    }
    0
}

#[cfg(target_os = "linux")]
fn send_read_only(fd: i32, rec: &TraceRecord) -> String {
    let Some(cdb_hex) = &rec.cdb_hex else {
        return "no cdb recorded".to_string();
    };
    let cdb = match parse_hex(cdb_hex) {
        Ok(c) => c,
        Err(e) => return format!("bad cdb: {e}"),
    };
    // The inherited fd is shared across records: dup it so each send owns
    // its own descriptor instead of closing the original on the first call.
    let dup_fd = unsafe { libc::dup(fd) };
    if dup_fd < 0 {
        return format!("dup failed: {}", std::io::Error::last_os_error());
    }
    let file = unsafe { std::fs::File::from_raw_fd(dup_fd) };
    let mut buf = vec![0u8; 4096];
    // Every whitelisted read-only command transfers data device->host (or
    // carries none), and classify_replay refuses any record that claims an
    // "out" direction, so the transfer direction is always from the device.
    let direction = nclr::scsi::SG_DXFER_FROM_DEV;
    match nclr::scsi::sg::exec(&file, &cdb, direction, &mut buf, 60_000) {
        Ok(()) => "ok".to_string(),
        Err(e) => e.to_string(),
    }
}

#[cfg(not(target_os = "linux"))]
fn send_read_only(_fd: i32, _rec: &TraceRecord) -> String {
    "execution requires Linux SG_IO".to_string()
}

#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_parsing() {
        assert_eq!(
            parse_hex("12 00 00 00 60 00").unwrap(),
            vec![0x12, 0x00, 0x00, 0x00, 0x60, 0x00]
        );
        assert_eq!(
            parse_hex("48,03,00,00,00,02").unwrap(),
            vec![0x48, 0x03, 0x00, 0x00, 0x00, 0x02]
        );
        assert!(parse_hex("12 0").is_err());
    }

    #[test]
    fn cdb_decode() {
        assert!(decode_cdb(&[0x12, 0x01, 0x80, 0x00, 0xfc, 0x00], false)
            .contains("INQUIRY evpd=true page=0x80"));
        assert!(decode_cdb(&[0x48, 0x82, 0, 0, 0, 0, 0, 0, 0, 0], false)
            .contains("SANITIZE service_action=BLOCK ERASE immed=true"));
        assert!(decode_cdb(&[0x25, 0, 0, 0, 0, 0, 0, 0, 0, 0], false).contains("READ CAPACITY(10)"));
        assert!(decode_cdb(&[0x12], true).contains("INQUIRY"));
        assert!(decode_cdb(&[0x12], false).contains("too short"));
        assert!(
            decode_cdb(&nclr::controller_protocol::phison_version_cdb(), false)
                .contains("PHISON VERSION PAGE")
        );
        assert!(
            decode_cdb(&nclr::controller_protocol::alcor_config_read_cdb(), false)
                .contains("ALCOR CONFIG READ")
        );
        let mut phison_image = vec![0u8; 0x200 + 0x8000];
        phison_image[..8].copy_from_slice(b"BtPramCd");
        phison_image[0x10..0x14].copy_from_slice(&32u32.to_le_bytes());
        let phison_chunks = nclr::controller_protocol::phison_pram_transfer(&phison_image).unwrap();
        assert!(decode_cdb(&phison_chunks[0].cdb, false).contains("HEADER TRANSFER bytes=512"));
        assert!(decode_cdb(&phison_chunks[1].cdb, false)
            .contains("address_bytes=0 transfer_bytes=32768"));
        assert!(decode_cdb(
            &nclr::controller_protocol::phison_transfer_status_cdb(),
            false
        )
        .contains("response_bytes=8"));
        assert!(
            decode_cdb(&nclr::controller_protocol::smi_identity_cdb(), false)
                .contains("not NAND ID")
        );
        assert!(decode_cdb(&[0x81, 0x00, 0xFF, 0, 0, 0], false).contains("prohibited"));
        assert!(
            decode_cdb(&[0xff, 0x22, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], false)
                .contains("not physical NAND erase")
        );
        assert!(
            decode_cdb(&[0xff, 0x03, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0], false)
                .contains("not NAND ID")
        );
        assert!(
            decode_cdb(&[0xff, 0x42, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3], false)
                .contains("block=2 count=3 transfer_bytes=6144")
        );
    }

    #[test]
    fn trace_diff_fixture() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.ndjson");
        let b = dir.path().join("b.ndjson");
        std::fs::write(
            &a,
            "{\"seq\":0,\"opcode\":18,\"response_hex\":\"aa\"}\n{\"seq\":1,\"opcode\":37}\n",
        )
        .unwrap();
        std::fs::write(&b, "{\"seq\":0,\"opcode\":18,\"response_hex\":\"bb\"}\n{\"seq\":1,\"opcode\":72}\n{\"seq\":2,\"opcode\":1}\n").unwrap();
        let ta = load_trace(&a).unwrap();
        let tb = load_trace(&b).unwrap();
        assert_eq!(ta.len(), 2);
        assert_eq!(tb.len(), 3);
    }

    #[test]
    fn tshark_rows_decode_strict_bot_and_redact_payload() {
        let mut cbw = vec![0u8; 31];
        cbw[..4].copy_from_slice(b"USBC");
        cbw[4..8].copy_from_slice(&7u32.to_le_bytes());
        cbw[8..12].copy_from_slice(&4u32.to_le_bytes());
        cbw[12] = 0x80;
        cbw[14] = 6;
        cbw[15..21].copy_from_slice(&[0x12, 0, 0, 0, 4, 0]);
        let mut csw = vec![0u8; 13];
        csw[..4].copy_from_slice(b"USBS");
        csw[4..8].copy_from_slice(&7u32.to_le_bytes());
        let rows = format!(
            "1\t1.0\t1\t2\t\t0x02\t\t{}\n2\t1.1\t1\t2\t\t0x81\t\t01020304\n3\t1.2\t1\t2\t\t0x81\t\t{}\n",
            hex::encode(cbw),
            hex::encode(csw)
        );
        let mut output = Vec::new();
        let (records, ignored) =
            decode_tshark_rows(std::io::Cursor::new(rows.as_bytes()), &mut output, false).unwrap();
        assert_eq!((records, ignored), (1, 0));
        let value: serde_json::Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["opcode"], 0x12);
        assert_eq!(value["transferred_length"], 4);
        assert!(value.get("response_hex").is_none());
        assert!(value["payload_sha256"]
            .as_str()
            .unwrap()
            .starts_with("sha256:"));
    }

    #[test]
    fn infer_checksum_candidates() {
        let bytes = [0x12u8, 0x00, 0x00, 0x00, 0x60, 0x00];
        let sum: u64 = bytes.iter().map(|b| *b as u64).sum();
        assert_eq!((sum & 0xFF) as u8, 0x72);
        assert_eq!(bytes.iter().fold(0u8, |a, b| a ^ b), 0x72);
    }

    #[test]
    fn crc16_known_value() {
        // CRC-16/CCITT of "123456789" is 0x29B1.
        assert_eq!(crc16(b"123456789"), 0x29B1);
    }

    #[test]
    fn replay_filters_writes_and_defaults_dry_run() {
        let dir = tempfile::tempdir().unwrap();
        let t = dir.path().join("t.ndjson");
        std::fs::write(
            &t,
            "{\"seq\":0,\"opcode\":18,\"cdb_hex\":\"120000006000\",\"dir\":\"in\"}\n\
             {\"seq\":1,\"opcode\":42,\"cdb_hex\":\"42000000000000000000\",\"dir\":\"out\"}\n\
             {\"seq\":2,\"opcode\":72,\"dir\":\"in\"}\n\
             {\"seq\":3,\"cdb_hex\":\"28000000000000000000\",\"dir\":\"in\"}\n",
        )
        .unwrap();
        let trace = load_trace(&t).unwrap();
        assert_eq!(trace.len(), 4);

        // Every recognized destructive opcode is classified as a skip.
        for (op, name) in [
            (0x04u64, "FORMAT UNIT"),
            (0x0A, "WRITE(6)"),
            (0x2A, "WRITE(10)"),
            (0xAA, "WRITE(12)"),
            (0x8A, "WRITE(16)"),
            (0x2E, "WRITE AND VERIFY(10)"),
            (0x8E, "WRITE AND VERIFY(16)"),
            (0xAE, "WRITE AND VERIFY(12)"),
            (0x41, "WRITE SAME(10)"),
            (0x93, "WRITE SAME(16)"),
            (0x42, "UNMAP"),
            (0x48, "SANITIZE"),
        ] {
            assert!(
                REPLAY_WRITES.contains(&op),
                "{name} (0x{op:02x}) must be in REPLAY_WRITES"
            );
        }
        // Read-only opcodes are replayable; unclassified opcodes are not.
        assert!(is_read_only_op(0x12)); // INQUIRY
        assert!(is_read_only_op(0x25)); // READ CAPACITY(10)
        assert!(!is_read_only_op(0x77)); // unclassified
        assert!(!is_read_only_op(0x42)); // UNMAP is a write, not read-only

        // Replay classification: seq 1 is WRITE(10) (0x2A) -> skip; seq 2 is
        // SANITIZE (0x48) -> skip; seq 3 is READ(10) (0x28, parsed from the
        // CDB) -> read-only.
        assert!(replay_line(&trace[0]).contains("read-only, dry-run"));
        assert!(replay_line(&trace[1]).contains("skip seq 1"));
        assert!(replay_line(&trace[2]).contains("skip seq 2"));
        assert!(replay_line(&trace[3]).contains("read-only, dry-run"));

        // A record with no opcode and no CDB is unclassified, never a read.
        let bare = TraceRecord {
            seq: 9,
            opcode: None,
            dir: Some("in".into()),
            cdb_hex: None,
            response_hex: None,
            status: None,
        };
        assert!(replay_line(&bare).contains("skip seq 9"));

        // A read-only opcode recorded with an "out" direction is a trace
        // mis-recording and must be skipped, not sent host->device.
        let misrecorded = TraceRecord {
            seq: 10,
            opcode: Some(0x12),
            dir: Some("out".into()),
            cdb_hex: Some("120000006000".into()),
            response_hex: None,
            status: None,
        };
        assert!(replay_line(&misrecorded).contains("skip seq 10"));
    }

    #[test]
    fn profile_template_roundtrip() {
        // The generated template must pass the schema loader (research trust).
        let rendered = TEMPLATE
            .replace("{family}", "test")
            .replace("{controller}", "ctlr-x");
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("p.toml");
        std::fs::write(&path, &rendered).unwrap();
        let p = nclr::profile::load(&path).unwrap();
        assert_eq!(p.controller_id, "ctlr-x");
        assert!(
            !p.destructive_allowed(),
            "template defaults to research trust"
        );
    }
}
