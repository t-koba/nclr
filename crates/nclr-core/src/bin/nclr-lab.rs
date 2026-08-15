//! nclr-lab: research tooling. Protocol inference and replay are separate
//! from destructive handlers. The artifact verifier is deliberately shared
//! with `nclr run` so both paths authenticate identical bytes. Write-command
//! brute forcing is prohibited; `replay` defaults to a dry run and refuses
//! write/unknown commands outside of it.
//!
//! Commands: alcor-au698x, artifact, cap, controller, decode, diff, infer,
//! phison-ps2303, probe, profile, recipe, replay, smi-ufdif, tool, trace.

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
    /// Validate and build exact Alcor AU698x service artifacts
    AlcorAu698x(AlcorAu698xArgs),
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
    /// Validate and perform final research checks for the PS2303 loader
    PhisonPs2303(PhisonPs2303Args),
    /// Generate or validate an exact read-only controller probe profile
    Probe(ProbeArgs),
    /// Generate / validate controller profile templates
    Profile(ProfileArgs),
    /// Authenticate and validate a controller protocol recipe against a profile
    Recipe(RecipeArgs),
    /// Replay read-only commands from a trace (dry-run by default)
    Replay(ReplayArgs),
    /// Reconstruct exact SMI UFDIF package and command contracts
    SmiUfdif(SmiUfdifArgs),
    /// Extract bounded protocol and controller/NAND package contracts
    Tool(ToolArgs),
    /// Convert a pcapng USB BOT capture to normalized NDJSON
    Trace(TraceArgs),
}

#[derive(clap::Args)]
struct AlcorAu698xArgs {
    #[command(subcommand)]
    cmd: AlcorAu698xCmd,
}

#[derive(Subcommand)]
enum AlcorAu698xCmd {
    /// Resolve one exact NAND/controller tuple from a genuine package
    PackageTuple {
        package: std::path::PathBuf,
        #[arg(long)]
        nand_id: String,
        /// Two hexadecimal digits from the CTL directory name
        #[arg(long)]
        controller_generation: String,
        /// Required only when the package contains distinct matching AFL rows
        #[arg(long)]
        database_selector: Option<String>,
        /// Decode the authenticated runtime module to a new research file
        #[arg(long)]
        decoded_module_output: Option<std::path::PathBuf>,
        /// Strict JSON runtime observations for the UfdApi normal geometry branch
        #[arg(long)]
        normal_geometry_runtime: Option<std::path::PathBuf>,
    },
    /// Decode the genuine encrypted NAND database without executing vendor code
    FlashDatabase {
        file: std::path::PathBuf,
        #[arg(long)]
        nand_id: Option<String>,
        /// Decode exactly one authenticated record to a new research file
        #[arg(long, requires = "record_output")]
        entry_index: Option<usize>,
        /// New output path for --entry-index; existing files are never replaced
        #[arg(long, requires = "entry_index")]
        record_output: Option<std::path::PathBuf>,
    },
    /// Decode the recovered MODULE_FETURE fields and normal geometry data flow
    ModuleFeature {
        /// Two hexadecimal digits from the CTL directory name
        #[arg(long)]
        controller_generation: String,
        /// Exact controller-specific comma-separated non-negative parameters
        #[arg(long)]
        parameters: String,
        /// Required upstream object value for generations other than CTL 10/13
        #[arg(long)]
        object_3cc: Option<u32>,
        /// Optional strict JSON inputs for the normal-mode geometry branch
        #[arg(long)]
        normal_geometry: Option<std::path::PathBuf>,
    },
    /// Build the recovered 512-byte parameter page from explicit JSON fields
    ParameterPage {
        #[arg(long)]
        fields: std::path::PathBuf,
        #[arg(short, long)]
        output: std::path::PathBuf,
    },
    /// Decode and validate one factory ASCII-hex module without executing it
    ModuleCheck { file: std::path::PathBuf },
    /// Build the exact module plus 512-byte parameter-page service payload
    ServicePayload {
        #[arg(long)]
        module: std::path::PathBuf,
        #[arg(long)]
        parameter_page: std::path::PathBuf,
        #[arg(short, long)]
        output: std::path::PathBuf,
    },
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
    /// Limit output to one canonical family or vendor alias
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
struct PhisonPs2303Args {
    #[command(subcommand)]
    cmd: PhisonPs2303Cmd,
}

#[derive(Subcommand)]
enum PhisonPs2303Cmd {
    /// Authenticate the exact reproducible loader image without executing it
    LoaderCheck { file: std::path::PathBuf },
    /// Encode and validate an exact-NAND-ID-bound non-ONFI geometry payload
    Geometry {
        #[arg(long)]
        nand_id: String,
        #[arg(long)]
        page_bytes: u32,
        #[arg(long)]
        oob_bytes: u16,
        #[arg(long)]
        pages_per_block: u32,
        #[arg(long)]
        blocks_per_lun: u32,
        #[arg(long)]
        luns: u8,
        #[arg(long)]
        column_address_cycles: u8,
        #[arg(long)]
        row_address_cycles: u8,
        #[arg(long)]
        bits_per_cell: u8,
        #[arg(long, default_value_t = 0)]
        channel: u8,
        #[arg(long, default_value_t = 0)]
        chip: u8,
    },
    /// Read and validate the signed Phison version page on the final device
    Inspect {
        device: String,
        #[arg(long)]
        confirm_research_device: bool,
    },
    /// Enter volatile BootROM mode after exact signed identity validation
    EnterBootrom {
        device: String,
        #[arg(long)]
        firmware: String,
        #[arg(long)]
        confirm_research_device: bool,
    },
    /// Transfer and start only the exact reviewed volatile loader image
    Load {
        device: String,
        file: std::path::PathBuf,
        #[arg(long)]
        firmware: String,
        #[arg(long)]
        confirm_research_device: bool,
    },
    /// Authenticate a running loader and read its NAND identity
    ProbeLoader {
        device: String,
        #[arg(long, default_value_t = 0)]
        channel: u8,
        #[arg(long, default_value_t = 0)]
        chip: u8,
        /// Require and validate three ONFI parameter-page copies
        #[arg(long)]
        read_onfi: bool,
        #[arg(long)]
        confirm_research_device: bool,
    },
}

#[derive(clap::Args)]
struct ProbeArgs {
    #[command(subcommand)]
    cmd: ProbeCmd,
}

#[derive(Subcommand)]
enum ProbeCmd {
    /// Validate a complete read-only probe profile
    Check { file: std::path::PathBuf },
    /// Generate a probe profile skeleton from `nclr info -j`
    New {
        info: std::path::PathBuf,
        #[arg(long)]
        family: String,
        #[arg(long)]
        controller: String,
        #[arg(long)]
        firmware: String,
        #[arg(long)]
        nand_id: String,
        #[arg(short, long)]
        out: Option<std::path::PathBuf>,
    },
    /// Match and optionally execute an exact read-only probe on macOS
    Run {
        file: std::path::PathBuf,
        device: String,
        /// Obtain exclusive access and send the two validated reads
        #[arg(long)]
        execute: bool,
        /// Confirm that traced vendor reads may be sent to this research device
        #[arg(long, requires = "execute")]
        confirm_research_device: bool,
    },
}

#[derive(clap::Args)]
struct ProfileArgs {
    /// Generate a new profile template
    #[arg(long, conflicts_with = "check")]
    new: bool,
    /// Validate an existing profile file
    #[arg(long, conflicts_with = "new")]
    check: bool,
    /// Require every production field except independent HIL evidence
    #[arg(long, requires = "check")]
    pre_hil: bool,
    /// Content-addressed artifact store; repeat for multiple stores
    #[arg(long = "artifact-dir", requires = "pre_hil")]
    artifact_dirs: Vec<std::path::PathBuf>,
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
struct SmiUfdifArgs {
    #[command(subcommand)]
    cmd: SmiUfdifCmd,
}

#[derive(Subcommand)]
enum SmiUfdifCmd {
    /// Parse the genuine 27-field ForceFlash NAND database
    ForceFlash {
        file: std::path::PathBuf,
        #[arg(long)]
        nand_id: Option<String>,
        #[arg(long, requires = "nand_id")]
        model: Option<String>,
    },
    /// Authenticate the reviewed SM3280 memory-symbol map
    MemFile { file: std::path::PathBuf },
    /// Resolve one exact controller/NAND/service-artifact tuple from a package
    PackageTuple {
        package: std::path::PathBuf,
        #[arg(long)]
        controller: String,
        #[arg(long)]
        nand_id: String,
        /// Exact ForceFlash record key when the NAND ID has multiple modes
        #[arg(long)]
        model: Option<String>,
    },
}

#[derive(clap::Args)]
struct RecipeArgs {
    /// Exact pre-HIL or production profile declaring the recipe artifact
    #[arg(long)]
    profile: std::path::PathBuf,
    /// Recipe bytes whose size and SHA-256 must match the profile
    #[arg(long)]
    file: std::path::PathBuf,
}

#[derive(clap::Args)]
struct ToolArgs {
    /// Vendor executable, loader, extracted package tree or source file
    path: std::path::PathBuf,
    /// Limit matches to one canonical controller family
    #[arg(long)]
    family: Option<String>,
    /// Include files with no protocol match in directory output
    #[arg(long)]
    include_unmatched: bool,
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
        LabCmd::AlcorAu698x(a) => cmd_alcor_au698x(&a),
        LabCmd::Artifact(a) => cmd_artifact(&a),
        LabCmd::Cap(a) => cmd_cap(&a),
        LabCmd::Controller(a) => cmd_controller(&a),
        LabCmd::Decode(a) => cmd_decode(&a),
        LabCmd::Diff(a) => cmd_diff(&a),
        LabCmd::Infer(a) => cmd_infer(&a),
        LabCmd::PhisonPs2303(a) => cmd_phison_ps2303(&a),
        LabCmd::Probe(a) => cmd_probe(&a),
        LabCmd::Profile(a) => cmd_profile(&a),
        LabCmd::Recipe(a) => cmd_recipe(&a),
        LabCmd::Replay(a) => cmd_replay(&a),
        LabCmd::SmiUfdif(a) => cmd_smi_ufdif(&a),
        LabCmd::Tool(a) => cmd_tool(&a),
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
    use nclr::controller_protocol::{family_from_str, support, Family};
    let families = match args.family.as_deref() {
        None => Family::ALL.to_vec(),
        Some("phison") | Some("phison-ufd") => vec![Family::PhisonUfd],
        Some("alcor") | Some("alcor-ufd") => vec![Family::AlcorUfd],
        Some("smi") | Some("silicon-motion") | Some("silicon-motion-ufd") => {
            vec![Family::SiliconMotionUfd]
        }
        Some("sandisk") | Some("sandisk-cruzer") => vec![Family::SandiskCruzer],
        Some("usbest") | Some("usbest-ufd") => vec![Family::UsbestUfd],
        Some("chipsbank") | Some("chipsbank-ufd") => vec![Family::ChipsbankUfd],
        Some("innostor") | Some("innostor-ufd") => vec![Family::InnostorUfd],
        Some("firstchip") | Some("firstchip-ufd") => vec![Family::FirstchipUfd],
        Some("sss") | Some("solid-state-system") | Some("solid-state-system-ufd") => {
            vec![Family::SolidStateSystemUfd]
        }
        Some("skymedi") | Some("skymedi-ufd") => vec![Family::SkymediUfd],
        Some("appotech") | Some("appotech-ufd") => vec![Family::AppotechUfd],
        Some("silicongo") | Some("silicongo-ufd") => vec![Family::SilicongoUfd],
        Some("icreate") | Some("icreate-ufd") => vec![Family::IcreateUfd],
        Some("oti") | Some("ours-technology") | Some("oti-ufd") => vec![Family::OtiUfd],
        Some("prolific") | Some("prolific-ufd") => vec![Family::ProlificUfd],
        Some("ameco") | Some("mxtronics") | Some("ameco-ufd") => vec![Family::AmecoUfd],
        Some("netac") | Some("netac-ufd") => vec![Family::NetacUfd],
        Some("efortune") | Some("efortune-ufd") => vec![Family::EfortuneUfd],
        Some("ite") | Some("ite-ufd") => vec![Family::IteUfd],
        Some("hyperstone") | Some("hyperstone-ufd") => vec![Family::HyperstoneUfd],
        Some("yeestor") | Some("yeestor-ufd") => vec![Family::YeestorUfd],
        Some("ramos") | Some("ramos-ufd") => vec![Family::RamosUfd],
        Some("trek") | Some("trek2000") | Some("trek2000-ufd") => vec![Family::Trek2000Ufd],
        Some("moai") | Some("moai-ufd") => vec![Family::MoaiUfd],
        Some("realway") | Some("realway-ufd") => vec![Family::RealwayUfd],
        Some("huayi") | Some("huayi-ufd") => vec![Family::HuayiUfd],
        Some("ktc") | Some("ktc-ufd") => vec![Family::KtcUfd],
        Some("smsc") | Some("smsc-ufd") => vec![Family::SmscUfd],
        Some(canonical) => match family_from_str(canonical) {
            Some(family) => vec![family],
            None => {
                eprintln!("nclr-lab: unknown controller family: {canonical}");
                return 64;
            }
        },
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
// phison-ps2303
// ---------------------------------------------------------------------------

const PS2303_LOADER_FILE_LIMIT: u64 = 1024 * 1024;

fn read_bounded_regular_file(
    path: &std::path::Path,
    maximum_bytes: u64,
    label: &str,
) -> Result<Vec<u8>> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|error| Error::io(format!("open {label} {}", path.display()), Some(error)))?;
    let before = file
        .metadata()
        .map_err(|error| Error::io(format!("stat {label} {}", path.display()), Some(error)))?;
    if !before.is_file() || before.len() == 0 || before.len() > maximum_bytes {
        return Err(Error::Invalid(format!(
            "{label} {} must be a regular file in 1..={maximum_bytes} bytes",
            path.display()
        )));
    }
    use std::io::Read;
    let mut bytes = Vec::with_capacity(before.len() as usize);
    file.by_ref()
        .take(maximum_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| Error::io(format!("read {label} {}", path.display()), Some(error)))?;
    let after = file
        .metadata()
        .map_err(|error| Error::io(format!("restat {label} {}", path.display()), Some(error)))?;
    if bytes.len() as u64 != before.len() || after.len() != before.len() {
        return Err(Error::Invalid(format!(
            "{label} {} changed size while being read",
            path.display()
        )));
    }
    Ok(bytes)
}

fn require_research_confirmation(confirmed: bool) -> Result<()> {
    if confirmed {
        Ok(())
    } else {
        Err(Error::Permission(
            "hardware access requires --confirm-research-device".into(),
        ))
    }
}

#[cfg(target_os = "macos")]
fn with_ps2303_scsi<T>(
    device: &str,
    state_changing: bool,
    operation: impl FnOnce(&mut nclr::macos_scsi::ScsiDevice) -> Result<T>,
) -> Result<T> {
    let identity = nclr::device::identify(device)?;
    nclr::safety::deep_probe(&identity)?;
    if identity.usb.is_none()
        || !matches!(
            identity.transport.as_str(),
            nclr::device::TRANSPORT_USB_MSD | nclr::device::TRANSPORT_SD_VIA_USB
        )
    {
        return Err(Error::Unsupported(format!(
            "PS2303 research access requires USB mass storage, got {}",
            identity.transport
        )));
    }
    if state_changing {
        nclr::safety::preflight(&identity, &nclr::safety::SafetyOptions::default())?;
    } else {
        nclr::safety::preflight_read(&identity, &nclr::safety::SafetyOptions::default())?;
    }

    let mut transport = nclr::macos_scsi::ScsiDevice::open(device)?;
    let result = operation(&mut transport);
    let cleanup = transport.close();
    match (result, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(operation), Err(cleanup)) => Err(Error::Backend(format!(
            "PS2303 device operation failed: {operation}; cleanup also failed: {cleanup}"
        ))),
    }
}

// ---------------------------------------------------------------------------
// alcor-au698x
// ---------------------------------------------------------------------------

const ALCOR_ARTIFACT_FILE_LIMIT: u64 = 8 * 1024 * 1024;

fn parse_alcor_nand_id(value: &str) -> Result<String> {
    let value = value.trim().to_ascii_lowercase();
    if value.len() != 12
        || !value.as_bytes().iter().all(u8::is_ascii_hexdigit)
        || matches!(value.as_str(), "000000000000" | "ffffffffffff")
    {
        return Err(Error::Invalid(
            "Alcor NAND id must be exactly six non-empty hexadecimal bytes".into(),
        ));
    }
    Ok(value)
}

fn parse_alcor_controller_generation(value: &str) -> Result<u8> {
    let generation = value
        .trim()
        .strip_prefix("0x")
        .or_else(|| value.trim().strip_prefix("0X"))
        .unwrap_or(value.trim());
    if generation.len() != 2 || !generation.as_bytes().iter().all(u8::is_ascii_hexdigit) {
        return Err(Error::Invalid(
            "Alcor controller generation must contain exactly two hexadecimal digits".into(),
        ));
    }
    u8::from_str_radix(generation, 16)
        .map_err(|_| Error::Invalid("Alcor controller generation is out of range".into()))
}

fn write_new_bytes(path: &std::path::Path, contents: &[u8], label: &str) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|error| {
        Error::io(
            format!("create {label} {} without overwriting", path.display()),
            Some(error),
        )
    })?;
    file.write_all(contents)
        .and_then(|()| file.flush())
        .and_then(|()| file.sync_all())
        .map_err(|error| Error::io(format!("write {label} {}", path.display()), Some(error)))
}

fn cmd_alcor_au698x(args: &AlcorAu698xArgs) -> i32 {
    use sha2::Digest as _;

    let result = (|| -> Result<serde_json::Value> {
        match &args.cmd {
            AlcorAu698xCmd::PackageTuple {
                package,
                nand_id,
                controller_generation,
                database_selector,
                decoded_module_output,
                normal_geometry_runtime,
            } => {
                let nand_id = parse_alcor_nand_id(nand_id)?;
                let generation = parse_alcor_controller_generation(controller_generation)?;
                let controller_id = format!("alcor-ctl-{generation:02x}");
                let analysis = nclr::vendor_tool::analyze(package, Some("alcor-ufd"), false)?;
                let candidates = analysis
                    .alcor_candidate_tuple_records
                    .iter()
                    .filter(|candidate| {
                        candidate.nand_id == nand_id
                            && candidate.controller_id == controller_id
                            && database_selector
                                .as_ref()
                                .is_none_or(|selector| &candidate.database_selector == selector)
                    })
                    .collect::<Vec<_>>();
                if candidates.is_empty() {
                    return Err(Error::Invalid(format!(
                        "Alcor package has no tuple for NAND {nand_id}, controller {controller_id}{}",
                        database_selector
                            .as_ref()
                            .map(|selector| format!(", database selector {selector}"))
                            .unwrap_or_default()
                    )));
                }
                if candidates.len() != 1 {
                    let selectors = candidates
                        .iter()
                        .map(|candidate| candidate.database_selector.as_str())
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                        .join(", ");
                    return Err(Error::Invalid(format!(
                        "Alcor package resolves NAND {nand_id}, controller {controller_id} to {} AFL rows ({selectors}); select one with --database-selector",
                        candidates.len()
                    )));
                }
                let candidate = candidates[0];
                if !candidate.selection_unambiguous {
                    return Err(Error::Invalid(format!(
                        "Alcor tuple {} is incomplete: AFL converter={}, DefaultEnable25NS={}, module feature={}{}",
                        candidate.database_selector,
                        candidate.flash_database_converter_resolution,
                        candidate.default_enable_25ns_resolution,
                        candidate.module_feature_resolution,
                        candidate
                            .module_feature_error
                            .as_ref()
                            .map(|error| format!(", parser error={error}"))
                            .unwrap_or_default()
                    )));
                }
                let [mapping] = candidate.module_feature_candidates.as_slice() else {
                    return Err(Error::Invalid(format!(
                        "Alcor tuple {} does not have exactly one module-feature mapping",
                        candidate.database_selector
                    )));
                };
                if mapping.artifact.resolution != "unique" {
                    return Err(Error::Invalid(format!(
                        "Alcor tuple {} runtime module artifact resolution is {}",
                        candidate.database_selector, mapping.artifact.resolution
                    )));
                }
                let [artifact] = mapping.artifact.candidates.as_slice() else {
                    return Err(Error::Invalid(format!(
                        "Alcor tuple {} does not resolve to exactly one runtime module artifact",
                        candidate.database_selector
                    )));
                };
                let encoded_module = read_bounded_regular_file(
                    &artifact.path,
                    ALCOR_ARTIFACT_FILE_LIMIT,
                    "Alcor factory module",
                )?;
                let encoded_sha256 = hex::encode(sha2::Sha256::digest(&encoded_module));
                if encoded_module.len() as u64 != artifact.size_bytes
                    || encoded_sha256 != artifact.sha256
                {
                    return Err(Error::Invalid(format!(
                        "Alcor runtime module {} changed after package analysis",
                        artifact.path.display()
                    )));
                }
                let decoded_module = nclr::alcor_au698x::decode_ascii_hex_module(&encoded_module)?;
                let module_sectors = nclr::alcor_au698x::validate_decoded_module(&decoded_module)?;
                let decoded_sha256 = hex::encode(sha2::Sha256::digest(&decoded_module));
                if let Some(output) = decoded_module_output {
                    write_new_bytes(output, &decoded_module, "Alcor decoded runtime module")?;
                }
                let normal_geometry = normal_geometry_runtime
                    .as_ref()
                    .map(|path| {
                        let source = read_bounded_regular_file(
                            path,
                            64 * 1024,
                            "Alcor UfdApi normal geometry runtime inputs",
                        )?;
                        let runtime: nclr::alcor_au698x::UfdApiNormalGeometryRuntimeInputs =
                            serde_json::from_slice(&source).map_err(|error| {
                                Error::Invalid(format!(
                                    "Alcor UfdApi normal geometry runtime inputs JSON: {error}"
                                ))
                            })?;
                        nclr::alcor_au698x::derive_ufdapi_normal_geometry(
                            candidate
                                .controller_adjusted_module_feature
                                .as_ref()
                                .ok_or_else(|| {
                                    Error::Invalid(
                                        "Alcor tuple has no adjusted module feature".into(),
                                    )
                                })?,
                            candidate.operational_fields.as_ref().ok_or_else(|| {
                                Error::Invalid(
                                    "Alcor tuple has no resolved operational fields".into(),
                                )
                            })?,
                            &runtime,
                        )
                    })
                    .transpose()?;
                let parameter_page_derived_fields = normal_geometry
                    .as_ref()
                    .map(|_| vec!["object_a8", "object_aa", "object_ac", "object_ae"])
                    .unwrap_or_default();
                let mut parameter_page_contract_inputs = vec![
                    "control_00",
                    "object_02",
                    "helper_10",
                    "helper_11",
                    "operation_code_102",
                    "operation_argument",
                    "object_105",
                    "helper_10f",
                    "address_words",
                    "feature_120",
                    "feature_121",
                    "controller_e3_signature",
                    "global_140",
                    "helper_192",
                    "object_194",
                    "helper_195",
                    "feature_19f",
                    "object_1a7",
                    "helper_1a8",
                    "object_mask_1ed_1ef",
                    "normalized_object_1ee",
                ];
                if normal_geometry.is_none() {
                    parameter_page_contract_inputs
                        .splice(2..2, ["object_a8", "object_aa", "object_ac", "object_ae"]);
                }
                let parameter_page_fields_derived_from_tuple =
                    parameter_page_contract_inputs.is_empty();
                Ok(serde_json::json!({
                    "ok": true,
                    "schema": 2,
                    "hardware_access": false,
                    "tool_analysis_schema": analysis.schema,
                    "package": package,
                    "candidate": candidate,
                    "runtime_module": {
                        "encoded_path": artifact.path,
                        "encoded_size_bytes": encoded_module.len(),
                        "encoded_sha256": encoded_sha256,
                        "decoded_size_bytes": decoded_module.len(),
                        "decoded_sha256": decoded_sha256,
                        "module_sectors": module_sectors,
                        "decoded_output": decoded_module_output,
                    },
                    "controller_tuple_ready": true,
                    "normal_geometry": normal_geometry,
                    "parameter_page_derived_fields": parameter_page_derived_fields,
                    "parameter_page_contract_inputs": parameter_page_contract_inputs,
                    "parameter_page_fields_derived_from_tuple": parameter_page_fields_derived_from_tuple,
                    "service_payload_ready": false,
                    "nand_mutation": false,
                    "purge_authorized": false,
                }))
            }
            AlcorAu698xCmd::FlashDatabase {
                file,
                nand_id,
                entry_index,
                record_output,
            } => {
                let source = read_bounded_regular_file(
                    file,
                    ALCOR_ARTIFACT_FILE_LIMIT,
                    "Alcor flash database",
                )?;
                let database = nclr::alcor_au698x::decode_flash_database(&source)?;
                let requested_nand_id = nand_id.as_deref().map(parse_alcor_nand_id).transpose()?;
                let matches = requested_nand_id.as_ref().map(|value| {
                    database
                        .entries
                        .iter()
                        .filter(|entry| &entry.nand_id_hex == value)
                        .collect::<Vec<_>>()
                });
                let mut controllers = std::collections::BTreeMap::<String, usize>::new();
                let mut vendors = std::collections::BTreeSet::<String>::new();
                for entry in &database.entries {
                    vendors.insert(entry.vendor.clone());
                    for selection in &entry.controller_selections {
                        if selection.runtime_module().is_some() {
                            *controllers
                                .entry(selection.controller_id.clone())
                                .or_default() += 1;
                        }
                    }
                }
                let extracted_record = match (entry_index, record_output) {
                    (Some(index), Some(output)) => {
                        let entry = database.entries.get(*index).ok_or_else(|| {
                            Error::Invalid(format!(
                                "Alcor flash database entry index {index} is outside 0..{}",
                                database.entries.len()
                            ))
                        })?;
                        write_new_bytes(output, &entry.decoded_record, "Alcor decoded record")?;
                        Some(serde_json::json!({
                            "index": index,
                            "output": output,
                            "size_bytes": entry.decoded_record.len(),
                            "sha256": entry.record_sha256,
                        }))
                    }
                    (None, None) => None,
                    _ => {
                        return Err(Error::Invalid(
                            "Alcor entry extraction requires both --entry-index and --record-output"
                                .into(),
                        ));
                    }
                };
                Ok(serde_json::json!({
                    "ok": true,
                    "hardware_access": false,
                    "source_size_bytes": source.len(),
                    "source_sha256": hex::encode(sha2::Sha256::digest(&source)),
                    "header": database.header,
                    "decoded_entries_sha256": database.decoded_entries_sha256,
                    "unparsed_suffix_bytes": database.unparsed_suffix_bytes,
                    "unparsed_suffix_sha256": database.unparsed_suffix_sha256,
                    "vendor_count": vendors.len(),
                    "controller_module_counts": controllers,
                    "requested_nand_id": requested_nand_id,
                    "matching_entries": matches,
                    "extracted_record": extracted_record,
                    "nand_mutation": false,
                    "purge_authorized": false,
                }))
            }
            AlcorAu698xCmd::ModuleFeature {
                controller_generation,
                parameters,
                object_3cc,
                normal_geometry,
            } => {
                let generation = parse_alcor_controller_generation(controller_generation)?;
                let parameters = parameters
                    .split(',')
                    .map(str::trim)
                    .map(|value| {
                        if value.is_empty() || !value.as_bytes().iter().all(u8::is_ascii_digit) {
                            return Err(Error::Invalid(
                                "Alcor module feature parameters must be non-negative decimals"
                                    .into(),
                            ));
                        }
                        value.parse::<u64>().map_err(|_| {
                            Error::Invalid("Alcor module feature parameter is out of range".into())
                        })
                    })
                    .collect::<Result<Vec<_>>>()?;
                nclr::alcor_au698x::validate_module_feature_parameter_count(
                    generation,
                    parameters.len(),
                )?;
                let parsed = nclr::alcor_au698x::parse_module_feature_parameters(&parameters)?;
                let adjusted = nclr::alcor_au698x::apply_module_feature_controller_limit(
                    &parsed,
                    generation,
                    *object_3cc,
                )?;
                let geometry = normal_geometry
                    .as_ref()
                    .map(|path| {
                        let source = read_bounded_regular_file(
                            path,
                            64 * 1024,
                            "Alcor normal geometry inputs",
                        )?;
                        let inputs: nclr::alcor_au698x::NormalGeometryInputs =
                            serde_json::from_slice(&source).map_err(|error| {
                                Error::Invalid(format!(
                                    "Alcor normal geometry inputs JSON: {error}"
                                ))
                            })?;
                        nclr::alcor_au698x::derive_normal_geometry(&adjusted, &inputs)
                    })
                    .transpose()?;
                Ok(serde_json::json!({
                    "ok": true,
                    "hardware_access": false,
                    "factory_library_sha256": nclr::alcor_au698x::PARAMETER_BUILDER_SOURCE_SHA256,
                    "module_feature_parser_va": format!(
                        "0x{:08x}",
                        nclr::alcor_au698x::MODULE_FEATURE_PARSER_VA
                    ),
                    "legacy_module_feature_parser_va": format!(
                        "0x{:08x}",
                        nclr::alcor_au698x::LEGACY_MODULE_FEATURE_PARSER_VA
                    ),
                    "normal_geometry_builder_va": format!(
                        "0x{:08x}",
                        nclr::alcor_au698x::NORMAL_GEOMETRY_BUILDER_VA
                    ),
                    "controller_generation": format!("{generation:02x}"),
                    "parsed_feature": parsed,
                    "controller_adjusted_feature": adjusted,
                    "normal_geometry": geometry,
                    "nand_mutation": false,
                    "purge_authorized": false,
                }))
            }
            AlcorAu698xCmd::ParameterPage { fields, output } => {
                let source =
                    read_bounded_regular_file(fields, 64 * 1024, "Alcor parameter-page fields")?;
                let fields: nclr::alcor_au698x::ParameterPageFields =
                    serde_json::from_slice(&source).map_err(|error| {
                        Error::Invalid(format!("Alcor parameter-page fields JSON: {error}"))
                    })?;
                let page = nclr::alcor_au698x::build_parameter_page(&fields)?;
                write_new_bytes(output, &page, "Alcor parameter page")?;
                Ok(serde_json::json!({
                    "ok": true,
                    "hardware_access": false,
                    "output": output,
                    "output_size_bytes": page.len(),
                    "output_sha256": hex::encode(sha2::Sha256::digest(page)),
                    "factory_library_sha256": nclr::alcor_au698x::PARAMETER_BUILDER_SOURCE_SHA256,
                    "factory_builder_va": format!("0x{:08x}", nclr::alcor_au698x::PARAMETER_BUILDER_VA),
                    "parameter_page_trailer_hex": "4a4e",
                    "nand_mutation": false,
                    "purge_authorized": false,
                }))
            }
            AlcorAu698xCmd::ModuleCheck { file } => {
                let source = read_bounded_regular_file(
                    file,
                    ALCOR_ARTIFACT_FILE_LIMIT,
                    "Alcor factory module",
                )?;
                let decoded = nclr::alcor_au698x::decode_ascii_hex_module(&source)?;
                let sectors = nclr::alcor_au698x::validate_decoded_module(&decoded)?;
                Ok(serde_json::json!({
                    "ok": true,
                    "hardware_access": false,
                    "source_size_bytes": source.len(),
                    "source_sha256": hex::encode(sha2::Sha256::digest(&source)),
                    "decoded_size_bytes": decoded.len(),
                    "decoded_sha256": hex::encode(sha2::Sha256::digest(&decoded)),
                    "module_sectors": sectors,
                    "trailer_hex": "55aa",
                    "nand_mutation": false,
                    "purge_authorized": false,
                }))
            }
            AlcorAu698xCmd::ServicePayload {
                module,
                parameter_page,
                output,
            } => {
                let source = read_bounded_regular_file(
                    module,
                    ALCOR_ARTIFACT_FILE_LIMIT,
                    "Alcor factory module",
                )?;
                let decoded = nclr::alcor_au698x::decode_ascii_hex_module(&source)?;
                let parameters = read_bounded_regular_file(
                    parameter_page,
                    nclr::alcor_au698x::PARAMETER_PAGE_BYTES as u64,
                    "Alcor parameter page",
                )?;
                let upload = nclr::alcor_au698x::build_service_upload(&decoded, &parameters)?;
                write_new_bytes(output, &upload.payload, "Alcor service payload")?;
                Ok(serde_json::json!({
                    "ok": true,
                    "hardware_access": false,
                    "output": output,
                    "output_size_bytes": upload.payload.len(),
                    "output_sha256": hex::encode(sha2::Sha256::digest(&upload.payload)),
                    "service_cdb_hex": hex::encode(upload.cdb),
                    "module_sectors": upload.module_sectors,
                    "parameter_page_bytes": nclr::alcor_au698x::PARAMETER_PAGE_BYTES,
                    "parameter_page_trailer_hex": "4a4e",
                    "nand_mutation": false,
                    "purge_authorized": false,
                }))
            }
        }
    })();

    match result {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(rendered) => {
                println!("{rendered}");
                0
            }
            Err(error) => {
                eprintln!("nclr-lab: Alcor result serialization failed: {error}");
                70
            }
        },
        Err(error) => {
            eprintln!("nclr-lab: {error}");
            error.exit_code()
        }
    }
}

fn cmd_phison_ps2303(args: &PhisonPs2303Args) -> i32 {
    use nclr::phison_ps2303::{GeometryOverride, LoaderAddress, LoaderCommand};
    use sha2::Digest as _;

    let result = (|| -> Result<serde_json::Value> {
        match &args.cmd {
            PhisonPs2303Cmd::LoaderCheck { file } => {
                let image = read_bounded_regular_file(
                    file,
                    PS2303_LOADER_FILE_LIMIT,
                    "PS2303 loader image",
                )?;
                nclr::phison_ps2303::validate_reviewed_loader_image(&image)?;
                Ok(serde_json::json!({
                    "ok": true,
                    "hardware_access": false,
                    "controller_id": nclr::phison_ps2303::REVIEWED_CONTROLLER_ID,
                    "loader_schema": nclr::phison_ps2303::LOADER_SCHEMA,
                    "size_bytes": image.len(),
                    "sha256": hex::encode(sha2::Sha256::digest(&image)),
                    "reviewed_size_bytes": nclr::phison_ps2303::REVIEWED_LOADER_IMAGE_BYTES,
                    "reviewed_sha256": nclr::phison_ps2303::REVIEWED_LOADER_IMAGE_SHA256,
                    "reproducible_source_binary_size_bytes": nclr::phison_ps2303::REVIEWED_LOADER_SOURCE_BINARY_BYTES,
                    "reproducible_source_binary_sha256": nclr::phison_ps2303::REVIEWED_LOADER_SOURCE_BINARY_SHA256,
                    "nand_mutation": false,
                    "purge_authorized": false,
                }))
            }
            PhisonPs2303Cmd::Geometry {
                nand_id,
                page_bytes,
                oob_bytes,
                pages_per_block,
                blocks_per_lun,
                luns,
                column_address_cycles,
                row_address_cycles,
                bits_per_cell,
                channel,
                chip,
            } => {
                let exact_id = nclr::controller_recipe::exact_nand_id_bytes(nand_id)?;
                let expected_nand_id: [u8; 6] = exact_id.try_into().map_err(|_| {
                    Error::Invalid("PS2303 geometry requires an exact six-byte NAND ID".into())
                })?;
                let geometry = GeometryOverride {
                    page_bytes: *page_bytes,
                    oob_bytes: *oob_bytes,
                    pages_per_block: *pages_per_block,
                    blocks_per_lun: *blocks_per_lun,
                    luns: *luns,
                    column_address_cycles: *column_address_cycles,
                    row_address_cycles: *row_address_cycles,
                    bits_per_cell: *bits_per_cell,
                    expected_nand_id,
                };
                let payload = nclr::phison_ps2303::geometry_override_payload(&geometry)?;
                let address = LoaderAddress {
                    channel: *channel,
                    chip: *chip,
                    ..LoaderAddress::default()
                };
                let cdb =
                    nclr::phison_ps2303::loader_cdb(LoaderCommand::ConfigureGeometry, address)?;
                let crc = u16::from_le_bytes([payload[38], payload[39]]);
                Ok(serde_json::json!({
                    "ok": true,
                    "hardware_access": false,
                    "controller_id": nclr::phison_ps2303::REVIEWED_CONTROLLER_ID,
                    "geometry": geometry,
                    "channel": channel,
                    "chip": chip,
                    "configure_geometry_cdb_hex": hex::encode(cdb),
                    "payload_hex": hex::encode(payload),
                    "payload_size_bytes": payload.len(),
                    "payload_crc16": format!("{crc:04x}"),
                    "live_nand_id_must_match": true,
                    "nand_mutation": false,
                    "purge_authorized": false,
                }))
            }
            PhisonPs2303Cmd::Inspect {
                device,
                confirm_research_device,
            } => {
                require_research_confirmation(*confirm_research_device)?;
                #[cfg(target_os = "macos")]
                {
                    let identity = with_ps2303_scsi(device, false, |transport| {
                        nclr::phison_ps2303::inspect_controller(transport)
                    })?;
                    Ok(serde_json::json!({
                        "ok": true,
                        "hardware_access": true,
                        "read_only": true,
                        "identity": identity,
                        "nand_mutation": false,
                        "purge_authorized": false,
                    }))
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = device;
                    Err(Error::Unsupported(
                        "PS2303 hardware research currently requires macOS SCSITask".into(),
                    ))
                }
            }
            PhisonPs2303Cmd::EnterBootrom {
                device,
                firmware,
                confirm_research_device,
            } => {
                require_research_confirmation(*confirm_research_device)?;
                #[cfg(target_os = "macos")]
                {
                    let transitioned = with_ps2303_scsi(device, true, |transport| {
                        nclr::phison_ps2303::enter_bootrom(transport, firmware)
                    })?;
                    Ok(serde_json::json!({
                        "ok": true,
                        "hardware_access": true,
                        "controller_id": nclr::phison_ps2303::REVIEWED_CONTROLLER_ID,
                        "firmware": firmware,
                        "transition_command_sent": transitioned,
                        "reenumeration_expected": transitioned,
                        "volatile_state_change": transitioned,
                        "nand_mutation": false,
                        "purge_authorized": false,
                    }))
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (device, firmware);
                    Err(Error::Unsupported(
                        "PS2303 hardware research currently requires macOS SCSITask".into(),
                    ))
                }
            }
            PhisonPs2303Cmd::Load {
                device,
                file,
                firmware,
                confirm_research_device,
            } => {
                require_research_confirmation(*confirm_research_device)?;
                let image = read_bounded_regular_file(
                    file,
                    PS2303_LOADER_FILE_LIMIT,
                    "PS2303 loader image",
                )?;
                nclr::phison_ps2303::validate_reviewed_loader_image(&image)?;
                #[cfg(target_os = "macos")]
                {
                    with_ps2303_scsi(device, true, |transport| {
                        nclr::phison_ps2303::load_reviewed_loader(transport, &image, firmware)
                    })?;
                    Ok(serde_json::json!({
                        "ok": true,
                        "hardware_access": true,
                        "controller_id": nclr::phison_ps2303::REVIEWED_CONTROLLER_ID,
                        "firmware": firmware,
                        "loader_size_bytes": image.len(),
                        "loader_sha256": hex::encode(sha2::Sha256::digest(&image)),
                        "reenumeration_expected": true,
                        "volatile_state_change": true,
                        "nand_mutation": false,
                        "purge_authorized": false,
                    }))
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (device, firmware, image);
                    Err(Error::Unsupported(
                        "PS2303 hardware research currently requires macOS SCSITask".into(),
                    ))
                }
            }
            PhisonPs2303Cmd::ProbeLoader {
                device,
                channel,
                chip,
                read_onfi,
                confirm_research_device,
            } => {
                require_research_confirmation(*confirm_research_device)?;
                #[cfg(target_os = "macos")]
                {
                    let (status, nand_id, onfi_geometry) =
                        with_ps2303_scsi(device, false, |transport| {
                            let mut session =
                                nclr::phison_ps2303::LoaderSession::connect(transport)?;
                            let status = session.status()?;
                            let nand_id = session.read_nand_id(*channel, *chip)?;
                            let onfi_geometry = if *read_onfi {
                                Some(session.read_onfi_geometry(*channel, *chip)?)
                            } else {
                                None
                            };
                            Ok((status, nand_id, onfi_geometry))
                        })?;
                    Ok(serde_json::json!({
                        "ok": true,
                        "hardware_access": true,
                        "read_only": true,
                        "controller_id": nclr::phison_ps2303::REVIEWED_CONTROLLER_ID,
                        "loader_schema": nclr::phison_ps2303::LOADER_SCHEMA,
                        "channel": channel,
                        "chip": chip,
                        "status": status,
                        "nand_id": hex::encode(nand_id),
                        "onfi_requested": read_onfi,
                        "onfi_geometry": onfi_geometry,
                        "raw_read_ecc_verdict_available": false,
                        "nand_mutation": false,
                        "purge_authorized": false,
                    }))
                }
                #[cfg(not(target_os = "macos"))]
                {
                    let _ = (device, channel, chip, read_onfi);
                    Err(Error::Unsupported(
                        "PS2303 hardware research currently requires macOS SCSITask".into(),
                    ))
                }
            }
        }
    })();

    match result {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(rendered) => {
                println!("{rendered}");
                0
            }
            Err(error) => {
                eprintln!("nclr-lab: PS2303 result serialization failed: {error}");
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
// probe
// ---------------------------------------------------------------------------

fn probe_info_bootstrap(value: &serde_json::Value) -> Result<&serde_json::Value> {
    value
        .pointer("/controller_identify/controller_research/exact_bootstrap_observed")
        .or_else(|| value.pointer("/controller_research/exact_bootstrap_observed"))
        .ok_or_else(|| {
            Error::Invalid(
                "nclr info JSON does not contain controller_research.exact_bootstrap_observed"
                    .into(),
            )
        })
}

fn probe_info_string<'a>(value: &'a serde_json::Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            Error::Invalid(format!(
                "nclr info exact bootstrap field {field} is absent or not a string"
            ))
        })
}

fn probe_info_u16(value: &serde_json::Value, field: &str) -> Result<u16> {
    if let Some(number) = value.get(field).and_then(serde_json::Value::as_u64) {
        return u16::try_from(number)
            .map_err(|_| Error::Invalid(format!("nclr info field {field} exceeds u16")));
    }
    let raw = probe_info_string(value, field)?;
    let digits = raw.trim_start_matches("0x").replace('.', "");
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Invalid(format!(
            "nclr info field {field} is not hexadecimal"
        )));
    }
    u16::from_str_radix(&digits, 16)
        .map_err(|_| Error::Invalid(format!("nclr info field {field} exceeds u16")))
}

fn toml_string(value: &str) -> String {
    toml::Value::String(value.to_string()).to_string()
}

fn write_new_text(path: &std::path::Path, contents: &str, label: &str) -> Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(path).map_err(|error| {
        Error::io(
            format!("create {label} {} without overwriting", path.display()),
            Some(error),
        )
    })?;
    file.write_all(contents.as_bytes())
        .map_err(|error| Error::io(format!("write {label} {}", path.display()), Some(error)))
}

fn new_probe_template(
    info: &std::path::Path,
    family: &str,
    controller: &str,
    firmware: &str,
    nand_id: &str,
) -> Result<String> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open(info).map_err(|error| {
        Error::io(
            format!("open nclr info JSON {}", info.display()),
            Some(error),
        )
    })?;
    let metadata = file.metadata().map_err(|error| {
        Error::io(
            format!("stat nclr info JSON {}", info.display()),
            Some(error),
        )
    })?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > 16 * 1024 * 1024 {
        return Err(Error::Invalid(format!(
            "nclr info JSON {} must be a regular file in 1..=16777216 bytes",
            info.display()
        )));
    }
    use std::io::Read;
    let mut source = String::with_capacity(metadata.len() as usize);
    file.take(16 * 1024 * 1024 + 1)
        .read_to_string(&mut source)
        .map_err(|error| {
            Error::io(
                format!("read nclr info JSON {}", info.display()),
                Some(error),
            )
        })?;
    if source.len() as u64 > 16 * 1024 * 1024 || source.len() as u64 != metadata.len() {
        return Err(Error::Invalid(format!(
            "nclr info JSON {} changed size while being read",
            info.display()
        )));
    }
    let value: serde_json::Value = serde_json::from_str(&source).map_err(|error| {
        Error::Invalid(format!("parse nclr info JSON {}: {error}", info.display()))
    })?;
    let bootstrap = probe_info_bootstrap(&value)?;
    let family_value = nclr::controller_protocol::family_from_recipe_str(family)
        .ok_or_else(|| Error::Usage(format!("unknown canonical controller family {family}")))?;
    if family != family_value.recipe_str() || !family_value.accepts_controller_id(controller) {
        return Err(Error::Usage(format!(
            "controller id {controller} does not belong to family {family}"
        )));
    }
    if firmware.is_empty() || firmware.trim() != firmware || firmware.chars().any(char::is_control)
    {
        return Err(Error::Usage(
            "firmware must be a non-empty exact printable value".into(),
        ));
    }
    let nand_id = hex::encode(nclr::controller_recipe::exact_nand_id_bytes(nand_id)?);
    if let Some(observed_family) = bootstrap.get("family").and_then(serde_json::Value::as_str) {
        if !observed_family.is_empty() && observed_family != family {
            return Err(Error::Permission(format!(
                "requested family {family} conflicts with nclr info family {observed_family}"
            )));
        }
    }
    let usb_vid = probe_info_u16(bootstrap, "usb_vid")?;
    let usb_pid = probe_info_u16(bootstrap, "usb_pid")?;
    let usb_bcd_device = probe_info_u16(bootstrap, "usb_bcd_device")?;
    if usb_vid == 0 {
        return Err(Error::Invalid(
            "nclr info exact bootstrap has a zero USB vendor id".into(),
        ));
    }
    let usb_manufacturer = toml_string(probe_info_string(bootstrap, "usb_manufacturer")?);
    let usb_product = toml_string(probe_info_string(bootstrap, "usb_product")?);
    let usb_serial = toml_string(probe_info_string(bootstrap, "usb_serial")?);
    let scsi_vendor_raw = probe_info_string(bootstrap, "scsi_vendor")?;
    let scsi_product_raw = probe_info_string(bootstrap, "scsi_product")?;
    let scsi_revision_raw = probe_info_string(bootstrap, "scsi_revision")?;
    if [scsi_vendor_raw, scsi_product_raw, scsi_revision_raw].contains(&"") {
        return Err(Error::Invalid(
            "nclr info lacks a complete SCSI vendor/product/revision tuple".into(),
        ));
    }
    let scsi_vendor = toml_string(scsi_vendor_raw);
    let scsi_product = toml_string(scsi_product_raw);
    let scsi_revision = toml_string(scsi_revision_raw);
    Ok(format!(
        r#"# Exact read-only controller probe. This file never authorizes purge.
# Replace every REPLACE_* value from exact static analysis or a factory-tool trace.
schema = 1
id = {id}
family = {family}
controller_id = {controller}
firmware = {firmware}
nand_id = {nand_id}
transport = "scsi"
controller_identity_hex = "REPLACE_WITH_EXACT_CONTROLLER_RESPONSE_PAYLOAD_HEX"
protocol_evidence_sha256 = "REPLACE_WITH_64_HEX_EVIDENCE_DIGEST"
source_reference = "https://REPLACE_WITH_PRIMARY_SOURCE_OR_CLEAN_ROOM_RECORD"

[bootstrap]
family = {family}
usb_vid = 0x{usb_vid:04X}
usb_pid = 0x{usb_pid:04X}
usb_bcd_device = 0x{usb_bcd_device:04X}
usb_manufacturer = {usb_manufacturer}
usb_product = {usb_product}
usb_serial = {usb_serial}
scsi_vendor = {scsi_vendor}
scsi_product = {scsi_product}
scsi_revision = {scsi_revision}

[commands.read-controller-id]
cdb_hex = "REPLACE_WITH_FIXED_READ_ONLY_CDB_HEX"
direction = "from-device"
transfer_bytes = 0
timeout_ms = 10000

[commands.read-controller-id.response]
min_bytes = 0
max_bytes = 0
prefix_hex = "REPLACE_WITH_RESPONSE_SIGNATURE_HEX"
payload_offset = 0
payload_bytes = 0

[commands.read-nand-id]
cdb_hex = "REPLACE_WITH_FIXED_READ_ONLY_CDB_HEX"
direction = "from-device"
transfer_bytes = 0
timeout_ms = 10000

[commands.read-nand-id.response]
min_bytes = 0
max_bytes = 0
prefix_hex = "REPLACE_WITH_RESPONSE_SIGNATURE_HEX"
payload_offset = 0
payload_bytes = 0
"#,
        id = toml_string(&format!("{controller}-probe")),
        family = toml_string(family),
        controller = toml_string(controller),
        firmware = toml_string(firmware),
        nand_id = toml_string(&nand_id),
    ))
}

fn usb_probe_value(value: &str, field: &str) -> Result<u16> {
    let digits = value.trim().trim_start_matches("0x").replace('.', "");
    if digits.is_empty() || !digits.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Invalid(format!(
            "device USB {field} is not hexadecimal"
        )));
    }
    u16::from_str_radix(&digits, 16)
        .map_err(|_| Error::Invalid(format!("device USB {field} exceeds u16")))
}

fn observed_probe_bootstrap(
    identity: &nclr::device::DeviceIdentity,
) -> Result<nclr::controller_probe::ObservedBootstrap<'_>> {
    let usb = identity.usb.as_ref().ok_or_else(|| {
        Error::Unsupported("read-only controller probes require USB mass storage".into())
    })?;
    let scsi = identity.scsi.as_ref().ok_or_else(|| {
        Error::Invalid("device identity lacks an exact SCSI INQUIRY tuple".into())
    })?;
    if scsi.vendor.is_empty() || scsi.model.is_empty() || scsi.rev.is_empty() {
        return Err(Error::Invalid(
            "device identity has an incomplete SCSI INQUIRY tuple".into(),
        ));
    }
    Ok(nclr::controller_probe::ObservedBootstrap {
        usb_vid: usb_probe_value(&usb.vid, "VID")?,
        usb_pid: usb_probe_value(&usb.pid, "PID")?,
        usb_bcd_device: usb_probe_value(&usb.bcd_device, "bcdDevice")?,
        usb_manufacturer: &usb.manufacturer,
        usb_product: &usb.product,
        usb_serial: &usb.serial,
        scsi_vendor: &scsi.vendor,
        scsi_product: &scsi.model,
        scsi_revision: &scsi.rev,
    })
}

fn probe_command_summary(
    profile: &nclr::controller_probe::ControllerProbeProfile,
) -> Result<Vec<serde_json::Value>> {
    profile
        .commands
        .iter()
        .map(|(name, command)| {
            let cdb = nclr::controller_recipe::build_cdb(
                command,
                nclr::controller_recipe::CommandContext::default(),
            )?;
            Ok(serde_json::json!({
                "name": name,
                "cdb_hex": hex::encode(cdb),
                "direction": "from-device",
                "transfer_bytes": command.transfer_bytes,
                "timeout_ms": command.timeout_ms,
                "macos_scsi_task_cdb_size": matches!(command.cdb_hex.len() / 2, 6 | 10 | 12 | 16),
            }))
        })
        .collect()
}

fn run_probe(
    file: &std::path::Path,
    device: &str,
    execute: bool,
    confirm_research_device: bool,
) -> Result<String> {
    let profile = nclr::controller_probe::load(file)?;
    let identity = nclr::device::identify(device)?;
    nclr::safety::deep_probe(&identity)?;
    if !identity.removable {
        return Err(Error::Permission(
            "read-only controller probe target is not removable".into(),
        ));
    }
    let observed = observed_probe_bootstrap(&identity)?;
    if !profile.matches(&observed) {
        return Err(Error::Permission(format!(
            "probe profile {} does not match the exact USB/SCSI tuple of {device}",
            profile.id
        )));
    }
    let family = profile.family_value()?;
    let identify_profiles = nclr::profile::load_identify_profiles(&[]);
    if nclr::profile::family_hint_from_vid(observed.usb_vid, &identify_profiles)
        .is_some_and(|hint| hint != family)
    {
        return Err(Error::Permission(format!(
            "probe profile {} family conflicts with the package USB vendor-id hint",
            profile.id
        )));
    }
    let commands = probe_command_summary(&profile)?;
    if !execute {
        return serde_json::to_string_pretty(&serde_json::json!({
            "ok": true,
            "executed": false,
            "device": device,
            "probe_profile": profile.id,
            "probe_profile_sha256": profile.source_sha256,
            "exact_bootstrap_match": true,
            "commands": commands,
            "read_only": true,
            "destructive_allowed": false,
        }))
        .map_err(|error| Error::Invalid(format!("serialize probe dry run: {error}")));
    }
    if !confirm_research_device {
        return Err(Error::Permission(
            "probe execution requires --confirm-research-device".into(),
        ));
    }
    nclr::safety::preflight_read(&identity, &nclr::safety::SafetyOptions::default())?;

    #[cfg(target_os = "macos")]
    let detected = {
        let mut transport = nclr::macos_scsi::ScsiDevice::open(device)?;
        let operation =
            nclr::controller_probe::execute_with(&profile, |_, cdb, length, timeout_ms| {
                transport.read_exact(cdb, length, timeout_ms)
            });
        let cleanup = transport.close();
        match (operation, cleanup) {
            (Ok(identity), Ok(())) => identity,
            (Err(error), Ok(())) => return Err(error),
            (Ok(_), Err(error)) => return Err(error),
            (Err(operation), Err(cleanup)) => {
                return Err(Error::Backend(format!(
                    "read-only controller probe failed: {operation}; cleanup also failed: {cleanup}"
                )));
            }
        }
    };
    #[cfg(not(target_os = "macos"))]
    return Err(Error::Unsupported(
        "nclr-lab probe run execution currently requires macOS SCSITask".into(),
    ));

    #[cfg(target_os = "macos")]
    serde_json::to_string_pretty(&serde_json::json!({
        "ok": true,
        "executed": true,
        "device": device,
        "probe_profile": profile.id,
        "probe_profile_sha256": profile.source_sha256,
        "exact_bootstrap_match": true,
        "family": detected.family.as_str(),
        "controller_id": detected.controller_id,
        "firmware": detected.firmware,
        "nand_id": detected.nand_id,
        "commands": commands,
        "read_only": true,
        "destructive_allowed": false,
    }))
    .map_err(|error| Error::Invalid(format!("serialize probe result: {error}")))
}

fn cmd_probe(args: &ProbeArgs) -> i32 {
    let result = (|| -> Result<String> {
        match &args.cmd {
            ProbeCmd::Check { file } => {
                let profile = nclr::controller_probe::load(file)?;
                let rendered = serde_json::to_string_pretty(&serde_json::json!({
                    "ok": true,
                    "id": profile.id,
                    "family": profile.family,
                    "controller_id": profile.controller_id,
                    "firmware": profile.firmware,
                    "nand_id": profile.nand_id,
                    "source_sha256": profile.source_sha256,
                    "commands": profile.commands.keys().collect::<Vec<_>>(),
                    "read_only": true,
                    "destructive_allowed": false,
                }))
                .map_err(|error| Error::Invalid(format!("serialize probe result: {error}")))?;
                Ok(rendered)
            }
            ProbeCmd::New {
                info,
                family,
                controller,
                firmware,
                nand_id,
                out,
            } => {
                let rendered = new_probe_template(info, family, controller, firmware, nand_id)?;
                if let Some(path) = out {
                    write_new_text(path, &rendered, "probe template")?;
                    Ok(format!("wrote {}", path.display()))
                } else {
                    Ok(rendered)
                }
            }
            ProbeCmd::Run {
                file,
                device,
                execute,
                confirm_research_device,
            } => run_probe(file, device, *execute, *confirm_research_device),
        }
    })();
    match result {
        Ok(rendered) => {
            print!("{rendered}");
            if !rendered.ends_with('\n') {
                println!();
            }
            0
        }
        Err(error) => {
            eprintln!("nclr-lab: {error}");
            error.exit_code()
        }
    }
}

// ---------------------------------------------------------------------------
// profile
// ---------------------------------------------------------------------------

const TEMPLATE: &str = r#"# nclr controller profile template.
# Fill in the identification ranges and trust state. Never add D1-D4 from a
# vendor data sheet or successful command alone: destructive execution needs
# exact hardware identity, compiled driver support and independent HIL evidence.
schema = 1
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
protected_area_bytes = 0
capacity = { bin_bytes = 0, minimum_spare_blocks = 4, spare_ratio = 0.05 }
ecc = { strength = 40, min_margin = 8, max_read_retry = 4, max_read_latency_ms = 200 }
recovery = { method = "service-mode-exit+reset", timeout_ms = 30000 }
logical_blank_value = 255
sd_vendor = { read_only_health = false, cmd56_arg = 0, block_len = 0 }
# Real trust = "validated" pre-HIL profiles require exact min=max identity,
# pinned static executable or trace evidence, a runtime recipe and the following fields. Production
# additionally requires the independent qualification-report attachment:
# implementation = { strategy = "clean-room", protocol_evidence_sha256 = "...", source_reference = "https://...", artifact_ids = ["protocol-recipe"] }
# For families without a fixed signed probe, copy every exact value from
# `nclr info -j` -> controller_identify.controller_research.exact_bootstrap_observed.
# Empty USB descriptor strings are exact empty values, never wildcards.
# controller_bootstrap = { family = "{family}", usb_vid = 0x0000, usb_pid = 0x0000, usb_bcd_device = 0x0000, usb_manufacturer = "", usb_product = "", usb_serial = "", scsi_vendor = "...", scsi_product = "...", scsi_revision = "..." }
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
                let mut verified_artifacts = 0usize;
                if args.pre_hil {
                    match nclr::profile::validate_pre_hil_artifacts(&p, file, &args.artifact_dirs) {
                        Ok(verified) => verified_artifacts = verified.len(),
                        Err(error) => {
                            eprintln!("nclr-lab: {error}");
                            return error.exit_code();
                        }
                    }
                }
                println!(
                    "ok: {} (controller {}, trust {}, pre_hil_complete={}, artifacts_verified={}, destructive_allowed={})",
                    p.id,
                    p.controller_id,
                    p.trust,
                    args.pre_hil,
                    verified_artifacts,
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
                if let Err(error) = write_new_text(path, &rendered, "profile template") {
                    eprintln!("nclr-lab: {error}");
                    return error.exit_code();
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
                )));
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
// smi-ufdif
// ---------------------------------------------------------------------------

const SMI_PACKAGE_FILE_LIMIT: u64 = 8 * 1024 * 1024;

fn parse_smi_nand_id(value: &str) -> Result<String> {
    let compact = value
        .trim()
        .chars()
        .filter(|character| !matches!(character, ':' | '-' | ' '))
        .collect::<String>()
        .to_ascii_lowercase();
    if compact.len() != 12
        || !compact.as_bytes().iter().all(u8::is_ascii_hexdigit)
        || matches!(compact.as_str(), "000000000000" | "ffffffffffff")
    {
        return Err(Error::Invalid(
            "SMI NAND id must be exactly six non-empty hexadecimal bytes".into(),
        ));
    }
    Ok(compact)
}

fn parse_smi_controller_id(value: &str) -> Result<String> {
    let normalized = value.trim().to_ascii_lowercase();
    let body = normalized
        .strip_prefix("smi-sm")
        .or_else(|| normalized.strip_prefix("sm"))
        .unwrap_or(&normalized);
    if body.len() < 4
        || !body.as_bytes()[..4].iter().all(u8::is_ascii_digit)
        || !body.as_bytes().iter().all(u8::is_ascii_alphanumeric)
    {
        return Err(Error::Invalid(
            "SMI controller must be an exact SMxxxx revision such as SM3281BA".into(),
        ));
    }
    Ok(format!("smi-sm{body}"))
}

fn exact_report_files<'a>(
    report: &'a nclr::vendor_tool::ToolAnalysis,
    predicate: impl Fn(&std::path::Path) -> bool,
    label: &str,
) -> Result<Vec<&'a nclr::vendor_tool::ToolFileAnalysis>> {
    let files = report
        .files
        .iter()
        .filter(|file| predicate(&file.path))
        .collect::<Vec<_>>();
    if files.is_empty() {
        return Err(Error::Invalid(format!(
            "SMI package has no exact {label} file"
        )));
    }
    Ok(files)
}

fn unique_report_file<'a>(
    report: &'a nclr::vendor_tool::ToolAnalysis,
    predicate: impl Fn(&std::path::Path) -> bool,
    label: &str,
) -> Result<&'a nclr::vendor_tool::ToolFileAnalysis> {
    let files = exact_report_files(report, predicate, label)?;
    let digests = files
        .iter()
        .map(|file| (&file.sha256, file.size_bytes))
        .collect::<std::collections::BTreeSet<_>>();
    if digests.len() != 1 {
        return Err(Error::Invalid(format!(
            "SMI package has {} distinct {label} files",
            digests.len()
        )));
    }
    Ok(files[0])
}

fn file_name_eq(path: &std::path::Path, expected: &str) -> bool {
    path.file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case(expected))
}

fn smi_assignment_value<'a>(
    binding: &'a nclr::vendor_tool::ToolNandBinding,
    key_suffix: &str,
) -> Result<Option<&'a str>> {
    let values = binding
        .assignments
        .iter()
        .filter(|assignment| assignment.key_suffix.as_deref() == Some(key_suffix))
        .map(|assignment| assignment.value.as_str())
        .collect::<std::collections::BTreeSet<_>>();
    match values.len() {
        0 => Ok(None),
        1 => Ok(values.iter().next().copied()),
        count => Err(Error::Invalid(format!(
            "SMI FFW binding has {count} distinct {key_suffix} assignments"
        ))),
    }
}

fn resolve_smi_binding_artifact(
    binding: &nclr::vendor_tool::ToolNandBinding,
    key_suffix: &str,
) -> Result<nclr::vendor_tool::ToolResolvedArtifact> {
    let assignments = binding
        .assignments
        .iter()
        .filter(|assignment| assignment.key_suffix.as_deref() == Some(key_suffix))
        .collect::<Vec<_>>();
    if assignments.len() != 1 {
        return Err(Error::Invalid(format!(
            "SMI FFW binding has {} {key_suffix} assignments; exactly one is required",
            assignments.len()
        )));
    }
    let reference = assignments[0].artifact.as_ref().ok_or_else(|| {
        Error::Invalid(format!(
            "SMI FFW {key_suffix} assignment has no resolved artifact"
        ))
    })?;
    if !matches!(reference.resolution, "unique" | "identical-content") {
        return Err(Error::Invalid(format!(
            "SMI FFW {key_suffix} artifact resolves as {}",
            reference.resolution
        )));
    }
    let distinct = reference
        .candidates
        .iter()
        .map(|candidate| (&candidate.sha256, candidate.size_bytes))
        .collect::<std::collections::BTreeSet<_>>();
    if distinct.len() != 1 || reference.candidates.is_empty() {
        return Err(Error::Invalid(format!(
            "SMI FFW {key_suffix} assignment resolves to {} distinct artifacts",
            distinct.len()
        )));
    }
    Ok(reference.candidates[0].clone())
}

#[derive(serde::Serialize)]
struct SmiScriptArtifact {
    role: String,
    declared_stem_prefix: String,
    selection_basis: String,
    path: std::path::PathBuf,
    size_bytes: u64,
    sha256: String,
    resolution: &'static str,
}

fn resolve_smi_script_artifact(
    report: &nclr::vendor_tool::ToolAnalysis,
    stem_prefix: &str,
    role: &str,
    selection_basis: &str,
) -> Result<SmiScriptArtifact> {
    let prefix = stem_prefix.to_ascii_lowercase();
    let candidates = exact_report_files(
        report,
        |path| {
            path.extension()
                .and_then(|value| value.to_str())
                .is_some_and(|value| value.eq_ignore_ascii_case("dll"))
                && path
                    .file_stem()
                    .and_then(|value| value.to_str())
                    .is_some_and(|value| value.to_ascii_lowercase().starts_with(&prefix))
        },
        &format!("script DLL with stem prefix {stem_prefix}"),
    )?;
    let distinct = candidates
        .iter()
        .map(|file| (&file.sha256, file.size_bytes))
        .collect::<std::collections::BTreeSet<_>>();
    if distinct.len() != 1 {
        return Err(Error::Invalid(format!(
            "SMI {role} script prefix {stem_prefix} resolves to {} distinct artifacts",
            distinct.len()
        )));
    }
    Ok(SmiScriptArtifact {
        role: role.to_string(),
        declared_stem_prefix: stem_prefix.to_string(),
        selection_basis: selection_basis.to_string(),
        path: candidates[0].path.clone(),
        size_bytes: candidates[0].size_bytes,
        sha256: candidates[0].sha256.clone(),
        resolution: if candidates.len() == 1 {
            "unique"
        } else {
            "identical-content"
        },
    })
}

fn force_flash_records_for_nand<'a>(
    records: &'a [nclr::smi_ufdif::ForceFlashRecord],
    nand_id: &str,
    model: Option<&str>,
) -> Result<Vec<&'a nclr::smi_ufdif::ForceFlashRecord>> {
    let mut selected = records
        .iter()
        .filter(|record| record.nand_id_hex == nand_id)
        .filter(|record| model.is_none_or(|model| record.model == model))
        .collect::<Vec<_>>();
    selected.sort_by_key(|record| record.source_line);
    if selected.is_empty() {
        return Err(Error::Invalid(format!(
            "SMI ForceFlash has no exact NAND {nand_id}{}",
            model.map_or_else(String::new, |value| format!(" and model {value:?}"))
        )));
    }
    Ok(selected)
}

fn cmd_smi_ufdif(args: &SmiUfdifArgs) -> i32 {
    use sha2::Digest as _;

    let result = (|| -> Result<serde_json::Value> {
        match &args.cmd {
            SmiUfdifCmd::ForceFlash {
                file,
                nand_id,
                model,
            } => {
                let bytes = read_bounded_regular_file(
                    file,
                    SMI_PACKAGE_FILE_LIMIT,
                    "SMI ForceFlash database",
                )?;
                let records = nclr::smi_ufdif::parse_force_flash(&bytes)?;
                let selected = if let Some(nand_id) = nand_id {
                    let nand_id = parse_smi_nand_id(nand_id)?;
                    force_flash_records_for_nand(&records, &nand_id, model.as_deref())?
                        .into_iter()
                        .cloned()
                        .collect::<Vec<_>>()
                } else {
                    records.clone()
                };
                let source_sha256 = hex::encode(sha2::Sha256::digest(&bytes));
                Ok(serde_json::json!({
                    "schema": 1,
                    "source_path": file,
                    "source_sha256": source_sha256,
                    "reviewed_source": source_sha256 == nclr::smi_ufdif::FORCE_FLASH_SOURCE_SHA256,
                    "parameter_layout": "six-byte NAND ID followed by 27 positional hexadecimal fields",
                    "record_count": records.len(),
                    "selected_count": selected.len(),
                    "records": selected,
                    "production_eligible": false,
                }))
            }
            SmiUfdifCmd::MemFile { file } => {
                let bytes =
                    read_bounded_regular_file(file, SMI_PACKAGE_FILE_LIMIT, "SMI memory map")?;
                Ok(
                    serde_json::to_value(nclr::smi_ufdif::raw_research_memory_contract(&bytes)?)
                        .map_err(|error| {
                            Error::Invalid(format!("serialize SMI memory map: {error}"))
                        })?,
                )
            }
            SmiUfdifCmd::PackageTuple {
                package,
                controller,
                nand_id,
                model,
            } => {
                let controller_id = parse_smi_controller_id(controller)?;
                let nand_id = parse_smi_nand_id(nand_id)?;
                let report = nclr::vendor_tool::analyze(
                    package,
                    Some(nclr::controller_protocol::Family::SiliconMotionUfd.as_str()),
                    true,
                )?;
                let bindings = report
                    .nand_binding_records
                    .iter()
                    .filter(|binding| {
                        binding.controller_id == controller_id && binding.nand_id == nand_id
                    })
                    .collect::<Vec<_>>();
                if bindings.len() != 1 {
                    return Err(Error::Invalid(format!(
                        "SMI package resolves controller {controller_id} and NAND {nand_id} to {} FFW bindings; exactly one is required",
                        bindings.len()
                    )));
                }
                let binding = bindings[0];
                if !binding.selection_unambiguous {
                    return Err(Error::Invalid(format!(
                        "SMI FFW binding has conflicting keys: {}",
                        binding.conflicting_key_suffixes.join(", ")
                    )));
                }
                for required in ["isp", "sortingcmd", "geninfocmd", "folder"] {
                    if !binding
                        .assignments
                        .iter()
                        .any(|assignment| assignment.key_suffix.as_deref() == Some(required))
                    {
                        return Err(Error::Invalid(format!(
                            "SMI FFW binding lacks required {required} assignment"
                        )));
                    }
                }
                for assignment in &binding.assignments {
                    if let Some(artifact) = &assignment.artifact {
                        if !matches!(artifact.resolution, "unique" | "identical-content") {
                            return Err(Error::Invalid(format!(
                                "SMI FFW artifact {} resolves as {}",
                                artifact.declared_path, artifact.resolution
                            )));
                        }
                    }
                }

                let force_flash = unique_report_file(
                    &report,
                    |path| {
                        path.file_name()
                            .and_then(|value| value.to_str())
                            .is_some_and(|value| {
                                value.to_ascii_lowercase().starts_with("forceflash-")
                                    && value.to_ascii_lowercase().ends_with(".set")
                            })
                    },
                    "ForceFlash database",
                )?;
                let force_flash_bytes = read_bounded_regular_file(
                    &force_flash.path,
                    SMI_PACKAGE_FILE_LIMIT,
                    "SMI ForceFlash database",
                )?;
                let force_records = nclr::smi_ufdif::parse_force_flash(&force_flash_bytes)?;
                let selected_force_records =
                    force_flash_records_for_nand(&force_records, &nand_id, model.as_deref())?;
                if selected_force_records.len() != 1 {
                    let selectors = selected_force_records
                        .iter()
                        .take(12)
                        .map(|record| record.model.as_str())
                        .collect::<Vec<_>>()
                        .join(" | ");
                    return Err(Error::Invalid(format!(
                        "SMI ForceFlash resolves NAND {nand_id} to {} records ({selectors}); select exactly one with --model",
                        selected_force_records.len()
                    )));
                }

                let mem_file = unique_report_file(
                    &report,
                    |path| file_name_eq(path, "MemFile.ini"),
                    "MemFile.ini",
                )?;
                let mem_bytes = read_bounded_regular_file(
                    &mem_file.path,
                    SMI_PACKAGE_FILE_LIMIT,
                    "SMI memory map",
                )?;
                let memory_contract = nclr::smi_ufdif::raw_research_memory_contract(&mem_bytes)?;

                let ufdif_contracts = report
                    .host_transport_contract_records
                    .iter()
                    .filter(|contract| {
                        contract.source_sha256 == nclr::smi_ufdif::UFDIF_SOURCE_SHA256
                            && file_name_eq(&contract.source_path, "UFDIF.dll")
                    })
                    .collect::<Vec<_>>();
                if ufdif_contracts.len() != 1 {
                    return Err(Error::Invalid(format!(
                        "SMI package has {} reviewed UFDIF transport contracts; exactly one is required",
                        ufdif_contracts.len()
                    )));
                }
                if ufdif_contracts[0].vendor_commands.len()
                    != nclr::smi_ufdif::REVIEWED_UFDIF_COMMAND_COUNT
                {
                    return Err(Error::Invalid(format!(
                        "reviewed SMI UFDIF contract contains {} commands; exactly {} are required",
                        ufdif_contracts[0].vendor_commands.len(),
                        nclr::smi_ufdif::REVIEWED_UFDIF_COMMAND_COUNT
                    )));
                }

                let smimp_tool = unique_report_file(
                    &report,
                    |path| file_name_eq(path, "SMIMPTool32.exe"),
                    "SMIMPTool32.exe",
                )?;
                if smimp_tool.sha256 != nclr::smi_ufdif::SMIMPTOOL32_SOURCE_SHA256 {
                    return Err(Error::Permission(format!(
                        "SMI host SHA-256 {} does not match the reviewed source",
                        smimp_tool.sha256
                    )));
                }

                let selected_force_record = selected_force_records[0];
                let primary_isp = smi_assignment_value(binding, "isp")?.ok_or_else(|| {
                    Error::Invalid("SMI FFW binding lacks a primary ISP assignment".into())
                })?;
                let flash_folder = smi_assignment_value(binding, "folder")?.ok_or_else(|| {
                    Error::Invalid("SMI FFW binding lacks a flash folder assignment".into())
                })?;
                let cell_mode = nclr::smi_ufdif::resolve_cell_mode(
                    primary_isp,
                    flash_folder,
                    selected_force_record.parameters[0],
                )?;
                let default_scripts =
                    nclr::smi_ufdif::default_script_selection(&controller_id, cell_mode)?;
                let explicit_low = smi_assignment_value(binding, "dllheader_lowlevel")?;
                let explicit_high = smi_assignment_value(binding, "dllheader_highlevel")?;
                let (low_prefix, low_basis) = explicit_low.map_or_else(
                    || {
                        (
                            default_scripts.low_level_artifact_stem_prefix.as_str(),
                            "reviewed SMIMPTool32 default branch",
                        )
                    },
                    |value| (value, "exact NAND FFW override"),
                );
                let (high_prefix, high_basis) = explicit_high.map_or_else(
                    || {
                        (
                            default_scripts.high_level_artifact_stem_prefix.as_str(),
                            "reviewed SMIMPTool32 default branch",
                        )
                    },
                    |value| (value, "exact NAND FFW override"),
                );
                let script_artifacts = vec![
                    resolve_smi_script_artifact(
                        &report,
                        low_prefix,
                        "dllheader_lowlevel",
                        low_basis,
                    )?,
                    resolve_smi_script_artifact(
                        &report,
                        high_prefix,
                        "dllheader_highlevel",
                        high_basis,
                    )?,
                ];
                let direct_transport_contract = (script_artifacts[0].sha256
                    == nclr::smi_ufdif::SM3280_LOW_LEVEL_SCRIPT_SOURCE_SHA256)
                    .then(nclr::smi_ufdif::reviewed_direct_transport_contract);
                let info_upload_contract = (script_artifacts[0].sha256
                    == nclr::smi_ufdif::SM3280_LOW_LEVEL_SCRIPT_SOURCE_SHA256)
                    .then(nclr::smi_ufdif::reviewed_info_upload_contract);
                let service_loader_contract = nclr::smi_ufdif::reviewed_service_loader_contract();
                let isp_programming_contract =
                    nclr::smi_ufdif::reviewed_sm3281_isp_programming_contract();
                let reviewed_internal_ic_mapping =
                    match nclr::smi_ufdif::reviewed_32bit_internal_ic_mapping_for_controller(
                        &controller_id,
                    ) {
                        Ok(mapping) => Some(mapping),
                        Err(Error::Unsupported(_)) => None,
                        Err(error) => return Err(error),
                    };
                let reviewed_controller_tuple = if controller_id
                    == nclr::smi_ufdif::SM3281BA_SANDISK_19NM_CONTROLLER_ID
                    && nand_id == nclr::smi_ufdif::SM3281BA_SANDISK_19NM_NAND_ID
                {
                    let contract = nclr::smi_ufdif::reviewed_sm3281ba_sandisk_19nm_contract();
                    let selected_isp_artifact = resolve_smi_binding_artifact(binding, "isp")?;
                    let selected_service_directory = selected_isp_artifact
                        .path
                        .parent()
                        .ok_or_else(|| {
                            Error::Invalid(
                                "SMI selected ISP artifact has no parent directory".into(),
                            )
                        })?
                        .to_path_buf();
                    let mut resolved_artifacts = Vec::with_capacity(contract.artifacts.len());
                    for expected in contract.artifacts.iter().copied() {
                        let (path, size_bytes, sha256) =
                            if matches!(expected.role, "findinfoblock" | "igo2rom") {
                                let file = unique_report_file(
                                    &report,
                                    |path| {
                                        file_name_eq(path, expected.filename)
                                            && path.parent()
                                                == Some(selected_service_directory.as_path())
                                    },
                                    &format!("{} beside the selected ISP", expected.filename),
                                )?;
                                (file.path.clone(), file.size_bytes, file.sha256.clone())
                            } else if expected.role == "isp" {
                                (
                                    selected_isp_artifact.path.clone(),
                                    selected_isp_artifact.size_bytes,
                                    selected_isp_artifact.sha256.clone(),
                                )
                            } else {
                                let artifact =
                                    resolve_smi_binding_artifact(binding, expected.role)?;
                                (artifact.path, artifact.size_bytes, artifact.sha256)
                            };
                        let filename = path
                            .file_name()
                            .and_then(|value| value.to_str())
                            .ok_or_else(|| {
                                Error::Invalid(format!(
                                    "SMI {} artifact path is not valid UTF-8",
                                    expected.role
                                ))
                            })?;
                        nclr::smi_ufdif::authenticate_reviewed_service_artifact(
                            expected, filename, size_bytes, &sha256,
                        )?;
                        let reviewed_load = contract
                            .artifact_loads
                            .iter()
                            .find(|load| load.role == expected.role)
                            .copied();
                        let lowered_load = if let Some(load) = reviewed_load {
                            let bytes = read_bounded_regular_file(
                                &path,
                                expected.size_bytes,
                                &format!("SMI {} service artifact", expected.role),
                            )?;
                            let command = nclr::smi_ufdif::load_reviewed_sm3281ba_service_artifact(
                                expected.role,
                                &bytes,
                            )?;
                            Some(serde_json::json!({
                                "contract": load,
                                "cdb_hex": hex::encode(command.cdb),
                                "transfer_bytes": command.data.len(),
                                "authenticated_and_lowered": true,
                            }))
                        } else {
                            None
                        };
                        resolved_artifacts.push(serde_json::json!({
                            "role": expected.role,
                            "path": path,
                            "size_bytes": size_bytes,
                            "sha256": sha256,
                            "authenticated": true,
                            "host_load": lowered_load,
                        }));
                    }
                    Some(serde_json::json!({
                        "contract": contract,
                        "resolved_artifacts": resolved_artifacts,
                    }))
                } else {
                    None
                };
                let force_flash_layout = nclr::smi_ufdif::force_flash_layout_contract();
                let encoded_force_flash = nclr::smi_ufdif::encode_force_flash_parameters(
                    &selected_force_record.parameters,
                );
                let mut unresolved_static_requirements = vec![
                    "recover the exact ForceFlash-to-Iinfo offsets and controller-side semantics of the seven type fields and twenty setting fields; the host layout and Iinfo upload are separate authenticated stages",
                    "decode raw page/OOB partitioning and F4/33 ECC values for the selected NAND geometry",
                    "decode status, retired-block, BBT and FTL metadata response layouts",
                    "recover the controller/NAND-specific ISP modification fields and page-address list; the exact system-block discovery, erase, F1/01 page-program and F0/01 verification command constructors are represented separately",
                ];
                if direct_transport_contract.is_none() {
                    unresolved_static_requirements.push(
                        "recover and authenticate the raw page data-return path in the selected low-level script",
                    );
                }
                if info_upload_contract.is_none() {
                    unresolved_static_requirements.push(
                        "recover and authenticate the Iinfo-to-UFDIF SetInfo path in the selected low-level script",
                    );
                }
                if reviewed_controller_tuple.is_none() {
                    unresolved_static_requirements.push(
                        "authenticate the exact ISP, sorting, generic-info and find-info service artifacts for this controller/NAND tuple",
                    );
                }
                let internal_ic_mapping_statically_proven = reviewed_internal_ic_mapping.is_some();

                Ok(serde_json::json!({
                    "schema": 5,
                    "family": nclr::controller_protocol::Family::SiliconMotionUfd.as_str(),
                    "controller_id": controller_id,
                    "nand_id": nand_id,
                    "cell_mode": cell_mode,
                    "ffw_binding": binding,
                    "force_flash_database": {
                        "path": force_flash.path,
                        "size_bytes": force_flash.size_bytes,
                        "sha256": force_flash.sha256,
                        "reviewed_source": force_flash.sha256 == nclr::smi_ufdif::FORCE_FLASH_SOURCE_SHA256,
                        "record": selected_force_record,
                        "host_layout": force_flash_layout,
                        "encoded_host_fields": encoded_force_flash,
                    },
                    "memory_contract": memory_contract,
                    "script_selection_contract": {
                        "host_path": smimp_tool.path,
                        "host_size_bytes": smimp_tool.size_bytes,
                        "host_sha256": smimp_tool.sha256,
                        "reviewed_default": default_scripts,
                    },
                    "script_artifacts": script_artifacts,
                    "ufdif_transport_contract": ufdif_contracts[0],
                    "info_upload_contract": info_upload_contract,
                    "service_loader_contract": service_loader_contract,
                    "isp_programming_contract": isp_programming_contract,
                    "reviewed_internal_ic_mapping": reviewed_internal_ic_mapping,
                    "reviewed_32bit_internal_ic_mappings": nclr::smi_ufdif::reviewed_32bit_internal_ic_mappings(),
                    "reviewed_controller_tuple": reviewed_controller_tuple,
                    "direct_transport_contract": direct_transport_contract,
                    "raw_page_data_return_statically_proven": direct_transport_contract.is_some(),
                    "host_info_upload_statically_proven": info_upload_contract.is_some(),
                    "service_host_command_constructors_statically_proven": true,
                    "isp_programming_command_constructors_statically_proven": true,
                    "reviewed_tuple_artifacts_authenticated": reviewed_controller_tuple.is_some(),
                    "internal_ic_mapping_statically_proven": internal_ic_mapping_statically_proven,
                    "reviewed_32bit_service_controller_count": nclr::smi_ufdif::SMIMP_REVIEWED_32BIT_INTERNAL_IC_COUNT,
                    "reviewed_service_artifact_load_count": reviewed_controller_tuple
                        .as_ref()
                        .map_or(0, |_| 4),
                    "static_contract_complete": false,
                    "unresolved_static_requirements": unresolved_static_requirements,
                    "hil_required_after_static_completion": true,
                    "production_eligible": false,
                }))
            }
        }
    })();
    match result {
        Ok(value) => match serde_json::to_string_pretty(&value) {
            Ok(rendered) => {
                println!("{rendered}");
                0
            }
            Err(error) => {
                eprintln!("nclr-lab: SMI result serialization failed: {error}");
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
// tool
// ---------------------------------------------------------------------------

fn cmd_tool(args: &ToolArgs) -> i32 {
    match nclr::vendor_tool::analyze(&args.path, args.family.as_deref(), args.include_unmatched) {
        Ok(report) => match serde_json::to_string_pretty(&report) {
            Ok(rendered) => {
                println!("{rendered}");
                0
            }
            Err(error) => {
                eprintln!("nclr-lab: tool result serialization failed: {error}");
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
        println!(
            "dry-run: {} records; use --execute with --confirm-sacrificial to send read-only commands",
            trace.len()
        );
    } else if !args.confirm_sacrificial {
        eprintln!(
            "nclr-lab: refusing to execute: this is a sacrificial test device? pass --confirm-sacrificial"
        );
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
    match nclr::scsi::sg::exec_len(&file, &cdb, direction, &mut buf, 60_000) {
        Ok(transferred) => format!("ok ({transferred} bytes)"),
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

    #[test]
    fn probe_template_preserves_the_exact_info_tuple() {
        let directory = tempfile::tempdir().unwrap();
        let info = directory.path().join("controller-info.json");
        std::fs::write(
            &info,
            serde_json::to_vec(&serde_json::json!({
                "controller_identify": {
                    "controller_research": {
                        "exact_bootstrap_observed": {
                            "usb_vid": "0781",
                            "usb_pid": "5406",
                            "usb_bcd_device": "01.26",
                            "usb_manufacturer": "SanDisk Corporation",
                            "usb_product": "U3 Cruzer Micro",
                            "usb_serial": "EXACT-SERIAL",
                            "scsi_vendor": "SanDisk",
                            "scsi_product": "U3 Cruzer Micro",
                            "scsi_revision": "3.21"
                        }
                    }
                }
            }))
            .unwrap(),
        )
        .unwrap();
        let rendered = new_probe_template(
            &info,
            "sandisk-cruzer",
            "sandisk-82-00263-1",
            "3.21",
            "45c798b2",
        )
        .unwrap();
        let parsed: toml::Value = toml::from_str(&rendered).unwrap();
        let bootstrap = &parsed["bootstrap"];
        assert_eq!(bootstrap["usb_vid"].as_integer(), Some(0x0781));
        assert_eq!(bootstrap["usb_pid"].as_integer(), Some(0x5406));
        assert_eq!(bootstrap["usb_bcd_device"].as_integer(), Some(0x0126));
        assert_eq!(bootstrap["usb_serial"].as_str(), Some("EXACT-SERIAL"));
        assert_eq!(parsed["controller_id"].as_str(), Some("sandisk-82-00263-1"));
        assert!(rendered.contains("This file never authorizes purge"));
    }

    #[test]
    fn generated_templates_never_overwrite_existing_files() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("probe.toml");
        write_new_text(&path, "first", "probe template").unwrap();
        assert!(write_new_text(&path, "second", "probe template").is_err());
        assert_eq!(std::fs::read_to_string(path).unwrap(), "first");
    }
}
