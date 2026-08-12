//! Acceptance suite: a structured, item-by-item verification record.
//! Each test documents one acceptance item; green = acceptance evidence.
//!
//! Most scenarios spawn the real binaries against sim images (no root).

use nclr::grade::{compute_controller_c3, CGrade, ControllerReinitEvidence};
use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

fn nclr() -> PathBuf {
    static NCLR: OnceLock<PathBuf> = OnceLock::new();
    NCLR.get_or_init(|| {
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "nclr-core", "--bin", "nclr"])
            .current_dir(&workspace)
            .status()
            .expect("build nclr test binary");
        assert!(status.success(), "build nclr test binary");
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| workspace.join("target"));
        target.join("debug/nclr")
    })
    .clone()
}

fn backend_dir() -> PathBuf {
    Path::new(env!("CARGO_BIN_EXE_nclr-sim"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn state_home() -> &'static PathBuf {
    static STATE_HOME: OnceLock<PathBuf> = OnceLock::new();
    STATE_HOME.get_or_init(|| {
        let path =
            std::env::temp_dir().join(format!("nclr-acceptance-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create acceptance state home");
        path
    })
}

fn run_nclr(args: &[&str], envs: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(nclr());
    cmd.args(args)
        .env("NCLR_BACKEND_DIR", backend_dir())
        .env(
            "NCLR_PROFILE_DIR",
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../profiles"),
        )
        .env("XDG_STATE_HOME", state_home())
        .env_remove("NCLR_TEST_HOOKS")
        .env_remove("NCLR_TEST_STOP_AFTER");
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let out = cmd.output().expect("spawn nclr");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn make_sim(path: &Path, extra: &[&str]) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nclr-sim"));
    cmd.arg("init").arg("--out").arg(path);
    cmd.args(extra);
    assert!(cmd.status().expect("spawn nclr-sim init").success());
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nclr-acc-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn json_of(s: &str) -> Value {
    serde_json::from_str(s).expect("expected JSON on stdout")
}

// ---------------------------------------------------------------------------
// core
// ---------------------------------------------------------------------------

/// no daemon, no API, no internal DB. Read-only commands must
/// not create sockets or persistent state.
#[test]
fn core_01_no_daemon_no_api_no_db() {
    let dir = tmpdir("c01");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "acc-c01"]);
    let state_home = dir.join("state");
    std::fs::create_dir_all(&state_home).unwrap();
    let before: Vec<String> = walk(&state_home);
    for args in [
        vec!["ls", "-j"],
        vec!["info", "-j", img.to_str().unwrap()],
        vec!["plan", "-l", "best", img.to_str().unwrap()],
        vec!["check", "-j", img.to_str().unwrap()],
    ] {
        let (rc, _, _) = run_nclr(&args, &[("XDG_STATE_HOME", state_home.to_str().unwrap())]);
        assert_eq!(rc, 0);
    }
    let after: Vec<String> = walk(&state_home);
    assert_eq!(before, after, "read-only commands must not create state");
}

/// `info -j` reports the device identity, the matched backend probe and the
/// best-effort controller identification (null for non-USB targets like the
/// sim file; a structured object for USB mass storage devices).
#[test]
fn core_06_info_reports_controller_identify_field() {
    let dir = tmpdir("c06");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "acc-c06"]);
    let (rc, out, err) = run_nclr(&["info", "-j", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0, "info failed: {err}");
    let v = json_of(&out);
    assert_eq!(v["identity"]["schema"], "nclr.device.v1");
    assert!(v["identity"].is_object(), "identity object missing");
    assert!(v["backend_probe"].is_object(), "backend_probe missing");
    // A regular file is not a USB device: no controller family can be
    // selected, so the field is present and null.
    assert!(
        v.get("controller_identify").is_some(),
        "controller_identify field must be present"
    );
    assert!(
        v["controller_identify"].is_null(),
        "controller_identify must be null for non-USB targets"
    );
}

/// The marker parser for the USBest UT163 INQUIRY signature is validated
/// against the byte layout measured on the Imation Flash Drive Mini
/// ("UtffU163A1BM" in the vendor-specific area past the standard 36 bytes).
#[test]
fn core_08_ut163_inquiry_marker_parser() {
    use nclr::controller_protocol::parse_inquiry_marker;
    use nclr::profile::InquiryMarkerIdentify;
    let marker = InquiryMarkerIdentify {
        marker: "U163".into(),
        alloc_len: 96,
        standard_len: 36,
    };
    let mut inquiry = vec![0u8; 96];
    inquiry[8..16].copy_from_slice(b"Imation ");
    inquiry[16..32].copy_from_slice(b"Flash Drive     ");
    inquiry[32..36].copy_from_slice(b"1.00");
    inquiry[36..48].copy_from_slice(b"UtffU163A1BM");
    let identity = parse_inquiry_marker(&inquiry, &marker).expect("UT163 marker must parse");
    assert_eq!(identity.controller_id, "usbest-ut163");
    assert_eq!(identity.firmware, "1.00");

    // A generic device without the vendor marker must not match.
    let mut generic = vec![0u8; 96];
    generic[8..16].copy_from_slice(b"Generic ");
    generic[16..32].copy_from_slice(b"USB Flash Disk  ");
    generic[32..36].copy_from_slice(b"8.07");
    assert!(parse_inquiry_marker(&generic, &marker).is_err());
}

fn walk(dir: &Path) -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(rd) = std::fs::read_dir(dir) {
        for e in rd.flatten() {
            out.push(e.path().display().to_string());
        }
    }
    out.sort();
    out
}

/// one medium per process.
#[test]
fn core_02_one_media_per_process() {
    let (rc, _, err) = run_nclr(&["run", "/dev/a", "/dev/b"], &[]);
    assert_eq!(rc, 64, "multiple device arguments must be a usage error");
    assert!(
        err.contains("unexpected argument"),
        "unexpected error: {err}"
    );
}

/// plan/run fingerprint re-verification.
#[test]
fn core_04_fingerprint_recheck() {
    let dir = tmpdir("c04");
    let a = dir.join("a.img");
    let b = dir.join("b.img");
    let plan_path = dir.join("plan.json");
    std::fs::write(&a, vec![0u8; 65536]).unwrap();
    std::fs::write(&b, vec![0xFFu8; 65536]).unwrap();
    let (rc, plan, _) = run_nclr(&["plan", "-l", "best", a.to_str().unwrap()], &[]);
    assert_eq!(rc, 0);
    std::fs::write(&plan_path, &plan).unwrap();
    let (rc, _, err) = run_nclr(
        &[
            "run",
            "--plan",
            plan_path.to_str().unwrap(),
            b.to_str().unwrap(),
            "--yes",
        ],
        &[],
    );
    assert_eq!(rc, 77);
    assert!(err.contains("fingerprint mismatch"));
}

/// stdout/stderr/events-fd separation.
#[test]
fn core_06_stream_separation() {
    let dir = tmpdir("c06");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "acc-c06"]);
    let ev = dir.join("events.ndjson");
    let f = std::fs::File::create(&ev).unwrap();
    use std::os::fd::IntoRawFd;
    let fd = f.into_raw_fd();
    let mut cmd = Command::new(nclr());
    cmd.args([
        "run",
        "-l",
        "best",
        img.to_str().unwrap(),
        "--yes",
        "-j",
        "--events-fd",
        &fd.to_string(),
    ])
    .env("NCLR_BACKEND_DIR", backend_dir())
    .env(
        "NCLR_PROFILE_DIR",
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../profiles"),
    )
    .env("XDG_STATE_HOME", dir.join("state"))
    .env_remove("NCLR_TEST_HOOKS")
    .env_remove("NCLR_TEST_STOP_AFTER");
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    // stdout carries only the final report JSON.
    let report: Value = serde_json::from_slice(&out.stdout).expect("stdout must be pure JSON");
    assert_eq!(report["result"], "ok");
    // events fd is NDJSON, separate from stdout.
    let events = std::fs::read_to_string(&ev).unwrap();
    let first: Value = serde_json::from_str(events.lines().next().unwrap()).unwrap();
    assert_eq!(first["phase"], "action");
}

/// append-only journal resume after interruption.
#[test]
fn core_07_journal_resume() {
    let dir = tmpdir("c07");
    let img = dir.join("sim.img");
    let state = dir.join("sim.state");
    make_sim(&img, &["--id", "acc-c07"]);
    let (rc, _, _) = run_nclr(
        &[
            "run",
            "-l",
            "lba",
            img.to_str().unwrap(),
            "--yes",
            "--state",
            state.to_str().unwrap(),
        ],
        &[
            ("NCLR_TEST_HOOKS", "1"),
            ("NCLR_TEST_STOP_AFTER", "lba-prbs-write"),
        ],
    );
    assert_eq!(rc, 75, "interrupted exit expected");
    let (rc, report, _) = run_nclr(&["resume", state.to_str().unwrap(), "--yes", "-j"], &[]);
    assert_eq!(rc, 0);
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "ok");
}

/// backend short-lived exec with pre-opened FDs.
#[test]
fn core_08_short_lived_exec_with_fds() {
    let dir = tmpdir("c08");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "acc-c08"]);
    // A successful run requires the backend to work purely on the inherited
    // device fd (the sim image path is never handed to the backend).
    let (rc, report, _) = run_nclr(
        &["run", "-l", "best", img.to_str().unwrap(), "--yes", "-j"],
        &[],
    );
    assert_eq!(rc, 0);
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "ok");
}

/// C grade, residual and H grade computed independently.
#[test]
fn core_09_grades_are_independent() {
    // C grade, residual and H are separate fields driven by separate
    // evidence (unit-level demonstration).
    let e = ControllerReinitEvidence {
        old_bbt_captured: true,
        old_rbb_erase_attempted: true,
        old_rbb_erase_failed: 1, // residual erase-failed
        fbb_preserved: true,
        new_bbt_committed: true,
        ftl_rebuilt: true,
        capacity_stable: true,
        spare_ok: true,
        weak_isolated: true,
        isolated_blocks: 0,
        power_cycled: true,
        io_errors: 0,
        expected_capacity_bytes: Some(221184),
        final_erase_failed: 0,
        old_bbt_generation: Some(1),
        new_bbt_generation: Some(2),
        new_ftl_generation: Some(2),
        fbb_count: Some(2),
        rbb_count: Some(3),
        old_rbb_erased: 3,
        throughput_mbps: None,
        flush_latency_ms: None,
    };
    let g = compute_controller_c3(&e);
    assert_eq!(g.grade, CGrade::C3);
    assert!(g.qualified);
    assert_eq!(g.residual.as_str(), "erase-failed");
}

/// no filesystem is created; final state is raw-uninitialized.
#[test]
fn core_10_no_filesystem_created() {
    let dir = tmpdir("c10");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "acc-c10"]);
    let (rc, report, _) = run_nclr(
        &["run", "-l", "best", img.to_str().unwrap(), "--yes", "-j"],
        &[],
    );
    assert_eq!(rc, 0);
    let r: Value = json_of(&report);
    assert_eq!(r["final_state"], "raw-uninitialized");
    // No MBR/GPT/FAT signatures anywhere on the media.
    let data = std::fs::read(&img).unwrap();
    let found = nclr_lba_signatures(&data);
    assert!(
        found.is_empty(),
        "filesystem signatures must not exist: {found:?}"
    );
}

fn nclr_lba_signatures(data: &[u8]) -> Vec<String> {
    // Minimal signature scan over the whole logical space (device files).
    let mut out = Vec::new();
    if data.len() >= 512 && data[510] == 0x55 && data[511] == 0xAA {
        out.push("MBR-boot-signature".into());
    }
    for (pat, name) in [
        (b"EFI PART", "GPT"),
        (b"EXFAT   ", "exFAT"),
        (b"FAT12   ", "FAT12"),
        (b"FAT16   ", "FAT16"),
        (b"FAT32   ", "FAT32"),
    ] {
        if data.windows(pat.len()).any(|w| w == pat) {
            out.push(name.into());
        }
    }
    out
}

/// sim backend fault injections complete without panics and
/// produce degraded/failed outcomes (never success).
#[test]
fn core_11_sim_fault_injection() {
    // Each injection is exercised on the path that uses it, and the outcome
    // must be the honest one (never an unsupported claim of success).
    let cases: &[(&[&str], &str, i32, &str)] = &[
        // read failure on the LBA path: verification breaks -> degraded
        (&["--fail-read", "0"], "lba", 1, "degraded"),
        // erase failure: per-block residual -> degraded erase-failed
        (&["--fail-erase", "10"], "best", 1, "degraded"),
        // self-running sanitize fails: documented fallback to L1
        (&["--sanitize-fail"], "device", 1, "degraded"),
        // FTL commit failure leaves controller metadata uncommitted. A lower
        // level fallback cannot make that state safe, so this is a hard I/O
        // failure rather than a degraded success.
        (&["--fail-ftl-commit"], "best", 74, "failed"),
        // unresolvable reservation: unknown-scope residual
        (&["--unknown-reservation", "40"], "best", 1, "degraded"),
        // capacity alias: capacity unstable across the power cycle -> H0
        (&["--capacity-alias"], "lba", 1, "degraded"),
    ];
    for (i, (flags, level, expected_rc, expected_result)) in cases.iter().enumerate() {
        let dir = tmpdir(&format!("c11-{i}"));
        let img = dir.join("sim.img");
        make_sim(&img, flags);
        let (rc, report, _) = run_nclr(
            &["run", "-l", level, img.to_str().unwrap(), "--yes", "-j"],
            &[],
        );
        assert_eq!(rc, *expected_rc, "case {flags:?}");
        let r: Value = json_of(&report);
        assert_eq!(
            r["result"].as_str().unwrap(),
            *expected_result,
            "case {flags:?}"
        );
        assert!(r["report_hash"].as_str().is_some());
    }
}

// ---------------------------------------------------------------------------
// standard backends
// ---------------------------------------------------------------------------

/// discard alone must not grant C2 or above.
#[test]
fn standard_discard_never_c2() {
    // The lba backend ceiling is C1; a device with only UNMAP never plans C2.
    let dir = tmpdir("s1");
    let img = dir.join("plain.img");
    std::fs::write(&img, vec![0u8; 65536]).unwrap();
    let (rc, plan, _) = run_nclr(&["plan", "-l", "best", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0);
    let p: Value = json_of(&plan);
    assert_eq!(p["expected_grade"], "C1");
    // Grade-level rule: discard-only evidence is rejected.
    let e = nclr::grade::DeviceEraseEvidence {
        erase_completed: true,
        scope_documented: true,
        blank_verify: true,
        signature_free: true,
        power_cycled: true,
        capacity_stable: true,
        discard_only: true,
        io_errors: 0,
    };
    let g = nclr::grade::compute_device_c2(&e);
    assert_ne!(g.grade, CGrade::C2, "discard alone must not grant C2");
}

/// LBA C1 recipe runs over the full capacity and verifies.
#[test]
fn standard_lba_c1_full_capacity() {
    let dir = tmpdir("s2");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "acc-s2"]);
    let (rc, report, _) = run_nclr(
        &["run", "-l", "lba", img.to_str().unwrap(), "--yes", "-j"],
        &[],
    );
    assert_eq!(rc, 0);
    let r: Value = json_of(&report);
    assert_eq!(r["achieved_grade"], "C1");
    assert_eq!(r["grade_qualified"], true);
    assert_eq!(r["postcheck"]["details"]["full_overwrite"], true);
}

// ---------------------------------------------------------------------------
// controller backend
// ---------------------------------------------------------------------------

/// exact profile match required; C3 requires a certified
/// production profile.
#[test]
fn controller_exact_profile_match_required() {
    let dir = tmpdir("k1");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "acc-k1", "--controller-id", "other-ctlr"]);
    let (rc, _, err) = run_nclr(&["plan", "-l", "controller", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 2, "expected unplannable: {err}");
    assert!(err.contains("cannot be planned"));
}

/// old BBT captured before any erase, per-RBB results,
/// weak isolation, new BBT/FTL, capacity stability after power cycle.
#[test]
fn controller_reinit_evidence_chain() {
    let dir = tmpdir("k2");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "acc-k2"]);
    let (rc, report, _) = run_nclr(
        &[
            "run",
            "-l",
            "controller",
            img.to_str().unwrap(),
            "--yes",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 0);
    let r: Value = json_of(&report);
    assert_eq!(r["achieved_grade"], "C3");
    let d = &r["postcheck"]["details"];
    assert_eq!(d["old_bbt_captured"], true);
    assert_eq!(d["old_rbb_erase_attempted"], true);
    assert_eq!(d["fbb_preserved"], true);
    assert_eq!(d["new_bbt_committed"], true);
    assert_eq!(d["ftl_rebuilt"], true);
    assert_eq!(d["capacity_stable"], true);
    assert_eq!(d["power_cycle_performed"], true);
}

/// never returns a grade above its certification.
#[test]
fn controller_grade_ceiling() {
    let dir = tmpdir("k3");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "acc-k3"]);
    // `-l controller` plans C3 (not C4) because physical scope is a separate
    // certification.
    let (rc, plan, err) = run_nclr(&["plan", "-l", "controller", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0, "plan failed: {err}");
    let p: Value = json_of(&plan);
    assert_eq!(p["expected_grade"], "C3");
}
