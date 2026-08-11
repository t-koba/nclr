//! End-to-end tests that spawn the real binaries (sim and lba backends).
//! These run on any Unix (no root required): the target "devices" are files.

use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// The `nclr` CLI binary lives in the nclr-core crate; resolve it from the
/// workspace target directory (CARGO_BIN_EXE_ is only set for same-package
/// bins). Build it once so tests never execute a stale artifact.
fn nclr() -> std::path::PathBuf {
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

fn sim_bin() -> &'static str {
    env!("CARGO_BIN_EXE_nclr-sim")
}

/// Directory containing the backend executables (same build dir).
fn backend_dir() -> PathBuf {
    Path::new(sim_bin()).parent().unwrap().to_path_buf()
}

fn state_home() -> &'static PathBuf {
    static STATE_HOME: OnceLock<PathBuf> = OnceLock::new();
    STATE_HOME.get_or_init(|| {
        let path = std::env::temp_dir().join(format!("nclr-e2e-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir_all(&path).expect("create e2e state home");
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
    let mut cmd = Command::new(sim_bin());
    cmd.arg("init").arg("--out").arg(path);
    cmd.args(extra);
    let st = cmd.status().expect("spawn nclr-sim init");
    assert!(st.success(), "sim init failed");
}

fn json_of(stdout: &str) -> Value {
    serde_json::from_str(stdout).expect("expected JSON on stdout")
}

fn tmpdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nclr-e2e-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn sim_plan_run_ok_c1() {
    let dir = tmpdir("ok");
    let img = dir.join("sim.img");
    let plan_path = dir.join("plan.json");
    make_sim(&img, &["--id", "e2e-ok"]);
    let (rc, plan_json, err) = run_nclr(&["plan", "-l", "lba", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0, "plan failed: {err}");
    std::fs::write(&plan_path, &plan_json).unwrap();
    let plan: Value = json_of(&plan_json);
    assert_eq!(plan["schema"], "nclr.plan.v1");
    assert_eq!(plan["expected_grade"], "C1");
    assert_eq!(plan["backend"]["id"], "sim");

    let (rc, report, err) = run_nclr(
        &[
            "run",
            "--plan",
            plan_path.to_str().unwrap(),
            img.to_str().unwrap(),
            "--yes",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 0, "run failed: {err}");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "ok");
    assert_eq!(r["achieved_grade"], "C1");
    assert_eq!(r["grade_qualified"], true);
    assert_eq!(r["health_grade"], "H2");
    assert_eq!(r["residual"], "none-known");
    assert_eq!(r["final_state"], "raw-uninitialized");
    assert_eq!(r["postcheck"]["passed"], true);
    assert_eq!(r["postcheck"]["power_cycle_performed"], true);
    // Stale MBR signature must be gone.
    assert_eq!(r["postcheck"]["details"]["signature_free"], true);
}

#[test]
fn sim_device_level_ok_c2() {
    let dir = tmpdir("c2");
    let img = dir.join("sim.img");
    let plan_path = dir.join("plan.json");
    make_sim(&img, &["--id", "e2e-c2"]);
    let (rc, plan, err) = run_nclr(&["plan", "-l", "device", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0, "plan failed: {err}");
    std::fs::write(&plan_path, &plan).unwrap();
    let plan: Value = json_of(&std::fs::read_to_string(&plan_path).unwrap());
    assert_eq!(plan["expected_grade"], "C2");
    // The C2 plan never layers LBA overwrites on top of the device erase.
    let ids: Vec<&str> = plan["actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["id"].as_str())
        .collect();
    assert_eq!(
        ids,
        vec![
            "inventory",
            "device-user-area-erase",
            "blank-verify",
            "signature-check",
            "power-cycle",
            "postcheck-p2",
        ]
    );

    let (rc, report, err) = run_nclr(
        &[
            "run",
            "--plan",
            plan_path.to_str().unwrap(),
            img.to_str().unwrap(),
            "--yes",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 0, "run failed: {err}");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "ok");
    assert_eq!(r["achieved_grade"], "C2");
    assert_eq!(r["grade_qualified"], true);
    assert_eq!(r["health_grade"], "H2");
    assert_eq!(r["postcheck"]["recipe"], "P2");
    assert_eq!(r["postcheck"]["passed"], true);
    assert_eq!(r["postcheck"]["power_cycle_performed"], true);
    assert_eq!(r["postcheck"]["details"]["erase_completed"], true);
    // D0-D2 erased per the documented plan scope; D3/D4 unreachable.
    let d0 = r["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["domain"] == "D0")
        .unwrap();
    assert_eq!(d0["final"], "erased");
    let d1 = r["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["domain"] == "D1")
        .unwrap();
    assert_eq!(d1["final"], "erased");
    let d2 = r["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["domain"] == "D2")
        .unwrap();
    assert_eq!(d2["final"], "erased");
    let d3 = r["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["domain"] == "D3")
        .unwrap();
    assert_eq!(d3["final"], "unreachable");
    assert_eq!(r["final_state"], "raw-uninitialized");
}

#[test]
fn sim_lba_does_not_reach_d2_but_device_erase_does() {
    // LBA C1 must not clear the D2/OP region; the device erase must.
    let dir = tmpdir("d2");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-d2"]);
    // Read a physical page outside the LBA window (last block = OP/D2 area).
    let page_bytes = 512usize;
    let read_d2 = |path: &Path| -> Vec<u8> {
        let mut f = std::fs::File::open(path).unwrap();
        use std::io::{Read, Seek, SeekFrom};
        // Sim layout: header 512 + block table (64*8) + 63*8*512 (last block).
        let offset = 512u64 + 64 * 8 + 63 * 8 * page_bytes as u64;
        f.seek(SeekFrom::Start(offset)).unwrap();
        let mut buf = vec![0u8; page_bytes];
        f.read_exact(&mut buf).unwrap();
        buf
    };
    assert_eq!(
        read_d2(&img)[0],
        0x5A,
        "precondition: stale data in D2 region"
    );

    // LBA path: stale data remains.
    let (rc, _, _) = run_nclr(&["run", "-l", "lba", img.to_str().unwrap(), "--yes"], &[]);
    assert_eq!(rc, 0);
    assert_eq!(read_d2(&img)[0], 0x5A, "LBA C1 must not clear D2");

    // Device erase path: D2 is blank.
    let (rc, _, _) = run_nclr(
        &["run", "-l", "device", img.to_str().unwrap(), "--yes"],
        &[],
    );
    assert_eq!(rc, 0);
    let d2 = read_d2(&img);
    assert_eq!(d2[0], 0xFF, "device erase must clear D2");
    assert!(d2.iter().all(|b| *b == 0xFF));
}

#[test]
fn sim_no_sanitize_device_level_unplannable() {
    let dir = tmpdir("nosan");
    let img = dir.join("sim.img");
    make_sim(
        &img,
        &["--id", "e2e-nosan", "--no-sanitize", "--no-controller"],
    );
    // best stays at C1.
    let (rc, plan, _) = run_nclr(&["plan", "-l", "best", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0);
    let plan: Value = json_of(&plan);
    assert_eq!(plan["expected_grade"], "C1");
    // device level is unplannable (exit 2).
    let (rc, _, err) = run_nclr(&["plan", "-l", "device", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 2, "expected unsupported: {err}");
}

#[test]
fn sim_sanitize_failure_falls_back_to_l1() {
    let dir = tmpdir("sanzfail");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-szf", "--sanitize-fail"]);
    // With fallback: degraded C1 (L1 recipe runs).
    let (rc, report, _) = run_nclr(
        &["run", "-l", "device", img.to_str().unwrap(), "--yes", "-j"],
        &[],
    );
    assert_eq!(rc, 1, "expected degraded");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "degraded");
    assert_eq!(r["achieved_grade"], "C1");
    // The L1 fallback recipe itself completed (qualified at C1); degraded
    // because the requested device (C2) minimum level was not met.
    assert_eq!(r["postcheck"]["details"]["min_level_met"], false);
    assert_eq!(r["postcheck"]["details"]["min_level"], "C2");
    // The L1 fallback cleared the LBA space (prbs+zero).
    assert_eq!(r["postcheck"]["details"]["zero_verify"], true);

    // With --no-fallback: the run fails.
    let img2 = dir.join("sim2.img");
    make_sim(&img2, &["--id", "e2e-szf2", "--sanitize-fail"]);
    let (rc, report, _) = run_nclr(
        &[
            "run",
            "-l",
            "device",
            img2.to_str().unwrap(),
            "--yes",
            "--no-fallback",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 74, "expected failure with --no-fallback");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "failed");
}

#[test]
fn resume_after_interruption() {
    let dir = tmpdir("resume");
    let img = dir.join("sim.img");
    let state = dir.join("sim.state");
    make_sim(&img, &["--id", "e2e-resume"]);
    // Stop after the first power cycle (interrupted run, exit 75).
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
            ("NCLR_TEST_STOP_AFTER", "power-cycle"),
        ],
    );
    assert_eq!(rc, 75, "expected interrupted exit");

    // Resume must complete the remaining actions and reach ok/C1.
    let (rc, report, err) = run_nclr(&["resume", state.to_str().unwrap(), "--yes", "-j"], &[]);
    assert_eq!(rc, 0, "resume failed: {err}");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "ok");
    assert_eq!(r["achieved_grade"], "C1");
    assert_eq!(r["grade_qualified"], true);
}

#[test]
fn resume_c2_after_interruption_rebuilds_evidence() {
    let dir = tmpdir("resumec2");
    let img = dir.join("sim.img");
    let state = dir.join("sim.state");
    make_sim(&img, &["--id", "e2e-resumec2"]);
    // Interrupt after the device erase completes (evidence lives in the
    // journal; the resumed run must rebuild it).
    let (rc, _, _) = run_nclr(
        &[
            "run",
            "-l",
            "device",
            img.to_str().unwrap(),
            "--yes",
            "--state",
            state.to_str().unwrap(),
        ],
        &[
            ("NCLR_TEST_HOOKS", "1"),
            ("NCLR_TEST_STOP_AFTER", "device-user-area-erase"),
        ],
    );
    assert_eq!(rc, 75, "expected interrupted exit");

    let (rc, report, err) = run_nclr(&["resume", state.to_str().unwrap(), "--yes", "-j"], &[]);
    assert_eq!(rc, 0, "resume failed: {err}");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "ok");
    assert_eq!(r["achieved_grade"], "C2");
    assert_eq!(r["grade_qualified"], true);
    // Evidence from before the interruption was rebuilt from the journal.
    assert_eq!(r["postcheck"]["details"]["erase_completed"], true);
    assert_eq!(r["postcheck"]["details"]["blank_verify"], true);
}

#[test]
fn sim_plan_run_stdin_plan() {
    let dir = tmpdir("stdin");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-stdin"]);
    let (rc, plan, err) = run_nclr(&["plan", "-l", "lba", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0, "plan failed: {err}");
    // Pipe the plan via stdin (nclr run --plan -).
    let mut cmd = Command::new(nclr());
    cmd.args(["run", "--plan", "-", img.to_str().unwrap(), "--yes", "-j"])
        .env("NCLR_BACKEND_DIR", backend_dir())
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().unwrap();
    use std::io::Write;
    child
        .stdin
        .take()
        .unwrap()
        .write_all(plan.as_bytes())
        .unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(0));
    let r: Value = json_of(&String::from_utf8_lossy(&out.stdout));
    assert_eq!(r["result"], "ok");
}

#[test]
fn fault_injection_is_degraded() {
    let dir = tmpdir("fault");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-fault", "--fail-read", "0"]);
    let (rc, report, _) = run_nclr(
        &["run", "-l", "lba", img.to_str().unwrap(), "--yes", "-j"],
        &[],
    );
    assert_eq!(rc, 1, "expected degraded exit");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "degraded");
    assert_eq!(r["grade_qualified"], false);
    assert_eq!(r["residual"], "erase-failed");
    assert_eq!(r["postcheck"]["passed"], false);
}

#[test]
fn plain_file_without_power_control_is_documented_exclusion() {
    let dir = tmpdir("plain");
    let img = dir.join("plain.img");
    std::fs::write(&img, vec![0u8; 2 * 1024 * 1024]).unwrap();
    let (rc, report, _) = run_nclr(
        &["run", "-l", "best", img.to_str().unwrap(), "--yes", "-j"],
        &[],
    );
    assert_eq!(rc, 1, "expected degraded exit");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "degraded");
    assert_eq!(r["residual"], "documented-exclusion");
    assert_eq!(r["postcheck"]["power_cycle_performed"], false);
}

#[test]
fn plain_file_with_external_power_cycle_is_ok() {
    let dir = tmpdir("plainpc");
    let img = dir.join("plain.img");
    std::fs::write(&img, vec![0u8; 2 * 1024 * 1024]).unwrap();
    let (rc, report, _) = run_nclr(
        &[
            "run",
            "-l",
            "best",
            img.to_str().unwrap(),
            "--yes",
            "--power-cycle",
            "true",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 0, "expected ok");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "ok");
    assert_eq!(r["grade_qualified"], true);
}

#[test]
fn fingerprint_mismatch_is_rejected() {
    let dir = tmpdir("mismatch");
    let a = dir.join("a.img");
    let b = dir.join("b.img");
    let plan_path = dir.join("plan.json");
    std::fs::write(&a, vec![0u8; 1024 * 1024]).unwrap();
    std::fs::write(&b, vec![0xFFu8; 1024 * 1024]).unwrap();
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
    assert_eq!(rc, 77, "expected permission exit: {err}");
    assert!(
        err.contains("fingerprint mismatch"),
        "unexpected error: {err}"
    );
}

/// A regular-file pseudo-device must bind its capacity into the fingerprint.
/// Resizing the same path after planning is an identity change, not a valid
/// way to bypass the plan/run capacity check.
#[test]
fn same_path_capacity_change_is_rejected() {
    let dir = tmpdir("capacity-mismatch");
    let img = dir.join("plain.img");
    let plan_path = dir.join("plain.plan.json");
    std::fs::write(&img, vec![0u8; 1024 * 1024]).unwrap();

    let (rc, plan, err) = run_nclr(&["plan", "-l", "lba", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0, "plan failed: {err}");
    std::fs::write(&plan_path, plan).unwrap();
    std::fs::OpenOptions::new()
        .write(true)
        .open(&img)
        .unwrap()
        .set_len(2 * 1024 * 1024)
        .unwrap();

    let (rc, _, err) = run_nclr(
        &[
            "run",
            "--plan",
            plan_path.to_str().unwrap(),
            img.to_str().unwrap(),
            "--yes",
        ],
        &[],
    );
    assert_eq!(rc, 77, "resized target must be rejected: {err}");
    assert!(err.contains("fingerprint mismatch") || err.contains("capacity changed"));
}

#[test]
fn unsupported_level_exits_2() {
    let dir = tmpdir("unsupported");
    let img = dir.join("plain.img");
    std::fs::write(&img, vec![0u8; 65536]).unwrap();
    let (rc, _, err) = run_nclr(&["plan", "-l", "physical", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 2, "expected unsupported exit: {err}");
    assert!(err.contains("cannot be planned"));
}

#[test]
fn usage_error_exits_64() {
    let (rc, _, err) = run_nclr(&["plan", "-l", "bogus", "/dev/null"], &[]);
    assert_eq!(rc, 64, "expected usage exit: {err}");
}

#[test]
fn missing_device_is_a_usage_error() {
    let dir = tmpdir("missing");
    let img = dir.join("plain.img");
    std::fs::write(&img, vec![0u8; 65536]).unwrap();
    let (rc, _, err) = run_nclr(&["run", "-l", "best", "/nonexistent/x.img", "--yes"], &[]);
    assert_eq!(rc, 64, "expected usage exit: {err}");
    assert!(err.contains("nonexistent"), "unexpected error: {err}");
}

#[test]
fn check_is_read_only_and_ok() {
    let dir = tmpdir("check");
    let img = dir.join("plain.img");
    std::fs::write(&img, vec![0u8; 65536]).unwrap();
    let before = std::fs::read(&img).unwrap();
    let (rc, out, _) = run_nclr(&["check", "-j", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0);
    let v: Value = json_of(&out);
    assert_eq!(v["identity"]["transport"], "file");
    let after = std::fs::read(&img).unwrap();
    assert_eq!(before, after, "check must not modify the media");
}

#[test]
fn events_fd_is_ndjson() {
    let dir = tmpdir("events");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-events"]);
    let events_path = dir.join("events.ndjson");
    let events_file = std::fs::File::create(&events_path).unwrap();
    use std::os::fd::IntoRawFd;
    let fd = events_file.into_raw_fd();
    // Spawn with the events fd handed over without CLOEXEC, like a shell
    // `nclr... 9>file` redirection would.
    let mut cmd = Command::new(nclr());
    cmd.args([
        "run",
        "-l",
        "best",
        img.to_str().unwrap(),
        "--yes",
        "--events-fd",
        &fd.to_string(),
    ])
    .env("NCLR_BACKEND_DIR", backend_dir());
    unsafe {
        use std::os::unix::process::CommandExt;
        cmd.pre_exec(move || {
            if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    let out = cmd.output().expect("spawn nclr");
    assert_eq!(out.status.code(), Some(0));
    let text = std::fs::read_to_string(&events_path).unwrap();
    let lines: Vec<&str> = text.lines().collect();
    assert!(
        lines.len() >= 22,
        "expected per-action events, got {}",
        lines.len()
    );
    let first: Value = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(first["phase"], "action");
}

// ---------------------------------------------------------------------------
// Phase 3: controller reinitialization (C3)
// ---------------------------------------------------------------------------

#[test]
fn sim_controller_level_ok_c3() {
    let dir = tmpdir("c3");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-c3ok"]);
    let (rc, plan, err) = run_nclr(&["plan", "-l", "controller", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0, "plan failed: {err}");
    let plan: Value = json_of(&plan);
    assert_eq!(plan["expected_grade"], "C3");
    assert_eq!(plan["minimum_level"], "C3");
    let ids: Vec<&str> = plan["actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["id"].as_str())
        .collect();
    assert_eq!(
        ids,
        vec![
            "inventory",
            "capture-old-bbt",
            "enter-service-mode",
            "erase-old-rbb",
            "qualify-blocks",
            "final-erase",
            "rebuild-bbt-ftl",
            "exit-service-mode",
            "power-cycle",
            "re-enumeration",
            "postcheck-c3",
        ]
    );

    let (rc, report, err) = run_nclr(
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
    assert_eq!(rc, 0, "run failed: {err}");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "ok");
    assert_eq!(r["achieved_grade"], "C3");
    assert_eq!(r["grade_qualified"], true);
    assert_eq!(r["health_grade"], "H2");
    assert_eq!(r["residual"], "none-known");
    assert_eq!(r["postcheck"]["recipe"], "P2"); // P2 = device/controller rebuild recipe
    assert_eq!(r["postcheck"]["passed"], true);
    let d = &r["postcheck"]["details"];
    assert_eq!(d["old_bbt_captured"], true);
    assert_eq!(d["old_rbb_erase_attempted"], true);
    assert_eq!(d["old_rbb_erase_failed"], 0);
    assert_eq!(d["fbb_preserved"], true);
    assert_eq!(d["new_bbt_committed"], true);
    assert_eq!(d["ftl_rebuilt"], true);
    assert_eq!(d["power_cycle_performed"], true);
    // D4 was rebuilt; D3 per-block erased.
    let d3 = r["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["domain"] == "D3")
        .unwrap();
    assert_eq!(d3["final"], "erased");
    let d4 = r["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["domain"] == "D4")
        .unwrap();
    assert_eq!(d4["final"], "rebuilt");
    assert_eq!(r["final_state"], "raw-uninitialized");
}

#[test]
fn sim_controller_rbb_erase_failure_is_residual() {
    let dir = tmpdir("c3rbb");
    let img = dir.join("sim.img");
    // Old RBB block 10 refuses to erase: documented residual.
    make_sim(&img, &["--id", "e2e-c3rbb", "--fail-erase", "10"]);
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
    assert_eq!(rc, 1, "expected degraded (residual erase-failed)");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "degraded");
    assert_eq!(r["residual"], "erase-failed");
    assert_eq!(r["postcheck"]["details"]["old_rbb_erase_failed"], 1);
    assert_eq!(r["grade_qualified"], true);
}

#[test]
fn sim_controller_ftl_commit_failure_never_falls_back_after_destructive_work() {
    let dir = tmpdir("c3fb");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-c3fb", "--fail-ftl-commit"]);
    // A metadata commit failure leaves controller state that must be
    // recovered. Issuing a different erase path is not a safe fallback.
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
    assert_eq!(rc, 74, "expected a hard controller failure");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "failed");
    assert!(!r["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["id"] == "device-user-area-erase"));

    // With --no-fallback the run fails instead.
    let img2 = dir.join("sim2.img");
    make_sim(&img2, &["--id", "e2e-c3fb2", "--fail-ftl-commit"]);
    let (rc, report, _) = run_nclr(
        &[
            "run",
            "-l",
            "controller",
            img2.to_str().unwrap(),
            "--yes",
            "--no-fallback",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 74, "expected failure with --no-fallback");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "failed");
}

#[test]
fn sim_controller_capacity_reduction_is_documented() {
    let dir = tmpdir("c3cap");
    let img = dir.join("sim.img");
    // ECC-corrupt blocks become weak -> capacity shrinks after the rebuild.
    make_sim(&img, &["--id", "e2e-c3cap", "--ecc-corrupt", "1,3,7"]);
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
    assert_eq!(rc, 1, "expected degraded (H1: weak blocks isolated)");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "degraded");
    assert_eq!(r["health_grade"], "H1");
    assert_eq!(r["achieved_grade"], "C3");
    assert_eq!(r["grade_qualified"], true);
    // The committed capacity is smaller than the nominal 229376 bytes.
    let expected = r["postcheck"]["details"]["expected_capacity_bytes"]
        .as_u64()
        .unwrap();
    assert!(expected < 229376, "capacity must shrink: {expected}");
    let after = r["device_after"]["capacity_bytes"].as_u64().unwrap();
    assert_eq!(after, expected, "device must report the committed capacity");
}

#[test]
fn sim_controller_profile_mismatch_is_unplannable() {
    let dir = tmpdir("c3mm");
    let img = dir.join("sim.img");
    // A controller id outside the profile's range: no exact match.
    make_sim(&img, &["--id", "e2e-c3mm", "--controller-id", "other-ctlr"]);
    let (rc, _, err) = run_nclr(&["plan", "-l", "controller", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 2, "expected unsupported: {err}");
    assert!(err.contains("cannot be planned"), "unexpected error: {err}");
    // best degrades to C2 (device erase still available).
    let (rc, plan, _) = run_nclr(&["plan", "-l", "best", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0);
    let plan: Value = json_of(&plan);
    assert_eq!(plan["expected_grade"], "C2");
}

#[test]
fn sim_controller_resume_rebuilds_evidence() {
    let dir = tmpdir("c3resume");
    let img = dir.join("sim.img");
    let state = dir.join("sim.state");
    make_sim(&img, &["--id", "e2e-c3resume"]);
    // Interrupt after the old-RBB erase: the C3 evidence before that point
    // must be rebuilt from the journal on resume.
    let (rc, _, _) = run_nclr(
        &[
            "run",
            "-l",
            "controller",
            img.to_str().unwrap(),
            "--yes",
            "--state",
            state.to_str().unwrap(),
        ],
        &[
            ("NCLR_TEST_HOOKS", "1"),
            ("NCLR_TEST_STOP_AFTER", "erase-old-rbb"),
        ],
    );
    assert_eq!(rc, 75, "expected interrupted exit");

    let (rc, report, err) = run_nclr(&["resume", state.to_str().unwrap(), "--yes", "-j"], &[]);
    assert_eq!(rc, 0, "resume failed: {err}");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "ok");
    assert_eq!(r["achieved_grade"], "C3");
    assert_eq!(r["grade_qualified"], true);
    assert_eq!(r["postcheck"]["details"]["old_bbt_captured"], true);
    assert_eq!(r["postcheck"]["details"]["old_rbb_erase_attempted"], true);
}

#[test]
fn resume_controller_failure_does_not_switch_erase_methods() {
    // Interrupt after physical writes, then fail the metadata commit. Resume
    // must preserve the controller recovery boundary and never switch to C2.
    let dir = tmpdir("resumefb");
    let img = dir.join("sim.img");
    let state = dir.join("sim.state");
    make_sim(&img, &["--id", "e2e-resumefb", "--fail-ftl-commit"]);
    let (rc, _, _) = run_nclr(
        &[
            "run",
            "-l",
            "controller",
            img.to_str().unwrap(),
            "--yes",
            "--state",
            state.to_str().unwrap(),
        ],
        &[
            ("NCLR_TEST_HOOKS", "1"),
            ("NCLR_TEST_STOP_AFTER", "qualify-blocks"),
        ],
    );
    assert_eq!(rc, 75, "expected interrupted exit");

    let (rc, report, err) = run_nclr(&["resume", state.to_str().unwrap(), "--yes", "-j"], &[]);
    assert_eq!(rc, 74, "expected hard controller failure: {err}");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "failed");
    let ids: Vec<String> = r["actions"]
        .as_array()
        .unwrap()
        .iter()
        .map(|a| a["id"].as_str().unwrap_or("").to_string())
        .collect();
    assert!(!ids.contains(&"device-user-area-erase".to_string()));
    assert!(!ids.contains(&"postcheck-p2".to_string()));
}

// ---------------------------------------------------------------------------
// Phase 4: certified physical scope (C4)
// ---------------------------------------------------------------------------

#[test]
fn sim_physical_level_ok_c4() {
    let dir = tmpdir("c4");
    let img = dir.join("sim.img");
    let ev = dir.join("evidence");
    make_sim(&img, &["--id", "e2e-c4ok"]);
    let (rc, plan, err) = run_nclr(&["plan", "-l", "physical", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0, "plan failed: {err}");
    let plan: Value = json_of(&plan);
    assert_eq!(plan["expected_grade"], "C4");
    let ids: Vec<&str> = plan["actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["id"].as_str())
        .collect();
    assert!(ids.contains(&"enumerate-blocks"));
    assert!(ids.contains(&"erase-data-blocks"));
    assert!(ids.contains(&"verify-physical-erasure"));
    assert!(ids.contains(&"postcheck-c4"));

    let (rc, report, err) = run_nclr(
        &[
            "run",
            "-l",
            "physical",
            img.to_str().unwrap(),
            "--yes",
            "--evidence-dir",
            ev.to_str().unwrap(),
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 0, "run failed: {err}");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "ok");
    assert_eq!(r["achieved_grade"], "C4");
    assert_eq!(r["grade_qualified"], true);
    assert_eq!(r["health_grade"], "H2");
    assert_eq!(r["residual"], "none-known");
    assert_eq!(r["postcheck"]["recipe"], "P1"); // P1 = physical complete test recipe
    let d = &r["postcheck"]["details"];
    assert_eq!(d["enumeration_complete"], true);
    assert_eq!(d["blocks_enumerated"], 62, "64 blocks - 2 FBB");
    assert_eq!(d["blocks_erased"], 62);
    assert_eq!(d["blocks_erase_failed"], 0);
    assert_eq!(d["unknown_reservation"], 0);
    assert_eq!(d["fbb_preserved"], true);
    assert_eq!(d["physical_sweep_complete"], true);
    assert_eq!(d["physical_pages"], 512);
    assert_eq!(d["physical_readable_pages"], 512);
    assert_eq!(d["physical_unreadable_pages"], 0);
    assert_eq!(d["physical_uncorrectable_pages"], 0);
    assert_eq!(d["ordered_sweep_sha256"].as_str().unwrap().len(), 64);
    assert_eq!(d["target_pages"], d["target_readable_pages"]);
    assert_eq!(d["target_unreadable_pages"], 0);
    assert_eq!(d["target_uncorrectable_pages"], 0);
    assert_eq!(d["target_non_erased_pages"], 0);
    // Per-block evidence file written and hashed.
    let ev_file = r["evidence_file"].as_str().unwrap();
    assert!(Path::new(ev_file).is_file());
    assert!(r["evidence_sha256"].as_str().unwrap().len() == 64);
    let text = std::fs::read_to_string(ev_file).unwrap();
    assert!(text.lines().count() >= 124, "per-block records expected");
    // D3 per-block erased; no unknown reservation.
    let d3 = r["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["domain"] == "D3")
        .unwrap();
    assert_eq!(d3["final"], "erased");
}

#[test]
fn sim_physical_erase_failure_is_c4_residual() {
    let dir = tmpdir("c4fail");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-c4fail", "--fail-erase", "10"]);
    let (rc, report, _) = run_nclr(
        &[
            "run",
            "-l",
            "physical",
            img.to_str().unwrap(),
            "--yes",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 1, "expected degraded (residual)");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "degraded");
    assert_eq!(r["achieved_grade"], "C4");
    assert_eq!(r["grade_qualified"], false);
    assert_eq!(r["residual"], "erase-failed");
    assert_eq!(r["postcheck"]["details"]["blocks_erase_failed"], 1);
    assert!(
        r["postcheck"]["details"]["target_non_erased_pages"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[test]
fn sim_physical_read_failure_cannot_qualify_c4() {
    let dir = tmpdir("c4-read-fail");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-c4-read-fail", "--fail-read", "10"]);
    let (rc, report, err) = run_nclr(
        &[
            "run",
            "-l",
            "physical",
            img.to_str().unwrap(),
            "--yes",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 1, "physical read failure must degrade C4: {err}");
    let result = json_of(&report);
    assert_eq!(result["achieved_grade"], "C4");
    assert_eq!(result["grade_qualified"], false);
    assert_eq!(result["residual"], "erase-failed");
    assert_eq!(result["postcheck"]["details"]["target_unreadable_pages"], 8);
    assert_eq!(
        result["postcheck"]["details"]["target_readable_pages"],
        result["postcheck"]["details"]["target_pages"]
            .as_u64()
            .unwrap()
            - 8
    );
}

#[test]
fn sim_physical_salvage_reads_every_raw_page() {
    let dir = tmpdir("salvage");
    let img = dir.join("sim.img");
    let output = dir.join("physical.img");
    let map = dir.join("physical.ndjson");
    let state = dir.join("salvage.state");
    let spec = nclr::sim::SimSpec::default();
    make_sim(&img, &["--id", "e2e-salvage"]);

    let (rc, report, err) = run_nclr(
        &[
            "salvage",
            img.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--map",
            map.to_str().unwrap(),
            "--state",
            state.to_str().unwrap(),
            "--backend",
            "sim",
            "--yes",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 0, "salvage failed: {err}");
    let result = json_of(&report);
    assert_eq!(result["schema"], "nclr.salvage.v1");
    assert_eq!(result["result"], "complete");
    assert_eq!(result["physical_read"]["total_pages"], 512);
    assert_eq!(result["physical_read"]["readable_pages"], 512);
    assert_eq!(result["physical_read"]["unreadable_pages"], 0);
    assert_eq!(result["physical_read"]["uncorrectable_pages"], 0);
    assert!(result["physical_read"].get("per_block").is_none());

    let raw = std::fs::read(&output).unwrap();
    let expected_bytes =
        spec.blocks as usize * spec.pages_per_block as usize * spec.page_bytes as usize;
    assert_eq!(raw.len(), expected_bytes);
    let source = std::fs::read(&img).unwrap();
    let data_offset = nclr::sim::HEADER_SIZE as usize
        + spec.blocks as usize * nclr::sim::BLOCK_TABLE_ENTRY as usize;
    assert_eq!(raw, source[data_offset..]);

    let lines = std::fs::read_to_string(&map).unwrap();
    assert_eq!(lines.lines().count(), 1 + 512);
    let header: Value = serde_json::from_str(lines.lines().next().unwrap()).unwrap();
    assert_eq!(header["schema"], "nclr.physical-map.v1");
    assert_eq!(header["record"], "header");
    assert_eq!(header["image_bytes"], expected_bytes as u64);
}

#[test]
fn sim_physical_salvage_keeps_holes_and_page_errors_explicit() {
    let dir = tmpdir("salvage-read-error");
    let img = dir.join("sim.img");
    let output = dir.join("physical.img");
    let map = dir.join("physical.ndjson");
    let state = dir.join("salvage.state");
    let spec = nclr::sim::SimSpec::default();
    make_sim(
        &img,
        &["--id", "e2e-salvage-read-error", "--fail-read", "10"],
    );

    let (rc, report, err) = run_nclr(
        &[
            "salvage",
            img.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--map",
            map.to_str().unwrap(),
            "--state",
            state.to_str().unwrap(),
            "--backend",
            "sim",
            "--yes",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 1, "salvage should be partial: {err}");
    let result = json_of(&report);
    assert_eq!(result["result"], "partial");
    assert_eq!(result["physical_read"]["unreadable_pages"], 8);
    assert_eq!(result["physical_read"]["exception_block_count"], 1);

    let raw = std::fs::read(&output).unwrap();
    let block_bytes = spec.pages_per_block as usize * spec.page_bytes as usize;
    assert_eq!(raw.len(), spec.blocks as usize * block_bytes);
    assert!(raw[10 * block_bytes..11 * block_bytes]
        .iter()
        .all(|byte| *byte == 0));
    let map = std::fs::read_to_string(&map).unwrap();
    let read_errors = map
        .lines()
        .skip(1)
        .map(|line| serde_json::from_str::<Value>(line).unwrap())
        .filter(|page| page["status"] == "read-error")
        .count();
    assert_eq!(read_errors, 8);
}

#[test]
fn sim_physical_unknown_reservation_is_unknown_scope() {
    let dir = tmpdir("c4unk");
    let img = dir.join("sim.img");
    make_sim(
        &img,
        &["--id", "e2e-c4unk", "--unknown-reservation", "40,41"],
    );
    let (rc, report, _) = run_nclr(
        &[
            "run",
            "-l",
            "physical",
            img.to_str().unwrap(),
            "--yes",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 1, "expected degraded (unknown-scope)");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "degraded");
    assert_eq!(r["achieved_grade"], "C4");
    assert_eq!(r["grade_qualified"], true);
    assert_eq!(r["residual"], "unknown-scope");
    assert_eq!(r["postcheck"]["details"]["unknown_reservation"], 2);
}

#[test]
fn sim_physical_ftl_failure_is_a_hard_recovery_boundary() {
    let dir = tmpdir("c4chain");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-c4chain", "--fail-ftl-commit"]);
    // A metadata commit failure after physical writes is a hard recovery
    // boundary. It must never switch to a different erase method.
    let (rc, report, _) = run_nclr(
        &[
            "run",
            "-l",
            "physical",
            img.to_str().unwrap(),
            "--yes",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 74, "expected a hard physical recovery failure");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "failed");
    assert!(!r["actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action["id"] == "device-user-area-erase"));
}

#[test]
fn sim_physical_resume_rebuilds_evidence() {
    let dir = tmpdir("c4resume");
    let img = dir.join("sim.img");
    let state = dir.join("sim.state");
    make_sim(&img, &["--id", "e2e-c4resume"]);
    // Interrupt right after the physical erase: the per-block evidence
    // before that point must be rebuilt from the journal on resume.
    let (rc, _, _) = run_nclr(
        &[
            "run",
            "-l",
            "physical",
            img.to_str().unwrap(),
            "--yes",
            "--state",
            state.to_str().unwrap(),
        ],
        &[
            ("NCLR_TEST_HOOKS", "1"),
            ("NCLR_TEST_STOP_AFTER", "erase-data-blocks"),
        ],
    );
    assert_eq!(rc, 75, "expected interrupted exit");

    let (rc, report, err) = run_nclr(&["resume", state.to_str().unwrap(), "--yes", "-j"], &[]);
    assert_eq!(rc, 0, "resume failed: {err}");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "ok");
    assert_eq!(r["achieved_grade"], "C4");
    assert_eq!(r["grade_qualified"], true);
    assert_eq!(r["postcheck"]["details"]["enumeration_complete"], true);
    assert_eq!(r["postcheck"]["details"]["blocks_erased"], 62);
}

/// Certification fixture: independent physical validation of the
/// sim controller family. Known patterns are placed in the user area, the
/// spare/obsolete region and the old RBBs; after a C4 run the raw sim image
/// (bypassing the FTL) must show no known patterns, FBB pages untouched and
/// the new BBT/FTL generations committed.
#[test]
fn certification_independent_physical_validation() {
    let dir = tmpdir("cert");
    let img = dir.join("sim.img");
    let spec = nclr::sim::SimSpec::default();
    nclr::sim::create(&img, &spec).unwrap();

    // Sanity: the FTL-view (LBA 0) holds the stale pattern before the run.
    let before = std::fs::read(&img).unwrap();
    let page = spec.page_bytes as usize;
    let block_data = |block: u32| -> usize {
        (nclr::sim::HEADER_SIZE as usize)
            + spec.blocks as usize * nclr::sim::BLOCK_TABLE_ENTRY as usize
            + block as usize * spec.pages_per_block as usize * page
    };
    assert_eq!(before[block_data(0) + 100], 0xA5, "user pattern");
    assert_eq!(before[block_data(10)], 0x5A, "old RBB pattern");
    assert_eq!(before[block_data(63)], 0x5A, "OP/obsolete pattern");

    // Run the C4 plan through the real binaries.
    let (rc, _, _) = run_nclr(
        &[
            "run",
            "-l",
            "physical",
            img.to_str().unwrap(),
            "--yes",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 0, "certified run must succeed");

    // Independent raw check: read the sim image directly, bypassing the FTL.
    let after = std::fs::read(&img).unwrap();
    let mut data_block_ok = true;
    for block in 0..spec.blocks {
        let state = after[nclr::sim::HEADER_SIZE as usize + block as usize * 8];
        if state == nclr::sim::STATE_FBB {
            // FBB marker page must be untouched (still holds stale data we
            // never wrote there: block 2/5 were never seeded, so their page
            // content is zeroes from creation).
            continue;
        }
        let base = block_data(block);
        let seg = &after[base..base + page];
        // Every non-FBB page must be blank (0xFF) after the final erase.
        if seg.iter().any(|b| *b != 0xFF) {
            data_block_ok = false;
            eprintln!("block {block} not blank: {:02x?} ...", &seg[..16]);
        }
    }
    assert!(data_block_ok, "all data-bearing pages must be blank");

    // Old RBB data and known patterns must be gone from the raw pages.
    let header = &after[..nclr::sim::HEADER_SIZE as usize];
    assert_ne!(
        header[232..240],
        before[232..240],
        "BBT generation advanced"
    );
    assert_ne!(
        header[240..248],
        before[240..248],
        "FTL generation advanced"
    );
    // FBB blocks were never erased (state preserved).
    assert_eq!(
        after[nclr::sim::HEADER_SIZE as usize + 2 * 8],
        nclr::sim::STATE_FBB
    );
    assert_eq!(
        after[nclr::sim::HEADER_SIZE as usize + 5 * 8],
        nclr::sim::STATE_FBB
    );
}

// ---------------------------------------------------------------------------
// Phase 5: Protected Area (D5) and vendor health (as much as hardware-free)
// ---------------------------------------------------------------------------

#[test]
fn sim_protected_area_is_documented_exclusion() {
    let dir = tmpdir("pa");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-pa", "--protected-area-blocks", "2"]);
    // C4 with a protected area: grade C4 qualified, residual
    // documented-exclusion, D5 coverage unreachable.
    let (rc, report, _) = run_nclr(
        &[
            "run",
            "-l",
            "physical",
            img.to_str().unwrap(),
            "--yes",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 1, "expected degraded (documented exclusion)");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "degraded");
    assert_eq!(r["achieved_grade"], "C4");
    assert_eq!(r["grade_qualified"], true);
    assert_eq!(r["residual"], "documented-exclusion");
    let d5 = r["coverage"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["domain"] == "D5")
        .unwrap();
    assert_eq!(d5["final"], "unreachable");
    assert_eq!(d5["residual"], true);

    // The protected blocks still hold their distinct stale pattern (0x6A).
    let data = std::fs::read(&img).unwrap();
    let page = 512usize;
    let block_data = |block: u32| -> usize {
        (nclr::sim::HEADER_SIZE as usize)
            + 64usize * nclr::sim::BLOCK_TABLE_ENTRY as usize
            + block as usize * 8 * page
    };
    assert_eq!(
        data[block_data(63)],
        0x6A,
        "protected block must be untouched"
    );
    assert_eq!(data[block_data(62)], 0x6A);
    // The user area is blank.
    assert_eq!(data[block_data(0)], 0xFF);
}

#[test]
fn check_includes_vendor_health() {
    let dir = tmpdir("vh");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-vh"]);
    let (rc, out, _) = run_nclr(&["check", "-j", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0);
    let v: Value = json_of(&out);
    let health = v["vendor_health"].as_array().unwrap();
    assert_eq!(health[0]["status"], "ok");
    assert_eq!(health[0]["read_only"], true);
    assert!(health[0]["health"]["power_cycles"].is_number());
}

// ---------------------------------------------------------------------------
// Phase 7: site policy config and scratch-range
// ---------------------------------------------------------------------------

#[test]
fn check_scratch_range_writes_and_restores() {
    let dir = tmpdir("scratch");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-scratch"]);
    let before = std::fs::read(&img).unwrap();
    let (rc, out, _) = run_nclr(
        &[
            "check",
            "-j",
            img.to_str().unwrap(),
            "--scratch-range",
            "0:64",
            "--yes",
        ],
        &[],
    );
    assert_eq!(rc, 0);
    let v: Value = json_of(&out);
    let st = v["scratch_test"].as_array().unwrap()[0].clone();
    assert_eq!(st["status"], "ok");
    assert_eq!(st["restored"], true);
    assert_eq!(st["bytes"], 32768);
    // The device is restored byte-for-byte (read-only by default).
    let after = std::fs::read(&img).unwrap();
    assert_eq!(before, after, "scratch test must restore the range");
    // Without --yes the write is refused.
    let (rc, _, err) = run_nclr(
        &[
            "check",
            "-j",
            img.to_str().unwrap(),
            "--scratch-range",
            "0:64",
        ],
        &[],
    );
    assert_eq!(rc, 77, "expected permission: {err}");
}

#[test]
fn scratch_range_bounds_are_enforced() {
    let dir = tmpdir("scratch2");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-scratch2"]);
    // Exceeds capacity.
    let (rc, _, err) = run_nclr(
        &[
            "check",
            img.to_str().unwrap(),
            "--scratch-range",
            "0:99999999",
            "--yes",
        ],
        &[],
    );
    assert_eq!(rc, 64, "expected usage: {err}");
    // Over the 64 MiB cap.
    let (rc, _, _) = run_nclr(
        &[
            "check",
            img.to_str().unwrap(),
            "--scratch-range",
            "0:200000",
            "--yes",
        ],
        &[],
    );
    assert_eq!(rc, 64);
}

#[test]
fn site_policy_enforced() {
    let dir = tmpdir("policy");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-policy"]);
    let cfg = dir.join("policy.toml");
    std::fs::write(
        &cfg,
        "allowed_backends = [\"sim\"]\n\
         minimum_level = \"device\"\n\
         [power_cycle]\nallowlist = [\"true\"]\n",
    )
    .unwrap();
    // Backend allowlist: lba is not allowed.
    let plain = dir.join("plain.img");
    std::fs::write(&plain, vec![0u8; 65536]).unwrap();
    let (rc, _, err) = run_nclr(
        &[
            "plan",
            "-l",
            "best",
            plain.to_str().unwrap(),
            "--config",
            cfg.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(rc, 77, "expected permission: {err}");
    assert!(err.contains("site policy"));
    // Minimum level floor: -l lba is raised to a C2 plan on the sim, but the
    // report keeps the user's requested level.
    let (rc, plan, _) = run_nclr(
        &[
            "plan",
            "-l",
            "lba",
            img.to_str().unwrap(),
            "--config",
            cfg.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(rc, 0);
    let plan: Value = json_of(&plan);
    assert_eq!(plan["expected_grade"], "C2");
    assert_eq!(plan["minimum_level"], "C2");
    assert_eq!(
        plan["requested_level"], "lba",
        "requested_level must keep the user's request, not the site floor"
    );
    // Power-cycle allowlist: an unapproved command is refused.
    let (rc, _, err) = run_nclr(
        &[
            "run",
            "-l",
            "lba",
            img.to_str().unwrap(),
            "--yes",
            "--power-cycle",
            "evil",
            "--config",
            cfg.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(rc, 77, "expected permission: {err}");
    assert!(err.contains("site policy"));
}

/// Imported plans must not bypass the policy applied at execution time.
#[test]
fn site_policy_rejects_noncompliant_imported_plans() {
    let dir = tmpdir("policy-import");
    let img = dir.join("sim.img");
    let plan_path = dir.join("plan.json");
    let cfg = dir.join("policy.toml");
    make_sim(&img, &["--id", "e2e-policy-import"]);

    let (rc, plan, err) = run_nclr(&["plan", "-l", "lba", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0, "plan failed: {err}");
    std::fs::write(&plan_path, plan).unwrap();
    std::fs::write(&cfg, "minimum_level = \"device\"\n").unwrap();

    let before = std::fs::read(&img).unwrap();
    let (rc, _, err) = run_nclr(
        &[
            "run",
            "--plan",
            plan_path.to_str().unwrap(),
            img.to_str().unwrap(),
            "--yes",
            "--config",
            cfg.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(rc, 77, "site floor must reject the imported plan: {err}");
    assert!(err.contains("site minimum level"));
    assert_eq!(std::fs::read(&img).unwrap(), before);

    let (rc, plan, err) = run_nclr(&["plan", "-l", "controller", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0, "controller plan failed: {err}");
    std::fs::write(&plan_path, plan).unwrap();
    std::fs::write(&cfg, "[spare_ratio]\nmin = 0.02\nmax = 0.04\n").unwrap();
    let (rc, _, err) = run_nclr(
        &[
            "run",
            "--plan",
            plan_path.to_str().unwrap(),
            img.to_str().unwrap(),
            "--yes",
            "--config",
            cfg.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(
        rc, 77,
        "site spare-ratio bounds must reject the imported plan: {err}"
    );
    assert!(err.contains("spare ratio"));
    assert_eq!(std::fs::read(&img).unwrap(), before);
}

// ---------------------------------------------------------------------------
// Phase 7: wear regression
// ---------------------------------------------------------------------------

/// Repeated runs must not add unnecessary passes: the planner output is
/// stable, capacity/spare stay stable and the P/E cost per run is
/// deterministic.
#[test]
fn wear_regression_repeated_runs_are_stable() {
    let dir = tmpdir("wear");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-wear"]);

    // Plan twice: identical action sets (no growing multi-pass).
    let (rc, p1, _) = run_nclr(&["plan", "-l", "best", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0);
    let (rc, p2, _) = run_nclr(&["plan", "-l", "best", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0);
    let p1: Value = json_of(&p1);
    let p2: Value = json_of(&p2);
    let ids = |p: &Value| -> Vec<String> {
        p["actions"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|a| a["id"].as_str().map(String::from))
            .collect()
    };
    assert_eq!(ids(&p1), ids(&p2), "planner must not add passes over time");

    // First run.
    let (rc, r1, _) = run_nclr(
        &["run", "-l", "best", img.to_str().unwrap(), "--yes", "-j"],
        &[],
    );
    assert_eq!(rc, 0, "first run must succeed");
    let r1: Value = json_of(&r1);
    assert_eq!(r1["achieved_grade"], "C4");

    // Second run: capacity and spare stay stable.
    let (rc, r2, _) = run_nclr(
        &["run", "-l", "best", img.to_str().unwrap(), "--yes", "-j"],
        &[],
    );
    assert_eq!(rc, 0, "second run must succeed");
    let r2: Value = json_of(&r2);
    assert_eq!(r2["achieved_grade"], "C4");
    assert_eq!(
        r1["device_after"]["capacity_bytes"], r2["device_after"]["capacity_bytes"],
        "capacity must be stable across repeated runs"
    );
    let spare1 = r1["postcheck"]["details"]["expected_capacity_bytes"]
        .as_u64()
        .unwrap();
    let spare2 = r2["postcheck"]["details"]["expected_capacity_bytes"]
        .as_u64()
        .unwrap();
    assert_eq!(spare1, spare2, "committed capacity must be stable");
}

// ---------------------------------------------------------------------------
// Phase 7 regression: broken pipe, spare-ratio clamp, backend timeout
// ---------------------------------------------------------------------------

/// "pipe close, broken pipe": a closed stdout pipe must
/// not panic; the process dies with SIGPIPE like standard tools.
#[test]
fn broken_pipe_does_not_panic() {
    use std::os::unix::process::ExitStatusExt;
    let dir = tmpdir("pipe");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-pipe"]);
    let mut child = Command::new(nclr())
        .args(["plan", "-l", "best", img.to_str().unwrap()])
        .env("NCLR_BACKEND_DIR", backend_dir())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    drop(child.stdout.take()); // close the read end immediately
    let out = child.wait_with_output().unwrap();
    assert!(
        out.status.code().is_none(),
        "must be killed by a signal, not a panic (exit {:?})",
        out.status.code()
    );
    assert_eq!(out.status.signal(), Some(13), "expected SIGPIPE");
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(!err.contains("panicked"), "must not panic: {err}");
}

/// The site policy spare-ratio clamp must reach the plan's capacity policy
/// (the backend uses the plan's clamped values, never its own).
#[test]
fn site_spare_ratio_clamp_reaches_the_plan() {
    let dir = tmpdir("ratio");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-ratio"]);
    // The shipped profile requests 0.05. Clamp it downward without replacing
    // the production profile with an untrusted test profile.
    let site = dir.join("site.toml");
    std::fs::write(&site, "[spare_ratio]\nmin = 0.02\nmax = 0.04\n").unwrap();

    let (rc, plan, _) = run_nclr(
        &[
            "plan",
            "-l",
            "controller",
            img.to_str().unwrap(),
            "--config",
            site.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(rc, 0);
    let p: Value = json_of(&plan);
    let rebuild = p["actions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["id"] == "rebuild-bbt-ftl")
        .unwrap();
    let ratio = rebuild["params"]["capacity_policy"]["spare_ratio"]
        .as_f64()
        .unwrap();
    assert_eq!(
        ratio, 0.04,
        "out-of-bounds ratio must be clamped to the site max"
    );
}

/// A user-modified profile cannot self-assert production trust for the
/// certified sim controller family. Only the shipped digest enables C3/C4.
#[test]
fn modified_production_profile_disables_destructive_controller_capabilities() {
    let dir = tmpdir("untrusted-profile");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-untrusted-profile"]);
    let profiles = dir.join("profiles");
    std::fs::create_dir_all(&profiles).unwrap();
    let source = std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../profiles/sim-controller-1.toml"),
    )
    .unwrap();
    let modified = source
        .replace("spare_ratio = 0.05", "spare_ratio = 0.20")
        .lines()
        .filter(|line| !line.trim_start().starts_with("sha256"))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(profiles.join("sim-controller-1.toml"), modified).unwrap();

    let (rc, _, err) = run_nclr(
        &["plan", "-l", "controller", img.to_str().unwrap()],
        &[("NCLR_PROFILE_DIR", profiles.to_str().unwrap())],
    );
    assert_eq!(rc, 2, "modified production profile must be refused: {err}");
    assert!(
        err.contains("not the shipped digest")
            || err.contains("destructive controller operations are disabled")
    );
}

/// A backend that exceeds the configured timeout is killed; the run is
/// interrupted (exit 75) and a resumable journal is left. Nothing is resent
/// without a status query.
#[test]
fn backend_timeout_kills_and_interrupts() {
    let dir = tmpdir("timeout");
    let img = dir.join("plain.img");
    std::fs::write(&img, vec![0u8; 65536]).unwrap();
    let state = dir.join("sim.state");
    // A slow backend: the probe answers immediately, every action sleeps
    // far beyond the 1s timeout (30s leaves the timeout reliably first
    // even under parallel-suite load).
    let back = dir.join("back");
    std::fs::create_dir_all(&back).unwrap();
    let script = "#!/bin/sh\nreq=$(cat <&4)\ncase \"$req\" in\n  *'\"op\":\"probe\"'*)\n    echo '{\"api\":2,\"ok\":true}'\n    ;;\n  *)\n    sleep 30\n    echo '{\"api\":2,\"ok\":true}'\n    ;;\nesac\n";
    std::fs::write(back.join("nclr-lba"), script).unwrap();
    let mut perms = std::fs::metadata(back.join("nclr-lba"))
        .unwrap()
        .permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(back.join("nclr-lba"), perms).unwrap();
    std::fs::write(
        back.join("lba.toml"),
        "schema = 2\nid = \"lba\"\nexec = \"nclr-lba\"\napi = 2\ntrust = \"production\"\noperations = [\"probe\", \"plan\", \"run\", \"status\", \"recover\"]\n",
    )
    .unwrap();

    let (rc, _, err) = run_nclr(
        &[
            "run",
            "-l",
            "lba",
            img.to_str().unwrap(),
            "--yes",
            "--backend-timeout",
            "1",
            "--state",
            state.to_str().unwrap(),
        ],
        &[("NCLR_BACKEND_DIR", back.to_str().unwrap())],
    );
    assert_eq!(rc, 75, "expected interrupted exit: {err}");
    assert!(state.is_file(), "a resumable journal must remain");
    assert!(
        std::fs::read_to_string(&state)
            .unwrap()
            .contains("interrupted"),
        "journal must record the interruption"
    );
}

/// A backend that answers a run action with `status: "interrupted"` (the
/// busy-timeout-mid-erase contract) must make the core exit 75 with a
/// resumable result, not fall back to writes or fail the run.
#[test]
fn backend_interrupted_status_exits_75() {
    let dir = tmpdir("interrupted");
    let img = dir.join("plain.img");
    std::fs::write(&img, vec![0u8; 65536]).unwrap();
    let back = dir.join("back");
    std::fs::create_dir_all(&back).unwrap();
    let script = "#!/bin/sh\nreq=$(cat <&4)\ncase \"$req\" in\n  *'\"op\":\"probe\"'*)\n    echo '{\"api\":2,\"ok\":true,\"backend\":\"lba\",\"version\":\"0.0.0\",\"match\":\"exact\",\"capabilities\":[\"LBA_PRBS_WRITE\",\"ERASE_USER_AREA\"],\"grade_ceiling\":\"C2\",\"erase_coverage\":[\"D0\"],\"erase_method\":\"fake-erase\"}'\n    ;;\n  *)\n    echo '{\"api\":2,\"ok\":true,\"backend\":\"lba\",\"version\":\"0.0.0\",\"action\":\"device-user-area-erase\",\"action_results\":[{\"status\":\"interrupted\",\"message\":\"busy timeout; card may still be erasing\"}]}'\n    ;;\nesac\n";
    std::fs::write(back.join("nclr-lba"), script).unwrap();
    let mut perms = std::fs::metadata(back.join("nclr-lba"))
        .unwrap()
        .permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o755);
    std::fs::set_permissions(back.join("nclr-lba"), perms).unwrap();
    std::fs::write(
        back.join("lba.toml"),
        "schema = 2\nid = \"lba\"\nexec = \"nclr-lba\"\napi = 2\ntrust = \"production\"\noperations = [\"probe\", \"plan\", \"run\", \"status\", \"recover\"]\n",
    )
    .unwrap();

    let (rc, report, err) = run_nclr(
        &["run", "-l", "device", img.to_str().unwrap(), "--yes", "-j"],
        &[("NCLR_BACKEND_DIR", back.to_str().unwrap())],
    );
    assert_eq!(rc, 75, "interrupted status must exit 75: {err}");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "interrupted");
}

// ---------------------------------------------------------------------------
// Correctness regressions: capacity-commit resume, alias consistency, recovery
// ---------------------------------------------------------------------------

/// Interruption after the FTL rebuild committed a reduced
/// capacity must be resumable (the fingerprint legitimately changed).
#[test]
fn resume_after_capacity_commit_succeeds() {
    let dir = tmpdir("capcommit");
    let img = dir.join("sim.img");
    let state = dir.join("sim.state");
    make_sim(&img, &["--id", "e2e-capcommit"]);
    let (rc, _, _) = run_nclr(
        &[
            "run",
            "-l",
            "controller",
            img.to_str().unwrap(),
            "--yes",
            "--state",
            state.to_str().unwrap(),
        ],
        &[
            ("NCLR_TEST_HOOKS", "1"),
            ("NCLR_TEST_STOP_AFTER", "rebuild-bbt-ftl"),
        ],
    );
    assert_eq!(rc, 75, "expected interrupted exit");
    // The capacity-committed identity is recorded in the journal.
    let journal = std::fs::read_to_string(&state).unwrap();
    assert!(journal.contains("capacity-committed"));

    // Resume must re-match the device (changed fingerprint) and finish.
    let (rc, report, err) = run_nclr(&["resume", state.to_str().unwrap(), "--yes", "-j"], &[]);
    assert_eq!(rc, 0, "resume after capacity commit failed: {err}");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "ok");
    assert_eq!(r["achieved_grade"], "C3");
    assert_eq!(r["grade_qualified"], true);
}

/// Capacity-alias: the effective capacity is coherent between the committed
/// value and the identity reports (no 55-vs-54 mismatch).
#[test]
fn capacity_alias_is_consistent_after_rebuild() {
    let dir = tmpdir("aliasfix");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-aliasfix", "--capacity-alias"]);
    let (rc, report, _) = run_nclr(
        &[
            "run",
            "-l",
            "physical",
            img.to_str().unwrap(),
            "--yes",
            "-j",
        ],
        &[],
    );
    // The alias shrinks the committed capacity by one block after the power
    // cycle: before/after/expected must all be coherent.
    assert_eq!(rc, 1, "expected degraded (capacity instability)");
    let r: Value = json_of(&report);
    let before = r["device_before"]["capacity_bytes"].as_u64().unwrap();
    let after = r["device_after"]["capacity_bytes"].as_u64().unwrap();
    let expected = r["postcheck"]["details"]["expected_capacity_bytes"]
        .as_u64()
        .unwrap();
    assert_eq!(before, 56 * 8 * 512, "nominal 56 blocks");
    assert_eq!(expected, 54 * 8 * 512, "committed 54 blocks");
    assert_eq!(
        after,
        53 * 8 * 512,
        "alias applies on top of the committed value"
    );
    assert_eq!(r["health_grade"], "H0");
    assert_eq!(r["result"], "degraded");
}

/// A failed run surfaces the backend's declared recovery procedure.
#[test]
fn failed_run_reports_recovery_procedure() {
    let dir = tmpdir("recover");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-recover", "--fail-ftl-commit"]);
    let (rc, report, _) = run_nclr(
        &[
            "run",
            "-l",
            "controller",
            img.to_str().unwrap(),
            "--yes",
            "--no-fallback",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 74, "expected failure with --no-fallback");
    let r: Value = json_of(&report);
    assert_eq!(r["result"], "failed");
    // The recover op (declared profile recovery method) is surfaced.
    let warnings = r["warnings"].as_array().unwrap();
    let recovery = warnings
        .iter()
        .find(|w| w.as_str().unwrap_or("").contains("recovery required"));
    assert!(
        recovery.is_some(),
        "report must surface the recovery procedure: {warnings:?}"
    );
}

// ---------------------------------------------------------------------------
// Schema conformance: summary report, ftl object, BBT
// summary, action duration, health metrics.
// ---------------------------------------------------------------------------

#[test]
fn summary_report_mode() {
    let dir = tmpdir("summary");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-summary"]);
    let (rc, out, _) = run_nclr(
        &[
            "run",
            "-l",
            "best",
            img.to_str().unwrap(),
            "--yes",
            "--summary",
            "-j",
        ],
        &[],
    );
    assert_eq!(rc, 0);
    let s: Value = json_of(&out);
    assert_eq!(s["schema"], "nclr.summary.v1");
    assert_eq!(s["result"], "ok");
    assert_eq!(s["achieved_grade"], "C4");
    assert_eq!(s["final_state"], "raw-uninitialized");
    // Identity fields are redacted in the summary.
    assert!(s.get("device_before").is_none());
    assert!(s.get("coverage").is_none());
    assert!(s["report_hash"].as_str().is_some());
}

#[test]
fn controller_report_has_ftl_and_bbt_summary() {
    let dir = tmpdir("ftl");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-ftl"]);
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
    // ftl object (controller paths).
    assert_eq!(r["ftl"]["rebuilt"], true);
    assert!(r["ftl"]["spare_ratio"].as_f64().is_some());
    assert!(r["ftl"]["bbt_generation"].as_u64().unwrap() >= 2);
    assert!(r["ftl"]["ftl_generation"].as_u64().unwrap() >= 2);
    // BBT summary in postcheck details.
    let b = &r["postcheck"]["details"]["bbt_summary"];
    assert_eq!(b["old_bbt_generation"], 1);
    assert_eq!(b["new_bbt_generation"], r["ftl"]["bbt_generation"]);
    assert_eq!(b["fbb_count"], 2);
    assert_eq!(b["rbb_count"], 3);
    assert_eq!(b["old_rbb_erased"], 3);
    // Per-action duration recorded.
    let durations: Vec<u64> = r["actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|a| a["duration_ms"].as_u64())
        .collect();
    assert!(
        durations.len() >= 11,
        "every action must carry duration_ms (got {})",
        durations.len()
    );
}

#[test]
fn lba_report_has_health_metrics() {
    let dir = tmpdir("metrics");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-metrics"]);
    let (rc, report, _) = run_nclr(
        &["run", "-l", "lba", img.to_str().unwrap(), "--yes", "-j"],
        &[],
    );
    assert_eq!(rc, 0);
    let r: Value = json_of(&report);
    let d = &r["postcheck"]["details"];
    assert!(
        d["throughput_mbps"].as_f64().unwrap_or(0.0) > 0.0,
        "throughput must be measured: {d}"
    );
    assert!(
        d["flush_latency_ms"].as_u64().is_some(),
        "flush latency must be measured"
    );
}

#[test]
fn plan_carries_power_requirements() {
    let dir = tmpdir("power");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-power"]);
    let (rc, plan, _) = run_nclr(&["plan", "-l", "best", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0);
    let p: Value = json_of(&plan);
    // The plan declares power requirements.
    assert!(p["power"].is_object());
    assert_eq!(
        p["power"]["power_cycle_required"], 0,
        "sim power cycles internally"
    );
    assert_eq!(p["power"]["ups_recommended"], false);
}

/// A corrupt journal state file must fail the run instead of silently
/// restarting the append-only chain.
#[test]
fn corrupt_state_file_fails_run() {
    let dir = tmpdir("corrupt-state");
    let img = dir.join("sim.img");
    let state = dir.join("broken.state");
    std::fs::write(&state, b"{\"not\": \"a journal\"\n").unwrap();
    make_sim(&img, &["--id", "e2e-corrupt"]);
    let (rc, _, err) = run_nclr(
        &[
            "run",
            "-l",
            "lba",
            img.to_str().unwrap(),
            "--yes",
            "--state",
            state.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(rc, 78, "expected invalid-journal exit: {err}");
    assert!(err.contains("journal"), "unexpected error: {err}");
}

/// An invalid embedded fallback plan is rejected before any device action.
#[test]
fn invalid_fallback_plan_is_rejected_upfront() {
    let dir = tmpdir("bad-fallback");
    let img = dir.join("sim.img");
    let plan_path = dir.join("plan.json");
    make_sim(&img, &["--id", "e2e-fallback"]);
    let (rc, plan_json, err) = run_nclr(&["plan", "-l", "best", img.to_str().unwrap()], &[]);
    assert_eq!(rc, 0, "plan failed: {err}");
    let mut plan: nclr::plan::Plan = serde_json::from_str(&plan_json).unwrap();
    plan.fallback_plan = Some(serde_json::json!({ "schema": "nclr.plan.invalid" }));
    plan.refresh_hash();
    std::fs::write(&plan_path, serde_json::to_string(&plan).unwrap()).unwrap();
    let (rc, _, err) = run_nclr(
        &[
            "run",
            "--plan",
            plan_path.to_str().unwrap(),
            img.to_str().unwrap(),
            "--yes",
        ],
        &[],
    );
    assert_eq!(rc, 78, "expected invalid-plan exit: {err}");
    assert!(err.contains("fallback plan"), "unexpected error: {err}");
}

/// An unusable evidence directory must fail the run, not silently disable
/// the evidence trail.
#[test]
fn evidence_dir_unwritable_fails_run() {
    let dir = tmpdir("evidence-blocked");
    let img = dir.join("sim.img");
    let blocker = dir.join("blocker");
    std::fs::write(&blocker, b"occupied").unwrap();
    make_sim(&img, &["--id", "e2e-evidence"]);
    let (rc, _, err) = run_nclr(
        &[
            "run",
            "-l",
            "lba",
            img.to_str().unwrap(),
            "--yes",
            "--evidence-dir",
            blocker.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(rc, 74, "expected device-io exit: {err}");
    assert!(err.contains("evidence dir"), "unexpected error: {err}");
}

/// A vendor-health probe failure is surfaced as a check warning instead of
/// being silently dropped.
#[test]
fn check_reports_vendor_health_failure_as_warning() {
    let dir = tmpdir("vh-fail");
    let img = dir.join("plain.img");
    std::fs::write(&img, vec![0u8; 65536]).unwrap();
    // A script backend that declares SD_VENDOR_HEALTH but fails the probe:
    // the failure must become a check warning, not vanish.
    let be = dir.join("nclr-lba");
    std::fs::write(
        &be,
        r#"#!/bin/sh
req=$(cat <&4)
case "$req" in
  *'"op":"probe"'*)
    echo '{"api":2,"ok":true,"backend":"lba","version":"0.0.0","capabilities":["SD_VENDOR_HEALTH","SAMPLE_READ"],"grade_ceiling":"L1","trust":"production"}'
    ;;
  *'"action":"vendor-health"'*)
    echo '{"api":2,"ok":false,"backend":"lba","version":"0.0.0","action_results":[{"status":"error","message":"vendor health probe denied"}]}'
    ;;
  *)
    echo '{"api":2,"ok":true,"backend":"lba","version":"0.0.0","action_results":[{"status":"ok","action":"sample-read","value":{}}]}'
    ;;
esac
"#,
    )
    .unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(&be).unwrap().permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(&be, perms).unwrap();
    std::fs::write(
        dir.join("lba.toml"),
        "schema = 2\nid = \"lba\"\nexec = \"nclr-lba\"\napi = 2\ntrust = \"production\"\noperations = [\"probe\", \"run\"]\n",
    )
    .unwrap();
    let (rc, out, _) = run_nclr(
        &["check", "-j", img.to_str().unwrap()],
        &[("NCLR_BACKEND_DIR", dir.to_str().unwrap())],
    );
    assert_eq!(rc, 0, "check stays non-fatal on vendor-health failure");
    let v: Value = json_of(&out);
    let warnings = v["warnings"].as_array().unwrap();
    assert!(
        warnings
            .iter()
            .any(|w| w.as_str().unwrap_or("").contains("vendor-health")),
        "vendor-health failure must surface as a warning: {warnings:?}"
    );
    assert!(v["vendor_health"].is_null());
}

/// With a site-policy floor configured, an invalid --level must be a usage
/// error instead of being silently coerced to the floor.
#[test]
fn invalid_level_is_usage_error_even_with_floor() {
    let dir = tmpdir("level-floor");
    let img = dir.join("sim.img");
    let cfg = dir.join("nclr.toml");
    std::fs::write(&cfg, "minimum_level = \"device\"\n").unwrap();
    make_sim(&img, &["--id", "e2e-floor"]);
    let (rc, _, err) = run_nclr(
        &[
            "plan",
            "-l",
            "bogus",
            img.to_str().unwrap(),
            "--config",
            cfg.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(rc, 64, "invalid level must be a usage error: {err}");
    assert!(
        err.contains("invalid planning level"),
        "unexpected error: {err}"
    );
    // Valid levels still work with the floor active.
    let (rc, _, err) = run_nclr(
        &[
            "plan",
            "-l",
            "lba",
            img.to_str().unwrap(),
            "--config",
            cfg.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(rc, 0, "valid level with floor must plan: {err}");
}

/// An invalid --min-level must be a usage error, not silently treated as C0.
#[test]
fn invalid_min_level_is_usage_error() {
    let dir = tmpdir("min-level");
    let img = dir.join("sim.img");
    make_sim(&img, &["--id", "e2e-min"]);
    let (rc, _, err) = run_nclr(
        &[
            "plan",
            "-l",
            "best",
            "--min-level",
            "bogus",
            img.to_str().unwrap(),
        ],
        &[],
    );
    assert_eq!(rc, 64, "invalid min-level must be a usage error: {err}");
    assert!(
        err.contains("invalid minimum planning level"),
        "unexpected error: {err}"
    );
}
