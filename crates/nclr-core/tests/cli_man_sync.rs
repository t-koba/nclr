//! CLI compatibility: `nclr --help` subcommands must match the man page
//! ("help and man page sync").

use std::process::Command;

#[test]
fn help_subcommands_match_man_page() {
    let out = Command::new(env!("CARGO_BIN_EXE_nclr"))
        .arg("--help")
        .output()
        .expect("spawn nclr --help");
    assert!(out.status.success());
    let help = String::from_utf8_lossy(&out.stdout).into_owned();

    // Subcommands advertised in --help (clap derives these).
    let expected = [
        "ls", "info", "plan", "run", "check", "salvage", "resume", "help",
    ];
    for cmd in expected {
        assert!(
            help.contains(cmd),
            "--help must mention the {cmd} subcommand:\n{help}"
        );
    }

    // The man page must cover the same subcommands.
    let man = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../man/nclr.1"),
    )
    .expect("man/nclr.1");
    for cmd in expected {
        assert!(
            man.contains(&format!(".B {cmd}")),
            "man/nclr.1 must document the {cmd} subcommand"
        );
    }
}

#[test]
fn lab_help_subcommands_match_man_page() {
    let output = Command::new(env!("CARGO_BIN_EXE_nclr-lab"))
        .arg("--help")
        .output()
        .expect("spawn nclr-lab --help");
    assert!(output.status.success());
    let help = String::from_utf8_lossy(&output.stdout).into_owned();
    let expected = [
        "artifact",
        "cap",
        "controller",
        "decode",
        "diff",
        "infer",
        "phison-ps2303",
        "probe",
        "profile",
        "recipe",
        "replay",
        "tool",
        "trace",
    ];
    for command in expected {
        assert!(
            help.contains(command),
            "--help must mention the {command} subcommand:\n{help}"
        );
    }

    let man = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../man/nclr-lab.1"),
    )
    .expect("man/nclr-lab.1");
    for command in expected {
        assert!(
            man.contains(&format!(".B nclr-lab {command}"))
                || man.contains(&format!(".B {command}")),
            "man/nclr-lab.1 must document the {command} subcommand"
        );
    }
    for contract in [
        "probe check",
        "probe new",
        "probe run",
        "phison-ps2303 loader-check",
        "phison-ps2303 geometry",
        "phison-ps2303 inspect",
        "phison-ps2303 enter-bootrom",
        "phison-ps2303 load",
        "phison-ps2303 probe-loader",
        "\\-\\-pre\\-hil",
        "\\-\\-artifact\\-dir",
        "\\-\\-confirm\\-research\\-device",
    ] {
        assert!(
            man.contains(contract),
            "man/nclr-lab.1 must document {contract}"
        );
    }
}

#[test]
fn backend_contract_man_page_covers_the_protocol() {
    let man = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../man/nclr-backend.7"),
    )
    .expect("man/nclr-backend.7");
    // The documented fd contract and ops must match the implementation.
    for needle in [
        "--device-fd 3",
        "--request-fd 4",
        "--events-fd 5",
        "probe",
        "plan",
        "run",
        "status",
        "recover",
        "extra_fds",
        "action_results",
        "grade_ceiling",
        "CONTROLLER_REINITIALIZE",
        "PHYSICAL_SCOPE",
        "PHYSICAL_SALVAGE",
    ] {
        assert!(
            man.contains(needle),
            "nclr-backend(7) must mention {needle}"
        );
    }
}

#[test]
fn version_flag_works() {
    let out = Command::new(env!("CARGO_BIN_EXE_nclr"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(out.status.success());
    let v = String::from_utf8_lossy(&out.stdout);
    assert!(v.starts_with("nclr "), "unexpected version output: {v}");
}
