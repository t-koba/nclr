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
