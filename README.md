# nclr

**NAND clear / reinitialize** — one-shot CLI that erases and reinitializes
managed NAND media (SD cards, microSD, USB flash drives) back to a reusable
*raw-uninitialized* block device state.

An implementation of a destructive media erase and reinitialize
pipeline, built in phases: Phase 0 Safe Core, Phase 1 LBA C1, Phase 2
Standard Device Operations, Phase 3 Controller Reinitialize, Phase 4
Physical Scope, Phase 5 hardware-free pieces, and Phase 6 Lab tooling.

## What it does

`nclr` is not a filesystem deletion tool. It:

1. Identifies the media with a stable SHA-256 fingerprint (transport, IDs,
   capacity, physical path — never kernel-assigned names alone).
2. Re-checks the fingerprint, capacity and physical path between planning and
   execution (`plan` vs `run`), rejecting any mismatch.
3. Refuses system disks, mounted media (unless `--unmount`), swap, LVM/RAID
   holders and non-removable devices by default.
4. Plans the strongest documented reach:
   - **C4 (Physical Scope Accounted)** when the backend holds a certified
     physical-scope validation: every non-FBB data-bearing physical block is
     enumerated and categorized (user/spare/obsolete/old RBB), erased with
     per-block results, then every declared physical page and OOB byte is read
     before controller metadata is rebuilt. C4 is qualified only when every
     page in the erased scope is readable, correctable and byte-for-byte
     blank. The sim family is certified via an independent physical
     validation fixture (TEST-001).
   - **C3 (Controller Reinitialized)** when a production controller profile
     matches the device exactly: BBT capture, service mode, per-block old
     RBB erase, PROGRAM/READ/ECC qualification, new BBT/spare/FTL rebuild
     (old FTL generation invalidated) and capacity accounting. The sim
     controller family is the certified reference implementation.
   - **C2 (Device User Area Erased)** when the backend has a documented
     device-level erase: SCSI SANITIZE BLOCK ERASE (`nclr-scsi`), native SD
     full-range ERASE (`nclr-sd-native`), or the sim model. The device erase
     runs last and is verified with a blank sweep, so no redundant LBA
     overwrite layers on top (PLAN-002).
   - **C1 (LBA Cleared)** otherwise: PRBS overwrite → flush → power cycle →
     read-back verify → zero overwrite → flush → power cycle → zero verify →
     partition/filesystem signature check.
   Per-block evidence for physical paths is streamed to `--evidence-dir`
   (the report carries only the summary and a digest).
5. Monitors long-running self-executing erases (SANITIZE-style) via status
   polling with progress events; interruption leaves a journal that `resume`
   uses to keep monitoring or continue.
6. Records every destructive phase boundary in an append-only NDJSON journal
   with a SHA-256 hash chain, fsync'd, and resumes from it after interruption
   (evidence is rebuilt from the journal).
7. Computes **C grade** (erase reach), **residual risk** and **H grade**
   (health) independently, and only reports what the evidence supports.
   UNMAP/discard alone never grants C2. A documented capacity reduction
   (weak-block isolation) is reported, not treated as a failure.
8. Creates no partitions and no filesystems. `final_state` is always
   `raw-uninitialized`.

The separate read-only salvage workflow uses the same physical addressing
and raw page reader without issuing erase or program commands:

```sh
sudo nclr salvage /dev/sdb \
  --output card.physical.img \
  --map card.physical.ndjson
```

Both destinations must be new files. The image order is flat block, page,
then data + OOB. The mandatory NDJSON map gives the geometry and one record
per page; an unreadable page is represented by a fixed-size zero-filled hole
whose record is explicitly `read-error`, so a hole cannot be mistaken for
recovered media data. Exit 0 means every address was readable and
correctable; exit 1 retains a usable partial image and map.

## Architecture

```
              plan/report JSON
shell  <-------------------------->  nclr
                                          |
                                          | exec + inherited FDs
                                          v
      nclr-sim | nclr-lba | nclr-scsi | nclr-sd-native | nclr-controller
                                          |
                              read/write / SCSI / MMC / NAND model
                                          |
                                      target media
```

The source is a Cargo workspace split into `crates/nclr-core` (library +
`nclr`/`nclr-lab`), `crates/nclr-backends` (the backend executables) and
`crates/nclr-profiles` (embedded profile
data). `packaging/stage.sh` materializes the OS-package layout (`nclr`,
`nclr-backends-usb`, `nclr-backends-sd`, `nclr-lab`, `nclr-profiles`);
`packaging/sbom.sh` emits an SPDX SBOM and `packaging/reproducible.sh`
verifies deterministic binaries.

- One process handles exactly one medium. `run` takes a single device or a
  fixed plan; multiple media are handled by the shell (`xargs -P`, etc.).
- Backends are short-lived executables that receive **pre-opened device FDs**
  (fd 3 device, fd 4 request, fd 5 events, fd 6+ extra roles like sg/usbfs)
  and never open device paths themselves (SEC-001). No daemon, no socket, no
  internal database.
- Data goes to stdout, diagnostics to stderr, machine progress to `--events-fd`
  (NDJSON).

## Build

Requires Rust (stable) and a Unix system.

```sh
cargo build --workspace --release
# binaries: target/release/nclr, nclr-lab, nclr-lba, nclr-sim,
#           nclr-scsi (Linux), nclr-sd-native (Linux), nclr-controller (Linux)

cargo test --workspace   # unit + backend protocol + e2e (no root needed)
cargo clippy --workspace --all-targets
```

The examples in this document use `target/debug/` binaries; run
`cargo build --workspace` (debug) or substitute `target/release/` after a
release build.

The core finds backends via `NCLR_BACKEND_DIR`, `--backend-dir`,
`/usr/libexec/nclr`, the directory of the `nclr` binary, or
`<prefix>/libexec/nclr` next to it (install layout). Profiles are resolved
from `NCLR_PROFILE_DIR`, `/usr/share/nclr/profiles`, backend-adjacent
`profiles/` dirs, and `<prefix>/share/nclr/profiles`. A backend manifest
(`<backend-dir>/<id>.toml` with `sha256`) is validated when present; digests
are always recorded in reports. Real destructive controller profiles are
accepted only from package-managed `/usr/share` or `<prefix>/share`
locations; a user-controlled `NCLR_PROFILE_DIR` cannot self-assert
production trust. The sim backend additionally accepts only the exact
digest of its compiled-in certified profile. Custom backends require a
schema-2 production manifest with an exact executable digest; only bundled
backend IDs in trusted install locations may omit the manifest.

## Backend selection

| Device | Linux | macOS / other |
|--------|-------|---------------|
| USB mass storage (`/dev/sdX`) | `nclr-scsi` (SANITIZE, C2) | `nclr-lba` (C1) |
| Native SD (`/dev/mmcblkN`) | `nclr-sd-native` (SD full-range ERASE, C2) | `nclr-lba` (C1) |
| controller device (matched profile) | `nclr-controller` (C3) | — |
| plain file (pseudo-device) | `nclr-lba` (C1) | `nclr-lba` (C1) |
| sim image (`NCLRSIM1`) | `nclr-sim` (C4 when certified, else C3/C2) | `nclr-sim` |

`nclr run -l physical /tmp/sim.img --yes --evidence-dir ./ev -j` runs the
certified physical-scope path; per-block records land in
`./ev/<plan-id>.blocks.ndjson` and the report references their SHA-256.

## Controller profiles

A controller profile (TOML, `profiles/`) declares the identification
conditions, coverage, rebuilds, preserves, capacity policy, ECC thresholds
and recovery method for a controller/firmware/NAND combination.
Destructive execution requires:

- an **exact match**: `controller_id` identical, firmware and NAND id within
  the declared ranges, and
- **trust = production** (research/experimental/validated are never used for
  destructive runs), and
- for real media, exact firmware/NAND values plus immutable independent HIL
  qualification metadata accounting for D1-D4 and power-cut recovery.

The sim controller family (`sim-controller-1`, trust = production) is the
bundled certified reference. The real-device backend contains the bounded
physical-block, FBB/RBB, qualification, BBT/FTL atomic-commit, capacity,
service re-enumeration and recovery engine for Phison, SMI, Alcor and SanDisk
Cruzer proprietary controllers. Vendor CDBs and response layouts are supplied
as an authenticated runtime protocol recipe tied to one exact
controller/firmware/NAND tuple; unknown commands are never inferred. Built-in
read-only identification is implemented for Phison PS2251, Alcor AU698x and
the publicly documented SMI SM32X identity page. SanDisk Cruzer, later
controller generations without a public fixed probe, and explicitly profiled
OEM VID products first select the required recipe by an exact USB/SCSI tuple,
then verify recipe-owned controller and NAND identity responses before
execution. The tuple never authorizes destructive commands by itself. No real tuple is
bundled as `production`, so D1-D4/C3 remains unavailable until that tuple's
recipe and independent HIL qualification are installed. Planning pins the
required runtime artifact digests; execution verifies those bytes before
enabling destructive commands. The boundary
is documented in
[`docs/controller-vendor-support.md`](docs/controller-vendor-support.md).
Without a trusted exact certified profile, `-l controller` fails at plan time
with exit 2. A matching profile permits only a read-only plan that pins all
artifact digests; missing or invalid bytes stop `run` before confirmation.

## Usage

```sh
# List removable candidates (read-only)
nclr ls

# Identify a device (read-only)
nclr info /dev/sdb
nclr info -j /dev/sdb

# Generate a plan (read-only); the plan pins fingerprint + plan hash
nclr plan -l best /dev/sdb > card.plan.json

# Execute a fixed plan (destructive; requires root for real block devices)
sudo nclr run --plan card.plan.json -j > card.report.json

# One-shot interactive run (confirmation token required unless --yes)
sudo nclr run -l best /dev/sdb

# Non-destructive assessment
nclr check -j /dev/sdb

# Resume after an interruption (SIGINT / power loss)
sudo nclr resume /var/lib/nclr/run/<plan-id>.state --yes
```

### Test without root (any Unix, including macOS)

Regular files act as pseudo-devices. Sim images model NAND behavior
(FBB, old RBB, OP space, D2 obsolete pages, failure injection, capacity
alias, internal power cycling, a self-running SANITIZE, and the full
controller reinitialization path):

```sh
target/debug/nclr-sim init --out /tmp/sim.img --id test-001

# Controller reinitialization (C3): BBT capture, old RBB per-block erase,
# ECC qualification, new BBT/FTL/spare rebuild, service-mode re-enumeration.
NCLR_PROFILE_DIR=profiles target/debug/nclr run -l controller /tmp/sim.img --yes -j \
  | jq '{result, achieved_grade, health_grade}'
# => ok, C3, H2

# Weak blocks (ECC-corrupt) are isolated and the capacity is reduced
# (documented, not a failure).
target/debug/nclr-sim init --out /tmp/weak.img --ecc-corrupt 1,3,7
target/debug/nclr run -l controller /tmp/weak.img --yes -j | jq .health_grade
# => H1 (weak blocks isolated), result degraded, grade C3 qualified

# Device-level erase (C2): the sim models SANITIZE with progress monitoring.
target/debug/nclr run -l device /tmp/sim.img --yes -j | jq '{result, achieved_grade}'

# Fault injection: an FTL commit failure is a hard recovery boundary and
# never switches erase methods after controller work has started.
target/debug/nclr-sim init --out /tmp/bad.img --fail-ftl-commit
target/debug/nclr run -l controller /tmp/bad.img --yes -j | jq '{result, achieved_grade}'

# LBA-only path (explicit level)
target/debug/nclr run -l lba /tmp/sim.img --yes -j | jq .result

# Protected Area (D5): the last N blocks are reserved and never erased;
# the report marks them unreachable (documented exclusion).
target/debug/nclr-sim init --out /tmp/pa.img --protected-area-blocks 2
target/debug/nclr run -l physical /tmp/pa.img --yes -j | jq '.residual'
# => documented-exclusion

# Read-only SD vendor health query (profile-gated, CMD56-equivalent)
target/debug/nclr check -j /tmp/sim.img | jq .vendor_health

# Research tooling (separate package)
target/debug/nclr-lab decode "48 03 00 00 00 02"
target/debug/nclr-lab profile --new --family sim --controller ctlr-1
target/debug/nclr-lab trace factory-tool.pcapng -o factory-tool.ndjson
target/debug/nclr-lab artifact verify artifact.toml --store controller-artifacts
target/debug/nclr-lab recipe --profile exact-production.toml --file recipe.json
```

### Machine-observable results

```sh
# stdout carries ONLY the final report JSON (with -j)
jq '{result, achieved_grade, grade_qualified, residual, health_grade,
     final_state, postcheck}' card.report.json

# long runs: NDJSON events (including device-erase progress)
nclr run --plan card.plan.json --events-fd 9 9> events.ndjson
```

## Exit codes

| Code | Meaning |
|-----:|---------|
| 0    | requested reach achieved, post-verification passed |
| 1    | completed but degraded (residual risk, H1, or unmet min level) |
| 2    | no safe path / requested level cannot be planned |
| 64   | usage error |
| 69   | backend or external capability unavailable |
| 74   | device I/O or protocol error |
| 75   | interrupted (resumable; journal left behind) |
| 77   | permission / safety interlock rejection |
| 78   | invalid profile, plan, signature or schema |

## Levels and grades

`-l` selects the processing level: `best` (default), `lba` (C1),
`device` (C2), `controller` (C3), `physical` (C4). The sim backend
certifies C3/C4 in this build; on real block devices C1 (LBA) and C2
(device erase, e.g. SCSI SANITIZE) are reachable, while C3/C4 require a
certified controller/physical profile and fail at plan time with exit 2
when unavailable. `--min-level` sets the floor the run result must meet.

Evidence is graded independently:

- **C1 (LBA Cleared)**: full-logical-space overwrite + power-cycle read
  verification. Without a power cycle (`--power-cycle CMD`, or a sim device),
  the run is `degraded` with residual `documented-exclusion` — the grade is
  reported but not `qualified`.
- **C2 (Device User Area Erased)**: a documented device-level erase (SANITIZE
  BLOCK ERASE / SD full-range ERASE) completed, verified by a full blank
  sweep + signature check + power cycle + stable re-enumeration. The erase
  scope (D0-D2) comes from the backend's documented coverage. UNMAP/discard
  is never C2 evidence. D3/D4 remain `unreachable`.
- **C3 (Controller Reinitialized)**: old BBT captured before any erase, old
  RBBs individually erased (per-block results preserved, `historical_rbb`
  retained), FBB preserved, weak/failed blocks isolated, new BBT + spare +
  FTL committed with a fresh generation (old FTL invalidated), capacity
  stable across the power cycle. Per-block erase failures and final-erase
  failures are recorded as `erase-failed` residual.
- **C4 (Physical Scope Accounted)**: every non-FBB data-bearing physical
  block enumerated and categorized, each erased with an individual result
  (failures are recorded, the scope stays fully accounted), followed by a
  complete raw page + OOB sweep before any new BBT/FTL metadata is committed.
  Every address is attempted, including FBB, preserved and unknown blocks;
  only their declared exclusion from the blank-byte requirement differs.
  Any unreadable, uncorrectable or non-blank page in the erased scope makes
  C4 unqualified. FBB is preserved, new BBT/FTL is committed and capacity is
  checked after power cycling. C4 is only claimed by backends that passed the
  independent physical validation (TEST-001); the sim family holds that
  certification in this build.
- **Residual**: `none-known`, `documented-exclusion`, `unreachable`,
  `erase-failed`, `unknown-scope`. Out-of-scope reach boundaries
  (`unreachable`) are documented; any other residual degrades the result.
- **H0–H3**: H2 = full LBA verification, power-cycle consistency, stable
  capacity, no uncorrectable errors, adequate spare. H3 requires extended
  lab tests and is never auto-assigned.

## Safety model

- Two-stage confirmation: the run token is `{device}-{fingerprint8}-{capacity}`
  (e.g. `sdb-1d4a8c2e-31GB`); `--yes` skips the prompt but never the checks.
- Plan fingerprint, physical path and capacity are re-verified before any
  destructive action.
- System disk protection is absolute in this build (no single-flag unlock).
- Per-device `flock` in `/run/lock/nclr` (Linux) or `$XDG_RUNTIME_DIR`,
  falling back to `TMPDIR` (elsewhere).
- Journal hash chain rejects tampered state files; `resume` re-verifies the
  device fingerprint, queries backend status, and rebuilds evidence from the
  journal before continuing.
- C2 plans embed their L1 fallback; switching plans is journaled
  (`fallback-plan` record) so a later resume continues in the right context.

## Platform support

| Component            | Linux (x86_64/arm64)       | macOS                         |
|----------------------|----------------------------|-------------------------------|
| `ls`/`info`          | sysfs (block, mmc, sg, usb) | diskutil / IOKit info         |
| `plan`/`run`         | /dev/sdX, /dev/mmcblkN     | /dev/rdiskN (raw, needs root) |
| SCSI SANITIZE (C2)   | `nclr-scsi` (SG_IO)        | — (falls back to lba, C1)     |
| SD full-range ERASE  | `nclr-sd-native` (MMC)     | — (falls back to lba, C1)     |
| controller reinit    | `nclr-controller` (profiles) | sim reference only         |
| sim/file targets     | full                       | full                          |
| power cycle          | `--power-cycle CMD` / sim  | `--power-cycle CMD` / sim     |

Note: real block devices require root and an unmounted, non-system device.
The Linux SCSI/MMC ioctl paths are validated with byte-level fixture tests
and the sim-driven C2/C3 flows; on-wire validation against real hardware is a
documented Linux follow-up (`scsi_debug` or a USB stick / SD card). The
mount/swap interlocks are fail-closed: an unreadable mount table or
`/proc/swaps` fails identification/preflight instead of being treated as
"not in use".

## Site policy config (`--config FILE`, default `/etc/nclr/nclr.toml`)

The default behavior is safe with no config file. A site policy may limit:

```toml
allowed_backends = ["sim", "lba", "scsi", "sd-native", "controller"]
minimum_level = "device"                # planning level floor
[spare_ratio]                           # profile spare-ratio clamp
min = 0.03
max = 0.10
[power_cycle]
allowlist = ["/usr/local/bin/hubctl", "true"]
```

Backend selection, the planning level floor, spare-ratio clamping and the
`--power-cycle` command are enforced against it. `--backend-timeout SECS`
kills hung backend calls (interrupted + resumable journal; SAFE-003).

## Report schema and summary

JSON outputs are self-describing: devices use `nclr.device.v1`, plans
`nclr.plan.v1`, reports `nclr.report.v1`, check output `nclr.check.v1` and
the redacted summary `nclr.summary.v1`. Reports carry coverage entries with
a `final` state per domain, an `ftl` object for controller paths
(rebuilt/spare-ratio/generations), a `bbt_summary` (old/new generations,
FBB/RBB counts, per-RBB erase results) and `postcheck.recipe` values `P1`
(physical complete test), `P2` (controller/device rebuild) or `L1` (LBA
fallback). Every action records `duration_ms`, `retries` (always 0: a
timed-out or failed action is never resent without a status query) and LBA
sweeps measure `throughput_mbps`/`flush_latency_ms`. Plans declare their
power requirements (`power` block: required power, direct port, external
control, power-cycle count, UPS, USB hub, temperature limit) and a safety
confirmation checklist. `ls -j` prints
`{"schema": "nclr.device.v1", "devices": [...]}`. Read-only/write-protected
devices (Linux sysfs `ro`) are refused for destructive runs.

## Bounded write test (`nclr check --scratch-range START:SECTORS --yes`)

`check` is read-only by default. An explicit scratch range enables a bounded
write test: the range is saved, PRBS-written, flushed, verified and restored
(64 MiB cap; mounted/holder devices are refused; `--yes` is required).

## Scope and known limits

- Phases 0-4 and the hardware-free Phase 5/6 pieces are implemented:
  Protected Area (D5) handling and a profile-gated read-only SD vendor
  health query (CMD56-equivalent) are modeled and tested; real SD CMD56
  vendor profiles, reader pass-through and SD controller LLF require
  hardware and certified vendor documentation.
- `nclr-lab` (research tooling: artifact/cap/controller/decode/diff/infer/
  profile/recipe/replay/trace) is separated from destructive handlers. Artifact
  acquisition pins HTTPS source, terms, size, SHA-256, format and exact
  hardware tuple without redistributing vendor bytes. Trace conversion runs
  on macOS with Wireshark/TShark, validates USB BOT CBW/CSW framing, and
  redacts data payloads by default. See
  `docs/controller-artifact-workflow.md`.
- Phase 7 hardening: `--scratch-range` bounded write test, site policy
  config (`--config`), backend call timeout (`--backend-timeout`), SIGPIPE-safe
  broken-pipe behavior, status heartbeat (stderr + events FD) for stalled
  long-running operations, the
  acceptance suite (`crates/nclr-backends/tests/acceptance.rs`), wear
  regression (sim P/E accounting, stable repeated plans), `nclr-backend(7)`
  protocol manual, CI (`.github/workflows/ci.yml`), and a Linux hardware
  validation guide (`docs/hardware-validation.md`).
- C4 applies to the certified sim family; real-vendor physical backends
  need their own certified profiles + HIL.
- Real vendor controller execution (Phison, SMI, Alcor, SanDisk Cruzer) requires a certified
  production profile and hardware-in-the-loop qualification. The compiled
  recipe engine implements the erase/rebuild primitives, but capability is
  exposed only when exact geometry, metadata layout, authenticated protocol
  recipe/trace, qualification report and clean-room/runtime provenance all
  match. Without the trusted exact profile, `-l controller` fails at plan time
  (exit 2); without its pinned artifact bytes, `run` fails before confirmation.
- LBA processing cannot prove that OP/spare blocks, retired blocks or
  controller metadata were reached: D1-D4 are reported as `unreachable` and
  the reach ceiling is C1.
- A device erase's documented scope comes from the backend capability data
  (SANITIZE per SBC-4, SD full-range ERASE per the SD spec); scope is never
  assumed from a GOOD status alone.
- `nclr` never claims standards compliance (Clear/Purge/Destroy), suitability
  for resale or any business judgment.
- Power cycling real USB media generally requires an external controlled hub
  or power switch (`--power-cycle`); without it the run degrades honestly.

## Development

```sh
cargo test            # unit + backend protocol + e2e (no root needed)
cargo clippy --all-targets
```

The e2e suite (`tests/e2e.rs`) drives the real binaries against sim images
and plain files: C1/C2/C3/C4 plan/run/report roundtrips, the D2-reach
distinction between LBA and device erase, sanitize failure → fallback, the
pre-destructive capability downgrade and the prohibition on falling back
after controller/physical processing starts, old-RBB
erase failures and unresolvable reservations as residuals, capacity
reduction from weak-block isolation, interrupt → resume (with journal-evidence
rebuild), profile-mismatch rejection, fingerprint-mismatch rejection,
`--evidence-dir` output, the TEST-001 certification fixture (independent
raw-page validation bypassing the FTL), exit-code mapping, stdout/stderr
separation, the events FD, and complete/partial physical salvage images with
explicit unreadable-page holes.
