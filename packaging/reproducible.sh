#!/bin/sh
# Reproducible-build check: build twice in isolated target dirs and compare
# the produced binary digests.
# Usage: ./packaging/reproducible.sh
set -eu

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
T1="$(mktemp -d "${TMPDIR:-/tmp}/nclr-repro-1.XXXXXX")"
T2="$(mktemp -d "${TMPDIR:-/tmp}/nclr-repro-2.XXXXXX")"
cleanup() {
    rm -rf "$T1" "$T2"
}
trap cleanup EXIT HUP INT TERM

cd "$ROOT"
echo "build 1..."
CARGO_TARGET_DIR="$T1" cargo build --workspace --release -q
echo "build 2..."
CARGO_TARGET_DIR="$T2" cargo build --workspace --release -q

fail=0
for bin in nclr nclr-lab nclr-lba nclr-sim nclr-scsi nclr-sd-native nclr-controller; do
    if [ ! -f "$T1/release/$bin" ]; then
        # Optional platform binaries may be absent from the selected target.
        echo "skip (not built on this platform): $bin"
        continue
    fi
    h1="$(shasum -a 256 "$T1/release/$bin" | cut -d' ' -f1)"
    h2="$(shasum -a 256 "$T2/release/$bin" | cut -d' ' -f1)"
    if [ "$h1" = "$h2" ]; then
        echo "reproducible: $bin $h1"
    else
        echo "DIFFERS: $bin"
        echo "  build1: $h1"
        echo "  build2: $h2"
        fail=1
    fi
done
[ "$fail" = 0 ] || exit 1
echo "all binaries reproducible"
