#!/bin/sh
# Stage the release layout (package split):
#
#   nclr/                 core CLI + standard backends + man
#   nclr-backends-usb/    controller-specific USB backends
#   nclr-backends-sd/     controller/reader SD backends
#   nclr-lab/             research tooling
#   nclr-profiles/        production profile data
#
# Usage: ./packaging/stage.sh [DESTDIR]
set -eu

DEST="${1:-build/stage}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

case "$DEST" in
    ""|/|.|..)
        echo "refusing unsafe staging destination: $DEST" >&2
        exit 64
        ;;
esac

case "$DEST" in
    /*) ;;
    *) DEST="$ROOT/$DEST" ;;
esac

if [ "$DEST" = "$ROOT" ]; then
    echo "refusing to use the source root as the staging destination" >&2
    exit 64
fi

if [ -e "$DEST" ] && [ ! -f "$DEST/.nclr-stage-root" ]; then
    echo "refusing to replace unrecognized directory: $DEST" >&2
    exit 64
fi

cargo build --workspace --release

rm -rf "$DEST"
mkdir -p "$DEST"
: > "$DEST/.nclr-stage-root"

# nclr: core CLI + standard backends + manuals
mkdir -p \
    "$DEST/nclr/bin" \
    "$DEST/nclr/libexec/nclr" \
    "$DEST/nclr/share/man/man1" \
    "$DEST/nclr/share/man/man7"
install -m 0755 target/release/nclr      "$DEST/nclr/bin/nclr"
install -m 0755 target/release/nclr-lba  "$DEST/nclr/libexec/nclr/nclr-lba"
install -m 0755 target/release/nclr-sim  "$DEST/nclr/libexec/nclr/nclr-sim"
install -m 0644 man/nclr.1               "$DEST/nclr/share/man/man1/nclr.1"
install -m 0644 man/nclr-backend.7       "$DEST/nclr/share/man/man7/nclr-backend.7"

# USB controller execution uses SG_IO on Linux and SCSITask on macOS.
if [ "$(uname -s)" = "Linux" ] || [ "$(uname -s)" = "Darwin" ]; then
    mkdir -p "$DEST/nclr-backends-usb/libexec/nclr"
    install -m 0755 target/release/nclr-controller "$DEST/nclr-backends-usb/libexec/nclr/nclr-controller"
fi

# Raw standards-based SCSI/MMC backends remain Linux-only.
if [ "$(uname -s)" = "Linux" ]; then
    install -m 0755 target/release/nclr-scsi       "$DEST/nclr-backends-usb/libexec/nclr/nclr-scsi"

    mkdir -p "$DEST/nclr-backends-sd/libexec/nclr"
    install -m 0755 target/release/nclr-sd-native "$DEST/nclr-backends-sd/libexec/nclr/nclr-sd-native"
fi

# nclr-lab
mkdir -p "$DEST/nclr-lab/bin" "$DEST/nclr-lab/share/man/man1"
install -m 0755 target/release/nclr-lab "$DEST/nclr-lab/bin/nclr-lab"
install -m 0644 man/nclr-lab.1          "$DEST/nclr-lab/share/man/man1/nclr-lab.1"

# nclr-profiles
mkdir -p "$DEST/nclr-profiles/share/nclr/profiles"
install -m 0644 profiles/*.toml "$DEST/nclr-profiles/share/nclr/profiles/"

find "$DEST" -type f ! -name .nclr-stage-root | sort
