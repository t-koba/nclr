#!/bin/sh
# Install nclr (packaging layout).
# Usage: sudo ./install.sh [PREFIX]
set -eu

PREFIX="${1:-/usr/local}"
LIBEXEC="$PREFIX/libexec/nclr"
BINDIR="$PREFIX/bin"
MANDIR="$PREFIX/share/man/man1"

echo "building release binaries..."
cargo build --workspace --release

install -d "$LIBEXEC" "$BINDIR" "$MANDIR"
install -m 0755 target/release/nclr      "$BINDIR/nclr"
install -m 0755 target/release/nclr-lba  "$LIBEXEC/nclr-lba"
install -m 0755 target/release/nclr-sim  "$LIBEXEC/nclr-sim"
if [ "$(uname -s)" = "Linux" ]; then
    install -m 0755 target/release/nclr-scsi "$LIBEXEC/nclr-scsi"
    install -m 0755 target/release/nclr-sd-native "$LIBEXEC/nclr-sd-native"
    install -m 0755 target/release/nclr-controller "$LIBEXEC/nclr-controller"
fi
install -m 0644 man/nclr.1               "$MANDIR/nclr.1"
install -m 0644 man/nclr-lab.1           "$MANDIR/nclr-lab.1"
install -d "$PREFIX/share/man/man7"
install -m 0644 man/nclr-backend.7       "$PREFIX/share/man/man7/nclr-backend.7"
install -m 0755 target/release/nclr-lab  "$BINDIR/nclr-lab"
install -d "$PREFIX/share/nclr/profiles"
install -m 0644 profiles/*.toml "$PREFIX/share/nclr/profiles/"

echo "installed:"
echo "  $BINDIR/nclr"
echo "  $BINDIR/nclr-lab"
echo "  $LIBEXEC/nclr-lba"
echo "  $LIBEXEC/nclr-sim"
[ -f "$LIBEXEC/nclr-scsi" ] && echo "  $LIBEXEC/nclr-scsi (Linux)"
[ -f "$LIBEXEC/nclr-sd-native" ] && echo "  $LIBEXEC/nclr-sd-native (Linux)"
[ -f "$LIBEXEC/nclr-controller" ] && echo "  $LIBEXEC/nclr-controller (Linux)"
echo "  $MANDIR/nclr.1"
echo "  $MANDIR/nclr-lab.1"
echo "  $PREFIX/share/man/man7/nclr-backend.7"
echo "  $PREFIX/share/nclr/profiles/ (sim profile and read-only controller identification profiles)"
echo "backend search order: NCLR_BACKEND_DIR, --backend-dir, /usr/libexec/nclr, \$PREFIX/bin, \$PREFIX/libexec/nclr"
echo "production profile search order: /usr/share/nclr/profiles, \$PREFIX/share/nclr/profiles"
echo "package split: see packaging/stage.sh (nclr / nclr-backends-usb / nclr-backends-sd / nclr-lab / nclr-profiles)"
