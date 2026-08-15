#!/bin/sh
set -eu

UPSTREAM_COMMIT=d9415a8d5c62354d09cd6410754c9d8bb65e164f
UPSTREAM_SHA256=25417e19b275a28e7e9865b36ae6ef3932d7f2d872a9b74e91361887261cd278
UPSTREAM_URL="https://github.com/flowswitch/phison/archive/${UPSTREAM_COMMIT}.tar.gz"
EXPECTED_SDCC_VERSION=4.6.0
EXPECTED_SOURCE_BINARY_BYTES=11874
EXPECTED_SOURCE_BINARY_SHA256=5c429132251f389983c7164c0bbcdbbbcbd032fa1cb5f47a8164a72e1408e306
EXPECTED_IMAGE_BYTES=12800
EXPECTED_IMAGE_SHA256=30a864283590d1acc4a3fa50b521f0ca78950c5958cc81adfd540e8d2e2586b6

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repository_dir=$(CDPATH= cd -- "$script_dir/../.." && pwd)
output="$repository_dir/build/phison-ps2303/nclr-ps2303.btpram"
source_archive=

while [ "$#" -gt 0 ]; do
    case "$1" in
        --source)
            [ "$#" -ge 2 ] || { echo "build.sh: --source requires a path" >&2; exit 64; }
            source_archive=$2
            shift 2
            ;;
        --output)
            [ "$#" -ge 2 ] || { echo "build.sh: --output requires a path" >&2; exit 64; }
            output=$2
            shift 2
            ;;
        *)
            echo "build.sh: unknown argument: $1" >&2
            exit 64
            ;;
    esac
done

for tool in shasum tar sed sdcc makebin python3; do
    command -v "$tool" >/dev/null 2>&1 || {
        echo "build.sh: required tool is unavailable: $tool" >&2
        exit 69
    }
done

sdcc_version=$(sdcc --version | sed -n '1{s/^SDCC : .* \([0-9][0-9.]*\) #.*/\1/p;}')
if [ "$sdcc_version" != "$EXPECTED_SDCC_VERSION" ]; then
    echo "build.sh: SDCC $EXPECTED_SDCC_VERSION is required, found ${sdcc_version:-unknown}" >&2
    exit 69
fi
if [ -e "$output" ] || [ -e "$output.json" ]; then
    echo "build.sh: refusing to overwrite an existing output: $output" >&2
    exit 74
fi

temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/nclr-ps2303.XXXXXX")
trap 'rm -rf "$temporary_dir"' EXIT HUP INT TERM

if [ -z "$source_archive" ]; then
    source_archive="$temporary_dir/upstream.tar.gz"
    curl --proto '=https' --tlsv1.2 -fL "$UPSTREAM_URL" -o "$source_archive"
fi
actual_sha256=$(shasum -a 256 "$source_archive" | sed 's/ .*//')
if [ "$actual_sha256" != "$UPSTREAM_SHA256" ]; then
    echo "build.sh: upstream SHA-256 mismatch: $actual_sha256" >&2
    exit 65
fi

tar -xzf "$source_archive" -C "$temporary_dir"
mcu="$temporary_dir/phison-${UPSTREAM_COMMIT}/mcu"
cp "$script_dir/src/nclr_scsi.c" "$mcu/scsi.c"
cp "$script_dir/src/nclr_usb_dma.c" "$mcu/nclr_usb_dma.c"
cp "$script_dir/src/nclr_usb_dma.h" "$mcu/nclr_usb_dma.h"

sed -i '' -E 's/__interrupt ([A-Z0-9_]+)/__interrupt (\1)/g' "$mcu"/*.c
sed -i '' -E 's/__interrupt ([A-Z0-9_]+)/__interrupt (\1)/g' "$mcu"/*.h
sed -i '' -E 's/^((static )?(void|BOOL) [A-Za-z0-9_]+)\(\)$/\1(void)/' "$mcu"/*.c
sed -i '' -E 's/^(void [A-Za-z0-9_]+)\(\);$/\1(void);/' "$mcu"/*.h
sed -i '' -E 's/, BYTE r8\)/)/' "$mcu/usb.c" "$mcu/usb.h"
sed -i '' 's/for(b=0; b<250; b++);/for (b = 0; b != (BYTE)250; ++b);/' "$mcu/usb.c"

mkdir "$mcu/build"
for source in main led ticks usb serial scsi ch9 nclr_usb_dma; do
    sdcc -mmcs51 --model-small --stack-auto --std-c11 -I"$mcu" \
        -c -o "$mcu/build/$source.rel" "$mcu/$source.c"
done
sdcc -mmcs51 --model-small --stack-auto --std-c11 --xram-loc 0x6000 \
    -o "$mcu/build/nclr-ps2303.ihx" \
    "$mcu/build/main.rel" \
    "$mcu/build/led.rel" \
    "$mcu/build/ticks.rel" \
    "$mcu/build/usb.rel" \
    "$mcu/build/serial.rel" \
    "$mcu/build/scsi.rel" \
    "$mcu/build/ch9.rel" \
    "$mcu/build/nclr_usb_dma.rel"
makebin -p "$mcu/build/nclr-ps2303.ihx" "$mcu/build/nclr-ps2303.bin"

python3 "$script_dir/pack_btpram.py" \
    --binary "$mcu/build/nclr-ps2303.bin" \
    --output "$output" \
    --upstream-sha256 "$UPSTREAM_SHA256" \
    --sdcc-version "$sdcc_version" \
    --expected-source-binary-bytes "$EXPECTED_SOURCE_BINARY_BYTES" \
    --expected-source-binary-sha256 "$EXPECTED_SOURCE_BINARY_SHA256" \
    --expected-image-bytes "$EXPECTED_IMAGE_BYTES" \
    --expected-image-sha256 "$EXPECTED_IMAGE_SHA256"
echo "built $output"
