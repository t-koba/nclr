#!/usr/bin/env python3
"""Pack one SDCC binary into the documented PS2303 BtPramCd container."""

import argparse
import hashlib
import json
import os
import pathlib
import struct


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", required=True, type=pathlib.Path)
    parser.add_argument("--output", required=True, type=pathlib.Path)
    parser.add_argument("--upstream-sha256", required=True)
    parser.add_argument("--sdcc-version", required=True)
    parser.add_argument("--expected-source-binary-bytes", required=True, type=int)
    parser.add_argument("--expected-source-binary-sha256", required=True)
    parser.add_argument("--expected-image-bytes", required=True, type=int)
    parser.add_argument("--expected-image-sha256", required=True)
    args = parser.parse_args()

    binary = args.binary.read_bytes()
    if not binary or len(binary) > 32768:
        raise SystemExit("loader binary must be in 1..=32768 bytes")
    binary_sha256 = digest(binary)
    if (
        len(binary) != args.expected_source_binary_bytes
        or binary_sha256 != args.expected_source_binary_sha256
    ):
        raise SystemExit(
            "loader source binary differs from the reviewed reproducible build: "
            f"bytes={len(binary)} sha256={binary_sha256}"
        )
    padded_size = (len(binary) + 1023) // 1024 * 1024
    pages = padded_size // 1024
    header = b"BtPramCd" + bytes(8) + struct.pack("<I", pages) + bytes(0x1EC)
    image = header + binary + bytes(padded_size - len(binary))
    if len(header) != 512:
        raise SystemExit("internal BtPramCd header length error")
    image_sha256 = digest(image)
    if len(image) != args.expected_image_bytes or image_sha256 != args.expected_image_sha256:
        raise SystemExit(
            "loader image differs from the reviewed reproducible build: "
            f"bytes={len(image)} sha256={image_sha256}"
        )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(args.output, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as output:
            output.write(image)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        args.output.unlink(missing_ok=True)
        raise

    manifest = {
        "schema": 1,
        "format": "phison-bt-pram",
        "controller": "PS2251-03 (PS2303)",
        "protocol": "nclr-ps2303-loader-v2",
        "source_binary_bytes": len(binary),
        "source_binary_sha256": binary_sha256,
        "body_bytes": padded_size,
        "body_pages_1k": pages,
        "image_bytes": len(image),
        "image_sha256": image_sha256,
        "upstream_archive_sha256": args.upstream_sha256,
        "sdcc_version": args.sdcc_version,
        "hil_qualified": False,
        "runtime_authorized": False,
    }
    manifest_path = args.output.with_suffix(args.output.suffix + ".json")
    fd = os.open(manifest_path, flags, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as output:
            json.dump(manifest, output, indent=2, sort_keys=True)
            output.write("\n")
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        manifest_path.unlink(missing_ok=True)
        raise


if __name__ == "__main__":
    main()
