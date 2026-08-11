#!/bin/sh
# Generate an SPDX-ish SBOM for the nclr release artifacts.
# Usage: ./packaging/sbom.sh [OUTPUT]
set -eu

OUT="${1:-build/nclr.sbom.spdx}"
mkdir -p "$(dirname "$OUT")"

PROJECT="nclr"
VERSION="0.1.0"
LOCK_SHA="$(shasum -a 256 Cargo.lock | cut -d' ' -f1)"
DOCUMENT_NAMESPACE="https://github.com/t-koba/nclr/spdx/${VERSION}/${LOCK_SHA}"
TODAY="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

{
  cat <<EOF
SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: ${PROJECT}-${VERSION}
DocumentNamespace: ${DOCUMENT_NAMESPACE}
Creator: Tool: nclr-sbom.sh
Created: ${TODAY}

## Package: ${PROJECT}
SPDXID: SPDXRef-Package-nclr
PackageName: ${PROJECT}
PackageVersion: ${VERSION}
PackageDownloadLocation: NOASSERTION
PackageLicenseConcluded: MIT OR Apache-2.0
FilesAnalyzed: false
PackageCopyrightText: NOASSERTION

Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-nclr

EOF

  # Cargo.lock is stanza-oriented: emit the completed previous stanza when
  # the next [[package]] begins, and flush the final stanza at EOF.
  awk '
    function emit(    id) {
      if (name == "" || version == "") return
      id = name "-" version
      gsub(/[^A-Za-z0-9.-]/, "-", id)
      print "SPDXID: SPDXRef-Package-" id
      print "PackageName: " name
      print "PackageVersion: " version
      print "PackageDownloadLocation: " (source == "" ? "NOASSERTION" : source)
      print "PackageLicenseConcluded: NOASSERTION"
      print "FilesAnalyzed: false"
      print "PackageCopyrightText: NOASSERTION"
      print "Relationship: SPDXRef-Package-nclr DEPENDS_ON SPDXRef-Package-" id
      print ""
    }
    /^\[\[package\]\]$/ { emit(); name = version = source = ""; next }
    /^name = / { name = $3; gsub(/"/, "", name); next }
    /^version = / { version = $3; gsub(/"/, "", version); next }
    /^source = / { source = $3; gsub(/"/, "", source); next }
    END { emit() }
  ' Cargo.lock
} > "$OUT"

n="$(awk '/^SPDXID: SPDXRef-Package-/{c++} END{print c-1}' "$OUT")"
echo "wrote $OUT ($n packages)"
