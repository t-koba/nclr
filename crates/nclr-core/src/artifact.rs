//! External controller-artifact acquisition and verification.
//!
//! Vendor production tools and NAND-specific service loaders are not shipped
//! with nclr. A manifest pins the exact bytes, hardware tuple and source
//! terms. `nclr-lab` may fetch or import those bytes into a content-addressed
//! store; the destructive core only opens an already verified local file.

use crate::errors::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const ARTIFACT_MANIFEST_SCHEMA: u32 = 1;
pub const MAX_ARTIFACT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    ServiceLoader,
    FactoryToolExecutable,
    FactoryToolArchive,
    GeometryTable,
    ProtocolRecipe,
    ProtocolTrace,
    QualificationReport,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactFormat {
    PhisonBtPram,
    PhisonBtPramExtended,
    PortableExecutable,
    Archive,
    Json,
    Toml,
    Pcapng,
    Opaque,
}

/// Exact external bytes required by one controller profile.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ArtifactSpec {
    pub id: String,
    pub role: String,
    pub kind: ArtifactKind,
    pub format: ArtifactFormat,
    pub controller_id: String,
    pub firmware: String,
    pub nand_id: String,
    pub sha256: String,
    pub size_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub terms_url: Option<String>,
    pub redistributable: bool,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(deny_unknown_fields)]
pub struct ArtifactManifest {
    pub schema: u32,
    pub artifact: ArtifactSpec,
}

#[derive(Serialize, Clone, Debug)]
pub struct VerifiedArtifact {
    pub id: String,
    pub path: PathBuf,
    pub sha256: String,
    pub size_bytes: u64,
    pub format: ArtifactFormat,
}

fn safe_id(value: &str) -> bool {
    !value.is_empty()
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn digest_text(value: &str) -> Option<&str> {
    let value = value.strip_prefix("sha256:").unwrap_or(value);
    (value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit())).then_some(value)
}

fn validate_https_url(value: &str, field: &str) -> Result<()> {
    if value.chars().any(|c| c.is_control() || c.is_whitespace()) || !value.starts_with("https://")
    {
        return Err(Error::Invalid(format!(
            "artifact {field} must be an HTTPS URL without whitespace"
        )));
    }
    let authority = value["https://".len()..]
        .split('/')
        .next()
        .unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(Error::Invalid(format!(
            "artifact {field} must not contain URL user information"
        )));
    }
    Ok(())
}

pub fn validate_spec(spec: &ArtifactSpec) -> Result<()> {
    if !safe_id(&spec.id) || !safe_id(&spec.role) {
        return Err(Error::Invalid(
            "artifact id and role must be safe non-empty identifiers".into(),
        ));
    }
    if spec.controller_id.trim().is_empty()
        || spec.firmware.trim().is_empty()
        || spec.nand_id.trim().is_empty()
    {
        return Err(Error::Invalid(
            "artifact controller_id, firmware and nand_id must be exact and non-empty".into(),
        ));
    }
    if digest_text(&spec.sha256).is_none() {
        return Err(Error::Invalid(
            "artifact sha256 must be 64 hexadecimal characters".into(),
        ));
    }
    if spec.size_bytes == 0 || spec.size_bytes > MAX_ARTIFACT_BYTES {
        return Err(Error::Invalid(format!(
            "artifact size_bytes must be in 1..={MAX_ARTIFACT_BYTES}"
        )));
    }
    if let Some(url) = &spec.source_url {
        validate_https_url(url, "source_url")?;
    }
    if let Some(url) = &spec.terms_url {
        validate_https_url(url, "terms_url")?;
    }
    if !spec.redistributable && spec.terms_url.is_none() {
        return Err(Error::Invalid(
            "a non-redistributable artifact requires terms_url".into(),
        ));
    }
    match (&spec.kind, &spec.format) {
        (
            ArtifactKind::ServiceLoader,
            ArtifactFormat::PhisonBtPram | ArtifactFormat::PhisonBtPramExtended,
        )
        | (ArtifactKind::FactoryToolExecutable, ArtifactFormat::PortableExecutable)
        | (ArtifactKind::FactoryToolArchive, ArtifactFormat::Archive)
        | (ArtifactKind::GeometryTable, ArtifactFormat::Json | ArtifactFormat::Toml)
        | (ArtifactKind::ProtocolRecipe, ArtifactFormat::Json | ArtifactFormat::Toml)
        | (ArtifactKind::ProtocolTrace, ArtifactFormat::Pcapng)
        | (ArtifactKind::QualificationReport, ArtifactFormat::Json)
        | (_, ArtifactFormat::Opaque) => {}
        _ => {
            return Err(Error::Invalid(format!(
                "artifact kind {:?} is incompatible with format {:?}",
                spec.kind, spec.format
            )));
        }
    }
    Ok(())
}

pub fn load_manifest(path: &Path) -> Result<ArtifactManifest> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open(path).map_err(|e| {
        Error::io(
            format!("artifact manifest open {}", path.display()),
            Some(e),
        )
    })?;
    let metadata = file.metadata().map_err(|e| {
        Error::io(
            format!("artifact manifest stat {}", path.display()),
            Some(e),
        )
    })?;
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(Error::Invalid(format!(
            "artifact manifest {} must be a regular file no larger than {MAX_MANIFEST_BYTES} bytes",
            path.display()
        )));
    }
    let mut source = String::with_capacity(metadata.len() as usize);
    file.take(MAX_MANIFEST_BYTES + 1)
        .read_to_string(&mut source)
        .map_err(|e| {
            Error::io(
                format!("artifact manifest read {}", path.display()),
                Some(e),
            )
        })?;
    if source.len() as u64 > MAX_MANIFEST_BYTES {
        return Err(Error::Invalid(format!(
            "artifact manifest {} grew beyond {MAX_MANIFEST_BYTES} bytes while reading",
            path.display()
        )));
    }
    let manifest: ArtifactManifest = toml::from_str(&source)
        .map_err(|e| Error::Invalid(format!("artifact manifest {}: {e}", path.display())))?;
    if manifest.schema != ARTIFACT_MANIFEST_SCHEMA {
        return Err(Error::Invalid(format!(
            "artifact manifest {}: schema {} != {ARTIFACT_MANIFEST_SCHEMA}",
            path.display(),
            manifest.schema
        )));
    }
    validate_spec(&manifest.artifact)?;
    Ok(manifest)
}

pub fn store_path(store: &Path, spec: &ArtifactSpec) -> PathBuf {
    let digest = digest_text(&spec.sha256).unwrap_or(&spec.sha256);
    store.join(&spec.id).join(digest.to_ascii_lowercase())
}

fn inspect_format(file: &mut File, spec: &ArtifactSpec) -> Result<()> {
    file.seek(SeekFrom::Start(0))
        .map_err(|e| Error::io("seek artifact for format inspection", Some(e)))?;
    let mut head = [0u8; 64];
    let n = file
        .read(&mut head)
        .map_err(|e| Error::io("read artifact format header", Some(e)))?;
    match spec.format {
        ArtifactFormat::PhisonBtPram | ArtifactFormat::PhisonBtPramExtended => {
            if spec.size_bytes > 1024 * 1024 {
                return Err(Error::Invalid(
                    "Phison PRAM artifact exceeds the bounded 1 MiB parser limit".into(),
                ));
            }
            file.seek(SeekFrom::Start(0))
                .map_err(|e| Error::io("seek Phison PRAM artifact", Some(e)))?;
            let mut image = Vec::with_capacity(spec.size_bytes as usize);
            file.read_to_end(&mut image)
                .map_err(|e| Error::io("read Phison PRAM artifact", Some(e)))?;
            match spec.format {
                ArtifactFormat::PhisonBtPram => {
                    crate::controller_protocol::phison_pram_transfer_legacy(&image)?;
                }
                ArtifactFormat::PhisonBtPramExtended => {
                    crate::controller_protocol::phison_pram_transfer_extended(&image)?;
                }
                _ => unreachable!("matched Phison PRAM formats"),
            }
        }
        ArtifactFormat::PortableExecutable => {
            if n < 2 || &head[..2] != b"MZ" {
                return Err(Error::Invalid(
                    "factory-tool executable is not a PE image".into(),
                ));
            }
        }
        ArtifactFormat::Archive => {
            let known = (n >= 4 && &head[..4] == b"PK\x03\x04")
                || (n >= 7 && &head[..7] == b"Rar!\x1A\x07")
                || (n >= 6 && &head[..6] == b"7z\xBC\xAF\x27\x1C");
            if !known {
                return Err(Error::Invalid(
                    "factory-tool archive is not ZIP, RAR or 7z".into(),
                ));
            }
        }
        ArtifactFormat::Pcapng => {
            if n < 4 || head[..4] != [0x0A, 0x0D, 0x0D, 0x0A] {
                return Err(Error::Invalid("protocol trace is not pcapng".into()));
            }
        }
        ArtifactFormat::Json => {
            file.seek(SeekFrom::Start(0))
                .map_err(|e| Error::io("seek JSON artifact", Some(e)))?;
            let value: serde_json::Value = serde_json::from_reader(&mut *file)
                .map_err(|e| Error::Invalid(format!("artifact is not valid JSON: {e}")))?;
            if !value.is_object() && !value.is_array() {
                return Err(Error::Invalid(
                    "JSON artifact must contain an object or array".into(),
                ));
            }
        }
        ArtifactFormat::Toml => {
            file.seek(SeekFrom::Start(0))
                .map_err(|e| Error::io("seek TOML artifact", Some(e)))?;
            let mut source = String::new();
            file.read_to_string(&mut source)
                .map_err(|e| Error::io("read TOML artifact", Some(e)))?;
            source
                .parse::<toml::Value>()
                .map_err(|e| Error::Invalid(format!("artifact is not valid TOML: {e}")))?;
        }
        ArtifactFormat::Opaque => {}
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| Error::io("rewind verified artifact", Some(e)))?;
    Ok(())
}

pub fn verify_open_file(
    file: &mut File,
    path: &Path,
    spec: &ArtifactSpec,
) -> Result<VerifiedArtifact> {
    validate_spec(spec)?;
    let metadata = file
        .metadata()
        .map_err(|e| Error::io(format!("stat artifact {}", path.display()), Some(e)))?;
    if !metadata.is_file() || metadata.len() != spec.size_bytes {
        return Err(Error::Invalid(format!(
            "artifact {} size/type mismatch: expected {} regular-file bytes, got {}",
            path.display(),
            spec.size_bytes,
            metadata.len()
        )));
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|e| Error::io("seek artifact", Some(e)))?;
    let mut hash = Sha256::new();
    let mut total = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file
            .read(&mut buffer)
            .map_err(|e| Error::io("hash artifact", Some(e)))?;
        if n == 0 {
            break;
        }
        total = total
            .checked_add(n as u64)
            .ok_or_else(|| Error::Invalid("artifact byte count overflow".into()))?;
        if total > spec.size_bytes {
            return Err(Error::Invalid("artifact grew while being verified".into()));
        }
        hash.update(&buffer[..n]);
    }
    let actual = hex::encode(hash.finalize());
    let expected = digest_text(&spec.sha256).expect("validated artifact digest");
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(Error::Invalid(format!(
            "artifact {} digest mismatch: expected {expected}, got {actual}",
            path.display()
        )));
    }
    inspect_format(file, spec)?;
    Ok(VerifiedArtifact {
        id: spec.id.clone(),
        path: path.to_path_buf(),
        sha256: actual,
        size_bytes: total,
        format: spec.format.clone(),
    })
}

pub fn open_verified(path: &Path, spec: &ArtifactSpec) -> Result<(File, VerifiedArtifact)> {
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options
        .open(path)
        .map_err(|e| Error::io(format!("open artifact {}", path.display()), Some(e)))?;
    let verified = verify_open_file(&mut file, path, spec)?;
    Ok((file, verified))
}

pub fn find_verified(spec: &ArtifactSpec, stores: &[PathBuf]) -> Result<(File, VerifiedArtifact)> {
    for store in stores {
        let path = store_path(store, spec);
        if path.exists() {
            return open_verified(&path, spec);
        }
    }
    Err(Error::Invalid(format!(
        "artifact {} ({}) not found in {}",
        spec.id,
        spec.sha256,
        stores
            .iter()
            .map(|p| p.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    )))
}

fn prepare_destination(store: &Path, spec: &ArtifactSpec) -> Result<PathBuf> {
    let destination = store_path(store, spec);
    let parent = destination
        .parent()
        .ok_or_else(|| Error::Invalid("artifact store destination has no parent".into()))?;
    std::fs::create_dir_all(parent).map_err(|e| {
        Error::io(
            format!("create artifact store directory {}", parent.display()),
            Some(e),
        )
    })?;
    Ok(destination)
}

fn persist_verified_temp(
    mut temp: tempfile::NamedTempFile,
    destination: &Path,
    spec: &ArtifactSpec,
) -> Result<VerifiedArtifact> {
    temp.as_file_mut()
        .flush()
        .map_err(|e| Error::io("flush downloaded artifact", Some(e)))?;
    temp.as_file_mut()
        .sync_all()
        .map_err(|e| Error::io("sync downloaded artifact", Some(e)))?;
    let temp_path = temp.path().to_path_buf();
    let verified = verify_open_file(temp.as_file_mut(), &temp_path, spec)?;
    match temp.persist_noclobber(destination) {
        Ok(_) => {
            if let Some(parent) = destination.parent() {
                File::open(parent)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|e| {
                        Error::io(
                            format!("sync artifact store directory {}", parent.display()),
                            Some(e),
                        )
                    })?;
            }
            Ok(VerifiedArtifact {
                path: destination.to_path_buf(),
                ..verified
            })
        }
        Err(_e) if destination.exists() => {
            let (_, existing) = open_verified(destination, spec)?;
            Ok(existing)
        }
        Err(e) => Err(Error::io(
            format!("persist artifact {}", destination.display()),
            Some(e.error),
        )),
    }
}

pub fn import_file(source: &Path, store: &Path, spec: &ArtifactSpec) -> Result<VerifiedArtifact> {
    validate_spec(spec)?;
    let destination = prepare_destination(store, spec)?;
    if destination.exists() {
        return open_verified(&destination, spec).map(|(_, verified)| verified);
    }
    let (mut input, _) = open_verified(source, spec)?;
    let parent = destination.parent().expect("validated destination parent");
    let mut temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| Error::io("create artifact import temp file", Some(e)))?;
    std::io::copy(&mut input, temp.as_file_mut())
        .map_err(|e| Error::io("copy artifact into store", Some(e)))?;
    persist_verified_temp(temp, &destination, spec)
}

pub fn fetch_with_curl(
    curl: &Path,
    store: &Path,
    spec: &ArtifactSpec,
    accepted_source_terms: bool,
) -> Result<VerifiedArtifact> {
    validate_spec(spec)?;
    if !spec.redistributable && !accepted_source_terms {
        return Err(Error::Permission(format!(
            "artifact {} is non-redistributable; review {} and pass --accept-source-terms",
            spec.id,
            spec.terms_url.as_deref().unwrap_or("its source terms")
        )));
    }
    let url = spec
        .source_url
        .as_deref()
        .ok_or_else(|| Error::Invalid(format!("artifact {} has no source_url", spec.id)))?;
    validate_https_url(url, "source_url")?;
    let destination = prepare_destination(store, spec)?;
    if destination.exists() {
        return open_verified(&destination, spec).map(|(_, verified)| verified);
    }
    let parent = destination.parent().expect("validated destination parent");
    let temp = tempfile::NamedTempFile::new_in(parent)
        .map_err(|e| Error::io("create artifact download temp file", Some(e)))?;
    let status = std::process::Command::new(curl)
        .args([
            "--disable",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--tlsv1.2",
            "--fail",
            "--location",
            "--silent",
            "--show-error",
            "--max-time",
            "900",
            "--connect-timeout",
            "30",
            "--max-redirs",
            "5",
            "--max-filesize",
            &spec.size_bytes.to_string(),
            "--output",
        ])
        .arg(temp.path())
        .arg("--")
        .arg(url)
        .status()
        .map_err(|e| Error::io(format!("execute {}", curl.display()), Some(e)))?;
    if !status.success() {
        return Err(Error::Io(
            format!("artifact download failed with {status}"),
            None,
        ));
    }
    persist_verified_temp(temp, &destination, spec)
}

pub fn search_stores(explicit: &[PathBuf]) -> Vec<PathBuf> {
    let mut stores = explicit.to_vec();
    if let Ok(value) = std::env::var("NCLR_ARTIFACT_DIR") {
        stores.extend(std::env::split_paths(&value));
    }
    stores.push(PathBuf::from("/usr/share/nclr/artifacts"));
    let mut unique = Vec::with_capacity(stores.len());
    for store in stores {
        if !unique.contains(&store) {
            unique.push(store);
        }
    }
    unique
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(bytes: &[u8], format: ArtifactFormat, kind: ArtifactKind) -> ArtifactSpec {
        ArtifactSpec {
            id: "fixture-1".into(),
            role: "protocol-trace".into(),
            kind,
            format,
            controller_id: "controller-1".into(),
            firmware: "1.0".into(),
            nand_id: "aabbccddeeff".into(),
            sha256: hex::encode(Sha256::digest(bytes)),
            size_bytes: bytes.len() as u64,
            source_url: Some("https://example.invalid/artifact.bin".into()),
            terms_url: Some("https://example.invalid/terms".into()),
            redistributable: false,
        }
    }

    #[test]
    fn imports_and_reopens_content_addressed_artifact() {
        let bytes = b"\x0a\x0d\x0d\x0a fixture";
        let spec = spec(bytes, ArtifactFormat::Pcapng, ArtifactKind::ProtocolTrace);
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.pcapng");
        std::fs::write(&source, bytes).unwrap();
        let store = dir.path().join("store");
        let imported = import_file(&source, &store, &spec).unwrap();
        assert_eq!(imported.path, store_path(&store, &spec));
        let (_, reopened) = find_verified(&spec, &[store]).unwrap();
        assert_eq!(reopened.sha256, spec.sha256);
    }

    #[test]
    fn rejects_digest_size_format_and_insecure_source() {
        let bytes = b"not a capture";
        let mut bad = spec(bytes, ArtifactFormat::Pcapng, ArtifactKind::ProtocolTrace);
        bad.source_url = Some("http://example.invalid/a".into());
        assert!(validate_spec(&bad).is_err());
        bad.source_url = Some("https://example.invalid/a".into());
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.bin");
        std::fs::write(&source, bytes).unwrap();
        assert!(open_verified(&source, &bad).is_err());
        bad.format = ArtifactFormat::Opaque;
        bad.size_bytes += 1;
        assert!(open_verified(&source, &bad).is_err());
    }

    #[test]
    fn validates_phison_pram_structure_after_digest() {
        let mut image = vec![0u8; 0x200 + 0x400];
        image[..8].copy_from_slice(b"BtPramCd");
        image[0x10..0x14].copy_from_slice(&1u32.to_le_bytes());
        let spec = spec(
            &image,
            ArtifactFormat::PhisonBtPram,
            ArtifactKind::ServiceLoader,
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("loader.bin");
        std::fs::write(&path, image).unwrap();
        open_verified(&path, &spec).unwrap();
    }

    #[test]
    fn validates_extended_phison_pram_structure_after_digest() {
        let mut image = vec![0u8; 0x200 + 0x1c000];
        image[..8].copy_from_slice(b"BtPramCd");
        image[0x10..0x14].copy_from_slice(&[0x10, 0x10, 0x06, 0x00]);
        image[0x200] = 0x5a;
        let spec = spec(
            &image,
            ArtifactFormat::PhisonBtPramExtended,
            ArtifactKind::ServiceLoader,
        );
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("loader.bin");
        std::fs::write(&path, image).unwrap();
        open_verified(&path, &spec).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symbolic_link_artifacts() {
        use std::os::unix::fs::symlink;
        let bytes = b"\x0a\x0d\x0d\x0a fixture";
        let spec = spec(bytes, ArtifactFormat::Pcapng, ArtifactKind::ProtocolTrace);
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("target.pcapng");
        let link = dir.path().join("link.pcapng");
        std::fs::write(&target, bytes).unwrap();
        symlink(&target, &link).unwrap();
        assert!(open_verified(&link, &spec).is_err());
    }
}
