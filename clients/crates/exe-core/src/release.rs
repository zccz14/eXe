//! The signed release manifest: what a device is willing to believe about a new
//! version.
//!
//! The relay couriers binaries exactly as it couriers calls, so a device must
//! not take its word for what the newest version is. It reads `manifest.json`
//! and accepts it only when the detached signature beside it verifies against
//! the release key compiled into this binary. A compromised relay can withhold
//! an upgrade — devices stay where they are — and nothing else.
use base64::{engine::general_purpose::STANDARD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

/// The signature covers this prefix and then the manifest bytes, so the release
/// key can never be replayed as a signature over anything else eXe signs.
pub const MANIFEST_CONTEXT: &[u8] = b"exe release manifest v1\n";

/// The public half of the release key. The private half lives with whoever
/// publishes releases, and in the `EXE_RELEASE_KEY` repository secret; losing it
/// stops *automatic* upgrades only — installing by hand still works.
pub const RELEASE_KEY: &str = "8cbc694c36104a4ffeef1a24f87ef89419bd94ef96e432ff1a71f3c22ae487ab";

/// One file in a release. `sha256` is what the updater checks the download
/// against, and it is covered by the signature like everything else here.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseFile {
    pub name: String,
    #[serde(default)]
    pub size: u64,
    #[serde(default)]
    pub sha256: Option<String>,
}

/// `manifest.json`, as published next to the archives by `release.yml`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReleaseManifest {
    pub version: String,
    #[serde(default)]
    pub tag: String,
    #[serde(default)]
    pub files: Vec<ReleaseFile>,
}

impl ReleaseManifest {
    pub fn file(&self, name: &str) -> Option<&ReleaseFile> {
        self.files.iter().find(|file| file.name == name)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReleaseError {
    #[error("this binary carries no usable release key")]
    Key,
    #[error("the signature is not base64 of 64 bytes")]
    Signature,
    #[error("the manifest was not signed by the eXe release key")]
    Unsigned,
    #[error("the manifest is not valid JSON: {0}")]
    Json(String),
}

pub fn release_key() -> Result<VerifyingKey, ReleaseError> {
    let bytes = hex::decode(RELEASE_KEY).map_err(|_| ReleaseError::Key)?;
    let array: [u8; 32] = bytes.try_into().map_err(|_| ReleaseError::Key)?;
    VerifyingKey::from_bytes(&array).map_err(|_| ReleaseError::Key)
}

/// Verifies the detached signature over the exact bytes of `manifest.json` and
/// then parses them — never the other way round: parsing first would mean acting
/// on a document before knowing who wrote it.
pub fn verify_manifest(manifest: &[u8], signature: &str) -> Result<ReleaseManifest, ReleaseError> {
    verify_with(&release_key()?, manifest, signature)
}

fn verify_with(
    key: &VerifyingKey,
    manifest: &[u8],
    signature: &str,
) -> Result<ReleaseManifest, ReleaseError> {
    let raw = STANDARD
        .decode(signature.trim())
        .map_err(|_| ReleaseError::Signature)?;
    let signature = Signature::from_slice(&raw).map_err(|_| ReleaseError::Signature)?;
    let mut signed = MANIFEST_CONTEXT.to_vec();
    signed.extend_from_slice(manifest);
    key.verify(&signed, &signature)
        .map_err(|_| ReleaseError::Unsigned)?;
    serde_json::from_slice(manifest).map_err(|error| ReleaseError::Json(error.to_string()))
}

/// `1.2.3` as numbers. Anything else is not a version this updater will move to:
/// a release that cannot be ordered cannot be compared with what is running.
pub fn version_numbers(version: &str) -> Option<[u64; 3]> {
    let core = version.trim().trim_start_matches('v');
    let core = core.split(['-', '+']).next().unwrap_or_default();
    let mut parts = core.split('.');
    let mut numbers = [0u64; 3];
    for slot in numbers.iter_mut() {
        *slot = parts.next()?.parse().ok()?;
    }
    parts.next().is_none().then_some(numbers)
}

pub fn is_newer(candidate: &str, current: &str) -> bool {
    match (version_numbers(candidate), version_numbers(current)) {
        (Some(candidate), Some(current)) => candidate > current,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    const MANIFEST: &str = r#"{"version":"9.9.9","tag":"v9.9.9","files":[{"name":"exe-x.bin","size":3,"sha256":"aa"}]}"#;

    fn signed(key: &SigningKey, manifest: &str) -> String {
        let mut bytes = MANIFEST_CONTEXT.to_vec();
        bytes.extend_from_slice(manifest.as_bytes());
        STANDARD.encode(key.sign(&bytes).to_bytes())
    }

    #[test]
    fn the_binary_carries_a_usable_release_key() {
        release_key().expect("RELEASE_KEY is a hex Ed25519 public key");
    }

    #[test]
    fn a_signed_manifest_is_read() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let manifest = verify_with(
            &key.verifying_key(),
            MANIFEST.as_bytes(),
            &signed(&key, MANIFEST),
        )
        .expect("signature verifies");
        assert_eq!(manifest.version, "9.9.9");
        assert_eq!(
            manifest.file("exe-x.bin").unwrap().sha256.as_deref(),
            Some("aa")
        );
    }

    #[test]
    fn one_changed_byte_is_refused() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        let signature = signed(&key, MANIFEST);
        let tampered = MANIFEST.replace("9.9.9", "9.9.8");
        assert!(matches!(
            verify_with(&key.verifying_key(), tampered.as_bytes(), &signature),
            Err(ReleaseError::Unsigned)
        ));
        assert!(matches!(
            verify_with(&key.verifying_key(), MANIFEST.as_bytes(), "not base64"),
            Err(ReleaseError::Signature)
        ));
    }

    #[test]
    fn the_context_prefix_is_part_of_what_is_signed() {
        let key = SigningKey::from_bytes(&[7u8; 32]);
        // A signature over the bare manifest (no domain separation) must not pass.
        let bare = STANDARD.encode(key.sign(MANIFEST.as_bytes()).to_bytes());
        assert!(matches!(
            verify_with(&key.verifying_key(), MANIFEST.as_bytes(), &bare),
            Err(ReleaseError::Unsigned)
        ));
    }

    #[test]
    fn versions_order_numerically_not_alphabetically() {
        assert!(is_newer("0.10.0", "0.9.9"));
        assert!(is_newer("1.0.0", "0.99.99"));
        assert!(!is_newer("0.6.4", "0.6.4"));
        assert!(!is_newer("0.6.3", "0.6.4"));
        assert!(is_newer("v0.7.1", "0.7.0"), "a leading v is tolerated");
        assert!(!is_newer("nightly", "0.6.4"), "unorderable is never newer");
        assert_eq!(version_numbers("0.7.1"), Some([0, 7, 1]));
        assert_eq!(version_numbers("0.7"), None);
    }
}
