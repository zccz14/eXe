use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey as X25519Public, StaticSecret};

pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64u(value: &str) -> Result<Vec<u8>, CryptoError> {
    URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .map_err(|_| CryptoError::Encoding)
}

pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex_lower(&sha256(bytes))
}

pub fn hex_lower(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    OsRng.fill_bytes(&mut out);
    out
}

/// Length-prefixed field: u32be(len) || bytes.
pub fn push_lp(out: &mut Vec<u8>, bytes: &[u8]) {
    out.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(bytes);
}

pub fn push_u64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid base64url value")]
    Encoding,
    #[error("invalid key material")]
    Key,
    #[error("malformed signature")]
    Signature,
    #[error("sealed result could not be opened")]
    Open,
}

#[derive(Clone)]
pub struct KeyPair {
    pub seed: [u8; 32],
    pub public: [u8; 32],
}

impl KeyPair {
    pub fn generate() -> Self {
        let seed = random_bytes::<32>();
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        Self { seed, public }
    }
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        Self { seed, public }
    }
    pub fn signing_key(&self) -> SigningKey {
        SigningKey::from_bytes(&self.seed)
    }
    pub fn sign(&self, message: &[u8]) -> String {
        b64u(&self.signing_key().sign(message).to_bytes())
    }
}

pub fn verify_ed25519(public: &[u8], message: &[u8], signature: &str) -> Result<(), CryptoError> {
    let key: [u8; 32] = public.try_into().map_err(|_| CryptoError::Key)?;
    let verifying = VerifyingKey::from_bytes(&key).map_err(|_| CryptoError::Key)?;
    let sig_bytes = unb64u(signature)?;
    let signature = Signature::from_slice(&sig_bytes).map_err(|_| CryptoError::Signature)?;
    verifying
        .verify(message, &signature)
        .map_err(|_| CryptoError::Signature)
}

/// Curve25519 key agreement pair used as the result-encryption recipient.
#[derive(Clone)]
pub struct KexPair {
    pub secret: [u8; 32],
    pub public: [u8; 32],
}

impl KexPair {
    pub fn generate() -> Self {
        let secret = random_bytes::<32>();
        Self::from_secret(secret)
    }
    pub fn from_secret(secret: [u8; 32]) -> Self {
        let static_secret = StaticSecret::from(secret);
        let public = X25519Public::from(&static_secret).to_bytes();
        Self { secret, public }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedResult {
    pub v: u8,
    pub eph: String,
    pub nonce: String,
    pub ct: String,
}

fn seal_key(shared: &[u8; 32], call_id: &str, device_id: &str) -> [u8; 32] {
    let mut salt_input = Vec::new();
    salt_input.extend_from_slice(b"eXe/v1/result");
    push_lp(&mut salt_input, call_id.as_bytes());
    push_lp(&mut salt_input, device_id.as_bytes());
    let salt = sha256(&salt_input);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = [0u8; 32];
    hk.expand(b"eXe/v1/seal", &mut okm)
        .expect("32-byte hkdf output");
    okm
}

fn seal_aad(call_id: &str, device_id: &str) -> Vec<u8> {
    let mut aad = Vec::new();
    push_lp(&mut aad, call_id.as_bytes());
    push_lp(&mut aad, device_id.as_bytes());
    aad
}

/// Seals a result for the account: X25519(ephemeral, account_kex_pub) + ChaCha20-Poly1305.
pub fn seal_result(
    call_id: &str,
    device_id: &str,
    account_kex_public: &[u8],
    plaintext: &str,
) -> Result<SealedResult, CryptoError> {
    let ephemeral_secret = random_bytes::<32>();
    let ephemeral = StaticSecret::from(ephemeral_secret);
    let peer: [u8; 32] = account_kex_public
        .try_into()
        .map_err(|_| CryptoError::Key)?;
    let shared = ephemeral
        .diffie_hellman(&X25519Public::from(peer))
        .to_bytes();
    let key = seal_key(&shared, call_id, device_id);
    let nonce = random_bytes::<12>();
    let cipher = ChaCha20Poly1305::new((&key).into());
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: plaintext.as_bytes(),
                aad: &seal_aad(call_id, device_id),
            },
        )
        .map_err(|_| CryptoError::Open)?;
    Ok(SealedResult {
        v: 1,
        eph: b64u(X25519Public::from(&ephemeral).as_bytes()),
        nonce: b64u(&nonce),
        ct: b64u(&ciphertext),
    })
}

/// Opens a sealed result with the account secret (used by tests and tooling).
pub fn open_result(
    account_kex_secret: &[u8],
    call_id: &str,
    device_id: &str,
    sealed: &SealedResult,
) -> Result<String, CryptoError> {
    let secret: [u8; 32] = account_kex_secret
        .try_into()
        .map_err(|_| CryptoError::Key)?;
    let static_secret = StaticSecret::from(secret);
    let eph = unb64u(&sealed.eph)?;
    let eph: [u8; 32] = eph.try_into().map_err(|_| CryptoError::Key)?;
    let shared = static_secret
        .diffie_hellman(&X25519Public::from(eph))
        .to_bytes();
    let key = seal_key(&shared, call_id, device_id);
    let nonce = unb64u(&sealed.nonce)?;
    let ciphertext = unb64u(&sealed.ct)?;
    let cipher = ChaCha20Poly1305::new((&key).into());
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: &seal_aad(call_id, device_id),
            },
        )
        .map_err(|_| CryptoError::Open)?;
    String::from_utf8(plaintext).map_err(|_| CryptoError::Open)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sealing_round_trips() {
        let account = KexPair::generate();
        let sealed = seal_result("call", "device", &account.public, "{\"ok\":true}").unwrap();
        let opened = open_result(&account.secret, "call", "device", &sealed).unwrap();
        assert_eq!(opened, "{\"ok\":true}");
        assert!(open_result(&account.secret, "other", "device", &sealed).is_err());
    }

    #[test]
    fn signing_round_trips() {
        let pair = KeyPair::generate();
        let signature = pair.sign(b"payload");
        assert!(verify_ed25519(&pair.public, b"payload", &signature).is_ok());
        assert!(verify_ed25519(&pair.public, b"other", &signature).is_err());
    }
}
