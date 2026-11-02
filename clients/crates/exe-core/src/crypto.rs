//! The wire primitives shared with `shared/protocol.ts`.
//!
//! One Ed25519 key per party. The address is the public key; X25519 is derived
//! from the same key, so nothing needs pairing or escrow. Sealing is two layers:
//! `crypto_box` wraps a 32-byte content key, AES-256-GCM carries the body.
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce as GcmNonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use crypto_box::aead::AeadInPlace;
use crypto_box::{
    Nonce as BoxNonce, PublicKey as BoxPublicKey, SalsaBox, SecretKey as BoxSecretKey,
};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};

pub const SEALED_PREFIX: usize = 24 + 32 + 48 + 12;

pub fn b64u(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn unb64u(value: &str) -> Result<Vec<u8>, CryptoError> {
    URL_SAFE_NO_PAD
        .decode(value.trim_end_matches('='))
        .map_err(|_| CryptoError::Encoding)
}

pub fn b58(bytes: &[u8]) -> String {
    bs58::encode(bytes).into_string()
}

pub fn unb58(value: &str) -> Result<Vec<u8>, CryptoError> {
    bs58::decode(value)
        .into_vec()
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

pub fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|value| value.as_secs())
        .unwrap_or(0)
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
    #[error("invalid base58 or base64url value")]
    Encoding,
    #[error("invalid key material")]
    Key,
    #[error("secret does not match its own public key")]
    SecretMismatch,
    #[error("malformed signature")]
    Signature,
    #[error("sealed payload could not be opened")]
    Open,
}

/// The one key pair a party has: it signs, receives sealed calls and opens sealed results.
#[derive(Clone)]
pub struct Identity {
    seed: [u8; 32],
    public: [u8; 32],
}

impl Identity {
    pub fn generate() -> Self {
        Self::from_seed(random_bytes::<32>())
    }
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        Self { seed, public }
    }
    /// base58(seed32 || pub32), the Solana `Keypair.secretKey` layout.
    pub fn from_secret(secret: &str) -> Result<Self, CryptoError> {
        let raw = unb58(secret)?;
        if raw.len() != 64 {
            return Err(CryptoError::SecretMismatch);
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw[..32]);
        let identity = Self::from_seed(seed);
        if identity.public != raw[32..] {
            return Err(CryptoError::SecretMismatch);
        }
        Ok(identity)
    }
    pub fn secret(&self) -> String {
        let mut raw = [0u8; 64];
        raw[..32].copy_from_slice(&self.seed);
        raw[32..].copy_from_slice(&self.public);
        b58(&raw)
    }
    pub fn address(&self) -> String {
        b58(&self.public)
    }
    pub fn public(&self) -> [u8; 32] {
        self.public
    }
    pub fn sign(&self, message: &[u8]) -> String {
        b58(&SigningKey::from_bytes(&self.seed).sign(message).to_bytes())
    }
    /// clamp(sha512(seed)[0..32]) — the X25519 half of the same key.
    pub fn agreement_secret(&self) -> [u8; 32] {
        let digest = Sha512::digest(self.seed);
        let mut scalar = [0u8; 32];
        scalar.copy_from_slice(&digest[..32]);
        scalar[0] &= 248;
        scalar[31] = (scalar[31] & 127) | 64;
        scalar
    }
    pub fn agreement_public(&self) -> [u8; 32] {
        agreement_public_of(&self.public).unwrap_or_default()
    }
}

pub fn address_of(public: &[u8; 32]) -> String {
    b58(public)
}

pub fn parse_address(text: &str) -> Result<[u8; 32], CryptoError> {
    let raw = unb58(text)?;
    if raw.len() != 32 {
        return Err(CryptoError::Key);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

/// edwardsToMontgomery(ed25519_pub).
pub fn agreement_public_of(public: &[u8; 32]) -> Result<[u8; 32], CryptoError> {
    let verifying = VerifyingKey::from_bytes(public).map_err(|_| CryptoError::Key)?;
    Ok(verifying.to_montgomery().to_bytes())
}

pub fn verify(public: &[u8; 32], message: &[u8], signature: &str) -> Result<(), CryptoError> {
    let raw = unb58(signature)?;
    let signature = Signature::from_slice(&raw).map_err(|_| CryptoError::Signature)?;
    let verifying = VerifyingKey::from_bytes(public).map_err(|_| CryptoError::Key)?;
    verifying
        .verify_strict(message, &signature)
        .map_err(|_| CryptoError::Signature)
}

/// aad = direction || issuer || device || call_id || issued_at || expires_at
pub struct SealContext<'a> {
    pub direction: &'a str,
    pub issuer: &'a str,
    pub device: &'a str,
    pub call_id: &'a str,
    pub issued_at: u64,
    pub expires_at: u64,
}

impl SealContext<'_> {
    pub fn aad(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(128);
        push_lp(&mut out, self.direction.as_bytes());
        push_lp(&mut out, self.issuer.as_bytes());
        push_lp(&mut out, self.device.as_bytes());
        push_lp(&mut out, self.call_id.as_bytes());
        push_u64(&mut out, self.issued_at);
        push_u64(&mut out, self.expires_at);
        out
    }
}

/// Fixed randomness for the cross-language vectors; production uses [`seal`].
pub struct SealRandomness<'a> {
    pub nonce: &'a [u8],
    pub content_key: &'a [u8],
    pub iv: &'a [u8],
    pub ephemeral_secret: &'a [u8],
}

pub fn seal(
    ctx: &SealContext,
    recipient: &[u8; 32],
    plaintext: &[u8],
) -> Result<String, CryptoError> {
    let nonce = random_bytes::<24>();
    let content_key = random_bytes::<32>();
    let iv = random_bytes::<12>();
    let ephemeral = random_bytes::<32>();
    seal_with(
        ctx,
        recipient,
        plaintext,
        &SealRandomness {
            nonce: &nonce,
            content_key: &content_key,
            iv: &iv,
            ephemeral_secret: &ephemeral,
        },
    )
}

/// sealed = base64url( nonce24 || eph_pub32 || tag16||ct32 || iv12 || body )
pub fn seal_with(
    ctx: &SealContext,
    recipient: &[u8; 32],
    plaintext: &[u8],
    randomness: &SealRandomness,
) -> Result<String, CryptoError> {
    Ok(b64u(&seal_bytes_with(
        ctx, recipient, plaintext, randomness,
    )?))
}

/// The same seal, left as the bytes an object store wants: an attached result is
/// not a field in a row, so it never needs the base64url wrapper.
pub fn seal_bytes(
    ctx: &SealContext,
    recipient: &[u8; 32],
    plaintext: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    let nonce = random_bytes::<24>();
    let content_key = random_bytes::<32>();
    let iv = random_bytes::<12>();
    let ephemeral = random_bytes::<32>();
    seal_bytes_with(
        ctx,
        recipient,
        plaintext,
        &SealRandomness {
            nonce: &nonce,
            content_key: &content_key,
            iv: &iv,
            ephemeral_secret: &ephemeral,
        },
    )
}

pub fn seal_bytes_with(
    ctx: &SealContext,
    recipient: &[u8; 32],
    plaintext: &[u8],
    randomness: &SealRandomness,
) -> Result<Vec<u8>, CryptoError> {
    if randomness.nonce.len() != 24
        || randomness.content_key.len() != 32
        || randomness.iv.len() != 12
        || randomness.ephemeral_secret.len() != 32
    {
        return Err(CryptoError::Key);
    }
    let aad = ctx.aad();
    let cipher = Aes256Gcm::new_from_slice(randomness.content_key).map_err(|_| CryptoError::Key)?;
    let body = cipher
        .encrypt(
            GcmNonce::from_slice(randomness.iv),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Open)?;

    let mut ephemeral_secret = [0u8; 32];
    ephemeral_secret.copy_from_slice(randomness.ephemeral_secret);
    let ephemeral = BoxSecretKey::from(ephemeral_secret);
    let salsa = SalsaBox::new(&BoxPublicKey::from(*recipient), &ephemeral);
    let mut wrapped = randomness.content_key.to_vec();
    let tag = salsa
        .encrypt_in_place_detached(BoxNonce::from_slice(randomness.nonce), b"", &mut wrapped)
        .map_err(|_| CryptoError::Open)?;

    let mut out = Vec::with_capacity(SEALED_PREFIX + body.len());
    out.extend_from_slice(randomness.nonce);
    out.extend_from_slice(ephemeral.public_key().as_bytes());
    out.extend_from_slice(&tag);
    out.extend_from_slice(&wrapped);
    out.extend_from_slice(randomness.iv);
    out.extend_from_slice(&body);
    Ok(out)
}

pub fn open(ctx: &SealContext, identity: &Identity, sealed: &str) -> Result<Vec<u8>, CryptoError> {
    open_bytes(ctx, identity, &unb64u(sealed)?)
}

/// The same seal, from the bytes an object store hands back: an attached result
/// never had the base64url wrapper, so it cannot be opened as a string.
pub fn open_bytes(
    ctx: &SealContext,
    identity: &Identity,
    raw: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if raw.len() < SEALED_PREFIX + 16 {
        return Err(CryptoError::Open);
    }
    let nonce = &raw[..24];
    let mut ephemeral = [0u8; 32];
    ephemeral.copy_from_slice(&raw[24..56]);
    let tag_bytes = &raw[56..72];
    let mut wrapped = raw[72..104].to_vec();
    let iv = &raw[104..116];
    let body = &raw[116..];

    let secret = BoxSecretKey::from(identity.agreement_secret());
    let salsa = SalsaBox::new(&BoxPublicKey::from(ephemeral), &secret);
    let mut tag: crypto_box::aead::Tag<SalsaBox> = Default::default();
    tag.copy_from_slice(tag_bytes);
    salsa
        .decrypt_in_place_detached(BoxNonce::from_slice(nonce), b"", &mut wrapped, &tag)
        .map_err(|_| CryptoError::Open)?;
    if wrapped.len() != 32 {
        return Err(CryptoError::Open);
    }
    let cipher = Aes256Gcm::new_from_slice(&wrapped).map_err(|_| CryptoError::Key)?;
    let aad = ctx.aad();
    cipher
        .decrypt(
            GcmNonce::from_slice(iv),
            Payload {
                msg: body,
                aad: &aad,
            },
        )
        .map_err(|_| CryptoError::Open)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identities_round_trip() {
        let identity = Identity::generate();
        let secret = identity.secret();
        let restored = Identity::from_secret(&secret).unwrap();
        assert_eq!(restored.address(), identity.address());
        assert_eq!(restored.agreement_public(), identity.agreement_public());

        let mut tampered = unb58(&secret).unwrap();
        tampered[40] ^= 1;
        assert!(Identity::from_secret(&b58(&tampered)).is_err());
    }

    #[test]
    fn key_agreement_is_derived_from_the_signing_key() {
        let identity = Identity::generate();
        let secret = BoxSecretKey::from(identity.agreement_secret());
        let public = BoxPublicKey::from(identity.agreement_public());
        assert_eq!(secret.public_key().as_bytes(), public.as_bytes());
    }

    #[test]
    fn sealing_round_trips_and_rejects_tampering() {
        let device = Identity::generate();
        let issuer = Identity::generate();
        let issuer_address = issuer.address();
        let device_address = device.address();
        let ctx = SealContext {
            direction: "call",
            issuer: &issuer_address,
            device: &device_address,
            call_id: "call",
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        };
        let sealed = seal(&ctx, &device.agreement_public(), b"hello").unwrap();
        assert_eq!(open(&ctx, &device, &sealed).unwrap(), b"hello");
        assert!(open(&ctx, &issuer, &sealed).is_err());

        let other = SealContext {
            direction: "call",
            issuer: &issuer_address,
            device: &device_address,
            call_id: "other",
            issued_at: 1_700_000_000,
            expires_at: 1_700_000_300,
        };
        assert!(open(&other, &device, &sealed).is_err());
    }

    #[test]
    fn signing_round_trips() {
        let identity = Identity::generate();
        let signature = identity.sign(b"payload");
        assert!(verify(&identity.public(), b"payload", &signature).is_ok());
        assert!(verify(&identity.public(), b"other", &signature).is_err());
    }
}
