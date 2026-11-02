use serde::{Deserialize, Serialize};

use crate::crypto::{
    b64u, push_lp, push_u64, sha256, unb64u, verify_ed25519, CryptoError, KexPair, KeyPair,
    SealedResult,
};

/// Device-side key material. The seeds never leave the device.
#[derive(Clone)]
pub struct DeviceKeys {
    pub sig: KeyPair,
    pub kex: KexPair,
}

impl DeviceKeys {
    pub fn generate() -> Self {
        Self {
            sig: KeyPair::generate(),
            kex: KexPair::generate(),
        }
    }
    pub fn sig_pub(&self) -> String {
        b64u(&self.sig.public)
    }
    pub fn kex_pub(&self) -> String {
        b64u(&self.kex.public)
    }
}

/// A call as it arrives over SSE. Everything readable here is routing metadata;
/// the tool and its arguments stay sealed until the device opens them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallEnvelope {
    pub id: String,
    pub device_id: String,
    pub account_id: String,
    pub eph: String,
    pub nonce: String,
    pub ct: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub sig: String,
}

/// What the device finds inside a sealed command.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedCall {
    pub name: String,
    pub args: String,
}

/// The three binary fields of a call envelope.
struct CallParts {
    eph: Vec<u8>,
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

impl CallEnvelope {
    fn opened(&self) -> Result<CallParts, CryptoError> {
        Ok(CallParts {
            eph: unb64u(&self.eph)?,
            nonce: unb64u(&self.nonce)?,
            ciphertext: unb64u(&self.ct)?,
        })
    }

    pub fn transcript(&self) -> Result<Vec<u8>, CryptoError> {
        let parts = self.opened()?;
        let mut out = Vec::with_capacity(200);
        out.extend_from_slice(b"eXe/v1/call\0");
        push_lp(&mut out, self.id.as_bytes());
        push_lp(&mut out, self.device_id.as_bytes());
        push_lp(&mut out, self.account_id.as_bytes());
        push_lp(&mut out, &parts.eph);
        push_lp(&mut out, &parts.nonce);
        push_lp(&mut out, &sha256(&parts.ciphertext));
        push_u64(&mut out, self.issued_at);
        push_u64(&mut out, self.expires_at);
        Ok(out)
    }

    /// Authenticity, audience and freshness — checked before anything is decrypted.
    pub fn verify(
        &self,
        account_sig_pub: &[u8],
        device_id: &str,
        now: u64,
    ) -> Result<(), VerifyError> {
        let transcript = self.transcript().map_err(|_| VerifyError::Malformed)?;
        verify_ed25519(account_sig_pub, &transcript, &self.sig)
            .map_err(|_| VerifyError::Signature)?;
        if self.device_id != device_id {
            return Err(VerifyError::WrongDevice);
        }
        if self.expires_at <= now {
            return Err(VerifyError::Expired);
        }
        if self.issued_at > now + 60 {
            return Err(VerifyError::NotYetValid);
        }
        Ok(())
    }

    /// Opens the sealed command with the device key agreement secret.
    pub fn open(&self, device_kex_secret: &[u8]) -> Result<SealedCall, VerifyError> {
        let parts = self.opened().map_err(|_| VerifyError::Malformed)?;
        let plaintext = crate::crypto::open_call(
            device_kex_secret,
            &self.id,
            &self.device_id,
            &self.account_id,
            &parts.eph,
            &parts.nonce,
            &parts.ciphertext,
        )
        .map_err(|_| VerifyError::Sealed)?;
        serde_json::from_str(&plaintext).map_err(|_| VerifyError::Malformed)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("call signature does not verify against the pinned account key")]
    Signature,
    #[error("call is addressed to another device")]
    WrongDevice,
    #[error("call has expired")]
    Expired,
    #[error("call is not valid yet")]
    NotYetValid,
    #[error("call envelope is malformed")]
    Malformed,
    #[error("call could not be opened with this device key")]
    Sealed,
}

/// Account registration: proves the browser holds the signing key, without the
/// key ever reaching the cloud.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountFields {
    pub user_id: String,
    pub nonce: String,
    pub sig_pub: String,
    pub kex_pub: String,
    pub issued_at: u64,
}

impl AccountFields {
    pub fn transcript(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(200);
        out.extend_from_slice(b"eXe/v1/account\0");
        push_lp(&mut out, self.user_id.as_bytes());
        push_lp(&mut out, self.nonce.as_bytes());
        push_lp(&mut out, self.sig_pub.as_bytes());
        push_lp(&mut out, self.kex_pub.as_bytes());
        push_u64(&mut out, self.issued_at);
        out
    }
}

/// What the console signs when a human approves a pairing.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Approval {
    pub pairing_id: String,
    pub device_id: String,
    pub account_id: String,
    pub account_sig_pub: String,
    pub account_kex_pub: String,
    pub device_sig_pub: String,
    pub device_kex_pub: String,
    pub issued_at: u64,
    pub sig: String,
}

impl Approval {
    pub fn transcript(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(b"eXe/v1/approval\0");
        push_lp(&mut out, self.pairing_id.as_bytes());
        push_lp(&mut out, self.device_id.as_bytes());
        push_lp(&mut out, self.account_id.as_bytes());
        push_lp(&mut out, self.account_sig_pub.as_bytes());
        push_lp(&mut out, self.account_kex_pub.as_bytes());
        push_lp(&mut out, self.device_sig_pub.as_bytes());
        push_lp(&mut out, self.device_kex_pub.as_bytes());
        push_u64(&mut out, self.issued_at);
        out
    }

    /// Self-signed pin: proves the account key holder issued *this* approval for *my* keys.
    pub fn verify(&self, keys: &DeviceKeys) -> Result<(), VerifyError> {
        let account_pub = unb64u(&self.account_sig_pub).map_err(|_| VerifyError::Signature)?;
        verify_ed25519(&account_pub, &self.transcript(), &self.sig)
            .map_err(|_| VerifyError::Signature)?;
        if self.device_sig_pub != keys.sig_pub() || self.device_kex_pub != keys.kex_pub() {
            return Err(VerifyError::WrongDevice);
        }
        Ok(())
    }
}

/// Device → cloud: encrypted payload plus a device signature over the ciphertext.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultEnvelope {
    #[serde(flatten)]
    pub sealed: SealedResult,
    pub sig: String,
}

impl ResultEnvelope {
    pub fn transcript(&self, call_id: &str, device_id: &str) -> Result<Vec<u8>, CryptoError> {
        let eph = unb64u(&self.sealed.eph)?;
        let nonce = unb64u(&self.sealed.nonce)?;
        let ciphertext = unb64u(&self.sealed.ct)?;
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(b"eXe/v1/result\0");
        push_lp(&mut out, call_id.as_bytes());
        push_lp(&mut out, device_id.as_bytes());
        push_lp(&mut out, &[u8::from(self.sealed.ok)]);
        push_lp(&mut out, &eph);
        push_lp(&mut out, &nonce);
        push_lp(&mut out, &sha256(&ciphertext));
        Ok(out)
    }

    pub fn build(
        call_id: &str,
        device_id: &str,
        ok: bool,
        account_kex_pub: &[u8],
        plaintext: &str,
        keys: &DeviceKeys,
    ) -> Result<Self, CryptoError> {
        let sealed =
            crate::crypto::seal_result(call_id, device_id, ok, account_kex_pub, plaintext)?;
        let mut envelope = Self {
            sealed,
            sig: String::new(),
        };
        let transcript = envelope.transcript(call_id, device_id)?;
        envelope.sig = keys.sig.sign(&transcript);
        Ok(envelope)
    }
}

/// Six decimals compared by the human between device and console.
pub fn sas(account_sig_pub: &str, device_sig_pub: &str) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(b"eXe/v1/sas");
    push_lp(&mut input, account_sig_pub.as_bytes());
    push_lp(&mut input, device_sig_pub.as_bytes());
    let digest = sha256(&input);
    let value = u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]]);
    format!("{:06}", value % 1_000_000)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyDecision {
    Allow,
    Deny(String),
}

impl Event {
    pub fn parse(event: &str, data: &str) -> Option<Event> {
        match event {
            "call" => serde_json::from_str(data).ok().map(Event::Call),
            "cancel" => serde_json::from_str::<serde_json::Value>(data)
                .ok()
                .and_then(|value| {
                    value
                        .get("id")?
                        .as_str()
                        .map(|id| Event::Cancel(id.to_owned()))
                }),
            "hello" => Some(Event::Hello),
            "heartbeat" => Some(Event::Heartbeat),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub enum Event {
    Hello,
    Call(CallEnvelope),
    Cancel(String),
    Heartbeat,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::sha256_hex;

    fn vector() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../tests/vectors.json")).unwrap()
    }

    #[test]
    fn call_vectors_cover_the_sealed_envelope() {
        let v = vector();
        let account_pub = unb64u(v["keys"]["account_sig_pub"].as_str().unwrap()).unwrap();
        let device_kex_secret =
            hex::decode(v["keys"]["device_kex_seed"].as_str().unwrap()).unwrap();
        let call = CallEnvelope {
            id: v["call"]["callId"].as_str().unwrap().into(),
            device_id: v["call"]["deviceId"].as_str().unwrap().into(),
            account_id: v["call"]["accountId"].as_str().unwrap().into(),
            eph: v["call"]["eph"].as_str().unwrap().into(),
            nonce: v["call"]["nonce"].as_str().unwrap().into(),
            ct: v["call"]["ct"].as_str().unwrap().into(),
            issued_at: v["call"]["issuedAt"].as_u64().unwrap(),
            expires_at: v["call"]["expiresAt"].as_u64().unwrap(),
            sig: v["call"]["sig"].as_str().unwrap().into(),
        };
        assert_eq!(
            sha256_hex(&call.transcript().unwrap()),
            v["call"]["transcript_sha256"].as_str().unwrap()
        );
        call.verify(&account_pub, &call.device_id, call.issued_at + 1)
            .expect("vector signature verifies");
        assert_eq!(
            call.verify(&account_pub, &call.device_id, call.expires_at + 1),
            Err(VerifyError::Expired)
        );
        let mut tampered = call.clone();
        tampered.ct = b64u(&[9u8; 40]);
        assert_eq!(
            tampered.verify(&account_pub, &call.device_id, call.issued_at + 1),
            Err(VerifyError::Signature)
        );
        assert_eq!(
            call.verify(
                &account_pub,
                "00000000-0000-4000-8000-000000000000",
                call.issued_at + 1
            ),
            Err(VerifyError::WrongDevice)
        );

        let sealed = call
            .open(&device_kex_secret)
            .expect("the device opens its command");
        let plain: serde_json::Value =
            serde_json::from_str(v["call"]["plaintext"].as_str().unwrap()).unwrap();
        assert_eq!(sealed.name, plain["name"].as_str().unwrap());
        assert_eq!(sealed.args, plain["args"].as_str().unwrap());
        assert!(call.open(&[7u8; 32]).is_err(), "another key cannot open it");

        // the cloud only ever sees these fields
        let visible = serde_json::to_string(&call).unwrap();
        assert!(!visible.contains("echo"), "no tool name on the wire");
    }

    #[test]
    fn account_and_approval_vectors() {
        let v = vector();
        let account_pub = unb64u(v["keys"]["account_sig_pub"].as_str().unwrap()).unwrap();
        let account = AccountFields {
            user_id: v["account"]["userId"].as_str().unwrap().into(),
            nonce: v["account"]["nonce"].as_str().unwrap().into(),
            sig_pub: v["account"]["sigPub"].as_str().unwrap().into(),
            kex_pub: v["account"]["kexPub"].as_str().unwrap().into(),
            issued_at: v["account"]["issuedAt"].as_u64().unwrap(),
        };
        assert_eq!(
            sha256_hex(&account.transcript()),
            v["account"]["transcript_sha256"].as_str().unwrap()
        );
        verify_ed25519(
            &account_pub,
            &account.transcript(),
            v["account"]["sig"].as_str().unwrap(),
        )
        .expect("account registration verifies");

        let approval = Approval {
            pairing_id: v["approval"]["pairingId"].as_str().unwrap().into(),
            device_id: v["approval"]["deviceId"].as_str().unwrap().into(),
            account_id: v["approval"]["accountId"].as_str().unwrap().into(),
            account_sig_pub: v["approval"]["accountSigPub"].as_str().unwrap().into(),
            account_kex_pub: v["approval"]["accountKexPub"].as_str().unwrap().into(),
            device_sig_pub: v["approval"]["deviceSigPub"].as_str().unwrap().into(),
            device_kex_pub: v["approval"]["deviceKexPub"].as_str().unwrap().into(),
            issued_at: v["approval"]["issuedAt"].as_u64().unwrap(),
            sig: v["approval"]["sig"].as_str().unwrap().into(),
        };
        assert_eq!(
            sha256_hex(&approval.transcript()),
            v["approval"]["transcript_sha256"].as_str().unwrap()
        );
        verify_ed25519(&account_pub, &approval.transcript(), &approval.sig).unwrap();
        assert_eq!(
            sas(
                v["keys"]["account_sig_pub"].as_str().unwrap(),
                v["keys"]["device_sig_pub"].as_str().unwrap()
            ),
            v["sas"].as_str().unwrap()
        );
    }

    #[test]
    fn result_vectors_open_only_with_the_account_key() {
        let v = vector();
        let sealed = SealedResult {
            v: 1,
            ok: v["result"]["ok"].as_bool().unwrap(),
            eph: v["result"]["eph"].as_str().unwrap().into(),
            nonce: v["result"]["nonce"].as_str().unwrap().into(),
            ct: v["result"]["ct"].as_str().unwrap().into(),
        };
        let account_kex_secret =
            hex::decode(v["keys"]["account_kex_seed"].as_str().unwrap()).unwrap();
        let opened = crate::crypto::open_result(
            &account_kex_secret,
            v["result"]["call_id"].as_str().unwrap(),
            v["result"]["device_id"].as_str().unwrap(),
            &sealed,
        )
        .unwrap();
        assert_eq!(opened, v["result"]["plaintext"].as_str().unwrap());

        let envelope = ResultEnvelope {
            sealed,
            sig: v["result"]["sig"].as_str().unwrap().into(),
        };
        let transcript = envelope
            .transcript(
                v["result"]["call_id"].as_str().unwrap(),
                v["result"]["device_id"].as_str().unwrap(),
            )
            .unwrap();
        assert_eq!(
            sha256_hex(&transcript),
            v["result"]["transcript_sha256"].as_str().unwrap()
        );
        verify_ed25519(
            &unb64u(v["keys"]["device_sig_pub"].as_str().unwrap()).unwrap(),
            &transcript,
            &envelope.sig,
        )
        .unwrap();
    }
}
