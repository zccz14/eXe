use serde::{Deserialize, Serialize};

use crate::crypto::{
    b64u, push_lp, push_u64, random_bytes, sha256, sha256_hex, unb64u, verify_ed25519, CryptoError,
    KexPair, KeyPair, SealedResult,
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

/// A call as it arrives over SSE. Nothing in it is trustworthy until `verify`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallEnvelope {
    pub id: String,
    pub device_id: String,
    pub account_id: String,
    pub name: String,
    pub args: String,
    pub nonce: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub sig: String,
}

impl CallEnvelope {
    pub fn transcript(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(b"eXe/v1/call\0");
        push_lp(&mut out, self.id.as_bytes());
        push_lp(&mut out, self.device_id.as_bytes());
        push_lp(&mut out, self.account_id.as_bytes());
        push_lp(&mut out, self.name.as_bytes());
        push_lp(&mut out, &sha256(self.args.as_bytes()));
        push_u64(&mut out, self.issued_at);
        push_u64(&mut out, self.expires_at);
        push_lp(&mut out, self.nonce.as_bytes());
        out
    }

    /// Verifies authenticity, audience and freshness against the pinned account key.
    pub fn verify(
        &self,
        account_sig_pub: &[u8],
        device_id: &str,
        now: u64,
    ) -> Result<(), VerifyError> {
        verify_ed25519(account_sig_pub, &self.transcript(), &self.sig)
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

    pub fn args_json(&self) -> Result<serde_json::Value, VerifyError> {
        serde_json::from_str(&self.args).map_err(|_| VerifyError::Args)
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
    #[error("call arguments are not a JSON object")]
    Args,
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
        push_lp(&mut out, &eph);
        push_lp(&mut out, &nonce);
        push_lp(&mut out, &sha256(&ciphertext));
        Ok(out)
    }

    pub fn build(
        call_id: &str,
        device_id: &str,
        account_kex_pub: &[u8],
        plaintext: &str,
        keys: &DeviceKeys,
    ) -> Result<Self, CryptoError> {
        let sealed = crate::crypto::seal_result(call_id, device_id, account_kex_pub, plaintext)?;
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

/// Signed body of a call, produced here only for tests and tooling.
pub fn sign_call(account_sig_seed: &[u8; 32], call: &CallEnvelope) -> String {
    KeyPair::from_seed(*account_sig_seed).sign(&call.transcript())
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

/// Deterministic nonce helper so callers do not invent their own encoding.
pub fn new_nonce() -> String {
    b64u(&random_bytes::<16>())
}

pub fn args_digest(args: &str) -> String {
    sha256_hex(args.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcripts_match_published_vectors() {
        let raw = include_str!("../../../../tests/vectors.json");
        let vectors: serde_json::Value = serde_json::from_str(raw).unwrap();

        let call = CallEnvelope {
            id: vectors["call"]["callId"].as_str().unwrap().into(),
            device_id: vectors["call"]["deviceId"].as_str().unwrap().into(),
            account_id: vectors["call"]["accountId"].as_str().unwrap().into(),
            name: vectors["call"]["name"].as_str().unwrap().into(),
            args: vectors["call"]["args"].as_str().unwrap().into(),
            nonce: vectors["call"]["nonce"].as_str().unwrap().into(),
            issued_at: vectors["call"]["issuedAt"].as_u64().unwrap(),
            expires_at: vectors["call"]["expiresAt"].as_u64().unwrap(),
            sig: vectors["call"]["sig"].as_str().unwrap().into(),
        };
        assert_eq!(
            sha256_hex(&call.transcript()),
            vectors["call"]["transcript_sha256"].as_str().unwrap()
        );
        let account_pub = unb64u(vectors["keys"]["account_sig_pub"].as_str().unwrap()).unwrap();
        call.verify(&account_pub, &call.device_id, call.issued_at + 1)
            .expect("vector signature verifies");
        assert_eq!(
            call.verify(&account_pub, &call.device_id, call.expires_at + 1),
            Err(VerifyError::Expired)
        );
        let mut tampered = call.clone();
        tampered.args = "{\"text\":\"evil\"}".into();
        assert_eq!(
            tampered.verify(&account_pub, &call.device_id, call.issued_at + 1),
            Err(VerifyError::Signature)
        );

        let approval = Approval {
            pairing_id: vectors["approval"]["pairingId"].as_str().unwrap().into(),
            device_id: vectors["approval"]["deviceId"].as_str().unwrap().into(),
            account_id: vectors["approval"]["accountId"].as_str().unwrap().into(),
            account_sig_pub: vectors["approval"]["accountSigPub"]
                .as_str()
                .unwrap()
                .into(),
            account_kex_pub: vectors["approval"]["accountKexPub"]
                .as_str()
                .unwrap()
                .into(),
            device_sig_pub: vectors["approval"]["deviceSigPub"].as_str().unwrap().into(),
            device_kex_pub: vectors["approval"]["deviceKexPub"].as_str().unwrap().into(),
            issued_at: vectors["approval"]["issuedAt"].as_u64().unwrap(),
            sig: vectors["approval"]["sig"].as_str().unwrap().into(),
        };
        assert_eq!(
            sha256_hex(&approval.transcript()),
            vectors["approval"]["transcript_sha256"].as_str().unwrap()
        );
        verify_ed25519(&account_pub, &approval.transcript(), &approval.sig).unwrap();

        let sealed = SealedResult {
            v: 1,
            eph: vectors["result"]["eph"].as_str().unwrap().into(),
            nonce: vectors["result"]["nonce"].as_str().unwrap().into(),
            ct: vectors["result"]["ct"].as_str().unwrap().into(),
        };
        let account_kex_secret =
            hex::decode(vectors["keys"]["account_kex_seed"].as_str().unwrap()).unwrap();
        let opened = crate::crypto::open_result(
            &account_kex_secret,
            vectors["result"]["call_id"].as_str().unwrap(),
            vectors["result"]["device_id"].as_str().unwrap(),
            &sealed,
        )
        .unwrap();
        assert_eq!(opened, vectors["result"]["plaintext"].as_str().unwrap());

        let envelope = ResultEnvelope {
            sealed,
            sig: vectors["result"]["sig"].as_str().unwrap().into(),
        };
        let transcript = envelope
            .transcript(
                vectors["result"]["call_id"].as_str().unwrap(),
                vectors["result"]["device_id"].as_str().unwrap(),
            )
            .unwrap();
        assert_eq!(
            sha256_hex(&transcript),
            vectors["result"]["transcript_sha256"].as_str().unwrap()
        );
        let device_pub = unb64u(vectors["keys"]["device_sig_pub"].as_str().unwrap()).unwrap();
        verify_ed25519(&device_pub, &transcript, &envelope.sig).unwrap();

        assert_eq!(
            sas(
                vectors["keys"]["account_sig_pub"].as_str().unwrap(),
                vectors["keys"]["device_sig_pub"].as_str().unwrap()
            ),
            vectors["sas"].as_str().unwrap()
        );
    }
}
