//! Envelopes, transcripts and the trust rule. Mirrors `shared/protocol.ts`.
use serde::{Deserialize, Serialize};

use crate::crypto::{
    b58, parse_address, push_lp, push_u64, seal, unb64u, unix_now, verify, CryptoError,
    Identity, SealContext,
};

/// What the device finds inside a sealed command.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SealedCall {
    pub name: String,
    pub args: String,
}

/// A call as it arrives over SSE. Everything readable here is routing metadata.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CallEnvelope {
    pub call_id: String,
    pub issuer: String,
    pub device: String,
    pub issued_at: u64,
    pub expires_at: u64,
    pub sealed: String,
    pub sig: String,
}

impl CallEnvelope {
    pub fn transcript(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(b"eXe/call\0");
        push_lp(&mut out, self.call_id.as_bytes());
        push_lp(&mut out, self.issuer.as_bytes());
        push_lp(&mut out, self.device.as_bytes());
        push_u64(&mut out, self.issued_at);
        push_u64(&mut out, self.expires_at);
        push_lp(&mut out, &unb64u(&self.sealed)?);
        Ok(out)
    }

    /// Signature, trust, audience and freshness — all before anything is decrypted.
    pub fn verify(&self, trust: &[String], device: &str, now: u64) -> Result<(), VerifyError> {
        let issuer = parse_address(&self.issuer).map_err(|_| VerifyError::Malformed)?;
        let transcript = self.transcript().map_err(|_| VerifyError::Malformed)?;
        verify(&issuer, &transcript, &self.sig).map_err(|_| VerifyError::Signature)?;
        if !trust.iter().any(|allowed| allowed == &self.issuer) {
            return Err(VerifyError::Untrusted);
        }
        if self.device != device {
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

    /// Opens the sealed command with the same key that signs for this device.
    pub fn open(&self, identity: &Identity) -> Result<SealedCall, VerifyError> {
        let ctx = SealContext {
            direction: "call",
            issuer: &self.issuer,
            device: &self.device,
            call_id: &self.call_id,
            issued_at: self.issued_at,
            expires_at: self.expires_at,
        };
        let plaintext =
            crate::crypto::open(&ctx, identity, &self.sealed).map_err(|_| VerifyError::Sealed)?;
        let sealed: SealedCall =
            serde_json::from_slice(&plaintext).map_err(|_| VerifyError::Malformed)?;
        Ok(sealed)
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum VerifyError {
    #[error("signature does not verify against the issuer address")]
    Signature,
    #[error("issuer is not in this device's trust list")]
    Untrusted,
    #[error("call is addressed to another device")]
    WrongDevice,
    #[error("call has expired")]
    Expired,
    #[error("call is not valid yet")]
    NotYetValid,
    #[error("envelope is malformed")]
    Malformed,
    #[error("call could not be opened with this device key")]
    Sealed,
}

/// Device → issuer: the outcome, sealed to the issuer and signed by the device.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ResultEnvelope {
    pub call_id: String,
    pub device: String,
    pub ok: bool,
    pub issued_at: u64,
    pub sealed: String,
    pub sig: String,
}

impl ResultEnvelope {
    pub fn transcript(&self) -> Result<Vec<u8>, CryptoError> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(b"eXe/result\0");
        push_lp(&mut out, self.call_id.as_bytes());
        push_lp(&mut out, self.device.as_bytes());
        out.push(u8::from(self.ok));
        push_u64(&mut out, self.issued_at);
        push_lp(&mut out, &unb64u(&self.sealed)?);
        Ok(out)
    }

    pub fn build(
        identity: &Identity,
        call: &CallEnvelope,
        ok: bool,
        plaintext: &str,
        issued_at: u64,
    ) -> Result<Self, CryptoError> {
        let recipient = parse_address(&call.issuer)?;
        let recipient = crate::crypto::agreement_public_of(&recipient)?;
        let ctx = SealContext {
            direction: "result",
            issuer: &call.issuer,
            device: &call.device,
            call_id: &call.call_id,
            issued_at,
            // The answer cannot outlive the question.
            expires_at: call.expires_at,
        };
        let sealed = seal(&ctx, &recipient, plaintext.as_bytes())?;
        let mut envelope = Self {
            call_id: call.call_id.clone(),
            device: call.device.clone(),
            ok,
            issued_at,
            sealed,
            sig: String::new(),
        };
        envelope.sig = identity.sign(&envelope.transcript()?);
        Ok(envelope)
    }

    pub fn verify(&self, device: &str) -> Result<(), VerifyError> {
        let device_key = parse_address(device).map_err(|_| VerifyError::Malformed)?;
        if self.device != device {
            return Err(VerifyError::WrongDevice);
        }
        let transcript = self.transcript().map_err(|_| VerifyError::Malformed)?;
        verify(&device_key, &transcript, &self.sig).map_err(|_| VerifyError::Signature)
    }
}

/// A device request authenticates itself: method, path, address, time.
///
/// No nonce: replay defence lives in the `call_id` the sender signed, not in a
/// server-side ledger of used numbers (see docs/THREAT-MODEL.md).
#[derive(Clone, Debug)]
pub struct RequestAuth {
    pub method: String,
    pub path: String,
    pub address: String,
    pub timestamp: u64,
}

impl RequestAuth {
    pub fn transcript(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        out.extend_from_slice(b"eXe/request\0");
        push_lp(&mut out, self.method.to_uppercase().as_bytes());
        push_lp(&mut out, self.path.as_bytes());
        push_lp(&mut out, self.address.as_bytes());
        push_u64(&mut out, self.timestamp);
        out
    }
}

pub fn new_request_auth(identity: &Identity, method: &str, path: &str) -> RequestAuth {
    RequestAuth {
        method: method.to_owned(),
        path: path.to_owned(),
        address: identity.address(),
        timestamp: unix_now(),
    }
}

pub fn request_headers(identity: &Identity, method: &str, path: &str) -> Vec<(String, String)> {
    let auth = new_request_auth(identity, method, path);
    let signature = identity.sign(&auth.transcript());
    vec![
        ("x-exe-timestamp".into(), auth.timestamp.to_string()),
        ("x-exe-signature".into(), signature),
    ]
}

pub fn verify_request(
    identity: &Identity,
    auth: &RequestAuth,
    signature: &str,
) -> Result<(), VerifyError> {
    verify(&identity.public(), &auth.transcript(), signature).map_err(|_| VerifyError::Signature)
}

pub fn address_of_public(public: &[u8; 32]) -> String {
    b58(public)
}

#[derive(Debug, Clone)]
pub enum Event {
    Hello,
    Call(CallEnvelope),
    Cancel(String),
    Heartbeat,
}

impl Event {
    pub fn parse(event: &str, data: &str) -> Option<Event> {
        match event {
            "call" => serde_json::from_str(data).ok().map(Event::Call),
            "cancel" => serde_json::from_str::<serde_json::Value>(data)
                .ok()
                .and_then(|value| {
                    value
                        .get("call_id")?
                        .as_str()
                        .map(|id| Event::Cancel(id.to_owned()))
                }),
            "hello" => Some(Event::Hello),
            "heartbeat" => Some(Event::Heartbeat),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{b64u, sha256_hex, Identity};

    fn vector() -> serde_json::Value {
        serde_json::from_str(include_str!("../../../../tests/vectors.json")).unwrap()
    }

    fn seed(hex: &str) -> Identity {
        let raw = unhex(hex);
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&raw);
        Identity::from_seed(seed)
    }

    fn unhex(value: &str) -> Vec<u8> {
        (0..value.len() / 2)
            .map(|i| u8::from_str_radix(&value[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    fn call(v: &serde_json::Value) -> CallEnvelope {
        CallEnvelope {
            call_id: v["call"]["call_id"].as_str().unwrap().into(),
            issuer: v["call"]["issuer"].as_str().unwrap().into(),
            device: v["call"]["device"].as_str().unwrap().into(),
            issued_at: v["call"]["issued_at"].as_u64().unwrap(),
            expires_at: v["call"]["expires_at"].as_u64().unwrap(),
            sealed: v["call"]["sealed"].as_str().unwrap().into(),
            sig: v["call"]["sig"].as_str().unwrap().into(),
        }
    }

    #[test]
    fn call_vectors_cover_the_sealed_envelope() {
        let v = vector();
        let issuer = seed(v["keys"]["issuer_seed"].as_str().unwrap());
        let device = seed(v["keys"]["device_seed"].as_str().unwrap());
        assert_eq!(
            issuer.address(),
            v["keys"]["issuer_address"].as_str().unwrap()
        );
        assert_eq!(
            device.address(),
            v["keys"]["device_address"].as_str().unwrap()
        );

        let call = call(&v);
        assert_eq!(
            sha256_hex(&call.transcript().unwrap()),
            v["call"]["transcript_sha256"].as_str().unwrap()
        );
        let trust = vec![issuer.address()];
        call.verify(&trust, &device.address(), call.issued_at + 1)
            .expect("vector signature verifies");
        assert_eq!(
            call.verify(&trust, &device.address(), call.expires_at + 1),
            Err(VerifyError::Expired)
        );
        assert_eq!(
            call.verify(&[], &device.address(), call.issued_at + 1),
            Err(VerifyError::Untrusted)
        );
        assert_eq!(
            call.verify(
                &trust,
                "11111111111111111111111111111111",
                call.issued_at + 1
            ),
            Err(VerifyError::WrongDevice)
        );
        let mut tampered = call.clone();
        tampered.sealed = b64u(&[9u8; 116 + 16]);
        assert_eq!(
            tampered.verify(&trust, &device.address(), call.issued_at + 1),
            Err(VerifyError::Signature)
        );

        let sealed = call.open(&device).expect("the device opens its command");
        let plain: serde_json::Value =
            serde_json::from_str(v["call"]["plaintext"].as_str().unwrap()).unwrap();
        assert_eq!(sealed.name, plain["name"].as_str().unwrap());
        assert_eq!(sealed.args, plain["args"].as_str().unwrap());
        assert!(call.open(&issuer).is_err(), "another key cannot open it");

        let wire = serde_json::to_string(&call).unwrap();
        assert!(!wire.contains("shell"), "no tool name on the wire");
    }

    #[test]
    fn result_vectors_open_only_with_the_issuer_key() {
        let v = vector();
        let issuer = seed(v["keys"]["issuer_seed"].as_str().unwrap());
        let device = seed(v["keys"]["device_seed"].as_str().unwrap());
        let call = call(&v);
        let result = ResultEnvelope {
            call_id: v["result"]["call_id"].as_str().unwrap().into(),
            device: v["result"]["device"].as_str().unwrap().into(),
            ok: v["result"]["ok"].as_bool().unwrap(),
            issued_at: v["result"]["issued_at"].as_u64().unwrap(),
            sealed: v["result"]["sealed"].as_str().unwrap().into(),
            sig: v["result"]["sig"].as_str().unwrap().into(),
        };
        assert_eq!(
            sha256_hex(&result.transcript().unwrap()),
            v["result"]["transcript_sha256"].as_str().unwrap()
        );
        result
            .verify(&device.address())
            .expect("device signature verifies");

        let ctx = SealContext {
            direction: "result",
            issuer: &call.issuer,
            device: &call.device,
            call_id: &call.call_id,
            issued_at: result.issued_at,
            expires_at: call.expires_at,
        };
        let opened = crate::crypto::open(&ctx, &issuer, &result.sealed).unwrap();
        assert_eq!(
            String::from_utf8(opened).unwrap(),
            v["result"]["plaintext"].as_str().unwrap()
        );
        assert!(crate::crypto::open(&ctx, &device, &result.sealed).is_err());

        let mut forged = result.clone();
        forged.ok = !forged.ok;
        assert_eq!(
            forged.verify(&device.address()),
            Err(VerifyError::Signature)
        );
    }

    #[test]
    fn request_vectors() {
        let v = vector();
        let device = seed(v["keys"]["device_seed"].as_str().unwrap());

        let auth = RequestAuth {
            method: v["request"]["method"].as_str().unwrap().into(),
            path: v["request"]["path"].as_str().unwrap().into(),
            address: v["request"]["address"].as_str().unwrap().into(),
            timestamp: v["request"]["timestamp"].as_u64().unwrap(),
        };
        assert_eq!(
            sha256_hex(&auth.transcript()),
            v["request"]["transcript_sha256"].as_str().unwrap()
        );
        verify_request(&device, &auth, v["request"]["sig"].as_str().unwrap())
            .expect("device request verifies");
    }
}
