//! eXe device core: protocol transcripts, sealed results and local policy.
//!
//! Everything here is platform-neutral so the desktop CLI, Android and iOS
//! shells all run the same trust logic. See `docs/PROTOCOL.md`.
pub mod crypto;
pub mod policy;
pub mod protocol;

pub use crypto::{b64u, random_bytes, sha256, sha256_hex, unb64u, KexPair, KeyPair, SealedResult};
pub use protocol::{CallEnvelope, DeviceKeys, Event, PolicyDecision, ResultEnvelope};
