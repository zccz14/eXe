//! eXe device core: identity, envelopes, the two-layer seal and local policy.
//!
//! Everything here is platform-neutral so the desktop CLI, Android and iOS
//! shells all run the same trust logic. See `docs/PROTOCOL.md`.
pub mod crypto;
pub mod policy;
pub mod protocol;

pub use crypto::{
    address_of, b58, b64u, parse_address, random_bytes, sha256, sha256_hex, unb58, unb64u,
    unix_now, Identity, SEALED_PREFIX,
};
pub use protocol::{CallEnvelope, Event, PolicyDecision, ResultEnvelope, SealedCall, VerifyError};
