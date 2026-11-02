PRAGMA foreign_keys = ON;

-- Public keys only: no column anywhere could hold a private key.
CREATE TABLE IF NOT EXISTS accounts (
  user_id    TEXT PRIMARY KEY,
  address    TEXT NOT NULL UNIQUE,   -- base58 Ed25519 public key of the browser
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- One-shot nonces proving possession of the signing key during registration.
CREATE TABLE IF NOT EXISTS account_challenges (
  user_id    TEXT PRIMARY KEY,
  nonce      TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

-- What the relay itself knows: an address checked in. Nothing else.
CREATE TABLE IF NOT EXISTS agents (
  address       TEXT PRIMARY KEY,
  hostname      TEXT NOT NULL,
  platform      TEXT NOT NULL,
  version       TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL
);

-- The console's address book: which device addresses this account may call.
CREATE TABLE IF NOT EXISTS devices (
  owner_user_id TEXT NOT NULL,
  address       TEXT NOT NULL,
  label         TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  revoked_at    INTEGER,
  PRIMARY KEY (owner_user_id, address)
);

CREATE TABLE IF NOT EXISTS calls (
  call_id        TEXT PRIMARY KEY,
  device_address TEXT NOT NULL,
  owner_user_id  TEXT NOT NULL,
  issuer         TEXT NOT NULL,
  sealed         TEXT NOT NULL,   -- base64url; opaque to the relay
  sig            TEXT NOT NULL,
  issued_at      INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  status         TEXT NOT NULL CHECK (status IN ('queued','delivered','received','succeeded','failed','cancelled','expired')),
  delivered_at   INTEGER,
  received_at    INTEGER,
  settled_at     INTEGER,
  result         TEXT,            -- the sealed result envelope, verbatim
  cancel_requested_at INTEGER,
  cancel_notified_at  INTEGER,
  created_at     INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS calls_queued ON calls(device_address, status, created_at);
CREATE INDEX IF NOT EXISTS calls_owner ON calls(owner_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS calls_device_recent ON calls(device_address, created_at DESC);

-- Single-use request nonces: a captured request cannot be replayed.
CREATE TABLE IF NOT EXISTS request_nonces (
  address    TEXT NOT NULL,
  nonce      TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (address, nonce)
);
CREATE INDEX IF NOT EXISTS request_nonces_expiry ON request_nonces(expires_at);
