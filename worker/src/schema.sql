PRAGMA foreign_keys = ON;

-- Public keys only: no column anywhere could hold a private key.
-- There is no account table: the address that signed a row is the identity that
-- owns it, so a `user_id` column would only be a second name for the same key.

-- What the relay itself knows: an address checked in. Nothing else.
CREATE TABLE IF NOT EXISTS agents (
  address       TEXT PRIMARY KEY,
  hostname      TEXT NOT NULL,
  platform      TEXT NOT NULL,
  version       TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at  INTEGER NOT NULL
);

-- Each console's own address book: which device addresses it may call.
CREATE TABLE IF NOT EXISTS devices (
  owner_address TEXT NOT NULL,       -- base58 Ed25519 public key of the browser
  address       TEXT NOT NULL,
  label         TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  PRIMARY KEY (owner_address, address)
);

CREATE TABLE IF NOT EXISTS calls (
  call_id        TEXT PRIMARY KEY,
  device_address TEXT NOT NULL,
  issuer         TEXT NOT NULL,   -- the console's address, and therefore the owner
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
CREATE INDEX IF NOT EXISTS calls_issuer ON calls(issuer, created_at DESC);
CREATE INDEX IF NOT EXISTS calls_device_recent ON calls(device_address, created_at DESC);

-- Single-use request nonces: a captured request cannot be replayed. Devices and
-- the console share the table; the key is the address that signed.
CREATE TABLE IF NOT EXISTS request_nonces (
  address    TEXT NOT NULL,
  nonce      TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  PRIMARY KEY (address, nonce)
);
CREATE INDEX IF NOT EXISTS request_nonces_expiry ON request_nonces(expires_at);
