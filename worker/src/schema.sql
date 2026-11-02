PRAGMA foreign_keys = ON;

-- Two tables, and that is the whole relay: `devices` is who has ever checked in,
-- `calls` is the queue and the only business truth. There is no third table —
-- no account, no console address book, no ledger of used request nonces.
--
-- Public keys only: no column anywhere could hold a private key.

CREATE TABLE IF NOT EXISTS devices (
  address       TEXT PRIMARY KEY,   -- base58 Ed25519 public key
  hostname      TEXT NOT NULL,
  platform      TEXT NOT NULL,
  version       TEXT NOT NULL,
  first_seen_at INTEGER NOT NULL,   -- the device's own signed registration
  last_seen_at  INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS calls (
  call_id        TEXT PRIMARY KEY,  -- chosen and signed by the console
  device_address TEXT NOT NULL,
  issuer         TEXT NOT NULL,     -- the console's address, and therefore the owner
  sealed         TEXT NOT NULL,     -- base64url; opaque to the relay
  sig            TEXT NOT NULL,
  issued_at      INTEGER NOT NULL,
  expires_at     INTEGER NOT NULL,
  status         TEXT NOT NULL CHECK (status IN ('queued','received','succeeded','failed','cancelled','expired')),
  received_at    INTEGER,           -- the device's signed receipt: the only proof of delivery
  settled_at     INTEGER,
  result         TEXT,              -- the sealed result envelope, verbatim
  cancel_requested_at INTEGER,
  created_at     INTEGER NOT NULL
);

-- `peek` reads this one: the unacknowledged calls of a single device.
CREATE INDEX IF NOT EXISTS calls_queued ON calls(device_address, status, created_at);
CREATE INDEX IF NOT EXISTS calls_issuer ON calls(issuer, created_at DESC);
CREATE INDEX IF NOT EXISTS calls_device_recent ON calls(device_address, created_at DESC);
