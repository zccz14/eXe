PRAGMA foreign_keys = ON;

-- Public keys only. There is no column that could hold a private key.
CREATE TABLE IF NOT EXISTS accounts (
  user_id    TEXT PRIMARY KEY,
  sig_pub    TEXT NOT NULL,
  kex_pub    TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- One-shot nonces proving possession of the signing key during registration.
CREATE TABLE IF NOT EXISTS account_challenges (
  user_id    TEXT PRIMARY KEY,
  nonce      TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
  id            TEXT PRIMARY KEY,
  owner_user_id TEXT NOT NULL,
  label         TEXT NOT NULL,
  hostname      TEXT NOT NULL,
  platform      TEXT NOT NULL,
  version       TEXT,
  sig_pub       TEXT NOT NULL,
  kex_pub       TEXT NOT NULL,
  token_hash    TEXT NOT NULL,
  status        TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
  boot_id       TEXT,
  sas           TEXT NOT NULL,
  created_at    INTEGER NOT NULL,
  last_seen_at  INTEGER,
  revoked_at    INTEGER
);
CREATE INDEX IF NOT EXISTS devices_owner ON devices(owner_user_id, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS devices_sig_pub_active ON devices(sig_pub) WHERE status='active';

CREATE TABLE IF NOT EXISTS pairings (
  id             TEXT PRIMARY KEY,
  user_code      TEXT NOT NULL UNIQUE,
  secret_hash    TEXT NOT NULL,
  token_hash     TEXT NOT NULL,
  dev_sig_pub    TEXT NOT NULL,
  dev_kex_pub    TEXT NOT NULL,
  hostname       TEXT NOT NULL,
  platform       TEXT NOT NULL,
  version        TEXT NOT NULL,
  expires_at     INTEGER NOT NULL,
  status         TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','approved','denied')),
  device_id      TEXT NOT NULL,
  account_id     TEXT,
  approval       TEXT,
  created_at     INTEGER NOT NULL,
  last_polled_at INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS pairings_device ON pairings(dev_sig_pub, created_at DESC);

CREATE TABLE IF NOT EXISTS calls (
  id                  TEXT PRIMARY KEY,
  device_id           TEXT NOT NULL,
  owner_user_id       TEXT NOT NULL,
  name                TEXT NOT NULL,
  args                TEXT NOT NULL,
  nonce               TEXT NOT NULL,
  issued_at           INTEGER NOT NULL,
  expires_at          INTEGER NOT NULL,
  sig                 TEXT NOT NULL,
  status              TEXT NOT NULL CHECK (status IN ('queued','delivered','received','succeeded','failed','cancelled','expired')),
  device_boot_id      TEXT,
  delivered_at        INTEGER,
  received_at         INTEGER,
  settled_at          INTEGER,
  envelope            TEXT,
  error               TEXT,
  failure_code        TEXT,
  cancel_requested_at INTEGER,
  cancel_notified_at  INTEGER,
  created_at          INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS calls_queued ON calls(device_id, status, created_at);
CREATE INDEX IF NOT EXISTS calls_owner ON calls(owner_user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS calls_device_recent ON calls(device_id, created_at DESC);
