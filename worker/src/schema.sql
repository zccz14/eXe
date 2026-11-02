PRAGMA foreign_keys = ON;

-- Two tables, and that is the whole relay: `devices` is who has ever checked in,
-- `calls` is the queue and the only business truth. There is no third table —
-- no account, no console address book, no ledger of used request nonces.
--
-- Public keys only: no column anywhere could hold a private key.

CREATE TABLE IF NOT EXISTS devices (
  address       TEXT PRIMARY KEY,   -- base58 Ed25519 public key
  platform      TEXT NOT NULL,
  version       TEXT NOT NULL,
  -- 设备声明的信任地址，逗号分隔，由设备自己上传。云端拿到的只是一份副本：
  -- 它只能用来**少发**（把明显不会被接受的调用挡在门外），永远不能用来多发。
  -- 副本最多和设备配置一样旧（重启才刷新），所以它绝不会比设备更宽松。
  trust         TEXT NOT NULL,
  -- 本次进程的标识（UUIDv7）。它变了就是进程重启过：上一枚 run 签过收据、
  -- 却始终没有结果的调用会被标记为 lost，而不是重投——已经发生的副作用
  -- 不该被静默重放，只有控制台后面的人知道那条命令能不能再跑一次。
  run_id        TEXT NOT NULL,
  run_started_at INTEGER NOT NULL,
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
  status         TEXT NOT NULL CHECK (status IN ('queued','received','succeeded','failed','cancelled','expired','lost')),
  received_at    INTEGER,           -- the device's signed receipt: the only proof of delivery
  device_run_id  TEXT,              -- 签收据的那枚 run；与当前 run_id 不同即为孤儿
  settled_at     INTEGER,
  result         TEXT,              -- the sealed result envelope, verbatim
  blob_bytes     INTEGER,           -- sealed attachment in R2 when the result was too big for this row
  cancel_requested_at INTEGER,
  created_at     INTEGER NOT NULL
);

-- `peek` reads this one: the unacknowledged calls of a single device.
CREATE INDEX IF NOT EXISTS calls_queued ON calls(device_address, status, created_at);
CREATE INDEX IF NOT EXISTS calls_issuer ON calls(issuer, created_at DESC);
CREATE INDEX IF NOT EXISTS calls_device_recent ON calls(device_address, created_at DESC);
-- The retention cron sweeps settled calls by age; without this it would scan the
-- whole table once an hour.
CREATE INDEX IF NOT EXISTS calls_retention ON calls(status, settled_at);
