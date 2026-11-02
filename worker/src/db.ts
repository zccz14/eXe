// Storage layer. The relay never holds a private key: only public keys, sealed
// envelopes and signatures are persisted (see docs/THREAT-MODEL.md).
import { isAddress, verifyRequest } from "../../shared/protocol.ts";
import { ApiError, now } from "./http.ts";

export interface Env {
  DB: D1Database;
  /** Attachments: sealed results too big for a row. Opaque bytes, never opened here. */
  BLOBS: R2Bucket;
  ASSETS: Fetcher;
  /** Comma-separated origins allowed to call the console API from another origin. */
  CONSOLE_ORIGINS?: string;
  /** owner/name of the repository whose GitHub Releases carry the client binaries. */
  GITHUB_REPO?: string;
}

/** Everything a signed request may be used for: five minutes either way. */
export const REQUEST_WINDOW_SECONDS = 300;

/** A device that has ever registered itself. The relay knows nothing else about it. */
export interface DeviceRow {
  address: string;
  platform: string;
  version: string;
  /** Comma-separated addresses the device says it trusts. Empty means "nobody". */
  trust: string;
  /** The `exe run` process currently behind this address. A change means a restart. */
  run_id: string;
  run_started_at: number;
  first_seen_at: number;
  last_seen_at: number;
}

/** Splits a stored trust list. An empty string is a device that trusts nobody. */
export function trustList(value: string): string[] {
  return value
    .split(",")
    .map((entry) => entry.trim())
    .filter(Boolean);
}

export interface CallRow {
  call_id: string;
  device_address: string;
  /** The console that signed it: issuer *is* the owner, so there is no second column. */
  issuer: string;
  sealed: string;
  sig: string;
  issued_at: number;
  expires_at: number;
  status: string;
  received_at: number | null;
  settled_at: number | null;
  result: string | null;
  /** Size of the attachment in `BLOBS`, when the result did not fit in this row. */
  blob_bytes: number | null;
  cancel_requested_at: number | null;
  created_at: number;
}

export async function deviceByAddress(env: Env, address: string): Promise<DeviceRow | null> {
  return env.DB.prepare("SELECT * FROM devices WHERE address=?").bind(address).first<DeviceRow>();
}

export async function callById(env: Env, callId: string): Promise<CallRow | null> {
  return env.DB.prepare("SELECT * FROM calls WHERE call_id=?").bind(callId).first<CallRow>();
}

export interface DeviceInfo {
  platform: string;
  version: string;
  trust: string;
  run_id: string;
  run_started_at: number;
}

/**
 * A new process is running behind this address. Every call the previous one
 * acknowledged and never settled becomes `lost`: it was handed to a process that
 * is gone, so its outcome is unknown. Re-delivering it would risk applying a
 * side effect twice, and only the human behind the console knows whether that is
 * safe — they can sign a fresh call if they want it run again.
 *
 * Runs on registration only, i.e. once per process start, and touches at most a
 * handful of rows.
 */
export async function abandonOrphans(env: Env, address: string, runId: string): Promise<number> {
  const result = await env.DB.prepare(
    "UPDATE calls SET status='lost', settled_at=? WHERE device_address=? AND status='received' AND (device_run_id IS NULL OR device_run_id != ?)",
  )
    .bind(now(), address, runId)
    .run();
  return result.meta.changes ?? 0;
}

/** Records that an address is alive; the relay stores nothing else about it. */
/**
 * The only delete path in the whole relay. A call is evidence, so nothing here
 * removes a row that could still be settled or retried; what it removes is a
 * call that is already over and older than the window. Retention is what keeps
 * "one relay, one D1 database" true: a result can now be megabytes, and `calls`
 * is also the only record of who talked to whom, so an unbounded table is both
 * a bill and a liability.
 */
export async function deleteSettledCalls(env: Env, olderThan: number, limit: number): Promise<number> {
  const rows = await env.DB.prepare(
    "SELECT call_id, blob_bytes FROM calls WHERE status IN ('succeeded','failed','cancelled','expired','lost') " +
      "AND settled_at IS NOT NULL AND settled_at < ? ORDER BY settled_at LIMIT ?",
  )
    .bind(olderThan, limit)
    .all<{ call_id: string; blob_bytes: number | null }>();
  const ids = rows.results.map((row) => row.call_id);
  if (ids.length === 0) return 0;
  // Objects first: a row that outlives its attachment is recoverable (the next
  // sweep removes it), a object that outlives its row is a permanent leak.
  for (const row of rows.results) {
    if (row.blob_bytes !== null) await env.BLOBS.delete(row.call_id);
  }
  const placeholders = ids.map(() => "?").join(",");
  const deleted = await env.DB.prepare(`DELETE FROM calls WHERE call_id IN (${placeholders})`)
    .bind(...ids)
    .run();
  return deleted.meta.changes ?? 0;
}

export async function touchDevice(env: Env, address: string, info?: DeviceInfo): Promise<void> {
  const stamp = now();
  if (info) {
    const platform = info.platform.slice(0, 40);
    const version = info.version.slice(0, 20);
    await env.DB.prepare(
      "INSERT INTO devices(address,platform,version,trust,run_id,run_started_at,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?,?,?) " +
        "ON CONFLICT(address) DO UPDATE SET platform=excluded.platform, version=excluded.version, " +
        "trust=excluded.trust, run_id=excluded.run_id, run_started_at=excluded.run_started_at, last_seen_at=excluded.last_seen_at",
    )
      .bind(address, platform, version, info.trust, info.run_id, info.run_started_at, stamp, stamp)
      .run();
    return;
  }
  await env.DB.prepare("UPDATE devices SET last_seen_at=? WHERE address=?").bind(stamp, address).run();
}

/**
 * Every request carries its own Ed25519 signature over method, path, address and
 * timestamp. There is no bearer token to steal and nothing to revoke: the address
 * in the transcript *is* the identity.
 *
 * Replay is not defended here, deliberately — and this is the one place where a
 * reader will look for a nonce and should not find one. Every write this relay
 * accepts is a function of a `call_id` the requester signed: a captured request
 * re-sends bytes that already produced a row, so a second attempt collides on the
 * primary key instead of queueing a second call, a repeated receipt rewrites the
 * same timestamp, and a repeated result either matches the stored envelope byte
 * for byte or is refused. A nonce ledger buys nothing on top of that and costs two
 * rows per request; see docs/THREAT-MODEL.md for the residual risk it does not cover.
 */
async function verifySelfSigned(_env: Env, request: Request, address: string): Promise<void> {
  const timestamp = Number(request.headers.get("x-exe-timestamp") ?? "");
  const signature = request.headers.get("x-exe-signature") ?? "";
  if (!Number.isInteger(timestamp) || timestamp <= 0) throw new ApiError(401, "missing request timestamp");
  if (!signature) throw new ApiError(401, "missing request signature");
  const skew = Math.abs(now() - timestamp);
  if (skew > REQUEST_WINDOW_SECONDS) throw new ApiError(401, "clock is outside the accepted window");

  const path = new URL(request.url).pathname;
  if (!verifyRequest({ method: request.method, path, address, timestamp }, signature)) {
    throw new ApiError(401, "request signature does not verify");
  }
}

/** A device: the address is the path segment `/v1/devices/{address}`. */
export async function authenticateDevice(input: { request: Request; env: Env; address: string }): Promise<void> {
  if (!isAddress(input.address)) throw new ApiError(404, "unknown device");
  await verifySelfSigned(input.env, input.request, input.address);
}

/**
 * The console: same signature, address in a header. It returns the address
 * because that address *is* the identity — there is no account behind it.
 */
export async function authenticateConsole(request: Request, env: Env): Promise<string> {
  const address = request.headers.get("x-exe-address") ?? "";
  if (!isAddress(address)) throw new ApiError(401, "this request names no console address");
  await verifySelfSigned(env, request, address);
  return address;
}
