// Storage layer. The relay never holds a private key: only public keys, sealed
// envelopes and signatures are persisted (see docs/THREAT-MODEL.md).
import { isAddress, verifyRequest } from "../../shared/protocol.ts";
import { ApiError, now } from "./http.ts";

export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  /** Comma-separated origins allowed to call the console API from another origin. */
  CONSOLE_ORIGINS?: string;
  /** owner/name of the repository whose GitHub Releases carry the client binaries. */
  GITHUB_REPO?: string;
}

/** Everything a signed request may be used for: five minutes either way. */
export const REQUEST_WINDOW_SECONDS = 300;

export interface AgentRow {
  address: string;
  hostname: string;
  platform: string;
  version: string;
  first_seen_at: number;
  last_seen_at: number;
}

export interface DeviceRow {
  /** The console that keeps this device in its own address book. */
  owner_address: string;
  address: string;
  label: string;
  created_at: number;
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
  delivered_at: number | null;
  received_at: number | null;
  settled_at: number | null;
  result: string | null;
  cancel_requested_at: number | null;
  cancel_notified_at: number | null;
  created_at: number;
}

export async function deviceByAddress(env: Env, owner: string, address: string): Promise<DeviceRow | null> {
  return env.DB.prepare("SELECT * FROM devices WHERE owner_address=? AND address=?")
    .bind(owner, address)
    .first<DeviceRow>();
}

export async function agentByAddress(env: Env, address: string): Promise<AgentRow | null> {
  return env.DB.prepare("SELECT * FROM agents WHERE address=?").bind(address).first<AgentRow>();
}

export async function callById(env: Env, callId: string): Promise<CallRow | null> {
  return env.DB.prepare("SELECT * FROM calls WHERE call_id=?").bind(callId).first<CallRow>();
}

export interface AgentInfo {
  hostname: string;
  platform: string;
  version: string;
}

/** Records that an address is alive; the relay stores nothing else about it. */
export async function touchAgent(env: Env, address: string, info?: AgentInfo): Promise<void> {
  const stamp = now();
  if (info) {
    const hostname = info.hostname.slice(0, 80);
    const platform = info.platform.slice(0, 40);
    const version = info.version.slice(0, 20);
    await env.DB.prepare(
      "INSERT INTO agents(address,hostname,platform,version,first_seen_at,last_seen_at) VALUES(?,?,?,?,?,?) " +
        "ON CONFLICT(address) DO UPDATE SET hostname=excluded.hostname, platform=excluded.platform, version=excluded.version, last_seen_at=excluded.last_seen_at",
    )
      .bind(address, hostname, platform, version, stamp, stamp)
      .run();
    return;
  }
  await env.DB.prepare("UPDATE agents SET last_seen_at=? WHERE address=?").bind(stamp, address).run();
}

/**
 * Every request carries its own Ed25519 signature over method, path, address,
 * timestamp and a single-use nonce. There is no bearer token to steal: a
 * captured request dies with its nonce. Devices and the console use the same
 * scheme; they only disagree on where the address travels.
 */
async function verifySelfSigned(env: Env, request: Request, address: string): Promise<void> {
  const timestamp = Number(request.headers.get("x-exe-timestamp") ?? "");
  const nonce = request.headers.get("x-exe-nonce") ?? "";
  const signature = request.headers.get("x-exe-signature") ?? "";
  if (!Number.isInteger(timestamp) || timestamp <= 0) throw new ApiError(401, "missing request timestamp");
  if (nonce.length < 16 || nonce.length > 64) throw new ApiError(401, "missing request nonce");
  if (!signature) throw new ApiError(401, "missing request signature");
  const skew = Math.abs(now() - timestamp);
  if (skew > REQUEST_WINDOW_SECONDS) throw new ApiError(401, "clock is outside the accepted window");

  const path = new URL(request.url).pathname;
  if (!verifyRequest({ method: request.method, path, address, timestamp, nonce }, signature)) {
    throw new ApiError(401, "request signature does not verify");
  }

  const claimed = await env.DB.prepare(
    "INSERT INTO request_nonces(address,nonce,expires_at) VALUES(?,?,?) ON CONFLICT(address,nonce) DO NOTHING",
  )
    .bind(address, nonce, timestamp + REQUEST_WINDOW_SECONDS * 2)
    .run();
  if (claimed.meta.changes === 0) throw new ApiError(401, "this request nonce was already used");

  // Opportunistic sweep; the table only ever holds one clock window of nonces.
  if (Math.random() < 0.05) {
    await env.DB.prepare("DELETE FROM request_nonces WHERE expires_at < ?").bind(now()).run();
  }
}

/** A device: the address is the path segment `/v1/agents/{address}`. */
export async function authenticateDevice(input: { request: Request; env: Env; address: string }): Promise<void> {
  if (!isAddress(input.address)) throw new ApiError(404, "unknown agent");
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
