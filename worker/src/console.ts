// Console API. The browser signs every execution-bearing action with the single
// Ed25519 key it owns; this module only ever verifies. The relay can route and
// queue, never sign, never decrypt.
import {
  b64u,
  isAddress,
  randomBytes,
  verifyAccount,
  verifyCall,
  type CallEnvelope,
} from "../../shared/protocol.ts";
import type { AccountRow, AgentRow, CallRow, DeviceRow, Env } from "./db.ts";
import { accountByUser, callById, deviceByAddress } from "./db.ts";
import { ApiError, body, empty, json, now } from "./http.ts";

const OFFLINE_AFTER_SECONDS = 90;
const CHALLENGE_TTL_SECONDS = 300;
const CLOCK_SKEW_SECONDS = 300;
const MAX_CALL_TTL_SECONDS = 3600;
const MAX_SEALED_CHARS = 96 * 1024;

function str(value: unknown, field: string, max: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) throw new ApiError(400, `${field} is invalid`);
  return value;
}
function num(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new ApiError(400, `${field} is invalid`);
  return Math.trunc(value);
}
function requireAddress(value: unknown, field: string): string {
  if (!isAddress(value)) throw new ApiError(400, `${field} must be a base58 eXe address`);
  return value;
}

export interface DeviceView {
  address: string;
  label: string;
  hostname: string | null;
  platform: string | null;
  version: string | null;
  online: boolean;
  last_seen_at: number | null;
  created_at: number;
  revoked_at: number | null;
}

function deviceView(device: DeviceRow, agent: AgentRow | null): DeviceView {
  const lastSeen = agent?.last_seen_at ?? null;
  return {
    address: device.address,
    label: device.label,
    hostname: agent?.hostname ?? null,
    platform: agent?.platform ?? null,
    version: agent?.version ?? null,
    online: device.revoked_at === null && lastSeen !== null && lastSeen > now() - OFFLINE_AFTER_SECONDS,
    last_seen_at: lastSeen,
    created_at: device.created_at,
    revoked_at: device.revoked_at,
  };
}

export interface CallView {
  call_id: string;
  device: string;
  issuer: string;
  status: string;
  issued_at: number;
  expires_at: number;
  delivered_at: number | null;
  received_at: number | null;
  settled_at: number | null;
  has_result: boolean;
}

function callView(row: CallRow): CallView {
  return {
    call_id: row.call_id,
    device: row.device_address,
    issuer: row.issuer,
    status: row.status,
    issued_at: row.issued_at,
    expires_at: row.expires_at,
    delivered_at: row.delivered_at,
    received_at: row.received_at,
    settled_at: row.settled_at,
    has_result: row.result !== null,
  };
}

async function requireAccount(env: Env, userId: string): Promise<AccountRow> {
  const account = await accountByUser(env, userId);
  if (!account) throw new ApiError(409, "this account has no registered address yet", "account_unregistered");
  return account;
}

export async function me(env: Env, userId: string): Promise<Response> {
  const account = await accountByUser(env, userId);
  return json({
    account_id: userId,
    registered: account !== null,
    address: account?.address ?? null,
    custody: "browser",
  });
}

export async function challenge(env: Env, userId: string): Promise<Response> {
  const nonce = b64u(randomBytes(24));
  const expiresAt = now() + CHALLENGE_TTL_SECONDS;
  await env.DB.prepare(
    "INSERT INTO account_challenges(user_id,nonce,expires_at) VALUES(?,?,?) ON CONFLICT(user_id) DO UPDATE SET nonce=excluded.nonce, expires_at=excluded.expires_at",
  )
    .bind(userId, nonce, expiresAt)
    .run();
  return json({ user_id: userId, nonce, expires_at: expiresAt });
}

/** Registers the browser-held address. The signature proves it owns the key. */
export async function registerAccount(env: Env, userId: string, request: Request): Promise<Response> {
  const input = await body<Record<string, unknown>>(request);
  const address = requireAddress(input.address, "address");
  const nonce = str(input.nonce, "nonce", 64);
  const issuedAt = num(input.issued_at, "issued_at");
  const signature = str(input.sig, "sig", 128);
  if (Math.abs(now() - issuedAt) > CHALLENGE_TTL_SECONDS) throw new ApiError(400, "registration is stale");

  const row = await env.DB.prepare("SELECT nonce, expires_at FROM account_challenges WHERE user_id=?")
    .bind(userId)
    .first<{ nonce: string; expires_at: number }>();
  if (!row || row.nonce !== nonce) throw new ApiError(409, "unknown registration challenge");
  if (row.expires_at <= now()) throw new ApiError(410, "registration challenge expired");

  const fields = { address, userId, nonce, issuedAt };
  if (!verifyAccount(fields, signature)) throw new ApiError(403, "registration signature does not verify against this address");

  const holder = await env.DB.prepare("SELECT user_id FROM accounts WHERE address=?").bind(address).first<{ user_id: string }>();
  if (holder && holder.user_id !== userId) throw new ApiError(409, "this address is registered to another account");

  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO accounts(user_id,address,created_at,updated_at) VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET address=excluded.address, updated_at=excluded.updated_at",
    ).bind(userId, address, now(), now()),
    env.DB.prepare("DELETE FROM account_challenges WHERE user_id=?").bind(userId),
  ]);
  return json({ account_id: userId, registered: true, address });
}

export async function listDevices(env: Env, userId: string): Promise<Response> {
  const rows = await env.DB.prepare(
    `SELECT d.*, a.hostname AS agent_hostname, a.platform AS agent_platform, a.version AS agent_version, a.last_seen_at AS agent_last_seen
     FROM devices d LEFT JOIN agents a ON a.address = d.address
     WHERE d.owner_user_id=? ORDER BY d.created_at DESC`,
  )
    .bind(userId)
    .all<DeviceRow & { agent_hostname: string | null; agent_platform: string | null; agent_version: string | null; agent_last_seen: number | null }>();
  return json({
    devices: rows.results.map((row) => {
      const agent: AgentRow | null =
        row.agent_last_seen === null
          ? null
          : {
              address: row.address,
              hostname: row.agent_hostname ?? "",
              platform: row.agent_platform ?? "",
              version: row.agent_version ?? "",
              first_seen_at: row.agent_last_seen,
              last_seen_at: row.agent_last_seen,
            };
      return deviceView(row, agent);
    }),
  });
}

/** Adding a device is typing its address: no code, no approval, no pairing. */
export async function addDevice(env: Env, userId: string, request: Request): Promise<Response> {
  const input = await body<Record<string, unknown>>(request);
  const address = requireAddress(input.address, "address");
  const label = typeof input.label === "string" && input.label.trim() ? input.label.trim().slice(0, 80) : address.slice(0, 12);
  // Every account keeps its own address book. Whether the device trusts this
  // account is decided on the device, not here.
  await env.DB.prepare(
    "INSERT INTO devices(owner_user_id,address,label,created_at) VALUES(?,?,?,?) " +
      "ON CONFLICT(owner_user_id,address) DO UPDATE SET label=excluded.label, revoked_at=NULL",
  )
    .bind(userId, address, label, now())
    .run();
  const device = await deviceByAddress(env, userId, address);
  const agent = await env.DB.prepare("SELECT * FROM agents WHERE address=?").bind(address).first<AgentRow>();
  return json({ device: deviceView(device!, agent ?? null) });
}

export async function removeDevice(env: Env, userId: string, address: string): Promise<Response> {
  if (!isAddress(address)) throw new ApiError(404, "device not found");
  const result = await env.DB.prepare("DELETE FROM devices WHERE owner_user_id=? AND address=?").bind(userId, address).run();
  if (result.meta.changes === 0) throw new ApiError(404, "device not found");
  await env.DB.prepare("UPDATE calls SET status='cancelled', settled_at=? WHERE device_address=? AND owner_user_id=? AND status IN ('queued','delivered','received')")
    .bind(now(), address, userId)
    .run();
  return empty();
}

/**
 * Accepts an opaque, signed command. The relay cannot read the tool or its
 * arguments: it verifies the issuer signature over the ciphertext and queues it.
 */
export async function createCall(env: Env, userId: string, address: string, request: Request): Promise<Response> {
  const input = await body<Record<string, unknown>>(request);
  const account = await requireAccount(env, userId);
  const callId = str(input.call_id, "call_id", 64);
  if (!/^[0-9a-zA-Z-]{8,64}$/.test(callId)) throw new ApiError(400, "call_id must be 8-64 url-safe characters");
  const issuer = requireAddress(input.issuer, "issuer");
  const device = requireAddress(input.device, "device");
  if (issuer !== account.address) throw new ApiError(403, "a call must be signed by the registered address");
  if (device !== address) throw new ApiError(400, "the envelope names another device");
  const sealed = str(input.sealed, "sealed", MAX_SEALED_CHARS);
  const sig = str(input.sig, "sig", 128);
  const issuedAt = num(input.issued_at, "issued_at");
  const expiresAt = num(input.expires_at, "expires_at");
  if (Math.abs(now() - issuedAt) > CLOCK_SKEW_SECONDS) throw new ApiError(400, "issued_at is stale");
  if (expiresAt <= now()) throw new ApiError(400, "call already expired");
  if (expiresAt - issuedAt > MAX_CALL_TTL_SECONDS) throw new ApiError(400, "a call may not live longer than one hour");

  const row: CallEnvelope = { call_id: callId, issuer, device, issued_at: issuedAt, expires_at: expiresAt, sealed, sig };
  if (!verifyCall(row)) throw new ApiError(403, "call signature does not verify against the registered address");

  const deviceRow = await deviceByAddress(env, userId, address);
  if (!deviceRow || deviceRow.owner_user_id !== userId) throw new ApiError(404, "device not found");
  if (deviceRow.revoked_at !== null) throw new ApiError(409, "device is revoked");
  if (await callById(env, callId)) throw new ApiError(409, "call_id already used");

  await env.DB.prepare(
    "INSERT INTO calls(call_id,device_address,owner_user_id,issuer,sealed,sig,issued_at,expires_at,status,created_at) VALUES(?,?,?,?,?,?,?,?,'queued',?)",
  )
    .bind(callId, address, userId, issuer, sealed, sig, issuedAt, expiresAt, now())
    .run();
  return json({ call: callView((await callById(env, callId))!) });
}

export async function listCalls(env: Env, userId: string, url: URL): Promise<Response> {
  const address = url.searchParams.get("device");
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? 50) || 50, 1), 200);
  const rows = address
    ? await env.DB.prepare("SELECT * FROM calls WHERE owner_user_id=? AND device_address=? ORDER BY created_at DESC LIMIT ?")
        .bind(userId, address, limit)
        .all<CallRow>()
    : await env.DB.prepare("SELECT * FROM calls WHERE owner_user_id=? ORDER BY created_at DESC LIMIT ?")
        .bind(userId, limit)
        .all<CallRow>();
  return json({ calls: rows.results.map(callView) });
}

/** Returns the sealed result envelope verbatim; opening it is the browser's job. */
export async function readCall(env: Env, userId: string, callId: string): Promise<Response> {
  const row = await callById(env, callId);
  if (!row || row.owner_user_id !== userId) throw new ApiError(404, "call not found");
  return json({ call: callView(row), result: row.result ? JSON.parse(row.result) : null });
}

export async function cancelCall(env: Env, userId: string, callId: string): Promise<Response> {
  const row = await callById(env, callId);
  if (!row || row.owner_user_id !== userId) throw new ApiError(404, "call not found");
  if (!["queued", "delivered", "received"].includes(row.status)) throw new ApiError(409, "call is already settled");
  await env.DB.prepare(
    "UPDATE calls SET cancel_requested_at=?, status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END, settled_at=CASE WHEN status='queued' THEN ? ELSE settled_at END WHERE call_id=?",
  )
    .bind(now(), now(), callId)
    .run();
  return empty();
}
