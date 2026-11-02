// Console API. Every execution-bearing action arrives already signed by the
// browser-held account key; this module only ever *verifies*.
import {
  b64u,
  randomBytes,
  sha256Hex,
  shortAuthenticationString,
  unb64u,
  verifyAccount,
  verifyApproval,
  verifyCall,
} from "../../shared/protocol.ts";
import type { AccountRow, CallRow, DeviceRow, Env, PairingRow } from "./db.ts";
import { accountByUser, callById, deviceById } from "./db.ts";
import { normalizeCode } from "./device.ts";
import { ApiError, body, empty, json, now } from "./http.ts";

const OFFLINE_AFTER_SECONDS = 90;
const CHALLENGE_TTL_SECONDS = 300;
const CLOCK_SKEW_SECONDS = 300;

function isKey(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 40 || value.length > 60) return false;
  try {
    return unb64u(value).length === 32;
  } catch {
    return false;
  }
}
function requireKey(value: unknown, field: string): string {
  if (!isKey(value)) throw new ApiError(400, `${field} must be a 32-byte base64url key`);
  return value;
}
function str(value: unknown, field: string, max: number): string {
  if (typeof value !== "string" || value.length === 0 || value.length > max) throw new ApiError(400, `${field} is invalid`);
  return value;
}
function num(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new ApiError(400, `${field} is invalid`);
  return Math.trunc(value);
}

export interface DeviceView {
  id: string;
  label: string;
  hostname: string;
  platform: string;
  version: string | null;
  sig_pub: string;
  kex_pub: string;
  sas: string;
  status: string;
  online: boolean;
  created_at: number;
  last_seen_at: number | null;
}

function deviceView(row: DeviceRow): DeviceView {
  return {
    id: row.id,
    label: row.label,
    hostname: row.hostname,
    platform: row.platform,
    version: row.version,
    sig_pub: row.sig_pub,
    kex_pub: row.kex_pub,
    sas: row.sas,
    status: row.status,
    online: row.status === "active" && (row.last_seen_at ?? 0) > now() - OFFLINE_AFTER_SECONDS,
    created_at: row.created_at,
    last_seen_at: row.last_seen_at,
  };
}

export interface CallView {
  id: string;
  device_id: string;
  status: string;
  issued_at: number;
  expires_at: number;
  delivered_at: number | null;
  received_at: number | null;
  settled_at: number | null;
  failure_code: string | null;
  error: string | null;
  has_result: boolean;
}

function callView(row: CallRow): CallView {
  return {
    id: row.id,
    device_id: row.device_id,
    status: row.status,
    issued_at: row.issued_at,
    expires_at: row.expires_at,
    delivered_at: row.delivered_at,
    received_at: row.received_at,
    settled_at: row.settled_at,
    failure_code: row.failure_code,
    error: row.error,
    has_result: row.envelope !== null,
  };
}

async function requireAccount(env: Env, userId: string): Promise<AccountRow> {
  const account = await accountByUser(env, userId);
  if (!account) throw new ApiError(409, "this account has no registered key yet", "account_unregistered");
  return account;
}

export async function me(env: Env, userId: string): Promise<Response> {
  const account = await accountByUser(env, userId);
  return json({
    account_id: userId,
    registered: account !== null,
    sig_pub: account?.sig_pub ?? null,
    kex_pub: account?.kex_pub ?? null,
    fingerprint: account ? sha256Hex(account.sig_pub).slice(0, 32) : null,
    created_at: account?.created_at ?? null,
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

/** Registers the browser-held public keys. A signature proves the browser owns them. */
export async function registerAccount(env: Env, userId: string, request: Request): Promise<Response> {
  const input = await body<Record<string, unknown>>(request);
  const sigPub = requireKey(input.sig_pub, "sig_pub");
  const kexPub = requireKey(input.kex_pub, "kex_pub");
  const nonce = str(input.nonce, "nonce", 64);
  const issuedAt = num(input.issued_at, "issued_at");
  const signature = str(input.sig, "sig", 128);
  if (Math.abs(now() - issuedAt) > CHALLENGE_TTL_SECONDS) throw new ApiError(400, "registration is stale");
  const row = await env.DB.prepare("SELECT nonce, expires_at FROM account_challenges WHERE user_id=?")
    .bind(userId)
    .first<{ nonce: string; expires_at: number }>();
  if (!row || row.nonce !== nonce) throw new ApiError(409, "unknown registration challenge");
  if (row.expires_at <= now()) throw new ApiError(410, "registration challenge expired");
  const fields = { userId, nonce, sigPub, kexPub, issuedAt };
  if (!verifyAccount(sigPub, fields, signature)) throw new ApiError(403, "registration signature does not verify");
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO accounts(user_id,sig_pub,kex_pub,created_at,updated_at) VALUES(?,?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET sig_pub=excluded.sig_pub, kex_pub=excluded.kex_pub, updated_at=excluded.updated_at",
    ).bind(userId, sigPub, kexPub, now(), now()),
    env.DB.prepare("DELETE FROM account_challenges WHERE user_id=?").bind(userId),
  ]);
  return json({ account_id: userId, registered: true, sig_pub: sigPub, kex_pub: kexPub });
}

export async function listDevices(env: Env, userId: string): Promise<Response> {
  const rows = await env.DB.prepare("SELECT * FROM devices WHERE owner_user_id=? ORDER BY created_at DESC")
    .bind(userId)
    .all<DeviceRow>();
  return json({ devices: rows.results.map(deviceView) });
}

export async function revokeDevice(env: Env, userId: string, id: string): Promise<Response> {
  const result = await env.DB.prepare("UPDATE devices SET status='revoked', revoked_at=? WHERE id=? AND owner_user_id=?")
    .bind(now(), id, userId)
    .run();
  if (result.meta.changes === 0) throw new ApiError(404, "device not found");
  return empty();
}

export async function readPairing(env: Env, userId: string, rawCode: string): Promise<Response> {
  const code = normalizeCode(rawCode);
  const row = await env.DB.prepare("SELECT * FROM pairings WHERE user_code=?").bind(code).first<PairingRow>();
  if (!row) throw new ApiError(404, "unknown pairing code");
  const account = await accountByUser(env, userId);
  if (!account) throw new ApiError(409, "register this browser's key before approving a device", "account_unregistered");
  const expired = row.status !== "approved" && row.expires_at <= now();
  return json({
    pairing_id: row.id,
    user_code: row.user_code,
    hostname: row.hostname,
    platform: row.platform,
    version: row.version,
    status: expired ? "expired" : row.status,
    expires_at: row.expires_at,
    device_id: row.device_id,
    device_sig_pub: row.dev_sig_pub,
    device_kex_pub: row.dev_kex_pub,
    account_sig_pub: account.sig_pub,
    account_kex_pub: account.kex_pub,
    sas: shortAuthenticationString(account.sig_pub, row.dev_sig_pub),
  });
}

interface ApprovalInput {
  issued_at?: unknown;
  sig?: unknown;
  label?: unknown;
}

/** Stores a browser-signed approval; the worker cannot mint one itself. */
export async function approvePairing(env: Env, userId: string, rawCode: string, request: Request): Promise<Response> {
  const code = normalizeCode(rawCode);
  const input = await body<ApprovalInput>(request).catch(() => ({}) as ApprovalInput);
  const account = await requireAccount(env, userId);
  const row = await env.DB.prepare("SELECT * FROM pairings WHERE user_code=?").bind(code).first<PairingRow>();
  if (!row) throw new ApiError(404, "unknown pairing code");
  if (row.status !== "pending") throw new ApiError(409, `pairing is already ${row.status}`);
  if (row.expires_at <= now()) throw new ApiError(410, "pairing code expired");
  const issuedAt = num(input.issued_at, "issued_at");
  if (Math.abs(now() - issuedAt) > CLOCK_SKEW_SECONDS) throw new ApiError(400, "approval is stale");
  const signature = str(input.sig, "sig", 128);
  const fields = {
    pairingId: row.id,
    deviceId: row.device_id,
    accountId: userId,
    accountSigPub: account.sig_pub,
    accountKexPub: account.kex_pub,
    deviceSigPub: row.dev_sig_pub,
    deviceKexPub: row.dev_kex_pub,
    issuedAt,
  };
  if (!verifyApproval(account.sig_pub, fields, signature)) {
    throw new ApiError(403, "approval signature does not verify against the registered account key");
  }
  const existing = await env.DB.prepare("SELECT id FROM devices WHERE sig_pub=? AND status='active'").bind(row.dev_sig_pub).first<{ id: string }>();
  if (existing) throw new ApiError(409, "this device is already registered");
  const label = typeof input.label === "string" && input.label.trim() ? input.label.trim().slice(0, 80) : row.hostname;
  const sas = shortAuthenticationString(account.sig_pub, row.dev_sig_pub);
  const approval = { ...fields, sig: signature };
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO devices(id,owner_user_id,label,hostname,platform,version,sig_pub,kex_pub,token_hash,status,sas,created_at) VALUES(?,?,?,?,?,?,?,?,?,'active',?,?)",
    ).bind(row.device_id, userId, label, row.hostname, row.platform, row.version, row.dev_sig_pub, row.dev_kex_pub, row.token_hash, sas, now()),
    env.DB.prepare("UPDATE pairings SET status='approved', device_id=?, account_id=?, approval=? WHERE id=? AND status='pending'").bind(
      row.device_id,
      userId,
      JSON.stringify(approval),
      row.id,
    ),
  ]);
  const device = await deviceById(env, row.device_id);
  return json({ device: device ? deviceView(device) : null, sas });
}

export async function denyPairing(env: Env, userId: string, rawCode: string): Promise<Response> {
  const code = normalizeCode(rawCode);
  await requireAccount(env, userId);
  const result = await env.DB.prepare("UPDATE pairings SET status='denied' WHERE user_code=? AND status='pending'").bind(code).run();
  if (result.meta.changes === 0) throw new ApiError(404, "unknown or settled pairing code");
  return empty();
}

interface CallInput {
  id?: unknown;
  eph?: unknown;
  nonce?: unknown;
  ct?: unknown;
  issued_at?: unknown;
  expires_at?: unknown;
  sig?: unknown;
}

function sealed(value: unknown, field: string, bytes: number): Uint8Array {
  if (typeof value !== "string") throw new ApiError(400, `${field} is required`);
  let raw: Uint8Array;
  try {
    raw = unb64u(value);
  } catch {
    throw new ApiError(400, `${field} is not base64url`);
  }
  if (raw.length !== bytes) throw new ApiError(400, `${field} must be ${bytes} bytes`);
  return raw;
}

/**
 * Accepts an opaque, signed command. The worker cannot read the tool or its
 * arguments: it verifies the account signature over the ciphertext and forwards.
 */
export async function createCall(env: Env, userId: string, deviceId: string, request: Request): Promise<Response> {
  const input = await body<CallInput>(request);
  const account = await requireAccount(env, userId);
  const id = str(input.id, "id", 36);
  if (!/^[0-9a-fA-F-]{36}$/.test(id)) throw new ApiError(400, "id must be a UUID");
  const eph = sealed(input.eph, "eph", 32);
  const nonce = sealed(input.nonce, "nonce", 12);
  if (typeof input.ct !== "string") throw new ApiError(400, "ct is required");
  let ciphertext: Uint8Array;
  try {
    ciphertext = unb64u(input.ct);
  } catch {
    throw new ApiError(400, "ct is not base64url");
  }
  if (ciphertext.length < 17 || ciphertext.length > 65536) throw new ApiError(400, "ct has an unsupported size");
  const issuedAt = num(input.issued_at, "issued_at");
  const expiresAt = num(input.expires_at, "expires_at");
  const signature = str(input.sig, "sig", 128);
  if (Math.abs(now() - issuedAt) > CLOCK_SKEW_SECONDS) throw new ApiError(400, "issued_at is stale");
  if (expiresAt <= now()) throw new ApiError(400, "call already expired");
  if (expiresAt - issuedAt > 3600) throw new ApiError(400, "a call may not live longer than one hour");

  const device = await deviceById(env, deviceId);
  if (!device || device.owner_user_id !== userId) throw new ApiError(404, "device not found");
  if (device.status !== "active") throw new ApiError(409, "device is revoked");

  const fields = { callId: id, deviceId: device.id, accountId: userId, eph, nonce, ciphertext, issuedAt, expiresAt };
  if (!verifyCall(account.sig_pub, fields, signature)) {
    throw new ApiError(403, "call signature does not verify against the registered account key");
  }
  if (await callById(env, id)) throw new ApiError(409, "call id already used");
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO calls(id,device_id,owner_user_id,eph,nonce,ct,issued_at,expires_at,sig,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,'queued',?)",
    ).bind(id, device.id, userId, b64u(eph), b64u(nonce), b64u(ciphertext), issuedAt, expiresAt, signature, now()),
    env.DB.prepare("UPDATE calls SET status='expired' WHERE device_id=? AND status='queued' AND expires_at<=?").bind(device.id, now()),
  ]);
  return json({ call: callView((await callById(env, id))!) });
}

export async function listCalls(env: Env, userId: string, url: URL): Promise<Response> {
  const deviceId = url.searchParams.get("device_id");
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? 50) || 50, 1), 200);
  const rows = deviceId
    ? await env.DB.prepare("SELECT * FROM calls WHERE owner_user_id=? AND device_id=? ORDER BY created_at DESC LIMIT ?")
        .bind(userId, deviceId, limit)
        .all<CallRow>()
    : await env.DB.prepare("SELECT * FROM calls WHERE owner_user_id=? ORDER BY created_at DESC LIMIT ?")
        .bind(userId, limit)
        .all<CallRow>();
  return json({ calls: rows.results.map(callView) });
}

/** Returns the sealed envelope verbatim; opening it is the browser's job. */
export async function readCall(env: Env, userId: string, id: string): Promise<Response> {
  const row = await callById(env, id);
  if (!row || row.owner_user_id !== userId) throw new ApiError(404, "call not found");
  return json({ call: callView(row), envelope: row.envelope ? JSON.parse(row.envelope) : null });
}

export async function cancelCall(env: Env, userId: string, id: string): Promise<Response> {
  const row = await callById(env, id);
  if (!row || row.owner_user_id !== userId) throw new ApiError(404, "call not found");
  if (!["queued", "delivered", "received"].includes(row.status)) throw new ApiError(409, "call is already settled");
  await env.DB.prepare(
    "UPDATE calls SET cancel_requested_at=?, status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END, settled_at=CASE WHEN status='queued' THEN ? ELSE settled_at END WHERE id=?",
  )
    .bind(now(), now(), id)
    .run();
  return empty();
}
