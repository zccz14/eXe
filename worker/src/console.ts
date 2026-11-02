// Console API: AuthMini-authenticated device management and call dispatch.
import {
  b64u,
  openResult,
  randomBytes,
  sha256Hex,
  shortAuthenticationString,
  signApproval,
  signCall,
  unb64u,
  type SealedResult,
} from "./crypto.ts";
import type { CallRow, DeviceRow, Env, PairingRow } from "./db.ts";
import { callById, deviceById, ensureAccount, unsealAccount, unsealAccount as unseal } from "./db.ts";
import { normalizeCode } from "./device.ts";
import { ApiError, body, empty, json, now } from "./http.ts";

const OFFLINE_AFTER_SECONDS = 90;

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
  name: string;
  args: string;
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
    name: row.name,
    args: row.args,
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

export async function me(env: Env, userId: string): Promise<Response> {
  const account = await ensureAccount(env, userId);
  return json({
    account_id: userId,
    sig_pub: account.sig_pub,
    kex_pub: account.kex_pub,
    fingerprint: sha256Hex(account.sig_pub).slice(0, 32),
    created_at: account.created_at,
  });
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
  const account = await ensureAccount(env, userId);
  const expired = row.status !== "approved" && row.expires_at <= now();
  return json({
    user_code: row.user_code,
    hostname: row.hostname,
    platform: row.platform,
    version: row.version,
    status: expired ? "expired" : row.status,
    expires_at: row.expires_at,
    device_sig_pub: row.dev_sig_pub,
    sas: shortAuthenticationString(account.sig_pub, row.dev_sig_pub),
  });
}

export async function approvePairing(env: Env, userId: string, rawCode: string, request: Request): Promise<Response> {
  const code = normalizeCode(rawCode);
  const input = await body<{ label?: string }>(request).catch(() => ({}) as { label?: string });
  const row = await env.DB.prepare("SELECT * FROM pairings WHERE user_code=?").bind(code).first<PairingRow>();
  if (!row) throw new ApiError(404, "unknown pairing code");
  if (row.status !== "pending") throw new ApiError(409, `pairing is already ${row.status}`);
  if (row.expires_at <= now()) throw new ApiError(410, "pairing code expired");
  const existing = await env.DB.prepare("SELECT id FROM devices WHERE sig_pub=? AND status='active'").bind(row.dev_sig_pub).first<{ id: string }>();
  if (existing) throw new ApiError(409, "this device is already registered");

  const account = await unseal(env, userId);
  const deviceId = crypto.randomUUID();
  const issuedAt = now();
  const label = (input.label ?? row.hostname).slice(0, 80);
  const sas = shortAuthenticationString(account.row.sig_pub, row.dev_sig_pub);
  const approvalFields = {
    pairingId: row.id,
    deviceId,
    accountId: userId,
    accountSigPub: account.row.sig_pub,
    accountKexPub: account.row.kex_pub,
    deviceSigPub: row.dev_sig_pub,
    deviceKexPub: row.dev_kex_pub,
    issuedAt,
  };
  const approval = { ...approvalFields, sig: signApproval(account.sigSk, approvalFields) };
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO devices(id,owner_user_id,label,hostname,platform,version,sig_pub,kex_pub,token_hash,status,sas,created_at) VALUES(?,?,?,?,?,?,?,?,?,'active',?,?)",
    ).bind(deviceId, userId, label, row.hostname, row.platform, row.version, row.dev_sig_pub, row.dev_kex_pub, row.token_hash, sas, now()),
    env.DB.prepare("UPDATE pairings SET status='approved', device_id=?, account_id=?, approval=? WHERE id=? AND status='pending'").bind(
      deviceId,
      userId,
      JSON.stringify(approval),
      row.id,
    ),
  ]);
  const device = await deviceById(env, deviceId);
  return json({ device: device ? deviceView(device) : null, sas });
}

export async function denyPairing(env: Env, userId: string, rawCode: string): Promise<Response> {
  const code = normalizeCode(rawCode);
  await ensureAccount(env, userId);
  const result = await env.DB.prepare("UPDATE pairings SET status='denied' WHERE user_code=? AND status='pending'").bind(code).run();
  if (result.meta.changes === 0) throw new ApiError(404, "unknown or settled pairing code");
  return empty();
}

export async function createCall(env: Env, userId: string, deviceId: string, request: Request): Promise<Response> {
  const input = await body<{ name?: unknown; args?: unknown; ttl?: unknown }>(request);
  if (typeof input.name !== "string" || !/^[a-z][a-z0-9_:.-]{0,63}$/.test(input.name)) throw new ApiError(400, "invalid tool name");
  const args = input.args ?? {};
  if (typeof args !== "object" || args === null || Array.isArray(args)) throw new ApiError(400, "args must be a JSON object");
  const ttl = typeof input.ttl === "number" && input.ttl >= 10 && input.ttl <= 3600 ? Math.trunc(input.ttl) : 300;
  const device = await deviceById(env, deviceId);
  if (!device || device.owner_user_id !== userId) throw new ApiError(404, "device not found");
  if (device.status !== "active") throw new ApiError(409, "device is revoked");

  const account = await unsealAccount(env, userId);
  const callId = crypto.randomUUID();
  const issuedAt = now();
  const fields = {
    callId,
    deviceId: device.id,
    accountId: userId,
    name: input.name,
    args: JSON.stringify(args),
    nonce: b64u(randomBytes(16)),
    issuedAt,
    expiresAt: issuedAt + ttl,
  };
  const sig = signCall(account.sigSk, fields);
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO calls(id,device_id,owner_user_id,name,args,nonce,issued_at,expires_at,sig,status,created_at) VALUES(?,?,?,?,?,?,?,?,?,'queued',?)",
    ).bind(callId, device.id, userId, fields.name, fields.args, fields.nonce, fields.issuedAt, fields.expiresAt, sig, now()),
    env.DB.prepare("UPDATE calls SET status='expired' WHERE device_id=? AND status='queued' AND expires_at<=?").bind(device.id, now()),
  ]);
  return json({ call: callView((await callById(env, callId))!), sig });
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

export async function readCall(env: Env, userId: string, id: string): Promise<Response> {
  const row = await callById(env, id);
  if (!row || row.owner_user_id !== userId) throw new ApiError(404, "call not found");
  let result: unknown = null;
  if (row.envelope) {
    const account = await unsealAccount(env, userId);
    try {
      result = JSON.parse(openResult({ accountKexSk: account.kexSk, callId: row.id, deviceId: row.device_id, envelope: JSON.parse(row.envelope) as SealedResult }));
    } catch {
      result = { ok: false, error: "result envelope could not be opened" };
    }
  }
  return json({ call: callView(row), result });
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
