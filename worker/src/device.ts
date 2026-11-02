// Device-facing API: pairing, SSE event stream, receipts, sealed results.
import {
  b64u,
  equalHex,
  randomBytes,
  sha256Hex,
  openResult,
  shortAuthenticationString,
  unb64u,
  verifyResultSignature,
  type SealedResult,
} from "./crypto.ts";
import type { CallRow, DeviceRow, Env } from "./db.ts";
import { callById, deviceByToken, unsealAccount } from "./db.ts";
import { ApiError, body, empty, json, now } from "./http.ts";

const PAIRING_TTL_SECONDS = 600;
const POLL_INTERVAL_SECONDS = 2;
const STREAM_MAX_SECONDS = 900;
const DEVICE_OFFLINE_SECONDS = 90;

function isKey(value: unknown): value is string {
  if (typeof value !== "string" || value.length < 40 || value.length > 60) return false;
  try {
    return unb64u(value).length === 32;
  } catch {
    return false;
  }
}
function isHash(value: unknown): value is string {
  return typeof value === "string" && /^[0-9a-f]{64}$/.test(value);
}
function shortLabel(value: unknown, field: string, max: number): string {
  if (typeof value !== "string") throw new ApiError(400, `${field} is required`);
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > max) throw new ApiError(400, `${field} must be 1-${max} characters`);
  return trimmed;
}
function formatCode(raw: string): string {
  return `${raw.slice(0, 4)}-${raw.slice(4, 8)}-${raw.slice(8, 12)}`.toUpperCase();
}
export function normalizeCode(value: string): string {
  const cleaned = value.replaceAll(/[\s-]/g, "").toUpperCase();
  if (!/^[0-9A-F]{12}$/.test(cleaned)) throw new ApiError(400, "enter the 12-character code shown on the device");
  return formatCode(cleaned);
}

export async function startPairing(request: Request, env: Env): Promise<Response> {
  const input = await body<Record<string, unknown>>(request);
  if (!isKey(input.dev_sig_pub) || !isKey(input.dev_kex_pub)) throw new ApiError(400, "device public keys must be 32-byte base64url");
  if (!isHash(input.secret_hash) || !isHash(input.token_hash)) throw new ApiError(400, "device digests must be sha256 hex");
  const hostname = shortLabel(input.hostname, "hostname", 80);
  const platform = shortLabel(input.platform, "platform", 40);
  const version = shortLabel(input.version, "version", 20);
  const id = crypto.randomUUID();
  const code = formatCode(sha256Hex(id).slice(0, 12));
  const expiresAt = now() + PAIRING_TTL_SECONDS;
  // One live pairing per device key: restarting the agent replaces the previous code.
  await env.DB.batch([
    env.DB.prepare("DELETE FROM pairings WHERE dev_sig_pub=? AND status='pending'").bind(input.dev_sig_pub),
    env.DB.prepare("DELETE FROM pairings WHERE expires_at<? ").bind(now() - 86400),
    env.DB.prepare(
      "INSERT INTO pairings(id,user_code,secret_hash,token_hash,dev_sig_pub,dev_kex_pub,hostname,platform,version,expires_at,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)",
    ).bind(
      id,
      code,
      input.secret_hash,
      input.token_hash,
      input.dev_sig_pub,
      input.dev_kex_pub,
      hostname,
      platform,
      version,
      expiresAt,
      now(),
    ),
  ]);
  return json({
    pairing_id: id,
    user_code: code,
    expires_at: expiresAt,
    interval: POLL_INTERVAL_SECONDS * 1000,
    verify_uri: `https://${env.AUTH_AUDIENCE}/#/pair`,
  });
}

export async function pollPairing(request: Request, env: Env, id: string): Promise<Response> {
  const header = request.headers.get("authorization") ?? "";
  if (!header.toLowerCase().startsWith("bearer ")) throw new ApiError(401, "missing device secret");
  const secretHash = sha256Hex(header.slice(7).trim());
  const row = await env.DB.prepare("SELECT * FROM pairings WHERE id=?").bind(id).first<{
    id: string;
    secret_hash: string;
    status: string;
    expires_at: number;
    approval: string | null;
    device_id: string | null;
    account_id: string | null;
    last_polled_at: number;
  }>();
  if (!row || !equalHex(row.secret_hash, secretHash)) throw new ApiError(401, "unknown pairing");
  if (row.status !== "approved" && row.expires_at <= now()) throw new ApiError(410, "pairing expired; restart the agent");
  if (row.status === "pending" && now() - row.last_polled_at < POLL_INTERVAL_SECONDS) {
    throw new ApiError(429, `poll no faster than every ${POLL_INTERVAL_SECONDS} seconds`);
  }
  await env.DB.prepare("UPDATE pairings SET last_polled_at=? WHERE id=?").bind(now(), id).run();
  if (row.status === "approved" && row.approval) {
    return json({
      status: "approved",
      device_id: row.device_id,
      account_id: row.account_id,
      approval: JSON.parse(row.approval),
    });
  }
  return json({ status: row.status }, row.status === "pending" ? 202 : 200);
}

/** Marks calls stranded by a previous boot; the side effect may already have happened. */
export async function registerBoot(env: Env, device: DeviceRow, bootId: string, version: string | null): Promise<void> {
  if (device.boot_id !== bootId) {
    await env.DB.batch([
      env.DB.prepare(
        "UPDATE calls SET status='failed', failure_code='device_restarted', error=?, settled_at=? WHERE device_id=? AND status IN ('delivered','received') AND (device_boot_id IS NULL OR device_boot_id<>?)",
      ).bind("device restarted; the result was lost and the operation may already have happened", now(), device.id, bootId),
      env.DB.prepare("UPDATE devices SET boot_id=? WHERE id=?").bind(bootId, device.id),
    ]);
  }
  await env.DB.prepare("UPDATE devices SET last_seen_at=?, version=COALESCE(?,version), status='active' WHERE id=?")
    .bind(now(), version, device.id)
    .run();
}

async function claimCall(env: Env, deviceId: string, bootId: string): Promise<CallRow | null> {
  const rows = await env.DB.prepare(
    `UPDATE calls SET status='delivered', device_boot_id=?, delivered_at=?
     WHERE id=(SELECT id FROM calls WHERE device_id=? AND status='queued' AND expires_at>? ORDER BY created_at,id LIMIT 1)
     RETURNING *`,
  )
    .bind(bootId, now(), deviceId, now())
    .all<CallRow>();
  return rows.results[0] ?? null;
}

async function claimCancellation(env: Env, deviceId: string): Promise<string | null> {
  const rows = await env.DB.prepare(
    `UPDATE calls SET cancel_notified_at=?
     WHERE id=(SELECT id FROM calls WHERE device_id=? AND status='delivered' AND cancel_requested_at IS NOT NULL AND cancel_notified_at IS NULL ORDER BY created_at,id LIMIT 1)
     RETURNING id`,
  )
    .bind(now(), deviceId)
    .all<{ id: string }>();
  return rows.results[0]?.id ?? null;
}

function sseChunk(event: string, data: unknown): Uint8Array {
  return new TextEncoder().encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

export async function eventStream(request: Request, env: Env, deviceId: string): Promise<Response> {
  const device = await deviceByToken(env, deviceId, request).catch(() => {
    throw new ApiError(401, "invalid device credentials");
  });
  const bootId = request.headers.get("x-exe-boot-id") ?? "";
  if (!/^[0-9a-f-]{36}$/i.test(bootId)) throw new ApiError(400, "x-exe-boot-id must be a UUID");
  const version = request.headers.get("x-exe-version");
  await registerBoot(env, device, bootId, version);

  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
  const writer = writable.getWriter();
  const startedAt = Date.now();
  const pump = async () => {
    try {
      await writer.write(sseChunk("hello", { device_id: device.id, sas: device.sas, now: now() }));
      while (Date.now() - startedAt < STREAM_MAX_SECONDS * 1000) {
        const call = await claimCall(env, device.id, bootId);
        if (call) {
          await writer.write(
            sseChunk("call", {
              id: call.id,
              device_id: call.device_id,
              account_id: call.owner_user_id,
              name: call.name,
              args: call.args,
              nonce: call.nonce,
              issued_at: call.issued_at,
              expires_at: call.expires_at,
              sig: call.sig,
            }),
          );
        } else {
          const cancelled = await claimCancellation(env, device.id);
          if (cancelled) await writer.write(sseChunk("cancel", { id: cancelled }));
          else await writer.write(sseChunk("heartbeat", { now: now() }));
        }
        await sleep(1000);
      }
    } catch {
      // Client went away or the runtime cancelled the request; nothing to clean up.
    } finally {
      await writer.close().catch(() => undefined);
    }
  };
  void pump();
  return new Response(readable, {
    headers: {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store",
      connection: "keep-alive",
      "x-exe-boot-id": bootId,
    },
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

export async function heartbeat(request: Request, env: Env, deviceId: string): Promise<Response> {
  const device = await deviceByToken(env, deviceId, request).catch(() => {
    throw new ApiError(401, "invalid device credentials");
  });
  await env.DB.prepare("UPDATE devices SET last_seen_at=? WHERE id=?").bind(now(), device.id).run();
  return json({ ok: true, now: now(), offline_after_seconds: DEVICE_OFFLINE_SECONDS });
}

export async function markReceived(request: Request, env: Env, deviceId: string, callId: string): Promise<Response> {
  const device = await deviceByToken(env, deviceId, request).catch(() => {
    throw new ApiError(401, "invalid device credentials");
  });
  const result = await env.DB.prepare(
    "UPDATE calls SET status='received', received_at=? WHERE id=? AND device_id=? AND status='delivered'",
  )
    .bind(now(), callId, device.id)
    .run();
  if (result.meta.changes === 0) throw new ApiError(409, "call is not awaiting a receipt");
  return empty();
}

interface ResultInput {
  v?: number;
  eph?: string;
  nonce?: string;
  ct?: string;
  sig?: string;
}

export async function submitResult(request: Request, env: Env, deviceId: string, callId: string): Promise<Response> {
  const device = await deviceByToken(env, deviceId, request).catch(() => {
    throw new ApiError(401, "invalid device credentials");
  });
  const input = await body<ResultInput>(request);
  if (input.v !== 1) throw new ApiError(400, "unsupported result envelope version");
  let eph: Uint8Array;
  let nonce: Uint8Array;
  let ciphertext: Uint8Array;
  try {
    eph = unb64u(String(input.eph));
    nonce = unb64u(String(input.nonce));
    ciphertext = unb64u(String(input.ct));
  } catch {
    throw new ApiError(400, "malformed result envelope");
  }
  if (eph.length !== 32 || nonce.length !== 12 || ciphertext.length < 17) throw new ApiError(400, "malformed result envelope");
  if (typeof input.sig !== "string") throw new ApiError(400, "result envelope is missing a signature");
  if (!verifyResultSignature(device.sig_pub, { callId, deviceId: device.id, eph, nonce, ciphertext }, input.sig)) {
    throw new ApiError(403, "result signature does not match the device key");
  }
  const call = await callById(env, callId);
  if (!call || call.device_id !== device.id) throw new ApiError(404, "unknown call");
  if (!["delivered", "received"].includes(call.status)) throw new ApiError(409, "call is already settled");

  const account = await unsealAccount(env, call.owner_user_id);
  const envelope: SealedResult = { v: 1, eph: b64u(eph), nonce: b64u(nonce), ct: b64u(ciphertext) };
  let ok = false;
  try {
    const plaintext = openResult({ accountKexSk: account.kexSk, callId, deviceId: device.id, envelope });
    const parsed = JSON.parse(plaintext) as { ok?: boolean };
    ok = parsed.ok === true;
  } catch {
    throw new ApiError(400, "result envelope could not be opened");
  }
  await env.DB.prepare(
    "UPDATE calls SET envelope=?, sig=COALESCE(sig,?), status=?, settled_at=?, failure_code=NULL WHERE id=? AND status IN ('delivered','received')",
  )
    .bind(JSON.stringify(envelope), input.sig, ok ? "succeeded" : "failed", now(), callId)
    .run();
  return empty();
}

export { shortAuthenticationString, randomBytes };
