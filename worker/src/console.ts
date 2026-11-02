// Console API. The browser signs every request with the one Ed25519 key it owns;
// this module only ever verifies. The relay can route and queue, never sign,
// never decrypt. There is no account behind the address: the address is the
// identity, so "who owns this row" is answered by the signature that made it.
//
// The relay keeps no address book. Which devices a console talks to is a fact
// about that browser (IndexedDB), not a row here — and it was never a boundary
// anyway, because a device decides by its own `trust` list (docs/SOUL.md §9).
import { isAddress, verifyCall, type CallEnvelope } from "../../shared/protocol.ts";
import type { CallRow, Env } from "./db.ts";
import { callById, deviceByAddress, trustList } from "./db.ts";
import { ApiError, body, empty, json, now } from "./http.ts";

const OFFLINE_AFTER_SECONDS = 90;
const CLOCK_SKEW_SECONDS = 300;
const MAX_CALL_TTL_SECONDS = 3600;
/**
 * The HTTP body of a create request, and therefore the only authority on how big
 * a command envelope may be. A command is a line of shell; 64 KiB is already
 * generous. There is deliberately no second constant to drift out of sync with
 * this one — the old `MAX_SEALED_CHARS = 96 KiB` never fired, because the body
 * limit rejected the request first.
 */
const MAX_CALL_BODY = 64 * 1024;

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

/** What the relay knows about one address: whether it has ever checked in. */
export interface DeviceStatus {
  address: string;
  registered: boolean;
  platform: string | null;
  version: string | null;
  /** The `exe run` process currently behind this address. A change means a restart. */
  run_id: string | null;
  run_started_at: number | null;
  online: boolean;
  last_seen_at: number | null;
}

export interface CallView {
  call_id: string;
  device: string;
  issuer: string;
  status: string;
  issued_at: number;
  expires_at: number;
  received_at: number | null;
  settled_at: number | null;
  has_result: boolean;
  /** Size of the attachment when the result was too big for the row. */
  blob_bytes: number | null;
}

function callView(row: CallRow): CallView {
  return {
    call_id: row.call_id,
    device: row.device_address,
    issuer: row.issuer,
    status: row.status,
    issued_at: row.issued_at,
    expires_at: row.expires_at,
    received_at: row.received_at,
    settled_at: row.settled_at,
    has_result: row.result !== null,
    blob_bytes: row.blob_bytes,
  };
}

/**
 * The attachment verbatim, still sealed. Only the console that signed the call
 * may ask for it, and only the console's key can open it afterwards.
 */
export async function readBlob(env: Env, owner: string, callId: string): Promise<Response> {
  const row = await callById(env, callId);
  if (!row || row.issuer !== owner) throw new ApiError(404, "call not found");
  if (row.blob_bytes === null) throw new ApiError(404, "this call has no attachment");
  const object = await env.BLOBS.get(callId);
  if (!object) throw new ApiError(404, "the attachment is gone");
  return new Response(object.body, {
    headers: {
      "content-type": "application/octet-stream",
      "cache-control": "no-store",
      "content-length": String(object.size),
    },
  });
}

/** The relay's answer to "who am I here?", which is only ever the address. */
export async function me(address: string): Promise<Response> {
  return json({ address, custody: "browser" });
}

/**
 * Online state by address. Any console may ask about any address: what a device
 * will actually accept is decided on the device, not by who is asking here.
 */
export async function deviceStatus(env: Env, address: string): Promise<Response> {
  if (!isAddress(address)) throw new ApiError(404, "device not found");
  const row = await deviceByAddress(env, address);
  const lastSeen = row?.last_seen_at ?? null;
  const status: DeviceStatus = {
    address,
    registered: row !== null,
    platform: row?.platform ?? null,
    version: row?.version ?? null,
    run_id: row?.run_id ?? null,
    run_started_at: row?.run_started_at ?? null,
    online: lastSeen !== null && lastSeen > now() - OFFLINE_AFTER_SECONDS,
    last_seen_at: lastSeen,
  };
  return json(status);
}

/**
 * Accepts an opaque, signed command. The relay cannot read the tool or its
 * arguments: it verifies the issuer signature over the ciphertext and queues it.
 * Whether the device will run it is the device's business alone.
 */
export async function createCall(env: Env, owner: string, address: string, request: Request): Promise<Response> {
  const input = await body<Record<string, unknown>>(request, MAX_CALL_BODY);
  const callId = str(input.call_id, "call_id", 64);
  if (!/^[0-9a-zA-Z-]{8,64}$/.test(callId)) throw new ApiError(400, "call_id must be 8-64 url-safe characters");
  const issuer = requireAddress(input.issuer, "issuer");
  const device = requireAddress(input.device, "device");
  if (issuer !== owner) throw new ApiError(403, "a call must be signed by the address that sent it");
  if (device !== address) throw new ApiError(400, "the envelope names another device");
  const sealed = str(input.sealed, "sealed", MAX_CALL_BODY);
  const sig = str(input.sig, "sig", 128);
  const issuedAt = num(input.issued_at, "issued_at");
  const expiresAt = num(input.expires_at, "expires_at");
  if (Math.abs(now() - issuedAt) > CLOCK_SKEW_SECONDS) throw new ApiError(400, "issued_at is stale");
  if (expiresAt <= now()) throw new ApiError(400, "call already expired");
  if (expiresAt - issuedAt > MAX_CALL_TTL_SECONDS) throw new ApiError(400, "a call may not live longer than one hour");

  const deviceRow = await deviceByAddress(env, address);
  if (!deviceRow) throw new ApiError(404, "no device has registered this address");

  const row: CallEnvelope = { call_id: callId, issuer, device, issued_at: issuedAt, expires_at: expiresAt, sealed, sig };
  // Cheap check first: an address the device does not trust is refused by a
  // string comparison, so the relay never hashes 96 KiB of ciphertext on behalf
  // of a stranger. Both refusals answer identically on purpose — "does device D
  // trust address X" is not a question the relay should answer.
  const accepted = trustList(deviceRow.trust).includes(issuer);
  if (!accepted || !verifyCall(row)) throw new ApiError(403, "the relay will not queue this call");

  // The primary key is the replay defence: the same signed envelope sent twice
  // queues once. There is no address-book gate — it never stopped anyone.
  if (await callById(env, callId)) throw new ApiError(409, "call_id already used");

  await env.DB.prepare(
    "INSERT INTO calls(call_id,device_address,issuer,sealed,sig,issued_at,expires_at,status,created_at) VALUES(?,?,?,?,?,?,?,'queued',?)",
  )
    .bind(callId, address, issuer, sealed, sig, issuedAt, expiresAt, now())
    .run();
  return json({ call: callView((await callById(env, callId))!) });
}

export async function listCalls(env: Env, owner: string, url: URL): Promise<Response> {
  const address = url.searchParams.get("device");
  const limit = Math.min(Math.max(Number(url.searchParams.get("limit") ?? 50) || 50, 1), 200);
  const rows = address
    ? await env.DB.prepare("SELECT * FROM calls WHERE issuer=? AND device_address=? ORDER BY created_at DESC LIMIT ?")
        .bind(owner, address, limit)
        .all<CallRow>()
    : await env.DB.prepare("SELECT * FROM calls WHERE issuer=? ORDER BY created_at DESC LIMIT ?")
        .bind(owner, limit)
        .all<CallRow>();
  return json({ calls: rows.results.map(callView) });
}

/** Returns the sealed result envelope verbatim; opening it is the browser's job. */
export async function readCall(env: Env, owner: string, callId: string): Promise<Response> {
  const row = await callById(env, callId);
  if (!row || row.issuer !== owner) throw new ApiError(404, "call not found");
  return json({ call: callView(row), result: row.result ? JSON.parse(row.result) : null });
}

export async function cancelCall(env: Env, owner: string, callId: string): Promise<Response> {
  const row = await callById(env, callId);
  if (!row || row.issuer !== owner) throw new ApiError(404, "call not found");
  if (!["queued", "received"].includes(row.status)) throw new ApiError(409, "call is already settled");
  await env.DB.prepare(
    "UPDATE calls SET cancel_requested_at=?, status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END, settled_at=CASE WHEN status='queued' THEN ? ELSE settled_at END WHERE call_id=?",
  )
    .bind(now(), now(), callId)
    .run();
  return empty();
}
