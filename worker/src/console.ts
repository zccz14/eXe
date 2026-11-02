// Console API. The browser signs every request with the one Ed25519 key it owns;
// this module only ever verifies. The relay can route and queue, never sign,
// never decrypt. There is no account behind the address: the address is the
// identity, so "who owns this row" is answered by the signature that made it.
import { isAddress, verifyCall, type CallEnvelope } from "../../shared/protocol.ts";
import type { AgentRow, CallRow, DeviceRow, Env } from "./db.ts";
import { callById, deviceByAddress } from "./db.ts";
import { ApiError, body, empty, json, now } from "./http.ts";

const OFFLINE_AFTER_SECONDS = 90;
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
}

function deviceView(device: DeviceRow, agent: AgentRow | null): DeviceView {
  const lastSeen = agent?.last_seen_at ?? null;
  return {
    address: device.address,
    label: device.label,
    hostname: agent?.hostname ?? null,
    platform: agent?.platform ?? null,
    version: agent?.version ?? null,
    online: lastSeen !== null && lastSeen > now() - OFFLINE_AFTER_SECONDS,
    last_seen_at: lastSeen,
    created_at: device.created_at,
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

/** The relay's answer to "who am I here?", which is only ever the address. */
export async function me(address: string): Promise<Response> {
  return json({ address, custody: "browser" });
}

export async function listDevices(env: Env, owner: string): Promise<Response> {
  const rows = await env.DB.prepare(
    `SELECT d.*, a.hostname AS agent_hostname, a.platform AS agent_platform, a.version AS agent_version, a.last_seen_at AS agent_last_seen
     FROM devices d LEFT JOIN agents a ON a.address = d.address
     WHERE d.owner_address=? ORDER BY d.created_at DESC`,
  )
    .bind(owner)
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
export async function addDevice(env: Env, owner: string, request: Request): Promise<Response> {
  const input = await body<Record<string, unknown>>(request);
  const address = requireAddress(input.address, "address");
  const label = typeof input.label === "string" && input.label.trim() ? input.label.trim().slice(0, 80) : address.slice(0, 12);
  // Every console keeps its own address book. Whether the device trusts this
  // address is decided on the device, not here.
  await env.DB.prepare(
    "INSERT INTO devices(owner_address,address,label,created_at) VALUES(?,?,?,?) " +
      "ON CONFLICT(owner_address,address) DO UPDATE SET label=excluded.label",
  )
    .bind(owner, address, label, now())
    .run();
  const device = await deviceByAddress(env, owner, address);
  const agent = await env.DB.prepare("SELECT * FROM agents WHERE address=?").bind(address).first<AgentRow>();
  return json({ device: deviceView(device!, agent ?? null) });
}

export async function removeDevice(env: Env, owner: string, address: string): Promise<Response> {
  if (!isAddress(address)) throw new ApiError(404, "device not found");
  const result = await env.DB.prepare("DELETE FROM devices WHERE owner_address=? AND address=?").bind(owner, address).run();
  if (result.meta.changes === 0) throw new ApiError(404, "device not found");
  await env.DB.prepare("UPDATE calls SET status='cancelled', settled_at=? WHERE device_address=? AND issuer=? AND status IN ('queued','delivered','received')")
    .bind(now(), address, owner)
    .run();
  return empty();
}

/**
 * Accepts an opaque, signed command. The relay cannot read the tool or its
 * arguments: it verifies the issuer signature over the ciphertext and queues it.
 */
export async function createCall(env: Env, owner: string, address: string, request: Request): Promise<Response> {
  const input = await body<Record<string, unknown>>(request);
  const callId = str(input.call_id, "call_id", 64);
  if (!/^[0-9a-zA-Z-]{8,64}$/.test(callId)) throw new ApiError(400, "call_id must be 8-64 url-safe characters");
  const issuer = requireAddress(input.issuer, "issuer");
  const device = requireAddress(input.device, "device");
  if (issuer !== owner) throw new ApiError(403, "a call must be signed by the address that sent it");
  if (device !== address) throw new ApiError(400, "the envelope names another device");
  const sealed = str(input.sealed, "sealed", MAX_SEALED_CHARS);
  const sig = str(input.sig, "sig", 128);
  const issuedAt = num(input.issued_at, "issued_at");
  const expiresAt = num(input.expires_at, "expires_at");
  if (Math.abs(now() - issuedAt) > CLOCK_SKEW_SECONDS) throw new ApiError(400, "issued_at is stale");
  if (expiresAt <= now()) throw new ApiError(400, "call already expired");
  if (expiresAt - issuedAt > MAX_CALL_TTL_SECONDS) throw new ApiError(400, "a call may not live longer than one hour");

  const row: CallEnvelope = { call_id: callId, issuer, device, issued_at: issuedAt, expires_at: expiresAt, sealed, sig };
  if (!verifyCall(row)) throw new ApiError(403, "call signature does not verify against the issuing address");

  const deviceRow = await deviceByAddress(env, owner, address);
  if (!deviceRow) throw new ApiError(404, "device not found");
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
  if (!["queued", "delivered", "received"].includes(row.status)) throw new ApiError(409, "call is already settled");
  await env.DB.prepare(
    "UPDATE calls SET cancel_requested_at=?, status=CASE WHEN status='queued' THEN 'cancelled' ELSE status END, settled_at=CASE WHEN status='queued' THEN ? ELSE settled_at END WHERE call_id=?",
  )
    .bind(now(), now(), callId)
    .run();
  return empty();
}
