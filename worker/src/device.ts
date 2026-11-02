// Device-facing API: self-registration, the SSE stream, receipts, sealed results.
// Every handler authenticates a signed request; no bearer token exists.
//
// The stream is read-only on the delivery path. Pushing a call writes nothing:
// whether this connection has already handed a call over is a fact about the
// connection, not a row in the database. The only proof of delivery the relay
// ever records is the device's own signed receipt, which arrives as a separate
// request (see docs/PROTOCOL.md §4).
import { isAddress, verifyResult, type CallEnvelope, type ResultEnvelope } from "../../shared/protocol.ts";
import type { CallRow, Env } from "./db.ts";
import { abandonOrphans, authenticateDevice, callById, deviceByAddress, touchDevice } from "./db.ts";
import { ApiError, body, empty, json, now } from "./http.ts";

const STREAM_MAX_SECONDS = 900;
const DEVICE_OFFLINE_SECONDS = 90;
/** How long a connection waits before handing the same call over again. */
const RESEND_AFTER_SECONDS = 120;
const PENDING_LIMIT = 16;
/**
 * A result travels in one request and lives in one D1 row, next to the call's own
 * envelope (up to 64 KiB). A row is capped at 2 MB by D1, so the body cap leaves
 * room for that envelope instead of discovering the ceiling as a 500.
 */
const MAX_RESULT_BODY = 1_900_000;
/** A device may attach more than a row could hold, but not without bound. */
const MAX_BLOB_BYTES = 16 * 1024 * 1024;
/** A device never needs to trust more issuers than this. */
const MAX_TRUST_ENTRIES = 64;

function text(value: unknown, field: string, max: number): string {
  if (typeof value !== "string") throw new ApiError(400, `${field} is required`);
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > max) throw new ApiError(400, `${field} must be 1-${max} characters`);
  return trimmed;
}

/** Turns an expired queue into `expired`; signed envelopes have a deadline too. */
async function sweep(env: Env, address: string): Promise<void> {
  await env.DB.prepare(
    "UPDATE calls SET status='expired', settled_at=? WHERE device_address=? AND status IN ('queued','received') AND expires_at<=?",
  )
    .bind(now(), address, now())
    .run();
}

/**
 * The device declares who it trusts. The relay keeps a copy so it can drop calls
 * the device would refuse anyway — a stranger's envelope then costs the device
 * nothing, not even a signature check. The copy can only ever make the relay
 * send *less*: it is refreshed on restart, so it is never fresher than the
 * device's own config, and the device still checks every call itself.
 */
function trustList(input: unknown): string {
  if (typeof input !== "string") throw new ApiError(400, "trust is required (comma-separated, may be empty)");
  const unique = [...new Set(input.split(",").map((entry) => entry.trim()).filter(Boolean))];
  if (unique.length > MAX_TRUST_ENTRIES) throw new ApiError(400, `trust may name at most ${MAX_TRUST_ENTRIES} addresses`);
  if (unique.some((entry) => !isAddress(entry))) throw new ApiError(400, "trust contains entries that are not eXe addresses");
  return unique.join(",");
}

/** One `exe run` process. A new value means the process restarted. */
function runId(value: unknown): string {
  if (typeof value !== "string") throw new ApiError(400, "run_id is required");
  const trimmed = value.trim();
  if (!/^[0-9a-zA-Z-]{4,64}$/.test(trimmed)) throw new ApiError(400, "run_id must be 4-64 url-safe characters");
  return trimmed;
}

export async function registerDevice(request: Request, env: Env, address: string): Promise<Response> {
  await authenticateDevice({ request, env, address });
  const input = await body<Record<string, unknown>>(request);
  const trust = trustList(input.trust);
  const run = runId(input.run_id);
  const previous = await deviceByAddress(env, address);
  const restarted = previous !== null && previous.run_id !== run;
  const startedAt = previous === null || restarted ? now() : previous.run_started_at;
  await touchDevice(env, address, {
    platform: text(input.platform, "platform", 40),
    version: text(input.version, "version", 20),
    trust,
    run_id: run,
    run_started_at: startedAt,
  });
  const abandoned = restarted ? await abandonOrphans(env, address, run) : 0;
  return json({
    address,
    now: now(),
    offline_after_seconds: DEVICE_OFFLINE_SECONDS,
    stream_max_seconds: STREAM_MAX_SECONDS,
    run_id: run,
    run_started_at: startedAt,
    trust: trust === "" ? [] : trust.split(","),
    abandoned,
  });
}

/** What the loop needs to know about a call, without dragging up to 96 KiB of ciphertext. */
interface PendingCall {
  call_id: string;
  status: string;
  cancel_requested_at: number | null;
}

/**
 * One read-only query per tick: the calls this device has not acknowledged yet.
 * `received` rows appear only while a cancellation is waiting for them, because a
 * receipt is the device saying it is already working on the call.
 */
async function pendingCalls(env: Env, address: string): Promise<PendingCall[]> {
  const rows = await env.DB.prepare(
    `SELECT call_id, status, cancel_requested_at FROM calls
     WHERE device_address=? AND status IN ('queued','received') AND expires_at>?
     ORDER BY created_at, call_id LIMIT ?`,
  )
    .bind(address, now(), PENDING_LIMIT)
    .all<PendingCall>();
  return rows.results;
}

function sseChunk(event: string, data: unknown): Uint8Array {
  return new TextEncoder().encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
}

function envelopeOf(call: CallRow): CallEnvelope {
  return {
    call_id: call.call_id,
    issuer: call.issuer,
    device: call.device_address,
    issued_at: call.issued_at,
    expires_at: call.expires_at,
    sealed: call.sealed,
    sig: call.sig,
  };
}

export async function eventStream(request: Request, env: Env, address: string): Promise<Response> {
  await authenticateDevice({ request, env, address });
  await touchDevice(env, address);
  await sweep(env, address);

  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
  const writer = writable.getWriter();
  const startedAt = Date.now();
  let lastSeen = 0;
  const pump = async () => {
    try {
      await writer.write(sseChunk("hello", { address, now: now() }));
      // Delivery is at-least-once. These two maps are the whole of "what has this
      // connection said" — a reconnect starts empty and therefore re-sends every
      // call the device has not acknowledged, which is exactly the guarantee.
      const sent = new Map<string, number>();
      const cancelled = new Map<string, number>();
      while (Date.now() - startedAt < STREAM_MAX_SECONDS * 1000) {
        const stamp = now();
        let wrote = false;
        for (const pending of await pendingCalls(env, address)) {
          if (pending.status === "queued") {
            const last = sent.get(pending.call_id);
            if (last === undefined || last <= stamp - RESEND_AFTER_SECONDS) {
              const call = await callById(env, pending.call_id);
              if (call) {
                await writer.write(sseChunk("call", envelopeOf(call)));
                sent.set(call.call_id, stamp);
                wrote = true;
              }
            }
          }
          if (pending.cancel_requested_at !== null) {
            const last = cancelled.get(pending.call_id);
            if (last === undefined || last <= stamp - RESEND_AFTER_SECONDS) {
              await writer.write(sseChunk("cancel", { call_id: pending.call_id }));
              cancelled.set(pending.call_id, stamp);
              wrote = true;
            }
          }
        }
        if (!wrote) await writer.write(sseChunk("heartbeat", { now: now() }));
        if (stamp - lastSeen >= 30) {
          lastSeen = stamp;
          await touchDevice(env, address);
          await sweep(env, address);
        }
        await sleep(1000);
      }
    } catch {
      // The device went away; nothing to clean up — its calls stay re-deliverable.
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
    },
  });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * The device's signed receipt: the only evidence in the whole system that a call
 * actually arrived. Everything else the relay knows about delivery is a guess.
 */
export async function markReceived(request: Request, env: Env, address: string, callId: string): Promise<Response> {
  await authenticateDevice({ request, env, address });
  // The stamping run is the one the relay believes is behind this address: the
  // receipt itself stays unchanged, so a restart is the only thing that can make
  // this column disagree with `devices.run_id` later.
  const result = await env.DB.prepare(
    "UPDATE calls SET status='received', received_at=?, device_run_id=(SELECT run_id FROM devices WHERE address=?) " +
      "WHERE call_id=? AND device_address=? AND status IN ('queued','received')",
  )
    .bind(now(), address, callId, address)
    .run();
  if (result.meta.changes === 0) throw new ApiError(409, "call is not awaiting a receipt");
  return empty();
}

/**
 * The sealed result, when it is too big for the row that will point at it. The
 * relay writes bytes it cannot read and records only their size; the console is
 * the only party that can open them. Keyed by `call_id`, so an attachment has
 * exactly the lifetime and the identity of the call it belongs to — nothing new
 * is invented on this side.
 */
export async function uploadBlob(request: Request, env: Env, address: string, callId: string): Promise<Response> {
  await authenticateDevice({ request, env, address });
  const call = await callById(env, callId);
  if (!call || call.device_address !== address) throw new ApiError(404, "unknown call");
  if (call.expires_at <= now()) throw new ApiError(409, "call has expired");
  const declared = Number(request.headers.get("content-length") ?? "");
  if (!Number.isFinite(declared) || declared <= 0) throw new ApiError(411, "content-length is required");
  if (declared > MAX_BLOB_BYTES) throw new ApiError(413, `an attachment may not exceed ${MAX_BLOB_BYTES} bytes`);
  if (!request.body) throw new ApiError(400, "an attachment needs a body");
  await env.BLOBS.put(callId, request.body);
  await env.DB.prepare("UPDATE calls SET blob_bytes=? WHERE call_id=? AND device_address=?")
    .bind(declared, callId, address)
    .run();
  return empty();
}

function parseResult(input: Record<string, unknown>, callId: string, address: string): ResultEnvelope {
  if (typeof input.sealed !== "string" || input.sealed.length === 0) throw new ApiError(400, "result envelope is malformed");
  if (typeof input.ok !== "boolean") throw new ApiError(400, "result envelope must state ok");
  if (typeof input.sig !== "string") throw new ApiError(400, "result envelope is missing a signature");
  if (typeof input.issued_at !== "number" || !Number.isFinite(input.issued_at)) throw new ApiError(400, "result envelope needs issued_at");
  if (input.call_id !== callId) throw new ApiError(400, "result does not match the call in the path");
  if (input.device !== address) throw new ApiError(400, "result is signed for another device");
  return {
    call_id: callId,
    device: address,
    ok: input.ok,
    issued_at: Math.trunc(input.issued_at),
    sealed: input.sealed,
    sig: input.sig,
  };
}

export async function submitResult(request: Request, env: Env, address: string, callId: string): Promise<Response> {
  await authenticateDevice({ request, env, address });
  const result = parseResult(await body<Record<string, unknown>>(request, MAX_RESULT_BODY), callId, address);
  if (!verifyResult(result)) throw new ApiError(403, "result signature does not match the device key");

  const call = await callById(env, callId);
  if (!call || call.device_address !== address) throw new ApiError(404, "unknown call");

  const canonical = JSON.stringify(result);
  if (["succeeded", "failed"].includes(call.status)) {
    // At-least-once delivery: the device is replaying the envelope it signed.
    if (call.result === canonical) return empty();
    throw new ApiError(409, "call is already settled with a different result");
  }
  // `lost` is accepted too: a signed outcome outranks the relay's guess that the
  // process died before answering. A lost receipt must never block a real result
  // either — a call that is merely `queued` is settled because the device clearly
  // has it.
  if (!["queued", "received", "lost"].includes(call.status)) throw new ApiError(409, `call is ${call.status}`);

  await env.DB.prepare(
    "UPDATE calls SET result=?, status=?, settled_at=? WHERE call_id=? AND status IN ('queued','received','lost')",
  )
    .bind(canonical, result.ok ? "succeeded" : "failed", now(), callId)
    .run();
  return empty();
}
