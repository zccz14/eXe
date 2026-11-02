// Device-facing API: self-registration, the SSE stream, receipts, sealed results.
// Every handler authenticates a signed request; no bearer token exists.
import { verifyResult, type CallEnvelope, type ResultEnvelope } from "../../shared/protocol.ts";
import type { CallRow, Env } from "./db.ts";
import { authenticateDevice, callById, touchAgent } from "./db.ts";
import { ApiError, body, empty, json, now } from "./http.ts";

const STREAM_MAX_SECONDS = 900;
const DEVICE_OFFLINE_SECONDS = 90;
const LOST_AFTER_SECONDS = 120;

function text(value: unknown, field: string, max: number): string {
  if (typeof value !== "string") throw new ApiError(400, `${field} is required`);
  const trimmed = value.trim();
  if (trimmed.length === 0 || trimmed.length > max) throw new ApiError(400, `${field} must be 1-${max} characters`);
  return trimmed;
}

/** Turns an expired queue into `expired`; signed envelopes have a deadline too. */
async function sweep(env: Env, address: string): Promise<void> {
  await env.DB.prepare(
    "UPDATE calls SET status='expired', settled_at=? WHERE device_address=? AND status IN ('queued','delivered','received') AND expires_at<=?",
  )
    .bind(now(), address, now())
    .run();
}

export async function registerAgent(request: Request, env: Env, address: string): Promise<Response> {
  await authenticateDevice({ request, env, address });
  const input = await body<Record<string, unknown>>(request);
  const info = {
    hostname: text(input.hostname, "hostname", 80),
    platform: text(input.platform, "platform", 40),
    version: text(input.version, "version", 20),
  };
  await touchAgent(env, address, info);
  return json({
    address,
    now: now(),
    offline_after_seconds: DEVICE_OFFLINE_SECONDS,
    stream_max_seconds: STREAM_MAX_SECONDS,
  });
}

async function claimCall(env: Env, address: string): Promise<CallRow | null> {
  const rows = await env.DB.prepare(
    `UPDATE calls SET status='delivered', delivered_at=?
     WHERE call_id=(SELECT call_id FROM calls WHERE device_address=? AND status='queued' AND expires_at>? ORDER BY created_at,call_id LIMIT 1)
     RETURNING *`,
  )
    .bind(now(), address, now())
    .all<CallRow>();
  return rows.results[0] ?? null;
}

/**
 * Delivery is at-least-once: a lost receipt or a dropped stream must not lose a
 * call. Anything that was handed to this device and never settled is re-sent on
 * the next stream; the device answers a repeat with the result it already
 * signed instead of running the tool twice.
 */
async function claimReplays(env: Env, address: string): Promise<CallRow[]> {
  const rows = await env.DB.prepare(
    `UPDATE calls SET status='delivered', delivered_at=?
     WHERE device_address=? AND status IN ('queued','delivered') AND expires_at>?
       AND (delivered_at IS NULL OR delivered_at<=?)
     RETURNING *`,
  )
    .bind(now(), address, now(), now() - LOST_AFTER_SECONDS)
    .all<CallRow>();
  return rows.results;
}

async function claimCancellation(env: Env, address: string): Promise<string | null> {
  const rows = await env.DB.prepare(
    `UPDATE calls SET cancel_notified_at=?
     WHERE call_id=(SELECT call_id FROM calls WHERE device_address=? AND status IN ('queued','delivered','received') AND cancel_requested_at IS NOT NULL AND cancel_notified_at IS NULL ORDER BY created_at,call_id LIMIT 1)
     RETURNING call_id`,
  )
    .bind(now(), address)
    .all<{ call_id: string }>();
  return rows.results[0]?.call_id ?? null;
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
  await touchAgent(env, address);
  await sweep(env, address);

  const { readable, writable } = new TransformStream<Uint8Array, Uint8Array>();
  const writer = writable.getWriter();
  const startedAt = Date.now();
  let lastSeen = 0;
  const pump = async () => {
    try {
      await writer.write(sseChunk("hello", { address, now: now() }));
      let lastReplay = 0;
      while (Date.now() - startedAt < STREAM_MAX_SECONDS * 1000) {
        const call = await claimCall(env, address);
        if (call) {
          await writer.write(sseChunk("call", envelopeOf(call)));
        } else {
          if (Date.now() - lastReplay > 15_000) {
            lastReplay = Date.now();
            for (const replay of await claimReplays(env, address)) {
              await writer.write(sseChunk("call", envelopeOf(replay)));
            }
          }
          const cancelled = await claimCancellation(env, address);
          if (cancelled) await writer.write(sseChunk("cancel", { call_id: cancelled }));
          else await writer.write(sseChunk("heartbeat", { now: now() }));
        }
        if (Date.now() - lastSeen > 30_000) {
          lastSeen = Date.now();
          await touchAgent(env, address);
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

export async function markReceived(request: Request, env: Env, address: string, callId: string): Promise<Response> {
  await authenticateDevice({ request, env, address });
  const result = await env.DB.prepare(
    "UPDATE calls SET status='received', received_at=? WHERE call_id=? AND device_address=? AND status IN ('delivered','received')",
  )
    .bind(now(), callId, address)
    .run();
  if (result.meta.changes === 0) throw new ApiError(409, "call is not awaiting a receipt");
  return empty();
}

function parseResult(input: Record<string, unknown>, callId: string, address: string): ResultEnvelope {
  if (typeof input.sealed !== "string" || input.sealed.length > 512 * 1024) throw new ApiError(400, "result envelope is malformed");
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
  const result = parseResult(await body<Record<string, unknown>>(request, 512 * 1024), callId, address);
  if (!verifyResult(result)) throw new ApiError(403, "result signature does not match the device key");

  const call = await callById(env, callId);
  if (!call || call.device_address !== address) throw new ApiError(404, "unknown call");

  const canonical = JSON.stringify(result);
  if (["succeeded", "failed"].includes(call.status)) {
    // At-least-once delivery: the device is replaying the envelope it signed.
    if (call.result === canonical) return empty();
    throw new ApiError(409, "call is already settled with a different result");
  }
  if (!["queued", "delivered", "received"].includes(call.status)) throw new ApiError(409, `call is ${call.status}`);

  await env.DB.prepare(
    "UPDATE calls SET result=?, status=?, settled_at=? WHERE call_id=? AND status IN ('queued','delivered','received')",
  )
    .bind(canonical, result.ok ? "succeeded" : "failed", now(), callId)
    .run();
  return empty();
}
