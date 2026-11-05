// A device and its relay, in one process, speaking the real protocol.
//
// The point of these tests is the wire, not a mock of our own functions: the
// simulator verifies the caller's request signature, opens the sealed call with
// a device key, signs the result back — the same four steps `docs/PROTOCOL.md`
// describes — so a mistake in sealing, signing or polling fails here.
import {
  addressOf,
  agreementPublic,
  buildResult,
  newIdentity,
  openCall,
  parseAddress,
  seal,
  unb64u,
  verifyCall,
  verifyRequest,
  type CallEnvelope,
  type Identity,
  type ResultEnvelope,
} from "../../../shared/protocol.ts";

type Answer = Record<string, unknown>;

export interface SimulatorOptions {
  /** What the device answers for one call. */
  answer?: (call: { name: string; args: Record<string, unknown> }) => Answer;
  /** Send the answer as an attachment: the row keeps a preview, the blob holds it whole. */
  attachment?: boolean;
  /** Sign the result with someone else's key. */
  tamper?: boolean;
  /** Never settle: the call stays queued, as if the device vanished mid-flight. */
  hang?: boolean;
}

interface CallEntry {
  status: string;
  result: ResultEnvelope | null;
  blobBytes: number;
  blob?: Uint8Array;
}

export interface Simulator {
  address: string;
  identity: Identity;
  fetch: typeof globalThis.fetch;
  /** Every request the caller made, as `METHOD /path`. */
  requests: string[];
  /** Calls the caller asked to cancel. */
  cancels: string[];
  calls: Map<string, CallEntry>;
}

const ANSWER: Answer = { ok: true, output: { tool: "shell", exit_code: 0, stdout: "", stderr: "" } };

export function simulateDevice(options: SimulatorOptions = {}): Simulator {
  const identity = newIdentity();
  const address = addressOf(identity);
  const impostor = newIdentity();
  const requests: string[] = [];
  const cancels: string[] = [];
  const calls = new Map<string, CallEntry>();

  const json = (body: unknown, status = 200): Response =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

  const fetch = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    const method = (init?.method ?? "GET").toUpperCase();
    const path = url.pathname;
    requests.push(`${method} ${path}`);
    if (path === "/api/health") return json({ ok: true, service: "exe" });

    const headers = new Headers(init?.headers);
    const caller = headers.get("x-exe-address") ?? "";
    if (
      !verifyRequest(
        { method, path, address: caller, timestamp: Number(headers.get("x-exe-timestamp") ?? 0) },
        headers.get("x-exe-signature") ?? "",
      )
    ) {
      return json({ error: "bad request signature" }, 403);
    }

    const now = Math.floor(Date.now() / 1000);
    const device = /^\/api\/devices\/([^/]+)$/.exec(path);
    if (device !== null) {
      return json({ address: device[1], registered: true, online: true, platform: "darwin", version: "test", last_seen_at: now });
    }

    const deliver = /^\/api\/devices\/([^/]+)\/calls$/.exec(path);
    if (deliver !== null && method === "POST") {
      const envelope = JSON.parse(String(init?.body ?? "{}")) as CallEnvelope;
      if (!verifyCall(envelope)) return json({ error: "bad call signature" }, 403);
      const opened = openCall({ seed: identity.seed, call: envelope });
      const args = JSON.parse(opened.args) as Record<string, unknown>;
      const answer = options.answer?.({ name: opened.name, args }) ?? ANSWER;
      const issuedAt = now;
      const entry: CallEntry = { status: "queued", result: null, blobBytes: 0 };
      if (options.hang !== true) {
        entry.status = "succeeded";
        if (options.attachment === true) {
          // What a real device does when the answer does not fit in one row: the
          // row keeps a preview with a pointer, the blob carries the whole thing.
          const blob = unb64u(
            seal({
              direction: "blob",
              caller: envelope.caller,
              device: address,
              callId: envelope.call_id,
              issuedAt,
              expiresAt: envelope.expires_at,
              recipient: agreementPublic(parseAddress(envelope.caller)),
              plaintext: JSON.stringify(answer),
            }),
          );
          entry.blob = blob;
          entry.blobBytes = blob.length;
          const preview = {
            ok: true,
            output: { tool: "shell", exit_code: 0, stdout: "<preview>", stderr: "", truncated: true },
            blob: { bytes: blob.length },
          };
          entry.result = buildResult({
            seed: identity.seed,
            call: envelope,
            ok: true,
            plaintext: JSON.stringify(preview),
            issuedAt,
          });
        } else {
          entry.result = buildResult({
            seed: options.tamper === true ? impostor.seed : identity.seed,
            call: envelope,
            ok: true,
            plaintext: JSON.stringify(answer),
            issuedAt,
          });
        }
      }
      calls.set(envelope.call_id, entry);
      return json({ call: { call_id: envelope.call_id, status: "queued" } });
    }

    const detail = /^\/api\/calls\/([^/]+)$/.exec(path);
    if (detail !== null && method === "GET") {
      const entry = calls.get(detail[1] ?? "");
      if (entry === undefined) return json({ error: "call not found" }, 404);
      return json({
        call: {
          call_id: detail[1],
          device: address,
          caller,
          status: entry.status,
          issued_at: now,
          expires_at: now + 600,
          received_at: null,
          settled_at: null,
          has_result: entry.result !== null,
          blob_bytes: entry.blobBytes === 0 ? null : entry.blobBytes,
        },
        result: entry.result,
      });
    }

    const blob = /^\/api\/calls\/([^/]+)\/blob$/.exec(path);
    if (blob !== null && method === "GET") {
      const entry = calls.get(blob[1] ?? "");
      if (entry?.blob === undefined) return json({ error: "this call has no attachment" }, 404);
      return new Response(entry.blob, { status: 200 });
    }

    const ack = /^\/api\/calls\/([^/]+)\/ack$/.exec(path);
    if (ack !== null && method === "POST") {
      calls.delete(ack[1] ?? "");
      return json({ ok: true });
    }

    const cancel = /^\/api\/calls\/([^/]+)\/cancel$/.exec(path);
    if (cancel !== null && method === "POST") {
      cancels.push(cancel[1] ?? "");
      const entry = calls.get(cancel[1] ?? "");
      if (entry !== undefined) entry.status = "cancelled";
      return json({ ok: true });
    }

    return json({ error: `no route for ${method} ${path}` }, 404);
  };

  return { address, identity, fetch: fetch as typeof globalThis.fetch, requests, cancels, calls };
}
