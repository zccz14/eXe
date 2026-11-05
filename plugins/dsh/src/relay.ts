// The caller half of the eXe relay, in this process: seal a call, queue it, wait
// for the device's answer, open it.
//
// The relay is a signed queue, not an API in the usual sense. It cannot read
// the tool name, the arguments or the output; it checks the caller's signature
// and the time window, and stores sealed bytes. Everything that matters —
// whether a device runs a command, and what it answers — is decided between
// this key and the device's own `trust` list.
import { randomUUID } from "node:crypto";
import {
  addressOf,
  buildCall,
  openAttachment,
  openResult,
  requestHeaders,
  verifyResult,
  type CallEnvelope,
  type Identity,
  type ResultEnvelope,
} from "../../../shared/protocol.ts";

/** A call may not outlive one hour; the device enforces the same ceiling. */
const MAX_TTL_SECONDS = 3600;
const POLL_START_MS = 150;
const POLL_CEILING_MS = 600;
const PROBE_TIMEOUT_MS = 3000;

/** What the relay knows about one device: metadata only, enough to say online or not. */
export interface DeviceStatus {
  address: string;
  registered: boolean;
  online: boolean;
  platform?: string;
  version?: string;
  last_seen_at?: number;
}

/** What the device answered, and the whole answer when the row could not hold it. */
export interface Outcome {
  /** The device's answer, already opened and parsed. */
  answer: unknown;
  /** The opened attachment — the device's entire answer, as text — when one arrived. */
  attachment?: string;
}

interface CallView {
  call_id: string;
  device: string;
  caller: string;
  status: string;
  issued_at: number;
  expires_at: number;
  received_at: number | null;
  settled_at: number | null;
  has_result: boolean;
  blob_bytes: number | null;
}

interface CallDetail {
  call?: CallView;
  result?: ResultEnvelope | null;
}

export interface CallRequest {
  /** The device's address, not its label: the relay has no address book. */
  device: string;
  /** The tool the device should run. eXe devices implement `shell`. */
  name: string;
  args: Record<string, unknown>;
  /** How long the call may live, which bounds the whole round trip. */
  ttlSeconds: number;
  signal: AbortSignal;
  /**
   * Poll pacing. The default backs off from 150 ms to 600 ms, which is the right
   * trade for a command that runs for seconds; a ping asks for a tighter start
   * so the number it reports is the round trip and not the poll interval.
   */
  poll?: { startMs: number; ceilingMs: number };
}

function reason(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function sleep(ms: number, signal: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      reject(signal.reason ?? new Error("cancelled"));
      return;
    }
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal.reason ?? new Error("cancelled"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

/** The caller's own signal plus a deadline, whichever fires first. */
function withDeadline(signal: AbortSignal | undefined, ms: number): AbortSignal {
  const deadline = AbortSignal.timeout(ms);
  return signal === undefined ? deadline : AbortSignal.any([signal, deadline]);
}

export class Relay {
  /** base58 of this caller's public key — the address devices must trust. */
  readonly address: string;
  private readonly endpoints: string[];
  private readonly identity: Identity;
  private readonly fetchImpl: typeof globalThis.fetch;
  /** Resolved on first use: a briefly unreachable relay must not look like a broken plugin. */
  private cloud?: string;

  constructor(options: { endpoints: string[]; identity: Identity; fetch?: typeof globalThis.fetch }) {
    this.endpoints = options.endpoints;
    this.identity = options.identity;
    this.address = addressOf(options.identity);
    this.fetchImpl = options.fetch ?? globalThis.fetch;
  }

  /** The first endpoint that answers as an eXe relay, remembered once found. */
  private async base(signal?: AbortSignal): Promise<string> {
    if (this.cloud !== undefined) return this.cloud;
    for (const endpoint of this.endpoints) {
      try {
        const response = await this.fetchImpl(`${endpoint}/api/health`, {
          signal: withDeadline(signal, PROBE_TIMEOUT_MS),
        });
        const health = (await response.json()) as { service?: unknown };
        if (health.service === "exe") {
          this.cloud = endpoint;
          return endpoint;
        }
      } catch {
        // Try the next entry: the endpoints are the same relay by other routes.
      }
    }
    throw new Error(`no eXe relay answered at ${this.endpoints.join(", ")}`);
  }

  /** One request, self-signed: there is no token and no login anywhere in eXe. */
  private async request(
    method: string,
    path: string,
    init: { body?: string; signal?: AbortSignal } = {},
  ): Promise<Response> {
    const base = await this.base(init.signal);
    const headers: Record<string, string> = { ...requestHeaders(this.identity, method, path) };
    if (init.body !== undefined) headers["content-type"] = "application/json";
    return await this.fetchImpl(`${base}${path}`, {
      method,
      headers,
      body: init.body,
      signal: init.signal,
    });
  }

  private async json<T>(path: string, signal?: AbortSignal): Promise<T> {
    const response = await this.request("GET", path, { signal });
    if (!response.ok) throw new Error(`the relay answered ${response.status} for ${path}`);
    return (await response.json()) as T;
  }

  /** Registered, online, platform — the relay's metadata about one device. */
  async device(address: string, signal?: AbortSignal): Promise<DeviceStatus> {
    const value = await this.json<Record<string, unknown>>(`/api/devices/${address}`, signal);
    const text = (key: string): string | undefined => {
      const entry = value[key];
      return typeof entry === "string" && entry.length > 0 ? entry : undefined;
    };
    const status: DeviceStatus = {
      address,
      registered: value.registered === true,
      online: value.online === true,
    };
    const platform = text("platform");
    const version = text("version");
    const lastSeen = value.last_seen_at;
    if (platform !== undefined) status.platform = platform;
    if (version !== undefined) status.version = version;
    if (typeof lastSeen === "number") status.last_seen_at = lastSeen;
    return status;
  }

  /**
   * One call: seal, queue, wait, open. The waiting is the caller's problem,
   * which is why the relay can stay a queue and a poll.
   */
  async call(request: CallRequest): Promise<Outcome> {
    const issuedAt = Math.floor(Date.now() / 1000);
    const ttl = Math.min(Math.max(Math.trunc(request.ttlSeconds), 1), MAX_TTL_SECONDS);
    const expiresAt = issuedAt + ttl;
    const callId = randomUUID().replaceAll("-", "");
    const envelope = buildCall({
      seed: this.identity.seed,
      caller: this.address,
      device: request.device,
      callId,
      name: request.name,
      args: JSON.stringify(request.args),
      issuedAt,
      expiresAt,
    });
    const response = await this.request("POST", `/api/devices/${request.device}/calls`, {
      body: JSON.stringify(envelope),
      signal: request.signal,
    });
    if (!response.ok) {
      const detail = (await response.text()).trim();
      throw new Error(
        `the relay refused the call${detail.length > 0 ? `: ${detail}` : ` (${response.status})`}`,
      );
    }
    try {
      return await this.wait(envelope, ttl, request.signal, request.poll);
    } catch (error) {
      // A cancelled call must stop being work on the device, not linger until it
      // expires. Best effort: the answer is already lost either way.
      if (request.signal.aborted) await this.cancel(callId);
      throw error;
    }
  }

  private async wait(
    envelope: CallEnvelope,
    ttl: number,
    signal: AbortSignal,
    poll?: { startMs: number; ceilingMs: number },
  ): Promise<Outcome> {
    const detailPath = `/api/calls/${envelope.call_id}`;
    const deadline = Date.now() + (ttl + 30) * 1000;
    const ceiling = Math.max(poll?.ceilingMs ?? POLL_CEILING_MS, 10);
    let wait = Math.min(Math.max(poll?.startMs ?? POLL_START_MS, 5), ceiling);
    for (;;) {
      if (signal.aborted) throw signal.reason ?? new Error("cancelled");
      if (Date.now() > deadline) throw new Error("no answer from the device before the call expired");
      const detail = await this.json<CallDetail>(detailPath, signal);
      const status = detail.call?.status ?? "queued";
      switch (status) {
        case "queued":
        case "received":
          break;
        case "succeeded":
        case "failed":
          return await this.settle(envelope, detail, signal);
        case "cancelled":
          throw new Error("the call was cancelled before the device ran it");
        case "expired":
          throw new Error("the call expired before the device answered");
        case "lost":
          throw new Error(
            "the device process that took this call is gone and it never answered: the command may have run. " +
              "Do not retry blindly — inspect the device state first.",
          );
        default:
          throw new Error(`unexpected call status \`${status}\``);
      }
      await sleep(wait, signal);
      wait = Math.min(wait * 2, ceiling);
    }
  }

  private async settle(envelope: CallEnvelope, detail: CallDetail, signal: AbortSignal): Promise<Outcome> {
    const result = detail.result;
    if (result === undefined || result === null) throw new Error("the relay has no result for a settled call");
    if (!verifyResult(result)) throw new Error("the device's signature on this result does not verify");
    let answer: unknown;
    try {
      answer = JSON.parse(openResult({ seed: this.identity.seed, call: envelope, result })) as unknown;
    } catch (error) {
      throw new Error(`the device's answer did not open with this caller's key: ${reason(error)}`);
    }
    let attachment: string | undefined;
    if ((detail.call?.blob_bytes ?? 0) > 0) {
      const response = await this.request("GET", `/api/calls/${envelope.call_id}/blob`, { signal });
      if (response.ok) {
        const raw = new Uint8Array(await response.arrayBuffer());
        try {
          attachment = openAttachment({
            seed: this.identity.seed,
            call: envelope,
            result,
            sealed: raw,
          });
        } catch (error) {
          throw new Error(`the device's attachment did not open: ${reason(error)}`);
        }
      }
    }
    await this.ack(envelope.call_id);
    return attachment === undefined ? { answer } : { answer, attachment };
  }

  private async cancel(callId: string): Promise<void> {
    try {
      await this.request("POST", `/api/calls/${callId}/cancel`);
    } catch {
      // The call is already lost; cancelling is a courtesy to the device.
    }
  }

  /** Taking the result ends the call's life: the relay drops the row and its blob. */
  private async ack(callId: string): Promise<void> {
    try {
      await this.request("POST", `/api/calls/${callId}/ack`);
    } catch {
      // An unacked row costs one fallback window, nothing more.
    }
  }
}
