import { requestHeaders } from "../../shared/protocol.ts";
import { localIdentity } from "./keystore";

/** The console is a static Pages app; the relay lives on its own origin. */
const API_BASE = (import.meta.env.VITE_API_BASE ?? "").replace(/\/$/, "");

/** Absolute URL on the relay, for plain links (downloads, redirects). */
export function apiUrl(path: string): string {
  return `${API_BASE}${path}`;
}

/** Endpoints that need no signature, such as release metadata. */
export async function publicApi<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`);
  if (!response.ok) throw new Error(`${response.status}`);
  return (await response.json()) as T;
}

/**
 * Every request is self-signed with this browser's key, so there is no login and
 * no token: the address in `x-exe-address` is the identity. A retry re-signs with
 * a fresh nonce and timestamp, which is what a rejected replay or a moved clock
 * needs.
 */
async function send(path: string, init: RequestInit): Promise<Response> {
  const identity = await localIdentity();
  const url = `${API_BASE}${path}`;
  // The signature covers the pathname only, so sign the one the worker will see.
  const { pathname } = new URL(url, window.location.origin);
  return fetch(url, {
    ...init,
    headers: {
      ...(init.body ? { "content-type": "application/json" } : {}),
      ...(init.headers ?? {}),
      ...requestHeaders(identity, init.method ?? "GET", pathname),
    },
  });
}

async function message(response: Response): Promise<string> {
  const text = await response.text().catch(() => "");
  try {
    return (JSON.parse(text) as { error?: string }).error ?? `${response.status}`;
  } catch {
    return `${response.status}`;
  }
}

/** A sealed attachment is bytes, not JSON; the caller decrypts it. */
export async function apiBytes(path: string): Promise<Uint8Array> {
  let response = await send(path, {});
  if (response.status === 401) response = await send(path, {});
  if (!response.ok) throw new Error(await message(response));
  return new Uint8Array(await response.arrayBuffer());
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  let response = await send(path, init);
  if (response.status === 401) response = await send(path, init);
  if (!response.ok) throw new Error(await message(response));
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

/** What the relay knows about one address. The label lives here, in the browser. */
export interface DeviceStatus {
  address: string;
  registered: boolean;
  platform: string | null;
  version: string | null;
  run_id: string | null;
  run_started_at: number | null;
  online: boolean;
  last_seen_at: number | null;
}

export interface CallView {
  call_id: string;
  device: string;
  issuer: string;
  status: "queued" | "received" | "succeeded" | "failed" | "cancelled" | "expired" | "lost";
  issued_at: number;
  expires_at: number;
  received_at: number | null;
  settled_at: number | null;
  has_result: boolean;
  /** Size of the attachment when the result was too big for the row. */
  blob_bytes: number | null;
}

/** The relay only ever knows this browser as an address. */
export interface Me {
  address: string;
  custody: "browser";
}

export interface SealedEnvelope {
  call_id: string;
  device: string;
  ok: boolean;
  issued_at: number;
  sealed: string;
  sig: string;
}

export interface CallDetail {
  call: CallView;
  result: SealedEnvelope | null;
}

export interface ReleaseAsset {
  name: string;
  size: number;
  url: string;
}

export interface LatestRelease {
  configured: boolean;
  repository: string;
  version: string | null;
  tag: string | null;
  published_at: string | null;
  release_url: string;
  assets: ReleaseAsset[];
}
