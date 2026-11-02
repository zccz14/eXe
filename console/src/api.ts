export interface SessionLike {
  getState(): { accessToken?: string | null };
  refresh(): Promise<{ accessToken?: string | null }>;
}
export interface SdkLike {
  session: SessionLike;
}

async function token(sdk: SdkLike): Promise<string> {
  const state = sdk.session.getState();
  if (state.accessToken) return state.accessToken;
  const refreshed = await sdk.session.refresh();
  if (!refreshed.accessToken) throw new Error("AuthMini session is not available");
  return refreshed.accessToken;
}

/** The console is a static Pages app; the relay lives on its own origin. */
const API_BASE = (import.meta.env.VITE_API_BASE ?? "").replace(/\/$/, "");

export async function api<T>(sdk: SdkLike, path: string, init: RequestInit = {}): Promise<T> {
  const send = async (bearer: string) =>
    fetch(`${API_BASE}${path}`, {
      ...init,
      headers: { ...(init.body ? { "content-type": "application/json" } : {}), ...(init.headers ?? {}), authorization: `Bearer ${bearer}` },
    });
  let response = await send(await token(sdk));
  if (response.status === 401) response = await send(await token(sdk));
  if (!response.ok) {
    const text = await response.text().catch(() => "");
    let message = `${response.status}`;
    try {
      message = (JSON.parse(text) as { error?: string }).error ?? message;
    } catch {
      /* keep status text */
    }
    throw new Error(message);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
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
  revoked_at: number | null;
}

export interface CallView {
  call_id: string;
  device: string;
  issuer: string;
  status: "queued" | "delivered" | "received" | "succeeded" | "failed" | "cancelled" | "expired";
  issued_at: number;
  expires_at: number;
  delivered_at: number | null;
  received_at: number | null;
  settled_at: number | null;
  has_result: boolean;
}

export interface Me {
  account_id: string;
  registered: boolean;
  address: string | null;
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
