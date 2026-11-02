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

export async function api<T>(sdk: SdkLike, path: string, init: RequestInit = {}): Promise<T> {
  const send = async (bearer: string) =>
    fetch(path, {
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

export interface CallView {
  id: string;
  device_id: string;
  name: string;
  args: string;
  status: "queued" | "delivered" | "received" | "succeeded" | "failed" | "cancelled" | "expired";
  issued_at: number;
  expires_at: number;
  delivered_at: number | null;
  received_at: number | null;
  settled_at: number | null;
  failure_code: string | null;
  error: string | null;
  has_result: boolean;
}

export interface PairingView {
  pairing_id: string;
  user_code: string;
  hostname: string;
  platform: string;
  version: string;
  status: string;
  expires_at: number;
  device_id: string;
  device_sig_pub: string;
  device_kex_pub: string;
  account_sig_pub: string;
  account_kex_pub: string;
  sas: string;
}

export interface Me {
  account_id: string;
  registered: boolean;
  sig_pub: string | null;
  kex_pub: string | null;
  fingerprint: string | null;
  custody: "browser";
}

export interface SealedEnvelope {
  v: 1;
  ok: boolean;
  eph: string;
  nonce: string;
  ct: string;
}

export interface CallDetail {
  call: CallView;
  envelope: SealedEnvelope | null;
}
