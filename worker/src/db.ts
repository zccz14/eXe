import { newAccountKeys, openSecret, sealSecret, unb64u, b64u, equalHex, sha256Hex, randomBytes } from "./crypto.ts";
import { now } from "./http.ts";

export interface Env {
  DB: D1Database;
  ASSETS: Fetcher;
  EXE_KEK: string;
  AUTH_ISSUER: string;
  AUTH_AUDIENCE: string;
}

export interface AccountRow {
  user_id: string;
  sig_pub: string;
  kex_pub: string;
  sig_sk_sealed: string;
  kex_sk_sealed: string;
  created_at: number;
}

export interface DeviceRow {
  id: string;
  owner_user_id: string;
  label: string;
  hostname: string;
  platform: string;
  version: string | null;
  sig_pub: string;
  kex_pub: string;
  token_hash: string;
  status: string;
  boot_id: string | null;
  sas: string;
  created_at: number;
  last_seen_at: number | null;
  revoked_at: number | null;
}

export interface CallRow {
  id: string;
  device_id: string;
  owner_user_id: string;
  name: string;
  args: string;
  nonce: string;
  issued_at: number;
  expires_at: number;
  sig: string;
  status: string;
  device_boot_id: string | null;
  delivered_at: number | null;
  received_at: number | null;
  settled_at: number | null;
  envelope: string | null;
  error: string | null;
  failure_code: string | null;
  cancel_requested_at: number | null;
  cancel_notified_at: number | null;
  created_at: number;
}

export interface PairingRow {
  id: string;
  user_code: string;
  secret_hash: string;
  token_hash: string;
  dev_sig_pub: string;
  dev_kex_pub: string;
  hostname: string;
  platform: string;
  version: string;
  expires_at: number;
  status: string;
  device_id: string | null;
  account_id: string | null;
  approval: string | null;
  created_at: number;
  last_polled_at: number;
}

export function kek(env: Env): Uint8Array {
  return unb64u(env.EXE_KEK);
}

/** Creates account key material on first authenticated touch; idempotent under races. */
export async function ensureAccount(env: Env, userId: string): Promise<AccountRow> {
  const existing = await env.DB.prepare("SELECT * FROM accounts WHERE user_id=?").bind(userId).first<AccountRow>();
  if (existing) return existing;
  const keys = newAccountKeys();
  const sigSk = await sealSecret(kek(env), keys.sigSk);
  const kexSk = await sealSecret(kek(env), keys.kexSk);
  await env.DB.prepare(
    "INSERT INTO accounts(user_id,sig_pub,kex_pub,sig_sk_sealed,kex_sk_sealed,created_at) VALUES(?,?,?,?,?,?) ON CONFLICT(user_id) DO NOTHING",
  )
    .bind(userId, b64u(keys.sigPub), b64u(keys.kexPub), sigSk, kexSk, now())
    .run();
  return (await env.DB.prepare("SELECT * FROM accounts WHERE user_id=?").bind(userId).first<AccountRow>())!;
}

export interface UnsealedAccount {
  row: AccountRow;
  sigPub: Uint8Array;
  kexPub: Uint8Array;
  sigSk: Uint8Array;
  kexSk: Uint8Array;
}

/** Private keys exist in plaintext only inside one request; storage keeps AES-GCM seals. */
export async function unsealAccount(env: Env, userId: string): Promise<UnsealedAccount> {
  const row = await ensureAccount(env, userId);
  return {
    row,
    sigPub: unb64u(row.sig_pub),
    kexPub: unb64u(row.kex_pub),
    sigSk: await openSecret(kek(env), row.sig_sk_sealed),
    kexSk: await openSecret(kek(env), row.kex_sk_sealed),
  };
}

export async function deviceById(env: Env, id: string): Promise<DeviceRow | null> {
  return env.DB.prepare("SELECT * FROM devices WHERE id=?").bind(id).first<DeviceRow>();
}

/** Authenticates a device bearer token; the token grants transport only, never execution. */
export async function deviceByToken(env: Env, id: string, request: Request): Promise<DeviceRow> {
  const header = request.headers.get("authorization") ?? "";
  if (!header.toLowerCase().startsWith("bearer ")) throw new Error("missing device token");
  const token = header.slice(7).trim();
  if (token.length < 32) throw new Error("invalid device token");
  const device = await deviceById(env, id);
  if (!device || device.status !== "active") throw new Error("unknown device");
  if (!equalHex(sha256Hex(token), device.token_hash)) throw new Error("invalid device token");
  return device;
}

export async function callById(env: Env, id: string): Promise<CallRow | null> {
  return env.DB.prepare("SELECT * FROM calls WHERE id=?").bind(id).first<CallRow>();
}

export function newToken(): string {
  return b64u(randomBytes(32));
}
