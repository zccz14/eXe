// The browser is the only place this console's key exists. It signs requests and
// calls, and opens results; the relay only ever sees the address and the sealed
// envelopes. Clearing site data or switching browsers mints a new identity.
import {
  addressOf,
  buildCall,
  decodeSecret,
  encodeSecret,
  newIdentity,
  openAttachment as openAttachmentBytes,
  openResult,
  type CallEnvelope,
  type Identity,
  type ResultEnvelope,
} from "../../shared/protocol.ts";
import { KEY_STORE, idbDelete, idbGet, idbKeys, idbPut, openDb } from "./db";

// A fresh database: the store that held an "account" key belongs to a model that
// no longer exists, and its key has nothing left to sign for.
const RECORD = "self";

interface StoredRecord {
  wrapping: CryptoKey;
  iv: string;
  ciphertext: string;
  address: string;
  created_at: number;
}

let cached: Promise<Identity> | null = null;

async function freshIdentity(db: IDBDatabase): Promise<Identity> {
  const identity = newIdentity();
  const wrapping = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, wrapping, new TextEncoder().encode(encodeSecret(identity)) as BufferSource),
  );
  const record: StoredRecord = {
    wrapping,
    iv: btoa(String.fromCharCode(...iv)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, ""),
    ciphertext: btoa(String.fromCharCode(...ciphertext)).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, ""),
    address: addressOf(identity),
    created_at: Math.floor(Date.now() / 1000),
  };
  await idbPut(db, KEY_STORE, RECORD, record);
  return identity;
}

function unb64uText(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}

async function load(): Promise<Identity> {
  const db = await openDb();
  const record = await idbGet<StoredRecord>(db, KEY_STORE, RECORD);
  if (record) {
    try {
      const plain = new Uint8Array(
        await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64uText(record.iv) as BufferSource }, record.wrapping, unb64uText(record.ciphertext) as BufferSource),
      );
      return decodeSecret(new TextDecoder().decode(plain));
    } catch {
      // A key from an older layout cannot be read; a draft protocol replaces it.
      return await freshIdentity(db);
    }
  }
  return await freshIdentity(db);
}

export function localIdentity(): Promise<Identity> {
  cached ??= load();
  return cached;
}

export async function localAddress(): Promise<string> {
  return addressOf(await localIdentity());
}

/** Discards this browser's key. Results sealed to it become unreadable here. */
export async function forgetLocalKeys(): Promise<void> {
  const db = await openDb();
  await idbDelete(db, KEY_STORE, RECORD);
  cached = null;
}

/** Seals the command to the device address and signs the envelope. */
export async function sealDeviceCall(input: {
  callId: string;
  device: string;
  name: string;
  args: string;
  ttlSeconds?: number;
}): Promise<CallEnvelope> {
  const identity = await localIdentity();
  const issuedAt = Math.floor(Date.now() / 1000);
  const call = buildCall({
    seed: identity.seed,
    issuer: addressOf(identity),
    device: input.device,
    callId: input.callId,
    name: input.name,
    args: input.args,
    issuedAt,
    expiresAt: issuedAt + (input.ttlSeconds ?? 300),
  });
  await rememberCall({ call_id: input.callId, device: input.device, name: input.name, args: input.args, issued_at: issuedAt });
  return call;
}

/** The relay cannot name a call, so the console keeps its own readable copy. */
export interface LocalCall {
  call_id: string;
  device: string;
  name: string;
  args: string;
  issued_at: number;
}

async function rememberCall(call: LocalCall): Promise<void> {
  const db = await openDb();
  await idbPut(db, KEY_STORE, `call:${call.call_id}`, call);
}

export async function localCalls(): Promise<Record<string, LocalCall>> {
  const db = await openDb();
  const keys = await idbKeys(db, KEY_STORE);
  const out: Record<string, LocalCall> = {};
  for (const key of keys) {
    if (typeof key !== "string" || !key.startsWith("call:")) continue;
    const value = await idbGet<LocalCall>(db, KEY_STORE, key);
    if (value) out[value.call_id] = value;
  }
  return out;
}

export async function openSealed(detail: {
  call: { call_id: string; issuer: string; device: string; expires_at: number };
  result: ResultEnvelope;
}): Promise<unknown> {
  const identity = await localIdentity();
  return JSON.parse(openResult({ seed: identity.seed, call: detail.call, result: detail.result }));
}

/** Opens an attachment the device uploaded for this call; only this key can. */
export async function openAttachment(
  call: { call_id: string; issuer: string; device: string; expires_at: number },
  result: { issued_at: number },
  sealed: Uint8Array,
): Promise<unknown> {
  const identity = await localIdentity();
  return JSON.parse(openAttachmentBytes({ seed: identity.seed, call, result, sealed }));
}

export function newCallId(): string {
  return crypto.randomUUID();
}
