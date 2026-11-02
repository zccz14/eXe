// The browser is the only place the account key exists. It signs calls and opens
// results; the relay only ever sees the address and sealed envelopes.
import {
  accountPayload,
  addressOf,
  buildCall,
  decodeSecret,
  encodeSecret,
  newIdentity,
  openResult,
  signAccount,
  type AccountFields,
  type AccountPayload,
  type CallEnvelope,
  type Identity,
  type ResultEnvelope,
} from "../../shared/protocol.ts";

const DB_NAME = "exe-keys";
const STORE = "account";
const RECORD = "self";

interface StoredRecord {
  wrapping: CryptoKey;
  iv: string;
  ciphertext: string;
  address: string;
  created_at: number;
}

let cached: Promise<Identity> | null = null;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function read(db: IDBDatabase, key: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE, "readonly").objectStore(STORE).get(key);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

function write(db: IDBDatabase, key: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const request = db.transaction(STORE, "readwrite").objectStore(STORE).put(value, key);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
}

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
  await write(db, RECORD, record);
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
  const record = (await read(db, RECORD)) as StoredRecord | undefined;
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
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction(STORE, "readwrite").objectStore(STORE).delete(RECORD);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
  cached = null;
}

/** Signs the registration the relay will store; the body is already wire-shaped. */
export async function signRegistration(userId: string, nonce: string, issuedAt: number): Promise<AccountPayload> {
  const identity = await localIdentity();
  const fields: AccountFields = { address: addressOf(identity), userId, nonce, issuedAt };
  return accountPayload(fields, signAccount(identity.seed, fields));
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
  await write(db, `call:${call.call_id}`, call);
}

export async function localCalls(): Promise<Record<string, LocalCall>> {
  const db = await openDb();
  const keys = await new Promise<IDBValidKey[]>((resolve, reject) => {
    const request = db.transaction(STORE, "readonly").objectStore(STORE).getAllKeys();
    request.onsuccess = () => resolve(request.result as IDBValidKey[]);
    request.onerror = () => reject(request.error);
  });
  const out: Record<string, LocalCall> = {};
  for (const key of keys) {
    if (typeof key !== "string" || !key.startsWith("call:")) continue;
    const value = (await read(db, key)) as LocalCall | undefined;
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

export function newCallId(): string {
  return crypto.randomUUID();
}
