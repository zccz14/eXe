// Browser-held account keys. The seed never leaves this origin: it is wrapped by
// a non-extractable AES-GCM key in IndexedDB, and the worker only ever sees the
// public half. See docs/THREAT-MODEL.md.
import {
  b64u,
  newAccountKeys,
  sealCall,
  openResult,
  signAccount,
  signApproval,
  unb64u,
  type AccountFields,
  type ApprovalFields,
  type SealedResult,
} from "../../shared/protocol.ts";

const DB_NAME = "exe-keys";
const STORE = "account";
const RECORD = "self";

export interface LocalKeys {
  sigSeed: Uint8Array;
  kexSecret: Uint8Array;
  sigPub: string;
  kexPub: string;
}

interface StoredRecord {
  wrapping: CryptoKey;
  iv: string;
  ciphertext: string;
  sig_pub: string;
  kex_pub: string;
  created_at: number;
}

let cached: Promise<LocalKeys> | null = null;

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);
    request.onupgradeneeded = () => request.result.createObjectStore(STORE);
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

async function load(): Promise<LocalKeys> {
  const db = await openDb();
  const record = await new Promise<StoredRecord | undefined>((resolve, reject) => {
    const request = db.transaction(STORE, "readonly").objectStore(STORE).get(RECORD);
    request.onsuccess = () => resolve(request.result as StoredRecord | undefined);
    request.onerror = () => reject(request.error);
  });
  if (record) {
    const plain = new Uint8Array(
      await crypto.subtle.decrypt(
        { name: "AES-GCM", iv: unb64u(record.iv) as BufferSource },
        record.wrapping,
        unb64u(record.ciphertext) as BufferSource,
      ),
    );
    return {
      sigSeed: plain.slice(0, 32),
      kexSecret: plain.slice(32, 64),
      sigPub: record.sig_pub,
      kexPub: record.kex_pub,
    };
  }
  const keys = newAccountKeys();
  const wrapping = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const secret = new Uint8Array(64);
  secret.set(keys.sigSk, 0);
  secret.set(keys.kexSk, 32);
  const ciphertext = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, wrapping, secret as BufferSource),
  );
  const stored: StoredRecord = {
    wrapping,
    iv: b64u(iv),
    ciphertext: b64u(ciphertext),
    sig_pub: b64u(keys.sigPub),
    kex_pub: b64u(keys.kexPub),
    created_at: Math.floor(Date.now() / 1000),
  };
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction(STORE, "readwrite").objectStore(STORE).put(stored, RECORD);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
  return { sigSeed: keys.sigSk, kexSecret: keys.kexSk, sigPub: stored.sig_pub, kexPub: stored.kex_pub };
}

export function localKeys(): Promise<LocalKeys> {
  cached ??= load();
  return cached;
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

export async function signRegistration(userId: string, nonce: string, issuedAt: number): Promise<AccountFields & { sig: string }> {
  const keys = await localKeys();
  const fields: AccountFields = { userId, nonce, sigPub: keys.sigPub, kexPub: keys.kexPub, issuedAt };
  return { ...fields, sig: signAccount(keys.sigSeed, fields) };
}

export async function signPairingApproval(
  fields: Omit<ApprovalFields, "accountSigPub" | "accountKexPub">,
): Promise<{ issued_at: number; sig: string }> {
  const keys = await localKeys();
  const full: ApprovalFields = { ...fields, accountSigPub: keys.sigPub, accountKexPub: keys.kexPub };
  return { issued_at: full.issuedAt, sig: signApproval(keys.sigSeed, full) };
}

/** Seals the command to the device key and signs the envelope. */
export async function sealDeviceCall(input: {
  callId: string;
  deviceId: string;
  accountId: string;
  deviceKexPub: string;
  name: string;
  args: string;
  ttlSeconds?: number;
}): Promise<{ id: string; eph: string; nonce: string; ct: string; issued_at: number; expires_at: number; sig: string }> {
  const keys = await localKeys();
  const issuedAt = Math.floor(Date.now() / 1000);
  const sealed = sealCall({
    callId: input.callId,
    deviceId: input.deviceId,
    accountId: input.accountId,
    name: input.name,
    args: input.args,
    issuedAt,
    expiresAt: issuedAt + (input.ttlSeconds ?? 300),
    deviceKexPub: unb64u(input.deviceKexPub),
    accountSigSeed: keys.sigSeed,
  });
  await rememberCall({ id: input.callId, device_id: input.deviceId, name: input.name, args: input.args, issued_at: issuedAt });
  return {
    id: input.callId,
    eph: sealed.eph,
    nonce: sealed.nonce,
    ct: sealed.ct,
    issued_at: sealed.issued_at,
    expires_at: sealed.expires_at,
    sig: sealed.sig,
  };
}

/** The cloud cannot name a call, so the console keeps its own readable copy. */
interface LocalCall {
  id: string;
  device_id: string;
  name: string;
  args: string;
  issued_at: number;
}

async function rememberCall(call: LocalCall): Promise<void> {
  const db = await openDb();
  await new Promise<void>((resolve, reject) => {
    const request = db.transaction(STORE, "readwrite").objectStore(STORE).put(call, `call:${call.id}`);
    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
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
    const value = await new Promise<LocalCall | undefined>((resolve, reject) => {
      const request = db.transaction(STORE, "readonly").objectStore(STORE).get(key);
      request.onsuccess = () => resolve(request.result as LocalCall | undefined);
      request.onerror = () => reject(request.error);
    });
    if (value) out[value.id] = value;
  }
  return out;
}

export async function openSealed(callId: string, deviceId: string, envelope: SealedResult): Promise<unknown> {
  const keys = await localKeys();
  return JSON.parse(openResult({ accountKexSk: keys.kexSecret, callId, deviceId, envelope }));
}

export function newCallId(): string {
  return crypto.randomUUID();
}
export function newNonce(): string {
  return b64u(crypto.getRandomValues(new Uint8Array(16)));
}
