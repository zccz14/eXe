// Browser-held account keys. The seed never leaves this origin: it is wrapped by
// a non-extractable AES-GCM key in IndexedDB, and the worker only ever sees the
// public half. See docs/THREAT-MODEL.md.
import {
  b64u,
  newAccountKeys,
  openResult,
  signAccount,
  signApproval,
  signCall,
  unb64u,
  type AccountFields,
  type ApprovalFields,
  type CallFields,
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

export async function signDeviceCall(
  fields: Omit<CallFields, "accountId"> & { accountId: string },
): Promise<{ id: string; name: string; args: string; nonce: string; issued_at: number; expires_at: number; sig: string }> {
  const keys = await localKeys();
  return {
    id: fields.callId,
    name: fields.name,
    args: fields.args,
    nonce: fields.nonce,
    issued_at: fields.issuedAt,
    expires_at: fields.expiresAt,
    sig: signCall(keys.sigSeed, {
      callId: fields.callId,
      deviceId: fields.deviceId,
      accountId: fields.accountId,
      name: fields.name,
      args: fields.args,
      nonce: fields.nonce,
      issuedAt: fields.issuedAt,
      expiresAt: fields.expiresAt,
    }),
  };
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
