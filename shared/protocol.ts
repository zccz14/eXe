// eXe protocol cryptography. Shared shapes with agent/crates/exe-core (see docs/PROTOCOL.md).
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { hkdf } from "@noble/hashes/hkdf.js";
import { chacha20poly1305 } from "@noble/ciphers/chacha.js";
import { concatBytes } from "@noble/hashes/utils.js";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

export function utf8(value: string): Uint8Array {
  return encoder.encode(value);
}
export function fromUtf8(value: Uint8Array): string {
  return decoder.decode(value);
}
export function randomBytes(length: number): Uint8Array {
  const out = new Uint8Array(length);
  crypto.getRandomValues(out);
  return out;
}
export function b64u(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replace(/=+$/, "");
}
export function unb64u(value: string): Uint8Array {
  const normalized = value.replaceAll("-", "+").replaceAll("_", "/");
  const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
  const binary = atob(padded);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) out[i] = binary.charCodeAt(i);
  return out;
}
export function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}
export function unhex(value: string): Uint8Array {
  if (!/^[0-9a-f]*$/.test(value) || value.length % 2 !== 0) throw new Error("invalid hex");
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
  return out;
}
export function sha256Hex(value: string): string {
  return hex(sha256(utf8(value)));
}
export function equalHex(a: string, b: string): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i += 1) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/** Length-prefixed field: u32be(len) || bytes. */
export function lp(bytes: Uint8Array): Uint8Array {
  const out = new Uint8Array(4 + bytes.length);
  new DataView(out.buffer).setUint32(0, bytes.length, false);
  out.set(bytes, 4);
  return out;
}
export function u64be(value: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(Math.trunc(value)), false);
  return out;
}
export function cat(...parts: Uint8Array[]): Uint8Array {
  return concatBytes(...parts);
}

export interface CallFields {
  callId: string;
  deviceId: string;
  accountId: string;
  eph: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
  issuedAt: number;
  expiresAt: number;
}

/** The cloud only ever sees these fields; the tool name and arguments are sealed. */
export function callTranscript(fields: CallFields): Uint8Array {
  return cat(
    utf8("eXe/v1/call\0"),
    lp(utf8(fields.callId)),
    lp(utf8(fields.deviceId)),
    lp(utf8(fields.accountId)),
    lp(fields.eph),
    lp(fields.nonce),
    lp(sha256(fields.ciphertext)),
    u64be(fields.issuedAt),
    u64be(fields.expiresAt),
  );
}

function callSealKey(ikm: Uint8Array, callId: string, deviceId: string): Uint8Array {
  const salt = sha256(cat(utf8("eXe/v1/call"), lp(utf8(callId)), lp(utf8(deviceId))));
  return hkdf(sha256, ikm, salt, utf8("eXe/v1/seal-call"), 32);
}
function callAad(callId: string, deviceId: string, accountId: string): Uint8Array {
  return cat(lp(utf8(callId)), lp(utf8(deviceId)), lp(utf8(accountId)));
}

export interface SealedCall {
  v: 1;
  eph: string;
  nonce: string;
  ct: string;
  issued_at: number;
  expires_at: number;
  sig: string;
}

/** Seals a command to the device's key agreement key and signs the envelope. */
export function sealCall(input: {
  callId: string;
  deviceId: string;
  accountId: string;
  name: string;
  args: string;
  issuedAt: number;
  expiresAt: number;
  deviceKexPub: Uint8Array;
  accountSigSeed: Uint8Array;
  ephemeralSecret?: Uint8Array;
}): SealedCall {
  const ephemeralSecret = input.ephemeralSecret ?? randomBytes(32);
  const eph = x25519.getPublicKey(ephemeralSecret);
  const key = callSealKey(x25519.getSharedSecret(ephemeralSecret, input.deviceKexPub), input.callId, input.deviceId);
  const nonce = randomBytes(12);
  const ct = chacha20poly1305(key, nonce, callAad(input.callId, input.deviceId, input.accountId)).encrypt(
    utf8(JSON.stringify({ name: input.name, args: input.args })),
  );
  const fields: CallFields = {
    callId: input.callId,
    deviceId: input.deviceId,
    accountId: input.accountId,
    eph,
    nonce,
    ciphertext: ct,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
  };
  return {
    v: 1,
    eph: b64u(eph),
    nonce: b64u(nonce),
    ct: b64u(ct),
    issued_at: input.issuedAt,
    expires_at: input.expiresAt,
    sig: b64u(ed25519.sign(callTranscript(fields), input.accountSigSeed)),
  };
}

/** Device side: opens the sealed command with its own key agreement secret. */
export function openCall(input: {
  deviceKexSk: Uint8Array;
  callId: string;
  deviceId: string;
  accountId: string;
  eph: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}): { name: string; args: string } {
  const key = callSealKey(x25519.getSharedSecret(input.deviceKexSk, input.eph), input.callId, input.deviceId);
  const plain = chacha20poly1305(key, input.nonce, callAad(input.callId, input.deviceId, input.accountId)).decrypt(input.ciphertext);
  return JSON.parse(fromUtf8(plain)) as { name: string; args: string };
}

export function verifyCall(sigPubB64u: string, fields: CallFields, signature: string): boolean {
  try {
    return ed25519.verify(unb64u(signature), callTranscript(fields), unb64u(sigPubB64u));
  } catch {
    return false;
  }
}

export interface ResultFields {
  callId: string;
  deviceId: string;
  /** Whether the tool succeeded. Signed, because the cloud can no longer decrypt. */
  ok: boolean;
  eph: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export function resultTranscript(fields: ResultFields): Uint8Array {
  return cat(
    utf8("eXe/v1/result\0"),
    lp(utf8(fields.callId)),
    lp(utf8(fields.deviceId)),
    lp(okByte(fields.ok)),
    lp(fields.eph),
    lp(fields.nonce),
    lp(sha256(fields.ciphertext)),
  );
}

function okByte(ok: boolean): Uint8Array {
  return new Uint8Array([ok ? 1 : 0]);
}

/** Account registration: proves possession of the signing key for this AuthMini identity. */
export interface AccountFields {
  userId: string;
  nonce: string;
  sigPub: string;
  kexPub: string;
  issuedAt: number;
}

export function accountTranscript(fields: AccountFields): Uint8Array {
  return cat(
    utf8("eXe/v1/account\0"),
    lp(utf8(fields.userId)),
    lp(utf8(fields.nonce)),
    lp(utf8(fields.sigPub)),
    lp(utf8(fields.kexPub)),
    u64be(fields.issuedAt),
  );
}

export interface ApprovalFields {
  pairingId: string;
  deviceId: string;
  accountId: string;
  accountSigPub: string;
  accountKexPub: string;
  deviceSigPub: string;
  deviceKexPub: string;
  issuedAt: number;
}

export function approvalTranscript(fields: ApprovalFields): Uint8Array {
  return cat(
    utf8("eXe/v1/approval\0"),
    lp(utf8(fields.pairingId)),
    lp(utf8(fields.deviceId)),
    lp(utf8(fields.accountId)),
    lp(utf8(fields.accountSigPub)),
    lp(utf8(fields.accountKexPub)),
    lp(utf8(fields.deviceSigPub)),
    lp(utf8(fields.deviceKexPub)),
    u64be(fields.issuedAt),
  );
}

/** Six decimal digits a human compares between the device terminal and the console. */
export function shortAuthenticationString(accountSigPub: string, deviceSigPub: string): string {
  const digest = sha256(cat(utf8("eXe/v1/sas"), lp(utf8(accountSigPub)), lp(utf8(deviceSigPub))));
  const value = new DataView(digest.buffer, digest.byteOffset, 4).getUint32(0, false);
  return String(value % 1_000_000).padStart(6, "0");
}

export interface AccountKeys {
  sigSk: Uint8Array;
  sigPub: Uint8Array;
  kexSk: Uint8Array;
  kexPub: Uint8Array;
}

export function newAccountKeys(): AccountKeys {
  const sigSk = randomBytes(32);
  const kexSk = randomBytes(32);
  return { sigSk, sigPub: ed25519.getPublicKey(sigSk), kexSk, kexPub: x25519.getPublicKey(kexSk) };
}

export function signAccount(sigSeed: Uint8Array, fields: AccountFields): string {
  return b64u(ed25519.sign(accountTranscript(fields), sigSeed));
}
export function verifyAccount(sigPubB64u: string, fields: AccountFields, signature: string): boolean {
  try {
    return ed25519.verify(unb64u(signature), accountTranscript(fields), unb64u(sigPubB64u));
  } catch {
    return false;
  }
}
export function signApproval(sigSeed: Uint8Array, fields: ApprovalFields): string {
  return b64u(ed25519.sign(approvalTranscript(fields), sigSeed));
}
export function verifyApproval(sigPubB64u: string, fields: ApprovalFields, signature: string): boolean {
  try {
    return ed25519.verify(unb64u(signature), approvalTranscript(fields), unb64u(sigPubB64u));
  } catch {
    return false;
  }
}

function sealKey(ikm: Uint8Array, callId: string, deviceId: string): Uint8Array {
  const salt = sha256(cat(utf8("eXe/v1/result"), lp(utf8(callId)), lp(utf8(deviceId))));
  return hkdf(sha256, ikm, salt, utf8("eXe/v1/seal"), 32);
}
function sealAad(callId: string, deviceId: string): Uint8Array {
  return cat(lp(utf8(callId)), lp(utf8(deviceId)));
}

export interface SealedResult {
  v: 1;
  ok: boolean;
  eph: string;
  nonce: string;
  ct: string;
}

export function sealResult(input: {
  callId: string;
  deviceId: string;
  ok: boolean;
  accountKexPub: Uint8Array;
  plaintext: string;
  ephemeralSecret?: Uint8Array;
}): SealedResult {
  const ephemeralSecret = input.ephemeralSecret ?? randomBytes(32);
  const eph = x25519.getPublicKey(ephemeralSecret);
  const key = sealKey(x25519.getSharedSecret(ephemeralSecret, input.accountKexPub), input.callId, input.deviceId);
  const nonce = randomBytes(12);
  const ct = chacha20poly1305(key, nonce, sealAad(input.callId, input.deviceId)).encrypt(utf8(input.plaintext));
  return { v: 1, ok: input.ok, eph: b64u(eph), nonce: b64u(nonce), ct: b64u(ct) };
}

export function openResult(input: {
  accountKexSk: Uint8Array;
  callId: string;
  deviceId: string;
  envelope: SealedResult;
}): string {
  const eph = unb64u(input.envelope.eph);
  const nonce = unb64u(input.envelope.nonce);
  const ct = unb64u(input.envelope.ct);
  const key = sealKey(x25519.getSharedSecret(input.accountKexSk, eph), input.callId, input.deviceId);
  return fromUtf8(chacha20poly1305(key, nonce, sealAad(input.callId, input.deviceId)).decrypt(ct));
}

/** Envelope signature, produced by the device over T_result. */
export function signResult(deviceSigSeed: Uint8Array, fields: ResultFields): string {
  return b64u(ed25519.sign(resultTranscript(fields), deviceSigSeed));
}

export function verifyResultSignature(deviceSigPub: string, fields: ResultFields, signature: string): boolean {
  try {
    return ed25519.verify(unb64u(signature), resultTranscript(fields), unb64u(deviceSigPub));
  } catch {
    return false;
  }
}
