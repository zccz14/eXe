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
  name: string;
  args: string;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
}

export function callTranscript(fields: CallFields): Uint8Array {
  return cat(
    utf8("eXe/v1/call\0"),
    lp(utf8(fields.callId)),
    lp(utf8(fields.deviceId)),
    lp(utf8(fields.accountId)),
    lp(utf8(fields.name)),
    lp(sha256(utf8(fields.args))),
    u64be(fields.issuedAt),
    u64be(fields.expiresAt),
    lp(utf8(fields.nonce)),
  );
}

export interface ResultFields {
  callId: string;
  deviceId: string;
  eph: Uint8Array;
  nonce: Uint8Array;
  ciphertext: Uint8Array;
}

export function resultTranscript(fields: ResultFields): Uint8Array {
  return cat(
    utf8("eXe/v1/result\0"),
    lp(utf8(fields.callId)),
    lp(utf8(fields.deviceId)),
    lp(fields.eph),
    lp(fields.nonce),
    lp(sha256(fields.ciphertext)),
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

export function signCall(sigSk: Uint8Array, fields: CallFields): string {
  return b64u(ed25519.sign(callTranscript(fields), sigSk));
}
export function verifyCall(sigPubB64u: string, fields: CallFields, signature: string): boolean {
  try {
    return ed25519.verify(unb64u(signature), callTranscript(fields), unb64u(sigPubB64u));
  } catch {
    return false;
  }
}
export function signApproval(sigSk: Uint8Array, fields: ApprovalFields): string {
  return b64u(ed25519.sign(approvalTranscript(fields), sigSk));
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
  eph: string;
  nonce: string;
  ct: string;
}

export function sealResult(input: {
  callId: string;
  deviceId: string;
  accountKexPub: Uint8Array;
  plaintext: string;
  ephemeralSecret?: Uint8Array;
}): SealedResult {
  const ephemeralSecret = input.ephemeralSecret ?? randomBytes(32);
  const eph = x25519.getPublicKey(ephemeralSecret);
  const key = sealKey(x25519.getSharedSecret(ephemeralSecret, input.accountKexPub), input.callId, input.deviceId);
  const nonce = randomBytes(12);
  const ct = chacha20poly1305(key, nonce, sealAad(input.callId, input.deviceId)).encrypt(utf8(input.plaintext));
  return { v: 1, eph: b64u(eph), nonce: b64u(nonce), ct: b64u(ct) };
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
export function verifyResultSignature(deviceSigPub: string, fields: ResultFields, signature: string): boolean {
  try {
    return ed25519.verify(unb64u(signature), resultTranscript(fields), unb64u(deviceSigPub));
  } catch {
    return false;
  }
}

const KEY_KEK = "eXe/v1/kek";

async function kekKey(kek: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey("raw", kek as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
}

/** Seals an account private key under the worker KEK; storage never holds the raw key. */
export async function sealSecret(kek: Uint8Array, secret: Uint8Array): Promise<string> {
  const iv = randomBytes(12);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv as BufferSource }, await kekKey(kek), secret as BufferSource),
  );
  return `v1.${b64u(iv)}.${b64u(ct)}`;
}
export async function openSecret(kek: Uint8Array, sealed: string): Promise<Uint8Array> {
  const [version, iv, ct] = sealed.split(".");
  if (version !== "v1" || !iv || !ct) throw new Error("unsupported sealed secret");
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: unb64u(iv) as BufferSource },
    await kekKey(kek),
    unb64u(ct) as BufferSource,
  );
  return new Uint8Array(plain);
}
export const KEK_INFO = KEY_KEK;
