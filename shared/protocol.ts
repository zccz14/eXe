// eXe wire protocol. See docs/PROTOCOL.md — this file is the TypeScript side of
// the single implementation both ends must agree on.
//
// One Ed25519 key per party: the address *is* the public key. X25519 for key
// agreement is derived from the same key, so nothing needs pairing, shipping or
// escrowing. Addresses, private keys and signatures are base58 (Solana
// compatible); sealed payloads are base64url.
import { ed25519, x25519 } from "@noble/curves/ed25519.js";
import { gcm } from "@noble/ciphers/aes.js";
import { xsalsa20poly1305 } from "@noble/ciphers/salsa.js";
import { sha256, sha512 } from "@noble/hashes/sha2.js";
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
export function cat(...parts: Uint8Array[]): Uint8Array {
  return concatBytes(...parts);
}

/** Length-prefixed field: u32be(len) || bytes. The only structural primitive. */
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
export function sha256Hex(bytes: Uint8Array): string {
  return hex(sha256(bytes));
}
export function hex(bytes: Uint8Array): string {
  let out = "";
  for (const byte of bytes) out += byte.toString(16).padStart(2, "0");
  return out;
}
export function unhex(value: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(value) || value.length % 2 !== 0) throw new Error("invalid hex");
  const out = new Uint8Array(value.length / 2);
  for (let i = 0; i < out.length; i += 1) out[i] = Number.parseInt(value.slice(i * 2, i * 2 + 2), 16);
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

// --- base58: addresses, private keys, signatures -----------------------------

const BASE58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE58_INDEX = new Map([...BASE58_ALPHABET].map((char, index) => [char, BigInt(index)]));

export function b58(bytes: Uint8Array): string {
  let value = 0n;
  for (const byte of bytes) value = value * 256n + BigInt(byte);
  let out = "";
  while (value > 0n) {
    out = BASE58_ALPHABET[Number(value % 58n)]! + out;
    value /= 58n;
  }
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros += 1;
  return "1".repeat(zeros) + out;
}

export function unb58(value: string): Uint8Array {
  if (value.length === 0) throw new Error("empty base58 value");
  let rest = 0n;
  for (const char of value) {
    const digit = BASE58_INDEX.get(char);
    if (digit === undefined) throw new Error("invalid base58 character");
    rest = rest * 58n + digit;
  }
  const body: number[] = [];
  while (rest > 0n) {
    body.unshift(Number(rest & 0xffn));
    rest >>= 8n;
  }
  let zeros = 0;
  while (zeros < value.length && value[zeros] === "1") zeros += 1;
  const out = new Uint8Array(zeros + body.length);
  out.set(body, zeros);
  return out;
}

// --- identity ----------------------------------------------------------------

export interface Identity {
  /** 32-byte Ed25519 seed; the private key never leaves the party that made it. */
  seed: Uint8Array;
  /** 32-byte Ed25519 public key, which is also the address. */
  public: Uint8Array;
}

export function identityFromSeed(seed: Uint8Array): Identity {
  if (seed.length !== 32) throw new Error("an eXe seed is 32 bytes");
  return { seed: new Uint8Array(seed), public: ed25519.getPublicKey(seed) };
}
export function newIdentity(): Identity {
  return identityFromSeed(randomBytes(32));
}
/** base58(seed32 || pub32) — the Solana `Keypair.secretKey` layout. */
export function encodeSecret(identity: Identity): string {
  return b58(cat(identity.seed, identity.public));
}
export function decodeSecret(secret: string): Identity {
  const raw = unb58(secret);
  if (raw.length !== 64) throw new Error("an eXe secret is 64 bytes: seed32 || pub32");
  const identity = identityFromSeed(raw.slice(0, 32));
  for (let i = 0; i < 32; i += 1) {
    if (identity.public[i] !== raw[32 + i]) throw new Error("the secret does not match its own public key");
  }
  return identity;
}
export function addressOf(identity: Identity): string {
  return b58(identity.public);
}
/** Decodes and validates an address (a 32-byte Ed25519 public key). */
export function parseAddress(text: string): Uint8Array {
  if (typeof text !== "string" || text.length < 32 || text.length > 64) throw new Error("not an eXe address");
  const raw = unb58(text);
  if (raw.length !== 32) throw new Error("an eXe address is 32 bytes");
  return raw;
}
export function isAddress(text: unknown): text is string {
  if (typeof text !== "string") return false;
  try {
    parseAddress(text);
    return true;
  } catch {
    return false;
  }
}
export function sign(seed: Uint8Array, message: Uint8Array): string {
  return b58(ed25519.sign(message, seed));
}
export function verifySignature(publicKey: Uint8Array, message: Uint8Array, signature: string): boolean {
  try {
    return ed25519.verify(unb58(signature), message, publicKey);
  } catch {
    return false;
  }
}

// --- key agreement, derived from the signing key -----------------------------

/**
 * x25519_pub = edwardsToMontgomery(ed25519_pub)
 * x25519_priv = clamp(sha512(seed)[0..32])
 * The same key therefore signs, receives sealed calls and opens sealed results.
 */
export function agreementPublic(publicKey: Uint8Array): Uint8Array {
  return ed25519.utils.toMontgomery(publicKey);
}
export function agreementSecret(seed: Uint8Array): Uint8Array {
  const clamped = new Uint8Array(sha512(seed).slice(0, 32));
  clamped[0] = clamped[0]! & 248;
  clamped[31] = (clamped[31]! & 127) | 64;
  return clamped;
}

// --- two-layer seal ----------------------------------------------------------

export type Direction = "call" | "result" | "blob";

export interface SealContext {
  direction: Direction;
  caller: string;
  device: string;
  callId: string;
  issuedAt: number;
  expiresAt: number;
}

/** aad = direction || caller || device || call_id || issued_at || expires_at */
export function associatedData(context: SealContext): Uint8Array {
  return cat(
    lp(utf8(context.direction)),
    lp(utf8(context.caller)),
    lp(utf8(context.device)),
    lp(utf8(context.callId)),
    u64be(context.issuedAt),
    u64be(context.expiresAt),
  );
}

const ZERO_16 = new Uint8Array(16);
const SIGMA = new Uint32Array([0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]);

function rotl(value: number, shift: number): number {
  return ((value << shift) | (value >>> (32 - shift))) >>> 0;
}
function quarterRound(x: Uint32Array, a: number, b: number, c: number, d: number): void {
  x[b] = x[b]! ^ rotl((x[a]! + x[d]!) >>> 0, 7);
  x[c] = x[c]! ^ rotl((x[b]! + x[a]!) >>> 0, 9);
  x[d] = x[d]! ^ rotl((x[c]! + x[b]!) >>> 0, 13);
  x[a] = x[a]! ^ rotl((x[d]! + x[c]!) >>> 0, 18);
}
function wordsLe(bytes: Uint8Array): Uint32Array {
  const out = new Uint32Array(bytes.length / 4);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = (bytes[i * 4]! | (bytes[i * 4 + 1]! << 8) | (bytes[i * 4 + 2]! << 16) | (bytes[i * 4 + 3]! << 24)) >>> 0;
  }
  return out;
}
function bytesLe(words: Uint32Array): Uint8Array {
  const out = new Uint8Array(words.length * 4);
  for (let i = 0; i < words.length; i += 1) {
    const word = words[i]!;
    out[i * 4] = word & 0xff;
    out[i * 4 + 1] = (word >>> 8) & 0xff;
    out[i * 4 + 2] = (word >>> 16) & 0xff;
    out[i * 4 + 3] = (word >>> 24) & 0xff;
  }
  return out;
}

/**
 * HSalsa20, which is what `crypto_box_beforenm` runs on the X25519 shared
 * secret. Exported because the vectors pin it directly.
 */
export function hsalsa20(key: Uint8Array, input: Uint8Array): Uint8Array {
  if (key.length !== 32 || input.length !== 16) throw new Error("hsalsa20 takes a 32-byte key and a 16-byte input");
  const k = wordsLe(key);
  const i = wordsLe(input);
  const x = new Uint32Array(16);
  x[0] = SIGMA[0]!;
  x[1] = k[0]!;
  x[2] = k[1]!;
  x[3] = k[2]!;
  x[4] = k[3]!;
  x[5] = SIGMA[1]!;
  x[6] = i[0]!;
  x[7] = i[1]!;
  x[8] = i[2]!;
  x[9] = i[3]!;
  x[10] = SIGMA[2]!;
  x[11] = k[4]!;
  x[12] = k[5]!;
  x[13] = k[6]!;
  x[14] = k[7]!;
  x[15] = SIGMA[3]!;
  for (let round = 0; round < 10; round += 1) {
    quarterRound(x, 0, 4, 8, 12);
    quarterRound(x, 5, 9, 13, 1);
    quarterRound(x, 10, 14, 2, 6);
    quarterRound(x, 15, 3, 7, 11);
    quarterRound(x, 0, 1, 2, 3);
    quarterRound(x, 5, 6, 7, 4);
    quarterRound(x, 10, 11, 8, 9);
    quarterRound(x, 15, 12, 13, 14);
  }
  return bytesLe(new Uint32Array([x[0]!, x[5]!, x[10]!, x[15]!, x[6]!, x[7]!, x[8]!, x[9]!]));
}

const SEALED_PREFIX = 24 + 32 + 48 + 12;

/**
 * sealed = base64url( nonce24 || eph_pub32 || crypto_box(content_key) || iv12 || body )
 * crypto_box output is libsodium's: MAC16 || ciphertext32.
 */
export function seal(input: SealContext & {
  recipient: Uint8Array;
  plaintext: string;
  /** Fixed randomness for the test vectors; production always generates. */
  nonce?: Uint8Array;
  contentKey?: Uint8Array;
  iv?: Uint8Array;
  ephemeralSecret?: Uint8Array;
}): string {
  const contentKey = input.contentKey ?? randomBytes(32);
  const iv = input.iv ?? randomBytes(12);
  const nonce = input.nonce ?? randomBytes(24);
  const ephemeralSecret = input.ephemeralSecret ?? randomBytes(32);
  if (contentKey.length !== 32 || iv.length !== 12 || nonce.length !== 24) throw new Error("bad seal parameters");
  const body = gcm(contentKey, iv, associatedData(input)).encrypt(utf8(input.plaintext));
  const ephemeral = x25519.getPublicKey(ephemeralSecret);
  const shared = x25519.getSharedSecret(ephemeralSecret, input.recipient);
  const box = xsalsa20poly1305(hsalsa20(shared, ZERO_16), nonce).encrypt(contentKey);
  return b64u(cat(nonce, ephemeral, box, iv, body));
}

export function open(input: SealContext & { recipientSecret: Uint8Array; sealed: string }): string {
  return openParts(unb64u(input.sealed), input, input.recipientSecret);
}

/**
 * The same open, for bytes that never went through base64url: an attachment
 * travels as raw ciphertext in an object store, not as a field in a row.
 */
export function openBytes(input: SealContext & { recipientSecret: Uint8Array; sealed: Uint8Array }): string {
  return openParts(input.sealed, input, input.recipientSecret);
}

function openParts(raw: Uint8Array, context: SealContext, recipientSecret: Uint8Array): string {
  if (raw.length < SEALED_PREFIX + 16) throw new Error("sealed payload is too short");
  const nonce = raw.slice(0, 24);
  const ephemeral = raw.slice(24, 56);
  const box = raw.slice(56, 104);
  const iv = raw.slice(104, 116);
  const body = raw.slice(116);
  const shared = x25519.getSharedSecret(recipientSecret, ephemeral);
  const contentKey = xsalsa20poly1305(hsalsa20(shared, ZERO_16), nonce).decrypt(box);
  return fromUtf8(gcm(contentKey, iv, associatedData(context)).decrypt(body));
}

export interface SealParts {
  nonce: Uint8Array;
  ephemeral: Uint8Array;
  box: Uint8Array;
  iv: Uint8Array;
  body: Uint8Array;
}
export function parseSealed(sealed: string): SealParts {
  const raw = unb64u(sealed);
  if (raw.length < SEALED_PREFIX + 16) throw new Error("sealed payload is too short");
  return {
    nonce: raw.slice(0, 24),
    ephemeral: raw.slice(24, 56),
    box: raw.slice(56, 104),
    iv: raw.slice(104, 116),
    body: raw.slice(116),
  };
}

// --- envelopes ---------------------------------------------------------------

export interface CallEnvelope {
  call_id: string;
  caller: string;
  device: string;
  issued_at: number;
  expires_at: number;
  /** base64url of the fixed layout above, sealed to the device's X25519 key. */
  sealed: string;
  sig: string;
}

export interface ResultEnvelope {
  call_id: string;
  device: string;
  /** Signed, not sealed: the cloud sees success or failure but never the output. */
  ok: boolean;
  issued_at: number;
  /** Sealed to the caller's X25519 key. */
  sealed: string;
  sig: string;
}

/** sig covers every field but itself, including the raw bytes of `sealed`. */
export function callTranscript(call: Omit<CallEnvelope, "sig">): Uint8Array {
  return cat(
    utf8("eXe/call\0"),
    lp(utf8(call.call_id)),
    lp(utf8(call.caller)),
    lp(utf8(call.device)),
    u64be(call.issued_at),
    u64be(call.expires_at),
    lp(unb64u(call.sealed)),
  );
}

export function resultTranscript(result: Omit<ResultEnvelope, "sig">): Uint8Array {
  return cat(
    utf8("eXe/result\0"),
    lp(utf8(result.call_id)),
    lp(utf8(result.device)),
    new Uint8Array([result.ok ? 1 : 0]),
    u64be(result.issued_at),
    lp(unb64u(result.sealed)),
  );
}

export function signCall(seed: Uint8Array, call: CallEnvelope): string {
  return sign(seed, callTranscript(call));
}
export function verifyCall(call: CallEnvelope): boolean {
  try {
    return verifySignature(parseAddress(call.caller), callTranscript(call), call.sig);
  } catch {
    return false;
  }
}
export function signResult(seed: Uint8Array, result: ResultEnvelope): string {
  return sign(seed, resultTranscript(result));
}
export function verifyResult(result: ResultEnvelope): boolean {
  try {
    return verifySignature(parseAddress(result.device), resultTranscript(result), result.sig);
  } catch {
    return false;
  }
}

// --- device request authentication ------------------------------------------

/**
 * Every request is self-signed: no bearer token exists. `/v1/*` takes the address
 * from the path and `/api/*` from `x-exe-address`, but both sign this same
 * transcript, so neither can speak for an address it cannot sign for.
 *
 * There is no nonce in here on purpose. A captured request is harmless because
 * every write it can reach is keyed by a `call_id` the sender signed, so replaying
 * it restates a row instead of causing a second effect (see docs/THREAT-MODEL.md).
 */
export interface RequestAuth {
  method: string;
  /** Request path exactly as sent, e.g. `/v1/devices/<address>/stream`. */
  path: string;
  address: string;
  timestamp: number;
}

export function requestTranscript(auth: RequestAuth): Uint8Array {
  return cat(
    utf8("eXe/request\0"),
    lp(utf8(auth.method.toUpperCase())),
    lp(utf8(auth.path)),
    lp(utf8(auth.address)),
    u64be(auth.timestamp),
  );
}
export function signRequest(seed: Uint8Array, auth: RequestAuth): string {
  return sign(seed, requestTranscript(auth));
}
export function verifyRequest(auth: RequestAuth, signature: string): boolean {
  try {
    return verifySignature(parseAddress(auth.address), requestTranscript(auth), signature);
  } catch {
    return false;
  }
}

/**
 * One self-authenticating request. `/v1/*` reads the address from the path and
 * `/api/*` from `x-exe-address`; both read the same `address` field, which the
 * signature covers, so neither can name an address it cannot sign for.
 */
export function requestHeaders(identity: Identity, method: string, path: string): Record<string, string> {
  const address = addressOf(identity);
  const timestamp = Math.floor(Date.now() / 1000);
  return {
    "x-exe-address": address,
    "x-exe-timestamp": String(timestamp),
    "x-exe-signature": signRequest(identity.seed, { method, path, address, timestamp }),
  };
}

// --- the four things a party actually does -----------------------------------

/** Issuer side: seal a command to a device address and sign the envelope. */
export function buildCall(input: {
  seed: Uint8Array;
  caller: string;
  device: string;
  callId: string;
  name: string;
  args: string;
  issuedAt: number;
  expiresAt: number;
  nonce?: Uint8Array;
  contentKey?: Uint8Array;
  iv?: Uint8Array;
  ephemeralSecret?: Uint8Array;
}): CallEnvelope {
  const sealed = seal({
    direction: "call",
    caller: input.caller,
    device: input.device,
    callId: input.callId,
    issuedAt: input.issuedAt,
    expiresAt: input.expiresAt,
    recipient: agreementPublic(parseAddress(input.device)),
    plaintext: JSON.stringify({ name: input.name, args: input.args }),
    nonce: input.nonce,
    contentKey: input.contentKey,
    iv: input.iv,
    ephemeralSecret: input.ephemeralSecret,
  });
  const call: CallEnvelope = {
    call_id: input.callId,
    caller: input.caller,
    device: input.device,
    issued_at: input.issuedAt,
    expires_at: input.expiresAt,
    sealed,
    sig: "",
  };
  call.sig = signCall(input.seed, call);
  return call;
}

/** Device side: open a verified call with the same key that signs for it. */
export function openCall(input: { seed: Uint8Array; call: CallEnvelope }): { name: string; args: string } {
  const plaintext = open({
    direction: "call",
    caller: input.call.caller,
    device: input.call.device,
    callId: input.call.call_id,
    issuedAt: input.call.issued_at,
    expiresAt: input.call.expires_at,
    recipientSecret: agreementSecret(input.seed),
    sealed: input.call.sealed,
  });
  const parsed = JSON.parse(plaintext) as { name?: unknown; args?: unknown };
  if (typeof parsed.name !== "string" || typeof parsed.args !== "string") throw new Error("sealed call is malformed");
  return { name: parsed.name, args: parsed.args };
}

/** Device side: seal the outcome to the caller and sign the envelope. */
export function buildResult(input: {
  seed: Uint8Array;
  call: CallEnvelope;
  ok: boolean;
  plaintext: string;
  issuedAt: number;
  nonce?: Uint8Array;
  contentKey?: Uint8Array;
  iv?: Uint8Array;
  ephemeralSecret?: Uint8Array;
}): ResultEnvelope {
  const sealed = seal({
    direction: "result",
    caller: input.call.caller,
    device: input.call.device,
    callId: input.call.call_id,
    issuedAt: input.issuedAt,
    // The result inherits the call's expiry: the reply cannot outlive the request.
    expiresAt: input.call.expires_at,
    recipient: agreementPublic(parseAddress(input.call.caller)),
    plaintext: input.plaintext,
    nonce: input.nonce,
    contentKey: input.contentKey,
    iv: input.iv,
    ephemeralSecret: input.ephemeralSecret,
  });
  const result: ResultEnvelope = {
    call_id: input.call.call_id,
    device: input.call.device,
    ok: input.ok,
    issued_at: input.issuedAt,
    sealed,
    sig: "",
  };
  result.sig = signResult(input.seed, result);
  return result;
}

/**
 * Issuer side: open an attachment the device sealed for this call. Same two
 * layers, same binding — only the direction differs, so a blob can never be
 * mistaken for the envelope that points at it, nor for another call's blob.
 */
export function openAttachment(input: {
  seed: Uint8Array;
  call: Pick<CallEnvelope, "call_id" | "caller" | "device" | "expires_at">;
  result: Pick<ResultEnvelope, "issued_at">;
  sealed: Uint8Array;
}): string {
  return openBytes({
    direction: "blob",
    caller: input.call.caller,
    device: input.call.device,
    callId: input.call.call_id,
    issuedAt: input.result.issued_at,
    expiresAt: input.call.expires_at,
    recipientSecret: agreementSecret(input.seed),
    sealed: input.sealed,
  });
}

/** Issuer side: open the sealed answer, which only its own key can unwrap. */
export function openResult(input: {
  seed: Uint8Array;
  call: Pick<CallEnvelope, "call_id" | "caller" | "device" | "expires_at">;
  result: ResultEnvelope;
}): string {
  return open({
    direction: "result",
    caller: input.call.caller,
    device: input.call.device,
    callId: input.call.call_id,
    issuedAt: input.result.issued_at,
    expiresAt: input.call.expires_at,
    recipientSecret: agreementSecret(input.seed),
    sealed: input.result.sealed,
  });
}
