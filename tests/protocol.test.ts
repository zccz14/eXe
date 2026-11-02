import assert from "node:assert/strict";
import { test } from "node:test";
import vectors from "./vectors.json" with { type: "json" };
import {
  accountPayload,
  accountTranscript,
  addressOf,
  agreementPublic,
  agreementSecret,
  b58,
  b64u,
  buildCall,
  buildResult,
  callTranscript,
  decodeSecret,
  encodeSecret,
  hex,
  hsalsa20,
  identityFromSeed,
  isAddress,
  newIdentity,
  openCall,
  openResult,
  parseAddress,
  parseSealed,
  requestTranscript,
  resultTranscript,
  sha256Hex,
  signAccount,
  signCall,
  unb58,
  unhex,
  verifyAccount,
  verifyCall,
  verifyRequest,
  verifyResult,
} from "../shared/protocol.ts";
import { ed25519, x25519 } from "@noble/curves/ed25519.js";

const issuer = identityFromSeed(unhex(vectors.keys.issuer_seed));
const device = identityFromSeed(unhex(vectors.keys.device_seed));

test("an address is a base58 Ed25519 public key and the secret round trips", () => {
  assert.equal(addressOf(issuer), vectors.keys.issuer_address);
  assert.equal(addressOf(device), vectors.keys.device_address);
  assert.equal(addressOf(issuer).length, 44);
  assert.ok(isAddress(vectors.keys.issuer_address));
  assert.equal(isAddress("not-an-address"), false);
  assert.equal(isAddress(""), false);
  assert.equal(isAddress(vectors.keys.issuer_seed), false, "hex is not an address");

  const secret = encodeSecret(device);
  const restored = decodeSecret(secret);
  assert.equal(hex(restored.seed), vectors.keys.device_seed);
  assert.equal(addressOf(restored), vectors.keys.device_address);

  // A secret whose trailing public half was swapped must be refused outright.
  const raw = unb58(secret);
  raw[40] = raw[40]! ^ 1;
  assert.throws(() => decodeSecret(b58(raw)));

  // Random 32-byte values survive the base58 round trip, including leading zeros.
  for (const value of [new Uint8Array(32), new Uint8Array(32).fill(255), unhex(vectors.keys.device_seed)]) {
    assert.equal(hex(unb58(b58(value))), hex(value));
  }
});

test("X25519 is derived from the one Ed25519 key, not stored separately", () => {
  assert.equal(hex(agreementPublic(device.public)), hex(x25519.getPublicKey(agreementSecret(device.seed))));
  assert.equal(hex(agreementSecret(device.seed)), hex(ed25519.utils.toMontgomerySecret(device.seed)));
  assert.notEqual(hex(agreementSecret(device.seed)), hex(device.seed));
});

test("HSalsa20 matches the reference vector", () => {
  assert.equal(hex(hsalsa20(new Uint8Array(32), new Uint8Array(16))), "351f86faa3b988468a850122b65b0acece9c4826806aeee63de9c0da2bd7f91e");
});

test("the call vector signs and verifies, and any edit breaks it", () => {
  const call = {
    call_id: vectors.call.call_id,
    issuer: vectors.call.issuer,
    device: vectors.call.device,
    issued_at: vectors.call.issued_at,
    expires_at: vectors.call.expires_at,
    sealed: vectors.call.sealed,
    sig: vectors.call.sig,
  };
  assert.equal(sha256Hex(callTranscript(call)), vectors.call.transcript_sha256);
  assert.ok(verifyCall(call));
  assert.equal(call.sig, signCall(issuer.seed, call));
  assert.equal(verifyCall({ ...call, sig: call.sig.slice(0, -1) + (call.sig.endsWith("a") ? "b" : "a") }), false);
  assert.equal(verifyCall({ ...call, device: addressOf(newIdentity()) }), false);
  assert.equal(verifyCall({ ...call, expires_at: call.expires_at + 1 }), false);
  assert.equal(verifyCall({ ...call, issuer: vectors.keys.device_address }), false, "the device cannot speak for the issuer");
});

test("only the device opens its command and the wire names nothing", () => {
  const call = {
    call_id: vectors.call.call_id,
    issuer: vectors.call.issuer,
    device: vectors.call.device,
    issued_at: vectors.call.issued_at,
    expires_at: vectors.call.expires_at,
    sealed: vectors.call.sealed,
    sig: vectors.call.sig,
  };
  const opened = openCall({ seed: device.seed, call });
  assert.equal(JSON.stringify(opened), vectors.call.plaintext);
  assert.throws(() => openCall({ seed: issuer.seed, call }), "another key cannot open it");

  const wire = JSON.stringify({ ...call, sealed: undefined }) + vectors.call.sealed;
  assert.equal(wire.includes("echo"), false, "no tool name on the wire");
  assert.equal(wire.includes("hello eXe"), false, "no arguments either");

  // The associated data binds the envelope: a different call_id cannot open it.
  assert.throws(() => openCall({ seed: device.seed, call: { ...call, call_id: "22222222-2222-4222-8222-222222222222" } }));
  assert.throws(() => openCall({ seed: device.seed, call: { ...call, expires_at: call.expires_at + 1 } }));
});

test("the result vector is sealed to the issuer and signed by the device", () => {
  const call = {
    call_id: vectors.call.call_id,
    issuer: vectors.call.issuer,
    device: vectors.call.device,
    expires_at: vectors.call.expires_at,
  };
  const result = {
    call_id: vectors.result.call_id,
    device: vectors.result.device,
    ok: vectors.result.ok,
    issued_at: vectors.result.issued_at,
    sealed: vectors.result.sealed,
    sig: vectors.result.sig,
  };
  assert.equal(sha256Hex(resultTranscript(result)), vectors.result.transcript_sha256);
  assert.ok(verifyResult(result));
  assert.equal(openResult({ seed: issuer.seed, call, result }), vectors.result.plaintext);
  assert.throws(() => openResult({ seed: device.seed, call, result }), "the device cannot read it back");
  assert.equal(verifyResult({ ...result, ok: false }), false, "the outcome is signed, not decorative");
  assert.equal(verifyResult({ ...result, device: vectors.keys.issuer_address }), false);
});

test("device requests are self-signed over method, path, address, time and nonce", () => {
  const auth = {
    method: vectors.request.method,
    path: vectors.request.path,
    address: vectors.request.address,
    timestamp: vectors.request.timestamp,
    nonce: vectors.request.nonce,
  };
  assert.equal(sha256Hex(requestTranscript(auth)), vectors.request.transcript_sha256);
  assert.ok(verifyRequest(auth, vectors.request.sig));
  assert.equal(verifyRequest({ ...auth, method: "GET" }, vectors.request.sig), false);
  assert.equal(verifyRequest({ ...auth, path: auth.path.replace("/result", "/received") }, vectors.request.sig), false);
  assert.equal(verifyRequest({ ...auth, timestamp: auth.timestamp + 1 }, vectors.request.sig), false);
  assert.equal(verifyRequest({ ...auth, nonce: b64u(new Uint8Array(16)) }, vectors.request.sig), false);
});

test("account registration proves the browser holds the key", () => {
  const fields = {
    address: vectors.account.address,
    userId: vectors.account.userId,
    nonce: vectors.account.nonce,
    issuedAt: vectors.account.issuedAt,
  };
  assert.equal(sha256Hex(accountTranscript(fields)), vectors.account.transcript_sha256);
  assert.ok(verifyAccount(fields, vectors.account.sig));
  assert.equal(verifyAccount({ ...fields, userId: "44444444-4444-4444-8444-444444444444" }, vectors.account.sig), false);
  assert.equal(JSON.stringify(vectors).match(/seed32|private/i), null, "vectors carry seeds for testing only, never secrets from production");
});

test("sealing is randomized but still opens", () => {
  const callId = "11111111-1111-4111-8111-111111111111";
  const make = () =>
    buildCall({
      seed: issuer.seed,
      issuer: addressOf(issuer),
      device: addressOf(device),
      callId,
      name: "echo",
      args: "{}",
      issuedAt: 1_700_000_000,
      expiresAt: 1_700_000_300,
    });
  const first = make();
  const second = make();
  assert.notEqual(first.sealed, second.sealed);
  for (const call of [first, second]) {
    assert.equal(openCall({ seed: device.seed, call }).name, "echo");
    assert.ok(verifyCall(call));
  }
});

test("a sealed payload carries a fixed header", () => {
  const bytes = parseSealed(vectors.call.sealed);
  assert.equal(bytes.nonce.length, 24);
  assert.equal(bytes.ephemeral.length, 32);
  assert.equal(bytes.box.length, 48);
  assert.equal(bytes.iv.length, 12);
  assert.ok(bytes.body.length >= 16);
  assert.throws(() => parseSealed(b64u(new Uint8Array(80))));
});

test("a result built after the fact cannot be swapped between calls", () => {
  const call = {
    call_id: vectors.call.call_id,
    issuer: vectors.call.issuer,
    device: vectors.call.device,
    issued_at: vectors.call.issued_at,
    expires_at: vectors.call.expires_at,
    sealed: vectors.call.sealed,
    sig: vectors.call.sig,
  };
  const result = buildResult({ seed: device.seed, call, ok: false, plaintext: '{"ok":false,"code":"spawn_failed"}', issuedAt: 1_700_000_010 });
  assert.equal(verifyResult(result), true);
  assert.equal(openResult({ seed: issuer.seed, call, result }), '{"ok":false,"code":"spawn_failed"}');
  const other = { ...call, call_id: "22222222-2222-4222-8222-222222222222", expires_at: call.expires_at + 60 };
  assert.throws(() => openResult({ seed: issuer.seed, call: other, result }), "aAD binds the result to the call");
});

test("the account registration body matches what the relay parses", () => {
  const fields = {
    address: vectors.call.issuer,
    userId: "031a393d-8a0a-4ca0-8cb1-313e0d71dfa9",
    nonce: b64u(new Uint8Array(24).fill(7)),
    issuedAt: 1_700_000_000,
  };
  const payload = accountPayload(fields, signAccount(issuer.seed, fields));
  // The relay reads `issued_at` as a number and never looks for `userId`: the
  // access token already carries it. A camelCase body fails with
  // "issued_at is invalid", which is exactly how the console broke.
  assert.deepEqual(Object.keys(payload).sort(), ["address", "issued_at", "nonce", "sig"]);
  assert.equal(typeof payload.issued_at, "number");
  assert.equal(payload.issued_at, fields.issuedAt);
  assert.equal(payload.nonce, fields.nonce);
  assert.equal(payload.address, fields.address);
  assert.equal(verifyAccount(fields, payload.sig), true);
});
