import assert from "node:assert/strict";
import { test } from "node:test";
import vectors from "./vectors.json" with { type: "json" };
import {
  approvalTranscript,
  b64u,
  callTranscript,
  hex,
  openResult,
  resultTranscript,
  sealResult,
  shortAuthenticationString,
  unb64u,
  unhex,
  verifyCall,
  verifyResultSignature,
} from "../worker/src/crypto.ts";
import { sha256 } from "@noble/hashes/sha2.js";
import { ed25519 } from "@noble/curves/ed25519.js";

const call = {
  callId: vectors.call.callId,
  deviceId: vectors.call.deviceId,
  accountId: vectors.call.accountId,
  name: vectors.call.name,
  args: vectors.call.args,
  nonce: vectors.call.nonce,
  issuedAt: vectors.call.issuedAt,
  expiresAt: vectors.call.expiresAt,
};

test("call transcript digest is stable and the account signature verifies", () => {
  assert.equal(hex(sha256(callTranscript(call))), vectors.call.transcript_sha256);
  assert.ok(verifyCall(vectors.keys.account_sig_pub, call, vectors.call.sig));
});

test("any change to a signed call is rejected", () => {
  assert.equal(verifyCall(vectors.keys.account_sig_pub, { ...call, args: '{"text":"evil"}' }, vectors.call.sig), false);
  assert.equal(verifyCall(vectors.keys.account_sig_pub, { ...call, deviceId: crypto.randomUUID() }, vectors.call.sig), false);
  assert.equal(verifyCall(vectors.keys.account_sig_pub, { ...call, expiresAt: call.expiresAt + 1 }, vectors.call.sig), false);
  assert.equal(verifyCall(vectors.keys.device_sig_pub, call, vectors.call.sig), false);
});

test("approval transcript is stable", () => {
  const fields = {
    pairingId: vectors.approval.pairingId,
    deviceId: vectors.approval.deviceId,
    accountId: vectors.approval.accountId,
    accountSigPub: vectors.approval.accountSigPub,
    accountKexPub: vectors.approval.accountKexPub,
    deviceSigPub: vectors.approval.deviceSigPub,
    deviceKexPub: vectors.approval.deviceKexPub,
    issuedAt: vectors.approval.issuedAt,
  };
  assert.equal(hex(sha256(approvalTranscript(fields))), vectors.approval.transcript_sha256);
  assert.ok(ed25519.verify(unb64u(vectors.approval.sig), approvalTranscript(fields), unb64u(vectors.keys.account_sig_pub)));
});

test("sealed results open with the account key and reject tampering", () => {
  const envelope = { v: 1 as const, eph: vectors.result.eph, nonce: vectors.result.nonce, ct: vectors.result.ct };
  const plaintext = openResult({
    accountKexSk: unhex(vectors.keys.account_kex_seed),
    callId: vectors.result.call_id,
    deviceId: vectors.result.device_id,
    envelope,
  });
  assert.equal(plaintext, vectors.result.plaintext);
  assert.throws(() =>
    openResult({
      accountKexSk: unhex(vectors.keys.account_kex_seed),
      callId: "00000000-0000-4000-8000-000000000000",
      deviceId: vectors.result.device_id,
      envelope,
    }),
  );
});

test("result signature covers the ciphertext", () => {
  const fields = {
    callId: vectors.result.call_id,
    deviceId: vectors.result.device_id,
    eph: unb64u(vectors.result.eph),
    nonce: unb64u(vectors.result.nonce),
    ciphertext: unb64u(vectors.result.ct),
  };
  assert.equal(hex(sha256(resultTranscript(fields))), vectors.result.transcript_sha256);
  assert.ok(verifyResultSignature(vectors.keys.device_sig_pub, fields, vectors.result.sig));
  const tampered = new Uint8Array(fields.ciphertext);
  tampered[0] = tampered[0]! ^ 1;
  assert.equal(verifyResultSignature(vectors.keys.device_sig_pub, { ...fields, ciphertext: tampered }, vectors.result.sig), false);
});

test("sealing is randomized but still opens", () => {
  const first = sealResult({
    callId: vectors.result.call_id,
    deviceId: vectors.result.device_id,
    accountKexPub: unb64u(vectors.keys.account_kex_pub),
    plaintext: "{}",
  });
  const second = sealResult({
    callId: vectors.result.call_id,
    deviceId: vectors.result.device_id,
    accountKexPub: unb64u(vectors.keys.account_kex_pub),
    plaintext: "{}",
  });
  assert.notEqual(first.ct, second.ct);
  assert.equal(
    openResult({ accountKexSk: unhex(vectors.keys.account_kex_seed), callId: vectors.result.call_id, deviceId: vectors.result.device_id, envelope: first }),
    "{}",
  );
});

test("SAS is deterministic and short", () => {
  assert.equal(shortAuthenticationString(vectors.keys.account_sig_pub, vectors.keys.device_sig_pub), vectors.sas);
  assert.match(vectors.sas, /^\d{6}$/);
  assert.notEqual(shortAuthenticationString(vectors.keys.account_sig_pub, vectors.keys.account_kex_pub), vectors.sas);
});
