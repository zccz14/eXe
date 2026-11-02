import assert from "node:assert/strict";
import { test } from "node:test";
import vectors from "./vectors.json" with { type: "json" };
import {
  accountTranscript,
  approvalTranscript,
  b64u,
  callTranscript,
  hex,
  openCall,
  openResult,
  resultTranscript,
  sealResult,
  shortAuthenticationString,
  unb64u,
  unhex,
  signAccount,
  verifyAccount,
  verifyApproval,
  verifyCall,
  verifyResultSignature,
} from "../shared/protocol.ts";
import { sha256 } from "@noble/hashes/sha2.js";
import { ed25519 } from "@noble/curves/ed25519.js";

const callFields = {
  callId: vectors.call.callId,
  deviceId: vectors.call.deviceId,
  accountId: vectors.call.accountId,
  eph: unb64u(vectors.call.eph),
  nonce: unb64u(vectors.call.nonce),
  ciphertext: unb64u(vectors.call.ct),
  issuedAt: vectors.call.issuedAt,
  expiresAt: vectors.call.expiresAt,
};

test("call transcript digest is stable and the account signature verifies", () => {
  assert.equal(hex(sha256(callTranscript(callFields))), vectors.call.transcript_sha256);
  assert.ok(verifyCall(vectors.keys.account_sig_pub, callFields, vectors.call.sig));
});

test("any change to a signed call is rejected", () => {
  const flipped = new Uint8Array(callFields.ciphertext);
  flipped[0] = flipped[0]! ^ 1;
  assert.equal(verifyCall(vectors.keys.account_sig_pub, { ...callFields, ciphertext: flipped }, vectors.call.sig), false);
  assert.equal(verifyCall(vectors.keys.account_sig_pub, { ...callFields, deviceId: crypto.randomUUID() }, vectors.call.sig), false);
  assert.equal(verifyCall(vectors.keys.account_sig_pub, { ...callFields, expiresAt: callFields.expiresAt + 1 }, vectors.call.sig), false);
  assert.equal(verifyCall(vectors.keys.device_sig_pub, callFields, vectors.call.sig), false);
});

test("only the device can open its command, and the cloud sees no tool name", () => {
  const opened = openCall({
    deviceKexSk: unhex(vectors.keys.device_kex_seed),
    callId: callFields.callId,
    deviceId: callFields.deviceId,
    accountId: callFields.accountId,
    eph: callFields.eph,
    nonce: callFields.nonce,
    ciphertext: callFields.ciphertext,
  });
  const expected = JSON.parse(vectors.call.plaintext) as { name: string; args: string };
  assert.equal(opened.name, expected.name);
  assert.equal(opened.args, expected.args);
  assert.throws(() =>
    openCall({
      deviceKexSk: unhex(vectors.keys.account_kex_seed),
      callId: callFields.callId,
      deviceId: callFields.deviceId,
      accountId: callFields.accountId,
      eph: callFields.eph,
      nonce: callFields.nonce,
      ciphertext: callFields.ciphertext,
    }),
  );
  const wire = `${vectors.call.eph}${vectors.call.nonce}${vectors.call.ct}`;
  assert.equal(wire.includes(expected.name), false, "the wire envelope carries no tool name");
  assert.equal(wire.includes("hello eXe"), false, "and no arguments either");
});

test("account registration proves possession without sending a private key", () => {
  const fields = {
    userId: vectors.account.userId,
    nonce: vectors.account.nonce,
    sigPub: vectors.account.sigPub,
    kexPub: vectors.account.kexPub,
    issuedAt: vectors.account.issuedAt,
  };
  assert.equal(hex(sha256(accountTranscript(fields))), vectors.account.transcript_sha256);
  assert.ok(verifyAccount(vectors.keys.account_sig_pub, fields, vectors.account.sig));
  assert.equal(verifyAccount(vectors.keys.account_sig_pub, { ...fields, nonce: "other" }, vectors.account.sig), false);
  assert.equal(verifyAccount(vectors.keys.device_sig_pub, fields, vectors.account.sig), false);
  assert.equal(JSON.stringify(vectors.account).includes("seed"), false, "vectors carry no private material");
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
  assert.ok(verifyApproval(vectors.keys.account_sig_pub, fields, vectors.approval.sig));
});

test("sealed results open with the account key and reject tampering", () => {
  const envelope = { v: 1 as const, ok: vectors.result.ok, eph: vectors.result.eph, nonce: vectors.result.nonce, ct: vectors.result.ct };
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

test("result signature covers the ciphertext and the outcome", () => {
  const fields = {
    callId: vectors.result.call_id,
    deviceId: vectors.result.device_id,
    ok: vectors.result.ok,
    eph: unb64u(vectors.result.eph),
    nonce: unb64u(vectors.result.nonce),
    ciphertext: unb64u(vectors.result.ct),
  };
  assert.equal(hex(sha256(resultTranscript(fields))), vectors.result.transcript_sha256);
  assert.ok(verifyResultSignature(vectors.keys.device_sig_pub, fields, vectors.result.sig));
  const tampered = new Uint8Array(fields.ciphertext);
  tampered[0] = tampered[0]! ^ 1;
  assert.equal(verifyResultSignature(vectors.keys.device_sig_pub, { ...fields, ciphertext: tampered }, vectors.result.sig), false);
  assert.equal(verifyResultSignature(vectors.keys.device_sig_pub, { ...fields, ok: false }, vectors.result.sig), false);
});

test("sealing is randomized but still opens", () => {
  const first = sealResult({
    callId: vectors.result.call_id,
    deviceId: vectors.result.device_id,
    ok: true,
    accountKexPub: unb64u(vectors.keys.account_kex_pub),
    plaintext: "{}",
  });
  const second = sealResult({
    callId: vectors.result.call_id,
    deviceId: vectors.result.device_id,
    ok: true,
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
