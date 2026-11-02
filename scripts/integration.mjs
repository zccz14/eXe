// End-to-end check against a local worker: pairing, signed call over SSE, sealed result.
import { spawn, spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { randomBytes, randomUUID } from "node:crypto";
import { startJwks } from "./jwks.mjs";
import {
  b64u,
  sealResult,
  shortAuthenticationString,
  verifyCall,
} from "../worker/src/crypto.ts";
import { ed25519 } from "@noble/curves/ed25519.js";
import { x25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";

const PORT = 8787;
const KEK = b64u(new Uint8Array(32).fill(9));
const base = `http://127.0.0.1:${PORT}`;
const jwks = startJwks(8788);

function writeDevVars() {
  const text = `AUTH_ISSUER=${jwks.url}\nAUTH_AUDIENCE=exe.test\nEXE_KEK=${KEK}\n`;
  spawnSync("bash", ["-c", `printf '%s' '${text}' > .dev.vars`], { stdio: "inherit" });
}

async function waitForWorker() {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    try {
      const response = await fetch(`${base}/api/health`);
      if (response.ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("wrangler dev did not become ready");
}

async function main() {
  writeDevVars();
  spawnSync("npx", ["wrangler", "d1", "execute", "exe", "--local", "--file", "worker/src/schema.sql"], { stdio: "inherit" });
  const dev = spawn("npx", ["wrangler", "dev", "--port", String(PORT), "--ip", "127.0.0.1"], {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1" },
    detached: true,
  });
  let devLog = "";
  dev.stdout.on("data", (chunk) => (devLog += chunk));
  dev.stderr.on("data", (chunk) => (devLog += chunk));
  const cleanup = () => {
    try {
      process.kill(-dev.pid, "SIGKILL");
    } catch {
      dev.kill("SIGKILL");
    }
    void jwks.close();
  };
  try {
    await waitForWorker();
    await run(devLog);
    console.log("\nintegration: ok");
  } catch (error) {
    console.error(devLog.slice(-4000));
    cleanup();
    process.exit(1);
  }
  cleanup();
  process.exit(0);
}

async function run() {
  const userId = randomUUID();
  const token = jwks.mint(userId);
  const auth = { authorization: `Bearer ${token}` };

  const me = await fetch(`${base}/api/me`, { headers: auth }).then((r) => r.json());
  assert.equal(me.account_id, userId, "account is created on first touch");
  const accountSigPub = me.sig_pub;

  // --- device side: generate keys, open a pairing ---
  const deviceSigSeed = randomBytes(32);
  const deviceKexSeed = randomBytes(32);
  const deviceSigPub = b64u(ed25519.getPublicKey(deviceSigSeed));
  const deviceKexPub = b64u(x25519.getPublicKey(deviceKexSeed));
  const deviceToken = b64u(new Uint8Array(32).fill(4));
  const deviceSecret = b64u(new Uint8Array(32).fill(5));
  const hex = (bytes) => Buffer.from(bytes).toString("hex");

  const pairing = await fetch(`${base}/v1/pairings`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      dev_sig_pub: deviceSigPub,
      dev_kex_pub: deviceKexPub,
      secret_hash: hex(sha256(new TextEncoder().encode(deviceSecret))),
      token_hash: hex(sha256(new TextEncoder().encode(deviceToken))),
      hostname: "integration-host",
      platform: "linux-x86_64",
      version: "0.1.0",
    }),
  }).then((r) => r.json());
  assert.match(pairing.user_code, /^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);

  const pending = await fetch(`${base}/v1/pairings/${pairing.pairing_id}`, {
    headers: { authorization: `Bearer ${deviceSecret}` },
  });
  assert.equal(pending.status, 202, "device polls while pending");

  // --- console side: the human sees the same SAS the device will print ---
  const view = await fetch(`${base}/api/pairings/${pairing.user_code}`, { headers: auth }).then((r) => r.json());
  assert.equal(view.sas, shortAuthenticationString(accountSigPub, deviceSigPub), "console SAS matches the device computation");

  const approved = await fetch(`${base}/api/pairings/${pairing.user_code}`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ label: "integration" }),
  }).then((r) => r.json());
  const deviceId = approved.device.id;
  assert.equal(approved.sas, view.sas);

  // --- device receives the signed approval and pins the account key ---
  const polled = await fetch(`${base}/v1/pairings/${pairing.pairing_id}`, {
    headers: { authorization: `Bearer ${deviceSecret}` },
  }).then((r) => r.json());
  assert.equal(polled.status, "approved");
  const approval = polled.approval;
  const approvalTranscript = (() => {
    // rebuilt exactly as the device does
    const lp = (bytes) => {
      const out = new Uint8Array(4 + bytes.length);
      new DataView(out.buffer).setUint32(0, bytes.length, false);
      out.set(bytes, 4);
      return out;
    };
    const parts = [
      new TextEncoder().encode("eXe/v1/approval\0"),
      ...["pairingId", "deviceId", "accountId", "accountSigPub", "accountKexPub", "deviceSigPub", "deviceKexPub"].map((key) =>
        lp(new TextEncoder().encode(approval[key])),
      ),
    ];
    const issued = new Uint8Array(8);
    new DataView(issued.buffer).setBigUint64(0, BigInt(approval.issuedAt), false);
    return Buffer.concat([...parts, issued].map((part) => Buffer.from(part)));
  })();
  assert.ok(
    ed25519.verify(
      new Uint8Array(Buffer.from(approval.sig, "base64url")),
      new Uint8Array(approvalTranscript),
      new Uint8Array(Buffer.from(accountSigPub, "base64url")),
    ),
    "the device verifies the approval signature against the pinned account key",
  );

  // --- device opens the stream, console queues a call ---
  const bootId = randomUUID();
  const controller = new AbortController();
  const stream = await fetch(`${base}/v1/devices/${deviceId}/events`, {
    headers: { authorization: `Bearer ${deviceToken}`, "x-exe-boot-id": bootId, "x-exe-version": "0.1.0" },
    signal: controller.signal,
  });
  assert.equal(stream.status, 200);
  assert.match(stream.headers.get("content-type") ?? "", /text\/event-stream/);

  const reader = stream.body.getReader();
  let buffer = "";
  const nextEvent = async (name, timeoutMs = 8000) => {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
      const index = buffer.indexOf("\n\n");
      if (index >= 0) {
        const frame = buffer.slice(0, index);
        buffer = buffer.slice(index + 2);
        const event = /^event:(.*)$/m.exec(frame)?.[1]?.trim();
        const data = /^data:(.*)$/m.exec(frame)?.[1]?.trim();
        if (event === name && data) return JSON.parse(data);
        continue;
      }
      const chunk = await reader.read();
      if (chunk.done) throw new Error("stream closed");
      buffer += new TextDecoder().decode(chunk.value);
    }
    throw new Error(`timed out waiting for ${name}`);
  };

  const call = await fetch(`${base}/api/devices/${deviceId}/calls`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ name: "echo", args: { text: "hello eXe" } }),
  }).then((r) => r.json());
  const callId = call.call.id;

  const delivered = await nextEvent("call");
  assert.equal(delivered.id, callId, "the queued call is delivered over SSE");
  assert.ok(
    verifyCall(accountSigPub, {
      callId: delivered.id,
      deviceId: delivered.device_id,
      accountId: delivered.account_id,
      name: delivered.name,
      args: delivered.args,
      nonce: delivered.nonce,
      issuedAt: delivered.issued_at,
      expiresAt: delivered.expires_at,
    }, delivered.sig),
    "the device can verify the call against the pinned account key",
  );

  await fetch(`${base}/v1/devices/${deviceId}/calls/${callId}/received`, {
    method: "POST",
    headers: { authorization: `Bearer ${deviceToken}` },
  }).then((r) => assert.equal(r.status, 204));

  // A tampered signature must be refused.
  const forged = await fetch(`${base}/v1/devices/${deviceId}/calls/${callId}/result`, {
    method: "POST",
    headers: { authorization: `Bearer ${deviceToken}`, "content-type": "application/json" },
    body: JSON.stringify({ v: 1, eph: b64u(new Uint8Array(32)), nonce: b64u(new Uint8Array(12)), ct: b64u(new Uint8Array(32)), sig: b64u(new Uint8Array(64)) }),
  });
  assert.equal(forged.status, 403, "a result without the device key is refused");

  const plaintext = JSON.stringify({ ok: true, output: { tool: "echo", text: "SEALED-MARKER-42" } });
  const sealed = sealResult({ callId, deviceId, accountKexPub: Buffer.from(me.kex_pub, "base64url"), plaintext });
  const signature = ed25519.sign(
    Buffer.concat([
      Buffer.from("eXe/v1/result\0"),
      lpString(callId),
      lpString(deviceId),
      lpBytes(Buffer.from(sealed.eph, "base64url")),
      lpBytes(Buffer.from(sealed.nonce, "base64url")),
      lpBytes(sha256(Buffer.from(sealed.ct, "base64url"))),
    ]),
    deviceSigSeed,
  );
  const posted = await fetch(`${base}/v1/devices/${deviceId}/calls/${callId}/result`, {
    method: "POST",
    headers: { authorization: `Bearer ${deviceToken}`, "content-type": "application/json" },
    body: JSON.stringify({ ...sealed, sig: b64u(signature) }),
  });
  assert.equal(posted.status, 204, "the sealed result is accepted");

  const detail = await fetch(`${base}/api/calls/${callId}`, { headers: auth }).then((r) => r.json());
  assert.equal(detail.call.status, "succeeded");
  assert.deepEqual(detail.result, JSON.parse(plaintext), "the console opens the envelope it stored");

  const stored = await fetch(`${base}/api/calls?device_id=${deviceId}`, { headers: auth }).then((r) => r.json());
  assert.equal(stored.calls[0].has_result, true);
  assert.equal(JSON.stringify(stored.calls).includes("SEALED-MARKER-42"), false, "list views never carry result plaintext");

  // --- a fresh boot marks the in-flight call lost ---
  const second = await fetch(`${base}/api/devices/${deviceId}/calls`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ name: "echo", args: { text: "second" } }),
  }).then((r) => r.json());
  const secondDelivered = await nextEvent("call");
  assert.equal(secondDelivered.id, second.call.id);
  controller.abort();
  await fetch(`${base}/v1/devices/${deviceId}/events`, {
    headers: { authorization: `Bearer ${deviceToken}`, "x-exe-boot-id": randomUUID(), "x-exe-version": "0.1.0" },
    signal: AbortSignal.timeout(1500),
  }).catch(() => undefined);
  await new Promise((resolve) => setTimeout(resolve, 500));
  const lost = await fetch(`${base}/api/calls/${second.call.id}`, { headers: auth }).then((r) => r.json());
  assert.equal(lost.call.status, "failed");
  assert.equal(lost.call.failure_code, "device_restarted");

  // --- revocation stops the device ---
  await fetch(`${base}/api/devices/${deviceId}`, { method: "DELETE", headers: auth }).then((r) => assert.equal(r.status, 204));
  const revoked = await fetch(`${base}/v1/devices/${deviceId}/heartbeat`, {
    method: "POST",
    headers: { authorization: `Bearer ${deviceToken}` },
  });
  assert.equal(revoked.status, 401, "a revoked device cannot talk to the worker");
}

function lpString(value) {
  return lpBytes(Buffer.from(value, "utf8"));
}
function lpBytes(bytes) {
  const out = Buffer.alloc(4 + bytes.length);
  out.writeUInt32BE(bytes.length, 0);
  Buffer.from(bytes).copy(out, 4);
  return out;
}

await main();
