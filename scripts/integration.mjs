// End-to-end check against a local worker: self-registration, signed requests,
// sealed call over SSE, sealed result, and proof that the relay never holds
// anything it could sign with or read.
import { spawn, spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { startJwks } from "./jwks.mjs";
import { makeBrowser, now, signedHeaders } from "./browser.mjs";
import {
  addressOf,
  b64u,
  buildResult,
  newIdentity,
  openCall,
  randomBytes,
  signRequest,
  verifyCall,
} from "../shared/protocol.ts";

const PORT = 8787;
const base = `http://127.0.0.1:${PORT}`;
const jwks = startJwks(8788);

function writeDevVars() {
  const text = `AUTH_ISSUER=${jwks.url}\nAUTH_AUDIENCE=exe.test\n`;
  spawnSync("bash", ["-c", `printf '%s' '${text}' > .dev.vars`], { stdio: "inherit" });
}

async function waitForWorker() {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    try {
      if ((await fetch(`${base}/api/health`)).ok) return;
    } catch {
      /* not up yet */
    }
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  throw new Error("wrangler dev did not become ready");
}

async function main() {
  writeDevVars();
  spawnSync("npx", ["wrangler", "d1", "execute", "exe", "--local", "--command",
    "DROP TABLE IF EXISTS calls; DROP TABLE IF EXISTS devices; DROP TABLE IF EXISTS agents; DROP TABLE IF EXISTS accounts; DROP TABLE IF EXISTS account_challenges; DROP TABLE IF EXISTS request_nonces;"],
    { stdio: "ignore" });
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
    await run();
    console.log("\nintegration: ok");
  } catch (error) {
    console.error("FAILED:", error instanceof Error ? error.message : error);
    console.error(devLog.slice(-3000));
    cleanup();
    process.exit(1);
  }
  cleanup();
  process.exit(0);
}

async function run() {
  // --- client binaries come from the latest GitHub Release -----------------
  const releases = await fetch(`${base}/api/releases/latest`).then((r) => r.json());
  assert.equal(releases.configured, false, "no GitHub token is configured in tests");
  assert.deepEqual(releases.assets, []);
  assert.match(releases.release_url, /github\.com\/zccz14\/eXe\/releases\/latest/);
  assert.equal((await fetch(`${base}/download/exe-aarch64-apple-darwin.tar.gz`)).status, 404, "nothing to download without a release");

  // --- the browser owns the only account key ------------------------------
  const userId = randomUUID();
  const auth = { authorization: `Bearer ${jwks.mint(userId)}` };
  const browser = makeBrowser();

  const meBefore = await fetch(`${base}/api/me`, { headers: auth }).then((r) => r.json());
  assert.equal(meBefore.registered, false);
  assert.equal(meBefore.custody, "browser");
  assert.equal((await fetch(`${base}/api/devices`, { headers: auth })).status, 200, "listing devices needs no key");

  await browser.register(base, auth);
  const me = await fetch(`${base}/api/me`, { headers: auth }).then((r) => r.json());
  assert.equal(me.address, browser.address);
  assert.equal(JSON.stringify(me).match(/secret|seed|sig_sk/i), null, "the relay never reports private material");

  // --- a device is added by address; there is nothing to pair --------------
  const device = newIdentity();
  const deviceAddress = addressOf(device);
  const added = await browser.addDevice(base, auth, deviceAddress, "integration");
  assert.equal(added.device.address, deviceAddress);
  assert.equal(added.device.online, false);
  assert.equal(added.device.hostname, null, "the relay knows nothing about it yet");
  const devices = await fetch(`${base}/api/devices`, { headers: auth }).then((r) => r.json());
  assert.equal(devices.devices.length, 1);

  // --- the device self-registers: one signed request, single-use nonce -----
  const regPath = `/v1/agents/${deviceAddress}`;
  const regBody = JSON.stringify({ hostname: "integration-host", platform: "linux-x86_64", version: "0.1.0" });
  const regHeaders = signedHeaders(device, "PUT", regPath);
  const reg = await fetch(`${base}${regPath}`, {
    method: "PUT",
    headers: { ...regHeaders, "content-type": "application/json" },
    body: regBody,
  });
  assert.equal(reg.status, 200, await reg.text());
  const replayed = await fetch(`${base}${regPath}`, {
    method: "PUT",
    headers: { ...regHeaders, "content-type": "application/json" },
    body: regBody,
  });
  assert.equal(replayed.status, 401, "a captured request cannot be replayed");

  const stale = {
    method: "PUT",
    path: regPath,
    address: deviceAddress,
    timestamp: now() - 3600,
    nonce: b64u(randomBytes(16)),
  };
  const staleAttempt = await fetch(`${base}${regPath}`, {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      "x-exe-timestamp": String(stale.timestamp),
      "x-exe-nonce": stale.nonce,
      "x-exe-signature": signRequest(device.seed, stale),
    },
    body: regBody,
  });
  assert.equal(staleAttempt.status, 401, "a signed request outside the window is refused");

  const unsigned = await fetch(`${base}${regPath}`, {
    method: "PUT",
    headers: { "content-type": "application/json" },
    body: regBody,
  });
  assert.equal(unsigned.status, 401, "self-registration needs the device key");

  const online = await fetch(`${base}/api/devices`, { headers: auth }).then((r) => r.json());
  assert.equal(online.devices[0].online, true);
  assert.equal(online.devices[0].hostname, "integration-host");

  // --- SSE with self-signed auth ------------------------------------------
  const streamPath = `/v1/agents/${deviceAddress}/stream`;
  const controller = new AbortController();
  const stream = await fetch(`${base}${streamPath}`, {
    headers: signedHeaders(device, "GET", streamPath),
    signal: controller.signal,
  });
  assert.equal(stream.status, 200);
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
  await nextEvent("hello");

  // --- a signed call the device alone can open ----------------------------
  const created = await browser.call(base, auth, deviceAddress, "echo", { text: "hello eXe" });
  const callId = created.call.call_id;
  const delivered = await nextEvent("call");
  assert.equal(delivered.call_id, callId);
  assert.ok(verifyCall(delivered), "the device can verify the issuer signature");
  const opened = openCall({ seed: device.seed, call: delivered });
  assert.equal(opened.name, "echo");
  assert.deepEqual(JSON.parse(opened.args), { text: "hello eXe" });
  const wire = JSON.stringify(delivered);
  assert.equal(wire.includes("echo"), false, "the wire carries no tool name");
  assert.equal(wire.includes("hello eXe"), false, "nor the arguments");

  // Editing the sealed body after signing is refused before it is queued.
  const forged = browser.signCall(deviceAddress, "echo", { text: "honest" });
  forged.sealed = b64u(new Uint8Array(160));
  const tampered = await fetch(`${base}/api/devices/${deviceAddress}/calls`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify(forged),
  });
  assert.equal(tampered.status, 403);

  const unsolicited = await fetch(`${base}/api/devices/${deviceAddress}/calls`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ name: "echo", args: "{}" }),
  });
  assert.equal(unsolicited.status, 400);

  // Another account may keep the same address in its own book: the relay routes
  // but does not decide trust. What stops it is the device's trust list.
  const stranger = makeBrowser();
  const strangerAuth = { authorization: `Bearer ${jwks.mint(randomUUID())}` };
  await stranger.register(base, strangerAuth);
  await stranger.addDevice(base, strangerAuth, deviceAddress, "not mine");
  const strangerCall = stranger.signCall(deviceAddress, "echo", { text: "from a stranger" });
  assert.ok(verifyCall(strangerCall), "the stranger's envelope is well formed");
  const strangerQueued = await fetch(`${base}/api/devices/${deviceAddress}/calls`, {
    method: "POST",
    headers: { ...strangerAuth, "content-type": "application/json" },
    body: JSON.stringify(strangerCall),
  });
  assert.equal(strangerQueued.status, 200, "the relay only queues what the sender signed");
  assert.notEqual(strangerCall.issuer, browser.address, "but a device that trusts only the browser will discard it");
  assert.equal(
    verifyCall({ ...strangerCall, issuer: browser.address }),
    false,
    "and nobody can sign in the browser's name",
  );

  // --- receipts and results ------------------------------------------------
  const receivedPath = `/v1/agents/${deviceAddress}/calls/${callId}/received`;
  const received = await fetch(`${base}${receivedPath}`, { method: "POST", headers: signedHeaders(device, "POST", receivedPath) });
  assert.equal(received.status, 204);

  const resultPath = `/v1/agents/${deviceAddress}/calls/${callId}/result`;
  const forgedResult = await fetch(`${base}${resultPath}`, {
    method: "POST",
    headers: { ...signedHeaders(device, "POST", resultPath), "content-type": "application/json" },
    body: JSON.stringify({ call_id: callId, device: deviceAddress, ok: true, issued_at: now(), sealed: b64u(new Uint8Array(140)), sig: b64u(new Uint8Array(64)) }),
  });
  assert.equal(forgedResult.status, 403, "the relay refuses a result the device did not sign");

  const plaintext = JSON.stringify({ ok: true, output: { tool: "echo", text: "SEALED-MARKER-42" } });
  const result = buildResult({ seed: device.seed, call: delivered, ok: true, plaintext, issuedAt: now() });
  const posted = await fetch(`${base}${resultPath}`, {
    method: "POST",
    headers: { ...signedHeaders(device, "POST", resultPath), "content-type": "application/json" },
    body: JSON.stringify(result),
  });
  assert.equal(posted.status, 204, await posted.text());

  // At-least-once: the same envelope may arrive twice and settles once.
  const again = await fetch(`${base}${resultPath}`, {
    method: "POST",
    headers: { ...signedHeaders(device, "POST", resultPath), "content-type": "application/json" },
    body: JSON.stringify(result),
  });
  assert.equal(again.status, 204, "a repeated envelope is accepted as the same outcome");

  const conflicting = buildResult({ seed: device.seed, call: delivered, ok: false, plaintext: '{"ok":false}', issuedAt: now() });
  const conflict = await fetch(`${base}${resultPath}`, {
    method: "POST",
    headers: { ...signedHeaders(device, "POST", resultPath), "content-type": "application/json" },
    body: JSON.stringify(conflicting),
  });
  assert.equal(conflict.status, 409, "a different outcome for a settled call is refused");

  // --- only the issuing browser can read it --------------------------------
  const detail = await fetch(`${base}/api/calls/${callId}`, { headers: auth }).then((r) => r.json());
  assert.equal(detail.call.status, "succeeded");
  assert.equal(detail.call.has_result, true);
  assert.ok(detail.result, "the envelope is returned verbatim");
  assert.equal(JSON.stringify(detail).includes("SEALED-MARKER-42"), false, "no plaintext in the API");
  assert.deepEqual(browser.open(detail.call, detail.result), JSON.parse(plaintext));
  assert.throws(() => stranger.open(detail.call, detail.result), "another browser cannot open the envelope");

  const stored = await fetch(`${base}/api/calls?device=${deviceAddress}`, { headers: auth }).then((r) => r.json());
  assert.equal(stored.calls.length, 1);
  assert.equal(JSON.stringify(stored).includes("SEALED-MARKER-42"), false);

  // --- cancelling something that was never delivered -----------------------
  const idle = newIdentity();
  const idleAddress = addressOf(idle);
  await browser.addDevice(base, auth, idleAddress, "idle");
  const pending = await browser.call(base, auth, idleAddress, "sleep", { seconds: 5 });
  const cancelled = await fetch(`${base}/api/calls/${pending.call.call_id}/cancel`, { method: "POST", headers: auth });
  assert.equal(cancelled.status, 204);
  const cancelledView = await fetch(`${base}/api/calls/${pending.call.call_id}`, { headers: auth }).then((r) => r.json());
  assert.equal(cancelledView.call.status, "cancelled");

  // --- removing a device stops new calls -----------------------------------
  const removed = await fetch(`${base}/api/devices/${idleAddress}`, { method: "DELETE", headers: auth });
  assert.equal(removed.status, 204);
  const blocked = await fetch(`${base}/api/devices/${idleAddress}/calls`, {
    method: "POST",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify(browser.signCall(idleAddress, "echo", {})),
  });
  assert.equal(blocked.status, 404);

  controller.abort();
}

await main();
