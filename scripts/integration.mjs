// End-to-end check against a local worker: self-signed console requests, self-signed
// device requests, a sealed call over SSE, a sealed result, and proof that the relay
// never holds anything it could sign with or read.
import { spawn, spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { makeBrowser, now, signedHeaders } from "./browser.mjs";
import {
  addressOf,
  b64u,
  buildResult,
  newIdentity,
  openCall,
  signRequest,
  verifyCall,
} from "../shared/protocol.ts";

const PORT = 8787;
const base = `http://127.0.0.1:${PORT}`;

/** One process's registration: who it trusts and which run is behind the address. */
async function registerDevice(identity, trust = [], runId = "run-1") {
  const address = addressOf(identity);
  const path = `/v1/devices/${address}`;
  const response = await fetch(`${base}${path}`, {
    method: "PUT",
    headers: { ...signedHeaders(identity, "PUT", path), "content-type": "application/json" },
    body: JSON.stringify({
      hostname: "integration-host",
      platform: "linux-x86_64",
      version: "0.3.0",
      trust: trust.join(","),
      run_id: runId,
    }),
  });
  const text = await response.text();
  assert.equal(response.status, 200, text);
  return { address, ...JSON.parse(text) };
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
  spawnSync("npx", ["wrangler", "d1", "execute", "exe", "--local", "--command",
    "DROP TABLE IF EXISTS calls; DROP TABLE IF EXISTS devices; DROP TABLE IF EXISTS agents; DROP TABLE IF EXISTS request_nonces;"],
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
  assert.equal(typeof releases.configured, "boolean", "release resolution degrades instead of failing");
  assert.ok(Array.isArray(releases.assets));
  assert.match(releases.release_url, /github\.com\/zccz14\/eXe\/releases/);
  if (!releases.configured) assert.deepEqual(releases.assets, [], "no metadata means no assets");
  const unknownAsset = await fetch(`${base}/download/definitely-not-an-asset`);
  assert.equal(unknownAsset.status, 404, "only assets of the latest release are downloadable");

  // --- the browser is the identity: a signature, not a login ---------------
  const browser = makeBrowser();
  const me = await browser.request(base, "GET", "/api/me");
  assert.equal(me.address, browser.address, "the relay knows this browser by its address");
  assert.equal(me.custody, "browser");
  assert.equal(JSON.stringify(me).match(/secret|seed|token|jwt/i), null, "nothing to steal from the answer");

  assert.equal((await fetch(`${base}/api/devices`)).status, 401, "no signature, no console API");
  assert.equal((await fetch(`${base}/api/me`, { headers: { authorization: `Bearer anything` } })).status, 401, "a bearer token means nothing here");

  // The address in `x-exe-address` must be the address that signed.
  const impostor = makeBrowser();
  const stolen = signedHeaders(browser.identity, "GET", "/api/me");
  const impersonation = await fetch(`${base}/api/me`, {
    headers: { ...stolen, "x-exe-address": impostor.address },
  });
  assert.equal(impersonation.status, 401, "a header cannot name an address it cannot sign for");

  // A captured request can be replayed — and that is the point: every write it can
  // reach is keyed by a `call_id` the sender signed, so a replay re-states a row.
  const replayable = signedHeaders(browser.identity, "GET", "/api/me");
  assert.equal((await fetch(`${base}/api/me`, { headers: replayable })).status, 200);
  assert.equal((await fetch(`${base}/api/me`, { headers: replayable })).status, 200, "no nonce ledger: a replay is a repeat, not an attack");

  // --- a device is reached by address; the relay keeps no address book ------
  const device = newIdentity();
  const deviceAddress = addressOf(device);
  const unknown = await browser.request(base, "GET", `/api/devices/${deviceAddress}`);
  assert.equal(unknown.registered, false, "an address that never checked in is unknown, not an error");
  assert.equal(unknown.online, false);
  assert.equal(unknown.hostname, null, "the relay knows nothing about it yet");

  // --- the device self-registers: one signed request, single-use nonce -----
  const regPath = `/v1/devices/${deviceAddress}`;
  const regBody = JSON.stringify({
    hostname: "integration-host",
    platform: "linux-x86_64",
    version: "0.3.0",
    trust: browser.address,
    run_id: "run-1",
  });
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
  assert.equal(replayed.status, 200, "a repeated registration restates the same row");

  const stale = {
    method: "PUT",
    path: regPath,
    address: deviceAddress,
    timestamp: now() - 3600,
  };
  const staleAttempt = await fetch(`${base}${regPath}`, {
    method: "PUT",
    headers: {
      "content-type": "application/json",
      "x-exe-timestamp": String(stale.timestamp),
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

  const online = await browser.request(base, "GET", `/api/devices/${deviceAddress}`);
  assert.equal(online.online, true);
  assert.equal(online.hostname, "integration-host");
  assert.equal(online.run_id, "run-1", "the relay can tell which process is behind the address");
  assert.ok(online.run_started_at, "and when it started");

  // --- SSE with self-signed auth ------------------------------------------
  const streamPath = `/v1/devices/${deviceAddress}/stream`;
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
  const created = await browser.call(base, deviceAddress, "shell", { command: "uname -a" });
  const callId = created.call.call_id;
  const delivered = await nextEvent("call");
  assert.equal(delivered.call_id, callId);
  assert.ok(verifyCall(delivered), "the device can verify the issuer signature");
  const opened = openCall({ seed: device.seed, call: delivered });
  assert.equal(opened.name, "shell");
  assert.deepEqual(JSON.parse(opened.args), { command: "uname -a" });
  const wire = JSON.stringify(delivered);
  assert.equal(wire.includes("shell"), false, "the wire carries no tool name");
  assert.equal(wire.includes("uname -a"), false, "nor the arguments");

  // Handing a call to a socket writes nothing: until the device signs a receipt,
  // the relay has no idea whether the call arrived.
  const pushed = await browser.request(base, "GET", `/api/calls/${callId}`);
  assert.equal(pushed.call.status, "queued", "pushing is not delivery; only the receipt is");
  assert.equal(pushed.call.received_at, null);

  // The same signed envelope sent twice queues once — replay is a no-op by key.
  const replayDevice = (await registerDevice(newIdentity(), [browser.address])).address;
  const replayCall = browser.signCall(replayDevice, "shell", { command: "printf replay" });
  const postCall = () =>
    fetch(`${base}/api/devices/${replayDevice}/calls`, {
      method: "POST",
      headers: { ...signedHeaders(browser.identity, "POST", `/api/devices/${replayDevice}/calls`), "content-type": "application/json" },
      body: JSON.stringify(replayCall),
    });
  assert.equal((await postCall()).status, 200, "a registered device takes calls from the addresses it trusts");
  assert.equal((await postCall()).status, 409, "a replayed envelope collides on the call_id");
  const replayList = await browser.request(base, "GET", `/api/calls?device=${replayDevice}`);
  assert.equal(replayList.calls.length, 1, "the replay wrote nothing");

  // The relay now drops what the device would refuse anyway: an unrouted address
  // never even reaches the device's socket.
  const neverRegistered = addressOf(newIdentity());
  const unrouted = await fetch(`${base}/api/devices/${neverRegistered}/calls`, {
    method: "POST",
    headers: { ...signedHeaders(browser.identity, "POST", `/api/devices/${neverRegistered}/calls`), "content-type": "application/json" },
    body: JSON.stringify(browser.signCall(neverRegistered, "shell", { command: "printf void" })),
  });
  assert.equal(unrouted.status, 404, "no device has ever checked in at that address");

  // Editing the sealed body after signing is refused before it is queued.
  const forged = browser.signCall(deviceAddress, "shell", { command: "printf honest" });
  forged.sealed = b64u(new Uint8Array(160));
  const tampered = await fetch(`${base}/api/devices/${deviceAddress}/calls`, {
    method: "POST",
    headers: { ...signedHeaders(browser.identity, "POST", `/api/devices/${deviceAddress}/calls`), "content-type": "application/json" },
    body: JSON.stringify(forged),
  });
  assert.equal(tampered.status, 403);

  const unsignedCall = await fetch(`${base}/api/devices/${deviceAddress}/calls`, {
    method: "POST",
    headers: { ...signedHeaders(browser.identity, "POST", `/api/devices/${deviceAddress}/calls`), "content-type": "application/json" },
    body: JSON.stringify({ name: "shell", args: "{}" }),
  });
  assert.equal(unsignedCall.status, 400);

  // A stranger is stopped before the device: the relay holds a copy of the
  // device's trust list and drops what it knows will be refused, so a stranger's
  // 96 KiB envelope never costs the device a signature check.
  const stranger = makeBrowser();
  const strangerCall = stranger.signCall(deviceAddress, "shell", { command: "printf stranger" });
  assert.ok(verifyCall(strangerCall), "the stranger's envelope is well formed");
  const strangerQueued = await fetch(`${base}/api/devices/${deviceAddress}/calls`, {
    method: "POST",
    headers: { ...signedHeaders(stranger.identity, "POST", `/api/devices/${deviceAddress}/calls`), "content-type": "application/json" },
    body: JSON.stringify(strangerCall),
  });
  assert.equal(strangerQueued.status, 403, "the device does not trust this address");
  assert.equal(
    verifyCall({ ...strangerCall, issuer: browser.address }),
    false,
    "and nobody can sign in the browser's name",
  );

  // --- receipts and results ------------------------------------------------
  const receivedPath = `/v1/devices/${deviceAddress}/calls/${callId}/received`;
  const received = await fetch(`${base}${receivedPath}`, { method: "POST", headers: signedHeaders(device, "POST", receivedPath) });
  assert.equal(received.status, 204);
  const acknowledged = await browser.request(base, "GET", `/api/calls/${callId}`);
  assert.equal(acknowledged.call.status, "received", "the signed receipt is the delivery proof");
  assert.ok(acknowledged.call.received_at);

  const resultPath = `/v1/devices/${deviceAddress}/calls/${callId}/result`;
  const forgedResult = await fetch(`${base}${resultPath}`, {
    method: "POST",
    headers: { ...signedHeaders(device, "POST", resultPath), "content-type": "application/json" },
    body: JSON.stringify({ call_id: callId, device: deviceAddress, ok: true, issued_at: now(), sealed: b64u(new Uint8Array(140)), sig: b64u(new Uint8Array(64)) }),
  });
  assert.equal(forgedResult.status, 403, "the relay refuses a result the device did not sign");

  const plaintext = JSON.stringify({ ok: true, output: { tool: "shell", stdout: "SEALED-MARKER-42" } });
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
  const detail = await browser.request(base, "GET", `/api/calls/${callId}`);
  assert.equal(detail.call.status, "succeeded");
  assert.equal(detail.call.has_result, true);
  assert.ok(detail.result, "the envelope is returned verbatim");
  assert.equal(JSON.stringify(detail).includes("SEALED-MARKER-42"), false, "no plaintext in the API");
  assert.deepEqual(browser.open(detail.call, detail.result), JSON.parse(plaintext));
  assert.throws(() => stranger.open(detail.call, detail.result), "another browser cannot open the envelope");
  await assert.rejects(stranger.request(base, "GET", `/api/calls/${callId}`), /404/, "and cannot even fetch it");
  const strangerList = await stranger.request(base, "GET", `/api/calls?device=${deviceAddress}`);
  assert.equal(strangerList.calls.some((call) => call.call_id === callId), false, "a call belongs to the console that signed it");
  assert.equal(strangerList.calls.length, 0, "the stranger's call never existed");

  const stored = await browser.request(base, "GET", `/api/calls?device=${deviceAddress}`);
  assert.equal(stored.calls.length, 1);
  assert.equal(JSON.stringify(stored).includes("SEALED-MARKER-42"), false);

  // --- cancelling something that was never delivered -----------------------
  const idle = newIdentity();
  const idleAddress = (await registerDevice(idle, [browser.address])).address;
  const pending = await browser.call(base, idleAddress, "shell", { command: "sleep 5" });
  const cancelled = await browser.request(base, "POST", `/api/calls/${pending.call.call_id}/cancel`);
  assert.equal(cancelled, null);
  const cancelledView = await browser.request(base, "GET", `/api/calls/${pending.call.call_id}`);
  assert.equal(cancelledView.call.status, "cancelled");

  // --- a restart is an observable event, not a silent void ----------------
  // A call handed to a process that then dies has an unknown outcome. It is
  // marked lost and never re-delivered: a side effect that may already exist
  // must not be repeated behind the caller's back.
  const crashy = newIdentity();
  const crashyAddress = (await registerDevice(crashy, [browser.address], "run-A")).address;
  const envelope = browser.signCall(crashyAddress, "shell", { command: "printf half-done" });
  const queued = await fetch(`${base}/api/devices/${crashyAddress}/calls`, {
    method: "POST",
    headers: { ...signedHeaders(browser.identity, "POST", `/api/devices/${crashyAddress}/calls`), "content-type": "application/json" },
    body: JSON.stringify(envelope),
  }).then((response) => response.json());
  const receiptPath = `/v1/devices/${crashyAddress}/calls/${queued.call.call_id}/received`;
  assert.equal((await fetch(`${base}${receiptPath}`, { method: "POST", headers: signedHeaders(crashy, "POST", receiptPath) })).status, 204);
  assert.equal((await browser.request(base, "GET", `/api/calls/${queued.call.call_id}`)).call.status, "received");

  const restarted = await registerDevice(crashy, [browser.address], "run-B");
  assert.equal(restarted.abandoned, 1, "the new process reports what it inherited");
  const orphaned = await browser.request(base, "GET", `/api/calls/${queued.call.call_id}`);
  assert.equal(orphaned.call.status, "lost", "an interrupted call is not silently re-run");
  assert.ok(orphaned.call.settled_at);
  await assert.rejects(
    browser.request(base, "POST", `/api/calls/${queued.call.call_id}/cancel`),
    /409/,
    "a lost call is already over",
  );

  // Evidence outranks the relay's guess: a result signed after the fact settles it.
  const late = buildResult({ seed: crashy.seed, call: envelope, ok: true, plaintext: '{"ok":true}', issuedAt: now() });
  const lateResultPath = `/v1/devices/${crashyAddress}/calls/${queued.call.call_id}/result`;
  assert.equal(
    (await fetch(`${base}${lateResultPath}`, {
      method: "POST",
      headers: { ...signedHeaders(crashy, "POST", lateResultPath), "content-type": "application/json" },
      body: JSON.stringify(late),
    })).status,
    204,
  );
  assert.equal((await browser.request(base, "GET", `/api/calls/${queued.call.call_id}`)).call.status, "succeeded");

  controller.abort();
}

await main();
