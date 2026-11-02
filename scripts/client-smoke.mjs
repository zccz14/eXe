// Drives the real exe binary against a local worker: the device generates its
// own key, a human adds the printed address in the console, and the console's
// address goes into the device's trust list. No pairing happens anywhere, and
// the console has no login: it signs with the key it holds.
import { spawn, spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeBrowser, signedHeaders } from "./browser.mjs";
import { addressOf, decodeSecret, openAttachment } from "../shared/protocol.ts";

const PORT = 8787;
const base = `http://127.0.0.1:${PORT}`;
const configDir = mkdtempSync(join(tmpdir(), "exe-smoke-"));
/** The first endpoint is a closed port: the client must probe and pick the second. */
const DEAD_ENDPOINT = "http://127.0.0.1:1";
const clientEnv = () => ({ ...process.env, EXE_CONFIG_DIR: configDir, EXE_CLOUD: `${DEAD_ENDPOINT},${base}`, RUST_LOG: "info" });

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

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

  let client;
  let clientLog = "";
  const cleanup = () => {
    client?.kill("SIGKILL");
    try {
      process.kill(-dev.pid, "SIGKILL");
    } catch {
      dev.kill("SIGKILL");
    }
    rmSync(configDir, { recursive: true, force: true });
  };
  try {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      try {
        if ((await fetch(`${base}/api/health`)).ok) break;
      } catch {
        /* starting */
      }
      await wait(500);
    }

    // The device makes its own key; the human reads the address off the device.
    const init = spawnSync("./clients/target/debug/exe", ["init"], { env: clientEnv(), encoding: "utf8" });
    assert.equal(init.status, 0, init.stderr);
    const secret = /^secret\s*=\s*"([^"]+)"/m.exec(readFileSync(join(configDir, "config.toml"), "utf8"))?.[1];
    assert.ok(secret, "exe init wrote a secret");
    const deviceAddress = addressOf(decodeSecret(secret));
    assert.ok(init.stdout.includes(deviceAddress), "exe init prints the address");

    // The console types that address into its own browser-side book and hands its
    // own address back to the device: trust is built in two places, both local.
    const browser = makeBrowser();
    const trust = spawnSync("./clients/target/debug/exe", ["trust", browser.address], { env: clientEnv(), encoding: "utf8" });
    assert.equal(trust.status, 0, trust.stderr);

    client = spawn("./clients/target/debug/exe", ["run"], { env: clientEnv(), stdio: ["ignore", "pipe", "pipe"] });
    client.stdout.on("data", (chunk) => (clientLog += chunk));
    client.stderr.on("data", (chunk) => (clientLog += chunk));

    for (let attempt = 0; attempt < 120 && !clientLog.includes("subscribed"); attempt += 1) await wait(250);
    assert.ok(clientLog.includes("subscribed"), `the client subscribed to the stream\n${clientLog}`);
    const chosen = /chose the fastest relay endpoint[^\n]*?(https?:\/\/[^"\s]+)/.exec(clientLog);
    assert.ok(chosen, `the client probes before it connects\n${clientLog}`);
    assert.equal(chosen[1], base, "the reachable endpoint wins over the dead one");
    assert.ok(clientLog.includes(deviceAddress), "the client logs its own address");

    const seen = () => browser.request(base, "GET", `/api/devices/${deviceAddress}`);
    for (let attempt = 0; attempt < 40 && !(await seen()).online; attempt += 1) await wait(250);
    // The relay learns platform/version from the device's own signed
    // registration, so no `sysinfo` verb is needed to display them. It learns
    // nothing about the machine itself — there is no hostname on the wire.
    const listed = await seen();
    assert.equal(listed.registered, true);
    assert.match(listed.platform, /^(macos|linux|windows)-[a-z0-9_]+$/, "the relay learns the platform from the device itself");
    assert.equal(listed.online, true);

    const settle = async (callId) => {
      for (let attempt = 0; attempt < 60; attempt += 1) {
        const detail = await browser.request(base, "GET", `/api/calls/${callId}`);
        if (detail.call.status === "succeeded" || detail.call.status === "failed") {
          return { ...detail, opened: detail.result ? browser.open(detail.call, detail.result) : null };
        }
        await wait(500);
      }
      throw new Error(`call ${callId} did not settle`);
    };

    // There is no local permission list and no tool registry: `shell` is the
    // only verb, and a trusted signature runs it.
    const shell = await browser.call(base, deviceAddress, "shell", { command: "printf smoke" });
    const shellResult = await settle(shell.call.call_id);
    assert.equal(shellResult.opened.ok, true);
    assert.equal(shellResult.opened.output.tool, "shell");
    assert.equal(shellResult.opened.output.stdout, "smoke");
    assert.equal(shellResult.call.status, "succeeded", "the signed outcome sets the status");

    const cwd = await browser.call(base, deviceAddress, "shell", { command: "pwd", cwd: "." });
    const cwdResult = await settle(cwd.call.call_id);
    assert.equal(cwdResult.opened.ok, true);
    assert.ok(cwdResult.opened.output.stdout.trim().length > 0, "cwd is honoured");

    // Anything past the inline budget comes back as a preview plus a pointer.
    const medium = await browser.call(base, deviceAddress, "shell", { command: "head -c 100000 /dev/zero | tr '\\0' 'm'" });
    const mediumDetail = await settle(medium.call.call_id);
    assert.equal(mediumDetail.opened.output.truncated, true, "100 KiB is not inline");
    assert.equal(mediumDetail.opened.output.stdout.length, 32 * 1024, "the preview is 32 KiB");
    assert.equal(mediumDetail.opened.output.stdout_bytes, 100_000, "and says how much there was");
    assert.ok(mediumDetail.opened.blob.bytes > 100_000, "the rest is attached");

    // A result too big for one row comes back as an attachment: the device seals
    // it separately, the relay stores bytes it cannot read, the console opens it.
    const heavy = await browser.call(base, deviceAddress, "shell", { command: "head -c 2000000 /dev/zero | tr '\\0' 'q'" });
    const heavyDetail = await settle(heavy.call.call_id);
    assert.equal(heavyDetail.opened.ok, true);
    assert.equal(heavyDetail.opened.output.truncated, true, "the row carries a summary, not two megabytes");
    assert.ok(heavyDetail.opened.blob.bytes > 2_000_000, "the attachment is announced");
    const blobPath = `/api/calls/${heavy.call.call_id}/blob`;
    const blobResponse = await fetch(`${base}${blobPath}`, { headers: signedHeaders(browser.identity, "GET", blobPath) });
    assert.equal(blobResponse.status, 200, "the console can fetch the attachment");
    const sealedBlob = new Uint8Array(await blobResponse.arrayBuffer());
    const full = JSON.parse(
      openAttachment({ seed: browser.identity.seed, call: heavyDetail.call, result: heavyDetail.result, sealed: sealedBlob }),
    );
    assert.equal(full.output.stdout.length, 2_000_000, "two megabytes survive the device's own seal");

    // The retired demo verbs are gone from the client, not just from the console.
    const retired = await browser.call(base, deviceAddress, "sysinfo", {});
    const retiredResult = await settle(retired.call.call_id);
    assert.equal(retiredResult.opened.ok, false);
    assert.equal(retiredResult.opened.code, "unknown_tool");
    assert.equal(retiredResult.call.status, "failed", "an unknown verb is a signed failure, not silence");
    console.log("client smoke: ok");
  } catch (error) {
    console.error("FAILED:", error instanceof Error ? error.message : error);
    console.error(clientLog.slice(-2000));
    console.error(devLog.slice(-1500));
    cleanup();
    process.exit(1);
  }
  cleanup();
  process.exit(0);
}

await main();
