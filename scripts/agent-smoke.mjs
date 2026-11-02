// Drives the real exe binary against a local worker: the device generates its
// own key, a human adds the printed address in the console, and the console's
// address goes into the device's trust list. No pairing happens anywhere, and
// the console has no login: it signs with the key it holds.
import { spawn, spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { makeBrowser } from "./browser.mjs";
import { addressOf, decodeSecret } from "../shared/protocol.ts";

const PORT = 8787;
const base = `http://127.0.0.1:${PORT}`;
const configDir = mkdtempSync(join(tmpdir(), "exe-smoke-"));
const agentEnv = () => ({ ...process.env, EXE_CONFIG_DIR: configDir, EXE_CLOUD: base, EXE_HOSTNAME: "smoke-host", RUST_LOG: "info" });

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

  let agent;
  let agentLog = "";
  const cleanup = () => {
    agent?.kill("SIGKILL");
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
    const init = spawnSync("./agent/target/debug/exe", ["init"], { env: agentEnv(), encoding: "utf8" });
    assert.equal(init.status, 0, init.stderr);
    const secret = /^secret\s*=\s*"([^"]+)"/m.exec(readFileSync(join(configDir, "config.toml"), "utf8"))?.[1];
    assert.ok(secret, "exe init wrote a secret");
    const deviceAddress = addressOf(decodeSecret(secret));
    assert.ok(init.stdout.includes(deviceAddress), "exe init prints the address");

    // The console adds that address and hands its own address back to the device.
    const browser = makeBrowser();
    await browser.addDevice(base, deviceAddress, "smoke");
    const trust = spawnSync("./agent/target/debug/exe", ["trust", browser.address], { env: agentEnv(), encoding: "utf8" });
    assert.equal(trust.status, 0, trust.stderr);

    agent = spawn("./agent/target/debug/exe", ["run"], { env: agentEnv(), stdio: ["ignore", "pipe", "pipe"] });
    agent.stdout.on("data", (chunk) => (agentLog += chunk));
    agent.stderr.on("data", (chunk) => (agentLog += chunk));

    for (let attempt = 0; attempt < 120 && !agentLog.includes("subscribed"); attempt += 1) await wait(250);
    assert.ok(agentLog.includes("subscribed"), `the agent subscribed to the stream\n${agentLog}`);
    assert.ok(agentLog.includes(deviceAddress), "the agent logs its own address");

    const devices = await browser.request(base, "GET", "/api/devices");
    assert.equal(devices.devices.length, 1);
    assert.equal(devices.devices[0].address, deviceAddress);
    for (let attempt = 0; attempt < 40 && !devices.devices[0]?.online; attempt += 1) await wait(250);
    // The relay learns hostname/platform/version from the device's own signed
    // registration, so no `sysinfo` verb is needed to display them.
    const listed = await browser.request(base, "GET", "/api/devices");
    assert.equal(listed.devices[0].hostname, "smoke-host");
    assert.equal(listed.devices[0].online, true);

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

    // The retired demo verbs are gone from the agent, not just from the console.
    const retired = await browser.call(base, deviceAddress, "sysinfo", {});
    const retiredResult = await settle(retired.call.call_id);
    assert.equal(retiredResult.opened.ok, false);
    assert.equal(retiredResult.opened.code, "unknown_tool");
    assert.equal(retiredResult.call.status, "failed", "an unknown verb is a signed failure, not silence");
    console.log("agent smoke: ok");
  } catch (error) {
    console.error("FAILED:", error instanceof Error ? error.message : error);
    console.error(agentLog.slice(-2000));
    console.error(devLog.slice(-1500));
    cleanup();
    process.exit(1);
  }
  cleanup();
  process.exit(0);
}

await main();
