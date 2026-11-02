// Drives the real exe binary against a local worker: the device generates its
// own key, a human adds the printed address in the console, and the console's
// address goes into the device's trust list. No pairing happens anywhere.
import { spawn, spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startJwks } from "./jwks.mjs";
import { makeBrowser } from "./browser.mjs";
import { addressOf, decodeSecret } from "../shared/protocol.ts";

const PORT = 8787;
const base = `http://127.0.0.1:${PORT}`;
const jwks = startJwks(8788);
const configDir = mkdtempSync(join(tmpdir(), "exe-smoke-"));
const agentEnv = () => ({ ...process.env, EXE_CONFIG_DIR: configDir, EXE_CLOUD: base, EXE_HOSTNAME: "smoke-host", RUST_LOG: "info" });

const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  spawnSync("bash", ["-c", `printf 'AUTH_ISSUER=${jwks.url}\\nAUTH_AUDIENCE=exe.test\\n' > .dev.vars`]);
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

  let agent;
  let agentLog = "";
  const cleanup = () => {
    agent?.kill("SIGKILL");
    try {
      process.kill(-dev.pid, "SIGKILL");
    } catch {
      dev.kill("SIGKILL");
    }
    void jwks.close();
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
    const userId = randomUUID();
    const auth = { authorization: `Bearer ${jwks.mint(userId)}`, "content-type": "application/json" };
    const browser = makeBrowser();
    await browser.register(base, auth);
    await browser.addDevice(base, auth, deviceAddress, "smoke");
    const trust = spawnSync("./agent/target/debug/exe", ["trust", browser.address], { env: agentEnv(), encoding: "utf8" });
    assert.equal(trust.status, 0, trust.stderr);

    agent = spawn("./agent/target/debug/exe", ["run"], { env: agentEnv(), stdio: ["ignore", "pipe", "pipe"] });
    agent.stdout.on("data", (chunk) => (agentLog += chunk));
    agent.stderr.on("data", (chunk) => (agentLog += chunk));

    for (let attempt = 0; attempt < 120 && !agentLog.includes("subscribed"); attempt += 1) await wait(250);
    assert.ok(agentLog.includes("subscribed"), `the agent subscribed to the stream\n${agentLog}`);
    assert.ok(agentLog.includes(deviceAddress), "the agent logs its own address");

    const devices = await fetch(`${base}/api/devices`, { headers: auth }).then((r) => r.json());
    assert.equal(devices.devices.length, 1);
    assert.equal(devices.devices[0].address, deviceAddress);
    for (let attempt = 0; attempt < 40 && !devices.devices[0].online; attempt += 1) await wait(250);

    const settle = async (callId) => {
      for (let attempt = 0; attempt < 60; attempt += 1) {
        const detail = await fetch(`${base}/api/calls/${callId}`, { headers: auth }).then((r) => r.json());
        if (detail.call.status === "succeeded" || detail.call.status === "failed") {
          return { ...detail, opened: detail.result ? browser.open(detail.call, detail.result) : null };
        }
        await wait(500);
      }
      throw new Error(`call ${callId} did not settle`);
    };

    const echo = await browser.call(base, auth, deviceAddress, "echo", { text: "hello from rust" });
    const echoResult = await settle(echo.call.call_id);
    assert.equal(echoResult.opened.output.text, "hello from rust");

    const sysinfo = await browser.call(base, auth, deviceAddress, "sysinfo", {});
    const sysinfoResult = await settle(sysinfo.call.call_id);
    assert.equal(sysinfoResult.opened.output.tool, "sysinfo");
    assert.equal(sysinfoResult.opened.output.hostname, "smoke-host");

    // Default policy denies the shell even though the signature is valid.
    const bash = await browser.call(base, auth, deviceAddress, "bash", { command: "id" });
    const bashResult = await settle(bash.call.call_id);
    assert.equal(bashResult.opened.ok, false);
    assert.equal(bashResult.opened.code, "policy_denied");
    assert.equal(bashResult.call.status, "failed", "the signed outcome, not a decryption, sets the status");
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
