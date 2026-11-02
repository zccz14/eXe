// Drives the real exe binary against a local worker with a non-custodial console.
import { spawn, spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startJwks } from "./jwks.mjs";
import { makeBrowser } from "./browser.mjs";

const PORT = 8787;
const base = `http://127.0.0.1:${PORT}`;
const jwks = startJwks(8788);
const configDir = mkdtempSync(join(tmpdir(), "exe-smoke-"));

const run = (command, args) => spawnSync(command, args, { stdio: "inherit" });
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  spawnSync("bash", ["-c", `printf 'AUTH_ISSUER=${jwks.url}\\nAUTH_AUDIENCE=exe.test\\n' > .dev.vars`]);
  run("npx", ["wrangler", "d1", "execute", "exe", "--local", "--file", "worker/src/schema.sql"]);
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
    const userId = randomUUID();
    const auth = { authorization: `Bearer ${jwks.mint(userId)}`, "content-type": "application/json" };
    const browser = makeBrowser();
    await browser.register(base, auth);

    agent = spawn("./agent/target/debug/exe", ["run"], {
      env: { ...process.env, EXE_BASE_URL: base, EXE_CONFIG_DIR: configDir, EXE_HOSTNAME: "smoke-host", RUST_LOG: "info" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    agent.stdout.on("data", (chunk) => (agentLog += chunk));
    agent.stderr.on("data", (chunk) => (agentLog += chunk));

    let code = null;
    for (let attempt = 0; attempt < 120 && !code; attempt += 1) {
      code = /[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}/.exec(agentLog)?.[0] ?? null;
      await wait(250);
    }
    assert.ok(code, `the agent printed a pairing code\n${agentLog}`);

    const view = await fetch(`${base}/api/pairings/${code}`, { headers: auth }).then((r) => r.json());
    assert.equal(view.status, "pending");
    console.log(`pairing code ${code}, sas ${view.sas}`);

    await browser.approve(base, auth, { ...view, account_id: userId }, "smoke");
    for (let attempt = 0; attempt < 80 && !agentLog.includes("SAS"); attempt += 1) await wait(250);
    assert.ok(agentLog.includes(view.sas), `the agent prints the same SAS\n${agentLog}`);
    for (let attempt = 0; attempt < 80 && !agentLog.includes("subscribed"); attempt += 1) await wait(250);

    const devices = await fetch(`${base}/api/devices`, { headers: auth }).then((r) => r.json());
    assert.equal(devices.devices.length, 1);
    const deviceId = devices.devices[0].id;
    assert.equal(devices.devices[0].sas, view.sas);

    const settle = async (callId) => {
      for (let attempt = 0; attempt < 60; attempt += 1) {
        const detail = await fetch(`${base}/api/calls/${callId}`, { headers: auth }).then((r) => r.json());
        if (detail.call.status === "succeeded" || detail.call.status === "failed") {
          return { ...detail, opened: detail.envelope ? browser.open(callId, deviceId, detail.envelope) : null };
        }
        await wait(500);
      }
      throw new Error(`call ${callId} did not settle`);
    };

    const echo = await browser.call(base, auth, deviceId, userId, "echo", { text: "hello from rust" });
    const echoResult = await settle(echo.call.id);
    assert.equal(echoResult.opened.output.text, "hello from rust");

    const sysinfo = await browser.call(base, auth, deviceId, userId, "sysinfo", {});
    const sysinfoResult = await settle(sysinfo.call.id);
    assert.equal(sysinfoResult.opened.output.tool, "sysinfo");

    // Default policy denies the shell even though the signature is valid.
    const bash = await browser.call(base, auth, deviceId, userId, "bash", { command: "id" });
    const bashResult = await settle(bash.call.id);
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
