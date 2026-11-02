// Drives the real exe binary against a local worker: pair, run, execute, report.
import { spawn, spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { startJwks } from "./jwks.mjs";
import { b64u } from "../worker/src/crypto.ts";

const PORT = 8787;
const base = `http://127.0.0.1:${PORT}`;
const jwks = startJwks(8788);
const configDir = mkdtempSync(join(tmpdir(), "exe-smoke-"));

const run = (command, args) => spawnSync(command, args, { stdio: "inherit" });
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function main() {
  spawnSync("bash", ["-c", `printf 'AUTH_ISSUER=${jwks.url}\\nAUTH_AUDIENCE=exe.test\\nEXE_KEK=${b64u(new Uint8Array(32).fill(3))}\\n' > .dev.vars`]);
  run("npx", ["wrangler", "d1", "execute", "exe", "--local", "--file", "worker/src/schema.sql"]);
  const dev = spawn("npx", ["wrangler", "dev", "--port", String(PORT), "--ip", "127.0.0.1"], {
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, WRANGLER_SEND_METRICS: "false" },
  });
  let devLog = "";
  dev.stdout.on("data", (chunk) => (devLog += chunk));
  dev.stderr.on("data", (chunk) => (devLog += chunk));

  let agent;
  let agentLog = "";
  const cleanup = () => {
    agent?.kill("SIGKILL");
    dev.kill("SIGTERM");
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
    const token = jwks.mint(randomUUID());
    const auth = { authorization: `Bearer ${token}`, "content-type": "application/json" };
    await fetch(`${base}/api/me`, { headers: auth });

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

    await fetch(`${base}/api/pairings/${code}`, { method: "POST", headers: auth, body: JSON.stringify({ label: "smoke" }) });
    for (let attempt = 0; attempt < 80 && !agentLog.includes("SAS"); attempt += 1) await wait(250);
    assert.ok(agentLog.includes(view.sas), `the agent prints the same SAS\n${agentLog}`);
    for (let attempt = 0; attempt < 80 && !agentLog.includes("subscribed"); attempt += 1) await wait(250);

    const devices = await fetch(`${base}/api/devices`, { headers: auth }).then((r) => r.json());
    assert.equal(devices.devices.length, 1);
    const deviceId = devices.devices[0].id;
    assert.equal(devices.devices[0].sas, view.sas);

    const send = async (name, args) =>
      (await fetch(`${base}/api/devices/${deviceId}/calls`, { method: "POST", headers: auth, body: JSON.stringify({ name, args }) }).then((r) => r.json())).call;

    const echo = await send("echo", { text: "hello from rust" });
    let detail = null;
    for (let attempt = 0; attempt < 40; attempt += 1) {
      detail = await fetch(`${base}/api/calls/${echo.id}`, { headers: auth }).then((r) => r.json());
      if (detail.call.status === "succeeded" || detail.call.status === "failed") break;
      await wait(500);
    }
    assert.equal(detail.call.status, "succeeded", JSON.stringify(detail));
    assert.equal(detail.result.output.text, "hello from rust");

    const sysinfo = await send("sysinfo", {});
    for (let attempt = 0; attempt < 40; attempt += 1) {
      detail = await fetch(`${base}/api/calls/${sysinfo.id}`, { headers: auth }).then((r) => r.json());
      if (detail.call.status === "succeeded" || detail.call.status === "failed") break;
      await wait(500);
    }
    assert.equal(detail.result.output.tool, "sysinfo");

    // Default policy denies the shell even though the signature is valid.
    const bash = await send("bash", { command: "id" });
    for (let attempt = 0; attempt < 40; attempt += 1) {
      detail = await fetch(`${base}/api/calls/${bash.id}`, { headers: auth }).then((r) => r.json());
      if (detail.call.status === "succeeded" || detail.call.status === "failed") break;
      await wait(500);
    }
    assert.equal(detail.result.ok, false);
    assert.equal(detail.result.code, "policy_denied");
    console.log("agent smoke: ok");
  } catch (error) {
    console.error(agentLog?.slice(-3000));
    console.error(devLog.slice(-2000));
    cleanup();
    throw error;
  }
  cleanup();
}

await main();
