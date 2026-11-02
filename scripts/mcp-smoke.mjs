// Drives `exe mcp` the way an agent harness does: spawn the process, speak MCP
// over stdio, and call tools that run on a real device through a local relay.
// Nothing here is mocked — the device is the real binary, and the caller key is
// the one `exe mcp init` writes.
import { spawn, spawnSync } from "node:child_process";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { addressOf, decodeSecret } from "../shared/protocol.ts";

const PORT = 8788;
const base = `http://127.0.0.1:${PORT}`;
const deviceDir = mkdtempSync(join(tmpdir(), "exe-mcp-device-"));
const callerDir = mkdtempSync(join(tmpdir(), "exe-mcp-caller-"));
const BIN = "./clients/target/debug/exe";
const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
const deviceEnv = () => ({ ...process.env, EXE_CONFIG_DIR: deviceDir, EXE_CLOUD: base, RUST_LOG: "info" });
const callerEnv = () => ({ ...process.env, EXE_CONFIG_DIR: callerDir, RUST_LOG: "info" });

async function main() {
  spawnSync("npx", ["wrangler", "d1", "execute", "exe", "--local", "--command",
    "DROP TABLE IF EXISTS calls; DROP TABLE IF EXISTS devices; DROP TABLE IF EXISTS agents; DROP TABLE IF EXISTS request_nonces;"], { stdio: "ignore" });
  spawnSync("npx", ["wrangler", "d1", "execute", "exe", "--local", "--file", "worker/src/schema.sql"], { stdio: "ignore" });
  const dev = spawn("npx", ["wrangler", "dev", "--port", String(PORT), "--ip", "127.0.0.1"], {
    stdio: ["ignore", "pipe", "pipe"], env: { ...process.env, WRANGLER_SEND_METRICS: "false", CI: "1" }, detached: true,
  });
  let device;
  let mcp;
  const cleanup = () => {
    mcp?.kill("SIGKILL");
    device?.kill("SIGKILL");
    try { process.kill(-dev.pid, "SIGKILL"); } catch { dev.kill("SIGKILL"); }
    rmSync(deviceDir, { recursive: true, force: true });
    rmSync(callerDir, { recursive: true, force: true });
  };
  try {
    for (let attempt = 0; attempt < 120; attempt += 1) {
      try { if ((await fetch(`${base}/api/health`)).ok) break; } catch { /* starting */ }
      await wait(500);
    }

    // The caller makes its own key, exactly as a user would on their laptop.
    const init = spawnSync(BIN, ["mcp", "init"], { env: callerEnv(), encoding: "utf8" });
    assert.equal(init.status, 0, init.stderr);
    const callerToml = join(callerDir, "mcp.toml");
    const secret = /^secret\s*=\s*"([^"]+)"/m.exec(readFileSync(callerToml, "utf8"))?.[1];
    assert.ok(secret, "exe mcp init wrote a caller key");
    const caller = addressOf(decodeSecret(secret));
    assert.ok(init.stdout.includes(caller), "exe mcp init prints the caller address");

    // The device makes its own key and is told to trust that caller.
    const deviceInit = spawnSync(BIN, ["init"], { env: deviceEnv(), encoding: "utf8" });
    assert.equal(deviceInit.status, 0, deviceInit.stderr);
    const deviceSecret = /^secret\s*=\s*"([^"]+)"/m.exec(readFileSync(join(deviceDir, "config.toml"), "utf8"))?.[1];
    const deviceAddress = addressOf(decodeSecret(deviceSecret));
    const trust = spawnSync(BIN, ["trust", caller], { env: deviceEnv(), encoding: "utf8" });
    assert.equal(trust.status, 0, trust.stderr);
    assert.ok(trust.stdout.includes(caller), "exe trust records the caller");

    device = spawn(BIN, ["run"], { env: deviceEnv(), stdio: ["ignore", "pipe", "pipe"] });
    let deviceLog = "";
    device.stdout.on("data", (chunk) => (deviceLog += chunk));
    device.stderr.on("data", (chunk) => (deviceLog += chunk));
    for (let attempt = 0; attempt < 120 && !deviceLog.includes("subscribed"); attempt += 1) await wait(250);
    assert.ok(deviceLog.includes("subscribed"), `the device subscribed\n${deviceLog}`);

    // The caller's device list is its own — the relay has no address book.
    writeFileSync(callerToml, [
      `endpoints = ["${base}"]`,
      `secret = "${secret}"`,
      'tool_prefix = "exe"',
      "[devices]",
      `box = "${deviceAddress}"`,
      "",
    ].join("\n"));

    mcp = spawn(BIN, ["mcp"], { env: callerEnv(), stdio: ["pipe", "pipe", "pipe"] });
    let mcpLog = "";
    mcp.stderr.on("data", (chunk) => (mcpLog += chunk));

    const pending = new Map();
    let buffer = "";
    mcp.stdout.on("data", (chunk) => {
      buffer += chunk;
      let index;
      while ((index = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, index).trim();
        buffer = buffer.slice(index + 1);
        if (!line) continue;
        const message = JSON.parse(line); // anything but JSON on stdout is a bug
        if (message.id !== undefined && pending.has(message.id)) {
          pending.get(message.id)(message);
          pending.delete(message.id);
        }
      }
    });
    let nextId = 1;
    const rpc = (method, params) => new Promise((resolve, reject) => {
      const id = nextId++;
      pending.set(id, (message) => (message.error ? reject(new Error(JSON.stringify(message.error))) : resolve(message.result)));
      mcp.stdin.write(`${JSON.stringify({ jsonrpc: "2.0", id, method, params })}\n`);
    });

    const hello = await rpc("initialize", { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "smoke", version: "0" } });
    assert.equal(hello.protocolVersion, "2025-06-18");
    assert.equal(hello.serverInfo.name, "exe");
    assert.ok(hello.capabilities.tools, "tools are advertised");

    const listed = await rpc("tools/list", {});
    assert.deepEqual(listed.tools.map((tool) => tool.name), ["exe_devices", "exe_bash", "exe_image"]);
    for (const tool of listed.tools) assert.equal(tool.inputSchema.type, "object");

    const devices = await rpc("tools/call", { name: "exe_devices", arguments: {} });
    const roster = devices.structuredContent.devices;
    assert.equal(roster.length, 1);
    assert.equal(roster[0].device, "box");
    assert.equal(roster[0].address, deviceAddress);
    assert.equal(roster[0].registered, true);
    assert.equal(roster[0].online, true, "the relay says the device is online");

    const ran = await rpc("tools/call", { name: "exe_bash", arguments: { device: "box", command: "printf mcp-smoke" } });
    assert.notEqual(ran.isError, true, JSON.stringify(ran));
    assert.equal(ran.structuredContent.exit_code, 0);
    assert.equal(ran.structuredContent.stdout, "mcp-smoke");
    assert.ok(ran.content[0].text.includes("mcp-smoke"));

    // Time is an argument now: the caller asks for two seconds and gets them.
    const slow = await rpc("tools/call", { name: "exe_bash", arguments: { device: "box", command: "sleep 5", timeout_seconds: 2 } });
    assert.equal(slow.isError, true);
    assert.ok(slow.content[0].text.includes("timeout"), slow.content[0].text);

    // A picture comes back as a picture, which is the whole point of `exe_image`.
    const png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";
    await rpc("tools/call", { name: "exe_bash", arguments: { device: "box", command: `mkdir -p /tmp/exe-smoke && printf '%s' '${png}' | base64 -d > /tmp/exe-smoke/dot.png` } });
    const image = await rpc("tools/call", { name: "exe_image", arguments: { device: "box", path: "/tmp/exe-smoke/dot.png" } });
    assert.notEqual(image.isError, true, JSON.stringify(image));
    assert.equal(image.content[0].type, "image");
    assert.equal(image.content[0].mimeType, "image/png");
    assert.equal(image.content[0].data, png, "the bytes survive the round trip");

    // An unknown label is a plain, actionable failure — not a crash.
    const missing = await rpc("tools/call", { name: "exe_bash", arguments: { device: "nope", command: "true" } });
    assert.equal(missing.isError, true);
    assert.ok(missing.content[0].text.includes("unknown device"), missing.content[0].text);

    console.log("mcp smoke: ok");
  } finally {
    cleanup();
  }
}

main().then(() => process.exit(0)).catch((error) => {
  console.error(error);
  process.exit(1);
});
