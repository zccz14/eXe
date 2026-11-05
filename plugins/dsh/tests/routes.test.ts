import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { addressOf, encodeSecret, newIdentity } from "../../../shared/protocol.ts";
import { registerExeRoutes, type WebRoute, type WebServerLike } from "../src/routes.ts";
import { createStateStore } from "../src/state.ts";

const caller = newIdentity();
const device = newIdentity();

interface Served {
  base: string;
  server: Server;
}

async function serve(options: { caller?: boolean } = {}): Promise<Served> {
  const dir = mkdtempSync(join(tmpdir(), "dsh-exe-routes-"));
  if (options.caller !== false) {
    writeFileSync(
      join(dir, "mcp.toml"),
      `secret = "${encodeSecret(caller)}"\n\n[devices]\nlab = "${addressOf(device)}"\n`,
    );
  }
  const env = { EXE_CONFIG_DIR: dir } as NodeJS.ProcessEnv;
  const store = createStateStore({}, env);
  let route: WebRoute | undefined;
  const webServer: WebServerLike = {
    register(candidate) {
      route = candidate;
      return () => {
        route = undefined;
      };
    },
  };
  const dispose = registerExeRoutes(webServer, store);
  assert.ok(route !== undefined, "the routes were not registered");
  const registered = route;
  const server = createServer((req, res) => {
    void registered.handler(req, res);
  });
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address() as AddressInfo;
  // The disposer must remove exactly this registration.
  const close = (): void => {
    dispose();
    server.close();
  };
  test.after?.(close);
  return { base: `http://127.0.0.1:${port}`, server };
}

test("the page reads one state document over GET", async (t) => {
  const served = await serve();
  t.after(() => served.server.close());
  const response = await fetch(`${served.base}/exe/api/state`);
  assert.equal(response.status, 200);
  assert.equal(response.headers.get("cache-control"), "no-store");
  const state = (await response.json()) as { caller: { address: string }; devices: Array<{ label: string }> };
  assert.equal(state.caller.address, addressOf(caller));
  assert.deepEqual(
    state.devices.map((row) => row.label),
    ["lab"],
  );
});

test("an edit returns the state it produced", async (t) => {
  const served = await serve();
  t.after(() => served.server.close());
  const added = newIdentity();
  const response = await fetch(`${served.base}/exe/api/edit`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ op: "device.set", label: "phone", address: addressOf(added) }),
  });
  assert.equal(response.status, 200);
  const state = (await response.json()) as { devices: Array<{ label: string; address: string }> };
  assert.deepEqual(
    state.devices.map((row) => `${row.label}=${row.address}`),
    ["lab=" + addressOf(device), `phone=${addressOf(added)}`],
  );
});

test("a refusal comes back as one sentence, not a stack", async (t) => {
  const served = await serve();
  t.after(() => served.server.close());
  const response = await fetch(`${served.base}/exe/api/edit`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ op: "device.set", label: "x", address: "nope" }),
  });
  assert.equal(response.status, 400);
  const body = (await response.json()) as { error: string };
  assert.match(body.error, /not an eXe address/);
});

test("a write from another origin is refused, and a non-JSON body with it", async (t) => {
  const served = await serve();
  t.after(() => served.server.close());
  const crossOrigin = await fetch(`${served.base}/exe/api/edit`, {
    method: "POST",
    headers: { "content-type": "application/json", origin: "https://evil.example" },
    body: JSON.stringify({ op: "trust.add", address: addressOf(newIdentity()) }),
  });
  assert.equal(crossOrigin.status, 403);

  const plain = await fetch(`${served.base}/exe/api/edit`, {
    method: "POST",
    headers: { "content-type": "text/plain" },
    body: JSON.stringify({ op: "trust.add", address: addressOf(newIdentity()) }),
  });
  assert.equal(plain.status, 415);
});

test("the method and the path are part of the contract", async (t) => {
  const served = await serve();
  t.after(() => served.server.close());
  const wrongMethod = await fetch(`${served.base}/exe/api/state`, { method: "POST" });
  assert.equal(wrongMethod.status, 405);
  const unknown = await fetch(`${served.base}/exe/api/nope`);
  assert.equal(unknown.status, 404);
});

test("it works without a key, and says so in the state", async (t) => {
  const served = await serve({ caller: false });
  t.after(() => served.server.close());
  const response = await fetch(`${served.base}/exe/api/state`);
  assert.equal(response.status, 200);
  const state = (await response.json()) as { caller: { address?: string; error?: string } };
  assert.equal(state.caller.address, undefined);
  assert.match(state.caller.error ?? "", /exe mcp init/);
});
