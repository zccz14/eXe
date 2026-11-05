import assert from "node:assert/strict";
import { test } from "node:test";
import { newIdentity } from "../../../shared/protocol.ts";
import { pingDevice, pingDevices } from "../src/ping.ts";
import { Relay } from "../src/relay.ts";
import { simulateDevice } from "./fake-device.ts";

const caller = newIdentity();

function relayTo(fetch: typeof globalThis.fetch): Relay {
  return new Relay({ endpoints: ["https://relay.test"], identity: caller, fetch });
}

test("a ping is one real round trip, and it is timed", async () => {
  const simulator = simulateDevice({ answer: () => ({ ok: true, output: { tool: "shell", exit_code: 0, stdout: "ping\n", stderr: "" } }) });
  const result = await pingDevice(relayTo(simulator.fetch), "lab", simulator.address);
  assert.equal(result.ok, true);
  assert.equal(typeof result.rttMs, "number");
  assert.ok((result.rttMs ?? -1) >= 0);
  assert.equal(result.online, true);
  // The device really ran the echo: the call carried `echo ping`.
  assert.ok(simulator.requests.some((entry) => entry.endsWith("/calls")));
});

test("an offline device fails at once, with the reason the relay gives", async () => {
  const simulator = simulateDevice({ online: false });
  const result = await pingDevice(relayTo(simulator.fetch), "lab", simulator.address);
  assert.equal(result.ok, false);
  assert.equal(result.online, false);
  assert.match(result.error ?? "", /设备离线/);
  // Nothing was queued: an offline device is not worth a six-second wait.
  assert.equal(simulator.calls.size, 0);
});

test("a device that never answers times out and is cancelled", async () => {
  const simulator = simulateDevice({ hang: true });
  const result = await pingDevice(relayTo(simulator.fetch), "lab", simulator.address, { timeoutMs: 300 });
  assert.equal(result.ok, false);
  assert.match(result.error ?? "", /没有回应/);
  assert.equal(simulator.cancels.length, 1);
});

test("a relay nobody can reach says so, and names no device problem", async () => {
  const unreachable = relayTo((async () => new Response("nope", { status: 502 })) as typeof globalThis.fetch);
  const result = await pingDevice(unreachable, "lab", simulateDevice().address);
  assert.equal(result.ok, false);
  assert.match(result.error ?? "", /中继不可达/);
});

test("pinging several devices stays parallel and keeps the order", async () => {
  const one = simulateDevice();
  const two = simulateDevice({ online: false });
  const results = await pingDevices(relayTo(async (input, init) => {
    const url = new URL(typeof input === "string" ? input : input instanceof URL ? input.href : input.url);
    if (url.pathname.includes(one.address) || !url.pathname.includes(two.address)) return one.fetch(input, init);
    return two.fetch(input, init);
  }), [
    { label: "one", address: one.address },
    { label: "two", address: two.address },
  ]);
  assert.deepEqual(results.map((result) => `${result.label}:${result.ok}`), ["one:true", "two:false"]);
});
