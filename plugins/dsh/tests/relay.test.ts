import assert from "node:assert/strict";
import { test } from "node:test";
import { addressOf, newIdentity } from "../../../shared/protocol.ts";
import { Relay } from "../src/relay.ts";
import { simulateDevice } from "./fake-device.ts";

const caller = newIdentity();

function relayTo(simulator: { fetch: typeof globalThis.fetch }): Relay {
  return new Relay({ endpoints: ["https://relay.test"], identity: caller, fetch: simulator.fetch });
}

function call(simulator: { address: string }, overrides: Partial<Parameters<Relay["call"]>[0]> = {}) {
  return {
    device: simulator.address,
    name: "shell",
    args: { command: "printf hi" },
    ttlSeconds: 120,
    signal: new AbortController().signal,
    ...overrides,
  };
}

test("a shell answer comes back opened, and the row is taken away after", async () => {
  const simulator = simulateDevice({
    answer: () => ({ ok: true, output: { tool: "shell", exit_code: 3, stdout: "out\n", stderr: "err\n" } }),
  });
  const outcome = await relayTo(simulator).call(call(simulator));
  assert.deepEqual(outcome.answer, {
    ok: true,
    output: { tool: "shell", exit_code: 3, stdout: "out\n", stderr: "err\n" },
  });
  assert.equal(outcome.attachment, undefined);
  assert.ok(simulator.requests.includes(`POST /api/devices/${simulator.address}/calls`));
  assert.ok(simulator.requests.some((entry) => entry.endsWith("/ack")));
  assert.equal(simulator.calls.size, 0);
});

test("an answer too big for one row arrives whole as the attachment", async () => {
  const long = "x".repeat(4000);
  const simulator = simulateDevice({
    attachment: true,
    answer: () => ({ ok: true, output: { tool: "shell", exit_code: 0, stdout: long, stderr: "" } }),
  });
  const outcome = await relayTo(simulator).call(call(simulator));
  assert.equal(typeof outcome.attachment, "string");
  const whole = JSON.parse(outcome.attachment ?? "{}") as { output: { stdout: string } };
  assert.equal(whole.output.stdout, long);
  // The row was only a preview; the attachment is not.
  const row = outcome.answer as { output: { stdout: string; truncated: boolean } };
  assert.equal(row.output.truncated, true);
  assert.equal(row.output.stdout, "<preview>");
});

test("a result signed by someone else is refused", async () => {
  const simulator = simulateDevice({ tamper: true });
  await assert.rejects(relayTo(simulator).call(call(simulator)), /signature on this result does not verify/);
});

test("a device that never answers can be cancelled, and the relay is told", async () => {
  const simulator = simulateDevice({ hang: true });
  const controller = new AbortController();
  const pending = relayTo(simulator).call(call(simulator, { signal: controller.signal }));
  setTimeout(() => controller.abort(new Error("user cancelled")), 120);
  await assert.rejects(pending);
  assert.equal(simulator.cancels.length, 1);
  assert.equal(simulator.cancels[0], [...simulator.calls.keys()][0]);
});

test("device status is metadata the relay is allowed to know", async () => {
  const simulator = simulateDevice();
  const status = await relayTo(simulator).device(simulator.address);
  assert.equal(status.address, simulator.address);
  assert.equal(status.registered, true);
  assert.equal(status.online, true);
  assert.equal(status.platform, "darwin");
  assert.equal(status.version, "test");
});

test("a relay that never answers is one clear error", async () => {
  const relay = new Relay({
    endpoints: ["https://nothing.test"],
    identity: caller,
    fetch: (async () => new Response("nope", { status: 502 })) as typeof globalThis.fetch,
  });
  await assert.rejects(relay.device(addressOf(caller)), /no eXe relay answered at https:\/\/nothing.test/);
});
