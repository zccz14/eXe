import assert from "node:assert/strict";
import { existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { addressOf, encodeSecret, isAddress, newIdentity } from "../../../shared/protocol.ts";
import { createStateStore } from "../src/state.ts";

const caller = newIdentity();
const device = newIdentity();
const other = newIdentity();

function workspace(options: { caller?: boolean; device?: boolean } = {}): { dir: string; env: NodeJS.ProcessEnv } {
  const dir = mkdtempSync(join(tmpdir(), "dsh-exe-panel-"));
  if (options.caller !== false) {
    writeFileSync(
      join(dir, "mcp.toml"),
      `endpoints = ["https://relay.example"]\nsecret = "${encodeSecret(caller)}"\n\n[devices]\nlab = "${addressOf(device)}"\n`,
    );
  }
  if (options.device !== false) {
    writeFileSync(
      join(dir, "config.toml"),
      `endpoints = ["https://exe.ntnl.io"]\nsecret = "${encodeSecret(newIdentity())}"\ntrust = ["${addressOf(other)}"]\n`,
    );
  }
  return { dir, env: { EXE_CONFIG_DIR: dir } as NodeJS.ProcessEnv };
}

test("the panel reads the address a device has to trust, and both lists", () => {
  const { dir, env } = workspace();
  const state = createStateStore({}, env).state();
  assert.equal(state.caller.address, addressOf(caller));
  assert.deepEqual(state.caller.endpoints, ["https://relay.example"]);
  assert.equal(state.caller.configPath, join(dir, "mcp.toml"));
  assert.deepEqual(state.devices, [{ label: "lab", address: addressOf(device), source: "file" }]);
  assert.equal(state.device.available, true);
  assert.deepEqual(state.device.trust, [{ address: addressOf(other) }]);
  assert.equal(isAddress(state.device.address), true);
});

test("editing a device writes the caller file at 0600 and keeps the old one", () => {
  const { dir, env } = workspace();
  const store = createStateStore({}, env);
  const added = newIdentity();
  const state = store.edit({ op: "device.set", label: "phone", address: addressOf(added) });
  assert.deepEqual(
    state.devices.map((row) => row.label),
    ["lab", "phone"],
  );
  const path = join(dir, "mcp.toml");
  assert.equal(statSync(path).mode & 0o777, 0o600);
  assert.equal(existsSync(`${path}.bak`), true);
  assert.match(readFileSync(path, "utf8"), new RegExp(addressOf(added)));

  const removed = store.edit({ op: "device.remove", label: "phone" });
  assert.deepEqual(
    removed.devices.map((row) => row.label),
    ["lab"],
  );
});

test("trust is edited in the device file, which the device hot-reloads", () => {
  const { dir, env } = workspace();
  const store = createStateStore({}, env);
  const trusted = addressOf(newIdentity());
  const state = store.edit({ op: "trust.add", address: trusted });
  assert.deepEqual(state.device.trust, [{ address: addressOf(other) }, { address: trusted }]);
  const after = store.edit({ op: "trust.remove", address: addressOf(other) });
  assert.deepEqual(after.device.trust, [{ address: trusted }]);
  assert.match(readFileSync(join(dir, "config.toml"), "utf8"), new RegExp(trusted));
});

test("the same address twice is one trust entry", () => {
  const { env } = workspace();
  const store = createStateStore({}, env);
  const state = store.edit({ op: "trust.add", address: addressOf(other) });
  assert.deepEqual(state.device.trust, [{ address: addressOf(other) }]);
});

test("a device label can be renamed in place, and a taken one is refused", () => {
  const { dir, env } = workspace();
  const store = createStateStore({}, env);
  const renamed = store.edit({ op: "device.rename", from: "lab", to: "workstation" });
  assert.deepEqual(
    renamed.devices.map((row) => row.label),
    ["workstation"],
  );
  assert.match(readFileSync(join(dir, "mcp.toml"), "utf8"), /workstation = /);
  store.edit({ op: "device.set", label: "phone", address: addressOf(newIdentity()) });
  assert.throws(() => store.edit({ op: "device.rename", from: "phone", to: "workstation" }), /already a device label/);
  assert.throws(() => store.edit({ op: "device.rename", from: "nope", to: "x" }), /no device labelled/);
});

test("a trusted caller can carry a label, kept beside the config", () => {
  const { dir, env } = workspace();
  const store = createStateStore({}, env);
  const labelled = store.edit({ op: "trust.label", address: addressOf(other), label: "cz 的 MacBook" });
  assert.deepEqual(labelled.device.trust, [{ address: addressOf(other), label: "cz 的 MacBook" }]);
  assert.match(readFileSync(join(dir, "dsh-labels.json"), "utf8"), /cz 的 MacBook/);
  // The eXe-owned file is untouched: labels never enter a schema `exe` rewrites.
  assert.doesNotMatch(readFileSync(join(dir, "config.toml"), "utf8"), /cz 的 MacBook/);

  const cleared = store.edit({ op: "trust.label", address: addressOf(other), label: "" });
  assert.deepEqual(cleared.device.trust, [{ address: addressOf(other) }]);
});

test("a label is only for an address this machine actually trusts", () => {
  const { env } = workspace();
  const store = createStateStore({}, env);
  assert.throws(
    () => store.edit({ op: "trust.label", address: addressOf(newIdentity()), label: "x" }),
    /is not trusted by this machine/,
  );
});

test("untrusting a caller takes its label with it", () => {
  const { env } = workspace();
  const store = createStateStore({}, env);
  store.edit({ op: "trust.label", address: addressOf(other), label: "gone" });
  const after = store.edit({ op: "trust.remove", address: addressOf(other) });
  assert.deepEqual(after.device.trust, []);
  store.edit({ op: "trust.add", address: addressOf(other) });
  assert.deepEqual(store.state().device.trust, [{ address: addressOf(other) }]);
});

test("a broken address or label is refused with the reason", () => {
  const { env } = workspace();
  const store = createStateStore({}, env);
  assert.throws(() => store.edit({ op: "device.set", label: "x", address: "nope" }), /not an eXe address/);
  assert.throws(() => store.edit({ op: "device.set", label: "  ", address: addressOf(device) }), /device label/);
  assert.throws(() => store.edit({ op: "trust.add", address: "nope" }), /not an eXe address/);
});

test("devices set in the plugin's own config are shown but not editable here", () => {
  const { env } = workspace();
  const inline = addressOf(newIdentity());
  const store = createStateStore({ devices: { pinned: inline } }, env);
  const state = store.state();
  assert.deepEqual(
    state.devices.find((row) => row.label === "pinned"),
    { label: "pinned", address: inline, source: "config" },
  );
  assert.throws(() => store.edit({ op: "device.remove", label: "pinned" }), /plugin's own config/);
});

test("without a key the page says what to run instead of inventing an address", () => {
  const { env } = workspace({ caller: false });
  const state = createStateStore({}, env).state();
  assert.equal(state.caller.address, undefined);
  assert.match(state.caller.error ?? "", /exe mcp init/);
});

test("a machine that is not a device says so, and refuses to grow a trust list", () => {
  const { env } = workspace({ device: false });
  const store = createStateStore({}, env);
  const state = store.state();
  assert.equal(state.device.available, false);
  assert.throws(() => store.edit({ op: "trust.add", address: addressOf(other) }), /not an eXe device/);
});
