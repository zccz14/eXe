import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { test } from "node:test";
import { addressOf, encodeSecret, newIdentity } from "../../../shared/protocol.ts";
import { addressForDevice, defaultConfigPath, resolveCaller } from "../src/config.ts";

const caller = newIdentity();
const device = newIdentity();

function callerFile(contents: string): { dir: string } {
  const dir = mkdtempSync(join(tmpdir(), "dsh-exe-"));
  writeFileSync(join(dir, "mcp.toml"), contents);
  return { dir };
}

function env(dir: string): NodeJS.ProcessEnv {
  return { EXE_CONFIG_DIR: dir } as NodeJS.ProcessEnv;
}

test("the key and device list come from the file `exe mcp` writes", () => {
  const { dir } = callerFile(
    `endpoints = ["https://relay.example"]\nsecret = "${encodeSecret(caller)}"\n\n[devices]\nlab = "${addressOf(device)}"\n`,
  );
  const resolved = resolveCaller({}, env(dir));
  assert.equal(resolved.address, addressOf(caller));
  assert.deepEqual(resolved.endpoints, ["https://relay.example"]);
  assert.equal(resolved.devices.get("lab"), addressOf(device));
  assert.equal(resolved.source, join(dir, "mcp.toml"));
});

test("inline configuration wins, and devices merge over the file", () => {
  const other = newIdentity();
  const { dir } = callerFile(
    `endpoints = ["https://from-file.example"]\nsecret = "${encodeSecret(caller)}"\n\n[devices]\nlab = "${addressOf(device)}"\n`,
  );
  const resolved = resolveCaller(
    {
      secret: encodeSecret(other),
      endpoints: ["https://inline.example/"],
      devices: { phone: addressOf(newIdentity()) },
    },
    env(dir),
  );
  assert.equal(resolved.address, addressOf(other));
  assert.deepEqual(resolved.endpoints, ["https://inline.example"]);
  assert.deepEqual([...resolved.devices.keys()].sort(), ["lab", "phone"]);
});

test("an older file with a single `cloud` and comma-separated endpoints still works", () => {
  const { dir } = callerFile(
    `cloud = "https://one.example/, https://two.example"\nsecret = "${encodeSecret(caller)}"\n`,
  );
  const resolved = resolveCaller({}, env(dir));
  assert.deepEqual(resolved.endpoints, ["https://one.example", "https://two.example"]);
  assert.equal(resolved.devices.size, 0);
});

test("no key is an instruction, not a crash", () => {
  const { dir } = callerFile("");
  assert.throws(() => resolveCaller({}, env(dir)), /exe mcp init/);
});

test("a key that is not a key fails where it was read", () => {
  const { dir } = callerFile(`secret = "not-a-key"\n`);
  assert.throws(() => resolveCaller({}, env(dir)), /base58\(seed32 \|\| pub32\)/);
});

test("a mistyped device address is named, not silently ignored", () => {
  const { dir } = callerFile(`secret = "${encodeSecret(caller)}"\n\n[devices]\ntypo = "nope"\n`);
  assert.throws(() => resolveCaller({}, env(dir)), /not an eXe address: `typo`/);
});

test("a device is reachable by label or by address", () => {
  const resolved = resolveCaller(
    { secret: encodeSecret(caller), devices: { lab: addressOf(device) } },
    env("/nonexistent"),
  );
  assert.equal(addressForDevice(resolved, "lab"), addressOf(device));
  assert.equal(addressForDevice(resolved, addressOf(device)), addressOf(device));
  assert.throws(() => addressForDevice(resolved, "nope"), /unknown device `nope`: configured: lab/);
});

test("the default path is the one the eXe CLI uses", () => {
  assert.equal(defaultConfigPath({ HOME: "/home/me" } as NodeJS.ProcessEnv), "/home/me/.config/exe/mcp.toml");
  assert.equal(
    defaultConfigPath({ EXE_CONFIG_DIR: "/elsewhere" } as NodeJS.ProcessEnv),
    "/elsewhere/mcp.toml",
  );
});
