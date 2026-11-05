import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, test } from "node:test";
import type { Context } from "@deepseek-ai/cordis";
import { assertSupportedJsonSchema } from "@deepseek-ai/dsh-tools";
import { addressOf, encodeSecret, newIdentity } from "../../../shared/protocol.ts";
import { Config, apply } from "../src/index.ts";
import { simulateDevice } from "./fake-device.ts";

/** A 1×1 png: the smallest thing that is still a picture. */
const PNG = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==";

const caller = newIdentity();

interface Definition {
  name: string;
  description: string;
  output: { schema: unknown; render: (args: unknown, value: never) => Array<Record<string, unknown>> };
  execute: (args: unknown, exec: { signal: AbortSignal }) => Promise<unknown>;
}

interface Saved {
  data: Uint8Array;
  mediaType: string;
  name?: string;
}

/** The harness, cut down to the seams this plugin touches. */
function harness(options: { attachments?: boolean; webServer?: boolean } = {}) {
  const tools = new Map<string, Definition>();
  const routes: Array<{ kind: string; path: string }> = [];
  const saved: Saved[] = [];
  const attachments =
    options.attachments === false
      ? undefined
      : {
          imageLimits: {
            maxImageBytes: 4 * 1024 * 1024,
            maxImagesPerMessage: 4,
            maxMessageImageBytes: 16 * 1024 * 1024,
            maxImagePixels: 4096 * 4096,
            maxImageDimension: 4096,
            mediaTypes: ["image/png", "image/jpeg", "image/webp", "image/gif"],
          },
          async saveImage(input: Saved) {
            saved.push(input);
            return {
              attachmentId: "a".repeat(64),
              mediaType: input.mediaType,
              bytes: input.data.length,
              width: 1,
              height: 1,
              ...(input.name === undefined ? {} : { name: input.name }),
            };
          },
        };
  const webServer = {
    register(route: { kind: string; path: string }) {
      routes.push(route);
      return () => undefined;
    },
  };
  const ctx = {
    tools: {
      register: (definition: Definition) => {
        tools.set(definition.name, definition);
        return () => tools.delete(definition.name);
      },
    },
    get: (name: string) => (name === "attachments" ? attachments : undefined),
    // Cordis mixes the registry's `inject` onto the context: the callback runs
    // only once the named service exists, in a child context.
    inject: (deps: string[], callback: (scoped: unknown) => void) => {
      if (deps.includes("webServer") && options.webServer === false) return;
      callback({
        webServer,
        effect: (execute: () => () => void) => execute(),
      });
    },
  };
  return { ctx: ctx as unknown as Context, tools, saved, routes };
}

/** A caller config on disk, pointing at one simulated device named `lab`. */
function configure(deviceAddress: string): void {
  const dir = mkdtempSync(join(tmpdir(), "dsh-exe-plugin-"));
  writeFileSync(
    join(dir, "mcp.toml"),
    `secret = "${encodeSecret(caller)}"\n\n[devices]\nlab = "${deviceAddress}"\n`,
  );
  process.env.EXE_CONFIG_DIR = dir;
}

const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
  delete process.env.EXE_CONFIG_DIR;
});

function execute(
  tools: Map<string, Definition>,
  name: string,
  args: Record<string, unknown>,
): Promise<Record<string, unknown>> {
  const definition = tools.get(name);
  assert.ok(definition, `${name} was not registered`);
  return definition.execute(args, { signal: new AbortController().signal }) as Promise<Record<string, unknown>>;
}

function render(tools: Map<string, Definition>, name: string, args: unknown, value: unknown) {
  const definition = tools.get(name);
  assert.ok(definition);
  return definition.output.render(args, value as never);
}

test("three tools, every name prefixed and every schema the registry's kind of schema", () => {
  const { ctx, tools } = harness();
  apply(ctx, Config({}));
  assert.deepEqual([...tools.keys()], ["exe_devices", "exe_bash", "exe_image"]);
  for (const definition of tools.values()) {
    assert.doesNotThrow(() => assertSupportedJsonSchema(definition.output.schema));
    assert.ok(definition.description.length > 80, `${definition.name} needs a description a model can act on`);
  }
});

test("the prefix is configuration, because two pools may coexist", () => {
  const { ctx, tools } = harness();
  apply(ctx, Config({ toolPrefix: "box" }));
  assert.deepEqual([...tools.keys()], ["box_devices", "box_bash", "box_image"]);
});

test("a shell command runs on the device and comes back as text", async () => {
  const simulator = simulateDevice({
    answer: () => ({ ok: true, output: { tool: "shell", exit_code: 0, stdout: "hi\n", stderr: "" } }),
  });
  configure(simulator.address);
  globalThis.fetch = simulator.fetch;
  const { ctx, tools } = harness();
  apply(ctx, Config({}));

  const args = { device: "lab", command: "printf hi" };
  const value = await execute(tools, "exe_bash", args);
  assert.equal(value.device, "lab");
  assert.equal(value.exit_code, 0);
  assert.equal(value.stdout, "hi\n");
  assert.equal(value.timed_out, false);

  const blocks = render(tools, "exe_bash", args, value);
  assert.deepEqual(blocks, [{ type: "text", text: "[lab] $ printf hi\nexit 0\nhi" }]);
});

test("a command the device killed at its timeout says so", async () => {
  const simulator = simulateDevice({
    answer: () => ({ ok: false, code: "timeout", error: "command exceeded 1s and was killed" }),
  });
  configure(simulator.address);
  globalThis.fetch = simulator.fetch;
  const { ctx, tools } = harness();
  apply(ctx, Config({}));

  const args = { device: "lab", command: "sleep 30", timeout_seconds: 1 };
  const value = await execute(tools, "exe_bash", args);
  assert.equal(value.timed_out, true);
  assert.equal(value.exit_code, -1);
  const text = render(tools, "exe_bash", args, value)[0]?.text as string;
  assert.match(text, /the device killed the command at its timeout/);
  assert.match(text, /command exceeded 1s and was killed/);
});

test("a screenshot on the device arrives as an image, not as base64", async () => {
  const simulator = simulateDevice({
    answer: () => ({ ok: true, output: { tool: "shell", exit_code: 0, stdout: `${PNG}\n`, stderr: "" } }),
  });
  configure(simulator.address);
  globalThis.fetch = simulator.fetch;
  const { ctx, tools, saved } = harness();
  apply(ctx, Config({}));

  const args = { device: "lab", path: "/tmp/shot.png" };
  const value = await execute(tools, "exe_image", args);
  assert.equal(value.media_type, "image/png");
  assert.equal(value.bytes, Buffer.from(PNG, "base64").length);
  assert.deepEqual(value.attachment, {
    attachmentId: "a".repeat(64),
    mediaType: "image/png",
    bytes: Buffer.from(PNG, "base64").length,
    width: 1,
    height: 1,
    name: "shot.png",
  });
  assert.equal(saved.length, 1);
  assert.equal(saved[0]?.mediaType, "image/png");

  const blocks = render(tools, "exe_image", args, value);
  assert.equal(blocks[0]?.type, "image");
  assert.equal(blocks[1]?.type, "text");
  assert.match(blocks[1]?.text as string, /\[lab\] \/tmp\/shot\.png — 1×1/);
});

test("base64 that is not an image is named, not handed over", async () => {
  const simulator = simulateDevice({
    answer: () => ({ ok: true, output: { tool: "shell", exit_code: 0, stdout: "bm90IGFuIGltYWdl", stderr: "" } }),
  });
  configure(simulator.address);
  globalThis.fetch = simulator.fetch;
  const { ctx, tools } = harness();
  apply(ctx, Config({}));
  await assert.rejects(
    execute(tools, "exe_image", { device: "lab", path: "/tmp/notes.txt" }),
    /is not a png, jpeg, webp or gif/,
  );
});

test("a harness without an attachment service refuses instead of pretending", async () => {
  const simulator = simulateDevice();
  configure(simulator.address);
  globalThis.fetch = simulator.fetch;
  const { ctx, tools } = harness({ attachments: false });
  apply(ctx, Config({}));
  await assert.rejects(
    execute(tools, "exe_image", { device: "lab", path: "/tmp/shot.png" }),
    /no attachment service/,
  );
});

test("the devices tool reports the caller address and the device's state", async () => {
  const simulator = simulateDevice();
  configure(simulator.address);
  globalThis.fetch = simulator.fetch;
  const { ctx, tools } = harness();
  apply(ctx, Config({}));

  const value = (await execute(tools, "exe_devices", {})) as unknown as {
    caller: string;
    devices: Array<{ device: string; online: boolean; platform?: string }>;
  };
  assert.equal(value.caller, addressOf(caller));
  assert.equal(value.devices.length, 1);
  assert.equal(value.devices[0]?.device, "lab");
  assert.equal(value.devices[0]?.online, true);
  assert.equal(value.devices[0]?.platform, "darwin");

  const text = render(tools, "exe_devices", {}, value)[0]?.text as string;
  assert.match(text, /^caller /);
  assert.match(text, /lab {2}\S+ {2}online/);
});

test("an unknown device is a list of what is configured", async () => {
  const simulator = simulateDevice();
  configure(simulator.address);
  globalThis.fetch = simulator.fetch;
  const { ctx, tools } = harness();
  apply(ctx, Config({}));
  await assert.rejects(
    execute(tools, "exe_bash", { device: "nope", command: "true" }),
    /unknown device `nope`: configured: lab/,
  );
});

test("the panel's routes are registered only where a web server exists", () => {
  const withServer = harness();
  apply(withServer.ctx, Config({}));
  assert.deepEqual(
    withServer.routes.map((route) => `${route.kind} ${route.path}`),
    ["prefix /exe/api"],
  );

  const headless = harness({ webServer: false });
  apply(headless.ctx, Config({}));
  assert.deepEqual(headless.routes, []);
});

test("a missing caller key fails at call time, with the command that fixes it", async () => {
  process.env.EXE_CONFIG_DIR = mkdtempSync(join(tmpdir(), "dsh-exe-empty-"));
  const { ctx, tools } = harness();
  apply(ctx, Config({}));
  await assert.rejects(execute(tools, "exe_bash", { device: "lab", command: "true" }), /exe mcp init/);
});
