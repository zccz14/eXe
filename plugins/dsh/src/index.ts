/**
 * dsh-plugin-exe — a DeepSeek Harness bundle that puts the user's own devices
 * behind three model-facing tools.
 *
 * eXe is an execution plane: a device runs the commands its `trust` list
 * accepts, and the relay in between only moves sealed bytes. This plugin is a
 * caller — the same role the `exe mcp` server plays — so a harness can operate
 * those devices without spawning a Rust binary, and pictures come back as
 * pictures rather than base64 in a text block.
 *
 * The key is never minted here: it is the caller key already on this machine
 * (`~/.config/exe/mcp.toml`), which is what the devices' trust lists name.
 *
 * @module dsh-plugin-exe
 */
import type { Context } from "@deepseek-ai/cordis";
import Schema from "@deepseek-ai/schemastery";
import { defineTool } from "@deepseek-ai/dsh-tools";
import type { ContentBlock } from "@deepseek-ai/dsh-llm";
import type {} from "@deepseek-ai/dsh-attachment";
import type { ImageAttachmentRef, ImageMediaType } from "@deepseek-ai/dsh-attachment";
import { DEFAULT_ENDPOINTS, addressForDevice, resolveCaller, type Caller } from "./config.ts";
import { Relay } from "./relay.ts";
import { pingDevices } from "./ping.ts";
import { registerExeRoutes, type WebServerLike } from "./routes.ts";
import { createStateStore } from "./state.ts";
import type { PingResult } from "./contract.ts";
import { imageBase64, renderDevices, renderShell, shellAnswer, type DeviceRow } from "./answers.ts";

export const name = "dsh-plugin-exe";
export const inject = ["tools"];

/**
 * Configuration for the eXe caller. Everything a deployment may want to change
 * lives here, and nothing is hardcoded: which relay, which key, which devices,
 * and what the tools are called.
 */
export const Config = Schema.object({
  endpoints: Schema.array(Schema.string())
    .description("Relay entry points, tried in order until one answers as an eXe relay.")
    .default([...DEFAULT_ENDPOINTS]),
  secret: Schema.string()
    .role("secret")
    .description(
      "Caller key, base58(seed32 || pub32). Leave it unset to use the key `exe mcp` already keeps in configPath.",
    ),
  configPath: Schema.string()
    .description("Where to read the caller key and device list when not set inline. Defaults to ~/.config/exe/mcp.toml."),
  devices: Schema.dict(Schema.string())
    .description("Device label → address, merged over the caller config's [devices] table.")
    .default({}),
  toolPrefix: Schema.string()
    .pattern(/^[A-Za-z][A-Za-z0-9_-]{0,40}$/)
    .description("Prefix for the three tool names. Keep it: a harness flattens every server's tools into one table.")
    .default("exe"),
  defaultTimeoutSeconds: Schema.natural()
    .min(1)
    .max(3600)
    .description("How long a command may run when the model does not say.")
    .default(60),
  maxCallSeconds: Schema.natural()
    .min(1)
    .max(3600)
    .description("Ceiling on one call's whole lifetime, including the wait for the device.")
    .default(3600),
});

export type Config = ReturnType<typeof Config>;

/** A shell path on the device, single-quoted: a quote in a name must not break out. */
function shQuote(value: string): string {
  return `'${value.replaceAll("'", `'\\''`)}'`;
}

function reason(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/** The media type is read from the bytes, not the extension, exactly as the harness will verify. */
function mediaTypeOf(bytes: Uint8Array, path: string, allowed: readonly ImageMediaType[]): ImageMediaType {
  const starts = (...signature: number[]): boolean => signature.every((byte, index) => bytes[index] === byte);
  let mediaType: ImageMediaType | undefined;
  if (starts(0x89, 0x50, 0x4e, 0x47)) mediaType = "image/png";
  else if (starts(0xff, 0xd8, 0xff)) mediaType = "image/jpeg";
  else if (starts(0x47, 0x49, 0x46, 0x38)) mediaType = "image/gif";
  else if (starts(0x52, 0x49, 0x46, 0x46) && bytes[8] === 0x57 && bytes[9] === 0x45) mediaType = "image/webp";
  if (mediaType === undefined) {
    throw new Error(`${path} is not a png, jpeg, webp or gif; read it with the shell tool if its bytes matter`);
  }
  if (!allowed.includes(mediaType)) {
    throw new Error(`this harness accepts ${allowed.join(", ")}; ${path} is ${mediaType}`);
  }
  return mediaType;
}

function basename(path: string): string {
  const parts = path.split(/[\\/]/);
  return parts[parts.length - 1] ?? path;
}

export function apply(ctx: Context, config: Config): void {
  const prefix = config.toolPrefix.trim();
  if (!/^[A-Za-z][A-Za-z0-9_-]{0,40}$/.test(prefix)) {
    throw new Error(`toolPrefix must be letters, digits, \`_\` or \`-\` and start with a letter: ${JSON.stringify(config.toolPrefix)}`);
  }

  // Resolved on first use, not at load: a harness starts this plugin at login,
  // and a machine that has not run `exe mcp init` yet should read as one clear
  // error from the tool, not as a harness that failed to boot.
  let resolved: Caller | undefined;
  let relay: Relay | undefined;
  const callerOf = (): Caller => (resolved ??= resolveCaller(config));
  const relayOf = (): Relay => {
    if (relay === undefined) {
      const caller = callerOf();
      relay = new Relay({ endpoints: caller.endpoints, identity: caller.identity });
    }
    return relay;
  };

  ctx.tools.register(
    defineTool({
      name: `${prefix}_devices`,
      description:
        `${prefix}_devices lists the devices this harness can reach through eXe, and whether each one is ` +
        "registered and online. Call it first: every other eXe tool takes a device label from here. " +
        "These are the user's own machines; nothing here runs on the machine hosting the harness.",
      parameters: {},
      output: {
        schema: {
          type: "object",
          additionalProperties: false,
          properties: {
            caller: {
              type: "string",
              required: true,
              description: "The address this harness signs as; every device's trust list must contain it.",
            },
            devices: {
              type: "array",
              required: true,
              items: {
                type: "object",
                additionalProperties: false,
                properties: {
                  device: { type: "string", required: true },
                  address: { type: "string", required: true },
                  registered: { type: "boolean" },
                  online: { type: "boolean" },
                  platform: { type: "string" },
                  version: { type: "string" },
                  last_seen_at: { type: "integer" },
                  error: { type: "string" },
                },
              },
            },
          },
        },
        render: (_args, value): ContentBlock[] => [
          { type: "text", text: renderDevices(value.caller, value.devices as DeviceRow[]) },
        ],
      },
      isConcurrencySafe: () => true,
      async execute(_args, exec) {
        const caller = callerOf();
        const client = relayOf();
        const rows = await Promise.all(
          [...caller.devices].map(async ([label, address]): Promise<DeviceRow> => {
            try {
              const status = await client.device(address, exec.signal);
              const row: DeviceRow = {
                device: label,
                address,
                registered: status.registered,
                online: status.online,
              };
              if (status.platform !== undefined) row.platform = status.platform;
              if (status.version !== undefined) row.version = status.version;
              if (status.last_seen_at !== undefined) row.last_seen_at = status.last_seen_at;
              return row;
            } catch (error) {
              return { device: label, address, error: reason(error) };
            }
          }),
        );
        return { caller: caller.address, devices: rows };
      },
    }),
  );

  ctx.tools.register(
    defineTool({
      name: `${prefix}_bash`,
      description:
        "Run a shell command on a REMOTE device through eXe — not on this machine and not in a sandbox. " +
        "The command runs as that device's own user, with no confirmation and no undo. " +
        "Prefer one command that does the whole job (`cd x && a && b`) over many small ones: every call is a round trip " +
        "through the relay. Use `cwd` instead of `cd` when only the directory matters. " +
        "A call that fails with `lost` may already have run on the device: check the device before retrying. " +
        "This does not look at files here; read them on the device or ask for an image with the image tool.",
      parameters: {
        device: {
          type: "string",
          required: true,
          description: "Device label from the devices tool, or the device's address.",
        },
        command: {
          type: "string",
          required: true,
          description: "The command line, run with `sh -c` on the device (`cmd /C` on Windows).",
        },
        cwd: { type: "string", description: "Working directory on the device." },
        timeout_seconds: {
          type: "integer",
          description: `How long the command may run before the device kills it. Defaults to ${config.defaultTimeoutSeconds}.`,
        },
      },
      output: {
        schema: {
          type: "object",
          additionalProperties: false,
          properties: {
            device: { type: "string", required: true },
            command: { type: "string", required: true },
            exit_code: { type: "integer", required: true },
            stdout: { type: "string", required: true },
            stderr: { type: "string", required: true },
            truncated: { type: "boolean", required: true },
            timed_out: { type: "boolean", required: true },
            error: { type: "string" },
          },
        },
        render: (_args, value): ContentBlock[] => [{ type: "text", text: renderShell(value) }],
      },
      async execute(args, exec) {
        const caller = callerOf();
        const client = relayOf();
        const timeout = args.timeout_seconds ?? config.defaultTimeoutSeconds;
        if (!Number.isFinite(timeout) || timeout <= 0) {
          throw new Error(`timeout_seconds must be a positive number, got ${JSON.stringify(args.timeout_seconds)}`);
        }
        const call: Record<string, unknown> = { command: args.command };
        if (args.cwd !== undefined) call.cwd = args.cwd;
        if (args.timeout_seconds !== undefined) call.timeout_seconds = timeout;
        const outcome = await client.call({
          device: addressForDevice(caller, args.device),
          name: "shell",
          args: call,
          ttlSeconds: Math.min(timeout + 60, config.maxCallSeconds),
          signal: exec.signal,
        });
        return shellAnswer(args.device, args.command, outcome);
      },
    }),
  );

  ctx.tools.register(
    defineTool({
      name: `${prefix}_image`,
      description:
        "Read an image file on a REMOTE device through eXe and return it as an image the model can see. " +
        "Useful for screenshots: take one with the shell tool, then read it here. " +
        "Only png, jpeg, webp and gif arrive; a file too large for this harness must be downscaled on the device first.",
      parameters: {
        device: {
          type: "string",
          required: true,
          description: "Device label from the devices tool, or the device's address.",
        },
        path: { type: "string", required: true, description: "Absolute path of a png, jpeg, webp or gif on the device." },
      },
      output: {
        schema: {
          type: "object",
          additionalProperties: false,
          properties: {
            device: { type: "string", required: true },
            path: { type: "string", required: true },
            media_type: { type: "string", required: true },
            bytes: { type: "integer", required: true },
            width: { type: "integer", required: true },
            height: { type: "integer", required: true },
            attachment: {
              type: "json",
              required: true,
              description: "The durable attachment this harness hands to the model as an image.",
            },
          },
        },
        render: (_args, value): ContentBlock[] => [
          { type: "image", attachment: value.attachment as unknown as ImageAttachmentRef },
          {
            type: "text",
            text: `[${value.device}] ${value.path} — ${value.width}×${value.height}, ${value.bytes} bytes`,
          },
        ],
      },
      isConcurrencySafe: () => true,
      async execute(args, exec) {
        const attachments = ctx.get("attachments");
        if (attachments === undefined) {
          throw new Error("this harness has no attachment service, so an image cannot be handed to the model");
        }
        const caller = callerOf();
        const client = relayOf();
        const outcome = await client.call({
          device: addressForDevice(caller, args.device),
          name: "shell",
          // One round trip: the device base64s the file, and a result too big for
          // one row travels whole as an attachment. `tr -d` keeps it on one line
          // so the JSON string stays valid whatever the platform's base64 does.
          args: { command: `base64 < ${shQuote(args.path)} | tr -d '\\n'`, timeout_seconds: 120 },
          ttlSeconds: Math.min(180, config.maxCallSeconds),
          signal: exec.signal,
        });
        const base64 = imageBase64(args.device, args.path, outcome);
        const bytes = new Uint8Array(Buffer.from(base64, "base64"));
        const limits = attachments.imageLimits;
        if (bytes.length > limits.maxImageBytes) {
          throw new Error(
            `${args.path} is ${bytes.length} bytes, past this harness's ${limits.maxImageBytes}-byte image limit: ` +
              "downscale it on the device first.",
          );
        }
        const mediaType = mediaTypeOf(bytes, args.path, limits.mediaTypes);
        const ref = await attachments.saveImage({ data: bytes, mediaType, name: basename(args.path) });
        // The canonical value is JSON; the reference rides along as plain data and
        // is cast back to its durable shape for the image block.
        return {
          device: args.device,
          path: args.path,
          media_type: ref.mediaType,
          bytes: ref.bytes,
          width: ref.width,
          height: ref.height,
          attachment: {
            attachmentId: ref.attachmentId,
            mediaType: ref.mediaType,
            bytes: ref.bytes,
            width: ref.width,
            height: ref.height,
            ...(ref.name === undefined ? {} : { name: ref.name }),
          },
        };
      },
    }),
  );

  // The browser half (this package's `./client`) is a sidebar page: the caller's
  // address — the string another device must trust — plus both device lists. It
  // reads and writes through these two routes, which exist only where a web
  // server does; a headless profile keeps the three tools and serves no page.
  ctx.inject(["webServer"], (scoped) => {
    const webServer = (scoped as unknown as { webServer: WebServerLike }).webServer;
    const store = createStateStore(config);
    // The ping is a real call: one `echo`, measured end to end. The relay's own
    // opinion is probed first, so an offline device fails in milliseconds instead
    // of waiting out the whole budget.
    const ping = async (labels?: string[]): Promise<PingResult[]> => {
      const caller = callerOf();
      const targets =
        labels === undefined
          ? [...caller.devices].map(([label, address]) => ({ label, address }))
          : labels.map((label) => ({ label, address: addressForDevice(caller, label) }));
      return await pingDevices(relayOf(), targets);
    };
    scoped.effect(() => registerExeRoutes(webServer, { store, ping }), "dsh-plugin-exe: panel routes");
  });
}
