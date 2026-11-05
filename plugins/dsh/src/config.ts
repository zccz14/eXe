// Who this harness is to eXe, where the relay lives, and which devices it may
// reach.
//
// The key is the *same* one `exe mcp` uses on this machine: one caller, one
// address, one trust list. A plugin that minted its own key would be a second
// stranger to every device, and the user would have to authorize it again for
// no reason — so by default this file is read, not invented.
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";
import { parse as parseToml } from "smol-toml";
import { addressOf, decodeSecret, isAddress, type Identity } from "../../../shared/protocol.ts";

/** The relay entry points a caller falls back to, in preference order. */
export const DEFAULT_ENDPOINTS = ["https://exe.ntnl.io", "https://exe.ntnl.top"];

/** The plugin row's own configuration, as validated by the schema in index.ts. */
export interface CallerOptions {
  endpoints?: string[];
  secret?: string;
  configPath?: string;
  devices?: Record<string, string>;
}

/** Everything a tool call needs: one key, one relay, one device list. */
export interface Caller {
  /** The base58 address this harness signs as. */
  address: string;
  identity: Identity;
  endpoints: string[];
  /** label → device address. Labels are the operator's own names. */
  devices: Map<string, string>;
  /** Where the key and the device list were read from, for messages. */
  source: string;
}

/** The parts of `mcp.toml` this plugin understands. Everything else is ignored. */
interface CallerFile {
  endpoints?: unknown;
  cloud?: unknown;
  secret?: unknown;
  devices?: unknown;
}

/** `~/.config/exe/mcp.toml`, the same path `exe mcp` reads and writes. */
export function defaultConfigPath(env: NodeJS.ProcessEnv = process.env): string {
  const override = env.EXE_CONFIG_DIR?.trim();
  if (override) return join(override, "mcp.toml");
  if (process.platform === "win32" && env.APPDATA?.trim()) return join(env.APPDATA.trim(), "exe", "mcp.toml");
  const home = env.HOME?.trim() || env.USERPROFILE?.trim() || homedir();
  return join(home, ".config", "exe", "mcp.toml");
}

/** One base URL per entry, trimmed: a trailing slash would double up in a join. */
export function splitEndpoints(value: unknown): string[] {
  const entries = Array.isArray(value) ? value : typeof value === "string" ? [value] : [];
  return entries
    .filter((entry): entry is string => typeof entry === "string")
    .flatMap((entry) => entry.split(","))
    .map((entry) => entry.trim().replace(/\/+$/, ""))
    .filter((entry) => entry.length > 0);
}

function readFileConfig(path: string): CallerFile | undefined {
  if (!existsSync(path)) return undefined;
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch (error) {
    throw new Error(`cannot read the eXe caller config at ${path}: ${message(error)}`);
  }
  try {
    return parseToml(text) as CallerFile;
  } catch (error) {
    throw new Error(`${path} is not valid TOML: ${message(error)}`);
  }
}

function message(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function endpointsOf(file: CallerFile | undefined, options: CallerOptions): string[] {
  const inline = splitEndpoints(options.endpoints);
  if (inline.length > 0) return inline;
  const configured = splitEndpoints(file?.endpoints);
  if (configured.length > 0) return configured;
  const legacy = splitEndpoints(file?.cloud);
  if (legacy.length > 0) return legacy;
  return [...DEFAULT_ENDPOINTS];
}

function devicesOf(file: CallerFile | undefined, options: CallerOptions): Map<string, string> {
  const merged = new Map<string, string>();
  const table = file?.devices;
  if (table !== undefined && (typeof table !== "object" || table === null || Array.isArray(table))) {
    throw new Error("`devices` in the eXe caller config must be a table of label = address");
  }
  for (const [label, address] of Object.entries((table ?? {}) as Record<string, unknown>)) {
    if (typeof address !== "string") throw new Error(`device \`${label}\` in the caller config is not a string address`);
    merged.set(label, address.trim());
  }
  for (const [label, address] of Object.entries(options.devices ?? {})) {
    merged.set(label, address.trim());
  }
  const invalid = [...merged].filter(([, address]) => !isAddress(address)).map(([label]) => label);
  if (invalid.length > 0) {
    throw new Error(
      `not an eXe address: ${invalid.map((label) => `\`${label}\``).join(", ")}. ` +
        "A device address is base58 of its 32-byte public key; `exe status` prints it on the device.",
    );
  }
  return merged;
}

/**
 * Resolve the caller from the plugin row, the shared `mcp.toml`, or both.
 *
 * Inline configuration wins; the file fills the gaps. Nothing is created on
 * demand: a missing key is a question for the human (`exe mcp init` mints one
 * and prints its address), not something a plugin should answer by inventing
 * an identity no device has ever trusted.
 */
export function resolveCaller(
  options: CallerOptions = {},
  env: NodeJS.ProcessEnv = process.env,
): Caller {
  const path = options.configPath?.trim() || defaultConfigPath(env);
  const file = readFileConfig(path);
  const inlineSecret = options.secret?.trim();
  const fileSecret = typeof file?.secret === "string" ? file.secret.trim() : undefined;
  const secret = inlineSecret || fileSecret;
  if (!secret) {
    throw new Error(
      `no eXe caller key: ${path} does not exist. Run \`exe mcp init\` on this machine and add the ` +
        "address it prints to every device with `exe trust <address>`, or set `secret` in this " +
        "plugin's config.",
    );
  }
  let identity: Identity;
  try {
    identity = decodeSecret(secret);
  } catch (error) {
    throw new Error(
      `the eXe caller key in ${inlineSecret ? "this plugin's config" : path} is not base58(seed32 || pub32): ` +
        message(error),
    );
  }
  return {
    address: addressOf(identity),
    identity,
    endpoints: endpointsOf(file, options),
    devices: devicesOf(file, options),
    source: inlineSecret ? "plugin config" : path,
  };
}

/**
 * The address behind a device label. A bare address is accepted too, so a
 * device the operator has not named yet is still reachable in one step.
 */
export function addressForDevice(caller: Caller, requested: string): string {
  const named = caller.devices.get(requested);
  if (named !== undefined) return named;
  if (isAddress(requested)) return requested;
  const known = [...caller.devices.keys()];
  throw new Error(
    `unknown device \`${requested}\`: ${known.length > 0 ? `configured: ${known.join(", ")}` : "no devices are configured"}. ` +
      "Call the devices tool for the labels, or add [devices] entries to the eXe caller config.",
  );
}
