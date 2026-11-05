// The panel's server half: read the two files eXe already owns, and write the
// two lists a human edits — the devices this caller may reach (`mcp.toml`), and
// the callers this machine, as a device, trusts (`config.toml`).
//
// Nothing here invents state. Both files stay the source of truth, so `exe
// status`, `exe trust`, and this panel always agree; an edit is a small TOML
// rewrite with the previous file kept beside it as `<name>.bak`.
import { copyFileSync, existsSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { parse as parseToml, stringify as stringifyToml } from "smol-toml";
import { addressOf, decodeSecret, isAddress } from "../../../shared/protocol.ts";
import { deviceConfigPath, defaultConfigPath, splitEndpoints, type CallerOptions } from "./config.ts";
import type { CallerView, DeviceRow, DeviceSideView, EditOp, ExeState } from "./contract.ts";

type Toml = Record<string, unknown>;

export interface ExeStateStore {
  /** Everything the panel draws. */
  state(): ExeState;
  /** Apply one edit and return the state after it. */
  edit(op: EditOp): ExeState;
}

function reason(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function readToml(path: string): Toml | undefined {
  if (!existsSync(path)) return undefined;
  try {
    return parseToml(readFileSync(path, "utf8")) as Toml;
  } catch (error) {
    throw new Error(`${path} is not valid TOML: ${reason(error)}`);
  }
}

/**
 * Replace one file atomically, at 0600, keeping the previous version beside it.
 * A config that cannot be read back is worse than one that cannot be written.
 */
function writeToml(path: string, value: Toml): void {
  const text = stringifyToml(value as never);
  const temporary = `${path}.tmp`;
  writeFileSync(temporary, text, { mode: 0o600 });
  if (existsSync(path)) copyFileSync(path, `${path}.bak`);
  renameSync(temporary, path);
}

function labelOf(value: unknown): string {
  const label = typeof value === "string" ? value.trim() : "";
  if (label.length === 0 || label.length > 64 || /[\u0000-\u001f]/.test(label)) {
    throw new Error("a device label is 1 to 64 printable characters");
  }
  return label;
}

function addressOfText(value: unknown): string {
  const address = typeof value === "string" ? value.trim() : "";
  if (!isAddress(address)) {
    throw new Error(`not an eXe address: ${JSON.stringify(address)}`);
  }
  return address;
}

function trustOf(file: Toml | undefined): string[] {
  const trust = file?.trust;
  if (trust === undefined) return [];
  if (!Array.isArray(trust)) throw new Error("`trust` in the device config must be a list of addresses");
  return trust.filter((entry): entry is string => typeof entry === "string");
}

export function createStateStore(options: CallerOptions = {}, env: NodeJS.ProcessEnv = process.env): ExeStateStore {
  const callerPath = options.configPath?.trim() || defaultConfigPath(env);
  const devicePath = deviceConfigPath(env);
  const inline = options.devices ?? {};

  const callerView = (): CallerView => {
    const view: CallerView = { endpoints: [], configPath: callerPath };
    try {
      const file = readToml(callerPath);
      const inlineSecret = options.secret?.trim();
      const secret = inlineSecret ?? (typeof file?.secret === "string" ? file.secret.trim() : undefined);
      if (secret === undefined || secret.length === 0) {
        view.error = `no caller key yet: run \`exe mcp init\`, or set \`secret\` in this plugin's config`;
        return view;
      }
      view.address = addressOf(decodeSecret(secret));
      view.source = inlineSecret === undefined ? callerPath : "plugin config";
      view.endpoints = splitEndpoints(options.endpoints).length > 0
        ? splitEndpoints(options.endpoints)
        : splitEndpoints(file?.endpoints).length > 0
          ? splitEndpoints(file?.endpoints)
          : splitEndpoints(file?.cloud);
    } catch (error) {
      view.error = reason(error);
    }
    return view;
  };

  const devicesView = (): DeviceRow[] => {
    const rows: DeviceRow[] = [];
    try {
      const table = readToml(callerPath)?.devices;
      if (table !== undefined && (typeof table !== "object" || table === null || Array.isArray(table))) {
        throw new Error("`devices` in the caller config must be a table of label = address");
      }
      for (const [label, address] of Object.entries((table ?? {}) as Toml)) {
        if (typeof address === "string") rows.push({ label, address, source: "file" });
      }
    } catch {
      // The caller view already carries this file's error; an unreadable file has no rows.
    }
    for (const [label, address] of Object.entries(inline)) {
      if (rows.some((row) => row.label === label)) continue;
      rows.push({ label, address, source: "config" });
    }
    return rows.sort((left, right) => left.label.localeCompare(right.label));
  };

  const deviceView = (): DeviceSideView => {
    const view: DeviceSideView = { available: false, path: devicePath, endpoints: [], trust: [] };
    if (!existsSync(devicePath)) return view;
    view.available = true;
    try {
      const file = readToml(devicePath);
      const secret = typeof file?.secret === "string" ? file.secret.trim() : "";
      if (secret.length === 0) throw new Error(`${devicePath} has no secret`);
      view.address = addressOf(decodeSecret(secret));
      view.endpoints = splitEndpoints(file?.endpoints).length > 0
        ? splitEndpoints(file?.endpoints)
        : splitEndpoints(file?.cloud);
      view.trust = trustOf(file);
    } catch (error) {
      view.error = reason(error);
    }
    return view;
  };

  const state = (): ExeState => ({ caller: callerView(), devices: devicesView(), device: deviceView() });

  const edit = (op: EditOp): ExeState => {
    switch (op.op) {
      case "device.set": {
        const label = labelOf(op.label);
        const address = addressOfText(op.address);
        if (Object.hasOwn(inline, label)) {
          throw new Error(`\`${label}\` is set in this plugin's own config; change it there, not in ${callerPath}`);
        }
        const file = readToml(callerPath) ?? {};
        const table = file.devices;
        const devices: Toml = typeof table === "object" && table !== null && !Array.isArray(table) ? { ...(table as Toml) } : {};
        devices[label] = address;
        writeToml(callerPath, { ...file, devices });
        break;
      }
      case "device.remove": {
        const label = labelOf(op.label);
        if (Object.hasOwn(inline, label)) {
          throw new Error(`\`${label}\` is set in this plugin's own config; remove it there, not in ${callerPath}`);
        }
        const file = readToml(callerPath);
        if (file === undefined) throw new Error(`no caller config at ${callerPath}`);
        const devices = { ...((file.devices ?? {}) as Toml) };
        delete devices[label];
        writeToml(callerPath, { ...file, devices });
        break;
      }
      case "trust.add":
      case "trust.remove": {
        const address = addressOfText(op.address);
        const file = readToml(devicePath);
        if (file === undefined) {
          throw new Error(`this machine is not an eXe device: ${devicePath} does not exist (run \`exe\`)`);
        }
        const trust = trustOf(file);
        const next = op.op === "trust.add" ? [...new Set([...trust, address])] : trust.filter((entry) => entry !== address);
        writeToml(devicePath, { ...file, trust: next });
        break;
      }
      default: {
        const never: never = op;
        throw new Error(`unknown edit ${JSON.stringify(never)}`);
      }
    }
    return state();
  };

  return { state, edit };
}
