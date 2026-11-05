// The vocabulary the panel and the route share.
//
// Types only, on purpose: the browser half bundles this file away, so nothing
// here may import `node:fs`, the protocol, or any other Host-only module.

/** The caller half: who this harness signs as, and where it can reach. */
export interface CallerView {
  /** base58 of the caller's public key — the string a device must trust. */
  address?: string;
  endpoints: string[];
  /** The file the key came from, for the human reading the panel. */
  configPath: string;
  /** `plugin config` when the key was set inline instead of in that file. */
  source?: string;
  /** Set when there is no usable key; the panel shows this instead of an address. */
  error?: string;
}

/** One device this caller may reach. */
export interface DeviceRow {
  label: string;
  address: string;
  /** `config` rows come from this plugin's own config and cannot be edited here. */
  source: "file" | "config";
}

/**
 * One caller address this machine, as a device, trusts.
 *
 * eXe stores trust as a bare address list, so a label here is this plugin's own
 * sidecar (next to the config), not something `exe` reads or rewrites.
 */
export interface TrustRow {
  address: string;
  label?: string;
}

/** The other direction: this machine as a device, and who may command it. */
export interface DeviceSideView {
  /** False when `config.toml` does not exist: this machine is not a device. */
  available: boolean;
  path: string;
  /** The device's own address — what other callers must name to reach it. */
  address?: string;
  endpoints: string[];
  /** Caller addresses this machine accepts commands from, each with its label. */
  trust: TrustRow[];
  error?: string;
}

/** Everything the panel draws, in one read. */
export interface ExeState {
  caller: CallerView;
  devices: DeviceRow[];
  device: DeviceSideView;
}

/** The edits the panel may make, each naming the file it belongs to. */
export type EditOp =
  | { op: "device.set"; label: string; address: string }
  | { op: "device.rename"; from: string; to: string }
  | { op: "device.remove"; label: string }
  | { op: "trust.add"; address: string }
  | { op: "trust.remove"; address: string }
  | { op: "trust.label"; address: string; label: string };

/** One device's answer to "can I reach you, and how fast". */
export interface PingResult {
  label: string;
  address: string;
  /** True only when the device answered a real call. */
  ok: boolean;
  /** Round trip in milliseconds; present only when the device answered. */
  rttMs?: number;
  /** The relay's view at ping time, for telling failures apart. */
  registered?: boolean;
  online?: boolean;
  error?: string;
}
