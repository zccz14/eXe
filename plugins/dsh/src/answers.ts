// Reading what a device answered.
//
// The device's reply is the same JSON document the eXe CLI and the MCP server
// consume: `{ ok, output: { tool, exit_code, stdout, stderr }, code?, error? }`.
// A result too big for one row arrives as an attachment instead — and that
// attachment is the whole document, not a stream of stdout, so it has to be
// parsed rather than treated as text.
import type { Outcome } from "./relay.ts";

/** One device's line in the devices tool, exactly as rendered. */
export interface DeviceRow {
  device: string;
  address: string;
  registered?: boolean;
  online?: boolean;
  platform?: string;
  version?: string;
  last_seen_at?: number;
  error?: string;
}

/** The device's answer, whole. Past the inline budget it is the attachment that holds it. */
export function whole(outcome: Outcome): Record<string, unknown> {
  if (outcome.attachment !== undefined) {
    try {
      const parsed = JSON.parse(outcome.attachment) as unknown;
      if (isRecord(parsed)) return parsed;
    } catch {
      // A malformed attachment is not the answer; the row still is.
    }
  }
  return isRecord(outcome.answer) ? outcome.answer : {};
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function text(value: unknown): string {
  return typeof value === "string" ? value : "";
}

/** One shell answer, flattened into the canonical value the tool returns. */
export interface ShellAnswer {
  device: string;
  command: string;
  exit_code: number;
  stdout: string;
  stderr: string;
  truncated: boolean;
  timed_out: boolean;
  error?: string;
}

export function shellAnswer(device: string, command: string, outcome: Outcome): ShellAnswer {
  const body = whole(outcome);
  const output = isRecord(body.output) ? body.output : {};
  const exitCode = output.exit_code;
  const answer: ShellAnswer = {
    device,
    command,
    exit_code: typeof exitCode === "number" ? exitCode : -1,
    stdout: text(output.stdout),
    stderr: text(output.stderr),
    truncated: output.truncated === true,
    timed_out: body.code === "timeout",
  };
  if (typeof body.error === "string") answer.error = body.error;
  return answer;
}

/** The device's stdout as one line of base64, or a reason it cannot be used. */
export function imageBase64(device: string, path: string, outcome: Outcome): string {
  const body = whole(outcome);
  const output = isRecord(body.output) ? body.output : {};
  const base64 = text(output.stdout).split(/\s+/).join("");
  // A preview of base64 is still base64 — short, and pretending to be a picture.
  if (output.truncated === true) {
    const failure = isRecord(body.blob) ? text(body.blob.error) : "";
    throw new Error(
      `${device}: ${path} did not arrive whole — the device had to cut the answer to a preview` +
        `${failure.length > 0 ? ` (${failure})` : ""}. Downscale it on the device first.`,
    );
  }
  if (base64.length === 0) {
    throw new Error(`${device}: nothing came back for ${path} — not a file, or base64 is missing there`);
  }
  return base64;
}

function trimmed(value: string): string {
  return value.endsWith("\n") ? value.slice(0, -1) : value;
}

/** `[mac] $ ls -la` / exit 0 / output — the shape the model reads fastest. */
export function renderShell(answer: ShellAnswer): string {
  const parts = [`[${answer.device}] $ ${answer.command}`, `exit ${answer.exit_code}`];
  if (answer.stdout.length > 0) parts.push(trimmed(answer.stdout));
  if (answer.stderr.length > 0) parts.push("--- stderr ---", trimmed(answer.stderr));
  if (answer.truncated) parts.push("[output truncated by the device]");
  if (answer.timed_out) parts.push("[the device killed the command at its timeout]");
  if (answer.error !== undefined) parts.push(`[device error: ${answer.error}]`);
  return parts.join("\n");
}

/** One line per device, plus the address the caller has to be trusted as. */
export function renderDevices(caller: string, rows: DeviceRow[]): string {
  const lines = [`caller ${caller}`];
  if (rows.length === 0) {
    lines.push(
      "no devices configured: add [devices] entries to the eXe caller config (~/.config/exe/mcp.toml) " +
        "or set `devices` in this plugin's config",
    );
    return lines.join("\n");
  }
  for (const row of rows) {
    if (row.error !== undefined) {
      lines.push(`${row.device}  ${row.address}  unreachable: ${row.error}`);
      continue;
    }
    const state = row.online === true ? "online" : "offline";
    const registered = row.registered === true ? "" : "  (not registered yet)";
    const platform = [row.platform, row.version].filter((part) => part !== undefined).join(" ");
    lines.push(
      `${row.device}  ${row.address}  ${state}${registered}${platform.length > 0 ? `  ${platform}` : ""}`,
    );
  }
  return lines.join("\n");
}
