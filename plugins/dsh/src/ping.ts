// "Is this device actually reachable from here, and how fast?"
//
// Registration and online state are the relay's opinion — it can only tell us
// whether a device checked in recently. A ping is the device's own answer: one
// `shell` call that echoes, measured from the moment we hand the sealed envelope
// to the relay until the sealed result is back and opened. That covers the whole
// path: this key, the relay queue, the device's trust list, its exec, and the
// crypto on both ends.
import type { PingResult } from "./contract.ts";
import type { Relay } from "./relay.ts";

/** How long the device may take before a ping counts as unanswered. */
export const PING_TIMEOUT_SECONDS = 6;

/** Tight pacing: the reported number should be the round trip, not our polling. */
const PING_POLL = { startMs: 20, ceilingMs: 120 };

export interface PingOptions {
  /** Total budget for one ping, including the wait. Defaults to a little over PING_TIMEOUT_SECONDS. */
  timeoutMs?: number;
}

function reason(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function hint(error: unknown): string {
  const text = reason(error);
  if (/expired|no answer|no result|abort|timed? ?out/i.test(text)) {
    return "设备没有回应：它可能没把这台 harness 的地址加进 trust，或者命令被它的进程丢掉了";
  }
  return text;
}

/**
 * One device, one round trip.
 *
 * The relay's own view is probed first because it is cheap and it tells the two
 * failures apart: an offline device is a different problem from a relay nobody
 * can reach, and neither is worth six seconds of waiting.
 */
export async function pingDevice(
  relay: Relay,
  label: string,
  address: string,
  options: PingOptions = {},
): Promise<PingResult> {
  let registered: boolean;
  let online: boolean;
  try {
    const status = await relay.device(address);
    registered = status.registered;
    online = status.online;
  } catch (error) {
    return { label, address, ok: false, error: `中继不可达：${reason(error)}` };
  }
  if (!online) {
    return {
      label,
      address,
      ok: false,
      registered,
      online: false,
      error: registered ? "设备离线：中继最近没见到它" : "设备还没在中继登记（在设备上跑一次 `exe`）",
    };
  }

  const budget = options.timeoutMs ?? (PING_TIMEOUT_SECONDS + 2) * 1000;
  const started = Date.now();
  try {
    await relay.call({
      device: address,
      name: "shell",
      args: { command: "echo ping", timeout_seconds: PING_TIMEOUT_SECONDS },
      ttlSeconds: PING_TIMEOUT_SECONDS,
      signal: AbortSignal.timeout(budget),
      poll: PING_POLL,
    });
    return { label, address, ok: true, registered, online, rttMs: Date.now() - started };
  } catch (error) {
    return { label, address, ok: false, registered, online, error: hint(error) };
  }
}

/** Ping several devices at once; one slow device does not hold the others back. */
export async function pingDevices(
  relay: Relay,
  targets: ReadonlyArray<{ label: string; address: string }>,
  options: PingOptions = {},
): Promise<PingResult[]> {
  return await Promise.all(targets.map((target) => pingDevice(relay, target.label, target.address, options)));
}
