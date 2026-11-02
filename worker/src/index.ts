import * as consoleApi from "./console.ts";
import { authenticateConsole, deleteSettledCalls, type Env } from "./db.ts";
import * as device from "./device.ts";
import * as releases from "./releases.ts";
import { ApiError, failure, json, now } from "./http.ts";
import pkg from "../../package.json" with { type: "json" };

/** The console is served from Pages, so it is a different origin than the relay. */
function corsHeaders(request: Request, env: Env): Headers | null {
  const origin = request.headers.get("origin");
  if (!origin) return null;
  const allowed = (env.CONSOLE_ORIGINS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  if (!allowed.includes(origin)) return null;
  const headers = new Headers({
    "access-control-allow-origin": origin,
    vary: "origin",
    "access-control-allow-headers": "content-type, x-exe-address, x-exe-timestamp, x-exe-signature",
    "access-control-allow-methods": "GET, POST, PUT, DELETE, OPTIONS",
    "access-control-max-age": "86400",
  });
  return headers;
}

function withCors(request: Request, env: Env, response: Response): Response {
  const headers = corsHeaders(request, env);
  if (!headers) return response;
  headers.forEach((value, key) => response.headers.set(key, value));
  return response;
}

const ADDRESS = "([1-9A-HJ-NP-Za-km-z]{32,64})";
const CALL_ID = "([0-9a-zA-Z-]{8,64})";

/** How long a settled call stays readable. D1 is 10 GB and a row can be megabytes. */
const CALL_RETENTION_DAYS = 7;
/** Rows per sweep: every deleted row is a row written, so this is a budget. */
const RETENTION_BATCH = 2000;

export default {
  /**
   * Retention, hourly. A call that is over and older than the window is deleted;
   * nothing queued, received or unsettled is ever touched. Firing once an hour
   * rather than once a day keeps a backlog from growing faster than the sweeper.
   */
  async scheduled(_controller: ScheduledController, env: Env): Promise<void> {
    const deleted = await deleteSettledCalls(env, now() - CALL_RETENTION_DAYS * 24 * 60 * 60, RETENTION_BATCH);
    console.log(`retention: deleted ${deleted} settled calls older than ${CALL_RETENTION_DAYS} days`);
  },

  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    try {
      if (method === "OPTIONS" && path.startsWith("/api/")) {
        const headers = corsHeaders(request, env);
        if (!headers) throw new ApiError(403, "origin is not allowed");
        return new Response(null, { status: 204, headers });
      }
      if (path === "/api/health") return withCors(request, env, json({ ok: true, service: "exe", version: pkg.version, now: Math.floor(Date.now() / 1000) }));

      // --- client binaries: latest GitHub Release, proxied -------------------
      if (path === "/api/releases/latest" && method === "GET") return withCors(request, env, await releases.latest(env));
      const asset = path.match(/^\/download\/([A-Za-z0-9][A-Za-z0-9._-]{0,120})$/);
      if (asset && method === "GET") return await releases.download(env, asset[1]!);

      // --- devices: self-signed, no bearer token -------------------------------
      let match = path.match(new RegExp(`^/v1/devices/${ADDRESS}$`));
      if (match && method === "PUT") return await device.registerDevice(request, env, match[1]!);
      match = path.match(new RegExp(`^/v1/devices/${ADDRESS}/stream$`));
      if (match && method === "GET") return await device.eventStream(request, env, match[1]!);
      match = path.match(new RegExp(`^/v1/devices/${ADDRESS}/calls/${CALL_ID}/blob$`));
      if (match && method === "PUT") return await device.uploadBlob(request, env, match[1]!, match[2]!);
      match = path.match(new RegExp(`^/v1/devices/${ADDRESS}/calls/${CALL_ID}/(received|result)$`));
      if (match && method === "POST") {
        return match[3] === "received"
          ? await device.markReceived(request, env, match[1]!, match[2]!)
          : await device.submitResult(request, env, match[1]!, match[2]!);
      }
      if (path.startsWith("/v1/")) throw new ApiError(404, "unknown device endpoint");

      // --- console: the same self-signature, address in a header ----------------
      if (path.startsWith("/api/")) {
        const address = await authenticateConsole(request, env);
        const answer = async (): Promise<Response> => {
          if (path === "/api/me" && method === "GET") return await consoleApi.me(address);
          if (path === "/api/calls" && method === "GET") return await consoleApi.listCalls(env, address, url);
          let match = path.match(new RegExp(`^/api/devices/${ADDRESS}$`));
          if (match && method === "GET") return await consoleApi.deviceStatus(env, match[1]!);
          match = path.match(new RegExp(`^/api/devices/${ADDRESS}/calls$`));
          if (match && method === "POST") return await consoleApi.createCall(env, address, match[1]!, request);
          match = path.match(new RegExp(`^/api/calls/${CALL_ID}$`));
          if (match && method === "GET") return await consoleApi.readCall(env, address, match[1]!);
          match = path.match(new RegExp(`^/api/calls/${CALL_ID}/blob$`));
          if (match && method === "GET") return await consoleApi.readBlob(env, address, match[1]!);
          match = path.match(new RegExp(`^/api/calls/${CALL_ID}/cancel$`));
          if (match && method === "POST") return await consoleApi.cancelCall(env, address, match[1]!);
          throw new ApiError(404, "unknown console endpoint");
        };
        return withCors(request, env, await answer());
      }

      if (method === "GET" || method === "HEAD") return await env.ASSETS.fetch(request);
      throw new ApiError(404, "not found");
    } catch (error) {
      return withCors(request, env, failure(error));
    }
  },
};
