import * as consoleApi from "./console.ts";
import { authenticateConsole, type Env } from "./db.ts";
import * as device from "./device.ts";
import * as releases from "./releases.ts";
import { ApiError, failure, json } from "./http.ts";
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
    "access-control-allow-headers": "content-type, x-exe-address, x-exe-timestamp, x-exe-nonce, x-exe-signature",
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

export default {
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
      let match = path.match(new RegExp(`^/v1/agents/${ADDRESS}$`));
      if (match && method === "PUT") return await device.registerAgent(request, env, match[1]!);
      match = path.match(new RegExp(`^/v1/agents/${ADDRESS}/stream$`));
      if (match && method === "GET") return await device.eventStream(request, env, match[1]!);
      match = path.match(new RegExp(`^/v1/agents/${ADDRESS}/calls/${CALL_ID}/(received|result)$`));
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
          if (path === "/api/devices" && method === "GET") return await consoleApi.listDevices(env, address);
          if (path === "/api/devices" && method === "POST") return await consoleApi.addDevice(env, address, request);
          if (path === "/api/calls" && method === "GET") return await consoleApi.listCalls(env, address, url);
          const match = path.match(new RegExp(`^/api/devices/${ADDRESS}$`));
          if (match && method === "DELETE") return await consoleApi.removeDevice(env, address, match[1]!);
          const deviceCalls = path.match(new RegExp(`^/api/devices/${ADDRESS}/calls$`));
          if (deviceCalls && method === "POST") return await consoleApi.createCall(env, address, deviceCalls[1]!, request);
          const readCall = path.match(new RegExp(`^/api/calls/${CALL_ID}$`));
          if (readCall && method === "GET") return await consoleApi.readCall(env, address, readCall[1]!);
          const cancel = path.match(new RegExp(`^/api/calls/${CALL_ID}/cancel$`));
          if (cancel && method === "POST") return await consoleApi.cancelCall(env, address, cancel[1]!);
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
