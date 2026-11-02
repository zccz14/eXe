import { requireUser } from "./auth.ts";
import * as consoleApi from "./console.ts";
import type { Env } from "./db.ts";
import * as device from "./device.ts";
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
    "access-control-allow-headers": "authorization, content-type",
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

      // --- console: AuthMini JWT ---------------------------------------------
      if (path.startsWith("/api/")) {
        const userId = await requireUser(request, env);
        const answer = async (): Promise<Response> => {
          if (path === "/api/me" && method === "GET") return await consoleApi.me(env, userId);
          if (path === "/api/account/challenge" && method === "GET") return await consoleApi.challenge(env, userId);
          if (path === "/api/account" && method === "PUT") return await consoleApi.registerAccount(env, userId, request);
          if (path === "/api/devices" && method === "GET") return await consoleApi.listDevices(env, userId);
          if (path === "/api/devices" && method === "POST") return await consoleApi.addDevice(env, userId, request);
          if (path === "/api/calls" && method === "GET") return await consoleApi.listCalls(env, userId, url);
          const match = path.match(new RegExp(`^/api/devices/${ADDRESS}$`));
          if (match && method === "DELETE") return await consoleApi.removeDevice(env, userId, match[1]!);
          const deviceCalls = path.match(new RegExp(`^/api/devices/${ADDRESS}/calls$`));
          if (deviceCalls && method === "POST") return await consoleApi.createCall(env, userId, deviceCalls[1]!, request);
          const readCall = path.match(new RegExp(`^/api/calls/${CALL_ID}$`));
          if (readCall && method === "GET") return await consoleApi.readCall(env, userId, readCall[1]!);
          const cancel = path.match(new RegExp(`^/api/calls/${CALL_ID}/cancel$`));
          if (cancel && method === "POST") return await consoleApi.cancelCall(env, userId, cancel[1]!);
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
