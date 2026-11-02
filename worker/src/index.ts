import { requireUser } from "./auth.ts";
import * as consoleApi from "./console.ts";
import type { Env } from "./db.ts";
import * as device from "./device.ts";
import { ApiError, failure, json } from "./http.ts";

const ID = "([0-9a-fA-F-]{36})";

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;
    try {
      if (path === "/api/health") return json({ ok: true, service: "exe", now: Math.floor(Date.now() / 1000) });

      if (path === "/v1/pairings" && method === "POST") return await device.startPairing(request, env);
      let match = path.match(new RegExp(`^/v1/pairings/${ID}$`));
      if (match && method === "GET") return await device.pollPairing(request, env, match[1]!);
      match = path.match(new RegExp(`^/v1/devices/${ID}/events$`));
      if (match && method === "GET") return await device.eventStream(request, env, match[1]!);
      match = path.match(new RegExp(`^/v1/devices/${ID}/heartbeat$`));
      if (match && method === "POST") return await device.heartbeat(request, env, match[1]!);
      match = path.match(new RegExp(`^/v1/devices/${ID}/calls/${ID}/(received|result)$`));
      if (match && method === "POST") {
        return match[3] === "received"
          ? await device.markReceived(request, env, match[1]!, match[2]!)
          : await device.submitResult(request, env, match[1]!, match[2]!);
      }
      if (path.startsWith("/v1/")) throw new ApiError(404, "unknown device endpoint");

      if (path.startsWith("/api/")) {
        const userId = await requireUser(request, env);
        if (path === "/api/me" && method === "GET") return await consoleApi.me(env, userId);
        if (path === "/api/account/challenge" && method === "GET") return await consoleApi.challenge(env, userId);
        if (path === "/api/account" && method === "PUT") return await consoleApi.registerAccount(env, userId, request);
        if (path === "/api/devices" && method === "GET") return await consoleApi.listDevices(env, userId);
        if (path === "/api/calls" && method === "GET") return await consoleApi.listCalls(env, userId, url);
        match = path.match(new RegExp(`^/api/devices/${ID}$`));
        if (match && method === "DELETE") return await consoleApi.revokeDevice(env, userId, match[1]!);
        match = path.match(new RegExp(`^/api/devices/${ID}/calls$`));
        if (match && method === "POST") return await consoleApi.createCall(env, userId, match[1]!, request);
        match = path.match(/^\/api\/pairings\/([A-Za-z0-9-]+)$/);
        if (match && method === "GET") return await consoleApi.readPairing(env, userId, match[1]!);
        if (match && method === "POST") return await consoleApi.approvePairing(env, userId, match[1]!, request);
        if (match && method === "DELETE") return await consoleApi.denyPairing(env, userId, match[1]!);
        match = path.match(new RegExp(`^/api/calls/${ID}$`));
        if (match && method === "GET") return await consoleApi.readCall(env, userId, match[1]!);
        match = path.match(new RegExp(`^/api/calls/${ID}/cancel$`));
        if (match && method === "POST") return await consoleApi.cancelCall(env, userId, match[1]!);
        throw new ApiError(404, "unknown console endpoint");
      }

      if (method === "GET" || method === "HEAD") return await env.ASSETS.fetch(request);
      throw new ApiError(404, "not found");
    } catch (error) {
      return failure(error);
    }
  },
};
