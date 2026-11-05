// The panel's HTTP surface, registered on the harness's own web server.
//
// Two routes, both under one prefix: read the state, apply one edit. The files
// they touch are the user's own eXe configuration, so the route is deliberately
// narrow — same-origin only, JSON only, one bounded body, no free-form paths.
import type { IncomingMessage, ServerResponse } from "node:http";
import type { EditOp, PingResult } from "./contract.ts";
import type { ExeStateStore } from "./state.ts";

/** The shape `ctx.webServer.register` accepts. Structural, so no host package is imported. */
export interface WebRoute {
  kind: "exact" | "prefix";
  path: string;
  handler: (req: IncomingMessage, res: ServerResponse) => void | Promise<void>;
}

/** The slice of `@deepseek-ai/dsh-host-webserver` this plugin uses. */
export interface WebServerLike {
  register(route: WebRoute): () => void;
}

/** One prefix for everything the panel reads and writes. */
export const ROUTE_PREFIX = "/exe/api";

const MAX_BODY_BYTES = 64 * 1024;

function send(res: ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(text),
    "cache-control": "no-store",
  });
  res.end(text);
}

/**
 * A browser that sends `Origin` must be on this very host. The route writes
 * files, so a page on another origin must not be able to drive it — and without
 * CORS headers it could not read a response anyway, but the write would land.
 */
function sameOrigin(req: IncomingMessage): boolean {
  const origin = req.headers.origin;
  if (origin === undefined) return true;
  const host = req.headers.host;
  if (host === undefined) return false;
  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

async function readJson(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk as Uint8Array);
    size += buffer.length;
    if (size > MAX_BODY_BYTES) throw new Error("request body is too large");
    chunks.push(buffer);
  }
  const text = Buffer.concat(chunks).toString("utf8").trim();
  if (text.length === 0) throw new Error("empty request body");
  try {
    return JSON.parse(text) as unknown;
  } catch (error) {
    throw new Error(`body is not JSON: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** What the routes need from the plugin: the two files, and a way to reach a device. */
export interface ExeRoutesDeps {
  store: ExeStateStore;
  /** Ping the named devices, or every configured one when `labels` is omitted. */
  ping(labels?: string[]): Promise<PingResult[]>;
}

/** Register the panel's routes and return the disposer that removes them. */
export function registerExeRoutes(webServer: WebServerLike, deps: ExeRoutesDeps): () => void {
  const handler = async (req: IncomingMessage, res: ServerResponse): Promise<void> => {
    try {
      if (!sameOrigin(req)) {
        send(res, 403, { error: "cross-origin request refused" });
        return;
      }
      const url = new URL(req.url ?? "/", "http://localhost");
      if (url.pathname === `${ROUTE_PREFIX}/state`) {
        if (req.method !== "GET") {
          send(res, 405, { error: "use GET" });
          return;
        }
        send(res, 200, deps.store.state());
        return;
      }
      if (url.pathname === `${ROUTE_PREFIX}/edit`) {
        if (req.method !== "POST") {
          send(res, 405, { error: "use POST" });
          return;
        }
        if (!(req.headers["content-type"] ?? "").includes("application/json")) {
          send(res, 415, { error: "send application/json" });
          return;
        }
        const body = (await readJson(req)) as Partial<EditOp>;
        if (typeof body !== "object" || body === null || typeof body.op !== "string") {
          send(res, 400, { error: "an edit names its `op`" });
          return;
        }
        send(res, 200, deps.store.edit(body as EditOp));
        return;
      }
      if (url.pathname === `${ROUTE_PREFIX}/ping`) {
        if (req.method !== "POST") {
          send(res, 405, { error: "use POST" });
          return;
        }
        if (!(req.headers["content-type"] ?? "").includes("application/json")) {
          send(res, 415, { error: "send application/json" });
          return;
        }
        const body = (await readJson(req)) as { labels?: unknown };
        const labels = body.labels;
        if (labels !== undefined && (!Array.isArray(labels) || labels.some((label) => typeof label !== "string"))) {
          send(res, 400, { error: "`labels` is a list of device labels" });
          return;
        }
        send(res, 200, { results: await deps.ping(labels as string[] | undefined) });
        return;
      }
      send(res, 404, { error: `no route for ${req.method} ${url.pathname}` });
    } catch (error) {
      send(res, 400, { error: error instanceof Error ? error.message : String(error) });
    }
  };
  return webServer.register({ kind: "prefix", path: ROUTE_PREFIX, handler });
}
