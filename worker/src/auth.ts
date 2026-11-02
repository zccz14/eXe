// AuthMini access-token verification (EdDSA over JWKS) with an in-isolate cache.
import { ed25519 } from "@noble/curves/ed25519.js";
import { unb64u, utf8 } from "../../shared/protocol.ts";
import type { Env } from "./db.ts";
import { ApiError } from "./http.ts";

interface JwksCache {
  origin: string;
  keys: Map<string, Uint8Array>;
  expiresAt: number;
}

const CACHE_MS = 5 * 60 * 1000;
let cache: JwksCache | null = null;

function decodeJson(part: string): Record<string, unknown> {
  return JSON.parse(new TextDecoder().decode(unb64u(part))) as Record<string, unknown>;
}

async function jwks(env: Env, force = false): Promise<Map<string, Uint8Array>> {
  if (!force && cache && cache.origin === env.AUTH_ISSUER && cache.expiresAt > Date.now()) return cache.keys;
  const response = await fetch(new URL("/jwks", env.AUTH_ISSUER));
  if (!response.ok) throw new ApiError(503, "identity provider unavailable");
  const body = (await response.json()) as { keys?: Array<Record<string, unknown>> };
  const keys = new Map<string, Uint8Array>();
  for (const key of body.keys ?? []) {
    if (key.kty !== "OKP" || key.crv !== "Ed25519" || typeof key.kid !== "string" || typeof key.x !== "string") continue;
    keys.set(key.kid, unb64u(key.x));
  }
  if (keys.size === 0) throw new ApiError(503, "identity provider returned no usable keys");
  cache = { origin: env.AUTH_ISSUER, keys, expiresAt: Date.now() + CACHE_MS };
  return keys;
}

/** AUTH_AUDIENCE accepts a comma-separated list; a token matching any entry is accepted. */
export function acceptedAudiences(env: Env): string[] {
  return (env.AUTH_AUDIENCE ?? "").split(",").map((value) => value.trim()).filter(Boolean);
}

export interface Identity {
  userId: string;
  expiresAt: number;
}

export async function verifyAccessToken(env: Env, token: string): Promise<Identity> {
  const parts = token.split(".");
  if (parts.length !== 3) throw new ApiError(401, "malformed access token");
  const [rawHeader, rawPayload, rawSignature] = parts as [string, string, string];
  const header = decodeJson(rawHeader);
  if (header.alg !== "EdDSA") throw new ApiError(401, "unsupported token algorithm");
  const kid = typeof header.kid === "string" ? header.kid : "";
  const payload = decodeJson(rawPayload);
  const message = utf8(`${rawHeader}.${rawPayload}`);
  const signature = unb64u(rawSignature);

  let key = (await jwks(env)).get(kid);
  if (!key) key = (await jwks(env, true)).get(kid);
  if (!key || !ed25519.verify(signature, message, key)) throw new ApiError(401, "invalid access token signature");

  if (payload.iss !== env.AUTH_ISSUER) throw new ApiError(401, "unexpected token issuer");
  const audiences = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  const accepted = acceptedAudiences(env);
  if (!accepted.some((audience) => audiences.includes(audience))) throw new ApiError(401, "token was minted for another audience");
  const now = Math.floor(Date.now() / 1000);
  const expiresAt = typeof payload.exp === "number" ? payload.exp : 0;
  if (expiresAt <= now) throw new ApiError(401, "access token expired");
  if (typeof payload.nbf === "number" && payload.nbf > now + 60) throw new ApiError(401, "access token not yet valid");
  if (typeof payload.sub !== "string" || payload.sub.length < 8) throw new ApiError(401, "access token has no subject");
  return { userId: payload.sub, expiresAt };
}

export async function requireUser(request: Request, env: Env): Promise<string> {
  const header = request.headers.get("authorization") ?? "";
  if (!header.toLowerCase().startsWith("bearer ")) throw new ApiError(401, "missing bearer token");
  return (await verifyAccessToken(env, header.slice(7).trim())).userId;
}
