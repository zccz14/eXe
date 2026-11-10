// Client binaries are published as GitHub Release assets. The relay reads them
// without any credential and without the GitHub API:
//
//   1. `GET https://github.com/<repo>/releases/latest` answers 302 with the tag.
//   2. `GET https://github.com/<repo>/releases/download/<tag>/manifest.json`
//      lists the files (published by the release workflow).
//
// The GitHub API is not used: unauthenticated API calls are limited to 60/hour
// per IP, and a Worker shares its egress IPs with everyone else on Cloudflare.
import type { Env } from "./db.ts";
import { ApiError, json } from "./http.ts";

const CACHE_MS = 10 * 60 * 1000;
const ASSET_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$/;

interface ReleaseFile {
  name: string;
  size: number;
  sha256?: string;
}

interface ReleaseManifest {
  version: string;
  tag: string;
  built_at?: string;
  files: ReleaseFile[];
}

interface Resolved {
  tag: string;
  manifest: ReleaseManifest;
  /** The exact bytes the signature covers: a device verifies before it parses. */
  bytes: ArrayBuffer;
  /** Detached Ed25519 signature, base64. Empty when the release was not signed. */
  signature: string;
}

interface CacheEntry extends Resolved {
  repo: string;
  expiresAt: number;
}

let cache: CacheEntry | null = null;

export function repository(env: Env): string {
  return (env.GITHUB_REPO ?? "zccz14/eXe").trim();
}

function releasePage(env: Env): string {
  return `https://github.com/${repository(env)}/releases/latest`;
}

async function resolveTag(env: Env): Promise<string | null> {
  const response = await fetch(`https://github.com/${repository(env)}/releases/latest`, {
    redirect: "manual",
    headers: { "user-agent": "exe-relay" },
  });
  const location = response.headers.get("location") ?? "";
  const match = /\/releases\/tag\/([^/?#]+)$/.exec(location);
  return match ? decodeURIComponent(match[1]!) : null;
}

async function resolveManifest(env: Env, tag: string): Promise<Resolved | null> {
  const base = `https://github.com/${repository(env)}/releases/download/${tag}`;
  const response = await fetch(`${base}/manifest.json`, { headers: { "user-agent": "exe-relay" } });
  if (!response.ok) return null;
  const bytes = await response.arrayBuffer();
  let manifest: ReleaseManifest;
  try {
    manifest = JSON.parse(new TextDecoder().decode(bytes)) as ReleaseManifest;
  } catch {
    return null;
  }
  if (!Array.isArray(manifest.files) || typeof manifest.tag !== "string") return null;
  // The signature rides along uncached-but-for-our-cache: without it a device
  // refuses the release, which is the point of the whole arrangement.
  const signed = await fetch(`${base}/manifest.json.sig`, { headers: { "user-agent": "exe-relay" } });
  const signature = signed.ok ? await signed.text() : "";
  return { tag, manifest, bytes, signature };
}

async function latestRelease(env: Env): Promise<Resolved | null> {
  const repo = repository(env);
  if (!repo) return null;
  if (cache && cache.repo === repo && cache.expiresAt > Date.now()) return cache;
  try {
    const tag = await resolveTag(env);
    if (!tag) return null;
    const resolved = await resolveManifest(env, tag);
    if (!resolved) return null;
    cache = { repo, expiresAt: Date.now() + CACHE_MS, ...resolved };
    return cache;
  } catch {
    // GitHub unreachable: keep serving the last answer we had, if any.
    return cache && cache.repo === repo ? cache : null;
  }
}

/** GET /api/releases/latest — what the console renders. */
export async function latest(env: Env): Promise<Response> {
  const resolved = await latestRelease(env);
  if (!resolved) {
    return json({
      configured: false,
      repository: repository(env),
      version: null,
      tag: null,
      published_at: null,
      release_url: releasePage(env),
      assets: [],
    });
  }
  const { tag, manifest } = resolved;
  return json({
    configured: true,
    repository: repository(env),
    version: manifest.version || tag.replace(/^v/, ""),
    tag,
    published_at: manifest.built_at ?? null,
    release_url: `https://github.com/${repository(env)}/releases/tag/${tag}`,
    assets: manifest.files.map((file) => ({
      name: file.name,
      size: file.size,
      url: `/download/${encodeURIComponent(file.name)}`,
    })),
  });
}

/** GET /download/{asset} — only files the release manifest lists are served. */
export async function download(env: Env, name: string): Promise<Response> {
  if (!ASSET_NAME.test(name)) throw new ApiError(400, "bad asset name");
  const resolved = await latestRelease(env);
  if (!resolved) throw new ApiError(404, "no release has been published");
  if (!resolved.manifest.files.some((file) => file.name === name)) throw new ApiError(404, "unknown asset");
  return new Response(null, {
    status: 302,
    headers: {
      location: `https://github.com/${repository(env)}/releases/download/${resolved.tag}/${encodeURIComponent(name)}`,
      "cache-control": "no-store",
    },
  });
}

/**
 * GET /api/releases/manifest.json — the exact bytes the signature covers.
 *
 * Devices do not parse `/api/releases/latest` to decide anything: this endpoint
 * hands over the document, `manifest.json.sig` hands over the signature, and the
 * client decides. Proxying the release asset verbatim is what keeps the relay a
 * courier here: it cannot edit a manifest into something a device would accept.
 */
export async function manifest(env: Env): Promise<Response> {
  const resolved = await latestRelease(env);
  if (!resolved) throw new ApiError(404, "no release has been published");
  return new Response(resolved.bytes, {
    headers: { "content-type": "application/json", "cache-control": "public, max-age=600" },
  });
}

/** GET /api/releases/manifest.json.sig — detached Ed25519 signature, base64. */
export async function signature(env: Env): Promise<Response> {
  const resolved = await latestRelease(env);
  if (!resolved) throw new ApiError(404, "no release has been published");
  if (resolved.signature.trim() === "") throw new ApiError(503, "this release is not signed");
  return new Response(resolved.signature, {
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "public, max-age=600" },
  });
}
