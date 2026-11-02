// Client binaries are published as GitHub Release assets. The relay resolves the
// latest release and can proxy the download, so the console never has to send a
// user to GitHub with a personal token. See docs/DEPLOY.md.
import type { Env } from "./db.ts";
import { ApiError, json } from "./http.ts";

const CACHE_MS = 5 * 60 * 1000;
const ASSET_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,120}$/;

interface GitHubAsset {
  name: string;
  size: number;
  url: string;
  browser_download_url: string;
}

interface GitHubRelease {
  tag_name: string;
  published_at: string;
  html_url: string;
  assets: GitHubAsset[];
}

let cache: { repo: string; expiresAt: number; release: GitHubRelease | null } | null = null;

export function repository(env: Env): string {
  return (env.GITHUB_REPO ?? "zccz14/eXe").trim();
}

function releasePage(env: Env): string {
  return `https://github.com/${repository(env)}/releases/latest`;
}

async function latestRelease(env: Env, force = false): Promise<GitHubRelease | null> {
  const repo = repository(env);
  // A private repository needs a token; without one the console falls back to the
  // GitHub release page instead of pretending the download works.
  if (!env.GITHUB_RELEASES_TOKEN) return null;
  if (!force && cache && cache.repo === repo && cache.expiresAt > Date.now()) return cache.release;

  const response = await fetch(`https://api.github.com/repos/${repo}/releases/latest`, {
    headers: {
      authorization: `Bearer ${env.GITHUB_RELEASES_TOKEN}`,
      accept: "application/vnd.github+json",
      "x-github-api-version": "2022-11-28",
      "user-agent": "exe-relay",
    },
  });
  if (response.status === 404) {
    cache = { repo, expiresAt: Date.now() + CACHE_MS, release: null };
    return null;
  }
  if (!response.ok) throw new ApiError(503, `github releases responded ${response.status}`);
  const release = (await response.json()) as GitHubRelease;
  cache = { repo, expiresAt: Date.now() + CACHE_MS, release };
  return release;
}

/** GET /api/releases/latest — what the console renders. */
export async function latest(env: Env): Promise<Response> {
  const release = await latestRelease(env);
  if (!release) {
    return json({
      configured: Boolean(env.GITHUB_RELEASES_TOKEN),
      repository: repository(env),
      version: null,
      tag: null,
      published_at: null,
      release_url: releasePage(env),
      assets: [],
    });
  }
  return json({
    configured: true,
    repository: repository(env),
    version: release.tag_name.replace(/^v/, ""),
    tag: release.tag_name,
    published_at: release.published_at,
    release_url: release.html_url,
    assets: release.assets.map((asset) => ({
      name: asset.name,
      size: asset.size,
      url: `/download/${encodeURIComponent(asset.name)}`,
    })),
  });
}

/** GET /download/{asset} — redirect to the signed asset URL, or stream it through. */
export async function download(env: Env, name: string): Promise<Response> {
  if (!ASSET_NAME.test(name)) throw new ApiError(400, "bad asset name");
  const release = await latestRelease(env);
  if (!release) throw new ApiError(404, "no release has been published");
  const asset = release.assets.find((item) => item.name === name);
  if (!asset) throw new ApiError(404, "unknown asset");

  const response = await fetch(asset.url, {
    headers: {
      authorization: `Bearer ${env.GITHUB_RELEASES_TOKEN}`,
      accept: "application/octet-stream",
      "user-agent": "exe-relay",
    },
    redirect: "manual",
  });
  const location = response.headers.get("location");
  if (location) {
    // The signed CDN URL is short-lived and does not need our token.
    return new Response(null, { status: 302, headers: { location, "cache-control": "no-store" } });
  }
  if (!response.ok || !response.body) throw new ApiError(502, "github did not return the asset");
  const headers = new Headers({
    "content-type": response.headers.get("content-type") ?? "application/octet-stream",
    "content-disposition": `attachment; filename="${name}"`,
    "cache-control": "public, max-age=300",
  });
  const length = response.headers.get("content-length");
  if (length) headers.set("content-length", length);
  return new Response(response.body, { status: 200, headers });
}
