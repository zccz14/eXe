export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, message: string, code?: string) {
    super(message);
    this.status = status;
    this.code = code ?? "error";
  }
}

const JSON_HEADERS = { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" };

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}
export function empty(status = 204): Response {
  return new Response(null, { status, headers: { "cache-control": "no-store" } });
}
export function failure(error: unknown): Response {
  if (error instanceof ApiError) return json({ error: error.message, code: error.code }, error.status);
  const message = error instanceof Error ? error.message : "internal error";
  return json({ error: message, code: "internal" }, 500);
}
export async function body<T>(request: Request): Promise<T> {
  const type = request.headers.get("content-type") ?? "";
  if (!type.includes("application/json")) throw new ApiError(415, "expected application/json");
  const text = await request.text();
  if (text.length > 65536) throw new ApiError(413, "request body too large");
  try {
    return JSON.parse(text) as T;
  } catch {
    throw new ApiError(400, "malformed JSON body");
  }
}
export function now(): number {
  return Math.floor(Date.now() / 1000);
}
