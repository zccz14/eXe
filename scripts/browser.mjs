// Emulates the console: holds the only copy of its key, signs every request, and
// signs calls. Nothing here ever reaches the relay in the clear.
import {
  addressOf,
  buildCall,
  newIdentity,
  openResult,
  requestHeaders,
  verifyCall,
} from "../shared/protocol.ts";

export const now = () => Math.floor(Date.now() / 1000);

/** Signed headers for a relay request: devices put the address in the path, the console in a header. */
export function signedHeaders(identity, method, path) {
  return requestHeaders(identity, method, path);
}

export function makeBrowser() {
  const identity = newIdentity();
  const address = addressOf(identity);

  /** One self-signed console request. `path` may carry a query; only the pathname is signed. */
  async function request(base, method, path, body) {
    const pathname = path.split("?")[0];
    const response = await fetch(`${base}${path}`, {
      method,
      headers: {
        ...signedHeaders(identity, method, pathname),
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) throw new Error(`${method} ${pathname} failed: ${response.status} ${await response.text()}`);
    return response.status === 204 ? null : response.json();
  }

  return {
    identity,
    address,
    request,
    signCall(deviceAddress, name, args, ttl = 300) {
      const issuedAt = now();
      return buildCall({
        seed: identity.seed,
        caller: address,
        device: deviceAddress,
        callId: crypto.randomUUID(),
        name,
        args: JSON.stringify(args),
        issuedAt,
        expiresAt: issuedAt + ttl,
      });
    },
    async call(base, deviceAddress, name, args) {
      return request(base, "POST", `/api/devices/${deviceAddress}/calls`, this.signCall(deviceAddress, name, args));
    },
    open(call, result) {
      return JSON.parse(openResult({ seed: identity.seed, call, result }));
    },
    verify: verifyCall,
  };
}
