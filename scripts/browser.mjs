// Emulates the console: holds the only copy of the account key, signs calls and
// opens results. Nothing here ever reaches the relay in the clear.
import {
  addressOf,
  b64u,
  buildCall,
  newIdentity,
  openResult,
  randomBytes,
  signAccount,
  signRequest,
  verifyCall,
} from "../shared/protocol.ts";

export const now = () => Math.floor(Date.now() / 1000);

/** Signed headers for a device request: no bearer token exists. */
export function signedHeaders(identity, method, path) {
  const auth = {
    method,
    path,
    address: addressOf(identity),
    timestamp: now(),
    nonce: b64u(randomBytes(16)),
  };
  return {
    "x-exe-timestamp": String(auth.timestamp),
    "x-exe-nonce": auth.nonce,
    "x-exe-signature": signRequest(identity.seed, auth),
  };
}

export function makeBrowser() {
  const identity = newIdentity();
  const address = addressOf(identity);

  return {
    identity,
    address,
    async register(base, auth) {
      const me = await fetch(`${base}/api/me`, { headers: auth }).then((r) => r.json());
      const challenge = await fetch(`${base}/api/account/challenge`, { headers: auth }).then((r) => r.json());
      const fields = { address, userId: me.account_id, nonce: challenge.nonce, issuedAt: now() };
      const response = await fetch(`${base}/api/account`, {
        method: "PUT",
        headers: { ...auth, "content-type": "application/json" },
        body: JSON.stringify({ address, nonce: fields.nonce, issued_at: fields.issuedAt, sig: signAccount(identity.seed, fields) }),
      });
      if (!response.ok) throw new Error(`account registration failed: ${response.status} ${await response.text()}`);
      return response.json();
    },
    async addDevice(base, auth, deviceAddress, label) {
      const response = await fetch(`${base}/api/devices`, {
        method: "POST",
        headers: { ...auth, "content-type": "application/json" },
        body: JSON.stringify({ address: deviceAddress, label }),
      });
      if (!response.ok) throw new Error(`adding the device failed: ${response.status} ${await response.text()}`);
      return response.json();
    },
    signCall(deviceAddress, name, args, ttl = 300) {
      const issuedAt = now();
      return buildCall({
        seed: identity.seed,
        issuer: address,
        device: deviceAddress,
        callId: crypto.randomUUID(),
        name,
        args: JSON.stringify(args),
        issuedAt,
        expiresAt: issuedAt + ttl,
      });
    },
    async call(base, auth, deviceAddress, name, args) {
      const envelope = this.signCall(deviceAddress, name, args);
      const response = await fetch(`${base}/api/devices/${deviceAddress}/calls`, {
        method: "POST",
        headers: { ...auth, "content-type": "application/json" },
        body: JSON.stringify(envelope),
      });
      if (!response.ok) throw new Error(`call failed: ${response.status} ${await response.text()}`);
      return response.json();
    },
    open(call, result) {
      return JSON.parse(openResult({ seed: identity.seed, call, result }));
    },
    verify: verifyCall,
  };
}
