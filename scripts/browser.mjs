// Emulates the console: holds the only copy of the account private keys.
import {
  b64u,
  newAccountKeys,
  openResult,
  signAccount,
  signApproval,
  signCall,
  unb64u,
} from "../shared/protocol.ts";

export function makeBrowser() {
  const keys = newAccountKeys();
  const sigPub = b64u(keys.sigPub);
  const kexPub = b64u(keys.kexPub);
  const now = () => Math.floor(Date.now() / 1000);

  return {
    sigPub,
    kexPub,
    async register(base, auth) {
      const challenge = await fetch(`${base}/api/account/challenge`, { headers: auth }).then((r) => r.json());
      const fields = { userId: challenge.user_id ?? (await fetch(`${base}/api/me`, { headers: auth }).then((r) => r.json())).account_id, nonce: challenge.nonce, sigPub, kexPub, issuedAt: now() };
      const response = await fetch(`${base}/api/account`, {
        method: "PUT",
        headers: { ...auth, "content-type": "application/json" },
        body: JSON.stringify({ sig_pub: sigPub, kex_pub: kexPub, nonce: fields.nonce, issued_at: fields.issuedAt, sig: signAccount(keys.sigSk, fields) }),
      });
      if (!response.ok) throw new Error(`account registration failed: ${response.status} ${await response.text()}`);
      return response.json();
    },
    async approve(base, auth, pairing, label) {
      const fields = {
        pairingId: pairing.pairing_id,
        deviceId: pairing.device_id,
        accountId: pairing.account_id ?? null,
        accountSigPub: sigPub,
        accountKexPub: kexPub,
        deviceSigPub: pairing.device_sig_pub,
        deviceKexPub: pairing.device_kex_pub,
        issuedAt: now(),
      };
      const response = await fetch(`${base}/api/pairings/${pairing.user_code}`, {
        method: "POST",
        headers: { ...auth, "content-type": "application/json" },
        body: JSON.stringify({ label, issued_at: fields.issuedAt, sig: signApproval(keys.sigSk, fields) }),
      });
      if (!response.ok) throw new Error(`approval failed: ${response.status} ${await response.text()}`);
      return response.json();
    },
    signDeviceCall(deviceId, accountId, name, args, ttl = 300) {
      const issuedAt = now();
      const callId = crypto.randomUUID();
      const nonce = b64u(crypto.getRandomValues(new Uint8Array(16)));
      const serialized = JSON.stringify(args);
      const sig = signCall(keys.sigSk, { callId, deviceId, accountId, name, args: serialized, nonce, issuedAt, expiresAt: issuedAt + ttl });
      return { id: callId, name, args: serialized, nonce, issued_at: issuedAt, expires_at: issuedAt + ttl, sig };
    },
    async call(base, auth, deviceId, accountId, name, args) {
      const body = this.signDeviceCall(deviceId, accountId, name, args);
      const response = await fetch(`${base}/api/devices/${deviceId}/calls`, {
        method: "POST",
        headers: { ...auth, "content-type": "application/json" },
        body: JSON.stringify(body),
      });
      if (!response.ok) throw new Error(`call failed: ${response.status} ${await response.text()}`);
      return response.json();
    },
    open(callId, deviceId, envelope) {
      return JSON.parse(openResult({ accountKexSk: keys.kexSk, callId, deviceId, envelope }));
    },
    kexSecret: keys.kexSk,
    sigSeed: keys.sigSk,
    unb64u,
  };
}
