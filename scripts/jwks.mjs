// Test-only AuthMini stand-in: one Ed25519 key, a JWKS endpoint and a token minter.
import { createServer } from "node:http";
import { generateKeyPairSync, sign } from "node:crypto";

export function startJwks(port = 8788) {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const jwk = publicKey.export({ format: "jwk" });
  const issuer = `http://127.0.0.1:${port}`;
  const server = createServer((request, response) => {
    if (request.url === "/jwks") {
      response.writeHead(200, { "content-type": "application/json" });
      response.end(JSON.stringify({ keys: [{ ...jwk, kid: "test-key", alg: "EdDSA", use: "sig" }] }));
      return;
    }
    response.writeHead(404).end();
  });
  server.listen(port, "127.0.0.1");

  function mint(sub, audience = "exe.test", ttl = 3600) {
    const now = Math.floor(Date.now() / 1000);
    const header = { alg: "EdDSA", kid: "test-key", typ: "JWT" };
    const payload = { sub, aud: audience, iss: issuer, iat: now, exp: now + ttl };
    const encode = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
    const body = `${encode(header)}.${encode(payload)}`;
    const signature = sign(null, Buffer.from(body), privateKey).toString("base64url");
    return `${body}.${signature}`;
  }

  return {
    url: issuer,
    mint,
    close: () => new Promise((resolve) => server.close(resolve)),
  };
}
