// Signs a release manifest with the eXe release key.
//
//   EXE_RELEASE_KEY="$(cat release.pem)" node scripts/sign-manifest.mjs artifacts/manifest.json
//
// The signature covers `exe release manifest v1\n` and then the exact bytes of
// the file, the same prefix `clients/crates/exe-core/src/release.rs` verifies.
// The private key is the repository secret `EXE_RELEASE_KEY`; its public half
// must be the `RELEASE_KEY` compiled into the client, so this refuses to produce
// a signature no device would accept — that failure would otherwise only show up
// on a device, after the release was already published.
import { readFileSync, writeFileSync } from "node:fs";
import { createPrivateKey, createPublicKey, sign, verify } from "node:crypto";

const CONTEXT = Buffer.from("exe release manifest v1\n");
const SOURCE = new URL("../clients/crates/exe-core/src/release.rs", import.meta.url);

function fail(message) {
  console.error(`sign-manifest: ${message}`);
  process.exit(1);
}

const file = process.argv[2] ?? "artifacts/manifest.json";
const pem = process.env.EXE_RELEASE_KEY ?? "";
if (pem.trim() === "") fail("EXE_RELEASE_KEY is not set");

let key;
try {
  key = createPrivateKey(pem);
} catch (error) {
  fail(`EXE_RELEASE_KEY is not a PEM Ed25519 private key: ${error.message}`);
}
if (key.asymmetricKeyType !== "ed25519") fail(`EXE_RELEASE_KEY is ${key.asymmetricKeyType}, not ed25519`);

const publicKey = createPublicKey(key);
const der = publicKey.export({ type: "spki", format: "der" });
const raw = der.subarray(der.length - 32).toString("hex");
const trusted = /RELEASE_KEY: &str = "([0-9a-f]{64})"/.exec(readFileSync(SOURCE, "utf8"));
if (!trusted) fail("cannot read RELEASE_KEY from clients/crates/exe-core/src/release.rs");
if (trusted[1] !== raw) {
  fail(
    `this key's public half is ${raw}, but the client trusts ${trusted[1]}; ` +
      "a release signed with it would be refused by every device",
  );
}

const bytes = readFileSync(file);
const message = Buffer.concat([CONTEXT, bytes]);
const signature = sign(null, message, key);
if (!verify(null, message, publicKey, signature)) fail("the signature does not verify");

writeFileSync(`${file}.sig`, `${signature.toString("base64")}\n`);
console.log(`sign-manifest: signed ${file} (${bytes.length} bytes) with ${raw}`);
