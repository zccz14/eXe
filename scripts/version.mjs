// One version for every eXe component. Nothing advances on its own.
//
//   node scripts/version.mjs              # sync everything to the root version
//   node scripts/version.mjs --check      # fail if anything drifted (CI)
//   node scripts/version.mjs --set 0.2.0  # move the whole product to a new version
import { readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = dirname(fileURLToPath(new URL("../package.json", import.meta.url)));
const path = (name) => join(root, name);
const args = process.argv.slice(2);
const check = args.includes("--check");
// Accept `--set 0.2.0`, a bare `0.2.0`, or whatever the package manager leaves us.
const next = args.find((value) => /^\d+\.\d+\.\d+$/.test(value));

const rootPath = path("package.json");
const rootPkg = JSON.parse(readFileSync(rootPath, "utf8"));

if (args.includes("--set") && !next) {
  console.error("usage: node scripts/version.mjs --set X.Y.Z");
  process.exit(2);
}
if (next) {
  rootPkg.version = next;
  writeFileSync(rootPath, `${JSON.stringify(rootPkg, null, 2)}\n`);
}

const version = rootPkg.version;
const drift = [];
const changed = [];

function syncJson(rel) {
  const file = path(rel);
  const data = JSON.parse(readFileSync(file, "utf8"));
  if (data.version === version) return;
  if (check) {
    drift.push(`${rel} is ${data.version}`);
    return;
  }
  data.version = version;
  writeFileSync(file, `${JSON.stringify(data, null, 2)}\n`);
  changed.push(rel);
}

function syncVersionField(rel, pattern, label, global = false) {
  const file = path(rel);
  const text = readFileSync(file, "utf8");
  const match = text.match(pattern);
  if (!match) {
    drift.push(`${rel}: cannot find ${label}`);
    return;
  }
  if (match[2] === version) return;
  if (check) {
    drift.push(`${rel}: ${label} is ${match[2]}`);
    return;
  }
  const expression = global ? new RegExp(pattern.source, "g") : pattern;
  writeFileSync(file, text.replace(expression, `$1${version}$3`));
  changed.push(`${rel} (${label})`);
}

syncJson("console/package.json");
syncVersionField("agent/Cargo.toml", /(\[workspace\.package\][\s\S]*?\nversion = ")([^"]+)(")/, "workspace.package.version");
syncVersionField(
  "agent/Cargo.lock",
  /(\[\[package\]\]\nname = "(?:exe|exe-core|exe-mobile)"\nversion = ")([^"]+)(")/,
  "workspace crate versions",
  true,
);

if (check && drift.length > 0) {
  console.error(`version drift (every component must be ${version}):`);
  for (const problem of drift) console.error(`  - ${problem}`);
  console.error("run `pnpm version:sync` and commit the result");
  process.exit(1);
}
if (check) {
  console.log(`version ${version}: every component agrees`);
} else if (changed.length === 0) {
  console.log(`version ${version}: already consistent`);
} else {
  console.log(`version ${version}: updated ${changed.join(", ")}`);
}
