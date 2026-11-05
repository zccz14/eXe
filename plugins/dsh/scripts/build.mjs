// Two artifacts, two module systems.
//
// `lib/index.js` is the Host half: one self-contained ESM file. The eXe protocol
// is imported from `shared/protocol.ts` at the repo root — the same file the
// relay's tests pin against the Rust implementation — and is bundled here rather
// than copied, so there is exactly one implementation.
//
// `lib/client.js` is the browser half. The harness module system does not load
// ES modules: it executes a factory with a `require` bound to its shared module
// table, so the bundle is a CommonJS body wrapped in the one registration call
// that system reads (`window.__ModuleLoader__.load`).
import { readFileSync, rmSync, writeFileSync } from "node:fs";
import { build } from "esbuild";

const PACKAGE_NAME = "dsh-plugin-exe";

await build({
  entryPoints: ["src/index.ts"],
  outfile: "lib/index.js",
  bundle: true,
  format: "esm",
  platform: "node",
  target: "node22",
  // The harness owns these instances; a second copy would split runtime identity.
  external: ["@deepseek-ai/*"],
  legalComments: "none",
  logLevel: "warning",
  banner: {
    js: "// dsh-plugin-exe — built from plugins/dsh/src. Do not edit; see src/index.ts.",
  },
});

await build({
  entryPoints: ["src/client/index.tsx"],
  outfile: "lib/client.body.js",
  bundle: true,
  format: "cjs",
  platform: "browser",
  target: "es2022",
  jsx: "automatic",
  // Seeded by the shell; requiring our own copy would split React's identity.
  external: ["react", "react/jsx-runtime", "react-dom", "react-dom/client", "@deepseek-ai/cordis"],
  define: { "process.env.NODE_ENV": '"production"' },
  legalComments: "none",
  logLevel: "warning",
});

const body = readFileSync("lib/client.body.js", "utf8")
  .replace(/^\/\/# sourceMappingURL=.*$/m, "")
  .trimEnd();
writeFileSync(
  "lib/client.js",
  `window.__ModuleLoader__.load({ id: ${JSON.stringify(PACKAGE_NAME)}, factory: (require) => { ` +
    `var module = { exports: {} }; var exports = module.exports;\n${body}\n` +
    `return module.exports; } });\n`,
);
rmSync("lib/client.body.js");
console.log("built lib/index.js and lib/client.js");
