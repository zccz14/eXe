// One self-contained ESM file, because a published plugin is loaded by someone
// else's harness: no build step at install time, and no runtime dependency on
// the repo that produced it.
//
// The eXe protocol is imported from `shared/protocol.ts` at the repo root — the
// same file the relay's tests pin against the Rust implementation — and is
// bundled here rather than copied, so there is exactly one implementation.
import { build } from "esbuild";

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
