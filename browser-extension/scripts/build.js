/**
 * Build script for the CapAuth browser extension.
 *
 * Bundles OpenPGP.js into lib/openpgp-bundle.js for use by the
 * service worker. The rest of the extension files are plain ES modules
 * that reference the bundle.
 *
 * Usage:
 *   npm install
 *   npm run build
 */

const esbuild = require("esbuild");
const path = require("path");

const ROOT = path.join(__dirname, "..");

async function build() {
  // Bundle the openpgp wrapper (lib/openpgp.js) which imports from 'openpgp'
  // into a single self-contained file for the extension.
  await esbuild.build({
    entryPoints: [path.join(ROOT, "lib", "openpgp.js")],
    bundle: true,
    outfile: path.join(ROOT, "lib", "openpgp-bundle.js"),
    format: "esm",
    target: ["chrome120"],
    minify: false,
    sourcemap: false,
    // Keep the module exports so background.js can import from it
    external: [],
  });

  console.log("Built lib/openpgp-bundle.js");

  // After building, update background.js import path:
  // Change: import ... from "./lib/openpgp-stub.js"
  // To:     import ... from "./lib/openpgp-bundle.js"
  console.log("");
  console.log("Next steps:");
  console.log("  1. Update background.js import to use './lib/openpgp-bundle.js'");
  console.log("  2. Load the extension in chrome://extensions (developer mode)");
  console.log("  3. Test with a CapAuth-enabled service");
}

build().catch((err) => {
  console.error("Build failed:", err);
  process.exit(1);
});
