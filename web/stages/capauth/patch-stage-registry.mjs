#!/usr/bin/env node
/**
 * patch-stage-registry.mjs — register the CapAuth PGP stage in Authentik's flow
 * stage registry so the FlowExecutor can DISPATCH to the `ak-stage-capauth`
 * web component (cap11 fix).
 *
 * WHY THIS EXISTS
 * ---------------
 * Defining the `ak-stage-capauth` custom element (cap10, via the entrypoint
 * `import "#flow/stages/capauth/CapAuthStage"`) is NECESSARY but NOT SUFFICIENT.
 * In Authentik 2026.5.x the flow executor does NOT have a hard-coded
 * `switch (challenge.component)`. Instead `web/src/flow/FlowExecutor.ts`
 * (`renderChallenge()`) dispatches via a data-driven registry:
 *
 *     const stageEntry = StageMapping.registry.get(challenge.component);
 *     if (!stageEntry) { ...return "No stage found for component: ..."; }
 *
 * `StageMapping.registry` (web/src/flow/FlowExecutorStageFactory.ts) is built
 * from the `StageEntries` array in `web/src/flow/FlowExecutorStages.ts`:
 *
 *     public static readonly registry = new Map(
 *         StageEntries.map((entry) => [entry.stage, entry]),
 *     );
 *
 * So a server component name only renders in the browser if it appears as an
 * `{ stage, fetch }` entry in `StageEntries`. cap10 shipped the COMPONENT but
 * never added the registry ENTRY, so `registry.get("ak-stage-capauth")` was
 * undefined → the browser showed "No stage found for component:
 * ak-stage-capauth" even though the server returned that component. This script
 * inserts the missing entry, mirroring the stock `ak-stage-identification` /
 * `ak-stage-password` sibling entries EXACTLY:
 *
 *     {
 *         stage: "ak-stage-identification",
 *         fetch: () => import("#flow/stages/identification/IdentificationStage"),
 *     },
 *
 * For CapAuth the custom-element tag equals the server component name
 * (`ak-stage-capauth`, see @customElement in CapAuthStage.ts) and the stage uses
 * the default "standard" prop variant (host + challenge), so no `tag`/`variant`
 * override is needed — exactly like identification/password.
 *
 * NOTE on types: `stage: FlowChallengeComponentName` is a closed string-literal
 * union generated from @goauthentik/api and does NOT include "ak-stage-capauth",
 * so `tsc` would reject this entry. That is fine: the production image is built
 * with `npm run build` (scripts/build-web.mjs = esbuild, which STRIPS types and
 * does NOT type-check — `build` only depends on `build-locales`, not `tsc`).
 * The runtime registry is a plain Map keyed by string, so the entry works.
 *
 * Idempotent. FAILS LOUD (exit 1) if the anchor is missing (upstream moved) so
 * the Docker build breaks instead of silently shipping a broken executor.
 */
import { readFileSync, writeFileSync } from "node:fs";

const FILE = process.argv[2];
if (!FILE) {
  console.error("usage: node patch-stage-registry.mjs <path-to-FlowExecutorStages.ts>");
  process.exit(2);
}

const ANCHOR = "export const StageEntries: readonly StageEntry[] = [";

// The entry to inject. Mirrors the stock ak-stage-identification entry: the
// stage token equals the custom-element tag and the module is lazy-imported.
const ENTRY = [
  "    // CapAuth PGP passwordless stage (cap11): registers ak-stage-capauth in the",
  "    // flow stage registry so FlowExecutor.renderChallenge() can dispatch to it.",
  "    {",
  '        stage: "ak-stage-capauth",',
  '        fetch: () => import("#flow/stages/capauth/CapAuthStage"),',
  "    },",
].join("\n");

let src = readFileSync(FILE, "utf8");

if (src.includes('stage: "ak-stage-capauth"')) {
  console.log("✅ ak-stage-capauth already registered in StageEntries — no-op");
  process.exit(0);
}

const idx = src.indexOf(ANCHOR);
if (idx === -1) {
  console.error(
    "❌ FATAL: could not find StageEntries anchor in " +
      FILE +
      "\n   Anchor expected: " +
      JSON.stringify(ANCHOR) +
      "\n   Authentik upstream likely changed the stage-registry shape; update this patch."
  );
  process.exit(1);
}

const insertAt = idx + ANCHOR.length;
src = src.slice(0, insertAt) + "\n" + ENTRY + src.slice(insertAt);
writeFileSync(FILE, src);

// Verify the write actually landed.
const after = readFileSync(FILE, "utf8");
if (!after.includes('stage: "ak-stage-capauth"')) {
  console.error("❌ FATAL: insertion did not take effect in " + FILE);
  process.exit(1);
}
console.log("✅ Registered ak-stage-capauth in StageEntries (" + FILE + ")");
