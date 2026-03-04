import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "happy-dom",
    globals: false,
    include: ["tests/**/*.test.js"],
    coverage: {
      provider: "v8",
      include: ["lib/**/*.js", "background.js", "content_scripts/**/*.js"],
      exclude: ["lib/openpgp-bundle.js", "lib/openpgp.js"],
    },
  },
});
