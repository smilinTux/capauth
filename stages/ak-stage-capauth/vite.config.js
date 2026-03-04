import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  plugins: [
    vue({
      // Enable Vue custom element compilation
      customElement: true,
    }),
  ],
  build: {
    lib: {
      entry: "src/index.js",
      name: "AkStageCapauth",
      fileName: "ak-stage-capauth",
      formats: ["es", "umd"],
    },
    rollupOptions: {
      // Bundle everything — Authentik loads this as a standalone JS file
      external: [],
    },
    // Keep readable for store review submission
    minify: false,
    sourcemap: true,
  },
  test: {
    environment: "happy-dom",
    include: ["src/**/*.test.js"],
  },
});
