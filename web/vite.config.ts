import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  base: "./",
  build: {
    rollupOptions: {
      input: {
        apt2rule: resolve(import.meta.dirname, "index.html"),
        threat2apt: resolve(import.meta.dirname, "threat2apt/index.html"),
      },
    },
  },
  test: { include: ["src/**/*.test.ts"] },
});
