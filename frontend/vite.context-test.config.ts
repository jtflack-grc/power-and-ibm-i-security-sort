import { defineConfig } from "vite";

// Bundle the browser calculator exactly as the SPA does; its upstream ESM
// extensionless imports do not resolve in bare Node.
export default defineConfig({
  build: {
    outDir: ".context-tests",
    lib: { entry: "tests/contextAssessment.test.ts", formats: ["es"], fileName: () => "context-tests.mjs" },
    rolldownOptions: { external: [/^node:/] },
  },
});
