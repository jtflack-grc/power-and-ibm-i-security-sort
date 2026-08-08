import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  // Default base for FastAPI single-process; Pages workflow overrides with --base=./
  base: "/",
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
      "/sample-triage.json": {
        target: "http://127.0.0.1:8000",
        changeOrigin: true,
      },
    },
  },
});
