import { defineConfig } from "vite";

export default defineConfig({
  // Built into the Go binary and served from the same origin, so assets are
  // referenced relatively rather than from an absolute root.
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
    // Content-hashed filenames. Fixed names would be a real bug against the
    // immutable caching an asset path invites: a deploy would leave every
    // browser running the old app indefinitely, and the symptom is a fix that
    // will not appear no matter how many times you reload.
    rollupOptions: {
      output: {
        entryFileNames: "assets/[name]-[hash].js",
        chunkFileNames: "assets/[name]-[hash].js",
        assetFileNames: "assets/[name]-[hash].[ext]",
      },
    },
  },
  server: {
    // `npm run dev` proxies to a locally running StatusHub, so the dashboard
    // behaves in development exactly as it does when embedded.
    proxy: {
      "/v1": "http://127.0.0.1:8081",
      "/healthz": "http://127.0.0.1:8081",
      "/metrics": "http://127.0.0.1:8081",
    },
  },
});
