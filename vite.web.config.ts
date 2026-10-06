import { defineConfig } from "vite";

export default defineConfig({
  root: "web",
  base: "./",
  build: { outDir: "../dist-web", emptyOutDir: true, target: "es2022" },
  // PGlite ships its WebAssembly and extension bundles as assets; pre-bundling breaks their URLs.
  optimizeDeps: { exclude: ["@electric-sql/pglite"] },
  worker: { format: "es" },
});
