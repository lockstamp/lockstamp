import { resolve } from "node:path";
import { defineConfig } from "vite";

const web = resolve(import.meta.dirname, "web");

// The home page plus the guide pages; each guide lives in its own folder so it gets a clean URL.
export const GUIDES = ["supabase-rls-checker", "supabase-rls-not-working", "is-my-lovable-app-secure"];

export default defineConfig({
  root: "web",
  base: "./",
  build: {
    outDir: "../dist-web",
    emptyOutDir: true,
    target: "es2022",
    rollupOptions: {
      input: {
        main: resolve(web, "index.html"),
        ...Object.fromEntries(GUIDES.map((slug) => [slug, resolve(web, slug, "index.html")])),
      },
    },
  },
  // PGlite ships its WebAssembly and extension bundles as assets; pre-bundling breaks their URLs.
  optimizeDeps: { exclude: ["@electric-sql/pglite"] },
  worker: { format: "es" },
});
