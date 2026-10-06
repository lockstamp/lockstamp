// Node-only helpers that read a project from disk. Everything else runs in the browser too.
import { readdir, readFile, stat } from "node:fs/promises";
import { basename, extname, join, relative } from "node:path";
import type { SqlFile } from "./load.js";
import type { CodeFile } from "./secrets.js";

const SKIP_DIRS = new Set([
  "node_modules", ".git", "dist", "build", ".next", ".nuxt", ".svelte-kit", ".turbo", ".vercel",
  ".netlify", "coverage", ".cache", "lockstamp-report", "supabase-guard-report",
]);
const SKIP_FILES = new Set(["package-lock.json", "pnpm-lock.yaml", "yarn.lock", "bun.lockb", "bun.lock"]);
const TEXT_EXTENSIONS = new Set([
  ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs", ".vue", ".svelte", ".astro", ".html", ".json",
  ".toml", ".yaml", ".yml", ".sql", ".py", ".rb", ".go", ".php", ".txt", ".md",
]);
const MAX_BYTES = 1_000_000;

export async function readMigrations(dir: string): Promise<SqlFile[]> {
  const names = (await readdir(dir)).filter((f) => f.toLowerCase().endsWith(".sql")).sort();
  return Promise.all(names.map(async (file) => ({ file, sql: await readFile(join(dir, file), "utf8") })));
}

export async function readCodeFiles(root: string): Promise<CodeFile[]> {
  const files = await listFiles(root);
  return Promise.all(files.map(async (file) => ({ path: relative(root, file), text: await readFile(file, "utf8") })));
}

async function listFiles(dir: string): Promise<string[]> {
  const out: string[] = [];
  for (const entry of await readdir(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (!SKIP_DIRS.has(entry.name)) out.push(...(await listFiles(full)));
      continue;
    }
    if (!entry.isFile() || SKIP_FILES.has(entry.name)) continue;
    const name = basename(full);
    if (!name.startsWith(".env") && !TEXT_EXTENSIONS.has(extname(name).toLowerCase())) continue;
    if ((await stat(full)).size > MAX_BYTES) continue;
    out.push(full);
  }
  return out;
}
