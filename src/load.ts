import { PGlite, type Extension } from "@electric-sql/pglite";
import { citext } from "@electric-sql/pglite/contrib/citext";
import { moddatetime } from "@electric-sql/pglite/contrib/moddatetime";
import { pg_trgm } from "@electric-sql/pglite/contrib/pg_trgm";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { uuid_ossp } from "@electric-sql/pglite/contrib/uuid_ossp";
import { SUPABASE_SHIM } from "./shim.js";
import { splitSql } from "./split.js";
import type { LoadIssue } from "./types.js";

export interface SqlFile {
  file: string;
  sql: string;
}

const SEARCH_PATH = `set search_path = "$user", public, extensions;`;
const TRANSACTION_CONTROL = /^(begin|commit|rollback|end|start\s+transaction)\b/i;
// pgvector and PostGIS types can't be loaded offline; for access-rule analysis they behave like text.
const UNSUPPORTED_TYPE = /type "?(?:extensions\.)?(vector|halfvec|sparsevec|geography|geometry)"? does not exist/i;

function rewriteUnsupportedTypes(statement: string): string {
  return statement
    .replace(/\b(?:extensions\.)?(?:vector|halfvec|sparsevec)\b(?:\s*\(\s*\d+\s*\))?/gi, "text")
    .replace(/\b(?:extensions\.)?(?:geography|geometry)\b(?:\s*\(\s*[A-Za-z]+\s*(?:,\s*\d+\s*)?\))?/gi, "text");
}

// In a browser, every test database would download each extension bundle again (a check builds
// three). Keep one local copy per worker instead; Node reads the bundles from disk anyway.
const bundles = new Map<string, Promise<URL | null>>();

const IN_NODE = Boolean((globalThis as { process?: { versions?: { node?: string } } }).process?.versions?.node);

function downloadOnce(ext: Extension): Extension {
  if (IN_NODE) return ext;
  return {
    ...ext,
    setup: async (pg, opts, clientOnly) => {
      const result = await ext.setup(pg, opts, clientOnly);
      if (!result.bundlePath) return result;
      const key = result.bundlePath.toString();
      if (!bundles.has(key)) bundles.set(key, keepLocal(key));
      const local = await bundles.get(key)!;
      return local ? { ...result, bundlePath: local } : result;
    },
  };
}

async function keepLocal(url: string): Promise<URL | null> {
  try {
    const response = await fetch(url);
    if (!response.ok) return null;
    let bundle = await response.blob();
    // Some servers send the .gz with "Content-Encoding: gzip", so the browser has already unpacked
    // it. PGlite unpacks local copies itself, so pack it again.
    if (response.headers.get("Content-Encoding") === "gzip") {
      bundle = await new Response(bundle.stream().pipeThrough(new CompressionStream("gzip"))).blob();
    }
    return new URL(URL.createObjectURL(bundle));
  } catch {
    return null;
  }
}

const EXTENSIONS = Object.fromEntries(
  Object.entries({ pgcrypto, uuid_ossp, citext, pg_trgm, moddatetime }).map(([name, ext]) => [name, downloadOnce(ext)]),
);

export async function createDatabase(): Promise<PGlite> {
  const db = new PGlite({ extensions: EXTENSIONS });
  await db.exec(SUPABASE_SHIM);
  await db.exec(SEARCH_PATH);
  return db;
}

// Applies each statement on its own so one unsupported statement (e.g. a Supabase-only
// extension) is recorded as an issue instead of discarding the whole migration file.
export async function applySql(db: PGlite, files: SqlFile[]): Promise<LoadIssue[]> {
  const issues: LoadIssue[] = [];
  for (const { file, sql } of files) {
    for (const statement of splitSql(sql)) {
      if (TRANSACTION_CONTROL.test(stripLeadingComments(statement))) continue;
      const error = await run(db, statement);
      if (error) issues.push({ file, statement: summarize(statement), error });
    }
  }
  await db.exec(SEARCH_PATH);
  return issues;
}

// For SQL rebuilt from a snapshot: order isn't guaranteed (views on views, functions in checks),
// so failed statements are retried until a pass makes no progress.
export async function applyStatements(db: PGlite, file: string, statements: string[]): Promise<LoadIssue[]> {
  let pending = statements;
  let failed: { statement: string; error: string }[] = [];
  for (let pass = 0; pass < 6 && pending.length > 0; pass++) {
    failed = [];
    for (const statement of pending) {
      const error = await run(db, statement);
      if (error) failed.push({ statement, error });
    }
    if (failed.length === pending.length) break;
    pending = failed.map((f) => f.statement);
  }
  await db.exec(SEARCH_PATH);
  return failed.map((f) => ({ file, statement: summarize(f.statement), error: f.error }));
}

async function run(db: PGlite, statement: string): Promise<string | null> {
  try {
    await db.exec(statement);
    return null;
  } catch (err) {
    const message = (err as Error).message;
    if (UNSUPPORTED_TYPE.test(message)) {
      try {
        await db.exec(rewriteUnsupportedTypes(statement));
        return null;
      } catch {
        // fall through and report the original error
      }
    }
    return message;
  }
}

function stripLeadingComments(statement: string): string {
  return statement.replace(/^(\s*(--[^\n]*\n|\/\*[\s\S]*?\*\/))*\s*/, "");
}

function summarize(statement: string): string {
  const oneLine = stripLeadingComments(statement).replace(/\s+/g, " ");
  return oneLine.length > 160 ? `${oneLine.slice(0, 157)}...` : oneLine;
}
