import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { beforeAll, describe, expect, it } from "vitest";
import { runGuard, SNAPSHOT_QUERY, type GuardResult } from "../src/index.js";
import { readMigrations } from "../src/files.js";
import { applySql, createDatabase } from "../src/load.js";
import { splitSql } from "../src/split.js";

const demo = join(import.meta.dirname, "..", "examples", "vibe-notes");

describe("splitSql", () => {
  it("keeps semicolons inside strings, dollar-quoted bodies and comments", () => {
    const sql = [
      "select 'a;b';",
      "create function f() returns int language sql as $$ select 1; $$;",
      "-- a comment; with a semicolon",
      'select "x;y" from t; /* block; comment */',
      "select 2",
    ].join("\n");
    expect(splitSql(sql)).toHaveLength(4);
  });

  it("drops comment-only fragments", () => {
    expect(splitSql("-- just a comment\n;\n/* another */;")).toEqual([]);
  });
});

describe("demo app with typical AI-builder mistakes", () => {
  let result: GuardResult;
  const targets = (rule: string) => result.findings.filter((f) => f.rule === rule).map((f) => f.target);

  beforeAll(async () => {
    result = await runGuard({ projectDir: demo });
  }, 120_000);

  it("applies every demo migration", () => {
    expect(result.loadIssues).toEqual([]);
  });

  it("flags tables with Row Level Security off", () => {
    expect(targets("rls_disabled").sort()).toEqual(["public.app_settings", "public.profiles", "public.subscriptions"]);
  });

  it("flags the rules that open other users' notes", () => {
    expect(targets("policy_always_true")).toHaveLength(2);
  });

  it("flags the view that bypasses access rules", () => {
    expect(targets("view_bypasses_rls")).toEqual(["public.note_counts"]);
  });

  it("flags the admin function that hands out every user's email", () => {
    expect(targets("definer_function_reads_users")).toEqual(["public.get_all_emails()"]);
  });

  it("flags that users could make themselves admin", () => {
    expect(targets("protected_columns_editable")).toEqual(["public.profiles"]);
  });

  it("never lets users write their own billing rows", () => {
    expect(result.fixSql).not.toMatch(/on "public"\."subscriptions" for (insert|update|delete)/);
    expect(result.fixSql).toMatch(/grant update \([^)]*\) on "public"\."profiles"/);
    expect(result.fixSql).not.toMatch(/grant update \([^)]*"role"[^)]*\) on "public"\."profiles"/);
  });

  it("proves the view and function leaks before the fix", () => {
    const leaks = result.proof.filter((p) => p.before === true).map((p) => p.table);
    expect(leaks).toContain("public.note_counts");
    expect(leaks).toContain("public.get_all_emails()");
  });

  it("finds leaked secrets but not the public anon key", () => {
    const found = targets("secret_in_code");
    expect(found.some((t) => t.startsWith("src/lib/admin.ts"))).toBe(true);
    expect(found.some((t) => t.startsWith("src/config.ts"))).toBe(true);
    expect(found.some((t) => t.startsWith("src/lib/supabase.ts"))).toBe(false);
  });

  it("produces a fix that applies cleanly", () => {
    expect(result.fixIssues).toEqual([]);
  });

  it("proves attacks work before the fix", () => {
    expect(result.proof.filter((p) => p.before === true).length).toBeGreaterThanOrEqual(6);
  });

  it("proves every one of those attacks is blocked after the fix", () => {
    expect(result.proof.filter((p) => p.before === true && p.after !== false)).toEqual([]);
  });
});

async function projectWith(sql: string): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), "guard-project-"));
  await mkdir(join(dir, "supabase", "migrations"), { recursive: true });
  await writeFile(join(dir, "supabase", "migrations", "0001_init.sql"), sql);
  return dir;
}

async function snapshotOf(projectDir: string): Promise<string> {
  const db = await createDatabase();
  await applySql(db, await readMigrations(join(projectDir, "supabase", "migrations")));
  const { rows } = await db.query<{ snapshot: unknown }>(SNAPSHOT_QUERY);
  await db.close();
  const file = join(projectDir, "snapshot.json");
  await writeFile(file, JSON.stringify(rows[0].snapshot));
  return file;
}

describe("never reports an all-clear it didn't test", () => {
  it("marks a table untested when one of its rules can't be rebuilt", async () => {
    const dir = await projectWith(`
      create table public.notes (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id), body text);
      alter table public.notes enable row level security;
      create policy "anyone" on public.notes for select using (private.is_visible(user_id) or true);
    `);
    const result = await runGuard({ projectDir: dir, scanCode: false });
    const rules = result.findings.filter((f) => f.target === "public.notes").map((f) => f.rule);
    expect(rules).toContain("rules_not_rebuilt");
    expect(rules).not.toContain("rls_no_policies");
    const notesProof = result.proof.filter((p) => p.table === "public.notes");
    expect(notesProof.length).toBeGreaterThan(0);
    expect(notesProof.every((p) => p.before === null && p.after === null)).toBe(true);
  }, 120_000);
});

describe("snapshot mode", () => {
  it("keeps helper functions from a private schema", async () => {
    const dir = await projectWith(`
      create schema private;
      grant usage on schema private to authenticated;
      create table public.items (id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id), title text not null);
      alter table public.items enable row level security;
      create function private.can_see(uid uuid) returns boolean language sql security definer set search_path = '' as $$ select uid = auth.uid() $$;
      create policy "see own" on public.items for select to authenticated using (private.can_see(user_id));
    `);
    const file = await snapshotOf(dir);
    const fromMigrations = await runGuard({ projectDir: dir, scanCode: false });
    const fromSnapshot = await runGuard({ projectDir: dir, snapshotFile: file, scanCode: false });
    expect(fromMigrations.loadIssues).toEqual([]);
    expect(fromSnapshot.loadIssues).toEqual([]);
    expect(fromSnapshot.findings.map((f) => f.rule)).not.toContain("rules_not_rebuilt");
    expect(fromSnapshot.proof.map((p) => `${p.table}|${p.test}|${p.before}`).sort()).toEqual(
      fromMigrations.proof.map((p) => `${p.table}|${p.test}|${p.before}`).sort(),
    );
  }, 120_000);

  it("finds the same problems from a snapshot as from the migrations", async () => {
    const db = await createDatabase();
    await applySql(db, await readMigrations(join(demo, "supabase", "migrations")));
    const { rows } = await db.query<{ snapshot: unknown }>(SNAPSHOT_QUERY);
    await db.close();

    const dir = await mkdtemp(join(tmpdir(), "guard-"));
    const file = join(dir, "snapshot.json");
    await writeFile(file, JSON.stringify(rows[0].snapshot));

    const fromMigrations = await runGuard({ projectDir: demo, scanCode: false });
    const fromSnapshot = await runGuard({ projectDir: dir, snapshotFile: file, scanCode: false });
    const summary = (r: GuardResult) => ({
      findings: r.findings.map((f) => `${f.rule}|${f.target}`).sort(),
      proof: r.proof.map((p) => `${p.table}|${p.test}|${p.before}|${p.after}`).sort(),
    });

    expect(fromSnapshot.loadIssues).toEqual([]);
    expect(fromSnapshot.fixIssues).toEqual([]);
    expect(summary(fromSnapshot)).toEqual(summary(fromMigrations));
  }, 120_000);
});
