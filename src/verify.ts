import type { PGlite } from "@electric-sql/pglite";
import { plural } from "./describe.js";
import { qualified, quoteIdent } from "./introspect.js";
import type { Column, DbSchema, ProbeRow, Table } from "./types.js";

export const ALICE = "a11ce000-0000-4000-8000-000000000001";
export const BOB = "b0b00000-0000-4000-8000-000000000002";
const VISITOR_ID = "c0ffee00-0000-4000-8000-000000000003";

// "least" seeds ordinary users; "most" is what an attacker would try to grant themselves.
type Privilege = "least" | "most";

const ROLE_COLUMN = /^(role|roles|user_type|account_type|access_level|permission|permissions)$/i;
const PLAN_COLUMN = /^(plan|tier|subscription_(plan|tier|status))$/i;
const FLAG_COLUMN = /^(is_admin|is_super_?admin|is_staff|is_moderator|is_verified|is_pro|is_premium|admin|premium|verified)$/i;
const PRIVILEGED_LABEL = "(admin|owner|super|moder|manager|editor|staff|master|root|lead)";

interface Attempt {
  ok: boolean;
  rows: number;
  affected: number;
  error?: string;
}

// Real values from seeded parent tables, so probe inserts satisfy foreign keys and only access rules decide.
type ForeignKeySamples = Map<string, string>;

// The attacker (Alice) is an ordinary user: no roles, no memberships. Every attempt is rolled back.
export async function runProbes(db: PGlite, schema: DbSchema): Promise<ProbeRow[]> {
  const seeded = await seed(db, schema);
  const samples = await foreignKeySamples(db, schema);
  const insertSql = (t: Table, owner: string | null, n: number, privilege: Privilege = "least") =>
    buildInsert(t, owner, n, privilege, samples);
  const results: ProbeRow[] = [];

  for (const t of schema.tables) {
    const name = `${t.schema}.${t.name}`;
    if (!seeded.has(name) || t.columns.length === 0) continue;
    const q = qualified(t.schema, t.name);

    if (t.ownerColumns.length > 0) {
      const owner = quoteIdent(t.ownerColumns[0]);
      const ofBob = `where ${owner} = '${BOB}'`;
      results.push(
        readProbe(name, "A visitor who isn't logged in can read rows", await attempt(db, "anon", null, `select count(*)::int as n from ${q}`)),
        writeProbe(name, "A visitor who isn't logged in can add rows", await attempt(db, "anon", null, insertSql(t, VISITOR_ID, 90))),
        readProbe(name, "A logged-in user can read another user's rows", await attempt(db, "authenticated", ALICE, `select count(*)::int as n from ${q} ${ofBob}`)),
        changeProbe(name, "A logged-in user can change another user's rows", await attempt(db, "authenticated", ALICE, `update ${q} set ${owner} = ${owner} ${ofBob}`)),
        changeProbe(name, "A logged-in user can delete another user's rows", await attempt(db, "authenticated", ALICE, `delete from ${q} ${ofBob}`)),
        writeProbe(name, "A logged-in user can add rows in another user's name", await attempt(db, "authenticated", ALICE, insertSql(t, BOB, 91))),
      );
      if (t.privilege) {
        results.push(
          writeProbe(name, "A logged-in user can give themselves a role or membership", await attempt(db, "authenticated", ALICE, insertSql(t, ALICE, 93, "most"))),
        );
      } else if (t.sensitive) {
        results.push(
          changeProbe(
            name,
            "A logged-in user can change their own billing records",
            await attempt(db, "authenticated", ALICE, `update ${q} set ${owner} = ${owner} where ${owner} = '${ALICE}'`),
          ),
        );
      } else if (t.protectedColumns.length > 0) {
        // Actually try to raise their own rights, so protective triggers get a chance to refuse.
        const column = t.columns.find((c) => c.name === t.protectedColumns[0]);
        if (column) {
          results.push(
            changeProbe(
              name,
              `A logged-in user can change their own ${t.protectedColumns.join(", ")}`,
              await attempt(db, "authenticated", ALICE, `update ${q} set ${quoteIdent(column.name)} = ${dummyValue(column, 94, "most")} where ${owner} = '${ALICE}'`),
            ),
          );
        }
      }
    } else {
      const first = quoteIdent(t.columns[0].name);
      results.push(
        writeProbe(name, "A visitor who isn't logged in can add rows", await attempt(db, "anon", null, insertSql(t, null, 92))),
        changeProbe(name, "A visitor who isn't logged in can change rows", await attempt(db, "anon", null, `update ${q} set ${first} = ${first}`)),
        changeProbe(name, "A visitor who isn't logged in can delete rows", await attempt(db, "anon", null, `delete from ${q}`)),
      );
    }
  }

  for (const v of schema.views) {
    if (v.materialized || v.securityInvoker || !v.apiReadable) continue;
    results.push(
      readProbe(
        `${v.schema}.${v.name}`,
        "A visitor who isn't logged in can read data through this view",
        await attempt(db, "anon", null, `select count(*)::int as n from ${qualified(v.schema, v.name)}`),
      ),
    );
  }

  for (const f of schema.functions) {
    if (!f.readsAuthUsers || !f.anonCanExecute || f.argCount > 0 || f.returnsVoid) continue;
    results.push(
      readProbe(
        `${f.schema}.${f.name}()`,
        "A visitor who isn't logged in can call this function and get user data",
        await attempt(db, "anon", null, `select count(*)::int as n from ${qualified(f.schema, f.name)}()`),
      ),
    );
  }
  return results;
}

async function seed(db: PGlite, schema: DbSchema): Promise<Set<string>> {
  const seeded = new Set<string>();
  await db.exec("set session_replication_role = replica");
  try {
    // The visitor exists as an account but never sends a login, mirroring the public API key.
    await db.exec(
      `insert into auth.users (id, email, raw_user_meta_data) values
         ('${ALICE}', 'alice@example.com', '{"full_name":"Alice"}'),
         ('${BOB}', 'bob@example.com', '{"full_name":"Bob"}'),
         ('${VISITOR_ID}', 'visitor@example.com', '{}')
       on conflict (id) do nothing`,
    );
    for (const t of schema.tables) {
      // Bob may hold roles; Alice never does, so her access reflects an ordinary stranger's.
      const owners = t.privilege ? [BOB] : t.ownerColumns.length > 0 ? [ALICE, BOB] : [null, null];
      let ok = true;
      for (const [i, owner] of owners.entries()) {
        try {
          await db.exec(buildInsert(t, owner, i + 1, "least", new Map()));
        } catch {
          ok = false;
        }
      }
      if (ok) seeded.add(`${t.schema}.${t.name}`);
    }
  } finally {
    await db.exec("set session_replication_role = origin");
  }
  return seeded;
}

async function foreignKeySamples(db: PGlite, schema: DbSchema): Promise<ForeignKeySamples> {
  const samples: ForeignKeySamples = new Map();
  for (const t of schema.tables) {
    for (const fk of t.foreignKeys) {
      if (fk.refSchema === "auth") continue;
      try {
        const r = await db.query<{ v: string | null }>(
          `select ${quoteIdent(fk.refColumn)}::text as v from ${qualified(fk.refSchema, fk.refTable)} where ${quoteIdent(fk.refColumn)} is not null limit 1`,
        );
        const value = r.rows[0]?.v;
        if (value !== undefined && value !== null) samples.set(`${t.schema}.${t.name}.${fk.column}`, value);
      } catch {
        // parent table missing or unreadable: the probe falls back to a dummy value
      }
    }
  }
  return samples;
}

// Probes run with triggers and foreign keys switched on, so an app's own protective triggers count.
async function attempt(db: PGlite, role: "anon" | "authenticated", sub: string | null, sql: string): Promise<Attempt> {
  await db.exec("begin");
  try {
    await db.query("select set_config('request.jwt.claims', $1, true)", [JSON.stringify(sub ? { sub, role } : { role })]);
    await db.exec(`set local role ${role}`);
    const result = await db.query<{ n?: number }>(sql);
    return { ok: true, rows: Number(result.rows[0]?.n ?? 0), affected: result.affectedRows ?? 0 };
  } catch (err) {
    const e = err as Error & { code?: string };
    return { ok: false, rows: 0, affected: 0, error: `${e.code ?? ""} ${e.message}`.trim() };
  } finally {
    await db.exec("rollback");
  }
}

// Refused by an access rule, a missing privilege, or the app's own check (RAISE in a trigger or function).
function blocked(a: Attempt): boolean {
  return /row-level security|permission denied|^42501|^P0001/i.test(a.error ?? "");
}

function readProbe(table: string, test: string, a: Attempt): ProbeRow {
  if (!a.ok) return { table, test, exposed: blocked(a) ? false : null, detail: a.error ?? "" };
  return { table, test, exposed: a.rows > 0, detail: `${plural(a.rows, "row")} visible` };
}

function changeProbe(table: string, test: string, a: Attempt): ProbeRow {
  if (!a.ok) return { table, test, exposed: blocked(a) ? false : null, detail: a.error ?? "" };
  return { table, test, exposed: a.affected > 0, detail: `${plural(a.affected, "row")} affected` };
}

function writeProbe(table: string, test: string, a: Attempt): ProbeRow {
  if (!a.ok) return { table, test, exposed: blocked(a) ? false : null, detail: a.error ?? "" };
  return { table, test, exposed: true, detail: "insert accepted" };
}

export function insertSql(t: Table, owner: string | null, n: number, privilege: Privilege = "least"): string {
  return buildInsert(t, owner, n, privilege, new Map());
}

function buildInsert(t: Table, owner: string | null, n: number, privilege: Privilege, samples: ForeignKeySamples): string {
  const cols: string[] = [];
  const vals: string[] = [];
  for (const c of t.columns) {
    if (t.ownerColumns.includes(c.name)) {
      if (owner) {
        cols.push(quoteIdent(c.name));
        vals.push(`'${owner}'`);
      }
      continue;
    }
    const grantsRights = ROLE_COLUMN.test(c.name) || PLAN_COLUMN.test(c.name) || FLAG_COLUMN.test(c.name);
    const required = !c.nullable && !c.hasDefault;
    if (!required && !(privilege === "most" && grantsRights)) continue;
    cols.push(quoteIdent(c.name));
    const sample = samples.get(`${t.schema}.${t.name}.${c.name}`);
    vals.push(sample !== undefined ? literal(sample) : dummyValue(c, n, privilege));
  }
  const q = qualified(t.schema, t.name);
  const insert = cols.length > 0
    ? `insert into ${q} (${cols.join(", ")}) values (${vals.join(", ")})`
    : `insert into ${q} default values`;
  return `${insert} on conflict do nothing`;
}

function pickAllowed(values: string[], privilege: Privilege): string {
  const privileged = new RegExp(PRIVILEGED_LABEL, "i");
  if (privilege === "most") return values.find((v) => /super|owner|admin/i.test(v)) ?? values[0];
  return values.find((v) => !privileged.test(v)) ?? values[0];
}

function literal(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}

function dummyValue(c: Column, n: number, privilege: Privilege): string {
  const u = c.udtName;
  const most = privilege === "most";
  if (c.dataType === "USER-DEFINED") {
    const order = most
      ? `(e.enumlabel ~* '(super|owner|admin)') desc, e.enumsortorder asc`
      : `(e.enumlabel ~* '${PRIVILEGED_LABEL}') asc, e.enumsortorder desc`;
    return `(select e.enumlabel from pg_enum e join pg_type ty on ty.oid = e.enumtypid where ty.typname = '${u.replace(/'/g, "''")}' order by ${order} limit 1)::${quoteIdent(u)}`;
  }
  if (u === "bool") return most && FLAG_COLUMN.test(c.name) ? "true" : "false";
  if (["text", "varchar", "bpchar", "citext", "name"].includes(u)) {
    if (c.allowedValues.length > 0) return literal(pickAllowed(c.allowedValues, privilege));
    if (ROLE_COLUMN.test(c.name)) return most ? "'admin'" : "'user'";
    if (PLAN_COLUMN.test(c.name)) return most ? "'pro'" : "'free'";
    return `'guard-test-${n}'`;
  }
  if (u === "uuid") return "gen_random_uuid()";
  // 1 satisfies the usual numeric checks (positive, rating between 1 and 5).
  if (["int2", "int4", "int8", "numeric", "float4", "float8", "money"].includes(u)) return "1";
  if (u === "timestamptz" || u === "timestamp") return "now()";
  if (u === "date") return "current_date";
  if (u === "time" || u === "timetz") return "current_time";
  if (u === "interval") return "interval '1 day'";
  if (u === "jsonb" || u === "json") return "'{}'";
  if (u === "bytea") return "'\\x00'";
  if (u === "inet") return "'127.0.0.1'";
  if (u.startsWith("_")) return "'{}'";
  return "null";
}
