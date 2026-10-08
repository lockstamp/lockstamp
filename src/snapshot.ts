// "Snapshot" mode: the client runs one read-only query in their SQL editor (Supabase, or Lovable
// Cloud) and sends the JSON it returns. It describes the database's structure only — no rows, no
// passwords — and is turned back into SQL so the same checks and attack tests run as with migrations.

// Every schema the app owns, not just public: access rules often call helper functions kept in a
// private schema, and leaving those out would make a rule silently disappear from the test copy.
export const SNAPSHOT_QUERY = String.raw`-- Lockstamp snapshot (read-only). Collects your database's structure: tables, columns,
-- access rules, functions, views and triggers. It reads no rows from your tables.
with
  app as (
    select n.oid, n.nspname from pg_namespace n
    where n.nspname not in (
        'pg_catalog', 'information_schema', 'auth', 'storage', 'extensions', 'graphql', 'graphql_public',
        'realtime', '_realtime', 'supabase_functions', 'supabase_migrations', 'vault', 'pgsodium',
        'pgsodium_masks', 'net', 'cron', 'pgmq', 'pgbouncer', '_analytics', 'tiger', 'topology')
      and n.nspname not like 'pg\_%'
  ),
  ext as (select objid from pg_depend where deptype = 'e'),
  rel as (
    select c.*, a.nspname as schema_name from pg_class c join app a on a.oid = c.relnamespace
    where c.oid not in (select objid from ext)
  )
select json_build_object(
  'version', 2,
  'server_version', current_setting('server_version'),
  'schemas', (
    select coalesce(json_agg(json_build_object(
      'name', a.nspname,
      'anon_usage', has_schema_privilege('anon', a.oid, 'USAGE'),
      'authenticated_usage', has_schema_privilege('authenticated', a.oid, 'USAGE')
    ) order by a.nspname), '[]'::json)
    from app a
  ),
  'enums', (
    select coalesce(json_agg(json_build_object(
      'schema', a.nspname,
      'name', t.typname,
      'labels', (select json_agg(e.enumlabel order by e.enumsortorder) from pg_enum e where e.enumtypid = t.oid)
    ) order by a.nspname, t.typname), '[]'::json)
    from pg_type t join app a on a.oid = t.typnamespace
    where t.typtype = 'e' and t.oid not in (select objid from ext)
  ),
  'tables', (
    select coalesce(json_agg(json_build_object(
      'schema', c.schema_name,
      'name', c.relname,
      'rls', c.relrowsecurity,
      'force_rls', c.relforcerowsecurity,
      'columns', (
        select json_agg(json_build_object(
          'name', att.attname,
          'type', format_type(att.atttypid, att.atttypmod),
          'not_null', att.attnotnull,
          'default', pg_get_expr(d.adbin, d.adrelid),
          'identity', att.attidentity,
          'generated', att.attgenerated,
          'grants', (
            select coalesce(json_agg(json_build_object('role', g.grantee::regrole::text, 'privilege', g.privilege_type)), '[]'::json)
            from aclexplode(att.attacl) g
            where g.grantee in ('anon'::regrole, 'authenticated'::regrole)
          )
        ) order by att.attnum)
        from pg_attribute att
        left join pg_attrdef d on d.adrelid = att.attrelid and d.adnum = att.attnum
        where att.attrelid = c.oid and att.attnum > 0 and not att.attisdropped
      ),
      'constraints', (
        select coalesce(json_agg(json_build_object('name', con.conname, 'type', con.contype, 'definition', pg_get_constraintdef(con.oid))), '[]'::json)
        from pg_constraint con where con.conrelid = c.oid
      ),
      'grants', (
        select coalesce(json_agg(json_build_object('role', g.grantee::regrole::text, 'privilege', g.privilege_type)), '[]'::json)
        from aclexplode(c.relacl) g
        where g.grantee in ('anon'::regrole, 'authenticated'::regrole)
      )
    ) order by c.schema_name, c.relname), '[]'::json)
    from rel c where c.relkind in ('r', 'p')
  ),
  'policies', (
    select coalesce(json_agg(json_build_object(
      'schema', p.schemaname, 'table', p.tablename, 'name', p.policyname, 'permissive', p.permissive,
      'roles', p.roles, 'cmd', p.cmd, 'using', p.qual, 'with_check', p.with_check
    ) order by p.schemaname, p.tablename, p.policyname), '[]'::json)
    from pg_policies p where p.schemaname in (select nspname from app)
  ),
  'functions', (
    select coalesce(json_agg(json_build_object(
      'schema', a.nspname,
      'name', p.proname,
      'args', pg_get_function_identity_arguments(p.oid),
      'definition', pg_get_functiondef(p.oid),
      'anon_execute', has_function_privilege('anon', p.oid, 'EXECUTE'),
      'authenticated_execute', has_function_privilege('authenticated', p.oid, 'EXECUTE')
    ) order by a.nspname, p.proname), '[]'::json)
    from pg_proc p join app a on a.oid = p.pronamespace
    where p.prokind in ('f', 'p') and p.oid not in (select objid from ext)
  ),
  'views', (
    select coalesce(json_agg(json_build_object(
      'schema', c.schema_name,
      'name', c.relname,
      'materialized', c.relkind = 'm',
      'definition', pg_get_viewdef(c.oid),
      'options', c.reloptions,
      'grants', (
        select coalesce(json_agg(json_build_object('role', g.grantee::regrole::text, 'privilege', g.privilege_type)), '[]'::json)
        from aclexplode(c.relacl) g
        where g.grantee in ('anon'::regrole, 'authenticated'::regrole)
      )
    ) order by c.schema_name, c.relname), '[]'::json)
    from rel c where c.relkind in ('v', 'm')
  ),
  'triggers', (
    select coalesce(json_agg(json_build_object('schema', c.schema_name, 'table', c.relname, 'definition', pg_get_triggerdef(t.oid)) order by c.schema_name, c.relname, t.tgname), '[]'::json)
    from pg_trigger t join rel c on c.oid = t.tgrelid
    where not t.tgisinternal
  ),
  'buckets', (
    select coalesce(json_agg(json_build_object('id', b.id, 'public', b.public) order by b.id), '[]'::json)
    from storage.buckets b
  )
) as snapshot;
`;

interface Grant {
  role: string;
  privilege: string;
}

interface Column {
  name: string;
  type: string;
  not_null: boolean;
  default: string | null;
  identity: string;
  generated: string;
  grants?: Grant[];
}

// Version 1 snapshots covered only the public schema and carried no schema fields.
export interface Snapshot {
  version: 1 | 2;
  server_version?: string;
  schemas?: { name: string; anon_usage: boolean; authenticated_usage: boolean }[];
  enums: { schema?: string; name: string; labels: string[] }[];
  tables: {
    schema?: string;
    name: string;
    rls: boolean;
    force_rls: boolean;
    columns: Column[];
    constraints: { name: string; type: string; definition: string }[];
    grants: Grant[];
  }[];
  policies: {
    schema?: string;
    table: string;
    name: string;
    permissive: string;
    roles: string[] | string;
    cmd: string;
    using: string | null;
    with_check: string | null;
  }[];
  functions: {
    schema?: string;
    name: string;
    args: string;
    definition: string;
    anon_execute: boolean;
    authenticated_execute: boolean;
  }[];
  views: { schema?: string; name: string; materialized: boolean; definition: string; options: string[] | null; grants: Grant[] }[];
  triggers: { schema?: string; table: string; definition: string }[];
  buckets: { id: string; public: boolean | null }[];
}

export class SnapshotError extends Error {
  constructor(
    message: string,
    readonly kind: "not-json" | "truncated" | "not-snapshot",
  ) {
    super(message);
  }
}

// Accepts the raw JSON, or the SQL editor's copy of the single "snapshot" cell (sometimes quoted,
// or wrapped in a row object or array).
export function parseSnapshot(text: string): Snapshot {
  const trimmed = unwrapCopiedTable(text.trim());
  if (/^(--|with\b|select\b)/i.test(trimmed) || trimmed.includes("json_build_object(")) {
    throw new SnapshotError(
      "That's the query itself. Run it in your SQL editor first, then copy the result and paste it here.",
      "not-json",
    );
  }
  let value: unknown;
  try {
    value = JSON.parse(trimmed);
  } catch {
    const looksLikeJson = /^[[{"]/.test(trimmed);
    if (looksLikeJson && !/[}\]"]$/.test(trimmed)) {
      throw new SnapshotError("The pasted result is cut off. Copy the whole cell again. It ends with }.", "truncated");
    }
    throw new SnapshotError(
      looksLikeJson
        ? "The pasted result is incomplete or damaged. Copy the whole cell under snapshot again and paste it here."
        : 'That isn\'t the query result. In the SQL editor\'s results, click the single cell under snapshot, copy it, and paste it here. It starts with {"version".',
      looksLikeJson ? "truncated" : "not-json",
    );
  }
  for (let depth = 0; depth < 4; depth++) {
    if (typeof value === "string") value = parseQuoted(value);
    else if (Array.isArray(value)) value = value[0];
    else if (value && typeof value === "object" && "snapshot" in value) value = (value as { snapshot: unknown }).snapshot;
    else break;
  }
  const snap = value as Snapshot;
  if (!snap || (snap.version !== 1 && snap.version !== 2) || !Array.isArray(snap.tables)) {
    throw new SnapshotError(
      "That's not the snapshot. Run the query from step 1 and paste the single value it returns.",
      "not-snapshot",
    );
  }
  // The query always returns every list; a missing one means the paste was cut or edited.
  for (const list of ["enums", "policies", "functions", "views", "triggers", "buckets"] as const) {
    if (!Array.isArray(snap[list])) {
      throw new SnapshotError(
        "That's only part of the snapshot. Run the query from step 1 again and paste the whole cell.",
        "not-snapshot",
      );
    }
  }
  return snap;
}

// The SQL editor can also copy results as CSV (a "snapshot" header, every quote doubled) or as a
// markdown table; both are unwrapped back to the cell's JSON.
function unwrapCopiedTable(text: string): string {
  const markdown = /^\|\s*snapshot\s*\|\s*\r?\n\|[\s:|-]+\|\s*\r?\n\|\s?([\s\S]*?)\s?\|\s*$/i.exec(text);
  if (markdown) return markdown[1].replace(/\\\|/g, "|").trim();
  const body = text.replace(/^"?snapshot"?[ \t]*\r?\n/i, "").trim();
  return /^"[{[]""/.test(body) && body.endsWith('"') ? body.slice(1, -1).replace(/""/g, '"') : body;
}

function parseQuoted(value: string): unknown {
  try {
    return JSON.parse(value);
  } catch {
    throw new SnapshotError(
      "The pasted result is incomplete or damaged. Copy the whole cell under snapshot again and paste it here.",
      "truncated",
    );
  }
}

const q = (name: string) => `"${name.replace(/"/g, '""')}"`;
const t = (schema: string | undefined, name: string) => `${q(schema ?? "public")}.${q(name)}`;
const lit = (value: string) => `'${value.replace(/'/g, "''")}'`;

// Rebuilds the structure as SQL statements, ordered so dependencies exist before they're used.
export function snapshotToSql(s: Snapshot): string[] {
  const out: string[] = ["set check_function_bodies = false"];

  for (const schema of s.schemas ?? []) {
    if (schema.name === "public") continue;
    out.push(`create schema if not exists ${q(schema.name)}`);
  }
  for (const schema of s.schemas ?? []) {
    const roles = [schema.anon_usage ? "anon" : "", schema.authenticated_usage ? "authenticated" : ""].filter(Boolean);
    if (schema.name !== "public" && roles.length > 0) out.push(`grant usage on schema ${q(schema.name)} to ${roles.join(", ")}`);
  }

  for (const e of s.enums) {
    out.push(`create type ${t(e.schema, e.name)} as enum (${(e.labels ?? []).map(lit).join(", ")})`);
  }

  const sequences = new Set<string>();
  for (const table of s.tables) {
    for (const c of table.columns ?? []) {
      for (const m of (c.default ?? "").matchAll(/nextval\('([^']+)'::regclass\)/g)) {
        sequences.add(m[1].includes(".") ? m[1] : `${q(table.schema ?? "public")}.${m[1]}`);
      }
    }
  }
  for (const seq of sequences) out.push(`create sequence if not exists ${seq}`);

  for (const table of s.tables) {
    const cols = (table.columns ?? []).map((c) => {
      let def = `${q(c.name)} ${c.type}`;
      if (c.generated === "s" && c.default) def += ` generated always as (${c.default}) stored`;
      else if (c.identity === "a") def += " generated always as identity";
      else if (c.identity === "d") def += " generated by default as identity";
      else if (c.default) def += ` default ${c.default}`;
      if (c.not_null) def += " not null";
      return def;
    });
    out.push(`create table ${t(table.schema, table.name)} (${cols.join(", ")})`);
  }

  // Functions come before constraints and triggers that call them; bodies aren't checked yet.
  for (const f of s.functions) out.push(f.definition);

  const order: Record<string, number> = { p: 0, u: 1, c: 2, x: 3, f: 4 };
  // Constraint triggers come back with the triggers, and not-null (Postgres 18) with the columns.
  const constraints = s.tables.flatMap((table) =>
    (table.constraints ?? []).filter((con) => con.type in order).map((con) => ({ schema: table.schema, table: table.name, ...con })),
  );
  constraints.sort((a, b) => (order[a.type] ?? 9) - (order[b.type] ?? 9));
  for (const con of constraints) {
    out.push(`alter table ${t(con.schema, con.table)} add constraint ${q(con.name)} ${con.definition}`);
  }

  for (const v of s.views) {
    const opts = v.options && v.options.length > 0 ? ` with (${v.options.join(", ")})` : "";
    const body = v.definition.replace(/;\s*$/, "");
    out.push(v.materialized ? `create materialized view ${t(v.schema, v.name)} as ${body}` : `create view ${t(v.schema, v.name)}${opts} as ${body}`);
  }

  for (const trg of s.triggers) out.push(trg.definition);

  for (const table of s.tables) {
    if (table.rls) out.push(`alter table ${t(table.schema, table.name)} enable row level security`);
    if (table.force_rls) out.push(`alter table ${t(table.schema, table.name)} force row level security`);
  }

  for (const p of s.policies) {
    const roles = Array.isArray(p.roles) ? p.roles : String(p.roles).replace(/^\{|\}$/g, "").split(",").filter(Boolean);
    let sql = `create policy ${q(p.name)} on ${t(p.schema, p.table)} as ${p.permissive === "RESTRICTIVE" ? "restrictive" : "permissive"} for ${p.cmd.toLowerCase()} to ${roles.map((r) => (r === "public" ? "public" : q(r))).join(", ")}`;
    if (p.using) sql += ` using (${p.using})`;
    if (p.with_check) sql += ` with check (${p.with_check})`;
    out.push(sql);
  }

  // Replace Supabase's default "grant everything" with exactly what the live database grants.
  const relations = [
    ...s.tables.map((x) => ({ schema: x.schema, name: x.name, grants: x.grants, columns: x.columns })),
    ...s.views.map((v) => ({ schema: v.schema, name: v.name, grants: v.grants, columns: [] as Column[] })),
  ];
  for (const r of relations) {
    out.push(`revoke all on ${t(r.schema, r.name)} from anon, authenticated`);
    for (const g of r.grants ?? []) out.push(`grant ${g.privilege} on ${t(r.schema, r.name)} to ${q(g.role)}`);
    for (const c of r.columns ?? []) {
      for (const g of c.grants ?? []) out.push(`grant ${g.privilege} (${q(c.name)}) on ${t(r.schema, r.name)} to ${q(g.role)}`);
    }
  }

  for (const f of s.functions) {
    const sig = `${t(f.schema, f.name)}(${f.args})`;
    out.push(`revoke execute on function ${sig} from public, anon, authenticated`);
    if (f.anon_execute) out.push(`grant execute on function ${sig} to anon`);
    if (f.authenticated_execute) out.push(`grant execute on function ${sig} to authenticated`);
  }

  for (const b of s.buckets ?? []) {
    out.push(`insert into storage.buckets (id, name, public) values (${lit(b.id)}, ${lit(b.id)}, ${b.public ? "true" : "false"}) on conflict (id) do update set public = excluded.public`);
  }

  out.push("set check_function_bodies = true");
  return out;
}
