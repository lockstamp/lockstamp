import type { PGlite } from "@electric-sql/pglite";
import type { Bucket, Column, DbSchema, DefinerFunction, Exposure, ForeignKey, Policy, PolicyCommand, Table, View } from "./types.js";

const OWNER_COLUMN_NAMES = ["user_id", "owner_id", "profile_id", "created_by", "author_id", "creator_id"];
// Foreign keys to auth.users that record who acted on a row, not who owns it.
const NOT_OWNER_COLUMN = /(^|_)(updated|modified|archived|deleted|approved|reviewed|assigned|invited|verified|cancell?ed|completed|closed|resolved|confirmed|published|edited|processed|rejected|accepted|last)_by$|^(assigned_to|assignee_id|reviewer_id|approver_id|referred_by|referrer_id)$/i;
const BILLING_TABLE = /(^|_)(subscriptions?|payments?|billing|invoices?|orders?|purchases?|transactions?|credits?|balances?|wallets?|entitlements?|plans?|licen[cs]es?|payouts?|refunds?)($|_)/i;
// The rights word must be the table's last segment: "user_roles" grants rights, "admin_audit_logs" doesn't.
const PRIVILEGE_TABLE = /((^|_)(roles?|permissions?|admins?|members?|memberships?|staff|collaborators?)|^users?_(organizations?|orgs?|teams?|workspaces?|companies|groups?)|(^|_)(organization|org|workspace|team|company|group|project|clinic|store|shop|tenant)_users?)$/i;
const PROTECTED_COLUMN = /^(role|roles|is_admin|admin|is_super_?admin|is_staff|is_moderator|is_verified|verified|is_pro|is_premium|premium|plan|tier|subscription_(status|tier|plan)|credits?|balance|stripe_customer_id|stripe_subscription_id|permissions?|access_level|user_type|account_type)$/i;
const PRIVATE_TABLE = /(^|_)(notes?|messages?|chats?|conversations?|journals?|diar(y|ies)|health|medical|patients?|appointments?|bookings?|invoices?|payments?|orders?|subscriptions?|transactions?|documents?|files?|uploads?|contacts?|leads?|customers?|clients?|employees?|addresses|settings|preferences|tokens?|secrets?|keys?|sessions?|logs?|notifications?|tasks?|todos?|expenses?|budgets?|accounts?|roles?|permissions?|members?|wallets?|credits?)($|_)/i;
const PUBLIC_TABLE = /(^|_)(posts?|articles?|blogs?|stories|news|products?|items?|listings?|categor(y|ies)|tags?|events?|reviews?|comments?|ratings?|testimonials?|courses?|lessons?|recipes?|menus?|menu_items?|services?|faqs?|pages?|portfolios?|galler(y|ies)|photos?|videos?|announcements?|jobs?|pricing|templates?|catalog(ue)?s?|collections?|artists?|venues?|tracks?|songs?|episodes?|podcasts?|questions?|answers?|polls?|leaderboards?|scores?)($|_)/i;
const PII_COLUMN = /(email|phone|address|birth|dob|ssn|passport|salary|iban|card_number|password|token|secret|api_key|ip_address|latitude|longitude|diagnos|medical|national_id|tax_id)/i;
const PRIVILEGES = ["SELECT", "INSERT", "UPDATE", "DELETE"] as const;

export async function introspect(db: PGlite, schemas: string[] = ["public"]): Promise<DbSchema> {
  const tableRows = await db.query<{
    schema: string;
    name: string;
    rls_enabled: boolean;
    anon_select: boolean;
    anon_insert: boolean;
    anon_update: boolean;
    anon_delete: boolean;
    auth_select: boolean;
    auth_insert: boolean;
    auth_update: boolean;
    auth_delete: boolean;
  }>(
    `select n.nspname as schema, c.relname as name, c.relrowsecurity as rls_enabled,
       has_table_privilege('anon', c.oid, 'SELECT') as anon_select,
       has_table_privilege('anon', c.oid, 'INSERT') as anon_insert,
       has_table_privilege('anon', c.oid, 'UPDATE') as anon_update,
       has_table_privilege('anon', c.oid, 'DELETE') as anon_delete,
       has_table_privilege('authenticated', c.oid, 'SELECT') as auth_select,
       has_table_privilege('authenticated', c.oid, 'INSERT') as auth_insert,
       has_table_privilege('authenticated', c.oid, 'UPDATE') as auth_update,
       has_table_privilege('authenticated', c.oid, 'DELETE') as auth_delete
     from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where c.relkind in ('r', 'p') and n.nspname = any($1::text[])
     order by 1, 2`,
    [schemas],
  );

  const columnRows = await db.query<{
    schema: string;
    table: string;
    name: string;
    data_type: string;
    udt_name: string;
    nullable: boolean;
    has_default: boolean;
  }>(
    `select c.table_schema as schema, c.table_name as table, c.column_name as name,
       c.data_type, c.udt_name, c.is_nullable = 'YES' as nullable,
       (c.column_default is not null or c.is_identity = 'YES' or c.is_generated = 'ALWAYS') as has_default
     from information_schema.columns c
     where c.table_schema = any($1::text[])
     order by c.table_schema, c.table_name, c.ordinal_position`,
    [schemas],
  );

  const checkRows = await db.query<{ schema: string; table: string; column: string; definition: string }>(
    `select n.nspname as schema, c.relname as table, a.attname as column, pg_get_constraintdef(con.oid) as definition
     from pg_constraint con
     join pg_class c on c.oid = con.conrelid
     join pg_namespace n on n.oid = c.relnamespace
     join pg_attribute a on a.attrelid = c.oid and a.attnum = con.conkey[1]
     where con.contype = 'c' and array_length(con.conkey, 1) = 1 and n.nspname = any($1::text[])`,
    [schemas],
  );

  const policyRows = await db.query<{
    schema: string;
    table: string;
    name: string;
    permissive: boolean;
    roles: string[];
    cmd: PolicyCommand;
    qual: string | null;
    with_check: string | null;
  }>(
    `select schemaname as schema, tablename as table, policyname as name,
       permissive = 'PERMISSIVE' as permissive, roles::text[] as roles, cmd, qual, with_check
     from pg_policies where schemaname = any($1::text[])
     order by schemaname, tablename, policyname`,
    [schemas],
  );

  const fkRows = await db.query<{
    schema: string;
    table: string;
    column: string;
    ref_schema: string;
    ref_table: string;
    ref_column: string;
  }>(
    `select n.nspname as schema, c.relname as table, a.attname as column,
       rn.nspname as ref_schema, rc.relname as ref_table, ra.attname as ref_column
     from pg_constraint con
     join pg_class c on c.oid = con.conrelid
     join pg_namespace n on n.oid = c.relnamespace
     join pg_class rc on rc.oid = con.confrelid
     join pg_namespace rn on rn.oid = rc.relnamespace
     join lateral unnest(con.conkey, con.confkey) as k(attnum, refattnum) on true
     join pg_attribute a on a.attrelid = c.oid and a.attnum = k.attnum
     join pg_attribute ra on ra.attrelid = rc.oid and ra.attnum = k.refattnum
     where con.contype = 'f' and n.nspname = any($1::text[])`,
    [schemas],
  );

  const tables: Table[] = tableRows.rows.map((t) => {
    const key = (r: { schema: string; table: string }) => r.schema === t.schema && r.table === t.name;
    const columns: Column[] = columnRows.rows.filter(key).map((c) => ({
      name: c.name,
      dataType: c.data_type,
      udtName: c.udt_name,
      nullable: c.nullable,
      hasDefault: c.has_default,
      allowedValues: checkRows.rows
        .filter((k) => key(k) && k.column === c.name)
        .flatMap((k) => [...k.definition.matchAll(/'((?:[^']|'')*)'/g)].map((m) => m[1].replace(/''/g, "'"))),
    }));
    const policies: Policy[] = policyRows.rows.filter(key).map((p) => ({
      name: p.name,
      permissive: p.permissive,
      roles: normalizeRoles(p.roles),
      cmd: p.cmd,
      using: p.qual,
      withCheck: p.with_check,
    }));
    const foreignKeys: ForeignKey[] = fkRows.rows.filter(key).map((f) => ({
      column: f.column,
      refSchema: f.ref_schema,
      refTable: f.ref_table,
      refColumn: f.ref_column,
    }));
    const flags = [t.anon_select, t.anon_insert, t.anon_update, t.anon_delete];
    const authFlags = [t.auth_select, t.auth_insert, t.auth_update, t.auth_delete];
    const table: Table = {
      schema: t.schema,
      name: t.name,
      rlsEnabled: t.rls_enabled,
      columns,
      policies,
      foreignKeys,
      access: {
        anon: PRIVILEGES.filter((_, i) => flags[i]),
        authenticated: PRIVILEGES.filter((_, i) => authFlags[i]),
      },
      ownerColumns: [],
      sensitive: false,
      privilege: false,
      protectedColumns: [],
      exposure: "unknown",
    };
    table.ownerColumns = detectOwnerColumns(table);
    const owned = table.ownerColumns.length > 0;
    table.privilege = owned && PRIVILEGE_TABLE.test(table.name);
    table.sensitive = owned && (table.privilege || BILLING_TABLE.test(table.name));
    // A "role" column only means rights when the row belongs to a user.
    table.protectedColumns = owned
      ? columns.map((c) => c.name).filter((c) => PROTECTED_COLUMN.test(c) && !table.ownerColumns.includes(c))
      : [];
    table.exposure = classifyExposure(table);
    return table;
  });

  const viewRows = await db.query<{
    schema: string;
    name: string;
    materialized: boolean;
    security_invoker: boolean;
    api_readable: boolean;
  }>(
    `select n.nspname as schema, c.relname as name, c.relkind = 'm' as materialized,
       exists (select 1 from unnest(coalesce(c.reloptions, '{}'::text[])) o
               where lower(o) in ('security_invoker=true', 'security_invoker=on', 'security_invoker=1', 'security_invoker=yes')) as security_invoker,
       (has_table_privilege('anon', c.oid, 'SELECT') or has_table_privilege('authenticated', c.oid, 'SELECT')) as api_readable
     from pg_class c join pg_namespace n on n.oid = c.relnamespace
     where c.relkind in ('v', 'm') and n.nspname = any($1::text[])
     order by 1, 2`,
    [schemas],
  );
  const views: View[] = viewRows.rows.map((v) => ({
    schema: v.schema,
    name: v.name,
    materialized: v.materialized,
    securityInvoker: v.security_invoker,
    apiReadable: v.api_readable,
  }));

  const fnRows = await db.query<{
    schema: string;
    name: string;
    args: string;
    anon_exec: boolean;
    auth_exec: boolean;
    search_path_set: boolean;
    arg_count: number;
    returns_void: boolean;
    reads_auth_users: boolean;
  }>(
    `select n.nspname as schema, p.proname as name, pg_get_function_identity_arguments(p.oid) as args,
       has_function_privilege('anon', p.oid, 'EXECUTE') as anon_exec,
       has_function_privilege('authenticated', p.oid, 'EXECUTE') as auth_exec,
       exists (select 1 from unnest(coalesce(p.proconfig, '{}'::text[])) cfg where cfg like 'search_path=%') as search_path_set,
       p.pronargs::int as arg_count,
       p.prorettype = 'void'::regtype as returns_void,
       pg_get_functiondef(p.oid) ~* 'auth\\.users' as reads_auth_users
     from pg_proc p join pg_namespace n on n.oid = p.pronamespace
     where p.prosecdef and p.prorettype <> 'trigger'::regtype and n.nspname = any($1::text[])
     order by 1, 2`,
    [schemas],
  );
  const functions: DefinerFunction[] = fnRows.rows.map((f) => ({
    schema: f.schema,
    name: f.name,
    args: f.args,
    anonCanExecute: f.anon_exec,
    authenticatedCanExecute: f.auth_exec,
    searchPathSet: f.search_path_set,
    argCount: f.arg_count,
    returnsVoid: f.returns_void,
    readsAuthUsers: f.reads_auth_users,
  }));

  const bucketRows = await db.query<{ id: string; public: boolean | null }>(
    `select id, coalesce(public, false) as public from storage.buckets order by id`,
  );
  const buckets: Bucket[] = bucketRows.rows.map((b) => ({ id: b.id, public: Boolean(b.public) }));

  return { tables, views, functions, buckets };
}

function normalizeRoles(roles: string[] | string): string[] {
  if (Array.isArray(roles)) return roles;
  return roles.replace(/^\{|\}$/g, "").split(",").filter(Boolean);
}

// A table "belongs to users" when a uuid column points at auth.users, or is named like an owner.
export function detectOwnerColumns(table: Table): string[] {
  const viaForeignKey = table.foreignKeys
    .filter((f) => f.refSchema === "auth" && f.refTable === "users" && !NOT_OWNER_COLUMN.test(f.column))
    .map((f) => f.column);
  if (viaForeignKey.length > 0) {
    const unique = [...new Set(viaForeignKey)];
    const preferred = unique.filter((c) => OWNER_COLUMN_NAMES.includes(c) || c === "id");
    return preferred.length > 0 ? preferred : unique;
  }
  const byName = table.columns.find((c) => OWNER_COLUMN_NAMES.includes(c.name) && c.udtName === "uuid");
  return byName ? [byName.name] : [];
}

function classifyExposure(table: Table): Exposure {
  if (table.sensitive || PRIVATE_TABLE.test(table.name) || table.columns.some((c) => PII_COLUMN.test(c.name))) return "private";
  if (PUBLIC_TABLE.test(table.name)) return "public";
  return "unknown";
}

export function qualified(schema: string, name: string): string {
  return `${quoteIdent(schema)}.${quoteIdent(name)}`;
}

export function quoteIdent(name: string): string {
  return `"${name.replace(/"/g, '""')}"`;
}
