import { plural } from "./describe.js";
import type { DbSchema, Finding, Policy, Table } from "./types.js";

const API_ROLES = ["public", "anon", "authenticated"];
const WRITE_COMMANDS = ["INSERT", "UPDATE", "DELETE", "ALL"];
const VERB: Record<string, string> = { SELECT: "read", INSERT: "add", UPDATE: "change", DELETE: "delete" };

// Conditions that only ask "is someone logged in?" — any stranger with an account passes them.
const LOGGED_IN_ONLY = [
  /^(selectauth\.uidasuid|auth\.uid)isnotnull$/,
  /^(selectauth\.roleasrole|auth\.role)='authenticated'(::text)?$/,
  /^auth\.jwt->>'role'(::text)?='authenticated'(::text)?$/,
];

export type Audience = "anyone" | "logged-in";

export function apiPolicies(t: Table): Policy[] {
  return t.policies.filter((p) => p.permissive && p.roles.some((r) => API_ROLES.includes(r)));
}

// Who a rule lets in, when it doesn't look at which rows they own. Null means it does restrict.
export function openAudience(p: Policy): Audience | null {
  const expression = p.cmd === "INSERT" ? p.withCheck : p.using;
  if (expression === null) return null;
  const e = expression.toLowerCase().replace(/[\s()]/g, "");
  const anonymousRoles = p.roles.includes("public") || p.roles.includes("anon");
  if (e === "true") return anonymousRoles ? "anyone" : "logged-in";
  if (LOGGED_IN_ONLY.some((rx) => rx.test(e))) return "logged-in";
  return null;
}

// Rules fix.sql replaces. Open reads are only replaced when the data is clearly private;
// for possibly-public data that's the owner's call.
export function autoFixable(t: Table, p: Policy): boolean {
  if (t.ownerColumns.length !== 1 || openAudience(p) === null) return false;
  return p.cmd !== "SELECT" || t.exposure === "private";
}

export function checkSchema(schema: DbSchema): Finding[] {
  const findings: Finding[] = [];
  for (const table of schema.tables) findings.push(...checkTable(table));

  for (const v of schema.views) {
    const name = `${v.schema}.${v.name}`;
    if (!v.apiReadable || v.securityInvoker) continue;
    findings.push({
      rule: "view_bypasses_rls",
      severity: "high",
      target: name,
      title: `${v.materialized ? "Materialized view" : "View"} ${name} ignores Row Level Security`,
      plain: `"${v.name}" shows data using its creator's full permissions, so it skips your access rules. Anyone with your app's public key can read everything it shows.`,
      fix: v.materialized
        ? `Materialized views can't apply Row Level Security. Move "${v.name}" out of the public schema or remove API access to it.`
        : `Make the view run with the permissions of the person asking (security_invoker), so your table rules apply.`,
      autoFixed: !v.materialized,
    });
  }

  findings.push(...checkFunctions(schema));

  for (const b of schema.buckets) {
    if (!b.public) continue;
    findings.push({
      rule: "public_bucket",
      severity: "info",
      target: `storage bucket "${b.id}"`,
      title: `Storage bucket "${b.id}" is public`,
      plain: `Anyone with a file's link can download files in "${b.id}". That's fine for things like profile pictures, not for private documents.`,
      fix: `If files in "${b.id}" are private, make the bucket private and serve files with signed links.`,
      autoFixed: false,
    });
  }

  return findings;
}

// Security-definer helpers (has_role, is_member, ...) are a normal Supabase pattern, so only the
// risky ones are listed one by one; the rest are summarized instead of drowning the report.
const RISKY_FUNCTION = /(^|_)(delete|drop|truncate|grant|revoke|promote|demote|make_admin|set_role|assign_role|reset|wipe|purge|impersonate|exec|execute_sql|run_sql)(_|$)/i;

function checkFunctions(schema: DbSchema): Finding[] {
  const findings: Finding[] = [];
  const callable = schema.functions.filter((f) => f.anonCanExecute || f.authenticatedCanExecute);
  const label = (f: { schema: string; name: string; args: string }) => `${f.schema}.${f.name}(${f.args})`;
  const who = (f: { anonCanExecute: boolean }) => (f.anonCanExecute ? "anyone, even without logging in," : "any logged-in user");

  for (const f of callable) {
    if (f.readsAuthUsers) {
      findings.push({
        rule: "definer_function_reads_users",
        severity: "high",
        target: label(f),
        title: `Function ${f.schema}.${f.name} exposes your users table`,
        plain: `"${f.name}" reads your users table (emails and account details) with full database permissions, and ${who(f)} can call it.`,
        fix: `Stop the public and logged-in users from calling it. If your app needs it, call it from a server function instead.`,
        autoFixed: true,
      });
    } else if (RISKY_FUNCTION.test(f.name)) {
      findings.push({
        rule: "definer_function_risky",
        severity: "medium",
        target: label(f),
        title: `Function ${f.schema}.${f.name} can change data with full permissions`,
        plain: `"${f.name}" skips your access rules, and ${who(f)} can call it. Its name suggests it deletes data or changes rights — check that it verifies who is calling.`,
        fix: `Add a check inside the function (for example that the caller is an admin), or remove API access to it.`,
        autoFixed: false,
      });
    }
  }

  const ordinary = callable.filter((f) => !f.readsAuthUsers && !RISKY_FUNCTION.test(f.name));
  const unpinned = ordinary.filter((f) => !f.searchPathSet);
  if (unpinned.length > 0) {
    findings.push({
      rule: "definer_function_search_path",
      severity: "medium",
      target: listNames(unpinned.map(label)),
      title: `${plural(unpinned.length, "function")} with full permissions ${unpinned.length === 1 ? "doesn't" : "don't"} lock ${unpinned.length === 1 ? "its" : "their"} search_path`,
      plain: `These functions skip your access rules and don't pin which schemas they read from, which an attacker can sometimes abuse to run their own code.`,
      fix: `Add "set search_path = ''" (or "= public") to each function's definition.`,
      autoFixed: false,
    });
  }
  if (ordinary.length > 0) {
    findings.push({
      rule: "definer_functions_review",
      severity: "info",
      target: listNames(ordinary.map(label)),
      title: `${plural(ordinary.length, "function")} ${ordinary.length === 1 ? "runs" : "run"} with full database permissions`,
      plain: `These can be called through your app's API and skip your access rules while they run. That's normal for helpers like has_role, but each one should only do what its name says.`,
      fix: `Skim each function: it should only return or change what the caller is allowed to.`,
      autoFixed: false,
    });
  }
  return findings;
}

function listNames(names: string[]): string {
  return names.length > 8 ? `${names.slice(0, 8).join(", ")} and ${names.length - 8} more` : names.join(", ");
}

function checkTable(t: Table): Finding[] {
  const name = `${t.schema}.${t.name}`;
  const reachable = t.access.anon.length > 0 || t.access.authenticated.length > 0;
  const owned = t.ownerColumns.length > 0;
  const findings: Finding[] = [];

  if (!t.rlsEnabled) {
    if (!reachable) return [];
    const privileges = t.access.anon.length > 0 ? t.access.anon : t.access.authenticated;
    findings.push({
      rule: "rls_disabled",
      severity: "critical",
      target: name,
      title: `Row Level Security is off for ${name}`,
      plain: `Anyone who has your app's public key — it's visible in your website's code — can ${listVerbs(privileges)} every row in "${t.name}".`,
      fix: !owned
        ? `Turn on Row Level Security. The fix allows read-only access for now — decide whether "${t.name}" should be public at all.`
        : t.sensitive
          ? `Turn on Row Level Security so each user can only read their own rows. Changes to "${t.name}" should come only from your server (for example a payment webhook or an admin function).`
          : `Turn on Row Level Security and add rules so each user can only reach their own rows (matched on ${t.ownerColumns.join(", ")}).`,
      autoFixed: true,
    });
    if (owned && !t.sensitive) findings.push(...protectedColumnFinding(t, name));
    return findings;
  }

  if (t.policies.length === 0 && reachable) {
    findings.push({
      rule: "rls_no_policies",
      severity: "info",
      target: name,
      title: `${name} has Row Level Security on but no rules`,
      plain: `Nobody can read or change "${t.name}" through your app. That's safe, but any feature that needs this table won't work.`,
      fix: `If your app uses "${t.name}", add rules for who may read and change it.`,
      autoFixed: false,
    });
  }

  const rules = apiPolicies(t);
  for (const p of rules) {
    const audience = openAudience(p);
    if (audience === null) continue;
    const who = audience === "anyone" ? "Anyone, even without logging in," : "Any logged-in user";
    const target = `${name} — rule "${p.name}"`;

    if (owned && p.cmd !== "SELECT") {
      findings.push({
        rule: "policy_always_true",
        severity: "high",
        target,
        title: `Rule "${p.name}" on ${name} lets users reach other users' rows`,
        plain: openOwnedSentence(p, who, t.name),
        fix: autoFixable(t, p)
          ? `Replace this rule with one that only matches rows where ${t.ownerColumns[0]} is the current user.`
          : `Narrow this rule so it only matches rows the person is allowed to change (several user columns: ${t.ownerColumns.join(", ")}).`,
        autoFixed: autoFixable(t, p),
      });
    } else if (owned) {
      findings.push(openReadFinding(t, p, who, target));
    } else if (p.cmd === "SELECT") {
      findings.push({
        rule: "public_read",
        severity: "low",
        target,
        title: `Everyone can read ${name}`,
        plain: `${who} can read every row in "${t.name}". That's fine if it's meant to be public (like a product list).`,
        fix: `If "${t.name}" holds private information, limit who can read it.`,
        autoFixed: false,
      });
    } else {
      findings.push({
        rule: "public_write",
        severity: audience === "anyone" ? "high" : "medium",
        target,
        title: `Rule "${p.name}" lets ${audience === "anyone" ? "anyone" : "any logged-in user"} ${commandVerb(p)} ${name}`,
        plain: `${who} can ${commandVerb(p)} rows in "${t.name}".`,
        fix: `Decide who should be allowed to ${commandVerb(p)} "${t.name}" and narrow the rule to them.`,
        autoFixed: false,
      });
    }
  }

  const writeRules = rules.filter((p) => WRITE_COMMANDS.includes(p.cmd));
  if (t.sensitive && writeRules.length > 0) {
    const what = t.privilege ? "roles or memberships" : "billing records";
    findings.push({
      rule: "sensitive_table_writable",
      severity: "high",
      target: name,
      title: `Users may be able to change ${what} in ${name}`,
      plain: `Rules on "${t.name}" let users write to it. If any of them match ordinary users, someone could ${t.privilege ? "give themselves extra rights" : "give themselves a paid plan or credits"} for free.`,
      fix: `Check the write rules (${writeRules.map((p) => `"${p.name}"`).join(", ")}). Ordinary users should never write "${t.name}"; make changes from your server or an admin-only function.`,
      autoFixed: writeRules.every((p) => autoFixable(t, p)),
    });
  } else if (owned && !t.sensitive && writeRules.length > 0) {
    findings.push(...protectedColumnFinding(t, name));
  }

  return findings;
}

function openReadFinding(t: Table, p: Policy, who: string, target: string): Finding {
  const name = `${t.schema}.${t.name}`;
  if (t.exposure === "private") {
    return {
      rule: "policy_always_true",
      severity: "high",
      target,
      title: `Rule "${p.name}" on ${name} lets users read other users' rows`,
      plain: openOwnedSentence(p, who, t.name),
      fix: autoFixable(t, p)
        ? `Replace this rule with one that only matches rows where ${t.ownerColumns[0]} is the current user.`
        : `Narrow this rule to the rows each person should see (several user columns: ${t.ownerColumns.join(", ")}).`,
      autoFixed: autoFixable(t, p),
    };
  }
  if (t.exposure === "public") {
    return {
      rule: "public_read",
      severity: "low",
      target,
      title: `Everyone can read ${name}`,
      plain: `${who} can read every row in "${t.name}". That looks intended for this kind of data — just make sure no private columns are stored in it.`,
      fix: `If some rows or columns are private (drafts, contact details), limit who can read them.`,
      autoFixed: false,
    };
  }
  return {
    rule: "open_read_review",
    severity: "medium",
    target,
    title: `${name} is readable by ${who === "Any logged-in user" ? "any logged-in user" : "anyone"} — is that intended?`,
    plain: `${who} can read every user's rows in "${t.name}". That's fine for public content, but a leak if these rows are personal.`,
    fix: `If each user's rows are private, replace this rule with one that only matches rows where ${t.ownerColumns[0]} is the current user.`,
    autoFixed: false,
  };
}

function protectedColumnFinding(t: Table, name: string): Finding[] {
  const tableLevelWrite = t.access.authenticated.includes("UPDATE") || t.access.authenticated.includes("INSERT");
  if (t.protectedColumns.length === 0 || !tableLevelWrite) return [];
  const cols = t.protectedColumns.map((c) => `"${c}"`).join(", ");
  return [
    {
      rule: "protected_columns_editable",
      severity: "high",
      target: name,
      title: `Users can set their own ${t.protectedColumns.join(", ")} in ${name}`,
      plain: `When a user edits their own row in "${t.name}", nothing stops them from also changing ${cols}. That could let someone make themselves an admin or unlock paid features for free.`,
      fix: `Allow users to edit only the safe columns of "${t.name}"; ${cols} can then only be changed by your server.`,
      autoFixed: true,
    },
  ];
}

function openOwnedSentence(p: Policy, who: string, table: string): string {
  switch (p.cmd) {
    case "SELECT":
      return `${who} can see every user's rows in "${table}", not just their own.`;
    case "INSERT":
      return `${who} can add rows to "${table}" that claim to belong to a different user.`;
    case "UPDATE":
      return `${who} can change other users' rows in "${table}".`;
    case "DELETE":
      return `${who} can delete other users' rows in "${table}".`;
    default:
      return `${who} can see, change and delete other users' rows in "${table}".`;
  }
}

function commandVerb(p: Policy): string {
  return p.cmd === "ALL" ? "read, add, change and delete" : VERB[p.cmd];
}

function listVerbs(privileges: string[]): string {
  const verbs = privileges.map((p) => VERB[p]).filter(Boolean);
  if (verbs.length <= 1) return verbs[0] ?? "read";
  return `${verbs.slice(0, -1).join(", ")} and ${verbs[verbs.length - 1]}`;
}
