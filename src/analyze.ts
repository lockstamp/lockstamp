// The whole check, with no file system access, so it runs the same in Node and in a browser.
import type { PGlite } from "@electric-sql/pglite";
import { checkSchema } from "./checks.js";
import type { InputKind } from "./describe.js";
import { buildFix, tablesChangedByFix } from "./fix.js";
import { introspect } from "./introspect.js";
import { applySql, applyStatements, createDatabase, type SqlFile } from "./load.js";
import { renderReport, sortFindings } from "./report.js";
import { scanCodeFiles, scanFunctionSecrets, type CodeFile } from "./secrets.js";
import { parseSnapshot, snapshotToSql } from "./snapshot.js";
import { STEPS } from "./steps.js";
import type { DbSchema, Finding, LoadIssue, ProbeRow, ProofRow } from "./types.js";
import { runProbes } from "./verify.js";

export type Source = { kind: "migrations"; files: SqlFile[] } | { kind: "snapshot"; text: string };

export interface AnalyzeInput {
  projectName: string;
  source: Source;
  codeFiles?: CodeFile[];
  schemas?: string[];
  verify?: boolean;
  onProgress?: (step: string) => void;
}

export interface GuardResult {
  projectName: string;
  schema: DbSchema;
  findings: Finding[];
  fixSql: string;
  proof: ProofRow[];
  loadIssues: LoadIssue[];
  fixIssues: LoadIssue[];
  report: string;
}

type Build = (db: PGlite) => Promise<LoadIssue[]>;

const FIX_FILE = "fix.sql";

export async function analyze(input: AnalyzeInput): Promise<GuardResult> {
  const progress = input.onProgress ?? (() => undefined);
  const extraFindings: Finding[] = [];
  let build: Build;

  if (input.source.kind === "snapshot") {
    const snapshot = parseSnapshot(input.source.text);
    const statements = snapshotToSql(snapshot);
    build = (db) => applyStatements(db, "snapshot", statements);
    extraFindings.push(...scanFunctionSecrets(snapshot.functions));
  } else {
    const files = input.source.files;
    build = (db) => applySql(db, files);
  }

  progress(STEPS.load);
  const db = await createDatabase();
  let schema: DbSchema;
  let loadIssues: LoadIssue[];
  try {
    progress(STEPS.rebuild);
    loadIssues = await build(db);
    schema = await introspect(db, input.schemas ?? ["public"]);
  } finally {
    await db.close();
  }

  // A table whose access rule couldn't be rebuilt would look locked in the test copy. Never let
  // that read as safe: its attacks count as untested and the report says so.
  const lostRules = tablesWithLostRules(loadIssues);

  progress(STEPS.check);
  let findings = sortFindings([
    ...checkSchema(schema).filter((f) => !(f.rule === "rls_no_policies" && lostRules.has(f.target))),
    ...[...lostRules].map((table) => lostRuleFinding(table, input.source.kind)),
    ...scanCodeFiles(input.codeFiles ?? []),
    ...extraFindings,
  ]);
  const fixSql = buildFix(schema);

  let proof: ProofRow[] = [];
  let fixIssues: LoadIssue[] = [];
  if (input.verify !== false) {
    progress(STEPS.attack);
    const before = await probeWith(build, schema);
    progress(STEPS.fix);
    const after = await probeWith(build, schema, { file: FIX_FILE, sql: fixSql });
    fixIssues = after.issues.filter((i) => i.file === FIX_FILE);
    const changed = tablesChangedByFix(schema);
    proof = before.probes.map((b) => {
      const untested = lostRules.has(b.table);
      return {
        table: b.table,
        test: b.test,
        before: untested ? null : b.exposed,
        after: untested ? null : (after.probes.find((a) => a.table === b.table && a.test === b.test)?.exposed ?? null),
        autoFixed: changed.has(b.table),
      };
    });
    findings = sortFindings(reconcile(findings, proof));
  }

  const report = renderReport({
    projectName: input.projectName,
    checkedAt: new Date().toLocaleDateString("en-CA"),
    tablesChecked: schema.tables.length,
    findings,
    proof,
    loadIssues,
    input: input.source.kind,
    scannedCode: (input.codeFiles?.length ?? 0) > 0,
  });
  return { projectName: input.projectName, schema, findings, fixSql, proof, loadIssues, fixIssues, report };
}

const IDENT = String.raw`(?:"(?:[^"]|"")+"|[\w$]+)`;
const LOST_POLICY = new RegExp(String.raw`^create\s+policy\s+${IDENT}\s+on\s+(${IDENT}(?:\.${IDENT})?)`, "i");

export function tablesWithLostRules(issues: LoadIssue[]): Set<string> {
  const tables = new Set<string>();
  for (const issue of issues) {
    const match = LOST_POLICY.exec(issue.statement);
    if (!match) continue;
    const parts = match[1].split(".").map((p) => p.replace(/^"|"$/g, "").replace(/""/g, '"'));
    tables.add(parts.length === 2 ? `${parts[0]}.${parts[1]}` : `public.${parts[0]}`);
  }
  return tables;
}

function lostRuleFinding(table: string, input: InputKind): Finding {
  const name = table.replace(/^public\./, "");
  return {
    rule: "rules_not_rebuilt",
    severity: "medium",
    target: table,
    title: `Some access rules on ${table} couldn't be tested`,
    plain: `At least one access rule on "${name}" couldn't be rebuilt in the test copy, so attacks on it weren't tested. This is not an all-clear for "${name}".`,
    fix:
      input === "snapshot"
        ? `Have a person review the access rules on "${name}": the parts listed as not tested weren't rebuilt, so its attacks weren't tried.`
        : "Run the check with a snapshot from your SQL editor instead. It captures the live database, including helper functions kept outside the public schema. If it still happens, have a person review this table's rules.",
    autoFixed: false,
  };
}

// Suspected rights problems are settled by the attack tests: proven-blocked ones are dropped,
// untestable ones are kept as "review" instead of "high".
function reconcile(findings: Finding[], proof: ProofRow[]): Finding[] {
  return findings.flatMap((f) => {
    if (f.rule !== "sensitive_table_writable" && f.rule !== "protected_columns_editable") return [f];
    const tests = proof.filter((p) => p.table === f.target && /give themselves|change their own/.test(p.test));
    if (tests.length === 0 || tests.some((p) => p.before === true)) return [f];
    if (tests.every((p) => p.before === false)) return [];
    return [{ ...f, severity: "medium" as const, title: `${f.title} (couldn't be tested automatically)` }];
  });
}

async function probeWith(build: Build, schema: DbSchema, fix?: SqlFile): Promise<{ probes: ProbeRow[]; issues: LoadIssue[] }> {
  const db = await createDatabase();
  try {
    const issues = await build(db);
    if (fix) issues.push(...(await applySql(db, [fix])));
    return { probes: await runProbes(db, schema), issues };
  } finally {
    await db.close();
  }
}
