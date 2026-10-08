#!/usr/bin/env node
import { mkdir, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { parseArgs } from "node:util";
import { runGuard, SNAPSHOT_QUERY } from "./index.js";
import { plural } from "./describe.js";
import { countBySeverity } from "./report.js";
import { renderSummary } from "./summary.js";
import { SEVERITY_ORDER } from "./types.js";

const HELP = `lockstamp: find and fix database security holes in Supabase apps, with proof.

Usage: lockstamp [project-folder] [options]

Options:
  --migrations <dir>  Migrations folder (default: <project>/supabase/migrations)
  --snapshot <file>   Check a snapshot instead of migrations (JSON from --snapshot-query)
  --snapshot-query    Print the read-only query to run in the Supabase SQL editor
  --out <dir>         Where to write the report (default: <project>/lockstamp-report)
  --schema <name>     Schema exposed through the API (default: public; repeatable)
  --no-verify         Skip the before/after attack tests
  --no-code           Skip scanning code for leaked keys
  --fail-on <level>   Exit with 1 at this severity or worse: critical, high (default), medium, low, never
  -h, --help          Show this help

Writes report.md, summary.md (short, for a merge request comment), fix.sql and results.json.
The exit code lets a CI pipeline fail when problems at the --fail-on level are found.
`;

const LEVELS = ["critical", "high", "medium", "low", "never"] as const;

async function main(): Promise<void> {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      migrations: { type: "string" },
      snapshot: { type: "string" },
      "snapshot-query": { type: "boolean", default: false },
      out: { type: "string" },
      schema: { type: "string", multiple: true },
      "no-verify": { type: "boolean", default: false },
      "no-code": { type: "boolean", default: false },
      "fail-on": { type: "string", default: "high" },
      help: { type: "boolean", short: "h", default: false },
    },
  });
  if (values.help) {
    process.stdout.write(HELP);
    return;
  }
  const failOn = values["fail-on"] as (typeof LEVELS)[number];
  if (!LEVELS.includes(failOn)) throw new Error(`--fail-on must be one of: ${LEVELS.join(", ")}`);
  if (values["snapshot-query"]) {
    process.stdout.write(SNAPSHOT_QUERY);
    return;
  }

  // With only a snapshot there's no code to scan, and the report goes next to the snapshot.
  const snapshotOnly = Boolean(values.snapshot) && positionals.length === 0;
  const projectDir = resolve(positionals[0] ?? (values.snapshot ? dirname(values.snapshot) : "."));
  const result = await runGuard({
    projectDir,
    migrationsDir: values.migrations,
    snapshotFile: values.snapshot,
    schemas: values.schema,
    verify: !values["no-verify"],
    scanCode: !values["no-code"] && !snapshotOnly,
  });

  const outDir = resolve(values.out ?? join(projectDir, "lockstamp-report"));
  await mkdir(outDir, { recursive: true });
  await writeFile(join(outDir, "report.md"), result.report);
  await writeFile(
    join(outDir, "summary.md"),
    renderSummary({ tablesChecked: result.schema.tables.length, findings: result.findings, proof: result.proof, loadIssues: result.loadIssues }),
  );
  await writeFile(join(outDir, "fix.sql"), result.fixSql);
  await writeFile(
    join(outDir, "results.json"),
    JSON.stringify({ findings: result.findings, proof: result.proof, loadIssues: result.loadIssues, fixIssues: result.fixIssues }, null, 2),
  );

  const c = countBySeverity(result.findings);
  const worked = result.proof.filter((p) => p.before === true);
  console.log(`lockstamp: ${plural(result.schema.tables.length, "table")} checked`);
  console.log(`  findings: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low, ${c.info} info`);
  if (result.proof.length > 0) {
    console.log(`  attacks that worked: ${worked.length} before the fix, ${worked.filter((p) => p.after === true).length} after`);
  }
  if (result.fixIssues.length > 0) {
    console.log(`  WARNING: ${plural(result.fixIssues.length, "statement")} in fix.sql failed to apply. Review it before use`);
  }
  console.log(`  report: ${join(outDir, "report.md")}`);
  if (failOn !== "never") {
    const levels = SEVERITY_ORDER.slice(0, SEVERITY_ORDER.indexOf(failOn) + 1);
    if (levels.some((s) => c[s] > 0)) process.exitCode = 1;
  }
}

main().catch((err: unknown) => {
  console.error(`lockstamp: ${(err as Error).message}`);
  process.exitCode = 2;
});
