// A short summary for a merge request comment or a CI log: the verdict, the attacks that worked,
// and the most serious findings. The full report and fix.sql travel as files next to it.
import { fixOutcome, plainName, plural, withoutPublic } from "./describe.js";
import { countBySeverity, sortFindings } from "./report.js";
import { SEVERITY_ORDER, type Finding, type LoadIssue, type ProofRow } from "./types.js";

export interface SummaryInput {
  tablesChecked: number;
  findings: Finding[];
  proof: ProofRow[];
  loadIssues: LoadIssue[];
}

const MAX_ROWS = 10;
const MAX_FINDINGS = 5;

export function renderSummary(r: SummaryInput): string {
  const findings = sortFindings(r.findings);
  const counts = countBySeverity(findings);
  const proven = r.proof.filter((p) => p.before === true);
  const blocked = proven.filter((p) => p.after === false).length;
  const decisions = proven.filter((p) => p.after === true && !p.autoFixed).length;
  const untested = r.proof.filter((p) => p.before === null).length;
  const partial = r.loadIssues.length > 0 || untested > 0;
  const out: string[] = [];

  if (proven.length > 0) {
    out.push(`### Lockstamp: ${plural(proven.length, "attack")} worked on a private copy of this database`, "");
    out.push(
      decisions === proven.length
        ? `${proven.length === 1 ? "It reaches" : "They reach"} data that may be meant to be public. Each needs a decision.`
        : fixOutcome(proven.length, blocked),
    );
  } else if (partial) {
    out.push("### Lockstamp: no ways in found in the parts that could be tested", "");
    out.push("Some of the setup couldn't be rebuilt in the test copy, so this is not an all-clear (see the report).");
  } else {
    out.push("### Lockstamp: no ways in found", "");
    out.push(`${plural(r.proof.length, "attack")} tried on a private copy of ${plural(r.tablesChecked, "table")}; none got through.`);
  }
  const parts = SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => `${counts[s]} ${s}`);
  if (parts.length > 0) out[out.length - 1] += ` **${parts.join(" · ")}**`;
  out.push("");

  if (proven.length > 0) {
    out.push("| Where | Attack | Before | After fix |", "|---|---|---|---|");
    for (const p of proven.slice(0, MAX_ROWS)) {
      out.push(`| ${plainName(p.table)} | ${p.test} | 🔓 Possible | ${afterCell(p)} |`);
    }
    if (proven.length > MAX_ROWS) out.push(`| … | ${proven.length - MAX_ROWS} more in the report | | |`);
    out.push("");
  }

  const serious = findings.filter((f) => f.severity !== "info").slice(0, MAX_FINDINGS);
  if (serious.length > 0) {
    out.push("**Top findings**");
    for (const f of serious) out.push(`- ${f.severity[0].toUpperCase()}${f.severity.slice(1)}: ${withoutPublic(f.title)}`);
    out.push("");
  }

  out.push(
    "The full report and `fix.sql` are in `lockstamp-report/`. Lockstamp rebuilds the database from the migrations in a " +
      "private in-memory copy and tries each attack before and after the fix; no real database is touched.",
  );
  return out.join("\n");
}

function afterCell(p: ProofRow): string {
  if (p.after === false) return "🔒 Blocked";
  if (p.after === null) return "Not tested";
  return p.autoFixed ? "🔓 Still possible" : "Your call";
}
