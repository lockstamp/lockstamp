import { describeStatement, explainError, fixOutcome, plainName, plural, withoutPublic, type InputKind } from "./describe.js";
import { SEVERITY_ORDER, type Finding, type LoadIssue, type ProofRow, type Severity } from "./types.js";

export interface ReportInput {
  projectName: string;
  checkedAt: string;
  tablesChecked: number;
  findings: Finding[];
  proof: ProofRow[];
  loadIssues: LoadIssue[];
  input: InputKind;
  // Whether app code files were scanned for leaked keys (the web version only sees the database).
  scannedCode: boolean;
}

const LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

export function sortFindings(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
}

export function countBySeverity(findings: Finding[]): Record<Severity, number> {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

export function renderReport(r: ReportInput): string {
  const findings = sortFindings(r.findings);
  const counts = countBySeverity(findings);
  const serious = counts.critical + counts.high;
  const proven = r.proof.filter((p) => p.before === true);
  const blockedByFix = proven.filter((p) => p.after === false).length;
  const stillOpen = proven.filter((p) => p.after === true && p.autoFixed).length;
  const decisions = proven.filter((p) => p.after === true && !p.autoFixed).length;
  const blockedAlready = r.proof.filter((p) => p.before === false).length;
  const untested = r.proof.filter((p) => p.before === null).length;
  const partial = r.loadIssues.length > 0 || untested > 0;
  const hasFix = findings.some((f) => f.autoFixed);
  const leakedKeys = findings.some((f) => f.rule === "secret_in_code");
  const out: string[] = [];

  out.push(`# Database security check: ${r.projectName}`, "");
  out.push(
    `Checked ${r.checkedAt} with Lockstamp · ${plural(r.tablesChecked, "table")} · ${plural(findings.length, "finding")}`,
    "",
  );

  out.push("## Summary", "");
  const parts = SEVERITY_ORDER.filter((s) => counts[s] > 0).map((s) => `${counts[s]} ${LABEL[s].toLowerCase()}`);
  out.push(
    parts.length > 0
      ? `**Found: ${parts.join(", ")}.**`
      : partial
        ? "**No problems found in the parts we could test.** Some parts couldn't be tested (listed below), so this is not an all-clear."
        : "**No problems found in what was checked.**",
    "",
  );
  const summary: string[] = [];
  if (proven.length > 0) {
    summary.push(`${plural(proven.length, "attack")} worked on a private test copy of your database.`);
    if (decisions === proven.length) {
      summary.push(
        `${proven.length === 1 ? "It involves" : "They involve"} data that may be meant to be public, like reviews or product listings — each one is marked "Needs your decision" below.`,
      );
    } else {
      summary.push(fixOutcome(proven.length, blockedByFix));
    }
  } else if (serious > 0) {
    summary.push("No attack got through, but some findings below can cause damage on their own.");
  }
  if (leakedKeys) summary.push("Leaked keys need a manual step (see below).");
  if (summary.length > 0) out.push(summary.join(" "), "");

  if (r.proof.length > 0) {
    out.push("## Proof: attacks tried before and after the fix", "");
    out.push(
      "We rebuilt your database setup in a private test copy, added two fake users, and tried the attacks below. " +
        "No real data was touched.",
      "",
    );
    if (proven.length > 0) {
      out.push("| Table | Attack | Before fix | After fix |", "|---|---|---|---|");
      for (const p of proven) out.push(`| ${plainName(p.table)} | ${p.test} | ${outcome(p.before)} | ${afterOutcome(p)} |`);
      out.push("");
    }
    const sentences: string[] = [];
    if (proven.length > 0) {
      const blocks =
        blockedByFix === 0 ? "" : `, and the fix blocks ${blockedByFix < proven.length ? blockedByFix : proven.length === 1 ? "it" : "all of them"}`;
      sentences.push(`${plural(proven.length, "attack")} worked before the fix${blocks}.`);
      if (stillOpen > 0) sentences.push(`${stillOpen} still ${stillOpen === 1 ? "works" : "work"} after it and ${stillOpen === 1 ? "needs" : "need"} a closer look.`);
      if (decisions > 0) {
        sentences.push(
          `${decisions} ${decisions === 1 ? "involves" : "involve"} data that may be meant to be public, or rules the tool won't change on its own — marked "Needs your decision" and explained in the findings.`,
        );
      }
    }
    if (blockedAlready > 0) {
      sentences.push(`${plural(blockedAlready, proven.length > 0 ? "other attack" : "attack")} ${blockedAlready === 1 ? "was" : "were"} already blocked.`);
    }
    if (untested > 0) sentences.push(`${plural(untested, "attack")} couldn't be tested automatically.`);
    out.push(sentences.join(" "), "");
  }

  if (findings.length > 0) {
    out.push("## What we found", "");
    findings.forEach((f, i) => {
      out.push(`### ${i + 1}. ${LABEL[f.severity]}: ${withoutPublic(f.title)}`, "");
      out.push(`**What this means:** ${withoutPublic(f.plain)}`, "");
      out.push(`**Fix:** ${f.fix} ${f.autoFixed ? "_(Included in fix.sql.)_" : "_(Needs a manual step.)_"}`, "");
      out.push(`**Where:** \`${withoutPublic(f.target)}\``, "");
    });
  }

  out.push("## What to do next", "");
  const steps: string[] = [];
  if (leakedKeys) {
    steps.push(
      "Replace (rotate) every leaked key listed above in its provider's dashboard **today** — removing it from the code isn't enough, because old versions of your site still contain it.",
    );
  }
  if (hasFix) {
    steps.push(
      "Read `fix.sql`, then apply it as a new migration or paste it into your SQL editor.",
      "Test your app's main features while logged in as a normal user.",
    );
  }
  const manual = findings.filter((f) => !f.autoFixed && f.severity !== "info" && f.rule !== "secret_in_code" && f.rule !== "rules_not_rebuilt");
  if (decisions > 0) {
    steps.push(
      'Look at each attack marked "Needs your decision" in the table above and its finding. If that data shouldn\'t be public, change the rule as the finding says, then run this check again.',
    );
  } else if (manual.length > 0) {
    steps.push('Work through the findings marked "Needs a manual step".');
  }
  if (partial) steps.push("Have a person review the parts this check couldn't test (listed below).");
  if (hasFix || leakedKeys) steps.push("Run this check again to confirm everything shows as blocked.");
  // Only an all-clear gets "nothing to do": every other case added a step above.
  if (steps.length === 0) steps.push("Nothing to do now. Run this check again whenever you change your database's access rules.");
  steps.forEach((s, i) => out.push(`${i + 1}. ${s}`));
  out.push("");

  if (r.loadIssues.length > 0) {
    out.push("## Parts we couldn't test", "");
    out.push(
      `${plural(r.loadIssues.length, "part")} of your setup couldn't be rebuilt in the test copy, so rules that depend on ${r.loadIssues.length === 1 ? "it" : "them"} weren't tested:`,
      "",
    );
    for (const issue of r.loadIssues.slice(0, 15)) {
      out.push(`- ${describeStatement(issue.statement)}: ${explainError(issue.error, r.input)} _(Database error: ${issue.error})_`);
    }
    if (r.loadIssues.length > 15) out.push(`- …and ${r.loadIssues.length - 15} more`);
    out.push("");
  }

  out.push("## What this check covers", "");
  out.push(
    "This check reviews your database access rules (Row Level Security), views, database functions, storage buckets, " +
      `and secret keys stored in database functions${r.scannedCode ? " or in the code files it was given" : ""}. ` +
      `It does not test your live site${r.scannedCode ? "" : " or look at your app's code"}, and it is not a guarantee that the app has no other vulnerabilities.`,
    "",
  );
  return out.join("\n");
}

function outcome(value: boolean | null): string {
  if (value === null) return "Not tested";
  return value ? "**Possible**" : "Blocked";
}

function afterOutcome(p: ProofRow): string {
  if (p.after === true) return p.autoFixed ? "**Still possible**" : "Needs your decision";
  return outcome(p.after);
}
