import { describe, expect, it } from "vitest";
import { describeStatement, explainError } from "../src/describe.js";
import { renderReport, type ReportInput } from "../src/report.js";
import { renderSummary } from "../src/summary.js";
import type { Finding, ProofRow } from "../src/types.js";

const finding = (over: Partial<Finding>): Finding => ({
  rule: "rls_disabled",
  severity: "critical",
  target: "public.notes",
  title: "Row Level Security is off for public.notes",
  plain: "Anyone can read it.",
  fix: "Turn it on.",
  autoFixed: true,
  ...over,
});

const proof = (over: Partial<ProofRow>): ProofRow => ({
  table: "public.notes",
  test: "A visitor can read rows",
  before: true,
  after: false,
  autoFixed: true,
  ...over,
});

const report = (over: Partial<ReportInput>) =>
  renderReport({
    projectName: "test",
    checkedAt: "2026-10-06",
    tablesChecked: 1,
    findings: [],
    proof: [],
    loadIssues: [],
    input: "snapshot",
    scannedCode: false,
    ...over,
  });

describe("the report only says what is true", () => {
  it("mentions leaked keys only when a key was found", () => {
    const withoutKey = report({ findings: [finding({})], proof: [proof({})] });
    expect(withoutKey).not.toMatch(/leaked key/i);
    const withKey = report({ findings: [finding({}), finding({ rule: "secret_in_code", severity: "high", autoFixed: false })] });
    expect(withKey).toMatch(/Leaked keys need a manual step/);
  });

  it("says the fix blocks everything only when it does", () => {
    const all = report({ findings: [finding({})], proof: [proof({}), proof({ test: "A visitor can delete rows" })] });
    expect(all).toMatch(/blocks all of them/);
    const some = report({ findings: [finding({})], proof: [proof({}), proof({ test: "x", after: true, autoFixed: false })] });
    expect(some).not.toMatch(/blocks all of them/);
    expect(some).toMatch(/blocks 1 of them/);
  });

  it("never says 'nothing to do' or 'blocks 0' when every attack needs a decision", () => {
    const text = report({
      findings: [finding({ rule: "public_read", severity: "low", target: "public.reviews", title: "Anyone can read public.reviews", autoFixed: false })],
      proof: [
        proof({ table: "public.reviews", after: true, autoFixed: false }),
        proof({ table: "public.reviews", test: "A logged-in user can read another user's rows", after: true, autoFixed: false }),
      ],
    });
    expect(text).not.toMatch(/Nothing to do now|fix blocks 0|blocks 0 of/);
    expect(text).toMatch(/may be meant to be public/);
    expect(text).toMatch(/Needs your decision/);
    expect(text).toMatch(/\| reviews \|/);
    expect(text).not.toMatch(/public\.reviews/);
  });

  it("uses singular wording for a single attack", () => {
    const one = report({ findings: [finding({ autoFixed: false, rule: "x", severity: "medium" })], proof: [proof({ after: true, autoFixed: true })] });
    expect(one).toMatch(/It can't be closed automatically/);
    expect(one).toMatch(/1 still works after it and needs a closer look/);
  });

  it("only tells people to read fix.sql when there is a fix", () => {
    const noFix = report({ findings: [finding({ rule: "rules_not_rebuilt", severity: "medium", autoFixed: false })] });
    expect(noFix).not.toMatch(/fix\.sql/);
    expect(report({ findings: [finding({})] })).toMatch(/Read `fix\.sql`/);
  });

  it("never prints (s) plurals", () => {
    const text = report({
      tablesChecked: 1,
      findings: [finding({})],
      proof: [proof({}), proof({ test: "y", before: false })],
      loadIssues: [{ file: "snapshot", statement: "create schema x", error: "boom" }],
    });
    expect(text).not.toMatch(/\(s\)/);
    expect(text).toMatch(/1 table ·/);
  });

  it("explains untested parts in plain words, not as an all-clear", () => {
    const text = report({
      loadIssues: [
        {
          file: "snapshot",
          statement: 'create policy "visible" on "public"."notes" for select using (private.is_visible(user_id))',
          error: 'schema "private" does not exist',
        },
      ],
    });
    expect(text).toMatch(/not an all-clear/);
    expect(text).toMatch(/Access rule "visible" on notes: It uses the "private" schema, which isn't in what you pasted/);
    expect(text).not.toMatch(/Supabase-only extensions/);
  });

  it("doesn't claim to have scanned app code it never saw", () => {
    expect(report({})).toMatch(/or look at your app's code/);
    expect(report({ scannedCode: true })).toMatch(/or in the code files it was given/);
  });
});

describe("the merge request summary", () => {
  it("leads with the verdict, shows the attack table and caps it", () => {
    const proof = Array.from({ length: 12 }, (_, i) => ({
      table: "public.notes",
      test: `Attack ${i + 1}`,
      before: true,
      after: false,
      autoFixed: true,
    }));
    const text = renderSummary({ tablesChecked: 1, findings: [finding({})], proof, loadIssues: [] });
    expect(text.split("\n")[0]).toBe("### Lockstamp: 12 attacks worked on a private copy of this database");
    expect(text).toMatch(/The fix blocks all of them\. \*\*1 critical\*\*/);
    expect(text).toMatch(/\| notes \| Attack 1 \| 🔓 Possible \| 🔒 Blocked \|/);
    expect(text).toMatch(/2 more in the report/);
    expect(text).not.toMatch(/public\./);
  });

  it("never reads as an all-clear when parts weren't tested", () => {
    const text = renderSummary({
      tablesChecked: 1,
      findings: [],
      proof: [],
      loadIssues: [{ file: "snapshot", statement: "create schema x", error: "boom" }],
    });
    expect(text).toMatch(/not an all-clear/);
  });
});

describe("plain-English labels", () => {
  it("names what a statement builds", () => {
    expect(describeStatement('create or replace function "private"."is_member"(uuid) returns boolean as $$ … $$')).toBe(
      "Function private.is_member()",
    );
    expect(describeStatement("create view public.note_counts as select 1")).toBe("View note_counts");
    expect(describeStatement('create trigger "t1" after insert on "public"."notes" for each row execute function f()')).toBe(
      'Trigger "t1" on notes',
    );
  });

  it("explains common rebuild errors for each input", () => {
    expect(explainError("function private.is_member(uuid) does not exist", "migrations")).toBe(
      "It calls private.is_member(uuid), which isn't in your migration files.",
    );
    expect(explainError('relation "public.teams" does not exist', "snapshot")).toBe("It refers to teams, which isn't in what you pasted.");
    expect(explainError("something odd happened", "snapshot")).toBe("Something odd happened.");
  });
});
