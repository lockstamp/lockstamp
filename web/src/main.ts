import "@fontsource-variable/archivo/wdth.css";
import "@fontsource-variable/public-sans/wght.css";
import "@fontsource/ibm-plex-mono/400.css";
import "@fontsource/ibm-plex-mono/500.css";
import "./styles.css";
import type { Source } from "../../src/analyze.js";
import { describeStatement, explainError, fixOutcome, plainName, plural, withoutPublic, type InputKind } from "../../src/describe.js";
import { parseSnapshot, SnapshotError, SNAPSHOT_QUERY } from "../../src/snapshot.js";
import { STEP_ORDER } from "../../src/steps.js";
import type { Finding, LoadIssue, ProofRow, Severity } from "../../src/types.js";
import { refreshMotion, scrollToElement, settleReveals, startMotion } from "./motion.js";
import type { WorkerMessage, WorkerRequest } from "./worker.js";

type Result = Extract<WorkerMessage, { type: "result" }>["result"];

// The paid next step, set once the owner approves it: where "Get it fixed" leads, and the name of the
// person who does the work. Until both are set, every fix-it-for-you offer stays hidden.
const FIX_URL = "https://www.upwork.com/freelancers/~01d7446dbecad0fbf2";
const SELLER = "Mark M.";
const OFFERS_LIVE = Boolean(FIX_URL && SELLER);

// Attack rows shown before "Show all".
const LEDGER_PREVIEW = 6;

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

const byId = <T extends HTMLElement = HTMLElement>(id: string) => document.getElementById(id) as T;

const ui = {
  copyQuery: byId<HTMLButtonElement>("copy-query"),
  toggleQuery: byId<HTMLButtonElement>("toggle-query"),
  copied: byId("copied"),
  preview: byId<HTMLPreElement>("query-preview"),
  snapshotInput: byId<HTMLTextAreaElement>("snapshot-input"),
  sqlFiles: byId<HTMLInputElement>("sql-files"),
  fileList: byId("file-list"),
  run: byId<HTMLButtonElement>("run"),
  inputError: byId("input-error"),
  progress: byId("progress"),
  progressSteps: byId("progress-steps"),
  results: byId("results"),
  resultsFor: byId("results-for"),
  verdict: byId("verdict"),
  verdictDetail: byId("verdict-detail"),
  counts: byId("severity-counts"),
  downloads: byId("downloads"),
  downloadReport: byId<HTMLAnchorElement>("download-report"),
  downloadFix: byId<HTMLAnchorElement>("download-fix"),
  offerInline: byId<HTMLAnchorElement>("offer-inline"),
  coverage: byId("coverage"),
  coverageList: byId("coverage-list"),
  ledgerBlock: byId("ledger-block"),
  ledger: byId("ledger"),
  findings: byId("findings"),
  checkAgain: byId<HTMLButtonElement>("check-again"),
  offer: byId("offer"),
  offerLink: byId<HTMLAnchorElement>("offer-link"),
  offerTitle: byId("offer-title"),
  offerText: byId("offer-text"),
  faqFix: byId("faq-fix"),
};

let migrationFiles: { file: string; sql: string }[] = [];
let worker: Worker | null = null;
let inputKind: InputKind = "snapshot";
const objectUrls: string[] = [];

function el<K extends keyof HTMLElementTagNameMap>(
  tag: K,
  props: { className?: string; text?: string; attrs?: Record<string, string> } = {},
  ...children: (Node | string)[]
): HTMLElementTagNameMap[K] {
  const node = document.createElement(tag);
  if (props.className) node.className = props.className;
  if (props.text !== undefined) node.textContent = props.text;
  for (const [k, v] of Object.entries(props.attrs ?? {})) node.setAttribute(k, v);
  for (const child of children) node.append(child);
  return node;
}

ui.faqFix.hidden = !OFFERS_LIVE;
for (const name of document.querySelectorAll("[data-seller]")) name.textContent = SELLER;
for (const link of document.querySelectorAll<HTMLAnchorElement>("a[data-fix-link]")) link.href = FIX_URL;

// Step 1: the query

ui.preview.querySelector("code")!.textContent = SNAPSHOT_QUERY;

ui.copyQuery.addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(SNAPSHOT_QUERY);
    ui.copied.textContent = "Copied. Paste it into your SQL editor and press Run.";
  } catch {
    showQuery(true);
    const range = document.createRange();
    range.selectNodeContents(ui.preview);
    getSelection()?.removeAllRanges();
    getSelection()?.addRange(range);
    ui.copied.textContent = "Selected. Press Ctrl+C (or ⌘C) to copy.";
  }
});

ui.toggleQuery.addEventListener("click", () => showQuery(Boolean(ui.preview.hidden)));

function showQuery(show: boolean): void {
  ui.preview.hidden = !show;
  ui.toggleQuery.setAttribute("aria-expanded", String(show));
  ui.toggleQuery.textContent = show ? "Hide the query" : "Read it first";
  refreshMotion();
}

// Step 2: the input

ui.snapshotInput.addEventListener("input", () => {
  hideError();
  if (ui.snapshotInput.value.trim() && migrationFiles.length > 0) clearFiles();
});

ui.sqlFiles.addEventListener("change", async () => {
  hideError();
  const chosen = [...(ui.sqlFiles.files ?? [])].filter((f) => f.name.toLowerCase().endsWith(".sql"));
  migrationFiles = (await Promise.all(chosen.map(async (f) => ({ file: f.name, sql: await f.text() })))).sort((a, b) =>
    a.file.localeCompare(b.file),
  );
  if (migrationFiles.length === 0) return clearFiles();
  ui.snapshotInput.value = "";
  ui.fileList.replaceChildren(
    `${plural(migrationFiles.length, "migration file")} selected. `,
    Object.assign(el("button", { className: "text-button", text: "Clear", attrs: { type: "button" } }), { onclick: clearFiles }),
  );
  ui.fileList.hidden = false;
});

function clearFiles(): void {
  migrationFiles = [];
  ui.sqlFiles.value = "";
  ui.fileList.hidden = true;
  ui.fileList.replaceChildren();
}

ui.run.addEventListener("click", () => {
  const text = ui.snapshotInput.value.trim();
  if (text) {
    const problem = snapshotProblem(text);
    if (problem) {
      showError(problem);
      ui.snapshotInput.focus();
      return;
    }
    return start("your project", { kind: "snapshot", text });
  }
  if (migrationFiles.length > 0) return start("your project", { kind: "migrations", files: migrationFiles });
  showError("Paste the result of the query from step 1, or choose your migration files.");
  ui.snapshotInput.focus();
});

// Checked here, before anything starts, so a bad paste gets a plain answer right under the box.
function snapshotProblem(text: string): string | null {
  try {
    parseSnapshot(text);
    return null;
  } catch (err) {
    return err instanceof SnapshotError
      ? err.message
      : "That isn't the query result. In the SQL editor's results, copy the single cell under snapshot and paste it here.";
  }
}

for (const button of document.querySelectorAll<HTMLButtonElement>("[data-demo]")) {
  button.addEventListener("click", async () => {
    try {
      const response = await fetch("./demo-snapshot.json");
      if (!response.ok) throw new Error(String(response.status));
      start("the demo notes app", { kind: "snapshot", text: await response.text() });
    } catch {
      showError("The sample app didn't load. Check your connection and try again.");
      scrollToElement(ui.inputError, "center");
    }
  });
}

ui.checkAgain.addEventListener("click", () => {
  ui.results.hidden = true;
  ui.snapshotInput.value = "";
  clearFiles();
  refreshMotion();
  scrollToElement(byId("check"));
  ui.snapshotInput.focus({ preventScroll: true });
});

function showError(message: string): void {
  ui.inputError.textContent = message;
  ui.inputError.hidden = false;
  ui.snapshotInput.setAttribute("aria-invalid", "true");
}

function hideError(): void {
  ui.inputError.hidden = true;
  ui.snapshotInput.removeAttribute("aria-invalid");
}

// Running the check

function start(projectName: string, source: Source): void {
  hideError();
  inputKind = source.kind;
  worker?.terminate();
  ui.run.disabled = true;
  ui.results.hidden = true;
  renderProgress(-1);
  ui.progress.hidden = false;
  refreshMotion();
  settleReveals(ui.progress);
  scrollToElement(ui.progress, "center");

  const stop = () => {
    worker?.terminate();
    worker = null;
    ui.run.disabled = false;
    ui.progress.hidden = true;
  };
  const fail = (message: string) => {
    stop();
    showError(message);
    refreshMotion();
    scrollToElement(ui.inputError, "center");
  };

  worker = new Worker(new URL("./worker.ts", import.meta.url), { type: "module" });
  worker.onmessage = (event: MessageEvent<WorkerMessage>) => {
    const message = event.data;
    if (message.type === "progress") {
      renderProgress(STEP_ORDER.indexOf(message.step));
      return;
    }
    if (message.type === "error") {
      // The internal message helps debugging but means nothing to the person checking their app.
      console.warn("Lockstamp: the check failed:", message.message);
      fail(
        source.kind === "snapshot"
          ? "The check couldn't finish on that input. Run the query from step 1 again, copy the whole cell, and paste it here."
          : "The check couldn't finish on those files. Choose the .sql files from your project's supabase/migrations folder and try again.",
      );
      return;
    }
    stop();
    renderResults(message.result, projectName);
  };
  worker.onerror = () => fail("The check stopped before it finished. Reload the page and try again.");
  const request: WorkerRequest = { projectName, source };
  worker.postMessage(request);
}

function renderProgress(active: number): void {
  ui.progressSteps.replaceChildren(
    ...STEP_ORDER.map((step, i) => el("li", { className: i < active ? "done" : i === active ? "active" : "pending", text: step })),
  );
}

// Results

function renderResults(result: Result, projectName: string): void {
  for (const url of objectUrls.splice(0)) URL.revokeObjectURL(url);
  ui.resultsFor.textContent = `Results for ${projectName}`;

  const tables = result.schema.tables.length;
  const proven = result.proof.filter((p) => p.before === true);
  const counts = countSeverities(result.findings);
  const serious = counts.critical + counts.high;
  const [verdict, detail] = verdictFor(result, proven, serious);
  ui.verdict.textContent = verdict;
  ui.verdictDetail.textContent = detail;

  ui.counts.replaceChildren(
    ...(Object.keys(counts) as Severity[])
      .filter((s) => counts[s] > 0)
      .map((s) => el("li", { className: `count sev-${s}`, text: `${counts[s]} ${SEVERITY_LABEL[s].toLowerCase()}` })),
  );

  // Downloads sit right under the verdict; there's nothing to download if no tables were read.
  ui.downloads.hidden = tables === 0;
  ui.downloadFix.hidden = !result.findings.some((f) => f.autoFixed);
  const reportUrl = URL.createObjectURL(new Blob([result.report], { type: "text/markdown" }));
  const fixUrl = URL.createObjectURL(new Blob([result.fixSql], { type: "text/plain" }));
  objectUrls.push(reportUrl, fixUrl);
  ui.downloadReport.href = reportUrl;
  ui.downloadFix.href = fixUrl;

  // Offer paid help only where there's something to fix or check — never for data that may be
  // public by design.
  const fixable = proven.some((p) => p.after === false || p.autoFixed) || serious > 0;
  const offer = OFFERS_LIVE && (fixable || result.loadIssues.length > 0);
  ui.offer.hidden = !offer;
  ui.offerInline.hidden = !offer;
  if (offer) {
    ui.offerTitle.textContent = fixable ? "Want it fixed for you?" : "Want the untested parts checked too?";
    ui.offerText.textContent = fixable
      ? `${SELLER} applies the fix to your project, tests your app's main features, and sends you the before-and-after proof. Intro price from $150 for the first few clients, hired through Upwork.`
      : `${SELLER} reviews the rules this check couldn't rebuild, fixes what's wrong, and sends you the before-and-after proof. Intro price from $150 for the first few clients, hired through Upwork.`;
    ui.offerInline.textContent = fixable ? "Have it applied for you" : "Have the rest checked";
    ui.offerInline.insertAdjacentHTML("beforeend", '<span class="sr-only"> (opens Upwork in a new tab)</span>');
    ui.offerLink.href = FIX_URL;
    ui.offerInline.href = FIX_URL;
  }

  renderCoverage(result.loadIssues);

  ui.ledgerBlock.hidden = tables === 0;
  ui.ledger.replaceChildren(renderLedger(proven, result.proof));
  ui.findings.replaceChildren(
    ...(result.findings.length > 0
      ? result.findings.map(renderFinding)
      : [el("p", { className: "hint", text: tables === 0 ? "Nothing to show yet." : "No problems found in what we could test." })]),
  );

  ui.results.hidden = false;
  refreshMotion();
  ui.verdict.focus({ preventScroll: true });
  scrollToElement(ui.results);
}

function verdictFor(result: Result, proven: ProofRow[], serious: number): [string, string] {
  const tables = result.schema.tables.length;
  const partial = result.loadIssues.length > 0;
  if (tables === 0) {
    return [
      "We couldn't read any tables from that.",
      partial
        ? `${plural(result.loadIssues.length, "part")} of it couldn't be rebuilt. Copy the whole cell under snapshot again, then run the check.`
        : "Copy the whole cell under snapshot again, then run the check.",
    ];
  }
  const untested = partial ? " Some parts couldn't be tested. They're listed below." : "";
  if (proven.length > 0) {
    const blocked = proven.filter((p) => p.after === false).length;
    const decisions = proven.filter((p) => p.after === true && !p.autoFixed).length;
    const stillOpen = proven.filter((p) => p.after === true && p.autoFixed).length;
    // Every attack reaches data that may be public by design: say so instead of sounding an alarm.
    if (decisions === proven.length && serious === 0) {
      return [
        `${plural(proven.length, "way")} in, maybe on purpose.`,
        "These attacks reach data that may be meant to be public, like reviews or product listings. If it isn't, each finding below says how to lock it down." +
          untested,
      ];
    }
    const parts = [fixOutcome(proven.length, blocked)];
    if (decisions > 0) parts.push(`${decisions} ${decisions === 1 ? "needs" : "need"} your decision.`);
    if (stillOpen > 0) {
      parts.push(`${stillOpen} still ${stillOpen === 1 ? "works" : "work"} after it and ${stillOpen === 1 ? "needs" : "need"} a closer look.`);
    }
    return [`${plural(proven.length, "way")} in.`, parts.join(" ") + untested];
  }
  if (serious > 0) {
    return [
      "No attacks got through, but there's work to do.",
      "The findings below can cause damage without an attack, for example a secret key stored in a database function." + untested,
    ];
  }
  const tested = result.proof.filter((p) => p.before !== null).length;
  const skipped = result.proof.length - tested;
  if (partial || skipped > 0) {
    return [
      "No ways in found in the parts we could test.",
      partial
        ? "Some of your setup couldn't be rebuilt in the test copy, so this isn't an all-clear. The untested parts are listed below."
        : `${plural(skipped, "attack")} couldn't be tested automatically, so this isn't an all-clear.`,
    ];
  }
  return [
    "No ways in found.",
    tested > 0
      ? `We tried ${plural(tested, "attack")} on a test copy of ${plural(tables, "table")}. None got through.`
      : `We checked ${plural(tables, "table")} and found nothing a visitor or user could attack.`,
  ];
}

function renderCoverage(issues: LoadIssue[]): void {
  ui.coverage.hidden = issues.length === 0;
  const shown = issues.slice(0, 6).map((issue) =>
    el(
      "li",
      {},
      el("strong", { text: describeStatement(issue.statement) }),
      el("span", { text: explainError(issue.error, inputKind) }),
    ),
  );
  if (issues.length > shown.length) {
    shown.push(el("li", { className: "hint", text: `…and ${issues.length - shown.length} more, listed in the report.` }));
  }
  ui.coverageList.replaceChildren(...shown);
}

function countSeverities(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) counts[f.severity]++;
  return counts;
}

// `step` is the delay between rows; `base` delays a whole column (the "after fix" tags land later).
type Timing = { index: number; base: number; step: number };

// A padlock: open (shackle raised) for attacks that work, shut for blocked ones.
function lockIcon(): SVGSVGElement {
  const ns = "http://www.w3.org/2000/svg";
  const svg = document.createElementNS(ns, "svg");
  svg.setAttribute("class", "lock");
  svg.setAttribute("viewBox", "0 0 16 16");
  svg.setAttribute("aria-hidden", "true");
  const shackle = document.createElementNS(ns, "path");
  shackle.setAttribute("class", "shackle");
  shackle.setAttribute("d", "M5.25 7.5V5.25a2.75 2.75 0 0 1 5.5 0V7.5");
  const body = document.createElementNS(ns, "rect");
  for (const [k, v] of Object.entries({ x: "3.5", y: "7.5", width: "9", height: "6.5", rx: "1.6" })) body.setAttribute(k, v);
  svg.append(shackle, body);
  return svg;
}

function chip(kind: "possible" | "blocked" | "decide" | "open" | "untested", text: string, t: Timing): HTMLElement {
  return el(
    "span",
    { className: `chip ${kind} press`, attrs: { style: `--i: ${t.index}; --base: ${t.base}ms; --step: ${t.step}ms` } },
    lockIcon(),
    text,
  );
}

function afterChip(p: ProofRow, t: Timing): HTMLElement {
  if (p.after === false) return chip("blocked", "Blocked", t);
  if (p.after === null) return chip("untested", "Not tested", t);
  return p.autoFixed ? chip("open", "Still possible", t) : chip("decide", "Your call", t);
}

function renderLedger(proven: ProofRow[], all: ProofRow[]): Node {
  const wrap = el("div");
  if (proven.length > 0) {
    const rows = proven.map((p, i) => {
      // The preview reveals its tags one by one; rows behind "Show all" land quickly together.
      const later = i >= LEDGER_PREVIEW;
      const index = later ? i - LEDGER_PREVIEW : i;
      const step = later ? 35 : 110;
      const row = el(
        "tr",
        {},
        el("td", { className: "where", attrs: { "data-label": "Where" } }, el("code", { text: plainName(p.table) })),
        el("td", { className: "attack", text: p.test, attrs: { "data-label": "Attack" } }),
        el("td", { attrs: { "data-label": "Before" } }, chip("possible", "Possible", { index, base: 0, step })),
        el("td", { attrs: { "data-label": "After fix" } }, afterChip(p, { index, base: later ? 250 : 500, step })),
      );
      row.hidden = i >= LEDGER_PREVIEW;
      return row;
    });
    wrap.append(
      el(
        "table",
        { className: "ledger" },
        el(
          "thead",
          {},
          el(
            "tr",
            {},
            el("th", { text: "Where", attrs: { scope: "col" } }),
            el("th", { text: "Attack", attrs: { scope: "col" } }),
            el("th", { text: "Before", attrs: { scope: "col" } }),
            el("th", { text: "After fix", attrs: { scope: "col" } }),
          ),
        ),
        el("tbody", {}, ...rows),
      ),
    );
    if (proven.length > LEDGER_PREVIEW) {
      const more = el("button", {
        className: "text-button ledger-more",
        text: `Show all ${proven.length} attacks`,
        attrs: { type: "button" },
      });
      more.addEventListener("click", () => {
        for (const row of rows) row.hidden = false;
        more.remove();
        refreshMotion();
      });
      wrap.append(more);
    }
  }
  const alreadyBlocked = all.filter((p) => p.before === false).length;
  const untested = all.filter((p) => p.before === null).length;
  const tested = all.length - untested;
  const notes = [
    proven.length === 0 && tested > 0
      ? `None of the ${plural(tested, "attack")} we ${untested > 0 ? "could test" : "tried"} got through.`
      : "",
    alreadyBlocked > 0 && proven.length > 0
      ? `${plural(alreadyBlocked, "other attack")} ${alreadyBlocked === 1 ? "was" : "were"} already blocked.`
      : "",
    untested > 0 ? `${plural(untested, "attack")} couldn't be tested automatically.` : "",
  ].filter(Boolean);
  if (notes.length > 0) wrap.append(el("p", { className: "hint", text: notes.join(" ") }));
  return wrap;
}

function renderFinding(f: Finding): HTMLElement {
  const details = el(
    "details",
    { className: `finding sev-${f.severity}` },
    el("summary", {}, el("span", { className: "sev", text: SEVERITY_LABEL[f.severity] }), el("span", { className: "finding-title", text: withoutPublic(f.title) })),
    el("p", { text: withoutPublic(f.plain) }),
    el("p", {}, el("strong", { text: "Fix: " }), f.fix, " ", el("em", { text: f.autoFixed ? "(Included in fix.sql.)" : "(Needs a manual step.)" })),
    el("p", { className: "where" }, "Where: ", el("code", { text: withoutPublic(f.target) })),
  );
  details.open = f.severity === "critical";
  return details;
}

startMotion();
