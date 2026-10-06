import type { Finding, Severity } from "./types.js";

export interface CodeFile {
  path: string;
  text: string;
}

interface Pattern {
  label: string;
  severity: Severity;
  regex: RegExp;
}

const PATTERNS: Pattern[] = [
  { label: "Supabase secret key", severity: "critical", regex: /\bsb_secret_[A-Za-z0-9_-]{16,}/g },
  { label: "Stripe live secret key", severity: "critical", regex: /\b[rs]k_live_[A-Za-z0-9]{16,}/g },
  { label: "Stripe test secret key", severity: "medium", regex: /\b[rs]k_test_[A-Za-z0-9]{16,}/g },
  { label: "Anthropic API key", severity: "high", regex: /\bsk-ant-[A-Za-z0-9_-]{20,}/g },
  { label: "OpenAI API key", severity: "high", regex: /\bsk-(?!ant-)(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}/g },
  { label: "AWS access key", severity: "high", regex: /\bAKIA[0-9A-Z]{16}\b/g },
  { label: "GitHub token", severity: "high", regex: /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g },
  { label: "Private key", severity: "high", regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g },
];

const JWT = /\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}/g;
const PUBLIC_ENV_SECRET = /\b(?:VITE|NEXT_PUBLIC|REACT_APP|EXPO_PUBLIC|PUBLIC|NUXT_PUBLIC)_[A-Z0-9_]*(?:SERVICE_ROLE|SECRET|PRIVATE)[A-Z0-9_]*\b/g;

type Location = "browser" | "server" | "database";

const EXPOSURE: Record<Location, string> = {
  browser: "It's in code that runs in the browser, so anyone visiting your site can find it.",
  server: "It's written into your code files, so anyone who can see your code (or your repository, if it's public) can use it.",
  database: "It's written into a database function, so anyone with access to your database, its dashboard or its backups can read it.",
};

export function scanCodeFiles(files: CodeFile[]): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const f of files) {
    const path = f.path.split("\\").join("/");
    scanText(f.text, (line) => `${path}:${line}`, isServerPath(path) ? "server" : "browser", seen, findings);
  }
  return findings;
}

export function scanFunctionSecrets(functions: { schema?: string; name: string; definition: string }[]): Finding[] {
  const findings: Finding[] = [];
  const seen = new Set<string>();
  for (const f of functions) scanText(f.definition, () => `function ${f.schema ?? "public"}.${f.name}`, "database", seen, findings);
  return findings;
}

function scanText(text: string, where: (line: number) => string, location: Location, seen: Set<string>, findings: Finding[]): void {
  text.split(/\r?\n/).forEach((line, index) => {
    const at = where(index + 1);
    const add = (label: string, severity: Severity, sample: string, explanation?: string) => {
      const key = `${at}|${label}`;
      if (seen.has(key)) return;
      seen.add(key);
      findings.push(secretFinding(label, location === "browser" ? severity : downgrade(severity), at, sample, location, explanation));
    };

    for (const match of line.matchAll(JWT)) {
      if (jwtRole(match[0]) === "service_role") add("Supabase service_role key", "critical", match[0]);
    }
    for (const p of PATTERNS) {
      for (const match of line.matchAll(p.regex)) add(p.label, p.severity, match[0]);
    }
    for (const match of line.matchAll(PUBLIC_ENV_SECRET)) {
      add(
        `Secret in a public environment variable (${match[0]})`,
        "critical",
        match[0],
        `Variables that start with ${match[0].split("_")[0]}_ are copied into your website when it's built, so anyone can read their values.`,
      );
    }
  });
}

// An explanation means the match is a variable name, not a key value, so it is shown in full.
function secretFinding(label: string, severity: Severity, where: string, sample: string, location: Location, explanation?: string): Finding {
  return {
    rule: "secret_in_code",
    severity,
    target: where,
    title: `${label} found in ${where}`,
    plain: explanation ? `${explanation} Found: ${sample}` : `${EXPOSURE[location]} Found: ${redact(sample)}`,
    fix: "Treat this key as leaked: replace (rotate) it in the provider's dashboard now, delete it from the code, and move whatever needs it into a server-side function that reads it from a secret setting.",
    autoFixed: false,
  };
}

function jwtRole(token: string): string | null {
  try {
    const b64 = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
    const padded = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const json = new TextDecoder().decode(Uint8Array.from(atob(padded), (c) => c.charCodeAt(0)));
    const role = (JSON.parse(json) as { role?: unknown }).role;
    return typeof role === "string" ? role : null;
  } catch {
    return null;
  }
}

function redact(value: string): string {
  return value.length <= 12 ? value : `${value.slice(0, 10)}… (${value.length} characters)`;
}

function downgrade(severity: Severity): Severity {
  return severity === "critical" ? "high" : severity;
}

function isServerPath(path: string): boolean {
  return /(^|\/)(supabase\/functions|server|api|backend|scripts|functions)\//.test(path);
}
