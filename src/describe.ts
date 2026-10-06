// Plain-English wording shared by the report and the web page.

export type InputKind = "snapshot" | "migrations";

export const plural = (n: number, one: string, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

// Most apps keep everything in the public schema, so "public." is noise for a reader.
export function plainName(name: string): string {
  return name.replace(/"((?:[^"]|"")+)"/g, (_, inner: string) => inner.replace(/""/g, '"')).replace(/^public\./, "");
}

// Drops "public." from names inside a sentence ("public.notes" → "notes"), leaving a sentence-ending
// "public." alone.
export function withoutPublic(text: string): string {
  return text.replace(/"public"\.(?=")/g, "").replace(/\bpublic\.(?=[\w"])/g, "");
}

const IDENT = String.raw`(?:"(?:[^"]|"")+"|[\w$]+)`;
const NAME = String.raw`(${IDENT}(?:\.${IDENT})?)`;
const KINDS: [RegExp, (m: RegExpExecArray) => string][] = [
  [new RegExp(String.raw`^create policy (${IDENT}) on ${NAME}`, "i"), (m) => `Access rule ${m[1]} on ${plainName(m[2])}`],
  [new RegExp(String.raw`^create (?:or replace )?function ${NAME}`, "i"), (m) => `Function ${plainName(m[1])}()`],
  [new RegExp(String.raw`^create (?:or replace )?(?:materialized )?view ${NAME}`, "i"), (m) => `View ${plainName(m[1])}`],
  [new RegExp(String.raw`^create (?:constraint )?trigger (${IDENT})[\s\S]*? on ${NAME}`, "i"), (m) => `Trigger ${m[1]} on ${plainName(m[2])}`],
  [new RegExp(String.raw`^create table (?:if not exists )?${NAME}`, "i"), (m) => `Table ${plainName(m[1])}`],
];

// Names the part of the database a statement builds, falling back to the start of the statement.
export function describeStatement(statement: string): string {
  const flat = statement.replace(/\s+/g, " ").trim();
  for (const [pattern, label] of KINDS) {
    const match = pattern.exec(flat);
    if (match) return label(match);
  }
  const short = withoutPublic(flat);
  return short.length > 90 ? `${short.slice(0, 88)}…` : short;
}

// What the fix does about the attacks that worked, in one sentence.
export function fixOutcome(proven: number, blocked: number): string {
  if (blocked === proven) return proven === 1 ? "The fix blocks it." : "The fix blocks all of them.";
  if (blocked > 0) return `The fix blocks ${blocked} of them; the rest are explained below.`;
  return proven === 1 ? "It can't be closed automatically; it's explained below." : "None of them can be closed automatically; each is explained below.";
}

// Turns a database error from the test copy into a reason a non-specialist can follow.
export function explainError(error: string, input: InputKind): string {
  const where = input === "snapshot" ? "what you pasted" : "your migration files";
  let m: RegExpExecArray | null;
  if ((m = /schema "([^"]+)" does not exist/i.exec(error))) return `It uses the "${m[1]}" schema, which isn't in ${where}.`;
  if ((m = /function (.+?) does not exist/i.exec(error))) return `It calls ${plainName(m[1])}, which isn't in ${where}.`;
  if ((m = /relation "([^"]+)" does not exist/i.exec(error))) return `It refers to ${plainName(m[1])}, which isn't in ${where}.`;
  if ((m = /type "([^"]+)" does not exist/i.exec(error))) return `It uses the data type ${plainName(m[1])}, which isn't in ${where}.`;
  if ((m = /role "([^"]+)" does not exist/i.exec(error))) return `It mentions the database role ${m[1]}, which the test copy doesn't have.`;
  if ((m = /extension "([^"]+)"/i.exec(error))) return `It needs the ${m[1]} extension, which this check can't run.`;
  if (/syntax error/i.test(error)) return "This check couldn't read it.";
  const sentence = error.charAt(0).toUpperCase() + error.slice(1);
  return /[.!?]$/.test(sentence) ? sentence : `${sentence}.`;
}
