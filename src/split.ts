// Splits a SQL script into statements, respecting strings, quoted identifiers,
// dollar-quoted bodies and comments, so one failing statement can be skipped.
export function splitSql(sql: string): string[] {
  const statements: string[] = [];
  let buf = "";
  let i = 0;
  const n = sql.length;

  while (i < n) {
    const ch = sql[i];
    const next = sql[i + 1];

    if (ch === "-" && next === "-") {
      const end = sql.indexOf("\n", i);
      const stop = end === -1 ? n : end;
      buf += sql.slice(i, stop);
      i = stop;
      continue;
    }

    if (ch === "/" && next === "*") {
      let depth = 1;
      let j = i + 2;
      while (j < n && depth > 0) {
        if (sql[j] === "/" && sql[j + 1] === "*") {
          depth++;
          j += 2;
        } else if (sql[j] === "*" && sql[j + 1] === "/") {
          depth--;
          j += 2;
        } else {
          j++;
        }
      }
      buf += sql.slice(i, j);
      i = j;
      continue;
    }

    if (ch === "'") {
      const escapeString = /[eE]$/.test(buf) && !/[A-Za-z0-9_]$/.test(buf.slice(0, -1));
      let j = i + 1;
      while (j < n) {
        if (escapeString && sql[j] === "\\") {
          j += 2;
          continue;
        }
        if (sql[j] === "'") {
          if (sql[j + 1] === "'") {
            j += 2;
            continue;
          }
          break;
        }
        j++;
      }
      buf += sql.slice(i, j + 1);
      i = j + 1;
      continue;
    }

    if (ch === '"') {
      let j = i + 1;
      while (j < n) {
        if (sql[j] === '"') {
          if (sql[j + 1] === '"') {
            j += 2;
            continue;
          }
          break;
        }
        j++;
      }
      buf += sql.slice(i, j + 1);
      i = j + 1;
      continue;
    }

    if (ch === "$" && !/[A-Za-z0-9_]$/.test(buf)) {
      const m = /^\$([A-Za-z_][A-Za-z0-9_]*)?\$/.exec(sql.slice(i, i + 64));
      if (m) {
        const tag = m[0];
        const end = sql.indexOf(tag, i + tag.length);
        const stop = end === -1 ? n : end + tag.length;
        buf += sql.slice(i, stop);
        i = stop;
        continue;
      }
    }

    if (ch === ";") {
      pushStatement(statements, buf);
      buf = "";
      i++;
      continue;
    }

    buf += ch;
    i++;
  }

  pushStatement(statements, buf);
  return statements;
}

function pushStatement(out: string[], raw: string): void {
  const trimmed = raw.trim();
  const withoutComments = trimmed.replace(/--[^\n]*/g, "").replace(/\/\*[\s\S]*?\*\//g, "").trim();
  if (withoutComments.length > 0) out.push(trimmed);
}
