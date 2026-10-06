import { existsSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";
import { analyze, type GuardResult, type Source } from "./analyze.js";
import { readCodeFiles, readMigrations } from "./files.js";

export interface GuardOptions {
  projectDir: string;
  migrationsDir?: string;
  // A JSON snapshot from the snapshot query, used instead of migrations.
  snapshotFile?: string;
  schemas?: string[];
  verify?: boolean;
  scanCode?: boolean;
}

export async function runGuard(options: GuardOptions): Promise<GuardResult> {
  const projectDir = resolve(options.projectDir);
  let source: Source;

  if (options.snapshotFile) {
    source = { kind: "snapshot", text: await readFile(resolve(options.snapshotFile), "utf8") };
  } else {
    const migrationsDir = resolve(options.migrationsDir ?? join(projectDir, "supabase", "migrations"));
    if (!existsSync(migrationsDir)) {
      throw new Error(
        `No migrations folder at ${migrationsDir}. Point to one with --migrations <folder>, or use --snapshot <file> (see --snapshot-query).`,
      );
    }
    source = { kind: "migrations", files: await readMigrations(migrationsDir) };
  }

  return analyze({
    projectName: basename(projectDir),
    source,
    codeFiles: options.scanCode === false ? [] : await readCodeFiles(projectDir),
    schemas: options.schemas,
    verify: options.verify,
  });
}

export { analyze, type GuardResult } from "./analyze.js";
export { buildFix } from "./fix.js";
export { checkSchema } from "./checks.js";
export { introspect } from "./introspect.js";
export { renderReport } from "./report.js";
export { SNAPSHOT_QUERY } from "./snapshot.js";
export type * from "./types.js";
