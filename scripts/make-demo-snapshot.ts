// Builds the demo app's database and saves its snapshot for the website's "try the demo" button.
import { writeFile } from "node:fs/promises";
import { join } from "node:path";
import { readMigrations } from "../src/files.js";
import { applySql, createDatabase } from "../src/load.js";
import { SNAPSHOT_QUERY } from "../src/snapshot.js";

const root = join(import.meta.dirname, "..");
const db = await createDatabase();
await applySql(db, await readMigrations(join(root, "examples", "vibe-notes", "supabase", "migrations")));
const { rows } = await db.query<{ snapshot: unknown }>(SNAPSHOT_QUERY);
await db.close();
await writeFile(join(root, "web", "public", "demo-snapshot.json"), JSON.stringify(rows[0].snapshot, null, 2));
console.log("wrote web/public/demo-snapshot.json");
