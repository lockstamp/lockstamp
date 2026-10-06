# Lockstamp

Find and fix the security holes that AI app builders (Lovable, Bolt, Replit, v0) commonly leave in Supabase apps — and prove the fix works before you ship it.

**Try it free in your browser: [lockstamp.github.io](https://lockstamp.github.io/)** — nothing is uploaded.

Lockstamp is an independent project. It is not affiliated with or endorsed by Supabase, Lovable, Bolt or Replit.

```bash
npm install
npm run guard -- path/to/your-app
```

It reads your `supabase/migrations` folder and your source code, then writes three files to `your-app/lockstamp-report/`:

| File | What it is |
|---|---|
| `report.md` | Plain-English findings, plus a before/after table of attacks that were tried |
| `fix.sql` | A reviewable migration that closes the database problems |
| `results.json` | Machine-readable findings and attack results |

### In the browser

`npm run web:dev` starts a web version of the same check. Paste a snapshot (or pick migration files) and it runs entirely in the browser tab — the database engine is compiled to WebAssembly, so nothing is uploaded. `npm run web:build` produces a static site in `dist-web/` that any static host can serve.

### No migrations folder? Use a snapshot

If your app was built in the Supabase dashboard (or your migrations don't match your database), check a snapshot instead:

1. Open the Supabase SQL editor, paste in [`snapshot.sql`](snapshot.sql) (also printed by `npm run guard -- --snapshot-query`), and run it.
2. Copy the single `snapshot` result into a file, e.g. `snapshot.json`.
3. Run `npm run guard -- --snapshot snapshot.json`.

The query is read-only and collects only your database's structure — tables, columns, access rules, functions, views and triggers. It never reads rows of data, and no passwords are involved.

## What it checks

- Tables with **Row Level Security turned off** (anyone with the public key can read and change every row)
- Rules that let users **see or change other users' rows** (`using (true)`, `with check (true)`)
- Users who can **set their own role, plan or credits** on their own row
- **Billing or permission tables** that users can write to
- **Views** that skip Row Level Security
- **Security-definer functions** that expose `auth.users` to the public
- **Public storage buckets**
- **Secret keys in code**: Supabase `service_role` / `sb_secret_`, Stripe, OpenAI, Anthropic, AWS, GitHub tokens, private keys, and secrets in `VITE_` / `NEXT_PUBLIC_` variables (which get bundled into the browser) — and, in snapshot mode, keys written into database functions

## How the proof works

1. Your migrations are loaded into a private, in-memory Postgres ([PGlite](https://pglite.dev)) with a small stand-in for Supabase's `auth` and `storage` schemas and default grants. Nothing touches your real database, and nothing goes over the network.
2. Two fake users are added, then the tool attacks the database the way a stranger would: as a visitor who isn't logged in, and as a logged-in user going after someone else's data.
3. The generated `fix.sql` is applied to a fresh copy and every attack is repeated.

The report shows which attacks worked before the fix and confirms they are blocked after it.

## Example

[`examples/vibe-notes`](examples/vibe-notes) is a demo app with the mistakes AI builders typically make (all keys are fake). Result:

```
lockstamp: 4 tables checked
  findings: 5 critical, 5 high, 0 medium, 0 low, 1 info
  attacks that worked: 22 before the fix, 0 after
```

Read the [full report](examples/vibe-notes/lockstamp-report/report.md) and the [generated fix](examples/vibe-notes/lockstamp-report/fix.sql).

## Tested on real apps

We ran Lockstamp offline against 35 public GitHub projects built with Lovable and Supabase (public code only; no live sites were touched, and individual results aren't published). Of the 29 that had a migrations folder:

- 27 could be rebuilt from their migrations (1,242 tables); 2 couldn't, because parts of their database were changed by hand in the Supabase dashboard.
- Attacks worked in 14 of them — 115 in total.
- 23 of those attacks, in 5 projects, reached clearly private data. The generated fix blocked all 23.
- The other 92 were left for a human decision: data that may be meant to be public, or rules too complex to change safely without context.
- The fix applied cleanly every time.
- 16 secret keys were found committed to code.

## Options

```
lockstamp [project-folder] [options]

  --migrations <dir>  Migrations folder (default: <project>/supabase/migrations)
  --snapshot <file>   Check a snapshot instead of migrations (JSON from --snapshot-query)
  --snapshot-query    Print the read-only query to run in the Supabase SQL editor
  --out <dir>         Where to write the report (default: <project>/lockstamp-report)
  --schema <name>     Schema exposed through the API (default: public; repeatable)
  --no-verify         Skip the before/after attack tests
  --no-code           Skip scanning code for leaked keys
```

The exit code is `1` when critical or high problems are found, so it can fail a CI pipeline.

## Limits

- It analyzes migrations (or a snapshot) and code, not your live site. Nothing is ever run against your real database.
- Statements that use Supabase-only extensions it can't simulate are skipped and listed in the report.
- Generated rules use common ownership patterns (`user_id`, `owner_id`, a foreign key to `auth.users`). Review `fix.sql` before applying it, and test your app afterwards.
- No tool can guarantee an app has no vulnerabilities.

## License

MIT
