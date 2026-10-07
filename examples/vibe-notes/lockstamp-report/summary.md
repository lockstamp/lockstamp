### Lockstamp: 22 attacks worked on a private copy of this database

The fix blocks all of them. **5 critical · 5 high · 1 info**

| Where | Attack | Before | After fix |
|---|---|---|---|
| app_settings | A visitor who isn't logged in can add rows | 🔓 Possible | 🔒 Blocked |
| app_settings | A visitor who isn't logged in can change rows | 🔓 Possible | 🔒 Blocked |
| app_settings | A visitor who isn't logged in can delete rows | 🔓 Possible | 🔒 Blocked |
| notes | A visitor who isn't logged in can read rows | 🔓 Possible | 🔒 Blocked |
| notes | A logged-in user can read another user's rows | 🔓 Possible | 🔒 Blocked |
| notes | A logged-in user can add rows in another user's name | 🔓 Possible | 🔒 Blocked |
| profiles | A visitor who isn't logged in can read rows | 🔓 Possible | 🔒 Blocked |
| profiles | A visitor who isn't logged in can add rows | 🔓 Possible | 🔒 Blocked |
| profiles | A logged-in user can read another user's rows | 🔓 Possible | 🔒 Blocked |
| profiles | A logged-in user can change another user's rows | 🔓 Possible | 🔒 Blocked |
| … | 12 more in the report | | |

**Top findings**
- Critical: Row Level Security is off for app_settings
- Critical: Row Level Security is off for profiles
- Critical: Row Level Security is off for subscriptions
- Critical: Secret in a public environment variable (VITE_SUPABASE_SERVICE_ROLE_KEY) found in src/config.ts:2
- Critical: Supabase service_role key found in src/lib/admin.ts:7

The full report and `fix.sql` are in `lockstamp-report/`. Lockstamp rebuilds the database from the migrations in a private in-memory copy and tries each attack before and after the fix; no real database is touched.