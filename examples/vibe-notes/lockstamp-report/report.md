# Database security check: vibe-notes

Checked 2026-10-08 with Lockstamp · 4 tables · 11 findings

## Summary

**Found: 5 critical, 5 high, 1 info.**

22 attacks worked on a private test copy of your database. The fix blocks all of them. Leaked keys need a manual step (see below).

## Proof: attacks tried before and after the fix

We rebuilt your database setup in a private test copy, added two fake users, and tried the attacks below. No real data was touched.

| Table | Attack | Before fix | After fix |
|---|---|---|---|
| app_settings | A visitor who isn't logged in can add rows | **Possible** | Blocked |
| app_settings | A visitor who isn't logged in can change rows | **Possible** | Blocked |
| app_settings | A visitor who isn't logged in can delete rows | **Possible** | Blocked |
| notes | A visitor who isn't logged in can read rows | **Possible** | Blocked |
| notes | A logged-in user can read another user's rows | **Possible** | Blocked |
| notes | A logged-in user can add rows in another user's name | **Possible** | Blocked |
| profiles | A visitor who isn't logged in can read rows | **Possible** | Blocked |
| profiles | A visitor who isn't logged in can add rows | **Possible** | Blocked |
| profiles | A logged-in user can read another user's rows | **Possible** | Blocked |
| profiles | A logged-in user can change another user's rows | **Possible** | Blocked |
| profiles | A logged-in user can delete another user's rows | **Possible** | Blocked |
| profiles | A logged-in user can add rows in another user's name | **Possible** | Blocked |
| profiles | A logged-in user can change their own role | **Possible** | Blocked |
| subscriptions | A visitor who isn't logged in can read rows | **Possible** | Blocked |
| subscriptions | A visitor who isn't logged in can add rows | **Possible** | Blocked |
| subscriptions | A logged-in user can read another user's rows | **Possible** | Blocked |
| subscriptions | A logged-in user can change another user's rows | **Possible** | Blocked |
| subscriptions | A logged-in user can delete another user's rows | **Possible** | Blocked |
| subscriptions | A logged-in user can add rows in another user's name | **Possible** | Blocked |
| subscriptions | A logged-in user can change their own billing records | **Possible** | Blocked |
| note_counts | A visitor who isn't logged in can read data through this view | **Possible** | Blocked |
| get_all_emails() | A visitor who isn't logged in can call this function and get user data | **Possible** | Blocked |

22 attacks worked before the fix, and the fix blocks all of them. 3 other attacks were already blocked.

## What we found

### 1. Critical: Row Level Security is off for app_settings

**What this means:** Anyone who has your app's public key (it's visible in your website's code) can read, add, change and delete every row in "app_settings".

**Fix:** Turn on Row Level Security. The fix allows read-only access for now. Decide whether "app_settings" should be public at all. _(Included in fix.sql.)_

**Where:** `app_settings`

### 2. Critical: Row Level Security is off for profiles

**What this means:** Anyone who has your app's public key (it's visible in your website's code) can read, add, change and delete every row in "profiles".

**Fix:** Turn on Row Level Security and add rules so each user can only reach their own rows (matched on id). _(Included in fix.sql.)_

**Where:** `profiles`

### 3. Critical: Row Level Security is off for subscriptions

**What this means:** Anyone who has your app's public key (it's visible in your website's code) can read, add, change and delete every row in "subscriptions".

**Fix:** Turn on Row Level Security so each user can only read their own rows. Changes to "subscriptions" should come only from your server (for example a payment webhook or an admin function). _(Included in fix.sql.)_

**Where:** `subscriptions`

### 4. Critical: Secret in a public environment variable (VITE_SUPABASE_SERVICE_ROLE_KEY) found in src/config.ts:2

**What this means:** Variables that start with VITE_ are copied into your website when it's built, so anyone can read their values. Found: VITE_SUPABASE_SERVICE_ROLE_KEY

**Fix:** Treat this key as leaked: replace (rotate) it in the provider's dashboard now, delete it from the code, and move whatever needs it into a server-side function that reads it from a secret setting. _(Needs a manual step.)_

**Where:** `src/config.ts:2`

### 5. Critical: Supabase service_role key found in src/lib/admin.ts:7

**What this means:** It's in code that runs in the browser, so anyone visiting your site can find it. Found: eyJhbGciOi… (221 characters)

**Fix:** Treat this key as leaked: replace (rotate) it in the provider's dashboard now, delete it from the code, and move whatever needs it into a server-side function that reads it from a secret setting. _(Needs a manual step.)_

**Where:** `src/lib/admin.ts:7`

### 6. High: Rule "Enable insert for authenticated users only" on notes lets users reach other users' rows

**What this means:** Any logged-in user can add rows to "notes" that claim to belong to a different user.

**Fix:** Replace this rule with one that only matches rows where user_id is the current user. _(Included in fix.sql.)_

**Where:** `notes, rule "Enable insert for authenticated users only"`

### 7. High: Rule "Enable read access for all users" on notes lets users read other users' rows

**What this means:** Anyone, even without logging in, can see every user's rows in "notes", not just their own.

**Fix:** Replace this rule with one that only matches rows where user_id is the current user. _(Included in fix.sql.)_

**Where:** `notes, rule "Enable read access for all users"`

### 8. High: Users can set their own role in profiles

**What this means:** When a user edits their own row in "profiles", nothing stops them from also changing "role". That could let someone make themselves an admin or unlock paid features for free.

**Fix:** Allow users to edit only the safe columns of "profiles"; "role" can then only be changed by your server. _(Included in fix.sql.)_

**Where:** `profiles`

### 9. High: View note_counts ignores Row Level Security

**What this means:** "note_counts" shows data using its creator's full permissions, so it skips your access rules. Anyone with your app's public key can read everything it shows.

**Fix:** Make the view run with the permissions of the person asking (security_invoker), so your table rules apply. _(Included in fix.sql.)_

**Where:** `note_counts`

### 10. High: Function get_all_emails exposes your users table

**What this means:** "get_all_emails" reads your users table (emails and account details) with full database permissions, and anyone, even without logging in, can call it.

**Fix:** Stop the public and logged-in users from calling it. If your app needs it, call it from a server function instead. _(Included in fix.sql.)_

**Where:** `get_all_emails()`

### 11. Info: Storage bucket "avatars" is public

**What this means:** Anyone with a file's link can download files in "avatars". That's fine for things like profile pictures, not for private documents.

**Fix:** If files in "avatars" are private, make the bucket private and serve files with signed links. _(Needs a manual step.)_

**Where:** `storage bucket "avatars"`

## What to do next

1. Replace (rotate) every leaked key listed above in its provider's dashboard **today**. Removing it from the code isn't enough, because old versions of your site still contain it.
2. Read `fix.sql`, then apply it as a new migration or paste it into your SQL editor.
3. Test your app's main features while logged in as a normal user.
4. Run this check again to confirm everything shows as blocked.

## What this check covers

This check reviews your database access rules (Row Level Security), views, database functions, storage buckets, and secret keys stored in database functions or in the code files it was given. It does not test your live site, and it is not a guarantee that the app has no other vulnerabilities.
