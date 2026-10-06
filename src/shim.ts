// A minimal stand-in for the parts of a Supabase database that app migrations
// depend on: API roles, the auth schema and its helper functions, storage tables,
// and Supabase's default grants on the public schema.
export const SUPABASE_SHIM = String.raw`
create role anon nologin noinherit;
create role authenticated nologin noinherit;
create role service_role nologin noinherit bypassrls;
create role authenticator noinherit;
create role supabase_admin;
create role supabase_auth_admin;
create role supabase_storage_admin;
create role dashboard_user;
grant anon, authenticated, service_role to authenticator;

create schema auth;
create schema extensions;
create schema storage;
create schema realtime;
create schema graphql_public;

-- Supabase pre-installs these, so migrations call their functions without creating them.
create extension if not exists pgcrypto with schema extensions;
create extension if not exists "uuid-ossp" with schema extensions;
-- Common optional extensions, so snapshot column types (citext) and triggers (moddatetime) resolve.
create extension if not exists citext with schema extensions;
create extension if not exists moddatetime with schema extensions;
create extension if not exists pg_trgm with schema extensions;

create table auth.users (
  instance_id uuid,
  id uuid primary key,
  aud text,
  role text,
  email text unique,
  encrypted_password text,
  email_confirmed_at timestamptz,
  confirmed_at timestamptz,
  invited_at timestamptz,
  confirmation_sent_at timestamptz,
  recovery_sent_at timestamptz,
  email_change text,
  phone text,
  phone_confirmed_at timestamptz,
  raw_app_meta_data jsonb default '{}'::jsonb,
  raw_user_meta_data jsonb default '{}'::jsonb,
  is_super_admin boolean,
  is_sso_user boolean default false,
  is_anonymous boolean default false,
  banned_until timestamptz,
  deleted_at timestamptz,
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  last_sign_in_at timestamptz
);

-- No-op stand-ins for Supabase extensions that can't run offline (pg_cron, pg_net, Vault,
-- pgmq, database webhooks), so migrations that call them still load.
create schema cron;
create table cron.job (jobid bigint primary key, jobname text, schedule text, command text, active boolean default true);
create function cron.schedule(job_name text, schedule text, command text) returns bigint language sql as $$ select 1::bigint $$;
create function cron.schedule(schedule text, command text) returns bigint language sql as $$ select 1::bigint $$;
create function cron.unschedule(job_name text) returns boolean language sql as $$ select true $$;
create function cron.unschedule(job_id bigint) returns boolean language sql as $$ select true $$;

create schema net;
create function net.http_post(url text, body jsonb default '{}'::jsonb, params jsonb default '{}'::jsonb, headers jsonb default '{}'::jsonb, timeout_milliseconds integer default 5000)
  returns bigint language sql as $$ select 1::bigint $$;
create function net.http_get(url text, params jsonb default '{}'::jsonb, headers jsonb default '{}'::jsonb, timeout_milliseconds integer default 5000)
  returns bigint language sql as $$ select 1::bigint $$;

create schema vault;
create table vault.secrets (id uuid primary key default gen_random_uuid(), name text unique, description text, secret text, created_at timestamptz default now());
create view vault.decrypted_secrets as select id, name, description, secret, secret as decrypted_secret, created_at from vault.secrets;
create function vault.create_secret(new_secret text, new_name text default null, new_description text default '')
  returns uuid language sql as $$ insert into vault.secrets (name, description, secret) values (new_name, new_description, new_secret) returning id $$;

create schema pgmq;
create type pgmq.message_record as (msg_id bigint, read_ct integer, enqueued_at timestamptz, vt timestamptz, message jsonb);
create function pgmq.create(queue_name text) returns void language plpgsql as $$ begin end $$;
create function pgmq.send(queue_name text, msg jsonb, delay integer default 0) returns setof bigint language sql as $$ select 1::bigint $$;
create function pgmq.read(queue_name text, vt integer, qty integer) returns setof pgmq.message_record
  language sql as $$ select null::bigint, 0, now(), now(), '{}'::jsonb where false $$;
create function pgmq.delete(queue_name text, msg_id bigint) returns boolean language sql as $$ select true $$;
create function pgmq.archive(queue_name text, msg_id bigint) returns boolean language sql as $$ select true $$;

create schema supabase_functions;
create function supabase_functions.http_request() returns trigger language plpgsql as $$ begin return new; end $$;

create function auth.jwt() returns jsonb language sql stable as $$
  select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb
$$;
create function auth.uid() returns uuid language sql stable as $$
  select nullif(coalesce(current_setting('request.jwt.claim.sub', true), auth.jwt() ->> 'sub'), '')::uuid
$$;
create function auth.role() returns text language sql stable as $$
  select nullif(coalesce(current_setting('request.jwt.claim.role', true), auth.jwt() ->> 'role'), '')::text
$$;
create function auth.email() returns text language sql stable as $$
  select nullif(coalesce(current_setting('request.jwt.claim.email', true), auth.jwt() ->> 'email'), '')::text
$$;

grant usage on schema public, auth, extensions, storage to anon, authenticated, service_role;
grant execute on all functions in schema auth to anon, authenticated, service_role;

alter default privileges in schema public grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public grant all on sequences to anon, authenticated, service_role;
alter default privileges in schema public grant all on functions to anon, authenticated, service_role;

create table storage.buckets (
  id text primary key,
  name text not null,
  owner uuid,
  public boolean default false,
  avif_autodetection boolean default false,
  file_size_limit bigint,
  allowed_mime_types text[],
  type text default 'STANDARD',
  created_at timestamptz default now(),
  updated_at timestamptz default now()
);
create table storage.objects (
  id uuid primary key default gen_random_uuid(),
  bucket_id text references storage.buckets(id),
  name text,
  owner uuid,
  owner_id text,
  metadata jsonb,
  user_metadata jsonb,
  version text,
  path_tokens text[],
  created_at timestamptz default now(),
  updated_at timestamptz default now(),
  last_accessed_at timestamptz default now()
);
alter table storage.buckets enable row level security;
alter table storage.objects enable row level security;
grant all on storage.buckets, storage.objects to anon, authenticated, service_role;

create function storage.foldername(name text) returns text[] language sql immutable as $$
  select (string_to_array(name, '/'))[1:greatest(array_length(string_to_array(name, '/'), 1) - 1, 0)]
$$;
create function storage.filename(name text) returns text language sql immutable as $$
  select (string_to_array(name, '/'))[array_length(string_to_array(name, '/'), 1)]
$$;
create function storage.extension(name text) returns text language sql immutable as $$
  select reverse(split_part(reverse(storage.filename(name)), '.', 1))
$$;
grant execute on all functions in schema storage to anon, authenticated, service_role;

do $$ begin
  create publication supabase_realtime;
exception when others then null;
end $$;
`;
