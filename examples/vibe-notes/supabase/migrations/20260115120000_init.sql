-- DEMO ONLY: a typical schema from an AI app builder, with the mistakes
-- Lockstamp is built to catch. Not a real project; every key in this demo is fake.

-- Profiles for each signed-up user
create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text,
  avatar_url text,
  role text not null default 'user',
  created_at timestamptz not null default now()
);

-- Notes written by users
create table public.notes (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id) on delete cascade,
  title text not null,
  body text,
  is_pinned boolean not null default false,
  created_at timestamptz not null default now()
);

alter table public.notes enable row level security;

create policy "Enable read access for all users"
  on public.notes for select
  using (true);

create policy "Enable insert for authenticated users only"
  on public.notes for insert
  to authenticated
  with check (true);

create policy "Users can update their own notes"
  on public.notes for update
  using (auth.uid() = user_id);

-- Billing details
create table public.subscriptions (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references auth.users(id),
  plan text not null default 'free',
  stripe_customer_id text,
  current_period_end timestamptz
);

-- App-wide settings
create table public.app_settings (
  key text primary key,
  value jsonb not null default '{}'::jsonb
);

-- Note counts per user for the dashboard
create view public.note_counts as
  select user_id, count(*) as total
  from public.notes
  group by user_id;

-- Create a profile when someone signs up
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer set search_path = public
as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, new.raw_user_meta_data ->> 'full_name');
  return new;
end;
$$;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute procedure public.handle_new_user();

-- Admin helper used by the dashboard
create or replace function public.get_all_emails()
returns table (email text)
language sql
security definer
as $$
  select email from auth.users;
$$;

-- Avatar uploads
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true);
