-- THREATLENS core data model. User-facing access is read-only for scan data;
-- trusted backend operations use a server-only Supabase secret key.

create schema if not exists private;
revoke all on schema private from public, anon;
grant usage on schema private to authenticated, service_role;

create table if not exists public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text not null default '' check (char_length(full_name) <= 160),
  avatar_url text check (avatar_url is null or avatar_url ~* '^https://'),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table if not exists public.scans (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles (id) on delete cascade,
  scan_type text not null check (length(btrim(scan_type)) > 0),
  target text not null check (length(btrim(target)) > 0),
  normalized_target text not null check (length(btrim(normalized_target)) > 0),
  status text not null default 'queued'
    check (status in ('queued', 'running', 'completed', 'failed', 'cancelled')),
  risk_level text not null default 'unknown'
    check (risk_level in ('unknown', 'info', 'low', 'medium', 'high', 'critical')),
  risk_score integer not null default 0 check (risk_score between 0 and 100),
  summary text not null default '',
  started_at timestamptz not null default now(),
  completed_at timestamptz,
  created_at timestamptz not null default now()
);

create table if not exists public.scan_findings (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  category text not null,
  title text not null,
  description text not null,
  severity text not null,
  evidence jsonb not null default '{}'::jsonb,
  source text not null,
  confidence numeric not null check (confidence between 0 and 1),
  created_at timestamptz not null default now()
);

create table if not exists public.threat_indicators (
  id uuid primary key default gen_random_uuid(),
  indicator_type text not null,
  indicator_value text not null,
  source text not null,
  threat_category text not null,
  confidence numeric not null check (confidence between 0 and 1),
  first_seen timestamptz not null default now(),
  last_seen timestamptz not null default now(),
  metadata jsonb not null default '{}'::jsonb
);

create table if not exists public.scan_events (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  event_type text not null,
  title text not null,
  description text not null,
  event_data jsonb not null default '{}'::jsonb,
  occurred_at timestamptz not null default now()
);

create table if not exists public.trust_passports (
  id uuid primary key default gen_random_uuid(),
  scan_id uuid not null references public.scans (id) on delete cascade,
  report_hash text not null,
  chain_id bigint,
  contract_address text,
  transaction_hash text,
  verification_status text not null,
  created_at timestamptz not null default now()
);

create table if not exists public.scan_relationships (
  id uuid primary key default gen_random_uuid(),
  source_scan_id uuid not null references public.scans (id) on delete cascade,
  related_scan_id uuid not null references public.scans (id) on delete cascade,
  relationship_type text not null,
  confidence numeric not null check (confidence between 0 and 1),
  evidence jsonb not null default '{}'::jsonb,
  constraint scan_relationships_distinct_scans check (source_scan_id <> related_scan_id),
  constraint scan_relationships_unique_pair unique (source_scan_id, related_scan_id, relationship_type)
);

create index if not exists scans_user_created_idx
  on public.scans (user_id, created_at desc);
create index if not exists scans_status_created_idx
  on public.scans (status, created_at desc);
create index if not exists scan_findings_scan_created_idx
  on public.scan_findings (scan_id, created_at desc);
create index if not exists scan_findings_severity_idx
  on public.scan_findings (severity);
create index if not exists threat_indicators_type_value_idx
  on public.threat_indicators (indicator_type, indicator_value);
create index if not exists threat_indicators_category_last_seen_idx
  on public.threat_indicators (threat_category, last_seen desc);
create index if not exists scan_events_scan_occurred_idx
  on public.scan_events (scan_id, occurred_at desc);
create index if not exists trust_passports_scan_created_idx
  on public.trust_passports (scan_id, created_at desc);
create index if not exists scan_relationships_source_idx
  on public.scan_relationships (source_scan_id);
create index if not exists scan_relationships_related_idx
  on public.scan_relationships (related_scan_id);

create or replace function public.set_updated_at()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  new.updated_at := now();
  return new;
end;
$$;

create or replace function public.create_profile_for_auth_user()
returns trigger
language plpgsql
security definer
set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name)
  values (new.id, coalesce(nullif(btrim(new.raw_user_meta_data ->> 'full_name'), ''), ''))
  on conflict (id) do nothing;
  return new;
end;
$$;

revoke all on function public.set_updated_at() from public, anon, authenticated;
revoke all on function public.create_profile_for_auth_user() from public, anon, authenticated;

drop trigger if exists profiles_set_updated_at on public.profiles;
create trigger profiles_set_updated_at
  before update on public.profiles
  for each row execute function public.set_updated_at();

drop trigger if exists on_auth_user_created on auth.users;
create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.create_profile_for_auth_user();

create or replace function private.user_owns_scan(scan_id uuid)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1
    from public.scans as owned_scan
    where owned_scan.id = scan_id
      and owned_scan.user_id = (select auth.uid())
  );
$$;

revoke all on function private.user_owns_scan(uuid) from public, anon;
grant execute on function private.user_owns_scan(uuid) to authenticated, service_role;

alter table public.profiles enable row level security;
alter table public.scans enable row level security;
alter table public.scan_findings enable row level security;
alter table public.threat_indicators enable row level security;
alter table public.scan_events enable row level security;
alter table public.trust_passports enable row level security;
alter table public.scan_relationships enable row level security;

-- A profile row is created by the auth.users trigger. Users can only read or edit their own profile.
revoke all on table public.profiles from anon, authenticated;
grant select, update on table public.profiles to authenticated;
create policy profiles_select_own on public.profiles
  for select to authenticated using (id = (select auth.uid()));
create policy profiles_update_own on public.profiles
  for update to authenticated
  using (id = (select auth.uid()))
  with check (id = (select auth.uid()));

-- Scan records and their derived data are read-only to end users. Trusted backend writes
-- use a server-only secret key and still validate the requesting user's ownership.
revoke all on table public.scans from anon, authenticated;
grant select on table public.scans to authenticated;
create policy scans_select_own on public.scans
  for select to authenticated using (user_id = (select auth.uid()));

revoke all on table public.scan_findings from anon, authenticated;
grant select on table public.scan_findings to authenticated;
create policy scan_findings_select_own on public.scan_findings
  for select to authenticated using (private.user_owns_scan(scan_id));

-- Threat intelligence is restricted to trusted backend access only.
revoke all on table public.threat_indicators from anon, authenticated;

revoke all on table public.scan_events from anon, authenticated;
grant select on table public.scan_events to authenticated;
create policy scan_events_select_own on public.scan_events
  for select to authenticated using (private.user_owns_scan(scan_id));

revoke all on table public.trust_passports from anon, authenticated;
grant select on table public.trust_passports to authenticated;
create policy trust_passports_select_own on public.trust_passports
  for select to authenticated using (private.user_owns_scan(scan_id));

revoke all on table public.scan_relationships from anon, authenticated;
grant select on table public.scan_relationships to authenticated;
create policy scan_relationships_select_own on public.scan_relationships
  for select to authenticated
  using (
    private.user_owns_scan(source_scan_id)
    and private.user_owns_scan(related_scan_id)
  );

-- Supabase secret/service-role credentials bypass RLS. Keep them in the backend only.
grant all on table public.profiles to service_role;
grant all on table public.scans to service_role;
grant all on table public.scan_findings to service_role;
grant all on table public.threat_indicators to service_role;
grant all on table public.scan_events to service_role;
grant all on table public.trust_passports to service_role;
grant all on table public.scan_relationships to service_role;
