-- Part 9 off-chain SHA-256 passports. No wallet, RPC, or contract is used.
-- Legacy chain-reference columns are retained only for backward compatibility.
alter table public.trust_passports
  add column if not exists user_id uuid references public.profiles(id) on delete cascade,
  add column if not exists report_version text not null default '1.0',
  add column if not exists canonical_report jsonb not null default '{}'::jsonb,
  add column if not exists hash_algorithm text not null default 'SHA-256',
  add column if not exists public_token text,
  add column if not exists public_sharing_enabled boolean not null default false,
  add column if not exists verification_at timestamptz;

update public.trust_passports as passports
set user_id = scans.user_id
from public.scans
where passports.scan_id = scans.id
  and passports.user_id is null;

alter table public.trust_passports alter column user_id set not null;

-- Ownership is recorded on the passport itself as well as checked against the
-- source scan. Service-role backend writes remain privileged; browser users
-- receive read-only access to their own passport rows.
drop policy if exists trust_passports_select_own on public.trust_passports;
create policy trust_passports_select_own on public.trust_passports
  for select to authenticated
  using (user_id = auth.uid() and private.user_owns_scan(scan_id));

revoke all on table public.trust_passports from anon;
revoke insert, update, delete on table public.trust_passports from authenticated;
grant select on table public.trust_passports to authenticated;

create unique index if not exists trust_passports_public_token_uidx
  on public.trust_passports (public_token)
  where public_token is not null;
create index if not exists trust_passports_user_created_idx
  on public.trust_passports (user_id, created_at desc);
create index if not exists trust_passports_sharing_idx
  on public.trust_passports (public_sharing_enabled, public_token)
  where public_sharing_enabled = true;

grant all on table public.trust_passports to service_role;
