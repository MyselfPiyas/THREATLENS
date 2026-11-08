-- Part 9: stable Trust Passport metadata. Run in Supabase SQL Editor.
alter table public.trust_passports
  add column if not exists updated_at timestamptz not null default now();

create index if not exists trust_passports_status_created_idx
  on public.trust_passports (verification_status, created_at desc);

create or replace function public.set_trust_passport_updated_at()
returns trigger
language plpgsql
security invoker
as $$
begin
  new.updated_at = now();
  return new;
end;
$$;

drop trigger if exists trust_passports_set_updated_at on public.trust_passports;
create trigger trust_passports_set_updated_at
before update on public.trust_passports
for each row execute function public.set_trust_passport_updated_at();

-- Privileged writes stay backend-only; authenticated users read only rows tied
-- to scans they own through the existing RLS policy.
grant all on table public.trust_passports to service_role;
