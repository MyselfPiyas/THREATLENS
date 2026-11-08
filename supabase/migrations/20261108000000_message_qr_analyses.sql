-- Ephemeral analysis results contain derived indicators only; raw message/image bytes are never stored.
create table if not exists public.message_analyses (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  result jsonb not null,
  created_at timestamptz not null default now()
);
create table if not exists public.qr_analyses (
  id uuid primary key default gen_random_uuid(),
  user_id uuid not null references public.profiles(id) on delete cascade,
  result jsonb not null,
  created_at timestamptz not null default now()
);
create index if not exists message_analyses_user_created_idx on public.message_analyses(user_id, created_at desc);
create index if not exists qr_analyses_user_created_idx on public.qr_analyses(user_id, created_at desc);
alter table public.message_analyses enable row level security;
alter table public.qr_analyses enable row level security;

grant select on table public.message_analyses to authenticated;
grant select on table public.qr_analyses to authenticated;
grant all on table public.message_analyses to service_role;
grant all on table public.qr_analyses to service_role;
drop policy if exists message_analyses_owner_select on public.message_analyses;
create policy message_analyses_owner_select on public.message_analyses for select to authenticated using (user_id = auth.uid());
drop policy if exists qr_analyses_owner_select on public.qr_analyses;
create policy qr_analyses_owner_select on public.qr_analyses for select to authenticated using (user_id = auth.uid());
