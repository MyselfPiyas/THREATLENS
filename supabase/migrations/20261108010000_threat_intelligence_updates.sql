-- Part 8: preserve indicator history while recording update time and preventing duplicates.
alter table public.threat_indicators
  add column if not exists updated_at timestamptz not null default now();

create unique index if not exists threat_indicators_source_type_value_uidx
  on public.threat_indicators (source, indicator_type, indicator_value);

drop trigger if exists threat_indicators_set_updated_at on public.threat_indicators;
create trigger threat_indicators_set_updated_at
  before update on public.threat_indicators
  for each row execute function public.set_updated_at();

grant all on table public.threat_indicators to service_role;
