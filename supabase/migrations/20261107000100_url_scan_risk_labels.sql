-- URL scanner classification values. Keep existing labels during transition so
-- historical records from the dashboard remain valid.
alter table public.scans
  drop constraint if exists scans_risk_level_check;

alter table public.scans
  add constraint scans_risk_level_check
  check (risk_level in (
    'unknown', 'info', 'low', 'medium', 'high', 'critical',
    'LOW_RISK', 'SUSPICIOUS', 'HIGH_RISK', 'CONFIRMED_MALICIOUS', 'INCONCLUSIVE'
  ));

create index if not exists scans_user_risk_created_idx
  on public.scans (user_id, risk_level, created_at desc);
