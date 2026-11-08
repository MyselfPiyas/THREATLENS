begin;

-- No extension is required. Stable fixture IDs and guards make reruns safe;
-- the final rollback removes any fixture rows added by this run.
insert into auth.users (id, email, raw_user_meta_data, created_at, updated_at)
values
  ('11111111-1111-4111-8111-111111111111', 'rls-one@threatlens.test', '{"full_name":"RLS User One"}', now(), now()),
  ('22222222-2222-4222-8222-222222222222', 'rls-two@threatlens.test', '{"full_name":"RLS User Two"}', now(), now())
on conflict (id) do nothing;

insert into public.scans (id, user_id, scan_type, target, normalized_target)
values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1', '11111111-1111-4111-8111-111111111111', 'url', 'fixture-one.example', 'https://fixture-one.example'),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2', '11111111-1111-4111-8111-111111111111', 'url', 'fixture-two.example', 'https://fixture-two.example'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1', '22222222-2222-4222-8222-222222222222', 'url', 'fixture-three.example', 'https://fixture-three.example')
on conflict (id) do nothing;

insert into public.scan_findings (scan_id, category, title, description, severity, source, confidence)
select fixture.scan_id, fixture.category, fixture.title, fixture.description,
       fixture.severity, fixture.source, fixture.confidence
from (values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'::uuid, 'fixture', 'RLS test fixture', 'Database policy test fixture.', 'info', 'sql-test', 1::numeric),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1'::uuid, 'fixture', 'RLS test fixture', 'Database policy test fixture.', 'info', 'sql-test', 1::numeric)
) as fixture(scan_id, category, title, description, severity, source, confidence)
where not exists (
  select 1 from public.scan_findings existing
  where existing.scan_id = fixture.scan_id and existing.source = fixture.source and existing.title = fixture.title
);

insert into public.scan_events (scan_id, event_type, title, description)
select fixture.scan_id, fixture.event_type, fixture.title, fixture.description
from (values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'::uuid, 'fixture', 'RLS test fixture', 'Database policy test fixture.'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1'::uuid, 'fixture', 'RLS test fixture', 'Database policy test fixture.')
) as fixture(scan_id, event_type, title, description)
where not exists (
  select 1 from public.scan_events existing
  where existing.scan_id = fixture.scan_id and existing.event_type = fixture.event_type and existing.title = fixture.title
);

insert into public.trust_passports (scan_id, report_hash, verification_status)
select fixture.scan_id, fixture.report_hash, fixture.verification_status
from (values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'::uuid, 'test-hash-one', 'not_published'),
  ('bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1'::uuid, 'test-hash-two', 'not_published')
) as fixture(scan_id, report_hash, verification_status)
where not exists (
  select 1 from public.trust_passports existing
  where existing.scan_id = fixture.scan_id and existing.report_hash = fixture.report_hash
);

insert into public.scan_relationships (source_scan_id, related_scan_id, relationship_type, confidence)
select fixture.source_scan_id, fixture.related_scan_id, fixture.relationship_type, fixture.confidence
from (values
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'::uuid, 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa2'::uuid, 'fixture_pair', 1::numeric),
  ('aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaa1'::uuid, 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbb1'::uuid, 'fixture_cross_user', 1::numeric)
) as fixture(source_scan_id, related_scan_id, relationship_type, confidence)
where not exists (
  select 1 from public.scan_relationships existing
  where existing.source_scan_id = fixture.source_scan_id and existing.related_scan_id = fixture.related_scan_id
    and existing.relationship_type = fixture.relationship_type
);

do $$
declare
  enabled_table_count integer;
  policy_count integer;
begin
  select count(*) into enabled_table_count
  from pg_class as c
  join pg_namespace as n on n.oid = c.relnamespace
  where n.nspname = 'public'
    and c.relname in ('profiles', 'scans', 'scan_findings', 'threat_indicators', 'scan_events', 'trust_passports', 'scan_relationships')
    and c.relrowsecurity;
  if enabled_table_count <> 7 then
    raise exception 'Expected RLS on all 7 THREATLENS tables; found %', enabled_table_count;
  end if;

  select count(*) into policy_count
  from pg_policies
  where schemaname = 'public'
    and policyname in ('profiles_select_own', 'profiles_update_own', 'scans_select_own', 'scan_findings_select_own', 'scan_events_select_own', 'trust_passports_select_own', 'scan_relationships_select_own');
  if policy_count <> 7 then
    raise exception 'Expected 7 ownership policies; found %', policy_count;
  end if;

  if has_table_privilege('anon', 'public.profiles', 'select')
    or has_table_privilege('anon', 'public.scans', 'select')
    or has_table_privilege('anon', 'public.scan_findings', 'select')
    or has_table_privilege('anon', 'public.threat_indicators', 'select')
    or has_table_privilege('anon', 'public.scan_events', 'select')
    or has_table_privilege('anon', 'public.trust_passports', 'select')
    or has_table_privilege('anon', 'public.scan_relationships', 'select') then
    raise exception 'Anonymous role unexpectedly has table read access';
  end if;

  if has_table_privilege('authenticated', 'public.threat_indicators', 'select')
    or has_table_privilege('authenticated', 'public.scans', 'insert')
    or has_table_privilege('authenticated', 'public.scan_findings', 'insert')
    or has_table_privilege('authenticated', 'public.scan_events', 'insert') then
    raise exception 'Authenticated role unexpectedly has privileged access';
  end if;

  if not has_table_privilege('service_role', 'public.threat_indicators', 'select')
    or not has_table_privilege('service_role', 'public.scans', 'insert') then
    raise exception 'Service role is missing required backend privileges';
  end if;
end
$$;

set local role authenticated;
select set_config('request.jwt.claim.sub', '11111111-1111-4111-8111-111111111111', true);
do $$
declare
  profile_count integer;
  scan_count integer;
  finding_count integer;
  event_count integer;
  passport_count integer;
  relationship_count integer;
begin
  select count(*) into profile_count from public.profiles;
  select count(*) into scan_count from public.scans;
  select count(*) into finding_count from public.scan_findings;
  select count(*) into event_count from public.scan_events;
  select count(*) into passport_count from public.trust_passports;
  select count(*) into relationship_count from public.scan_relationships;

  if (profile_count, scan_count, finding_count, event_count, passport_count, relationship_count)
    is distinct from (1, 2, 1, 1, 1, 1) then
    raise exception 'User one ownership counts are incorrect: profiles %, scans %, findings %, events %, passports %, relationships %',
      profile_count, scan_count, finding_count, event_count, passport_count, relationship_count;
  end if;
end
$$;

select set_config('request.jwt.claim.sub', '22222222-2222-4222-8222-222222222222', true);
do $$
declare
  profile_count integer;
  scan_count integer;
  finding_count integer;
  event_count integer;
  passport_count integer;
  relationship_count integer;
begin
  select count(*) into profile_count from public.profiles;
  select count(*) into scan_count from public.scans;
  select count(*) into finding_count from public.scan_findings;
  select count(*) into event_count from public.scan_events;
  select count(*) into passport_count from public.trust_passports;
  select count(*) into relationship_count from public.scan_relationships;

  if (profile_count, scan_count, finding_count, event_count, passport_count, relationship_count)
    is distinct from (1, 1, 1, 1, 1, 0) then
    raise exception 'User two ownership counts are incorrect: profiles %, scans %, findings %, events %, passports %, relationships %',
      profile_count, scan_count, finding_count, event_count, passport_count, relationship_count;
  end if;
end
$$;
reset role;
rollback;
