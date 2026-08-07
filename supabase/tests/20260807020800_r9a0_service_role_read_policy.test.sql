begin;

do $$
declare
  v_event_policy_roles name[];
  v_receipt_policy_roles name[];
begin
  select roles
    into v_event_policy_roles
  from pg_policies
  where schemaname = 'r9a0_coordination'
    and tablename = 'events'
    and policyname = 'events_service_role_read'
    and cmd = 'SELECT'
    and permissive = 'PERMISSIVE';

  if v_event_policy_roles is null
     or not ('service_role' = any(v_event_policy_roles)) then
    raise exception 'events service_role SELECT policy is missing or malformed';
  end if;

  select roles
    into v_receipt_policy_roles
  from pg_policies
  where schemaname = 'r9a0_governance'
    and tablename = 'migration_applications'
    and policyname = 'migration_applications_service_role_read'
    and cmd = 'SELECT'
    and permissive = 'PERMISSIVE';

  if v_receipt_policy_roles is null
     or not ('service_role' = any(v_receipt_policy_roles)) then
    raise exception 'migration receipt service_role SELECT policy is missing or malformed';
  end if;

  if exists (
    select 1
    from pg_policies
    where policyname in (
      'events_service_role_read',
      'migration_applications_service_role_read'
    )
      and ('anon' = any(roles) or 'authenticated' = any(roles) or 'public' = any(roles))
  ) then
    raise exception 'service_role read policy leaked to a broader role';
  end if;
end;
$$;

do $$
declare
  v_inserted jsonb;
  v_event_id uuid;
  v_visible_id uuid;
begin
  perform set_config('request.jwt.claim.role', 'service_role', true);
  execute 'set local role service_role';

  v_inserted := r9a0_api.append_coordination_event(
    'r9a0-service-read-test-0001',
    'r9a0/test/service-role-read',
    'test/producer',
    'test/reviewer',
    'STATUS',
    'IN_PROGRESS',
    'Create a row for the service-role projection regression.',
    'Synthetic read-policy test event.',
    null,
    null,
    null,
    '{"synthetic":true}'::jsonb,
    '{"test":"service-role-read-policy"}'::jsonb
  );

  v_event_id := (v_inserted->>'event_id')::uuid;

  select event_id
    into v_visible_id
  from r9a0_coordination.latest_thread_state
  where thread_key = 'r9a0/test/service-role-read';

  if v_visible_id is distinct from v_event_id then
    raise exception 'service_role cannot read the controlling tip through latest_thread_state';
  end if;

  perform count(*) from r9a0_coordination.events;
  perform count(*) from r9a0_governance.migration_applications;

  if has_table_privilege('service_role', 'r9a0_coordination.events', 'INSERT')
     or has_table_privilege('service_role', 'r9a0_coordination.events', 'UPDATE')
     or has_table_privilege('service_role', 'r9a0_coordination.events', 'DELETE')
     or has_table_privilege('service_role', 'r9a0_coordination.events', 'TRUNCATE') then
    raise exception 'service_role gained a direct mutation privilege';
  end if;

  execute 'reset role';
end;
$$;

rollback;
