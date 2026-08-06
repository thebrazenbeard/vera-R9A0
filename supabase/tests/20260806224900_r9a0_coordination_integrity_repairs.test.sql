begin;

do $$
declare
  v_owner_oid oid;
begin
  select oid into v_owner_oid from pg_roles where rolname = 'r9a0_owner';

  if v_owner_oid is null then
    raise exception 'missing r9a0_owner role';
  end if;

  if (select rolcanlogin from pg_roles where oid = v_owner_oid) then
    raise exception 'r9a0_owner must be NOLOGIN';
  end if;

  if (select rolbypassrls from pg_roles where oid = v_owner_oid) then
    raise exception 'r9a0_owner must not BYPASSRLS';
  end if;

  if (select relowner from pg_class where oid = 'r9a0_coordination.events'::regclass) <> v_owner_oid then
    raise exception 'events table owner mismatch';
  end if;

  if not (select relforcerowsecurity from pg_class where oid = 'r9a0_coordination.events'::regclass) then
    raise exception 'events table does not FORCE RLS';
  end if;

  if not (select relforcerowsecurity from pg_class where oid = 'r9a0_governance.migration_applications'::regclass) then
    raise exception 'migration_applications does not FORCE RLS';
  end if;

  if (
    select proowner
    from pg_proc
    where oid = 'r9a0_api.append_coordination_event(text,text,text,text,text,text,text,text,text,uuid,uuid,jsonb,jsonb)'::regprocedure
  ) <> v_owner_oid then
    raise exception 'append_coordination_event owner mismatch';
  end if;
end;
$$;

do $$
declare
  v_role text;
  v_privilege text;
begin
  foreach v_role in array array['anon','authenticated','service_role'] loop
    foreach v_privilege in array array['INSERT','UPDATE','DELETE','TRUNCATE'] loop
      if has_table_privilege(v_role, 'r9a0_coordination.events', v_privilege) then
        raise exception '% unexpectedly has % on r9a0_coordination.events', v_role, v_privilege;
      end if;
    end loop;
  end loop;

  if has_function_privilege(
    'anon',
    'r9a0_api.append_coordination_event(text,text,text,text,text,text,text,text,text,uuid,uuid,jsonb,jsonb)',
    'EXECUTE'
  ) then
    raise exception 'anon unexpectedly has RPC execute';
  end if;

  if has_function_privilege(
    'authenticated',
    'r9a0_api.append_coordination_event(text,text,text,text,text,text,text,text,text,uuid,uuid,jsonb,jsonb)',
    'EXECUTE'
  ) then
    raise exception 'authenticated unexpectedly has RPC execute';
  end if;

  if not has_function_privilege(
    'service_role',
    'r9a0_api.append_coordination_event(text,text,text,text,text,text,text,text,text,uuid,uuid,jsonb,jsonb)',
    'EXECUTE'
  ) then
    raise exception 'service_role is missing RPC execute';
  end if;
end;
$$;

do $$
declare
  v_first jsonb;
  v_second jsonb;
  v_first_id uuid;
  v_second_id uuid;
begin
  perform set_config('request.jwt.claim.role', 'service_role', true);
  execute 'set local role service_role';

  v_first := r9a0_api.append_coordination_event(
    'r9a0-integrity-test-0001',
    'r9a0/test/integrity-chain',
    'test/producer',
    'test/reviewer',
    'STATUS',
    'IN_PROGRESS',
    'Create the first chain event.',
    'Synthetic integrity test event.',
    null,
    null,
    null,
    '{"synthetic":true}'::jsonb,
    '{"test":"graph"}'::jsonb
  );

  v_first_id := (v_first->>'event_id')::uuid;

  v_second := r9a0_api.append_coordination_event(
    'r9a0-integrity-test-0002',
    'r9a0/test/integrity-chain',
    'test/reviewer',
    'test/producer',
    'REVIEW',
    'APPROVED',
    'Advance the chain through explicit acknowledgement.',
    'Synthetic controlling transition.',
    null,
    null,
    v_first_id,
    '{"synthetic":true}'::jsonb,
    '{"test":"projection"}'::jsonb
  );

  v_second_id := (v_second->>'event_id')::uuid;

  if (
    select event_id
    from r9a0_coordination.latest_thread_state
    where thread_key = 'r9a0/test/integrity-chain'
  ) is distinct from v_second_id then
    raise exception 'latest_thread_state did not select the controlling tip';
  end if;

  begin
    perform r9a0_api.append_coordination_event(
      'r9a0-integrity-test-0003',
      'r9a0/test/integrity-chain',
      'test/producer',
      'test/reviewer',
      'STATUS',
      'IN_PROGRESS',
      'Attempt a stale predecessor fork.',
      'This call must fail.',
      null,
      v_first_id,
      null,
      '{"synthetic":true}'::jsonb,
      '{"test":"fork"}'::jsonb
    );
    raise exception 'stale predecessor fork was not rejected';
  exception
    when check_violation then null;
  end;

  begin
    perform r9a0_api.append_coordination_event(
      'r9a0-integrity-test-0004',
      'r9a0/test/other-thread',
      'test/producer',
      'test/reviewer',
      'STATUS',
      'IN_PROGRESS',
      'Attempt a cross-thread reference.',
      'This call must fail.',
      null,
      null,
      v_second_id,
      '{"synthetic":true}'::jsonb,
      '{"test":"cross-thread"}'::jsonb
    );
    raise exception 'cross-thread reference was not rejected';
  exception
    when check_violation then null;
  end;

  begin
    perform r9a0_api.append_coordination_event(
      'r9a0-integrity-test-0005',
      'r9a0/test/payload-boundary',
      'test/producer',
      'test/reviewer',
      'STATUS',
      'IN_PROGRESS',
      'Reject oversized payload.',
      'This call must fail.',
      null,
      null,
      null,
      jsonb_build_object('blob', repeat('x', 17000)),
      '{}'::jsonb
    );
    raise exception 'oversized payload was not rejected';
  exception
    when invalid_parameter_value then null;
  end;

  execute 'reset role';
end;
$$;

do $$
declare
  v_definition text;
begin
  select pg_get_functiondef(
    'r9a0_governance.validate_event_graph()'::regprocedure
  ) into v_definition;

  if position('pg_advisory_xact_lock' in v_definition) = 0 then
    raise exception 'thread concurrency serialization lock is absent';
  end if;

  if position('r9a0_coordination.events' in v_definition) = 0 then
    raise exception 'graph validator does not use a schema-qualified events reference';
  end if;

  if not exists (
    select 1
    from pg_proc
    where oid = 'r9a0_api.append_coordination_event(text,text,text,text,text,text,text,text,text,uuid,uuid,jsonb,jsonb)'::regprocedure
      and proconfig @> array['search_path=pg_catalog, r9a0_governance, r9a0_coordination']
  ) then
    raise exception 'append_coordination_event search_path is not pinned';
  end if;
end;
$$;

do $$
begin
  insert into r9a0_governance.migration_applications (
    migration_version,
    migration_name,
    migration_sha256,
    repository,
    repository_commit,
    repository_path,
    target_project_ref,
    target_namespace,
    operation_id,
    evidence
  ) values (
    '99999999999999',
    'synthetic_integrity_test',
    repeat('a', 64),
    'thebrazenbeard/vera-R9A0',
    repeat('b', 40),
    'supabase/tests/synthetic.sql',
    'synthetic-test-target',
    'r9a0_coordination',
    'r9a0-integrity-receipt-test-0001',
    '{"synthetic":true}'::jsonb
  );

  begin
    update r9a0_governance.migration_applications
    set evidence = evidence || '{"forbidden":true}'::jsonb;
    raise exception 'migration receipt UPDATE was not blocked';
  exception
    when sqlstate '55000' then null;
  end;

  begin
    delete from r9a0_governance.migration_applications;
    raise exception 'migration receipt DELETE was not blocked';
  exception
    when sqlstate '55000' then null;
  end;

  begin
    truncate table r9a0_governance.migration_applications;
    raise exception 'migration receipt TRUNCATE was not blocked';
  exception
    when sqlstate '55000' then null;
  end;
end;
$$;

rollback;
