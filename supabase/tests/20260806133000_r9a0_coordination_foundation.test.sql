begin;

-- Structural assertions.
do $$
begin
  if to_regclass('r9a0_coordination.events') is null then
    raise exception 'missing r9a0_coordination.events';
  end if;
  if to_regclass('r9a0_governance.migration_applications') is null then
    raise exception 'missing r9a0_governance.migration_applications';
  end if;
  if to_regprocedure('r9a0_api.append_coordination_event(text,text,text,text,text,text,text,text,text,uuid,uuid,jsonb,jsonb)') is null then
    raise exception 'missing append_coordination_event RPC';
  end if;
end;
$$;

-- Client roles must not have direct table privileges.
do $$
declare
  v_role text;
  v_privilege text;
begin
  foreach v_role in array array['anon','authenticated'] loop
    foreach v_privilege in array array['SELECT','INSERT','UPDATE','DELETE','TRUNCATE'] loop
      if has_table_privilege(v_role, 'r9a0_coordination.events', v_privilege) then
        raise exception '% unexpectedly has % on r9a0_coordination.events', v_role, v_privilege;
      end if;
    end loop;
  end loop;
end;
$$;

-- Idempotent insert and replay.
do $$
declare
  v_first jsonb;
  v_second jsonb;
begin
  v_first := r9a0_api.append_coordination_event(
    'r9a0-test-coordination-0001',
    'r9a0/test/coordination',
    'debug/masamune/masa',
    'auditor/voss',
    'STATUS',
    'IN_PROGRESS',
    'Verify R9A0 coordination foundation.',
    'Synthetic transactional test event.',
    null,
    null,
    null,
    '{"synthetic":true}'::jsonb,
    '{"test":"idempotency"}'::jsonb
  );

  v_second := r9a0_api.append_coordination_event(
    'r9a0-test-coordination-0001',
    'r9a0/test/coordination',
    'debug/masamune/masa',
    'auditor/voss',
    'STATUS',
    'IN_PROGRESS',
    'Verify R9A0 coordination foundation.',
    'Synthetic transactional test event.',
    null,
    null,
    null,
    '{"synthetic":true}'::jsonb,
    '{"test":"idempotency"}'::jsonb
  );

  if v_first->>'result' <> 'INSERTED' then
    raise exception 'first call did not insert: %', v_first;
  end if;
  if v_second->>'result' <> 'EXISTING' then
    raise exception 'second call did not replay: %', v_second;
  end if;
  if v_first->>'event_id' <> v_second->>'event_id' then
    raise exception 'idempotent replay returned a different event';
  end if;
end;
$$;

-- Same operation ID with different content must fail closed.
do $$
begin
  begin
    perform r9a0_api.append_coordination_event(
      'r9a0-test-coordination-0001',
      'r9a0/test/coordination',
      'debug/masamune/masa',
      'auditor/voss',
      'STATUS',
      'IN_PROGRESS',
      'Verify R9A0 coordination foundation.',
      'Different content must conflict.',
      null,
      null,
      null,
      '{"synthetic":true}'::jsonb,
      '{"test":"idempotency"}'::jsonb
    );
    raise exception 'expected idempotency conflict was not raised';
  exception
    when unique_violation then null;
  end;
end;
$$;

-- UPDATE, DELETE, and TRUNCATE must all be blocked.
do $$
begin
  begin
    update r9a0_coordination.events set summary = 'forbidden';
    raise exception 'UPDATE was not blocked';
  exception
    when sqlstate '55000' then null;
  end;

  begin
    delete from r9a0_coordination.events;
    raise exception 'DELETE was not blocked';
  exception
    when sqlstate '55000' then null;
  end;

  begin
    truncate table r9a0_coordination.events;
    raise exception 'TRUNCATE was not blocked';
  exception
    when sqlstate '55000' then null;
  end;
end;
$$;

rollback;
