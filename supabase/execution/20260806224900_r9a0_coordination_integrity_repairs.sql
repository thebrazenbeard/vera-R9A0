begin;

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'r9a0_owner') then
    create role r9a0_owner
      nologin
      nosuperuser
      nocreatedb
      nocreaterole
      noinherit;
  else
    alter role r9a0_owner
      nologin
      nosuperuser
      nocreatedb
      nocreaterole
      noinherit;
  end if;
end;
$$;

alter schema r9a0_governance owner to r9a0_owner;
alter schema r9a0_coordination owner to r9a0_owner;
alter schema r9a0_api owner to r9a0_owner;

alter table r9a0_governance.migration_applications owner to r9a0_owner;
alter table r9a0_coordination.events owner to r9a0_owner;
alter sequence r9a0_coordination.events_event_sequence_seq owner to r9a0_owner;

alter table r9a0_governance.migration_applications force row level security;
alter table r9a0_coordination.events force row level security;

drop policy if exists migration_applications_owner_access
  on r9a0_governance.migration_applications;
create policy migration_applications_owner_access
  on r9a0_governance.migration_applications
  as permissive for all to r9a0_owner
  using (true) with check (true);

drop policy if exists events_owner_access
  on r9a0_coordination.events;
create policy events_owner_access
  on r9a0_coordination.events
  as permissive for all to r9a0_owner
  using (true) with check (true);

create or replace function r9a0_governance.validate_event_chain()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog
as $$
declare
  v_head_id uuid;
  v_reference_id uuid;
  v_reference_thread text;
  v_link_count integer;
begin
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('r9a0-thread:' || new.thread_key, 0)
  );

  select e.event_id
    into v_head_id
  from r9a0_coordination.events e
  where e.thread_key = new.thread_key
    and not exists (
      select 1
      from r9a0_coordination.events successor
      where successor.thread_key = e.thread_key
        and (
          successor.supersedes_event_id = e.event_id
          or successor.acknowledges_event_id = e.event_id
        )
    )
  order by e.event_sequence desc
  limit 1;

  v_link_count :=
    (case when new.supersedes_event_id is null then 0 else 1 end)
    + (case when new.acknowledges_event_id is null then 0 else 1 end);

  if v_head_id is null then
    if v_link_count <> 0 then
      raise exception 'Initial event for thread % cannot reference a predecessor', new.thread_key
        using errcode = '23514';
    end if;
  else
    if v_link_count <> 1 then
      raise exception 'Non-initial event for thread % must reference exactly one current head', new.thread_key
        using errcode = '23514';
    end if;

    v_reference_id := coalesce(new.supersedes_event_id, new.acknowledges_event_id);

    if v_reference_id <> v_head_id then
      raise exception 'Event for thread % must reference current head %', new.thread_key, v_head_id
        using errcode = '23514';
    end if;

    select e.thread_key
      into v_reference_thread
    from r9a0_coordination.events e
    where e.event_id = v_reference_id;

    if not found or v_reference_thread <> new.thread_key then
      raise exception 'Cross-thread coordination reference is not permitted'
        using errcode = '23514';
    end if;
  end if;

  return new;
end;
$$;

drop trigger if exists events_validate_graph on r9a0_coordination.events;
drop trigger if exists events_validate_chain on r9a0_coordination.events;
create trigger events_validate_chain
before insert on r9a0_coordination.events
for each row execute function r9a0_governance.validate_event_chain();

create unique index if not exists events_single_superseder_idx
  on r9a0_coordination.events (supersedes_event_id)
  where supersedes_event_id is not null;

create unique index if not exists events_single_acknowledger_idx
  on r9a0_coordination.events (acknowledges_event_id)
  where acknowledges_event_id is not null;

create or replace view r9a0_coordination.thread_heads
with (security_invoker = true)
as
select e.*
from r9a0_coordination.events e
where not exists (
  select 1
  from r9a0_coordination.events successor
  where successor.thread_key = e.thread_key
    and (
      successor.supersedes_event_id = e.event_id
      or successor.acknowledges_event_id = e.event_id
    )
);

create or replace view r9a0_coordination.latest_thread_state
with (security_invoker = true)
as
select distinct on (thread_key)
  event_id,
  event_sequence,
  operation_id,
  request_digest,
  thread_key,
  source_address,
  target_address,
  event_type,
  status,
  objective,
  summary,
  active_issue,
  supersedes_event_id,
  acknowledges_event_id,
  payload,
  reference_data,
  record_time
from r9a0_coordination.thread_heads
order by thread_key, event_sequence desc;

create or replace view r9a0_coordination.open_threads
with (security_invoker = true)
as
select *
from r9a0_coordination.latest_thread_state
where status in ('BLOCKED','DEGRADED','CHANGES_REQUESTED','IN_PROGRESS');

create or replace function r9a0_api.append_coordination_event(
  p_operation_id text,
  p_thread_key text,
  p_source_address text,
  p_target_address text,
  p_event_type text,
  p_status text,
  p_objective text,
  p_summary text,
  p_active_issue text default null,
  p_supersedes_event_id uuid default null,
  p_acknowledges_event_id uuid default null,
  p_payload jsonb default '{}'::jsonb,
  p_reference_data jsonb default '{}'::jsonb
)
returns jsonb
language plpgsql
security definer
set search_path = pg_catalog
as $$
declare
  v_digest text;
  v_existing r9a0_coordination.events%rowtype;
  v_inserted r9a0_coordination.events%rowtype;
begin
  perform r9a0_governance.require_service_role();

  if p_operation_id is null or p_operation_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$' then
    raise exception 'Invalid operation_id' using errcode = '22023';
  end if;

  if p_payload is null or pg_catalog.jsonb_typeof(p_payload) <> 'object'
     or pg_catalog.pg_column_size(p_payload) > 16384 then
    raise exception 'payload must be a JSON object no larger than 16384 bytes'
      using errcode = '22023';
  end if;

  if p_reference_data is null or pg_catalog.jsonb_typeof(p_reference_data) <> 'object'
     or pg_catalog.pg_column_size(p_reference_data) > 16384 then
    raise exception 'reference_data must be a JSON object no larger than 16384 bytes'
      using errcode = '22023';
  end if;

  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('r9a0-operation:' || p_operation_id, 0)
  );
  perform pg_catalog.pg_advisory_xact_lock(
    pg_catalog.hashtextextended('r9a0-thread:' || p_thread_key, 0)
  );

  v_digest := r9a0_governance.sha256_text(pg_catalog.jsonb_build_object(
    'operation_id', p_operation_id,
    'thread_key', p_thread_key,
    'source_address', p_source_address,
    'target_address', p_target_address,
    'event_type', p_event_type,
    'status', p_status,
    'objective', p_objective,
    'summary', p_summary,
    'active_issue', p_active_issue,
    'supersedes_event_id', p_supersedes_event_id,
    'acknowledges_event_id', p_acknowledges_event_id,
    'payload', p_payload,
    'reference_data', p_reference_data
  )::text);

  select *
    into v_existing
  from r9a0_coordination.events
  where operation_id = p_operation_id;

  if found then
    if v_existing.request_digest <> v_digest then
      raise exception 'IDEMPOTENCY_CONFLICT for operation_id %', p_operation_id
        using errcode = '23505';
    end if;

    return pg_catalog.jsonb_build_object(
      'result', 'EXISTING',
      'event_id', v_existing.event_id,
      'event_sequence', v_existing.event_sequence,
      'operation_id', v_existing.operation_id,
      'request_digest', v_existing.request_digest,
      'record_time', v_existing.record_time
    );
  end if;

  insert into r9a0_coordination.events (
    operation_id,
    request_digest,
    thread_key,
    source_address,
    target_address,
    event_type,
    status,
    objective,
    summary,
    active_issue,
    supersedes_event_id,
    acknowledges_event_id,
    payload,
    reference_data
  ) values (
    p_operation_id,
    v_digest,
    p_thread_key,
    p_source_address,
    p_target_address,
    p_event_type,
    p_status,
    p_objective,
    p_summary,
    p_active_issue,
    p_supersedes_event_id,
    p_acknowledges_event_id,
    p_payload,
    p_reference_data
  )
  returning * into v_inserted;

  return pg_catalog.jsonb_build_object(
    'result', 'INSERTED',
    'event_id', v_inserted.event_id,
    'event_sequence', v_inserted.event_sequence,
    'operation_id', v_inserted.operation_id,
    'request_digest', v_inserted.request_digest,
    'record_time', v_inserted.record_time
  );
exception
  when unique_violation then
    select *
      into v_existing
    from r9a0_coordination.events
    where operation_id = p_operation_id;

    if not found or v_existing.request_digest <> v_digest then
      raise exception 'IDEMPOTENCY_CONFLICT for operation_id %', p_operation_id
        using errcode = '23505';
    end if;

    return pg_catalog.jsonb_build_object(
      'result', 'EXISTING',
      'event_id', v_existing.event_id,
      'event_sequence', v_existing.event_sequence,
      'operation_id', v_existing.operation_id,
      'request_digest', v_existing.request_digest,
      'record_time', v_existing.record_time
    );
end;
$$;

alter function r9a0_governance.sha256_text(text) owner to r9a0_owner;
alter function r9a0_governance.require_service_role() owner to r9a0_owner;
alter function r9a0_governance.block_append_only_mutation() owner to r9a0_owner;
alter function r9a0_governance.validate_event_chain() owner to r9a0_owner;
alter function r9a0_api.append_coordination_event(
  text,text,text,text,text,text,text,text,text,uuid,uuid,jsonb,jsonb
) owner to r9a0_owner;

alter view r9a0_coordination.thread_heads owner to r9a0_owner;
alter view r9a0_coordination.latest_thread_state owner to r9a0_owner;
alter view r9a0_coordination.open_threads owner to r9a0_owner;

alter default privileges for role r9a0_owner in schema r9a0_governance
  revoke all on tables from public, anon, authenticated, service_role;
alter default privileges for role r9a0_owner in schema r9a0_governance
  revoke all on sequences from public, anon, authenticated, service_role;
alter default privileges for role r9a0_owner in schema r9a0_governance
  revoke all on functions from public, anon, authenticated, service_role;
alter default privileges for role r9a0_owner in schema r9a0_coordination
  revoke all on tables from public, anon, authenticated, service_role;
alter default privileges for role r9a0_owner in schema r9a0_coordination
  revoke all on sequences from public, anon, authenticated, service_role;
alter default privileges for role r9a0_owner in schema r9a0_coordination
  revoke all on functions from public, anon, authenticated, service_role;
alter default privileges for role r9a0_owner in schema r9a0_api
  revoke all on functions from public, anon, authenticated, service_role;

revoke all on r9a0_coordination.thread_heads from public, anon, authenticated, service_role;
revoke all on r9a0_coordination.latest_thread_state from public, anon, authenticated, service_role;
revoke all on r9a0_coordination.open_threads from public, anon, authenticated, service_role;
revoke all on function r9a0_api.append_coordination_event(
  text,text,text,text,text,text,text,text,text,uuid,uuid,jsonb,jsonb
) from public, anon, authenticated, service_role;

grant usage on schema r9a0_governance to service_role;
grant usage on schema r9a0_coordination to service_role;
grant usage on schema r9a0_api to service_role;
grant select on r9a0_governance.migration_applications to service_role;
grant select on r9a0_coordination.events to service_role;
grant select on r9a0_coordination.thread_heads to service_role;
grant select on r9a0_coordination.latest_thread_state to service_role;
grant select on r9a0_coordination.open_threads to service_role;
grant execute on function r9a0_api.append_coordination_event(
  text,text,text,text,text,text,text,text,text,uuid,uuid,jsonb,jsonb
) to service_role;

commit;
