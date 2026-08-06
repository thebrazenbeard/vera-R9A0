begin;

do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'r9a0_owner') then
    create role r9a0_owner
      nologin
      nosuperuser
      nocreatedb
      nocreaterole
      noinherit
      noreplication
      nobypassrls;
  end if;
end;
$$;

create or replace function r9a0_governance.validate_event_graph()
returns trigger
language plpgsql
security definer
set search_path = pg_catalog, r9a0_coordination
as $$
declare
  v_predecessor_id uuid;
  v_current_tip_id uuid;
  v_reference_thread text;
begin
  perform pg_advisory_xact_lock(hashtextextended(new.thread_key, 0));

  if new.supersedes_event_id is not null and new.acknowledges_event_id is not null then
    raise exception 'exactly one controlling predecessor reference is permitted'
      using errcode = '23514';
  end if;

  if new.supersedes_event_id is not null then
    select thread_key into v_reference_thread
    from r9a0_coordination.events
    where event_id = new.supersedes_event_id;

    if not found then
      raise exception 'supersedes_event_id does not exist'
        using errcode = '23503';
    end if;

    if v_reference_thread <> new.thread_key then
      raise exception 'supersedes_event_id must reference the same thread'
        using errcode = '23514';
    end if;
  end if;

  if new.acknowledges_event_id is not null then
    select thread_key into v_reference_thread
    from r9a0_coordination.events
    where event_id = new.acknowledges_event_id;

    if not found then
      raise exception 'acknowledges_event_id does not exist'
        using errcode = '23503';
    end if;

    if v_reference_thread <> new.thread_key then
      raise exception 'acknowledges_event_id must reference the same thread'
        using errcode = '23514';
    end if;
  end if;

  select e.event_id
    into v_current_tip_id
  from r9a0_coordination.events e
  where e.thread_key = new.thread_key
    and not exists (
      select 1
      from r9a0_coordination.events successor
      where successor.supersedes_event_id = e.event_id
         or successor.acknowledges_event_id = e.event_id
    )
  order by e.event_sequence desc
  limit 1;

  v_predecessor_id := coalesce(new.supersedes_event_id, new.acknowledges_event_id);

  if v_current_tip_id is null then
    if v_predecessor_id is not null then
      raise exception 'the first event in a thread cannot reference a predecessor'
        using errcode = '23514';
    end if;
  elsif v_predecessor_id is distinct from v_current_tip_id then
    raise exception 'new event must reference the current thread tip %', v_current_tip_id
      using errcode = '23514';
  end if;

  return new;
end;
$$;

drop trigger if exists events_validate_graph on r9a0_coordination.events;
create trigger events_validate_graph
before insert on r9a0_coordination.events
for each row execute function r9a0_governance.validate_event_graph();

create unique index if not exists events_one_superseder_idx
  on r9a0_coordination.events (supersedes_event_id)
  where supersedes_event_id is not null;

create unique index if not exists events_one_acknowledger_idx
  on r9a0_coordination.events (acknowledges_event_id)
  where acknowledges_event_id is not null;

create or replace view r9a0_coordination.latest_thread_state
with (security_invoker = true)
as
select
  e.event_id,
  e.event_sequence,
  e.operation_id,
  e.request_digest,
  e.thread_key,
  e.source_address,
  e.target_address,
  e.event_type,
  e.status,
  e.objective,
  e.summary,
  e.active_issue,
  e.supersedes_event_id,
  e.acknowledges_event_id,
  e.payload,
  e.reference_data,
  e.record_time
from r9a0_coordination.events e
where not exists (
  select 1
  from r9a0_coordination.events successor
  where successor.supersedes_event_id = e.event_id
     or successor.acknowledges_event_id = e.event_id
);

create or replace view r9a0_coordination.open_threads
with (security_invoker = true)
as
select *
from r9a0_coordination.latest_thread_state
where status in ('BLOCKED','DEGRADED','CHANGES_REQUESTED','IN_PROGRESS');

alter table r9a0_governance.migration_applications force row level security;
alter table r9a0_coordination.events force row level security;

do $$
begin
  if not exists (
    select 1 from pg_policies
    where schemaname = 'r9a0_governance'
      and tablename = 'migration_applications'
      and policyname = 'migration_applications_owner_access'
  ) then
    create policy migration_applications_owner_access
      on r9a0_governance.migration_applications
      as permissive for all to r9a0_owner
      using (true) with check (true);
  end if;

  if not exists (
    select 1 from pg_policies
    where schemaname = 'r9a0_coordination'
      and tablename = 'events'
      and policyname = 'events_owner_access'
  ) then
    create policy events_owner_access
      on r9a0_coordination.events
      as permissive for all to r9a0_owner
      using (true) with check (true);
  end if;
end;
$$;

alter schema r9a0_governance owner to r9a0_owner;
alter schema r9a0_coordination owner to r9a0_owner;
alter schema r9a0_api owner to r9a0_owner;

alter table r9a0_governance.migration_applications owner to r9a0_owner;
alter table r9a0_coordination.events owner to r9a0_owner;
alter sequence r9a0_coordination.events_event_sequence_seq owner to r9a0_owner;
alter view r9a0_coordination.latest_thread_state owner to r9a0_owner;
alter view r9a0_coordination.open_threads owner to r9a0_owner;

alter function r9a0_governance.sha256_text(text) owner to r9a0_owner;
alter function r9a0_governance.require_service_role() owner to r9a0_owner;
alter function r9a0_governance.block_append_only_mutation() owner to r9a0_owner;
alter function r9a0_governance.validate_event_graph() owner to r9a0_owner;
alter function r9a0_api.append_coordination_event(
  text,text,text,text,text,text,text,text,text,uuid,uuid,jsonb,jsonb
) owner to r9a0_owner;

revoke all on schema r9a0_governance from public, anon, authenticated;
revoke all on schema r9a0_coordination from public, anon, authenticated;
revoke all on schema r9a0_api from public, anon, authenticated;

grant usage on schema r9a0_governance to service_role;
grant usage on schema r9a0_coordination to service_role;
grant usage on schema r9a0_api to service_role;

revoke all on all tables in schema r9a0_governance from public, anon, authenticated, service_role;
revoke all on all tables in schema r9a0_coordination from public, anon, authenticated, service_role;
revoke all on all sequences in schema r9a0_governance from public, anon, authenticated, service_role;
revoke all on all sequences in schema r9a0_coordination from public, anon, authenticated, service_role;
revoke all on all functions in schema r9a0_governance from public, anon, authenticated, service_role;
revoke all on all functions in schema r9a0_coordination from public, anon, authenticated, service_role;
revoke all on all functions in schema r9a0_api from public, anon, authenticated, service_role;

grant select on r9a0_governance.migration_applications to service_role;
grant select on r9a0_coordination.events to service_role;
grant select on r9a0_coordination.latest_thread_state to service_role;
grant select on r9a0_coordination.open_threads to service_role;
grant execute on function r9a0_api.append_coordination_event(
  text,text,text,text,text,text,text,text,text,uuid,uuid,jsonb,jsonb
) to service_role;

commit;
