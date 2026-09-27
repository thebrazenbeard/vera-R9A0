begin;

create schema if not exists r9a0_governance;
create schema if not exists r9a0_coordination;
create schema if not exists r9a0_api;

revoke all on schema r9a0_governance from public, anon, authenticated;
revoke all on schema r9a0_coordination from public, anon, authenticated;
revoke all on schema r9a0_api from public, anon, authenticated;

grant usage on schema r9a0_governance to service_role;
grant usage on schema r9a0_coordination to service_role;
grant usage on schema r9a0_api to service_role;

alter default privileges for role postgres in schema r9a0_governance
  revoke all on tables from public, anon, authenticated;
alter default privileges for role postgres in schema r9a0_governance
  revoke all on sequences from public, anon, authenticated;
alter default privileges for role postgres in schema r9a0_governance
  revoke all on functions from public, anon, authenticated;
alter default privileges for role postgres in schema r9a0_coordination
  revoke all on tables from public, anon, authenticated;
alter default privileges for role postgres in schema r9a0_coordination
  revoke all on sequences from public, anon, authenticated;
alter default privileges for role postgres in schema r9a0_coordination
  revoke all on functions from public, anon, authenticated;
alter default privileges for role postgres in schema r9a0_api
  revoke all on functions from public, anon, authenticated;

create or replace function r9a0_governance.sha256_text(p_value text)
returns text
language sql
immutable
strict
set search_path = pg_catalog, extensions
as $$
  select encode(extensions.digest(convert_to(p_value, 'UTF8'), 'sha256'), 'hex')
$$;

create or replace function r9a0_governance.require_service_role()
returns void
language plpgsql
security invoker
set search_path = pg_catalog
as $$
begin
  if session_user = 'postgres' then
    return;
  end if;

  if coalesce(current_setting('request.jwt.claim.role', true), '') <> 'service_role' then
    raise exception 'R9A0 service_role authorization required' using errcode = '42501';
  end if;
end;
$$;

create or replace function r9a0_governance.block_append_only_mutation()
returns trigger
language plpgsql
security invoker
set search_path = pg_catalog
as $$
begin
  raise exception '% is append-only; % is not permitted',
    quote_ident(tg_table_schema) || '.' || quote_ident(tg_table_name), tg_op
    using errcode = '55000';
end;
$$;

create table if not exists r9a0_governance.migration_applications (
  application_id uuid primary key default extensions.gen_random_uuid(),
  migration_version text not null,
  migration_name text not null,
  migration_sha256 text not null check (migration_sha256 ~ '^[0-9a-f]{64}$'),
  repository text not null,
  repository_commit text not null check (repository_commit ~ '^[0-9a-f]{40}$'),
  repository_path text not null,
  target_project_ref text not null,
  target_namespace text not null check (target_namespace ~ '^r9a0_[a-z0-9_]+$'),
  applied_at timestamptz not null default clock_timestamp(),
  applied_by text not null default session_user,
  operation_id text not null unique,
  evidence jsonb not null default '{}'::jsonb check (jsonb_typeof(evidence) = 'object'),
  unique (target_project_ref, migration_version)
);

comment on table r9a0_governance.migration_applications is
  'Append-only repository-to-database migration application receipts for R9A0 build and verification environments.';

alter table r9a0_governance.migration_applications enable row level security;
create policy migration_applications_client_deny
  on r9a0_governance.migration_applications
  as restrictive for all to anon, authenticated
  using (false) with check (false);

create trigger migration_applications_no_update_delete
before update or delete on r9a0_governance.migration_applications
for each row execute function r9a0_governance.block_append_only_mutation();

create trigger migration_applications_no_truncate
before truncate on r9a0_governance.migration_applications
for each statement execute function r9a0_governance.block_append_only_mutation();

create table if not exists r9a0_coordination.events (
  event_id uuid primary key default extensions.gen_random_uuid(),
  event_sequence bigint generated always as identity unique,
  operation_id text not null unique,
  request_digest text not null check (request_digest ~ '^[0-9a-f]{64}$'),
  thread_key text not null check (length(thread_key) between 1 and 160),
  source_address text not null check (source_address ~ '^[a-z0-9][a-z0-9/_-]{0,127}$'),
  target_address text not null check (target_address ~ '^[a-z0-9][a-z0-9/_-]{0,127}$'),
  event_type text not null check (event_type in (
    'STATUS','ISSUE','ACKNOWLEDGEMENT','REVIEW','DECISION','RESOLUTION'
  )),
  status text not null check (status in (
    'DRAFT','READY_FOR_REVIEW','IN_PROGRESS','BLOCKED','DEGRADED',
    'ACKNOWLEDGED','CHANGES_REQUESTED','APPROVED','RESOLVED','CANCELLED'
  )),
  objective text not null check (length(objective) between 1 and 2000),
  summary text not null check (length(summary) between 1 and 8000),
  active_issue text check (active_issue is null or length(active_issue) <= 2000),
  supersedes_event_id uuid references r9a0_coordination.events(event_id),
  acknowledges_event_id uuid references r9a0_coordination.events(event_id),
  payload jsonb not null default '{}'::jsonb check (
    jsonb_typeof(payload) = 'object' and pg_column_size(payload) <= 16384
  ),
  reference_data jsonb not null default '{}'::jsonb check (
    jsonb_typeof(reference_data) = 'object' and pg_column_size(reference_data) <= 16384
  ),
  record_time timestamptz not null default clock_timestamp(),
  constraint events_no_self_supersession check (
    supersedes_event_id is null or supersedes_event_id <> event_id
  ),
  constraint events_no_self_acknowledgement check (
    acknowledges_event_id is null or acknowledges_event_id <> event_id
  )
);

create index if not exists events_thread_sequence_idx
  on r9a0_coordination.events (thread_key, event_sequence desc);
create index if not exists events_route_sequence_idx
  on r9a0_coordination.events (source_address, target_address, event_sequence desc);
create index if not exists events_status_sequence_idx
  on r9a0_coordination.events (status, event_sequence desc);
create index if not exists events_supersedes_idx
  on r9a0_coordination.events (supersedes_event_id)
  where supersedes_event_id is not null;
create index if not exists events_acknowledges_idx
  on r9a0_coordination.events (acknowledges_event_id)
  where acknowledges_event_id is not null;

comment on table r9a0_coordination.events is
  'Append-only R9A0 operational coordination. It is not autobiographical memory, relationship authority, installation proof, or deployment proof.';

alter table r9a0_coordination.events enable row level security;
create policy events_client_deny
  on r9a0_coordination.events
  as restrictive for all to anon, authenticated
  using (false) with check (false);

create trigger events_no_update_delete
before update or delete on r9a0_coordination.events
for each row execute function r9a0_governance.block_append_only_mutation();

create trigger events_no_truncate
before truncate on r9a0_coordination.events
for each statement execute function r9a0_governance.block_append_only_mutation();

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
from r9a0_coordination.events
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
set search_path = pg_catalog, r9a0_governance, r9a0_coordination
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

  if p_payload is null or jsonb_typeof(p_payload) <> 'object' or pg_column_size(p_payload) > 16384 then
    raise exception 'payload must be a JSON object no larger than 16384 bytes' using errcode = '22023';
  end if;

  if p_reference_data is null or jsonb_typeof(p_reference_data) <> 'object' or pg_column_size(p_reference_data) > 16384 then
    raise exception 'reference_data must be a JSON object no larger than 16384 bytes' using errcode = '22023';
  end if;

  v_digest := r9a0_governance.sha256_text(jsonb_build_object(
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

  select * into v_existing
  from r9a0_coordination.events
  where operation_id = p_operation_id;

  if found then
    if v_existing.request_digest <> v_digest then
      raise exception 'IDEMPOTENCY_CONFLICT for operation_id %', p_operation_id using errcode = '23505';
    end if;

    return jsonb_build_object(
      'result', 'EXISTING',
      'event_id', v_existing.event_id,
      'event_sequence', v_existing.event_sequence,
      'operation_id', v_existing.operation_id,
      'request_digest', v_existing.request_digest,
      'record_time', v_existing.record_time
    );
  end if;

  begin
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
    ) returning * into v_inserted;
  exception
    when unique_violation then
      select * into v_existing
      from r9a0_coordination.events
      where operation_id = p_operation_id;

      if not found or v_existing.request_digest <> v_digest then
        raise exception 'IDEMPOTENCY_CONFLICT for operation_id %', p_operation_id using errcode = '23505';
      end if;

      return jsonb_build_object(
        'result', 'EXISTING',
        'event_id', v_existing.event_id,
        'event_sequence', v_existing.event_sequence,
        'operation_id', v_existing.operation_id,
        'request_digest', v_existing.request_digest,
        'record_time', v_existing.record_time
      );
  end;

  return jsonb_build_object(
    'result', 'INSERTED',
    'event_id', v_inserted.event_id,
    'event_sequence', v_inserted.event_sequence,
    'operation_id', v_inserted.operation_id,
    'request_digest', v_inserted.request_digest,
    'record_time', v_inserted.record_time
  );
end;
$$;

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
