begin;

drop view if exists r9a0_coordination.open_threads;
drop view if exists r9a0_coordination.latest_thread_state;

drop trigger if exists events_validate_graph on r9a0_coordination.events;
drop index if exists r9a0_coordination.events_one_superseder_idx;
drop index if exists r9a0_coordination.events_one_acknowledger_idx;
drop function if exists r9a0_governance.validate_event_graph();

drop policy if exists events_owner_access on r9a0_coordination.events;
drop policy if exists migration_applications_owner_access on r9a0_governance.migration_applications;

alter table r9a0_governance.migration_applications no force row level security;
alter table r9a0_coordination.events no force row level security;

alter schema r9a0_governance owner to postgres;
alter schema r9a0_coordination owner to postgres;
alter schema r9a0_api owner to postgres;

alter table r9a0_governance.migration_applications owner to postgres;
alter table r9a0_coordination.events owner to postgres;
alter sequence r9a0_coordination.events_event_sequence_seq owner to postgres;

alter function r9a0_governance.sha256_text(text) owner to postgres;
alter function r9a0_governance.require_service_role() owner to postgres;
alter function r9a0_governance.block_append_only_mutation() owner to postgres;
alter function r9a0_api.append_coordination_event(
  text,text,text,text,text,text,text,text,text,uuid,uuid,jsonb,jsonb
) owner to postgres;

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

alter view r9a0_coordination.latest_thread_state owner to postgres;
alter view r9a0_coordination.open_threads owner to postgres;

commit;
