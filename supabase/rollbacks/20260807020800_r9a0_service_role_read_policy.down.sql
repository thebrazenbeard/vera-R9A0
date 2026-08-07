begin;

drop policy if exists events_service_role_read
  on r9a0_coordination.events;
drop policy if exists migration_applications_service_role_read
  on r9a0_governance.migration_applications;

commit;
