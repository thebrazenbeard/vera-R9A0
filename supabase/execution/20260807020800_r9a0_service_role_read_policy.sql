begin;

drop policy if exists events_service_role_read
  on r9a0_coordination.events;
create policy events_service_role_read
  on r9a0_coordination.events
  as permissive for select to service_role
  using (true);

drop policy if exists migration_applications_service_role_read
  on r9a0_governance.migration_applications;
create policy migration_applications_service_role_read
  on r9a0_governance.migration_applications
  as permissive for select to service_role
  using (true);

commit;
