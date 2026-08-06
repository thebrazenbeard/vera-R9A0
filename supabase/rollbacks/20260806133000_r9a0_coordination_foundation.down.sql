begin;

revoke all on schema r9a0_api from service_role;
revoke all on schema r9a0_coordination from service_role;
revoke all on schema r9a0_governance from service_role;

drop schema if exists r9a0_api cascade;
drop schema if exists r9a0_coordination cascade;
drop schema if exists r9a0_governance cascade;

commit;
