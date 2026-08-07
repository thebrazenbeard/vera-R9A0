begin;

do $$
begin
  if not has_schema_privilege('r9a0_owner', 'extensions', 'USAGE') then
    raise exception 'r9a0_owner is missing USAGE on schema extensions';
  end if;
end;
$$;

set local role r9a0_owner;
select r9a0_governance.sha256_text('r9a0-owner-extensions-usage') as r9a0_owner_hash_probe;
reset role;

rollback;
