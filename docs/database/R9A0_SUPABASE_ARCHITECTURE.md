# R9A0 Supabase Architecture

## Scope

This first repository-backed R9A0 database slice creates only schemas whose names begin with `r9a0_`.
It is designed for the temporary BT2 build ground and must not alter the Vera project or the BT2 `public`, `governance`, or `bt2_native` namespaces.

## Schemas

- `r9a0_governance`: migration receipts and shared hardening helpers.
- `r9a0_coordination`: append-only operational events and authoritative thread projections.
- `r9a0_api`: narrow service-role RPC entry points.

## Repaired defects

1. Direct client access fails closed through schema revocation, table revocation, RLS, and explicit deny policies.
2. Future objects inherit deny-by-default privileges through schema-scoped default privileges.
3. Every function has an explicit `search_path`.
4. Append-only relations block `UPDATE`, `DELETE`, and `TRUNCATE`.
5. Coordination operations require a unique operation ID and deterministic request digest.
6. Duplicate operation IDs replay the original receipt only when the request digest matches.
7. Payload and reference objects are type-checked and capped at 16 KiB each.
8. The authoritative latest state is projected by database sequence rather than inferred from chronology in application code.
9. The service role receives read access and one narrow write RPC rather than general table insertion rights.

## Trust boundary

The RPC accepts direct SQL execution by `postgres` for controlled build and verification. Remote calls require the JWT claim role `service_role`.
The function is a database boundary, not proof of deployment, installation, personal identity, memory admission, or authority outside its exact operation.

## Deliberate exclusions

This slice does not yet implement autobiographical-memory admission, recovery lifecycle registries, native ChatGPT Project installation receipts, Edge Functions, Storage, Realtime, queues, or vector features. Those require separate contracts and hostile tests.
