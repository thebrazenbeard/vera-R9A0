# R9A0 Supabase Architecture

## Scope

The R9A0 database slice creates and modifies only the `r9a0_governance`, `r9a0_coordination`, and `r9a0_api` namespaces, plus the dedicated `r9a0_owner` NOLOGIN role. It does not alter the Vera production project or unrelated schemas.

## Schemas

- `r9a0_governance`: migration receipts, graph validation, hashing, and append-only enforcement helpers.
- `r9a0_coordination`: append-only operational events and controlling thread-state projections.
- `r9a0_api`: the narrow service-role write RPC.

## Integrity and security controls

1. Direct client access fails closed through schema revocation, table revocation, RLS, and explicit deny policies.
2. Future objects inherit deny-by-default privileges through schema-scoped default privileges.
3. Every function has an explicit `search_path`.
4. Append-only relations block `UPDATE`, `DELETE`, and `TRUNCATE`.
5. Coordination operations require a unique operation ID and deterministic request digest.
6. Duplicate operation IDs replay the original receipt only when the request digest matches.
7. Payload and reference objects are type-checked and capped at 16 KiB each.
8. Current thread state is the event that has not been referenced by a later controlling supersession or acknowledgement.
9. Every event after the first must reference the current same-thread tip through exactly one controlling predecessor field.
10. Per-thread advisory transaction locks serialize competing transitions; stale predecessors, cross-thread links, and forks fail closed.
11. Tables and privileged functions are owned by the dedicated `r9a0_owner` NOLOGIN role.
12. RLS is forced on the append-only base tables. The service role receives read access and one narrow write RPC rather than general table insertion rights.

## Trust boundary

Remote writes require the `service_role` JWT claim and execute through `r9a0_api.append_coordination_event`. The security-definer function is owned by `r9a0_owner`, not by a login role. Neither a database receipt nor a green test proves merge, deployment, installation, personal identity, memory admission, or authority outside the exact recorded operation.

## Provenance

The original foundation apply is retained with its exact applied-statement artifact and a disclosed repository-first deviation. Migration `20260806224900_r9a0_coordination_integrity_repairs` exists in the repository before any hosted apply and must be applied byte-for-byte from that artifact.

## Deliberate exclusions

This slice does not implement autobiographical-memory admission, recovery lifecycle registries, native ChatGPT Project installation receipts, Edge Functions, Storage, Realtime, queues, or vector features. Those require separate contracts and hostile tests.
