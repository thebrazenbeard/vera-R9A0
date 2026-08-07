# R9A0 Database Successor Repair Review

## Scope

This repair package addresses the six Mune findings issued against database head `71b3fc4892df3a70e493e287542e68bfa1e5a798`, the owner-extension privilege failure exposed by disposable run `31135561656`, and the service-role projection failure exposed by run `31137411068`.

## Finding disposition

- **MUNE-R9A0-FND-001:** the database slice manifest is regenerated from the repaired file set and includes exact byte counts and SHA-256 digests.
- **MUNE-R9A0-FND-002:** `latest_thread_state` selects the controlling tip that has not been superseded or acknowledged by a later event.
- **MUNE-R9A0-FND-003:** a before-insert graph validator enforces same-thread references, one controlling predecessor, current-tip transitions, and advisory-lock serialization. Partial unique indexes add direct duplicate-reference protection.
- **MUNE-R9A0-FND-004:** `r9a0_owner` is a dedicated NOLOGIN, non-BYPASSRLS owner for R9A0 schemas, tables, views, sequence, and privileged functions. Base tables use FORCE RLS.
- **MUNE-R9A0-FND-005:** the successor tests cover role privileges, RPC authorization, ownership, forced RLS, projection correctness, stale predecessor/fork rejection, cross-thread rejection, payload limits, search-path pinning, advisory-lock presence, migration-receipt immutability, and deterministic two-session overlap.
- **MUNE-R9A0-FND-006:** repository-first migration artifacts are committed before any hosted apply. The original foundation deviation remains disclosed and is not rewritten.
- **VOSS-R9A0-DB-EXTENSIONS-USAGE-001:** migration `20260807005800` grants only `USAGE` on the existing `extensions` schema to `r9a0_owner`, with rollback and owner-execution regression coverage.
- **VOSS-R9A0-DB-SERVICE-ROLE-RLS-001:** migration `20260807020800` adds named service-role `SELECT` policies to the two governed base tables. FORCE RLS and the owner policies remain active; no direct mutation privilege is added. The security-invoker projections now have an explicit read contract instead of relying on ineffective ACL grants alone.

## Remaining evidence boundary

Repository repair does not equal hosted approval. Required next evidence is:

1. run the exact PR merge candidate on disposable PostgreSQL;
2. apply all four repository-first migrations in order;
3. pass the foundation, integrity, owner-extension, and service-role read-policy SQL suites;
4. pass the deterministic two-session concurrency harness and verify the 22-file manifest;
5. capture owner, policy, RLS, ACL, projection, and protected-scope readback;
6. obtain Mune exact-head review and successful execution-receipt verification;
7. obtain Voss reconciliation and approval.

No merge, hosted apply, deployment, installation, or production mutation is claimed by this document.
