# R9A0 Database Successor Repair Review

## Scope

This repair package addresses the six findings issued against database head `71b3fc4892df3a70e493e287542e68bfa1e5a798`.

## Finding disposition

- **MUNE-R9A0-FND-001:** the database slice manifest is regenerated from the repaired file set and includes exact byte counts and SHA-256 digests.
- **MUNE-R9A0-FND-002:** `latest_thread_state` now selects the controlling tip that has not been superseded or acknowledged by a later event.
- **MUNE-R9A0-FND-003:** a before-insert graph validator enforces same-thread references, one controlling predecessor, current-tip transitions, and advisory-lock serialization. Partial unique indexes add direct duplicate-reference protection.
- **MUNE-R9A0-FND-004:** `r9a0_owner` is a dedicated NOLOGIN, non-BYPASSRLS owner for R9A0 schemas, tables, views, sequence, and privileged functions. Base tables use FORCE RLS.
- **MUNE-R9A0-FND-005:** the successor test covers role privileges, RPC authorization, ownership, forced RLS, projection correctness, stale predecessor/fork rejection, cross-thread rejection, payload limits, search-path pinning, advisory-lock presence, migration-receipt immutability, and deterministic two-session overlap through the disposable-database harness.
- **MUNE-R9A0-FND-006:** migration `20260806224900` is committed as an exact repository artifact before any hosted apply. The original deviation remains disclosed and is not rewritten.

## Remaining evidence boundary

Repository repair does not equal hosted approval. Required next evidence is:

1. apply the exact pre-existing migration artifact to an authorized disposable R9A0 test target;
2. run both transactional SQL suites and `scripts/supabase/test_r9a0_two_session_concurrency.sh`;
3. capture owner, policy, RLS, ACL, projection, protected-scope, and harness readback;
4. obtain Mune exact-head verification of the execution receipt;
5. obtain Voss approval before integration.

The current native-only GitHub workflow does not cover database paths, so absence of a database-head workflow run is not evidence of failure and is not an approval gate for this slice.

No merge, deployment, installation, or production mutation is claimed by this document.
