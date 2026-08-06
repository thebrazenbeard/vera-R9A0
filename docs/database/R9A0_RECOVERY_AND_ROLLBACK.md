# R9A0 Recovery and Rollback

## Before apply

1. Verify the target project reference is the authorized R9A0 build or release target.
2. Verify the repository branch head and every migration SHA-256 against the immutable handoff.
3. Confirm the migration artifact existed in the repository before apply.
4. Confirm no non-R9A0 schema is named except creation or ownership of the dedicated `r9a0_owner` NOLOGIN role.
5. Capture schema, role, privilege, RLS, policy, function-owner, and migration-ledger fingerprints.

## Apply order

1. `20260806133000_r9a0_coordination_foundation.sql`
2. `20260806224900_r9a0_coordination_integrity_repairs.sql`

The second migration must be applied byte-for-byte from the pre-existing repository artifact. Do not compact, rewrite, or regenerate it at apply time.

## Rollback boundary

The paired integrity-repair rollback removes the new graph validator, controlling-tip indexes and views, owner policies, and forced-RLS/NOLOGIN ownership boundary, then restores the prior projection and postgres ownership. The foundation rollback removes the R9A0 schemas.

No rollback may run after real R9A0 evidence has been admitted without a separate preservation decision and export receipt.

## Verification

Run both transactional SQL test scripts after apply. The successor test verifies:

- NOLOGIN ownership and forced RLS
- actual role privilege matrix
- service-role-only RPC execution
- same-thread controlling transitions
- acknowledgement-aware current-state projection
- stale predecessor, cross-thread, and fork rejection
- payload boundaries
- advisory-lock concurrency control
- schema-qualified search paths
- migration-receipt mutation blocking

The test transaction rolls back synthetic rows. A separate two-session hostile concurrency run is required on the hosted target before approval.

## Restore

A logical restore rehearsal must create an isolated target, apply migrations from empty in order, import only approved synthetic fixtures, run all tests, and compare schema fingerprints. Hosted production claims remain prohibited until that rehearsal and a separately authorized hosted target exist.
