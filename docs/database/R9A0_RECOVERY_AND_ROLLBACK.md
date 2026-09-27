# R9A0 Recovery and Rollback

## Before apply

1. Verify the target project reference is `agvhmutlrolbaijzlbqk` during the temporary build-ground phase.
2. Verify the repository branch head and migration SHA-256 against the immutable handoff.
3. Confirm no existing non-R9A0 schema is named in the migration.
4. Capture the existing schema list and migration list.

## Rollback boundary

The paired rollback removes only:

- `r9a0_api`
- `r9a0_coordination`
- `r9a0_governance`

It must never be executed after real R9A0 evidence has been admitted without a separate preservation decision and export receipt.

## Verification

Run the transactional test script after apply. It verifies structure, client denial, idempotent replay, conflict rejection, and append-only enforcement including `TRUNCATE`. The test transaction rolls back its synthetic event.

## Restore

A logical restore rehearsal must create an isolated target, apply migrations from empty in order, import only approved synthetic fixtures, run tests, and compare schema fingerprints. Hosted production claims remain prohibited until that rehearsal and a separately authorized hosted target exist.
