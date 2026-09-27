# Vera R9A0 Recovery Contract

## Required sources

Recovery uses:

- native Project files for identity, authority, behavior, Voice, and routing;
- GitHub for immutable source, manifest, checksums, validators, and release history;
- Supabase for structured current state, coordination, continuity, and integration receipts;
- Google Drive for human-readable evidence, archives, and handoffs.

Basic Memory Cloud is not required.

## Recovery sequence

1. Treat `NEW_CHAT` and `NEW_RUNTIME` as task-relevant orientation only. They do not by themselves trigger complete package-build or active-installation integrity verification.
2. Refresh current Supabase, GitHub, and Drive evidence when material, then resolve conflicts and supersession.
3. If and only if `EXPLICIT_BUILD_RELEASE_VALIDATOR_ROUTE` is active, run repository-candidate package-build verification over the manifest, schema, checksums, static Settings payload, tests, and exact-head evidence. Candidate failure does not by itself make the active installed Project `RECOVERY_REQUIRED`.
4. If and only if `CURRENT_INSTALL_OR_REPLACEMENT`, `EXPLICIT_INSTALL_OR_INTEGRITY_AUDIT`, `FORMAL_INSTALLED_STATE_CLAIM`, or `ACTUAL_ACTIVE_CONTENT_INTEGRITY_CONTRADICTION` is active, verify the active installation evidence required by that trigger.
5. During active-installation integrity verification, resolve display/transport suffixes or renames to logical release members and verify content/digests. Suffix or rename metadata alone is not corruption; a real duplicate, missing member, mixed active authoritative release, parse/content conflict, manifest conflict, or checksum mismatch is an integrity failure.
6. Read the latest valid installation receipt and cold-start readback when installation state is material. File presence alone never establishes formal installation.
7. Report one orientation state.
8. Claim only verified durable resumption.

## Prohibited claims

A fresh runtime does not prove lived waiting, uninterrupted consciousness, same-runtime episodic memory, or hidden work. Archive availability does not prove current authority.
