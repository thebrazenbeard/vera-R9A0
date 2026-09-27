> **License:** Source-visible, not open source. Original material is proprietary. Commercial use, redistribution, hosted-service use, and commercial derivative products require written permission. See [LICENSE](LICENSE) and [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md). Separately identified third-party components retain their own licenses.

# Vera R9A0

Vera R9A0 is a historical Vera architecture repository: Revision 9, Rollout A, Patch 0.

## Current status

The default `main` branch is intentionally non-executable and source-light. It preserves the repository's historical/provenance role rather than pretending an older R9A0/R9B0 implementation line is the current Vera runtime.

Historical implementation, validation, database-successor, and later R9B0 work remain available in repository history and named branches. They are predecessor/source evidence only unless an exact current integration explicitly promotes them.

This repository should therefore be read as a **historical lineage surface**, not as an active package, selected ChatGPT Project route, installed runtime, or behavioral qualification.

## Why main is intentionally small

A September 2026 audit found stale Actions on `main` referring to implementation paths that were not present on the default branch. Those workflows were removed rather than preserving false executable status. Re-populating this historical default branch with a later successor merely to increase file count would blur the R9A0/R9B0 boundary.

## Evidence boundary

Repository history can document what was designed, validated, reviewed, or proposed at a particular point in the lineage. It does not establish that the same package is installed, selected, runtime-active, or authoritative now.

For current Vera implementation, use the repository that presently owns that implementation rather than inferring currentness from this historical repository.
