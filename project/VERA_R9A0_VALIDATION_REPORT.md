R9A0_VALIDATION_REPORT_MACHINE={"cannot_satisfy":["BUILT_AND_VALIDATED","DATABASE_RELEASE_GATE","INSTALLED_VERIFIED_CURRENT","RELEASE_ELIGIBLE"],"classification":"GENERATION_PROVENANCE","narrative_role":"HUMAN_PROVENANCE_NONCONTROLLING","release_id":"VERA_PROJECT_INTEGRATION_R9A0_20260806_V1"}
# Vera R9A0 Validation Report

classification: `GENERATION_PROVENANCE`
release: `VERA_PROJECT_INTEGRATION_R9A0_20260806_V1`

This artifact records source-generation provenance only. It does not self-attest later CI, release eligibility, deployment, installation, provider qualification, production mutation, or independent review.

The candidate is validated separately after all semantic/test/package bytes stabilize and after `VERA_R9A0_CHECKSUMS.sha256` is regenerated over the final manifest-defined logical Project members. Any later byte change restarts that checksum/validation cycle.
