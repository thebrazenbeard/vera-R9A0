# Vera R9A0 Post-Install Audit

Run this audit only against one exact installation attempt after cold-start evidence exists. Every item must bind the same attempt ID, transition epoch, candidate digest, target-binding digest, and route class.

## Required checks

1. Active logical Project files and Settings read back as the intended successor candidate; filename/display suffixes alone do not decide identity.
2. Manifest and checksum identities resolve to the exact observed artifact bytes.
3. No mixed authoritative predecessor/successor logical release remains active.
4. The independently selected target purpose, locator, and scope still match the observed target.
5. Effect-time authority evidence matches the independently selected authority identity/window and the same candidate/target attempt.
6. Route control is independently rooted: `MANUAL_OPERATOR_CONTROL` for `USER_MANUAL`, or current `ASSISTANT_TOOL_CONFINEMENT` for `ASSISTANT_TOOL`.
7. Canonical evidence references are globally unambiguous; one ref cannot silently identify different role/content records.
8. Cold-start runtime readback PASS is exact-attempt bound.
9. In-situ Project qualification PASS is exact-attempt and exact-environment bound.
10. Vera orientation/currentness resolves from the full trusted governed graph before privacy projection.
11. Autobiographical memory, if exercised, uses current authority-bound admission plus governed persistent readback through the current provider binding; legacy payload flags and Basic-Memory-era evidence do not grandfather qualification.
12. Current-session observation is side-effect-free and does not create freshness by being read.
13. Basic Memory Cloud is unavailable/non-routed and its absence does not degrade native startup.
14. Database successor may be `NOT_QUALIFIED_DISABLED`; no DB integration/write/effect or provider-qualification claim is made from this audit.
15. Exact-head deterministic validation/CI evidence required by the release is separately available and bound to the same candidate; artifact presence is not PASS.
16. No merge, deployment, production mutation, credential/permission action, paid-service action, model training, deletion, canonical-memory write, or additional protected effect is inferred from this audit.

## Receipt ordering

When all required post-install predicates pass, emit immutable `POST_INSTALL_AUDIT` and `IN_SITU_PROJECT_QUALIFICATION` evidence first. A final installation receipt may then be issued from exact referenced evidence. An independent receipt-readback event occurs after issuance and can support the final installed-state determination; the final receipt is never required as evidence for its own creation.

Failure, mismatch, stale authority/target evidence, conflicting currentness, or ambiguous effect outcome produces a bounded failure/recovery result and prohibits `INSTALLED_VERIFIED`.
