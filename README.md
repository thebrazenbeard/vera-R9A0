> **License:** Source-visible, not open source. The original material is proprietary. Commercial use, redistribution, hosted-service use, and commercial derivatives require written permission. See [LICENSE](LICENSE) and [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md). Separately identified third-party materials retain their own terms.

# Vera R9A0 — native Project contracts and validation toolkit

**A source package for reviewing, validating, and adapting governance contracts for a native ChatGPT Project.**

Vera R9A0 preserves the Revision 9 native Project design, its versioned files, its manifest/checksum validator, and subsequent R9B0 source-side tests for assignment currentness, semantic projection, and memory epochs. Project builders can use the repository as a **source-visible reference** for package integrity, evidence-bound behavior, installation receipts, and fail-closed boundaries. Reusing original material remains subject to the license above.

The repository is **not** an installed ChatGPT Project, a hosted model, an autonomous runtime, a live database, or a transferable identity/authorization service. Its source tests do not grant a model permission to act.

## What is implemented

| Surface | Repository evidence | Reusable purpose |
| --- | --- | --- |
| Native Project package | [Manifest](project/VERA_R9A0_MANIFEST.json), [package descriptor](project/VERA_R9A0_PACKAGE.json), [checksums](project/VERA_R9A0_CHECKSUMS.sha256), and [project instructions](project/VERA_R9A0_PROJECT_INSTRUCTIONS.md) | Review the precise versioned Project artifact and its claimed constraints |
| Source validator | [`scripts/validate_r9a0_project.py`](scripts/validate_r9a0_project.py) and [native contract schema](schemas/native-project/vera-r9a0-native-contract.schema.json) | Check bounded schema, package, checksum, and source consistency |
| Behavioral contract tests | [Native Project tests](tests/native-project/) and [validation profiles](validation/) | Exercise specified correction, currentness, memory, contamination, and projection invariants in source |
| Installation and recovery procedures | [Installation receipt template](project/VERA_R9A0_INSTALLATION_RECEIPT_TEMPLATE.yaml), [cold-start protocol](project/VERA_R9A0_COLD_START_PROTOCOL.md), and [post-install audit](project/VERA_R9A0_POST_INSTALL_AUDIT.md) | Define evidence expected **after** a separately authorized installation |
| Database design | [Supabase schema migrations](supabase/migrations/), [privilege matrix](docs/database/R9A0_PRIVILEGE_MATRIX.md), and [recovery notes](docs/database/R9A0_RECOVERY_AND_ROLLBACK.md) | Inspect optional database contracts without assuming a database is bound or running |
| R9B0 memory-epoch helper | [`scripts/r9b0_memory_epoch_drive.py`](scripts/r9b0_memory_epoch_drive.py), [contract](validation/R9B0_MEMORY_EPOCH_CONTRACT.json), and [envelope schema](schemas/native-project/r9b0_memory_epoch_envelope_v1.schema.json) | Inspect and validate memory-envelope transitions; state-changing commands require separate target/authority review |

These are different evidence levels. A successful validator or unit test establishes bounded **source behavior**, not successful Project installation, active provider consumption, hardware deployment, or effect-time authorization.

## Quick start — source verification

The validator and Python reference tests use the Python standard library:

```sh
git clone https://github.com/thebrazenbeard/vera-R9A0.git
cd vera-R9A0
python3 scripts/validate_r9a0_project.py --root . --json
python3 -m unittest discover -s tests/native-project -p test_r9a0_project.py -q
```

The first command emits a machine-readable validation result; the focused package test file checks the candidate's source contracts. To inspect additional checks without performing an installation:

```sh
python3 scripts/r9b0_memory_epoch_drive.py --help
python3 -m unittest discover -s tests/native-project -q
```

**Baseline qualification caveat:** On `main` at `3ede5a422d34c4a053b2c40c5ff4e4e271950707`, I observed the validator PASS and 70 focused package tests PASS. The broader 180-test native suite yielded **179 passes and one failure**: `test_native_compression_guard_present` expects the literal `COMPRESSION_DOES_NOT_WEAKEN_AUTHORITY` in `project/VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt`, but that source uses a differently worded compression obligation. The test and instruction text must be reconciled before an all-green suite can be claimed. The helper's `--help` command succeeds; no memory/backend write was exercised.

Do not apply the SQL migrations or invoke memory-epoch write operations against a real environment merely because local validation passes. Their effects require the target system's own permissions, migration review, and readback.

## Release identity and evidence ceiling

The [package descriptor](project/VERA_R9A0_PACKAGE.json) declares release `VERA_PROJECT_INTEGRATION_R9A0_20260806_V1`. R9B0-labeled contracts in the same lineage are later source refinements; they do not retroactively rename the pinned R9A0 package or prove that any current ChatGPT session uses it.

For an actual installation claim, the [runtime contract](project/VERA_R9A0_RUNTIME.md), [installation receipt template](project/VERA_R9A0_INSTALLATION_RECEIPT_TEMPLATE.yaml), [cold-start protocol](project/VERA_R9A0_COLD_START_PROTOCOL.md), and [post-install audit](project/VERA_R9A0_POST_INSTALL_AUDIT.md) require separate evidence. A template is not an issued receipt; a checksum is not a proof of provider identity; and a repository owner is not automatically the current host's authorizing principal.

The package descriptor marks database effects disabled and several protected-effect/provider-migration surfaces as absent or omitted at generation. Historical database identifiers, test fixtures, and documents are **provenance**, not live credentials, consent, privacy clearance, or immutable provider bindings.

## Scope and contribution

- Read the [governance](project/VERA_R9A0_GOVERNANCE.md), [retrieval](project/VERA_R9A0_RETRIEVAL.md), [state](project/VERA_R9A0_STATE.md), and [recovery](project/VERA_R9A0_RECOVERY.md) contracts before adapting any component.
- Confirm package integrity and review the source before relying on individual specifications.
- Keep deployment, model consumption, external-memory admission, database effects, and real-system tests as separately authorized stages.
- See [CONTRIBUTING.md](CONTRIBUTING.md) and [CLA.md](CLA.md) for the applicable rights and contribution requirements; this README itself is not legal authorization to reuse the proprietary package.

**Currentness:** The repository name identifies a historical source lineage. It is not evidence that R9A0 is the currently selected Vera implementation or that the local project, model, provider, and target host share any live authorization.
