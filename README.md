> **License:** Source-visible, not open source. Original material is proprietary. Commercial use, redistribution, hosted-service use, and commercial derivative products require written permission. See [LICENSE](LICENSE) and [COMMERCIAL_LICENSE.md](COMMERCIAL_LICENSE.md). Separately identified third-party components retain their own licenses.

# Vera R9A0

Vera R9A0 is the repository lineage for the Revision 9 native ChatGPT Project architecture and its later source-side hardening.

## What is on main

The canonical branch contains the executable/source package that had previously been stranded on the green R9A0/R9B0 source line:

- the native Project package, manifest, checksums, laws, governance, runtime, state, retrieval, Voice, recovery, cold-start, and post-install contracts under `project/`;
- native-project schemas and validation tooling;
- database/source qualification material;
- GitHub Actions validation;
- deterministic native-project tests;
- successor hardening present in the same lineage, including R9B0-labeled semantic-projection and memory-epoch contracts.

The packaged manifest still identifies release `VERA_PROJECT_INTEGRATION_R9A0_20260806_V1`. Later source refinements do not silently rename that historical release.

## Evidence boundary

Repository source is not installation or runtime proof. A green source/CI result does not establish that this package is installed in a ChatGPT Project, selected by the current route, consuming live provider state, behaviorally qualified, or deployed.

Historical provider/database identifiers in the package are provenance unless a current explicit binding says otherwise. New chat/runtime startup does not itself trigger full installation verification.

## Start here

- `project/VERA_R9A0_MANIFEST.json` — package membership and release identity.
- `project/VERA_R9A0_RUNTIME.md` — runtime/orientation/currentness contract.
- `project/VERA_R9A0_NATIVE_CONTRACT.json` — machine-readable native-project contract.
- `project/VERA_R9A0_VALIDATION_REPORT.md` — generation-provenance claim ceiling.
- `.github/workflows/r9a0-native-project.yml` — source validation workflow.

The repository name is historical lineage, not evidence that its package is the current Vera runtime. Current Vera implementation authority lives wherever the current portfolio explicitly binds it.
