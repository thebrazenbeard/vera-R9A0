# Vera R9A0 Cold-Start Protocol

Cold start is attempt-bound evidence for a staged installation. It does not consume a not-yet-issued final receipt as its own prerequisite.

## Inputs

Before this protocol can support an installation claim, independently resolve and bind:

- exact installation attempt ID and transition epoch;
- candidate digest and manifest/checksum identities;
- exact target purpose, locator, and scope;
- route class and route-specific control evidence;
- current authority source/action window;
- predecessor-active release/recovery context;
- current knowledge-continuity provider binding when memory-sensitive readback is required.

## Procedure

1. Start a fresh Project runtime under the same bound installation attempt.
2. Read the active logical Project-file set and Project Settings from the target; transport/display suffixes are metadata unless logical identity plus bytes prove conflict.
3. Verify the active successor candidate against its manifest and checksum set. File presence alone is insufficient.
4. Verify that the target still matches the independently selected target identity and that route/authority evidence remains current for this attempt.
5. Resolve Vera orientation and required heads from fresh admitted evidence. Do not use chronology, max sequence, or a visibility-filtered subset as currentness.
6. For autobiographical continuity checks, require current authority-bound admission and governed durable readback through `KNOWLEDGE_CONTINUITY_PROVIDER_BINDING_CURRENT`; provider identity is provenance, not Vera identity.
7. Confirm Basic Memory Cloud is not required or queried.
8. Verify Voice-critical and portable-start behavior exists in native Project instructions.
9. Emit immutable `COLD_START_RUNTIME_READBACK` evidence bound to the exact attempt/candidate/target tuple and actual observed bytes/state.

## Outcome

Cold start yields one of:

- successor coherent and verified for this attempt;
- predecessor restored and verified;
- recovery required;
- outcome unknown.

Cold-start success is necessary evidence for later post-install qualification and final receipt issuance. It is not itself `INSTALLED_VERIFIED`, release admission, provider qualification, or permission to perform another protected effect.
