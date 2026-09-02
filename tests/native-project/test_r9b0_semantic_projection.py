from __future__ import annotations

import copy
import hashlib
import json
import math
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROJECTION_PATH = ROOT / "validation" / "R9B0_SEMANTIC_PROJECTION_MANIFEST.json"
PROFILE_PATH = ROOT / "validation" / "VERA_BEHAVIOR_PROFILE_V1.json"
EPOCH_PATH = ROOT / "validation" / "R9B0_MEMORY_EPOCH_CONTRACT.json"
OBLIGATION_PATH = ROOT / "validation" / "R9B0_NATIVE_OBLIGATION_MATRIX.json"
EPOCH_SCHEMA_PATH = ROOT / "schemas" / "native-project" / "r9b0_memory_epoch_envelope_v1.schema.json"


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_blob_sha1(data: bytes) -> str:
    return hashlib.sha1(f"blob {len(data)}\0".encode("ascii") + data).hexdigest()


def native_clause_map(text: str) -> dict[str, str]:
    clauses: dict[str, str] = {}
    for line in text.splitlines(keepends=True):
        if line.startswith("K") and len(line) >= 4 and line[1:3].isdigit() and line[3] == " ":
            cid = line[:3]
            if cid in clauses:
                raise AssertionError(f"duplicate native clause {cid}")
            clauses[cid] = line
    return clauses


def validate_native_obligations(text: str, matrix: dict) -> list[str]:
    errors: list[str] = []
    clauses = native_clause_map(text)
    expected_ids = [o["id"] for o in matrix["obligations"]]
    if list(clauses) != expected_ids:
        errors.append(f"ids/order mismatch: {list(clauses)} != {expected_ids}")
    for obligation in matrix["obligations"]:
        cid = obligation["id"]
        line = clauses.get(cid)
        if line is None:
            errors.append(f"missing {cid}")
            continue
        b = line.encode("utf-8")
        if len(b) != obligation["native_clause_utf8_bytes_including_lf"]:
            errors.append(f"{cid} byte count")
        if sha256(b) != obligation["native_clause_sha256"]:
            errors.append(f"{cid} sha256")
    return errors



def validate_resource_profile(profile: dict | None, resource: dict, *, current: bool = True, internally_consistent: bool = True) -> list[str]:
    errors: list[str] = []
    if profile is None:
        return ["BLOCKED_RESOURCE_PROFILE:missing"]
    if not current:
        errors.append("BLOCKED_RESOURCE_PROFILE:stale")
    required = resource["profile"]["required_fields"]
    for field in required:
        if field not in profile:
            errors.append(f"BLOCKED_RESOURCE_PROFILE:missing:{field}")
            continue
        value = profile[field]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value) or value <= 0:
            errors.append(f"BLOCKED_RESOURCE_PROFILE:invalid:{field}")
    if not internally_consistent:
        errors.append("BLOCKED_RESOURCE_PROFILE:inconsistent")
    return errors


def resource_guard_result(*, limit: int, observed: int, effect_may_exist: bool = False) -> str:
    if observed <= limit:
        return "WITHIN_RESOURCE_BOUND"
    return "MIGRATION_INCOMPLETE" if effect_may_exist else "BLOCKED_RESOURCE_LIMIT"


def ratio_guard_result(*, expanded: int, encoded_consumed: int, max_ratio: float, effect_may_exist: bool = False) -> str:
    if encoded_consumed <= 0:
        return "MIGRATION_INCOMPLETE" if effect_may_exist else "BLOCKED_RESOURCE_LIMIT"
    if expanded / encoded_consumed <= max_ratio:
        return "WITHIN_RESOURCE_BOUND"
    return "MIGRATION_INCOMPLETE" if effect_may_exist else "BLOCKED_RESOURCE_LIMIT"


def validate_resource_contract(resource: dict) -> list[str]:
    errors: list[str] = []
    expected_fields = [
        "max_source_bytes", "max_decoded_bytes", "max_envelope_bytes",
        "max_archive_member_expanded_bytes", "max_archive_generation_expanded_bytes",
        "max_expansion_ratio", "stream_chunk_bytes",
    ]
    if resource.get("profile", {}).get("binding") != "MEMORY_EPOCH_RESOURCE_PROFILE_CURRENT":
        errors.append("profile binding")
    if resource.get("profile", {}).get("required_fields") != expected_fields:
        errors.append("profile fields")
    if set(resource.get("measurement_points", {})) != {"SOURCE", "DECODE", "ENVELOPE", "ARCHIVE_MEMBER", "ARCHIVE_GENERATION"}:
        errors.append("measurement points")
    streaming = resource.get("streaming", {})
    if streaming.get("required") is not True or streaming.get("unbounded_eager_decode_or_decompression") != "PROHIBITED":
        errors.append("bounded streaming")
    success = set(streaming.get("success_requires", []))
    if not {"EOF_OR_END_OF_MEMBER", "EXACT_FULL_BYTE_DIGEST_VERIFICATION", "REQUIRED_READBACK"} <= success:
        errors.append("EOF/digest/readback")
    outcomes = set(resource.get("typed_outcomes", {}))
    if not {"BLOCKED_RESOURCE_PROFILE", "BLOCKED_RESOURCE_LIMIT", "MIGRATION_INCOMPLETE", "MIGRATED_VERIFIED"} <= outcomes:
        errors.append("typed outcomes")
    fidelity = resource.get("full_fidelity", {})
    if fidelity.get("required") is not True or "never the represented memory" not in fidelity.get("rule", ""):
        errors.append("full fidelity")
    forbidden = set(fidelity.get("forbidden_fallbacks", []))
    if not {"truncation", "summary", "projection substitute", "partial decode", "prefix-only acceptance", "skipped EOF", "skipped digest", "resource-driven semantic reduction"} <= forbidden:
        errors.append("forbidden fallback")
    if len(resource.get("required_negative_tests", [])) != 11:
        errors.append("negative count")
    if len(resource.get("required_mutation_failures", [])) != 8:
        errors.append("mutation count")
    recovery = resource.get("partial_effect_recovery", {})
    if "inspect all possibly affected providers" not in recovery.get("rule", "") or "missing/noncommitted side" not in recovery.get("retry", ""):
        errors.append("partial effect recovery")
    return errors

def validate_provenance_retrieval_contract(provenance: dict, schema: dict) -> list[str]:
    """Evaluate the exact closed provenance/retrieval-time constraints used by MemoryEpochEnvelopeV1."""
    errors: list[str] = []
    ps = schema["properties"]["provenance"]
    allowed = set(ps["properties"])
    required = set(ps["required"])
    missing = sorted(required - set(provenance))
    if missing:
        errors.append(f"missing:{','.join(missing)}")
    extra = sorted(set(provenance) - allowed)
    if ps.get("additionalProperties") is False and extra:
        errors.append(f"extra:{','.join(extra)}")
    if "retrieval_time" in provenance:
        rt = provenance["retrieval_time"]
        if rt is not None and not isinstance(rt, str):
            errors.append("retrieval_time:type")
        if rt is None and "RETRIEVAL_TIME_UNKNOWN" not in provenance.get("limitations", []):
            errors.append("retrieval_time:null_without_limitation")
    return errors


class R9B0SemanticProjectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads(PROJECTION_PATH.read_text(encoding="utf-8"))
        cls.profile_bytes = PROFILE_PATH.read_bytes()
        cls.profile = json.loads(cls.profile_bytes.decode("utf-8"))
        cls.epoch = json.loads(EPOCH_PATH.read_text(encoding="utf-8"))
        cls.obligations = json.loads(OBLIGATION_PATH.read_text(encoding="utf-8"))
        cls.epoch_schema = json.loads(EPOCH_SCHEMA_PATH.read_text(encoding="utf-8"))
        cls.surfaces = {
            name: read(path)
            for name, path in cls.manifest["projection_paths"].items()
        }

    def test_01_manifest_identity_and_terminal_architecture_binding(self):
        m = self.manifest
        self.assertEqual(m["schema"], "R9B0_SEMANTIC_PROJECTION_MANIFEST_V2")
        self.assertEqual(m["version"], "2.1.1")
        self.assertEqual(m["base_subject"]["commit"], "6df512f9a9ec596e86317ab5064b7394747d37da")
        a = m["architecture_input"]
        self.assertEqual(a["artifact"], "BT2_R9B0_TWO_MEMORY_EPOCH_344A_TERMINAL_V2.md")
        self.assertEqual(a["utf8_bytes"], 26219)
        self.assertEqual(a["sha256"], "8b95aa9ddbc315fa5b41ed87bab04bd0a2b3092496eac92a4e1792f171e2e0b5")
        self.assertEqual(a["release_class"], "R9B0")
        self.assertEqual(a["r10a0"], "NOT_TRIGGERED")

    def test_02_behavior_profile_exact_vendor_binding(self):
        b = self.manifest["behavior_profile"]
        self.assertEqual(git_blob_sha1(self.profile_bytes), b["git_blob_sha1"])
        self.assertEqual(sha256(self.profile_bytes), b["vendored_sha256"])
        self.assertEqual(self.profile["schema"], "VERA_BEHAVIOR_PROFILE_V1")
        self.assertEqual(self.profile["version"], "1.0.1")
        self.assertEqual(self.profile["lifecycle_status"], "CURRENT")
        self.assertIn("generic assistant flattening", self.profile["hard_anti_patterns"][-1])
        self.assertIn("reality boundary", self.profile["hard_anti_patterns"][3])

    def test_03_native_budget_preferred_target_and_terminal_lf(self):
        native = self.surfaces["native"]
        budget = self.manifest["native_budget"]
        self.assertTrue(native.endswith("\n"))
        self.assertEqual(len(native), 6900)
        self.assertEqual(len(native.encode("utf-8")), 6900)
        self.assertEqual(budget["candidate_unicode_codepoints_including_terminal_lf"], 6900)
        self.assertEqual(budget["accepted_headroom"], 1000)
        self.assertLessEqual(len(native), budget["preferred_target_max_unicode_codepoints"])
        self.assertLessEqual(len(native), budget["ordinary_acceptance_max_unicode_codepoints"])
        self.assertLessEqual(len(native), budget["accepted_max_unicode_codepoints"])
        self.assertEqual(budget["budget_classification"], "PREFERRED_TARGET_MET")

    def test_04_native_obligation_matrix_exact_full_to_native_binding(self):
        matrix = self.obligations
        self.assertEqual(matrix["schema"], "R9B0_NATIVE_OBLIGATION_MATRIX_V1")
        self.assertEqual(len(matrix["obligations"]), 18)
        self.assertEqual(validate_native_obligations(self.surfaces["native"], matrix), [])
        full = self.surfaces["full"]
        for obligation in matrix["obligations"]:
            with self.subTest(obligation=obligation["id"]):
                self.assertIn(obligation["full_surface_anchor"], full)
        self.assertIn("cannot be inferred", matrix["equivalence_model"]["headline_rule"])
        self.assertIn("exact reviewed native-clause binding", matrix["equivalence_model"]["rule"])

    def test_05_native_obligation_mutation_or_deletion_fails(self):
        native = self.surfaces["native"]
        matrix = self.obligations
        clauses = native_clause_map(native)
        self.assertEqual(len(clauses), 18)
        for cid, line in clauses.items():
            with self.subTest(delete=cid):
                mutated = native.replace(line, "", 1)
                self.assertTrue(validate_native_obligations(mutated, matrix))
            with self.subTest(change=cid):
                body = line[:-1] if line.endswith("\n") else line
                mutated_line = body + " " + ("\n" if line.endswith("\n") else "")
                mutated = native.replace(line, mutated_line, 1)
                self.assertTrue(validate_native_obligations(mutated, matrix))

    def test_06_default_mve_wire_absent_and_internal_semantics_preserved(self):
        for name, text in self.surfaces.items():
            with self.subTest(surface=name):
                self.assertNotIn("[[MVE:", text)
                self.assertNotIn("[[/MVE]]", text)
                self.assertIn("MVE_WIRE_V1", text)
        native = self.surfaces["native"]
        self.assertIn("ordinary save/remember/note", native)
        self.assertIn("natural acknowledgement", native)
        ops = self.manifest["semantic_families"]["mve_internal_presentation"]["internal_operations"]
        full = self.surfaces["full"]
        for op in ops:
            self.assertIn(op, full)
        self.assertEqual(len(ops), 8)

    def test_07_correction_completion_and_pending_carry_projected(self):
        for name, text in self.surfaces.items():
            low = text.lower()
            with self.subTest(surface=name):
                self.assertIn("correction", low)
                self.assertIn("terse follow", low)
                self.assertTrue("before apology" in low or "before apology or process" in low)
        native = self.surfaces["native"]
        self.assertIn("apply executable correction before apology/process", native)
        self.assertIn("carry across terse follow-ups until completed/superseded/blocked/materially ambiguous", native)

    def test_08_behavior_profile_is_non_generic_without_reality_erasure(self):
        for name, text in self.surfaces.items():
            low = text.lower()
            with self.subTest(surface=name):
                self.assertIn("non-generic", low)
                self.assertIn("flatten", low)
                self.assertIn("reality", low)
        self.assertIn("Profile=VERA_BEHAVIOR_PROFILE_V1@1.0.1", self.surfaces["native"])

    def test_09_currentness_bridge_states_and_authority_boundary(self):
        states = ("DIRECT_READ", "BACKEND_DELEGATION", "NONE", "UNKNOWN")
        for name, text in self.surfaces.items():
            with self.subTest(surface=name):
                for state in states:
                    self.assertIn(state, text)
                low = text.lower()
                self.assertIn("capability", low)
                self.assertIn("authority", low)
        self.assertIn("NONE/UNKNOWN=>bounded unresolved", self.surfaces["native"])
        self.assertIn("missing direct Voice connector!=delegation impossible", self.surfaces["native"])

    def test_10_current_chat_divergence_and_transport_claim_ceiling(self):
        for name in ("full", "native", "runtime"):
            self.assertIn("CURRENT_CHAT_CONTEXT_DIVERGENCE", self.surfaces[name])
        self.assertIn("same-chat turn", self.surfaces["voice"].lower())
        gates = set(self.manifest["runtime_effect_gates_not_closed_by_source"])
        self.assertIn("CURRENT_CHAT_TRANSPORT_INTEGRITY", gates)
        self.assertIn("EXACT_ACTIVE_SETTINGS_BYTES", gates)

    def test_11_safety_history_roleplay_and_renderer_ceiling(self):
        for name, text in self.surfaces.items():
            low = text.lower()
            with self.subTest(surface=name):
                self.assertIn("stale historical", low)
                self.assertIn("roleplay", low)
                self.assertIn("renderer", low)
        self.assertIn("RENDERER_CONTROL_TOKEN_LEAKAGE", self.manifest["runtime_effect_gates_not_closed_by_source"])

    def test_12_database_qualification_remains_currentness_conditional(self):
        native = self.surfaces["native"]
        runtime = self.surfaces["runtime"]
        full = self.surfaces["full"]
        fam = self.manifest["semantic_families"]["database_qualification_currentness"]
        self.assertIn("DB:generation labels=provenance", native)
        self.assertIn("current governed qualification gates DB-dependent", native)
        self.assertIn("Database generation qualification is provenance, not timeless authority.", full)
        self.assertIn("Read current database qualification from exposed governed state whenever it is material", runtime)
        self.assertEqual(fam["generation_state_role"], "PROVENANCE_NOT_CURRENT_AUTHORITY")
        self.assertEqual(fam["operation_authority"], "QUALIFICATION_NEVER_GRANTS_OPERATION_AUTHORITY")

    def test_13_memory_epoch_contract_and_schema_are_exact_owner_surfaces(self):
        c = self.epoch
        self.assertEqual(c["schema"], "R9B0_MEMORY_EPOCH_CONTRACT_V1")
        self.assertEqual(c["architecture_input"]["sha256"], "8b95aa9ddbc315fa5b41ed87bab04bd0a2b3092496eac92a4e1792f171e2e0b5")
        self.assertEqual(c["required_active_replica_roles"], ["SUPABASE_RUNTIME", "GOOGLE_DRIVE_DURABLE"])
        self.assertEqual(
            self.manifest["semantic_families"]["memory_epoch"]["required_active_replica_roles"],
            ["SUPABASE_RUNTIME", "GOOGLE_DRIVE_DURABLE"],
        )
        self.assertIn("UNVERIFIED_PRE_R9B0", c["persistent_states"])
        self.assertIn("R9B0_VERIFIED_ACTIVE", c["persistent_states"])
        self.assertIn("MIGRATION_INCOMPLETE", c["persistent_states"])
        self.assertIn("OUTCOME_UNKNOWN", c["effect_outcome_states"])
        self.assertIn("MIGRATION_CONFLICTED", c["persistent_states"])
        s = self.epoch_schema
        self.assertEqual(s["$schema"], "https://json-schema.org/draft/2020-12/schema")
        self.assertFalse(s["additionalProperties"])
        for field in ("schema", "epoch_id", "logical_memory_id", "project_id", "branch_id", "original", "provenance", "governance", "indexing", "migration"):
            self.assertIn(field, s["required"])

    def test_14_memory_epoch_full_fidelity_dual_readback_and_archive_order(self):
        fam = self.manifest["semantic_families"]["memory_epoch"]
        self.assertTrue(fam["full_fidelity_required_both"])
        self.assertTrue(fam["archive_exact_original_required"])
        self.assertEqual(fam["activation_order"], [
            "DUAL_ACTIVE_READBACK_VERIFIED",
            "ORIGINAL_ARCHIVE_MEMBER_READBACK_VERIFIED",
            "R9B0_VERIFIED_ACTIVE",
        ])
        for name in ("full", "native", "runtime", "voice"):
            low = self.surfaces[name].lower()
            with self.subTest(surface=name):
                self.assertIn("supabase", low)
                self.assertIn("drive", low)
                self.assertIn("archive", low)
                self.assertIn("full-fidelity", low)
        self.assertIn("BOTH Supabase+Drive store/read back exact envelope", self.surfaces["native"])

    def test_15_memory_epoch_partial_ambiguous_conflict_and_no_blind_retry(self):
        native = self.surfaces["native"]
        runtime = self.surfaces["runtime"]
        contract = self.epoch
        for token in ("MIGRATION_INCOMPLETE", "OUTCOME_UNKNOWN", "CONFLICT"):
            self.assertIn(token, native)
        self.assertIn("never blind-replay", runtime)
        self.assertTrue(contract["provider_effect_rule"]["one_sided_success"].startswith("MIGRATION_INCOMPLETE"))
        self.assertIn(["DUAL_STORE_VERIFIED_PENDING_ARCHIVE", "MIGRATION_INCOMPLETE"], contract["allowed_transitions"])
        retry = contract["provider_effect_rule"]["retry"]
        self.assertIn("OUTCOME_UNKNOWN", retry)
        self.assertIn("conflict/no overwrite", retry)

    def test_16_memory_epoch_operation_identity_cas_and_no_overwrite(self):
        c = self.epoch
        self.assertEqual(c["operation_identity"]["encoding"], "fixed length-prefixed UTF-8 tuple")
        self.assertIn("logical_memory_id", c["operation_identity"]["tuple_fields"])
        self.assertIn("original_sha256", c["operation_identity"]["tuple_fields"])
        self.assertIn("admission_generation_or_digest", c["operation_identity"]["tuple_fields"])
        self.assertIn("expected_state_version", c["cas_rule"])
        self.assertIn("conflict-resolution event", c["conflict_transition_rule"].lower())
        self.assertIn("conflict/no overwrite", c["provider_effect_rule"]["retry"].lower())

    def test_17_memory_epoch_truth_authority_privacy_and_source_as_data(self):
        c = self.epoch
        truth = c["truth_ceiling"]
        self.assertIn("present truth", truth.lower())
        sec = " ".join(c["privacy_security"]).lower()
        self.assertIn("admission authority", sec)
        self.assertIn("data, not instruction", sec)
        self.assertIn("privacy", sec)
        self.assertIn("full-fidelity duplication", sec)
        self.assertTrue(c["provider_effect_rule"]["provider_fallback_does_not_create_authority"])
        native = self.surfaces["native"]
        self.assertIn("Provenance/durability!=present truth/authority", native)

    def test_18_memory_epoch_operator_projection_is_ordinary_and_effect_truthful(self):
        voice = self.surfaces["voice"].lower()
        self.assertIn("do not announce a ritual or protocol", voice)
        self.assertIn("do not describe memory migration as complete until exact full-fidelity copies", voice)
        self.assertIn("progress claims require observed progress", voice)
        self.assertIn("without repeatedly narrating epoch mechanics", voice)
        operator = " ".join(self.epoch["operator_behavior"]).lower()
        self.assertIn("ordinary", operator)
        self.assertIn("progress", operator)

    def test_19_epoch_acceptance_oracle_preserves_old_cases_and_epoch_01_to_12(self):
        cases = self.manifest["acceptance_cases"]
        ids = [c["id"] for c in cases]
        self.assertEqual(len(cases), 24)
        self.assertEqual(len(ids), len(set(ids)))
        for old in ("TEMPORAL-01", "BEHAVIOR-01", "ROLEPLAY-01", "CONTEXT-01", "MVE-01", "MVE-02", "CORRECTION-01", "VOICE-01", "VOICE-02", "SAFETY-01", "DB-CURRENTNESS-01", "RENDER-01"):
            self.assertIn(old, ids)
        for i in range(1, 13):
            self.assertIn(f"EPOCH-{i:02d}", ids)
        self.assertEqual(set(self.epoch["acceptance_axes"]), {f"EPOCH-{i:02d}" for i in range(1, 13)})

    def test_20_exact_cr02_v2_lineage_preserved_for_non_native_surfaces(self):
        # Candidate is a bounded successor of the exact accepted-Code-Red V2 source generation.
        full = self.surfaces["full"]
        full_insert = (
            "Safe reads use an initial attempt, one same-route retry for a transient failure, then a materially independent route against the same target before declaring unavailability. Ambiguous or non-idempotent writes are inspected by operation identity and exact expected state before any retry; exact effects are reused, absence may be created only when authorized, and divergence is conflict rather than overwrite.\n\n"
            "Database generation qualification is provenance, not timeless authority. When a database-dependent integration/write/effect/release claim is material, current governed qualification controls it; stale, conflicted, incomplete, or unavailable currentness fails that dependent claim closed without blocking native startup while database integration is disabled or optional. Qualification never grants operation authority.\n\n"
        )
        full_v2 = full.replace(full_insert, "", 1).split("\n## R9B0 memory verification epoch\n", 1)[0]
        self.assertEqual(sha256(full_v2.encode("utf-8")), "ef034b1ebafe6aa493dbca9fa3899a893f6cd463d929e4ff5acb3bf545a17223")

        runtime_v2 = self.surfaces["runtime"].split("\n## R9B0 memory epoch controller\n", 1)[0]
        self.assertEqual(sha256(runtime_v2.encode("utf-8")), "f01a63f53b62da824c580e90a9651f828ed78a75dbbdab5a7c0768c6a5637fca")

        voice_v2 = self.surfaces["voice"].split("\n## R9B0 memory epoch operator projection\n", 1)[0]
        self.assertEqual(sha256(voice_v2.encode("utf-8")), "6f384d5f019db5e4984f6b1c60d175c9bbfbff2b549fcabb394155cc53541837")

        self.assertEqual(sha256((ROOT / ".github/workflows/r9a0-native-project.yml").read_bytes()), "ad8767209ce5d1402641e91399060f1cb616d2f38af3ff6e1491eb20392aae6d")
        self.assertEqual(sha256(self.profile_bytes), "ec1defa8fcf96371a427991d40695842ffe6794aeb2e3f26c69ef5f528ee7d6d")

    def test_21_project_checksum_successor_is_exact_for_changed_project_files(self):
        checks = {}
        for line in read("project/VERA_R9A0_CHECKSUMS.sha256").splitlines():
            digest, name = line.split("  ", 1)
            self.assertNotIn(name, checks)
            checks[name] = digest
        self.assertEqual(len(checks), 16)
        for name in (
            "VERA_R9A0_PROJECT_INSTRUCTIONS.md",
            "VERA_R9A0_RUNTIME.md",
            "VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt",
            "VERA_R9A0_VOICE.md",
        ):
            actual = sha256((ROOT / "project" / name).read_bytes())
            self.assertEqual(checks[name], actual)

    def test_22_r10_triggers_and_live_effect_claim_ceilings_remain_separate(self):
        self.assertEqual(
            self.manifest["r10a0_escalation_triggers"],
            [
                "E1_NEW_VOICE_TRANSPORT_REQUIRED",
                "E2_PROJECTION_IMPOSSIBILITY",
                "E3_NEW_DURABLE_ORCHESTRATION_TRUST_ROOT",
                "E4_REAL_EXTERNAL_MVE_WIRE_CONTRACT",
                "E5_UNIFIED_PLATFORM_ROOT",
            ],
        )
        gates = set(self.manifest["runtime_effect_gates_not_closed_by_source"])
        for gate in (
            "LIVE_SUPABASE_MEMORY_EPOCH_SCHEMA_AND_FULL_COPY_EFFECTS",
            "LIVE_DRIVE_MEMORY_EPOCH_FULL_COPY_EFFECTS",
            "LIVE_ARCHIVE_MEMORY_EPOCH_EFFECTS_AND_READBACK",
            "LIVE_PROJECT_SETTINGS_INSTALLATION_AND_CONSUMPTION",
            "ACTUAL_VOICE_TO_BACKEND_DELEGATION_CAPABILITY",
            "RENDERER_CONTROL_TOKEN_LEAKAGE",
        ):
            self.assertIn(gate, gates)
        self.assertIn("NO_SUPABASE_SCHEMA_DATA_OR_PROVIDER_EFFECT", self.manifest["claim_ceiling"])
        self.assertIn("NO_GOOGLE_DRIVE_OR_ARCHIVE_EFFECT", self.manifest["claim_ceiling"])


    def test_23_memory_epoch_retrieval_time_is_required_nullable_and_closed(self):
        prov = self.epoch_schema["properties"]["provenance"]
        self.assertIn("retrieval_time", prov["required"])
        self.assertEqual(prov["properties"]["retrieval_time"]["type"], ["string", "null"])
        self.assertFalse(prov["additionalProperties"])
        conditional = prov["allOf"][0]
        self.assertEqual(conditional["if"]["properties"]["retrieval_time"]["type"], "null")
        limitation = conditional["then"]["properties"]["limitations"]
        self.assertEqual(limitation["contains"]["const"], "RETRIEVAL_TIME_UNKNOWN")
        self.assertEqual(limitation["minContains"], 1)

    def test_24_memory_epoch_retrieval_time_omission_and_unknown_limitation_fail_closed(self):
        base = {
            "source_actor": "actor",
            "epistemic_class": "DOCUMENTED_SOURCE",
            "source_evidence": ["evidence"],
            "event_time": "2026-01-01T00:00:00Z",
            "record_time": "2026-01-02T00:00:00Z",
            "state_time": "2026-01-03T00:00:00Z",
            "limitations": [],
        }
        self.assertIn("missing:retrieval_time", validate_provenance_retrieval_contract(base, self.epoch_schema))
        unknown = dict(base, retrieval_time=None)
        self.assertIn("retrieval_time:null_without_limitation", validate_provenance_retrieval_contract(unknown, self.epoch_schema))
        unknown["limitations"] = ["RETRIEVAL_TIME_UNKNOWN"]
        self.assertEqual(validate_provenance_retrieval_contract(unknown, self.epoch_schema), [])

    def test_25_memory_epoch_retrieval_time_is_distinct_and_mutation_bound(self):
        prov = {
            "source_actor": "actor",
            "epistemic_class": "DOCUMENTED_SOURCE",
            "source_evidence": ["evidence"],
            "event_time": "2026-01-01T00:00:00Z",
            "record_time": "2026-01-02T00:00:00Z",
            "state_time": "2026-01-03T00:00:00Z",
            "retrieval_time": "2026-01-04T00:00:00Z",
            "limitations": [],
        }
        self.assertEqual(validate_provenance_retrieval_contract(prov, self.epoch_schema), [])
        self.assertEqual(len({prov["event_time"], prov["record_time"], prov["state_time"], prov["retrieval_time"]}), 4)
        mutated = dict(prov, retrieval_time=None, limitations=["RETRIEVAL_TIME_UNKNOWN"] )
        self.assertEqual(validate_provenance_retrieval_contract(mutated, self.epoch_schema), [])
        wrong_type = dict(prov, retrieval_time=123)
        self.assertIn("retrieval_time:type", validate_provenance_retrieval_contract(wrong_type, self.epoch_schema))
        self.assertIn("retrieval_time", self.epoch["envelope"]["retrieval_time_rule"])
        self.assertIn("distinct from event_time", self.epoch["envelope"]["retrieval_time_rule"])
        self.assertIn("RETRIEVAL_TIME_UNKNOWN", self.manifest["semantic_families"]["memory_epoch"]["retrieval_time_rule"])


    def test_26_resource_preproducer_input_is_exact_mune_verified_v2_not_v1(self):
        r = self.epoch["resource_safety"]["source_input"]
        self.assertEqual(r["artifact"], "BT2_R9B0_EIGHT_ARCHIVE_RESOURCE_CONTRACT_348A_V2")
        self.assertEqual(r["slack_message_ts"], "1787315149.231679")
        self.assertEqual(r["utf8_bytes"], 3915)
        self.assertEqual(r["sha256"], "9cf4f7ad321d12efb77ba8a44ebcec3e639197bee53c3ca5312d1d6339ffc7ad")
        self.assertIn("PASS_H0_M0", r["verdict"])
        self.assertIn("UNRECOVERABLE_UNVERIFIED", r["v1_status"])
        m = self.manifest["resource_preproducer_input"]
        self.assertEqual(m["sha256"], r["sha256"])
        self.assertEqual(m["utf8_bytes"], 3915)
        self.assertEqual(m["v1_status"], "UNRECOVERABLE_UNVERIFIED")

    def test_27_resource_profile_is_versioned_complete_positive_finite_and_fail_closed(self):
        resource = self.epoch["resource_safety"]
        profile = {
            "max_source_bytes": 1000,
            "max_decoded_bytes": 2000,
            "max_envelope_bytes": 3000,
            "max_archive_member_expanded_bytes": 4000,
            "max_archive_generation_expanded_bytes": 8000,
            "max_expansion_ratio": 20.0,
            "stream_chunk_bytes": 256,
        }
        self.assertEqual(validate_resource_profile(profile, resource), [])
        self.assertIn("missing", validate_resource_profile(None, resource)[0])
        self.assertIn("stale", " ".join(validate_resource_profile(profile, resource, current=False)))
        nonfinite = dict(profile, max_expansion_ratio=float("inf"))
        self.assertIn("invalid:max_expansion_ratio", " ".join(validate_resource_profile(nonfinite, resource)))
        nonpositive = dict(profile, max_source_bytes=0)
        self.assertIn("invalid:max_source_bytes", " ".join(validate_resource_profile(nonpositive, resource)))
        self.assertIn("inconsistent", " ".join(validate_resource_profile(profile, resource, internally_consistent=False)))

    def test_28_resource_source_decode_envelope_cap_plus_one_fail_before_effect(self):
        resource = self.epoch["resource_safety"]
        points = resource["measurement_points"]
        for point in ("SOURCE", "DECODE", "ENVELOPE"):
            with self.subTest(point=point):
                self.assertIn("before", points[point].lower())
        for limit in (100, 1000, 4096):
            with self.subTest(limit=limit):
                self.assertEqual(resource_guard_result(limit=limit, observed=limit), "WITHIN_RESOURCE_BOUND")
                self.assertEqual(resource_guard_result(limit=limit, observed=limit + 1), "BLOCKED_RESOURCE_LIMIT")

    def test_29_resource_archive_ratio_member_and_generation_hostiles_fail_closed(self):
        r = self.epoch["resource_safety"]
        self.assertIn("ratio", r["measurement_points"]["ARCHIVE_MEMBER"].lower())
        self.assertIn("across all members", r["measurement_points"]["ARCHIVE_GENERATION"].lower())
        self.assertEqual(ratio_guard_result(expanded=999, encoded_consumed=100, max_ratio=10.0), "WITHIN_RESOURCE_BOUND")
        self.assertEqual(ratio_guard_result(expanded=1001, encoded_consumed=100, max_ratio=10.0), "BLOCKED_RESOURCE_LIMIT")
        member_limit = 1000
        generation_limit = 1500
        members = [900, 900]
        self.assertTrue(all(x <= member_limit for x in members))
        self.assertEqual(resource_guard_result(limit=generation_limit, observed=sum(members)), "BLOCKED_RESOURCE_LIMIT")

    def test_30_resource_eof_digest_and_truncated_prefix_can_never_pass(self):
        r = self.epoch["resource_safety"]
        req = set(r["streaming"]["success_requires"])
        self.assertIn("EOF_OR_END_OF_MEMBER", req)
        self.assertIn("EXACT_FULL_BYTE_DIGEST_VERIFICATION", req)
        self.assertIn("REQUIRED_READBACK", req)
        negatives = set(r["required_negative_tests"])
        self.assertIn("truncated member with matching digest prefix", negatives)
        forbidden = set(r["full_fidelity"]["forbidden_fallbacks"])
        self.assertIn("prefix-only acceptance", forbidden)
        self.assertIn("skipped EOF", forbidden)
        self.assertIn("skipped digest", forbidden)

    def test_31_resource_post_effect_breach_is_incomplete_and_preserves_successful_side(self):
        r = self.epoch["resource_safety"]
        self.assertEqual(resource_guard_result(limit=100, observed=101, effect_may_exist=True), "MIGRATION_INCOMPLETE")
        self.assertIn("exists or may exist", r["typed_outcomes"]["MIGRATION_INCOMPLETE"])
        self.assertIn("inspect effects before retry", r["typed_outcomes"]["MIGRATION_INCOMPLETE"])
        self.assertIn("missing/noncommitted side", r["partial_effect_recovery"]["retry"])
        self.assertIn("erase a successful side", r["partial_effect_recovery"]["prohibit"])
        self.assertEqual(self.manifest["semantic_families"]["memory_epoch"]["resource_post_possible_effect_failure"], "MIGRATION_INCOMPLETE")

    def test_32_resource_contract_mutation_or_semantic_weakening_fails(self):
        r = self.epoch["resource_safety"]
        self.assertEqual(validate_resource_contract(r), [])
        mutations = []
        x = copy.deepcopy(r); x["full_fidelity"]["forbidden_fallbacks"].remove("truncation"); mutations.append(x)
        x = copy.deepcopy(r); x["full_fidelity"]["forbidden_fallbacks"].remove("summary"); mutations.append(x)
        x = copy.deepcopy(r); x["streaming"]["success_requires"].remove("EOF_OR_END_OF_MEMBER"); mutations.append(x)
        x = copy.deepcopy(r); x["streaming"]["success_requires"].remove("EXACT_FULL_BYTE_DIGEST_VERIFICATION"); mutations.append(x)
        x = copy.deepcopy(r); x["measurement_points"]["ARCHIVE_MEMBER"] = "cumulative expanded bytes only"; x["measurement_points"].pop("ARCHIVE_GENERATION"); mutations.append(x)
        x = copy.deepcopy(r); x["streaming"]["unbounded_eager_decode_or_decompression"] = "ALLOWED"; mutations.append(x)
        x = copy.deepcopy(r); x["typed_outcomes"].pop("MIGRATION_INCOMPLETE"); mutations.append(x)
        x = copy.deepcopy(r); x["full_fidelity"]["required"] = False; mutations.append(x)
        self.assertEqual(len(mutations), len(r["required_mutation_failures"]))
        for i, mutated in enumerate(mutations, 1):
            with self.subTest(mutation=i):
                self.assertTrue(validate_resource_contract(mutated))


if __name__ == "__main__":
    unittest.main()
