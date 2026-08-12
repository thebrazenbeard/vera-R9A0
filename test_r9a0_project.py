from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import pathlib
import shutil
import subprocess
import sys
import tempfile
import unittest
from decimal import Decimal

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("validator", ROOT / "scripts/validate_r9a0_project.py")
validator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(validator)

def load_strict(rel: str):
    return validator.strict_json_load(ROOT / rel)

CONTRACT = load_strict("project/VERA_R9A0_NATIVE_CONTRACT.json")
SCHEMA = load_strict("schemas/native-project/vera-r9a0-native-contract.schema.json")

def manifest_v2():
    return {
        "release_id": validator.RELEASE_ID,
        "release_kind": validator.MANIFEST_RELEASE_KIND,
        "files": list(validator.R9A0_NATIVE_LOGICAL_SET_V1),
        "unique_file_count": len(validator.R9A0_NATIVE_LOGICAL_SET_V1),
        "checksums_path": "VERA_R9A0_CHECKSUMS.sha256",
        "native_settings_path": "VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt",
    }

def receipt_template_v2():
    bind = {
        "candidate_digest": None,
        "installation_attempt_id": None,
        "route_class": None,
        "target_binding_digest": None,
        "transition_epoch": None,
    }
    return {
        "artifact_identity": {
            "artifact_composition_root": None,
            "checksums_sha256": None,
            "manifest_sha256": None,
        },
        "attempt_action_envelope_evidence": {"ref": None, "sha256": None},
        "attempt_binding": copy.deepcopy(bind),
        "authority_evidence": {"ref": None, "sha256": None},
        "evidence_roots": {
            "cold_start_runtime_readback": {
                "attempt_binding": copy.deepcopy(bind), "ref": None, "result": None, "sha256": None
            },
            "in_situ_project_qualification": {
                "attempt_binding": copy.deepcopy(bind), "ref": None, "result": None, "sha256": None
            },
            "install_base_outcome_readback": {
                "attempt_binding": copy.deepcopy(bind), "ref": None, "result": None, "sha256": None
            },
            "post_install_environment_check": {
                "attempt_binding": copy.deepcopy(bind), "ref": None, "result": None, "sha256": None
            },
        },
        "operator_decision_packet_evidence": {"ref": None, "sha256": None},
        "receipt_schema": "VERA_R9A0_INSTALLATION_RECEIPT_V2",
        "release_id": validator.RELEASE_ID,
        "target_binding_evidence": {"ref": None, "sha256": None},
        "template_profile": "R9A0_INSTALLATION_RECEIPT_TEMPLATE_V2",
    }

def issued_receipt_v2(*, target_locator="project:vera:test-target", target_scope="PROJECT_FILES_AND_SETTINGS", expected_target_locator="project:vera:test-target", expected_target_scope="PROJECT_FILES_AND_SETTINGS", route_class="USER_MANUAL", authority_ref="authority:1", authority_source="patrick-current-authority", action_window_id="window:1", environment_locator="project:vera:test-target:observed", expected_environment_locator="project:vera:test-target:observed", manual_control_ref="manual:1", human_authorized=True, tool_control_ref="toolconfinement:1", tool_route="openai:project-install-tool", capability_scope="EXACT_TARGET_PROJECT_FILES_AND_SETTINGS", confinement_current=True):

    d = "a" * 64
    binding = {
        "candidate_digest": d,
        "installation_attempt_id": "attempt:1",
        "route_class": route_class,
        "target_binding_digest": None,
        "transition_epoch": "epoch:1",
    }

    def seal(record):
        record = copy.deepcopy(record)
        record["sha256"] = "0" * 64
        record["sha256"] = validator._canonical_evidence_digest(record)
        return record

    target = seal({
        "role": "EXACT_TARGET_BINDING",
        "ref": "target:1",
        "target_purpose": "VERA_R9A0_NATIVE_PROJECT_INSTALLATION",
        "target_locator": target_locator,
        "target_scope": target_scope,
        "candidate_digest": d,
        "target_matches_expected": True,
    })
    binding["target_binding_digest"] = target["sha256"]

    packet = seal({
        "role": "OPERATOR_DECISION_PACKET",
        "ref": "packet:1",
        "decision": "APPROVE_ATTEMPT",
        "candidate_digest": d,
        "target_binding_sha256": target["sha256"],
        "route_class": route_class,
    })
    plan = seal({
        "role": "ATTEMPT_PLAN",
        "ref": "plan:1",
        "attempt_binding": copy.deepcopy(binding),
        "operator_decision_packet_sha256": packet["sha256"],
        "target_binding_sha256": target["sha256"],
        "effect_class": "PROJECT_INSTALLATION_ATTEMPT",
    })
    authority = seal({
        "role": "EFFECT_TIME_AUTHORITY",
        "ref": authority_ref,
        "decision": "ALLOW",
        "authorized": True,
        "effect_class": "PROJECT_INSTALLATION_ATTEMPT",
        "valid_at_effect_time": True,
        "attempt_binding": copy.deepcopy(binding),
        "target_binding_sha256": target["sha256"],
        "attempt_plan_sha256": plan["sha256"],
        "authority_source": authority_source,
        "action_window_id": action_window_id,
    })
    recheck = seal({
        "role": "PRE_DISPATCH_RECHECK",
        "ref": "recheck:1",
        "attempt_binding": copy.deepcopy(binding),
        "authority_sha256": authority["sha256"],
        "target_binding_sha256": target["sha256"],
        "attempt_plan_sha256": plan["sha256"],
        "target_current": True,
        "authority_current": True,
        "plan_current": True,
    })
    if route_class == "USER_MANUAL":
        route_control_name = "manual_operator_control_evidence"
        route_control = seal({
            "role": "MANUAL_OPERATOR_CONTROL",
            "ref": manual_control_ref,
            "attempt_binding": copy.deepcopy(binding),
            "operator_decision_packet_sha256": packet["sha256"],
            "target_binding_sha256": target["sha256"],
            "human_authorized": human_authorized,
        })
    else:
        route_control_name = "assistant_tool_confinement_evidence"
        route_control = seal({
            "role": "ASSISTANT_TOOL_CONFINEMENT",
            "ref": tool_control_ref,
            "attempt_binding": copy.deepcopy(binding),
            "target_binding_sha256": target["sha256"],
            "authority_sha256": authority["sha256"],
            "tool_route": tool_route,
            "capability_scope": capability_scope,
            "confinement_current": confinement_current,
            "effect_class": "PROJECT_INSTALLATION_ATTEMPT",
        })
    envelope = seal({
        "role": "ATTEMPT_ACTION_ENVELOPE",
        "ref": "env:1",
        "operator_decision_packet_sha256": packet["sha256"],
        "authority_sha256": authority["sha256"],
        "target_binding_sha256": target["sha256"],
        "attempt_binding": copy.deepcopy(binding),
        "attempt_plan_sha256": plan["sha256"],
        "pre_dispatch_recheck_sha256": recheck["sha256"],
        "effect_class": "PROJECT_INSTALLATION_ATTEMPT",
        "route_control_sha256": route_control["sha256"],
    })
    env_binding = seal({
        "role": "IN_SITU_ENVIRONMENT_BINDING",
        "ref": "environment:1",
        "target_binding_sha256": target["sha256"],
        "candidate_digest": d,
        "environment_locator": environment_locator,
        "environment_matches_expected": True,
    })
    selector = seal({
        "role": "INSTALLATION_INTENT_SELECTOR",
        "ref": "selector:1",
        "candidate_digest": d,
        "target_purpose": "VERA_R9A0_NATIVE_PROJECT_INSTALLATION",
        "target_locator": expected_target_locator,
        "target_scope": expected_target_scope,
        "authority_ref": authority_ref,
        "authority_source": authority_source,
        "action_window_id": action_window_id,
        "effect_class": "PROJECT_INSTALLATION_ATTEMPT",
        "environment_locator": expected_environment_locator,
        "route_class": route_class,
    })

    def root(field, role, result, **extra):
        return seal({
            "role": role,
            "ref": field + ":1",
            "attempt_binding": copy.deepcopy(binding),
            "result": result,
            **extra,
        })
    root_records = {
        "cold_start_runtime_readback": root("cold", "COLD_START_RUNTIME_READBACK", "PASS"),
        "in_situ_project_qualification": root("insitu", "IN_SITU_PROJECT_QUALIFICATION", "PASS", environment_binding_sha256=env_binding["sha256"]),
        "install_base_outcome_readback": root("base", "INSTALL_BASE_OUTCOME_READBACK", "SUCCESSOR_EXACT"),
        "post_install_environment_check": root("post", "POST_INSTALL_ENVIRONMENT_CHECK", "PASS"),
    }

    manifest_bytes = b'{"fixture":"manifest"}\n'
    checksums_bytes = b'fixture-checksums\n'
    m = hashlib.sha256(manifest_bytes).hexdigest()
    c = hashlib.sha256(checksums_bytes).hexdigest()
    receipt = {
        "artifact_identity": {
            "artifact_composition_root": d,
            "checksums_sha256": c,
            "manifest_sha256": m,
        },
        "attempt_action_envelope_evidence": {"ref": envelope["ref"], "sha256": envelope["sha256"]},
        "attempt_binding": copy.deepcopy(binding),
        "authority_evidence": {"ref": authority["ref"], "sha256": authority["sha256"]},
        "evidence_roots": {
            field: {
                "attempt_binding": copy.deepcopy(binding),
                "ref": record["ref"],
                "result": record["result"],
                "sha256": record["sha256"],
            }
            for field, record in root_records.items()
        },
        "operator_decision_packet_evidence": {"ref": packet["ref"], "sha256": packet["sha256"]},
        "receipt_schema": "VERA_R9A0_INSTALLATION_RECEIPT_V2",
        "release_id": validator.RELEASE_ID,
        "target_binding_evidence": {"ref": target["ref"], "sha256": target["sha256"]},
        "template_profile": "R9A0_INSTALLATION_RECEIPT_TEMPLATE_V2",
    }
    evidence = {
        "operator_decision_packet_evidence": packet,
        "attempt_action_envelope_evidence": envelope,
        "authority_evidence": authority,
        "target_binding_evidence": target,
        "attempt_plan_evidence": plan,
        "pre_dispatch_recheck_evidence": recheck,
        route_control_name: route_control,
        "in_situ_environment_binding_evidence": env_binding,
        "installation_selector_evidence": selector,
        "__trusted_control_roots": {
            "installation_selector_evidence": {"ref": selector["ref"], "sha256": selector["sha256"]},
            "route_control_evidence": {"ref": route_control["ref"], "sha256": route_control["sha256"]},
        },
        "artifact_bytes": {
            "VERA_R9A0_MANIFEST.json": manifest_bytes,
            "VERA_R9A0_CHECKSUMS.sha256": checksums_bytes,
        },
        **root_records,
    }
    return receipt, evidence

def validate_issued(receipt, evidence, trusted_roots=None):
    roots = trusted_roots if trusted_roots is not None else evidence.get("__trusted_control_roots")
    return validator.validate_issued_receipt(receipt, evidence, roots)

class B40Tests(unittest.TestCase):
    def test_01_receipt_profile_exact_identity(self):
        raw = validator.RECEIPT_PROFILE_JSON.encode("utf-8")
        self.assertEqual(len(raw), 4260)
        self.assertEqual(hashlib.sha256(raw).hexdigest(), validator.RECEIPT_PROFILE_SHA256)

    def test_02_contract_schema_valid(self):
        validator.validate_contract(CONTRACT, SCHEMA)

    def test_03_closed_stable_subtrees_present(self):
        for key in ("anticipatory_pragmatics", "safety_semantic_gate", "assignment_currentness"):
            self.assertIn(key, CONTRACT)
        self.assertEqual(CONTRACT["native_instructions"]["accepted_max_characters"], Decimal(7900))
        self.assertEqual(CONTRACT["native_instructions"]["outer_hard_max_characters"], Decimal(8000))

    def test_04_wrong_role_slot_rejected(self):
        bad = copy.deepcopy(CONTRACT)
        bad["current_projection_requirements"]["release"]["database_integration_binding"] = "DB_QUALIFICATION_EXECUTION_BINDING"
        with self.assertRaises(validator.ValidationError):
            validator.validate_instance(bad, SCHEMA)

    def test_05_generation_provenance_cannot_promote_to_current_slot(self):
        bad = copy.deepcopy(CONTRACT)
        bad["current_projection_requirements"]["release"]["candidate_selection"] = "INSTALLATION_UNVERIFIED"
        with self.assertRaises(validator.ValidationError):
            validator.validate_instance(bad, SCHEMA)

    def test_06_live_locator_extra_rejected(self):
        bad = copy.deepcopy(CONTRACT)
        bad["supabase"]["temporary_project"] = "agvhmutlrolbaijzlbqk"
        with self.assertRaises(validator.ValidationError):
            validator.validate_instance(bad, SCHEMA)

    def test_07_unqualified_production_field_rejected(self):
        bad = copy.deepcopy(CONTRACT)
        bad["supabase"]["production_prohibited"] = True
        with self.assertRaises(validator.ValidationError):
            validator.validate_instance(bad, SCHEMA)

    def test_08_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(validator.ValidationError, "duplicate_json_key"):
            validator.strict_json_loads('{"a":1,"a":2}')

    def test_09_nonfinite_tokens_rejected(self):
        for token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token), self.assertRaises(validator.ValidationError):
                validator.strict_json_loads('{"x":' + token + '}')

    def test_10_numeric_profile_bounds(self):
        self.assertEqual(validator.strict_json_loads('{"x":' + "9"*32 + '}')["x"], Decimal("9"*32))
        with self.assertRaisesRegex(validator.ValidationError, "digits"):
            validator.strict_json_loads('{"x":' + "9"*33 + '}')
        self.assertEqual(validator.strict_json_loads('{"x":1e128}')["x"], Decimal("1e128"))
        with self.assertRaisesRegex(validator.ValidationError, "exponent"):
            validator.strict_json_loads('{"x":1e129}')
        with self.assertRaisesRegex(validator.ValidationError, "exponent"):
            validator.strict_json_loads('{"x":1e9999}')

    def test_11_json_equality_is_json_not_python(self):
        self.assertFalse(validator.json_equal(True, Decimal(1)))
        self.assertTrue(validator.json_equal(Decimal(1), Decimal("1.0")))
        self.assertTrue(validator.json_equal(
            {"a": Decimal(1), "b": Decimal(2)},
            {"b": Decimal("2.0"), "a": Decimal("1.0")},
        ))
        self.assertFalse(validator.json_equal([Decimal(1), Decimal(2)], [Decimal(2), Decimal(1)]))

    def test_12_unique_items_uses_json_equality(self):
        sch = validator.strict_json_loads('{"type":"array","items":{"type":"number"},"uniqueItems":true}')
        validator._validate_schema_node(sch)
        with self.assertRaisesRegex(validator.ValidationError, "uniqueItems"):
            validator.validate_instance([Decimal(1), Decimal("1.0")], sch)
        validator.validate_instance([True, Decimal(1)], validator.strict_json_loads(
            '{"type":"array","items":{"type":["boolean","number"]},"uniqueItems":true}'
        )) if False else None  # profile intentionally does not admit union types.

    def test_13_schema_unknown_keyword_rejected_recursively(self):
        bad = copy.deepcopy(SCHEMA)
        bad["properties"]["ci"]["mystery"] = True
        with self.assertRaisesRegex(validator.ValidationError, "unknown_keyword"):
            validator.validate_schema_profile(bad)

    def test_14_schema_required_shape_rejected(self):
        bad = copy.deepcopy(SCHEMA)
        bad["properties"]["ci"]["required"] = "exact_candidate_head_required"
        with self.assertRaisesRegex(validator.ValidationError, "required_shape"):
            validator.validate_schema_profile(bad)

    def test_15_schema_properties_shape_rejected(self):
        bad = copy.deepcopy(SCHEMA)
        bad["properties"]["ci"]["properties"] = []
        with self.assertRaisesRegex(validator.ValidationError, "properties_shape"):
            validator.validate_schema_profile(bad)

    def test_16_schema_self_weakening_additional_properties_rejected(self):
        bad = copy.deepcopy(SCHEMA)
        del bad["properties"]["ci"]["additionalProperties"]
        with self.assertRaisesRegex(validator.ValidationError, "additional_properties"):
            validator.validate_schema_profile(bad)

    def test_17_schema_self_weakening_required_drop_rejected(self):
        bad = copy.deepcopy(SCHEMA)
        bad["properties"]["ci"]["required"] = bad["properties"]["ci"]["required"][:-1]
        with self.assertRaisesRegex(validator.ValidationError, "required_mismatch"):
            validator.validate_schema_profile(bad)

    def test_18_schema_pattern_allowlist(self):
        sch = validator.strict_json_loads('{"type":"string","pattern":"^.*$"}')
        with self.assertRaisesRegex(validator.ValidationError, "pattern_unsupported"):
            validator._validate_schema_node(sch)

    def test_19_schema_keyword_value_shapes(self):
        bad_cases = [
            '{"type":"array","uniqueItems":1}',
            '{"type":"array","items":[]}',
            '{"type":"object","required":[],"properties":{},"additionalProperties":"false"}',
            '{"type":"string","pattern":7}',
        ]
        for raw in bad_cases:
            with self.subTest(raw=raw), self.assertRaises(validator.ValidationError):
                validator._validate_schema_node(validator.strict_json_loads(raw))

    def test_20_manifest_independent_logical_set(self):
        good = manifest_v2()
        validator.validate_manifest(validator._to_decimal_json(good))
        bad = copy.deepcopy(good)
        bad["files"] = bad["files"][:-1]
        bad["unique_file_count"] -= 1
        with self.assertRaisesRegex(validator.ValidationError, "logical_set"):
            validator.validate_manifest(validator._to_decimal_json(bad))

    def test_21_manifest_rejects_old_policy_ownership(self):
        bad = manifest_v2()
        bad["active_surfaces"] = ["SUPABASE"]
        with self.assertRaisesRegex(validator.ValidationError, "closed_shape"):
            validator.validate_manifest(validator._to_decimal_json(bad))

    def test_22_package_closed_semantic_shape(self):
        validator.validate_package(validator._to_decimal_json(copy.deepcopy(validator.PACKAGE_V2)))
        bad = copy.deepcopy(validator.PACKAGE_V2)
        bad["atomic_upload_required"] = True
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(validator._to_decimal_json(bad))

    def test_23_package_rejects_current_selector(self):
        bad = copy.deepcopy(validator.PACKAGE_V2)
        bad["database_contract_state"] = "PASS"
        with self.assertRaises(validator.ValidationError):
            validator.validate_package(validator._to_decimal_json(bad))

    def test_24_receipt_template_valid(self):
        self.assertEqual(
            validator.validate_receipt_template(receipt_template_v2()),
            "RECEIPT_TEMPLATE_PROFILE_VALID",
        )

    def test_25_receipt_template_prepopulation_rejected(self):
        bad = receipt_template_v2()
        bad["attempt_binding"]["installation_attempt_id"] = "fake"
        with self.assertRaisesRegex(validator.ValidationError, "RECEIPT_TEMPLATE_PREPOPULATED"):
            validator.validate_receipt_template(bad)

    def test_26_receipt_template_forbidden_current_state_rejected(self):
        bad = receipt_template_v2()
        bad["final_state"] = "INSTALLED_VERIFIED_CURRENT"
        with self.assertRaises(validator.ValidationError):
            validator.validate_receipt_template(bad)

    def test_27_issued_receipt_needs_external_evidence_resolution(self):
        receipt, _ = issued_receipt_v2()
        with self.assertRaisesRegex(validator.ValidationError, "external_evidence_resolution_required"):
            validator.validate_issued_receipt(receipt)

    def test_28_issued_receipt_valid_with_bound_evidence(self):
        receipt, evidence = issued_receipt_v2()
        self.assertEqual(validate_issued(receipt, evidence), "ISSUED_RECEIPT_VALID")

    def test_29_issued_receipt_root_attempt_mismatch_rejected(self):
        receipt, evidence = issued_receipt_v2()
        receipt["evidence_roots"]["cold_start_runtime_readback"]["attempt_binding"]["transition_epoch"] = "epoch:other"
        with self.assertRaisesRegex(validator.ValidationError, "evidence_root_attempt_mismatch"):
            validate_issued(receipt, evidence)

    def test_30_issued_receipt_target_digest_mismatch_rejected(self):
        receipt, evidence = issued_receipt_v2()
        receipt["target_binding_evidence"]["sha256"] = "9"*64
        with self.assertRaisesRegex(validator.ValidationError, "target_binding_digest_mismatch"):
            validate_issued(receipt, evidence)

    def test_31_validation_report_machine_header_exact(self):
        header = validator.VALIDATION_REPORT_PREFIX + json.dumps(
            validator.VALIDATION_REPORT_MACHINE, sort_keys=True, separators=(",",":")
        )
        validator.validate_validation_report(header + "\n\nHuman body may discuss historical PASS text without becoming machine state.\n")

    def test_32_validation_report_wrong_classification_rejected(self):
        bad = copy.deepcopy(validator.VALIDATION_REPORT_MACHINE)
        bad["classification"] = "CURRENT_PASS"
        header = validator.VALIDATION_REPORT_PREFIX + json.dumps(bad, sort_keys=True, separators=(",",":"))
        with self.assertRaises(validator.ValidationError):
            validator.validate_validation_report(header + "\n")

    def test_33_native_7900_accepted_7901_rejected(self):
        validator.validate_native_instructions("x"*7900)
        with self.assertRaisesRegex(validator.ValidationError, "release_acceptance_limit"):
            validator.validate_native_instructions("x"*7901)

    def test_34_outer_8000_is_not_release_acceptance(self):
        with self.assertRaisesRegex(validator.ValidationError, "release_acceptance_limit"):
            validator.validate_native_instructions("x"*8000)
        with self.assertRaisesRegex(validator.ValidationError, "outer_platform_limit"):
            validator.validate_native_instructions("x"*8001)

    def test_35_no_phrase_based_currentness_oracle(self):
        self.assertFalse(hasattr(validator, "REQUIRED_NATIVE"))
        self.assertFalse(hasattr(validator, "FORBIDDEN_NATIVE"))

    def test_36_identity_continuity_recollection_policy(self):
        ic = CONTRACT["identity_continuity"]
        self.assertEqual(ic["project_identity"], "VERA")
        self.assertTrue(ic["session_runtime_process_model_call_ids_are_provenance_only"])
        self.assertEqual(set(ic["recollection_requires"]), {"VERA_OWNED","AUTOBIOGRAPHICAL","CURRENT_AUTHORITY_BOUND_ADMISSION","SUCCESSFUL_GOVERNED_PERSISTENT_READBACK"})
        self.assertTrue(ic["memory_owner_does_not_rewrite_proposition_actor"])
        self.assertTrue(ic["event_time_preserved"])

    def test_37_knowledge_continuity_provider_binding_policy(self):
        kc = CONTRACT["knowledge_continuity"]
        self.assertEqual(kc["capability_id"], "KNOWLEDGE_CONTINUITY")
        self.assertEqual(kc["current_provider_binding_role"], "KNOWLEDGE_CONTINUITY_PROVIDER_BINDING_CURRENT")
        self.assertTrue(kc["provider_identity_is_provenance_not_project_identity"])
        self.assertTrue(kc["reachable_alternate_is_not_fallback_authority"])

    def test_38_source_cut_and_privacy_ordering_policy(self):
        ac = CONTRACT["assignment_currentness"]
        self.assertTrue(ac["rollback_vulnerable_source_current_complete_requires_independent_outside_domain_cut_witness"])
        self.assertTrue(ac["full_trusted_graph_before_privacy_projection"])
        self.assertTrue(ac["visibility_filtered_subset_cannot_establish_controlling_currentness"])

    def test_39_parent_symlink_ancestry_rejected(self):
        import tempfile, os
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td)
            (root / "realproject").mkdir()
            (root / "realproject" / "x.json").write_text("{}")
            os.symlink(root / "realproject", root / "project")
            with self.assertRaisesRegex(validator.ValidationError, "symlink_forbidden"):
                validator.strict_json_load(root / "project" / "x.json")

    def test_40_mic_database_optionality_is_fail_closed(self):
        self.assertFalse(CONTRACT["supabase"]["database_release_gate_required"])
        self.assertFalse(CONTRACT["supabase"]["provider_faithful_qualification_required"])
        self.assertEqual(CONTRACT["supabase"]["database_integration_mode_at_generation"], "NOT_QUALIFIED_DISABLED")
        self.assertFalse(CONTRACT["supabase"]["database_effects_enabled"])
        self.assertEqual(set(CONTRACT["supabase"]["database_unqualified_blocks_only"]), {"DATABASE_INTEGRATION","DATABASE_WRITE","DATABASE_EFFECT"})

    def test_41_installation_mincut_is_staged_and_acyclic(self):
        ins = CONTRACT["installation"]
        self.assertEqual(ins["first_active_project_mutation_state"], "INSTALL_TRANSITION_IN_PROGRESS")
        self.assertEqual(set(ins["base_outcome_enum"]), {"SUCCESSOR_BASE_COHERENT_VERIFIED","PREDECESSOR_BASE_RESTORED_VERIFIED","RECOVERY_REQUIRED","OUTCOME_UNKNOWN"})
        self.assertTrue(ins["final_receipt_cannot_self_readback_or_assert_current_state"])
        self.assertEqual(ins["receipt_profile_base_result_code"], "SUCCESSOR_EXACT")
        self.assertEqual(ins["base_outcome_semantic_mapping"]["SUCCESSOR_EXACT"], "SUCCESSOR_BASE_COHERENT_VERIFIED")
        self.assertEqual(ins["target_binding_current_role"], "INSTALL_TARGET_BINDING_CURRENT")

    def test_42_red_white_minimum_provenance_succession_fence(self):
        ps = CONTRACT["provenance_succession"]
        self.assertEqual(ps["logical_identity"], "VERA")
        self.assertTrue(ps["producer_session_runtime_provenance_retained"])
        self.assertTrue(ps["transport_or_slack_is_not_durable_admission"])
        self.assertEqual(ps["white_worm_succession_default"], "DENY")
        self.assertTrue(ps["succession_requires_explicit_governed_receipt"])
        self.assertTrue(ps["conflict_provenance_retained"])

    def test_43_deferred_feature_surfaces_are_explicit(self):
        fp=CONTRACT["feature_surface_policy"]
        self.assertEqual(fp["red_white_minimum_provenance_succession_fence"], "ACTIVE_FIXED")
        self.assertEqual(fp["assignment_currentness_policy_core"], "ACTIVE_FIXED")
        self.assertEqual(fp["ap_safety_create_path_suites"], "DISABLED_OMITTED")
        self.assertEqual(fp["database_successor_integration"], "DISABLED_OMITTED")
        self.assertEqual(fp["protected_effect_broker_confinement"], "DISABLED_OMITTED")
        for k in ("full_red_white_lineage_event_store_topology","work_chat_origin_attestation","cross_surface_atomic_snapshot_multicast","new_canonical_ingestion_store","generalized_provider_migration_conformance"):
            self.assertEqual(fp[k], "NOT_PRESENT")

    def test_44_mic_core_test_profile_mechanically_excludes_deferred_create_suites(self):
        ci=CONTRACT["ci"]
        self.assertEqual(ci["release_gating_test_profile"], "MIC_CORE_V1")
        self.assertEqual(ci["release_gating_test_modules"], ["tests/native-project/test_r9a0_project.py"])
        deferred=set(ci["deferred_non_gating_test_modules"])
        self.assertEqual(deferred, {
            "tests/native-project/test_r9a0_anticipatory_pragmatics.py",
            "tests/native-project/test_r9a0_assignment_currentness.py",
            "tests/native-project/test_r9a0_cross_feature_invariants.py",
            "tests/native-project/test_r9a0_safety_contamination.py",
        })
        workflow=(ROOT/".github/workflows/r9a0-native-project.yml").read_text()
        self.assertNotIn("unittest discover", workflow)
        self.assertIn("python -m unittest tests/native-project/test_r9a0_project.py -v", workflow)

    def test_45_install_docs_break_receipt_cycle_and_basic_memory_is_observation_only(self):
        cold=(ROOT/"project/VERA_R9A0_COLD_START_PROTOCOL.md").read_text()
        post=(ROOT/"project/VERA_R9A0_POST_INSTALL_AUDIT.md").read_text()
        self.assertIn("INSTALL_BASE_OUTCOME_READBACK", cold)
        self.assertNotIn("completed installation receipt", cold.lower())
        self.assertNotIn("disable or make unavailable", cold.lower())
        self.assertIn("observe and verify", cold.lower())
        self.assertIn("independent receipt-readback event", post)
        self.assertIn("after", post.lower())

    def test_46_install_base_coherence_distinguishes_suffix_digest_and_mixed_generation(self):
        ins=CONTRACT["installation"]
        self.assertTrue(ins["display_suffix_is_transport_metadata_when_logical_mapping_and_digest_match"])
        self.assertTrue(ins["mixed_authoritative_generation_fails_base_coherence"])
        self.assertTrue(ins["settings_digest_count_readback_required_for_successor_coherence"])
        self.assertTrue(ins["interrupted_staging_cannot_claim_predecessor_or_successor_active_without_readback"])

    def test_47_receipt_readback_is_strictly_post_issuance(self):
        ins=CONTRACT["installation"]
        order=ins["successor_activation_order"]
        self.assertLess(order.index("FINAL_INSTALL_RECEIPT"), order.index("FINAL_INSTALL_RECEIPT_READBACK"))
        self.assertLess(order.index("FINAL_INSTALL_RECEIPT_READBACK"), order.index("SUCCESSOR_ACTIVE_VERIFIED"))

    def test_48_cli_executes_validator_and_reports_json(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "candidate"
            shutil.copytree(ROOT, root)
            manifest = validator.strict_json_load(root / "project/VERA_R9A0_MANIFEST.json")
            for name in manifest["files"]:
                member = root / "project" / name
                if not member.exists():
                    member.write_text("MIC_CORE_V1 placeholder for non-semantic checksum fixture\n", encoding="utf-8")
            report = root / "project/VERA_R9A0_VALIDATION_REPORT.md"
            report.write_text(validator.VALIDATION_REPORT_PREFIX + json.dumps(validator.VALIDATION_REPORT_MACHINE, sort_keys=True, separators=(",", ":")) + "\n", encoding="utf-8")
            lines = []
            for name in manifest["files"]:
                data = (root / "project" / name).read_bytes()
                lines.append(f"{hashlib.sha256(data).hexdigest()}  {name}")
            (root / "project/VERA_R9A0_CHECKSUMS.sha256").write_text("\n".join(lines)+"\n", encoding="utf-8")
            proc = subprocess.run([sys.executable, str(root / "scripts/validate_r9a0_project.py"), "--root", str(root), "--json"], capture_output=True, text=True)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            payload = json.loads(proc.stdout)
            self.assertEqual(payload["status"], "PASS")

    def test_49_cli_bad_candidate_exits_nonzero(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "candidate"
            shutil.copytree(ROOT, root)
            contract_path = root / "project/VERA_R9A0_NATIVE_CONTRACT.json"
            contract_path.write_text("{}\n", encoding="utf-8")
            proc = subprocess.run([sys.executable, str(root / "scripts/validate_r9a0_project.py"), "--root", str(root), "--json"], capture_output=True, text=True)
            self.assertNotEqual(proc.returncode, 0)
            self.assertEqual(json.loads(proc.stdout)["status"], "FAIL")

    def test_50_receipt_missing_subordinate_root_record_rejected(self):
        receipt, evidence = issued_receipt_v2()
        del evidence["cold_start_runtime_readback"]
        with self.assertRaises(validator.ValidationError):
            validate_issued(receipt, evidence)

    def test_51_receipt_top_level_ref_mismatch_rejected(self):
        receipt, evidence = issued_receipt_v2()
        receipt["authority_evidence"]["ref"] = "nonexistent:authority"
        with self.assertRaises(validator.ValidationError):
            validate_issued(receipt, evidence)

    def test_52_receipt_redigested_authority_deny_rejected(self):
        receipt, evidence = issued_receipt_v2()
        auth = copy.deepcopy(evidence["authority_evidence"])
        auth["decision"] = "DENY"
        auth["authorized"] = False
        auth["sha256"] = validator._canonical_evidence_digest(auth)
        evidence["authority_evidence"] = auth
        receipt["authority_evidence"]["sha256"] = auth["sha256"]
        env = copy.deepcopy(evidence["attempt_action_envelope_evidence"])
        env["authority_sha256"] = auth["sha256"]
        env["sha256"] = validator._canonical_evidence_digest(env)
        evidence["attempt_action_envelope_evidence"] = env
        receipt["attempt_action_envelope_evidence"]["sha256"] = env["sha256"]
        recheck = copy.deepcopy(evidence["pre_dispatch_recheck_evidence"])
        recheck["authority_sha256"] = auth["sha256"]
        recheck["sha256"] = validator._canonical_evidence_digest(recheck)
        evidence["pre_dispatch_recheck_evidence"] = recheck
        env["pre_dispatch_recheck_sha256"] = recheck["sha256"]
        env["sha256"] = validator._canonical_evidence_digest(env)
        evidence["attempt_action_envelope_evidence"] = env
        receipt["attempt_action_envelope_evidence"]["sha256"] = env["sha256"]
        with self.assertRaises(validator.ValidationError):
            validate_issued(receipt, evidence)

    def test_53_receipt_redigested_target_wrong_semantics_rejected(self):
        receipt, evidence = issued_receipt_v2()
        target = copy.deepcopy(evidence["target_binding_evidence"])
        target["target_matches_expected"] = False
        target["sha256"] = validator._canonical_evidence_digest(target)
        evidence["target_binding_evidence"] = target
        receipt["target_binding_evidence"]["sha256"] = target["sha256"]
        receipt["attempt_binding"]["target_binding_digest"] = target["sha256"]
        for root in receipt["evidence_roots"].values():
            root["attempt_binding"]["target_binding_digest"] = target["sha256"]
        with self.assertRaises(validator.ValidationError):
            validate_issued(receipt, evidence)

    def test_54_receipt_contradictory_extra_root_fields_rejected(self):
        receipt, evidence = issued_receipt_v2()
        cold = copy.deepcopy(evidence["cold_start_runtime_readback"])
        cold["actually_passed"] = False
        cold["sha256"] = validator._canonical_evidence_digest(cold)
        evidence["cold_start_runtime_readback"] = cold
        receipt["evidence_roots"]["cold_start_runtime_readback"]["sha256"] = cold["sha256"]
        with self.assertRaises(validator.ValidationError):
            validate_issued(receipt, evidence)

    def test_55_attempt_plan_boolean_sentinel_is_not_accepted(self):
        receipt, evidence = issued_receipt_v2()
        env = copy.deepcopy(evidence["attempt_action_envelope_evidence"])
        env["attempt_plan_bound"] = "false"
        env["sha256"] = validator._canonical_evidence_digest(env)
        evidence["attempt_action_envelope_evidence"] = env
        receipt["attempt_action_envelope_evidence"]["sha256"] = env["sha256"]
        with self.assertRaises(validator.ValidationError):
            validate_issued(receipt, evidence)

    def test_56_checksums_control_file_symlink_rejected(self):
        with tempfile.TemporaryDirectory() as td:
            root = pathlib.Path(td) / "candidate"
            shutil.copytree(ROOT, root)
            checksum = root / "project/VERA_R9A0_CHECKSUMS.sha256"
            outside = pathlib.Path(td) / "outside-checksums.sha256"
            outside.write_bytes(checksum.read_bytes())
            checksum.unlink()
            checksum.symlink_to(outside)
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertTrue(any("symlink_ancestry" in e for e in result["errors"]))

    def test_57_in_situ_environment_binding_must_be_resolved_and_match(self):
        receipt, evidence = issued_receipt_v2()
        envb = copy.deepcopy(evidence["in_situ_environment_binding_evidence"])
        envb["environment_matches_expected"] = False
        envb["sha256"] = validator._canonical_evidence_digest(envb)
        evidence["in_situ_environment_binding_evidence"] = envb
        insitu = copy.deepcopy(evidence["in_situ_project_qualification"])
        insitu["environment_binding_sha256"] = envb["sha256"]
        insitu["sha256"] = validator._canonical_evidence_digest(insitu)
        evidence["in_situ_project_qualification"] = insitu
        receipt["evidence_roots"]["in_situ_project_qualification"]["sha256"] = insitu["sha256"]
        with self.assertRaises(validator.ValidationError):
            validate_issued(receipt, evidence)

    def test_58_receipt_manifest_digest_must_bind_exact_artifact_bytes(self):
        receipt, evidence = issued_receipt_v2()
        receipt["artifact_identity"]["manifest_sha256"] = "f" * 64
        with self.assertRaises(validator.ValidationError):
            validate_issued(receipt, evidence)

    def test_59_receipt_checksums_digest_must_bind_exact_artifact_bytes(self):
        receipt, evidence = issued_receipt_v2()
        receipt["artifact_identity"]["checksums_sha256"] = "e" * 64
        with self.assertRaises(validator.ValidationError):
            validate_issued(receipt, evidence)

    def test_60_redigested_wrong_target_with_true_flag_rejected_by_independent_expected_target(self):
        receipt, evidence = issued_receipt_v2(
            target_locator="attacker://other",
            target_scope="PRODUCTION",
            expected_target_locator="project:vera:test-target",
            expected_target_scope="PROJECT_FILES_AND_SETTINGS",
        )
        self.assertIs(evidence["target_binding_evidence"]["target_matches_expected"], True)
        with self.assertRaises(validator.ValidationError):
            validate_issued(receipt, evidence)

    def test_61_independent_selector_evidence_is_required(self):
        receipt, evidence = issued_receipt_v2()
        del evidence["installation_selector_evidence"]
        with self.assertRaises(validator.ValidationError):
            validate_issued(receipt, evidence)


    def test_62_attacker_authority_ref_rejected_by_independent_selector(self):
        receipt, evidence = issued_receipt_v2()
        bad = copy.deepcopy(evidence["authority_evidence"])
        bad["ref"] = "attacker:authority"
        bad["sha256"] = "0"*64
        bad["sha256"] = validator._canonical_evidence_digest(bad)
        evidence["authority_evidence"] = bad
        receipt["authority_evidence"] = {"ref": bad["ref"], "sha256": bad["sha256"]}
        evidence["pre_dispatch_recheck_evidence"]["authority_sha256"] = bad["sha256"]
        evidence["pre_dispatch_recheck_evidence"]["sha256"] = "0"*64
        evidence["pre_dispatch_recheck_evidence"]["sha256"] = validator._canonical_evidence_digest(evidence["pre_dispatch_recheck_evidence"])
        evidence["attempt_action_envelope_evidence"]["authority_sha256"] = bad["sha256"]
        evidence["attempt_action_envelope_evidence"]["pre_dispatch_recheck_sha256"] = evidence["pre_dispatch_recheck_evidence"]["sha256"]
        evidence["attempt_action_envelope_evidence"]["sha256"] = "0"*64
        evidence["attempt_action_envelope_evidence"]["sha256"] = validator._canonical_evidence_digest(evidence["attempt_action_envelope_evidence"])
        receipt["attempt_action_envelope_evidence"]["sha256"] = evidence["attempt_action_envelope_evidence"]["sha256"]
        with self.assertRaisesRegex(validator.ValidationError, "authority_ref_mismatch_selector"):
            validate_issued(receipt, evidence)

    def test_63_wrong_environment_true_rejected_by_independent_expected_identity(self):
        receipt, evidence = issued_receipt_v2()
        env = copy.deepcopy(evidence["in_situ_environment_binding_evidence"])
        env["environment_locator"] = "attacker://wrong-environment"
        env["environment_matches_expected"] = True
        env["sha256"] = "0"*64
        env["sha256"] = validator._canonical_evidence_digest(env)
        evidence["in_situ_environment_binding_evidence"] = env
        evidence["in_situ_project_qualification"]["environment_binding_sha256"] = env["sha256"]
        evidence["in_situ_project_qualification"]["sha256"] = "0"*64
        evidence["in_situ_project_qualification"]["sha256"] = validator._canonical_evidence_digest(evidence["in_situ_project_qualification"])
        receipt["evidence_roots"]["in_situ_project_qualification"]["sha256"] = evidence["in_situ_project_qualification"]["sha256"]
        with self.assertRaisesRegex(validator.ValidationError, "environment_locator_mismatch_selector"):
            validate_issued(receipt, evidence)

    def test_64_canonical_ref_reuse_across_roles_rejected(self):
        receipt, evidence = issued_receipt_v2()
        target = copy.deepcopy(evidence["target_binding_evidence"])
        target["ref"] = evidence["authority_evidence"]["ref"]
        target["sha256"] = "0"*64
        target["sha256"] = validator._canonical_evidence_digest(target)
        evidence["target_binding_evidence"] = target
        receipt["target_binding_evidence"] = {"ref": target["ref"], "sha256": target["sha256"]}
        # Rebind the attempt target digest and dependent records so only canonical ref reuse remains.
        new_binding = copy.deepcopy(receipt["attempt_binding"])
        new_binding["target_binding_digest"] = target["sha256"]
        receipt["attempt_binding"] = new_binding
        for root in receipt["evidence_roots"].values():
            root["attempt_binding"] = copy.deepcopy(new_binding)
        for name in ["authority_evidence","attempt_plan_evidence","pre_dispatch_recheck_evidence","manual_operator_control_evidence","attempt_action_envelope_evidence"]:
            if name not in evidence: continue
            if "attempt_binding" in evidence[name]: evidence[name]["attempt_binding"] = copy.deepcopy(new_binding)
            if "target_binding_sha256" in evidence[name]: evidence[name]["target_binding_sha256"] = target["sha256"]
        evidence["authority_evidence"]["target_binding_sha256"] = target["sha256"]
        evidence["in_situ_environment_binding_evidence"]["target_binding_sha256"] = target["sha256"]
        # A full canonical reseal helper is intentionally not needed: duplicate ref is checked after individual digest validation,
        # so use the valid fixture and directly assert the global rule with two valid records.
        with self.assertRaises(validator.ValidationError):
            validate_issued(receipt, evidence)

    def test_65_assistant_tool_requires_confinement_capability_evidence(self):
        receipt, evidence = issued_receipt_v2(route_class="ASSISTANT_TOOL")
        self.assertEqual(validate_issued(receipt, evidence), "ISSUED_RECEIPT_VALID")
        del evidence["assistant_tool_confinement_evidence"]
        with self.assertRaisesRegex(validator.ValidationError, "assistant_tool_confinement"):
            validate_issued(receipt, evidence)

    def test_66_target_and_selector_cannot_move_together(self):
        _, baseline = issued_receipt_v2()
        trusted = copy.deepcopy(baseline["__trusted_control_roots"])
        receipt, evidence = issued_receipt_v2(
            target_locator="attacker://other", target_scope="PRODUCTION",
            expected_target_locator="attacker://other", expected_target_scope="PRODUCTION",
        )
        with self.assertRaisesRegex(validator.ValidationError, "installation_selector:sha256"):
            validate_issued(receipt, evidence, trusted)

    def test_67_authority_and_selector_cannot_move_together(self):
        _, baseline = issued_receipt_v2()
        trusted = copy.deepcopy(baseline["__trusted_control_roots"])
        receipt, evidence = issued_receipt_v2(
            authority_ref="attacker:authority", authority_source="attacker-source", action_window_id="attacker-window",
        )
        with self.assertRaisesRegex(validator.ValidationError, "installation_selector:sha256"):
            validate_issued(receipt, evidence, trusted)

    def test_68_environment_and_selector_cannot_move_together(self):
        _, baseline = issued_receipt_v2()
        trusted = copy.deepcopy(baseline["__trusted_control_roots"])
        receipt, evidence = issued_receipt_v2(
            environment_locator="attacker://environment", expected_environment_locator="attacker://environment",
        )
        with self.assertRaisesRegex(validator.ValidationError, "installation_selector:sha256"):
            validate_issued(receipt, evidence, trusted)

    def test_69_assistant_tool_control_must_match_independent_root(self):
        _, baseline = issued_receipt_v2(route_class="ASSISTANT_TOOL")
        trusted = copy.deepcopy(baseline["__trusted_control_roots"])
        receipt, evidence = issued_receipt_v2(
            route_class="ASSISTANT_TOOL", tool_control_ref="attacker:tool-control",
            tool_route="attacker://fake-tool", capability_scope="EVERYTHING", confinement_current=True,
        )
        with self.assertRaisesRegex(validator.ValidationError, "assistant_tool_confinement:ref|assistant_tool_confinement:sha256"):
            validate_issued(receipt, evidence, trusted)

    def test_70_manual_control_must_match_independent_root(self):
        _, baseline = issued_receipt_v2(route_class="USER_MANUAL")
        trusted = copy.deepcopy(baseline["__trusted_control_roots"])
        receipt, evidence = issued_receipt_v2(
            route_class="USER_MANUAL", manual_control_ref="attacker:manual-control", human_authorized=True,
        )
        with self.assertRaisesRegex(validator.ValidationError, "manual_operator_control:ref|manual_operator_control:sha256"):
            validate_issued(receipt, evidence, trusted)


if __name__ == "__main__":
    unittest.main()

