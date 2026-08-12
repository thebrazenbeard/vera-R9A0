from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
from decimal import Decimal, InvalidOperation
from typing import Any, Callable

RELEASE_ID = "VERA_PROJECT_INTEGRATION_R9A0_20260806_V1"
SCHEMA_PROFILE_ID = "R9A0_SCHEMA_PROFILE_V1"
SCHEMA_ID = "VERA_R9A0_NATIVE_CONTRACT_SCHEMA_V1"
RECEIPT_PROFILE_SHA256 = "e81a47132c1b6067fa3b04cdb7fb5e7cabcb97e4c0f40bc2de313bfc3cf8c056"
RECEIPT_PROFILE_BYTE_COUNT = 4260
RECEIPT_PROFILE_JSON = '{"artifact_identity":{"artifact_composition_root_equals_candidate_digest":true,"issued_shapes":{"artifact_composition_root":"hex64","checksums_sha256":"hex64","manifest_sha256":"hex64"},"keys":["artifact_composition_root","checksums_sha256","manifest_sha256"]},"attempt_binding":{"issued_shapes":{"candidate_digest":"hex64","installation_attempt_id":"opaque_attempt_token","route_class":{"enum":["ASSISTANT_TOOL","USER_MANUAL"]},"target_binding_digest":"hex64","transition_epoch":"opaque_attempt_token"},"keys":["candidate_digest","installation_attempt_id","route_class","target_binding_digest","transition_epoch"],"same_in_all_evidence_roots":true},"const":{"receipt_schema":"VERA_R9A0_INSTALLATION_RECEIPT_V2","release_id":"VERA_PROJECT_INTEGRATION_R9A0_20260806_V1","template_profile":"R9A0_INSTALLATION_RECEIPT_TEMPLATE_V2"},"evidence_role_shape":"reference_object","evidence_roles":{"attempt_action_envelope_evidence":"ATTEMPT_ACTION_ENVELOPE","authority_evidence":"EFFECT_TIME_AUTHORITY","operator_decision_packet_evidence":"OPERATOR_DECISION_PACKET","target_binding_evidence":"EXACT_TARGET_BINDING"},"evidence_roots":{"in_situ_refs_distinct_environment_binding":true,"issued_result_const":{"cold_start_runtime_readback":"PASS","in_situ_project_qualification":"PASS","install_base_outcome_readback":"SUCCESSOR_EXACT","post_install_environment_check":"PASS"},"keys":["cold_start_runtime_readback","in_situ_project_qualification","install_base_outcome_readback","post_install_environment_check"],"root_issued_shapes":{"attempt_binding":"attempt_binding","ref":"nonempty_string","sha256":"hex64"},"root_keys":["attempt_binding","ref","result","sha256"]},"forbidden_top_level_keys":["action_plan_evidence","atomic_file_replacement_verified","atomic_upload_required","authorized_by","basic_memory_connector_unavailable_during_test","checksums_verified","cold_start_readback_passed","database_successor_approved","final_receipt_readback_passed","final_state","google_drive_readback_passed","issued_at","issuer_provenance","limitations","logical_member_count","operation_id","operator_packet_evidence","receipt_sha256","release_admission","security_advisors_clear","status","suffix_drift_absent","suffix_drift_prohibited","supabase_readback_passed","voice_critical_context_native"],"h63_rules":{"envelope_authority_equals_authority_evidence":true,"envelope_binds_exact_ATTEMPT_PLAN":true,"envelope_binds_operator_decision_packet":true,"envelope_binds_same_attempt":true,"envelope_target_equals_target_binding_evidence":true},"issued_mode":{"all_issuance_leaves_nonnull":true,"claim":"ISSUED_RECEIPT_VALID","target_binding_evidence_sha256_equals_target_binding_digest":true},"lifecycle":{"current_state_fields_in_receipt":false,"manual_attempt_token_is_correlation_only":true,"receipt_readback_is_post_receipt":true,"record_time_external":true,"release_admission_body_root":false,"release_eligibility_in_h63_context":true},"meta":{"keys_arrays_are_exact_closed_keysets":true,"reject_unlisted_object_keys":true,"wildcard_star_means_each_named_role_or_root":true},"profile_id":"R9A0_INSTALLATION_RECEIPT_PROFILE_V2","profile_version":2,"reference_object":{"issued_shapes":{"ref":"nonempty_string","sha256":"hex64"},"keys":["ref","sha256"]},"shape_profiles":{"hex64":{"pattern":"^[0-9a-f]{64}$","type":"string"},"nonempty_string":{"min_length":1,"type":"string"},"opaque_attempt_token":{"pattern":"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$","semantics":"EQUALITY_ONLY","type":"string"}},"template_mode":{"claim":"RECEIPT_TEMPLATE_PROFILE_VALID","null":["attempt_binding.*","operator_decision_packet_evidence.*","attempt_action_envelope_evidence.*","authority_evidence.*","target_binding_evidence.*","artifact_identity.artifact_composition_root","artifact_identity.manifest_sha256","artifact_identity.checksums_sha256","evidence_roots.*.attempt_binding.*","evidence_roots.*.ref","evidence_roots.*.sha256","evidence_roots.*.result"],"reject_prepopulated_issuance_leaves":true},"top_level_keys":["artifact_identity","attempt_action_envelope_evidence","attempt_binding","authority_evidence","evidence_roots","operator_decision_packet_evidence","receipt_schema","release_id","target_binding_evidence","template_profile"],"transport":"STRICT_JSON_SUBSET_AT_EXISTING_YAML_PATH"}'
R9A0_NATIVE_LOGICAL_SET_V1 = ['VERA_R9A0_PROJECT_INSTRUCTIONS.md', 'VERA_R9A0_LAWS.md', 'VERA_R9A0_GOVERNANCE.md', 'VERA_R9A0_RUNTIME.md', 'VERA_R9A0_STATE.md', 'VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt', 'VERA_R9A0_NATIVE_CONTRACT.json', 'VERA_R9A0_RETRIEVAL.md', 'VERA_R9A0_VOICE.md', 'VERA_R9A0_RECOVERY.md', 'VERA_R9A0_MANIFEST.json', 'VERA_R9A0_PACKAGE.json', 'VERA_R9A0_VALIDATION_REPORT.md', 'VERA_R9A0_INSTALLATION_RECEIPT_TEMPLATE.yaml', 'VERA_R9A0_COLD_START_PROTOCOL.md', 'VERA_R9A0_POST_INSTALL_AUDIT.md']
NATIVE_ACCEPTED_MAX_CHARACTERS = 7900
NATIVE_OUTER_HARD_MAX_CHARACTERS = 8000

JSON_NUMBER_MAX_TOKEN_LENGTH = 64
JSON_NUMBER_MAX_DIGITS = 32
JSON_NUMBER_MAX_ABS_EXPONENT = 128

ALLOWED_SCHEMA_PATTERNS = {
    r"^[0-9a-f]{64}$",
    r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$",
}

VALIDATION_REPORT_PREFIX = "R9A0_VALIDATION_REPORT_MACHINE="
VALIDATION_REPORT_MACHINE = {
    "cannot_satisfy": [
        "BUILT_AND_VALIDATED",
        "DATABASE_RELEASE_GATE",
        "INSTALLED_VERIFIED_CURRENT",
        "RELEASE_ELIGIBLE",
    ],
    "classification": "GENERATION_PROVENANCE",
    "narrative_role": "HUMAN_PROVENANCE_NONCONTROLLING",
    "release_id": RELEASE_ID,
}

PACKAGE_V2 = {'release_id': 'VERA_PROJECT_INTEGRATION_R9A0_20260806_V1', 'manifest_path': 'VERA_R9A0_MANIFEST.json', 'checksums_path': 'VERA_R9A0_CHECKSUMS.sha256', 'logical_generation_completeness_required': True, 'project_settings_replacement_required': True, 'mixed_authoritative_release_prohibited': True, 'installation_requires_separate_authority': True, 'independent_install_base_outcome_readback_required': True, 'cold_start_required': True, 'post_install_audit_required': True, 'database_execution_reuse_requires_versioned_dependency_equivalence': True, 'database_release_gate_policy_version': 'R9A0_DATABASE_RELEASE_GATE_POLICY_V1', 'database_integration_mode_at_generation': 'NOT_QUALIFIED_DISABLED', 'database_integration_required_for_native_install': False, 'database_effects_enabled': False, 'feature_surface_policy': {'native_startup_trust': 'ACTIVE_FIXED', 'identity_recollection_minimum': 'ACTIVE_FIXED', 'knowledge_continuity_provider_neutral_boundary': 'ACTIVE_FIXED', 'assignment_currentness_policy_core': 'ACTIVE_FIXED', 'ap_safety_create_path_suites': 'DISABLED_OMITTED', 'red_white_minimum_provenance_succession_fence': 'ACTIVE_FIXED', 'full_red_white_lineage_event_store_topology': 'NOT_PRESENT', 'work_chat_origin_attestation': 'NOT_PRESENT', 'cross_surface_atomic_snapshot_multicast': 'NOT_PRESENT', 'new_canonical_ingestion_store': 'NOT_PRESENT', 'database_successor_integration': 'DISABLED_OMITTED', 'generalized_provider_migration_conformance': 'NOT_PRESENT', 'protected_effect_broker_confinement': 'DISABLED_OMITTED'}}
MANIFEST_RELEASE_KIND = "NATIVE_CHATGPT_PROJECT_PACKAGE"

class ValidationError(ValueError):
    pass

def reject_symlink_ancestry(root: pathlib.Path, path: pathlib.Path) -> None:
    root_abs = root.absolute()
    path_abs = path.absolute()
    try:
        rel = path_abs.relative_to(root_abs)
    except ValueError as exc:
        raise ValidationError("path:outside_root") from exc
    cur = root_abs
    if cur.is_symlink():
        raise ValidationError("path:symlink_ancestry")
    for part in rel.parts:
        cur = cur / part
        if cur.is_symlink():
            raise ValidationError("path:symlink_ancestry")


def _reject_constant(token: str) -> None:
    raise ValidationError(f"non_finite_json_number:{token}")

_NUMBER_RE = re.compile(r"-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?\Z")

def _bounded_decimal(token: str) -> Decimal:
    if len(token) > JSON_NUMBER_MAX_TOKEN_LENGTH:
        raise ValidationError("json_number_profile_unsupported:token_length")
    if not _NUMBER_RE.fullmatch(token):
        raise ValidationError("json_number_profile_unsupported:lexical")
    mantissa, sep, exp = re.split(r"[eE]", token, maxsplit=1)[0], None, None
    if "e" in token.lower():
        mantissa, exp = re.split(r"[eE]", token, maxsplit=1)
        exp_digits = exp.lstrip("+-")
        if len(exp_digits) > 3:
            raise ValidationError("json_number_profile_unsupported:exponent")
        exponent = int(exp)
        if abs(exponent) > JSON_NUMBER_MAX_ABS_EXPONENT:
            raise ValidationError("json_number_profile_unsupported:exponent")
    digits = sum(ch.isdigit() for ch in mantissa)
    if digits > JSON_NUMBER_MAX_DIGITS:
        raise ValidationError("json_number_profile_unsupported:digits")
    try:
        value = Decimal(token)
    except InvalidOperation as exc:
        raise ValidationError("json_number_profile_unsupported:decimal") from exc
    if not value.is_finite():
        raise ValidationError("non_finite_json_number")
    return value

def _object_pairs_no_dupes(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValidationError(f"duplicate_json_key:{key}")
        out[key] = value
    return out

def strict_json_loads(text: str) -> Any:
    try:
        return json.loads(
            text,
            parse_int=_bounded_decimal,
            parse_float=_bounded_decimal,
            parse_constant=_reject_constant,
            object_pairs_hook=_object_pairs_no_dupes,
        )
    except ValidationError:
        raise
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        raise ValidationError(f"json_parse:{exc}") from exc

def strict_json_load(path: pathlib.Path) -> Any:
    if path.is_symlink() or any(parent.is_symlink() for parent in path.parents):
        raise ValidationError(f"symlink_forbidden:{path.name}")
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValidationError(f"utf8:{path.name}") from exc
    return strict_json_loads(text)

def _is_json_number(value: Any) -> bool:
    return isinstance(value, Decimal) and not isinstance(value, bool)

def _is_json_integer(value: Any) -> bool:
    return _is_json_number(value) and value == value.to_integral_value()

def json_equal(a: Any, b: Any) -> bool:
    if a is None or b is None:
        return a is None and b is None
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a is b
    if _is_json_number(a) or _is_json_number(b):
        return _is_json_number(a) and _is_json_number(b) and a == b
    if isinstance(a, str) or isinstance(b, str):
        return isinstance(a, str) and isinstance(b, str) and a == b
    if isinstance(a, list) or isinstance(b, list):
        return isinstance(a, list) and isinstance(b, list) and len(a) == len(b) and all(
            json_equal(x, y) for x, y in zip(a, b)
        )
    if isinstance(a, dict) or isinstance(b, dict):
        return (
            isinstance(a, dict)
            and isinstance(b, dict)
            and set(a) == set(b)
            and all(json_equal(a[k], b[k]) for k in a)
        )
    return False

def _expect_json_type(value: Any, type_name: str) -> bool:
    if type_name == "null":
        return value is None
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "string":
        return isinstance(value, str)
    if type_name == "array":
        return isinstance(value, list)
    if type_name == "object":
        return isinstance(value, dict)
    if type_name == "number":
        return _is_json_number(value)
    if type_name == "integer":
        return _is_json_integer(value)
    raise ValidationError(f"schema_profile_unknown_type:{type_name}")

ROOT_SCHEMA_KEYS = {
    "schema_profile", "schema_id", "title", "type", "required", "properties", "additionalProperties"
}
NODE_SCHEMA_KEYS = {
    "type", "required", "properties", "additionalProperties", "const", "enum",
    "pattern", "items", "uniqueItems", "minLength", "maxLength"
}
ALLOWED_TYPES = {"null","boolean","string","array","object","number","integer"}

def validate_schema_profile(schema: Any) -> None:
    if not isinstance(schema, dict):
        raise ValidationError("schema_profile:root_not_object")
    extra = set(schema) - ROOT_SCHEMA_KEYS
    if extra:
        raise ValidationError("schema_profile:unknown_root_keyword:" + ",".join(sorted(extra)))
    if schema.get("schema_profile") != SCHEMA_PROFILE_ID:
        raise ValidationError("schema_profile:unsupported")
    if schema.get("schema_id") != SCHEMA_ID:
        raise ValidationError("schema_profile:schema_id")
    if not isinstance(schema.get("title"), str) or not schema["title"]:
        raise ValidationError("schema_profile:title")
    _validate_schema_node(schema, root=True)

def _validate_schema_node(node: Any, *, root: bool = False) -> None:
    if not isinstance(node, dict):
        raise ValidationError("schema_profile:node_not_object")
    allowed = ROOT_SCHEMA_KEYS if root else NODE_SCHEMA_KEYS
    extra = set(node) - allowed
    if extra:
        raise ValidationError("schema_profile:unknown_keyword:" + ",".join(sorted(extra)))
    if "type" not in node or not isinstance(node["type"], str) or node["type"] not in ALLOWED_TYPES:
        raise ValidationError("schema_profile:type")
    typ = node["type"]

    if "required" in node:
        required = node["required"]
        if not isinstance(required, list) or not required or any(not isinstance(x, str) or not x for x in required):
            raise ValidationError("schema_profile:required_shape")
        if len(set(required)) != len(required):
            raise ValidationError("schema_profile:required_duplicate")
    if "properties" in node:
        props = node["properties"]
        if not isinstance(props, dict) or any(not isinstance(k, str) or not k for k in props):
            raise ValidationError("schema_profile:properties_shape")
        for child in props.values():
            _validate_schema_node(child)
    if typ == "object":
        if set(node.get("required", [])) != set(node.get("properties", {})):
            raise ValidationError("schema_profile:closed_object_required_mismatch")
        if node.get("additionalProperties") is not False:
            raise ValidationError("schema_profile:closed_object_additional_properties")
    else:
        if "required" in node or "properties" in node or "additionalProperties" in node:
            raise ValidationError("schema_profile:object_keywords_wrong_type")

    if "const" in node:
        _validate_json_value_profile(node["const"])
    if "enum" in node:
        enum = node["enum"]
        if not isinstance(enum, list) or not enum:
            raise ValidationError("schema_profile:enum_shape")
        for item in enum:
            _validate_json_value_profile(item)
        for i, item in enumerate(enum):
            if any(json_equal(item, prior) for prior in enum[:i]):
                raise ValidationError("schema_profile:enum_duplicate")
    if "pattern" in node:
        if not isinstance(node["pattern"], str) or node["pattern"] not in ALLOWED_SCHEMA_PATTERNS:
            raise ValidationError("schema_profile:pattern_unsupported")
        if typ != "string":
            raise ValidationError("schema_profile:pattern_wrong_type")
    if "items" in node:
        if typ != "array":
            raise ValidationError("schema_profile:items_wrong_type")
        _validate_schema_node(node["items"])
    if "uniqueItems" in node:
        if typ != "array" or not isinstance(node["uniqueItems"], bool):
            raise ValidationError("schema_profile:uniqueItems_shape")
    for key in ("minLength","maxLength"):
        if key in node:
            val = node[key]
            if typ != "string" or not _is_json_integer(val) or val < 0:
                raise ValidationError(f"schema_profile:{key}_shape")
    if "minLength" in node and "maxLength" in node and node["minLength"] > node["maxLength"]:
        raise ValidationError("schema_profile:length_order")

def _validate_json_value_profile(value: Any) -> None:
    if value is None or isinstance(value, (bool, str, Decimal)):
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value_profile(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationError("schema_profile:nonstring_object_key")
            _validate_json_value_profile(item)
        return
    raise ValidationError("schema_profile:unsupported_json_runtime_type")

def validate_instance(instance: Any, schema: dict[str, Any], path: str = "$") -> None:
    typ = schema["type"]
    if not _expect_json_type(instance, typ):
        raise ValidationError(f"schema_instance:type:{path}:{typ}")
    if "const" in schema and not json_equal(instance, schema["const"]):
        raise ValidationError(f"schema_instance:const:{path}")
    if "enum" in schema and not any(json_equal(instance, item) for item in schema["enum"]):
        raise ValidationError(f"schema_instance:enum:{path}")
    if isinstance(instance, str):
        if "pattern" in schema and re.fullmatch(schema["pattern"], instance) is None:
            raise ValidationError(f"schema_instance:pattern:{path}")
        if "minLength" in schema and len(instance) < int(schema["minLength"]):
            raise ValidationError(f"schema_instance:minLength:{path}")
        if "maxLength" in schema and len(instance) > int(schema["maxLength"]):
            raise ValidationError(f"schema_instance:maxLength:{path}")
    if isinstance(instance, dict):
        props = schema.get("properties", {})
        missing = [k for k in schema.get("required", []) if k not in instance]
        if missing:
            raise ValidationError(f"schema_instance:missing:{path}:{','.join(missing)}")
        extra = set(instance) - set(props)
        if extra and schema.get("additionalProperties") is False:
            raise ValidationError(f"schema_instance:extra:{path}:{','.join(sorted(extra))}")
        for key, child_schema in props.items():
            if key in instance:
                validate_instance(instance[key], child_schema, path + "." + key)
    if isinstance(instance, list):
        if schema.get("uniqueItems"):
            for i, item in enumerate(instance):
                if any(json_equal(item, prior) for prior in instance[:i]):
                    raise ValidationError(f"schema_instance:uniqueItems:{path}")
        if "items" in schema:
            for i, item in enumerate(instance):
                validate_instance(item, schema["items"], f"{path}[{i}]")

def _standard_json(value: Any) -> Any:
    """Convert Decimal-backed strict JSON values to ordinary JSON-compatible values for exact stable comparisons."""
    if isinstance(value, Decimal):
        if value == value.to_integral_value():
            return int(value)
        return str(value.normalize())
    if isinstance(value, list):
        return [_standard_json(x) for x in value]
    if isinstance(value, dict):
        return {k: _standard_json(v) for k, v in value.items()}
    return value

def validate_contract(contract: Any, schema: Any) -> None:
    validate_schema_profile(schema)
    validate_instance(contract, schema)
    if not isinstance(contract, dict):
        raise ValidationError("contract:not_object")
    native = contract["native_instructions"]
    if int(native["accepted_max_characters"]) != NATIVE_ACCEPTED_MAX_CHARACTERS:
        raise ValidationError("contract:native_accepted_limit")
    if int(native["outer_hard_max_characters"]) != NATIVE_OUTER_HARD_MAX_CHARACTERS:
        raise ValidationError("contract:native_outer_limit")
    if contract["installation"]["receipt_profile_sha256"] != RECEIPT_PROFILE_SHA256:
        raise ValidationError("contract:receipt_profile_sha")
    if contract["installation"]["receipt_profile_id"] != "R9A0_INSTALLATION_RECEIPT_PROFILE_V2":
        raise ValidationError("contract:receipt_profile_id")
    if contract["assignment_currentness"]["universal_effect_eligible"] is not False:
        raise ValidationError("contract:universal_effect_eligible")
    if contract["supabase"]["production_construction_target_prohibited"] is not True:
        raise ValidationError("contract:production_construction_target_policy")
    kc = contract["knowledge_continuity"]
    if kc["current_provider_binding_role"] != "KNOWLEDGE_CONTINUITY_PROVIDER_BINDING_CURRENT":
        raise ValidationError("contract:knowledge_provider_binding_role")
    if contract["identity_continuity"]["project_identity"] != "VERA":
        raise ValidationError("contract:project_identity")

def validate_native_instructions(text: str) -> None:
    count = len(text)
    if count > NATIVE_OUTER_HARD_MAX_CHARACTERS:
        raise ValidationError("native:outer_platform_limit")
    if count > NATIVE_ACCEPTED_MAX_CHARACTERS:
        raise ValidationError("native:release_acceptance_limit")

def validate_manifest(manifest: Any) -> None:
    if not isinstance(manifest, dict):
        raise ValidationError("manifest:not_object")
    expected_keys = {
        "release_id","release_kind","files","unique_file_count","checksums_path","native_settings_path"
    }
    if set(manifest) != expected_keys:
        raise ValidationError("manifest:closed_shape")
    if manifest["release_id"] != RELEASE_ID:
        raise ValidationError("manifest:release_id")
    if manifest["release_kind"] != MANIFEST_RELEASE_KIND:
        raise ValidationError("manifest:release_kind")
    if manifest["files"] != R9A0_NATIVE_LOGICAL_SET_V1:
        raise ValidationError("manifest:logical_set")
    if manifest["unique_file_count"] != len(R9A0_NATIVE_LOGICAL_SET_V1):
        raise ValidationError("manifest:derived_count")
    if manifest["checksums_path"] != "VERA_R9A0_CHECKSUMS.sha256":
        raise ValidationError("manifest:checksums_path")
    if manifest["native_settings_path"] != "VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt":
        raise ValidationError("manifest:native_settings_path")

def validate_package(package: Any) -> None:
    if _standard_json(package) != PACKAGE_V2:
        raise ValidationError("package:closed_semantic_shape")

def parse_checksums(text: str) -> dict[str,str]:
    out: dict[str,str] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line:
            continue
        m = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9_.-]+)", line)
        if not m:
            raise ValidationError(f"checksums:malformed:{lineno}")
        digest, name = m.groups()
        if name in out:
            raise ValidationError(f"checksums:duplicate:{name}")
        out[name] = digest
    return out

def validate_checksums(root: pathlib.Path, manifest: dict[str,Any], checksums_text: str) -> None:
    checks = parse_checksums(checksums_text)
    if list(checks) != R9A0_NATIVE_LOGICAL_SET_V1:
        raise ValidationError("checksums:logical_set")
    for name in R9A0_NATIVE_LOGICAL_SET_V1:
        path = root / "project" / name
        if path.is_symlink():
            raise ValidationError(f"manifest:symlink_forbidden:{name}")
        if not path.is_file():
            raise ValidationError(f"manifest:missing:{name}")
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        if actual != checks[name]:
            raise ValidationError(f"checksums:mismatch:{name}")

def _load_receipt_profile() -> dict[str,Any]:
    raw = RECEIPT_PROFILE_JSON.encode("utf-8")
    if len(raw) != RECEIPT_PROFILE_BYTE_COUNT:
        raise ValidationError("receipt_profile:byte_count")
    if hashlib.sha256(raw).hexdigest() != RECEIPT_PROFILE_SHA256:
        raise ValidationError("receipt_profile:sha256")
    value = strict_json_loads(RECEIPT_PROFILE_JSON)
    if not isinstance(value, dict):
        raise ValidationError("receipt_profile:not_object")
    return value

RECEIPT_PROFILE = _load_receipt_profile()

def _exact_keys(obj: Any, keys: list[str], label: str) -> dict[str,Any]:
    if not isinstance(obj, dict):
        raise ValidationError(f"{label}:not_object")
    if set(obj) != set(keys):
        raise ValidationError(f"{label}:closed_keys")
    return obj

def _valid_hex64(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value) is not None

def _valid_attempt_token(value: Any) -> bool:
    return isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}", value) is not None

def _attempt_binding_template() -> dict[str,None]:
    return {
        "candidate_digest": None,
        "installation_attempt_id": None,
        "route_class": None,
        "target_binding_digest": None,
        "transition_epoch": None,
    }

def validate_receipt_template(template: Any) -> str:
    p = RECEIPT_PROFILE
    top = _exact_keys(template, p["top_level_keys"], "receipt_template")
    for key, expected in p["const"].items():
        if top.get(key) != expected:
            raise ValidationError(f"receipt_template:const:{key}")
    binding = _exact_keys(top["attempt_binding"], p["attempt_binding"]["keys"], "receipt_template:attempt_binding")
    if any(v is not None for v in binding.values()):
        raise ValidationError("RECEIPT_TEMPLATE_PREPOPULATED:attempt_binding")
    for role in p["evidence_roles"]:
        ref_obj = _exact_keys(top[role], p["reference_object"]["keys"], f"receipt_template:{role}")
        if any(v is not None for v in ref_obj.values()):
            raise ValidationError(f"RECEIPT_TEMPLATE_PREPOPULATED:{role}")
    art = _exact_keys(top["artifact_identity"], p["artifact_identity"]["keys"], "receipt_template:artifact_identity")
    if any(v is not None for v in art.values()):
        raise ValidationError("RECEIPT_TEMPLATE_PREPOPULATED:artifact_identity")
    roots = _exact_keys(top["evidence_roots"], p["evidence_roots"]["keys"], "receipt_template:evidence_roots")
    for role in p["evidence_roots"]["keys"]:
        root = _exact_keys(roots[role], p["evidence_roots"]["root_keys"], f"receipt_template:evidence_roots.{role}")
        rb = _exact_keys(root["attempt_binding"], p["attempt_binding"]["keys"], f"receipt_template:root_binding.{role}")
        if any(v is not None for v in rb.values()) or root["ref"] is not None or root["sha256"] is not None or root["result"] is not None:
            raise ValidationError(f"RECEIPT_TEMPLATE_PREPOPULATED:evidence_root:{role}")
    for forbidden in p["forbidden_top_level_keys"]:
        if forbidden in top:
            raise ValidationError(f"receipt_template:forbidden:{forbidden}")
    return p["template_mode"]["claim"]

def _validate_reference_object(obj: Any, label: str) -> dict[str,Any]:
    p = RECEIPT_PROFILE
    refobj = _exact_keys(obj, p["reference_object"]["keys"], label)
    if not isinstance(refobj["ref"], str) or len(refobj["ref"]) < 1:
        raise ValidationError(f"{label}:ref")
    if not _valid_hex64(refobj["sha256"]):
        raise ValidationError(f"{label}:sha256")
    return refobj

def _validate_attempt_binding(obj: Any, label: str) -> dict[str,Any]:
    p = RECEIPT_PROFILE
    b = _exact_keys(obj, p["attempt_binding"]["keys"], label)
    if not _valid_hex64(b["candidate_digest"]):
        raise ValidationError(f"{label}:candidate_digest")
    if not _valid_attempt_token(b["installation_attempt_id"]):
        raise ValidationError(f"{label}:installation_attempt_id")
    if b["route_class"] not in ["ASSISTANT_TOOL","USER_MANUAL"]:
        raise ValidationError(f"{label}:route_class")
    if not _valid_hex64(b["target_binding_digest"]):
        raise ValidationError(f"{label}:target_binding_digest")
    if not _valid_attempt_token(b["transition_epoch"]):
        raise ValidationError(f"{label}:transition_epoch")
    return b

def _canonical_evidence_digest(record: dict[str,Any]) -> str:
    if not isinstance(record, dict):
        raise ValidationError("evidence_record:not_object")
    body = {k:v for k,v in record.items() if k != "sha256"}
    try:
        encoded = json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ValidationError("evidence_record:not_canonical_json") from exc
    return hashlib.sha256(encoded).hexdigest()


def _closed_evidence_record(
    record: Any,
    *,
    label: str,
    keys: set[str],
    role: str,
    ref: str,
    sha256: str,
) -> dict[str,Any]:
    if not isinstance(record, dict) or set(record) != keys:
        raise ValidationError(f"{label}:closed_keys")
    if record.get("role") != role:
        raise ValidationError(f"{label}:role")
    if record.get("ref") != ref:
        raise ValidationError(f"{label}:ref")
    if record.get("sha256") != sha256:
        raise ValidationError(f"{label}:sha256")
    if _canonical_evidence_digest(record) != sha256:
        raise ValidationError(f"{label}:canonical_digest")
    return record


def _require_attempt_binding_equal(record: dict[str,Any], binding: dict[str,Any], label: str) -> None:
    rb = _validate_attempt_binding(record.get("attempt_binding"), f"{label}:attempt_binding")
    if not json_equal(_to_decimal_json(rb), _to_decimal_json(binding)):
        raise ValidationError(f"{label}:attempt_binding_mismatch")


def _trusted_evidence_root(roots: Any, key: str, label: str) -> dict[str,Any]:
    if not isinstance(roots, dict) or set(roots) != {"installation_selector_evidence", "route_control_evidence"}:
        raise ValidationError("issued_receipt:trusted_control_roots_required")
    root = _exact_keys(roots.get(key), {"ref", "sha256"}, label)
    if not isinstance(root["ref"], str) or not root["ref"]:
        raise ValidationError(f"{label}:ref")
    if not _valid_hex64(root["sha256"]):
        raise ValidationError(f"{label}:sha256")
    return root


def validate_issued_receipt(
    receipt: Any,
    resolved_evidence: dict[str,dict[str,Any]] | None = None,
    trusted_control_roots: dict[str,dict[str,str]] | None = None,
) -> str:
    p = RECEIPT_PROFILE
    top = _exact_keys(receipt, p["top_level_keys"], "issued_receipt")
    for key, expected in p["const"].items():
        if top.get(key) != expected:
            raise ValidationError(f"issued_receipt:const:{key}")
    binding = _validate_attempt_binding(top["attempt_binding"], "issued_receipt:attempt_binding")
    for role in p["evidence_roles"]:
        _validate_reference_object(top[role], f"issued_receipt:{role}")
    art = _exact_keys(top["artifact_identity"], p["artifact_identity"]["keys"], "issued_receipt:artifact_identity")
    for key in p["artifact_identity"]["keys"]:
        if not _valid_hex64(art[key]):
            raise ValidationError(f"issued_receipt:artifact_identity:{key}")
    if art["artifact_composition_root"] != binding["candidate_digest"]:
        raise ValidationError("issued_receipt:artifact_root_candidate_mismatch")
    if top["target_binding_evidence"]["sha256"] != binding["target_binding_digest"]:
        raise ValidationError("issued_receipt:target_binding_digest_mismatch")
    roots = _exact_keys(top["evidence_roots"], p["evidence_roots"]["keys"], "issued_receipt:evidence_roots")
    for role, expected_result in p["evidence_roots"]["issued_result_const"].items():
        root = _exact_keys(roots[role], p["evidence_roots"]["root_keys"], f"issued_receipt:evidence_roots.{role}")
        rb = _validate_attempt_binding(root["attempt_binding"], f"issued_receipt:evidence_roots.{role}.attempt_binding")
        if not json_equal(_to_decimal_json(rb), _to_decimal_json(binding)):
            raise ValidationError(f"issued_receipt:evidence_root_attempt_mismatch:{role}")
        if not isinstance(root["ref"], str) or len(root["ref"]) < 1:
            raise ValidationError(f"issued_receipt:evidence_roots.{role}:ref")
        if not _valid_hex64(root["sha256"]):
            raise ValidationError(f"issued_receipt:evidence_roots.{role}:sha256")
        if root["result"] != expected_result:
            raise ValidationError(f"issued_receipt:evidence_roots.{role}:result")
    if resolved_evidence is None:
        raise ValidationError("issued_receipt:external_evidence_resolution_required")
    selector_root = _trusted_evidence_root(trusted_control_roots, "installation_selector_evidence", "issued_receipt:trusted_selector_root")
    route_control_root = _trusted_evidence_root(trusted_control_roots, "route_control_evidence", "issued_receipt:trusted_route_control_root")

    artifact_bytes = resolved_evidence.get("artifact_bytes")
    if not isinstance(artifact_bytes, dict) or set(artifact_bytes) != {"VERA_R9A0_MANIFEST.json", "VERA_R9A0_CHECKSUMS.sha256"}:
        raise ValidationError("issued_receipt:artifact_bytes_resolution_required")
    manifest_bytes = artifact_bytes.get("VERA_R9A0_MANIFEST.json")
    checksums_bytes = artifact_bytes.get("VERA_R9A0_CHECKSUMS.sha256")
    if not isinstance(manifest_bytes, (bytes, bytearray)) or not isinstance(checksums_bytes, (bytes, bytearray)):
        raise ValidationError("issued_receipt:artifact_bytes_type")
    if hashlib.sha256(bytes(manifest_bytes)).hexdigest() != art["manifest_sha256"]:
        raise ValidationError("issued_receipt:manifest_sha256_unbound")
    if hashlib.sha256(bytes(checksums_bytes)).hexdigest() != art["checksums_sha256"]:
        raise ValidationError("issued_receipt:checksums_sha256_unbound")

    packet = _closed_evidence_record(
        resolved_evidence.get("operator_decision_packet_evidence"),
        label="issued_receipt:operator_packet",
        keys={"role","ref","sha256","decision","candidate_digest","target_binding_sha256","route_class"},
        role="OPERATOR_DECISION_PACKET",
        ref=top["operator_decision_packet_evidence"]["ref"],
        sha256=top["operator_decision_packet_evidence"]["sha256"],
    )
    if packet["decision"] != "APPROVE_ATTEMPT" or packet["candidate_digest"] != binding["candidate_digest"]:
        raise ValidationError("issued_receipt:operator_packet_semantics")
    if packet["target_binding_sha256"] != binding["target_binding_digest"] or packet["route_class"] != binding["route_class"]:
        raise ValidationError("issued_receipt:operator_packet_binding")

    selector = _closed_evidence_record(
        resolved_evidence.get("installation_selector_evidence"),
        label="issued_receipt:installation_selector",
        keys={"role","ref","sha256","candidate_digest","target_purpose","target_locator","target_scope","authority_ref","authority_source","action_window_id","effect_class","environment_locator","route_class"},
        role="INSTALLATION_INTENT_SELECTOR",
        ref=selector_root["ref"],
        sha256=selector_root["sha256"],
    )
    if selector["candidate_digest"] != binding["candidate_digest"] or selector["route_class"] != binding["route_class"]:
        raise ValidationError("issued_receipt:selector_attempt_identity")
    if selector["effect_class"] != "PROJECT_INSTALLATION_ATTEMPT":
        raise ValidationError("issued_receipt:selector_effect_class")

    target = _closed_evidence_record(
        resolved_evidence.get("target_binding_evidence"),
        label="issued_receipt:target_binding",
        keys={"role","ref","sha256","target_purpose","target_locator","target_scope","candidate_digest","target_matches_expected"},
        role="EXACT_TARGET_BINDING",
        ref=top["target_binding_evidence"]["ref"],
        sha256=top["target_binding_evidence"]["sha256"],
    )
    if target["target_purpose"] != "VERA_R9A0_NATIVE_PROJECT_INSTALLATION" or not target["target_locator"] or not target["target_scope"]:
        raise ValidationError("issued_receipt:target_binding_semantics")
    if target["candidate_digest"] != binding["candidate_digest"] or target["target_matches_expected"] is not True:
        raise ValidationError("issued_receipt:target_binding_candidate")
    if target["target_purpose"] != selector["target_purpose"]:
        raise ValidationError("issued_receipt:target_purpose_mismatch_selector")
    if target["target_locator"] != selector["target_locator"]:
        raise ValidationError("issued_receipt:target_locator_mismatch_selector")
    if target["target_scope"] != selector["target_scope"]:
        raise ValidationError("issued_receipt:target_scope_mismatch_selector")

    authority = _closed_evidence_record(
        resolved_evidence.get("authority_evidence"),
        label="issued_receipt:authority",
        keys={"role","ref","sha256","decision","authorized","effect_class","valid_at_effect_time","attempt_binding","target_binding_sha256","attempt_plan_sha256","authority_source","action_window_id"},
        role="EFFECT_TIME_AUTHORITY",
        ref=top["authority_evidence"]["ref"],
        sha256=top["authority_evidence"]["sha256"],
    )
    _require_attempt_binding_equal(authority, binding, "issued_receipt:authority")
    if authority["decision"] != "ALLOW" or authority["authorized"] is not True:
        raise ValidationError("issued_receipt:authority_decision")
    if authority["effect_class"] != "PROJECT_INSTALLATION_ATTEMPT" or authority["valid_at_effect_time"] is not True:
        raise ValidationError("issued_receipt:authority_effect_semantics")
    if authority["target_binding_sha256"] != binding["target_binding_digest"]:
        raise ValidationError("issued_receipt:authority_target_binding")
    if not authority["authority_source"] or not authority["action_window_id"]:
        raise ValidationError("issued_receipt:authority_identity_missing")
    if authority["ref"] != selector["authority_ref"]:
        raise ValidationError("issued_receipt:authority_ref_mismatch_selector")
    if authority["authority_source"] != selector["authority_source"]:
        raise ValidationError("issued_receipt:authority_source_mismatch_selector")
    if authority["action_window_id"] != selector["action_window_id"]:
        raise ValidationError("issued_receipt:authority_action_window_mismatch_selector")
    if authority["effect_class"] != selector["effect_class"]:
        raise ValidationError("issued_receipt:authority_effect_class_mismatch_selector")

    plan = resolved_evidence.get("attempt_plan_evidence")
    if not isinstance(plan, dict):
        raise ValidationError("issued_receipt:evidence_missing:attempt_plan_evidence")
    plan = _closed_evidence_record(
        plan,
        label="issued_receipt:attempt_plan",
        keys={"role","ref","sha256","attempt_binding","operator_decision_packet_sha256","target_binding_sha256","effect_class"},
        role="ATTEMPT_PLAN",
        ref=plan.get("ref"),
        sha256=plan.get("sha256"),
    )
    _require_attempt_binding_equal(plan, binding, "issued_receipt:attempt_plan")
    if plan["operator_decision_packet_sha256"] != top["operator_decision_packet_evidence"]["sha256"]:
        raise ValidationError("issued_receipt:attempt_plan_packet_binding")
    if plan["target_binding_sha256"] != top["target_binding_evidence"]["sha256"] or plan["effect_class"] != "PROJECT_INSTALLATION_ATTEMPT":
        raise ValidationError("issued_receipt:attempt_plan_target_binding")
    if authority["attempt_plan_sha256"] != plan["sha256"]:
        raise ValidationError("issued_receipt:authority_attempt_plan_binding")

    recheck = resolved_evidence.get("pre_dispatch_recheck_evidence")
    if not isinstance(recheck, dict):
        raise ValidationError("issued_receipt:evidence_missing:pre_dispatch_recheck_evidence")
    recheck = _closed_evidence_record(
        recheck,
        label="issued_receipt:pre_dispatch_recheck",
        keys={"role","ref","sha256","attempt_binding","authority_sha256","target_binding_sha256","attempt_plan_sha256","target_current","authority_current","plan_current"},
        role="PRE_DISPATCH_RECHECK",
        ref=recheck.get("ref"),
        sha256=recheck.get("sha256"),
    )
    _require_attempt_binding_equal(recheck, binding, "issued_receipt:pre_dispatch_recheck")
    if recheck["authority_sha256"] != top["authority_evidence"]["sha256"] or recheck["target_binding_sha256"] != top["target_binding_evidence"]["sha256"]:
        raise ValidationError("issued_receipt:pre_dispatch_binding")
    if recheck["attempt_plan_sha256"] != plan["sha256"]:
        raise ValidationError("issued_receipt:pre_dispatch_plan_binding")
    if recheck["target_current"] is not True or recheck["authority_current"] is not True or recheck["plan_current"] is not True:
        raise ValidationError("issued_receipt:pre_dispatch_not_current")

    if binding["route_class"] == "USER_MANUAL":
        route_control = _closed_evidence_record(
            resolved_evidence.get("manual_operator_control_evidence"),
            label="issued_receipt:manual_operator_control",
            keys={"role","ref","sha256","attempt_binding","operator_decision_packet_sha256","target_binding_sha256","human_authorized"},
            role="MANUAL_OPERATOR_CONTROL",
            ref=route_control_root["ref"],
            sha256=route_control_root["sha256"],
        )
        _require_attempt_binding_equal(route_control, binding, "issued_receipt:manual_operator_control")
        if route_control["operator_decision_packet_sha256"] != top["operator_decision_packet_evidence"]["sha256"]:
            raise ValidationError("issued_receipt:manual_operator_packet_binding")
        if route_control["target_binding_sha256"] != top["target_binding_evidence"]["sha256"] or route_control["human_authorized"] is not True:
            raise ValidationError("issued_receipt:manual_operator_control_semantics")
    else:
        route_control = _closed_evidence_record(
            resolved_evidence.get("assistant_tool_confinement_evidence"),
            label="issued_receipt:assistant_tool_confinement",
            keys={"role","ref","sha256","attempt_binding","target_binding_sha256","authority_sha256","tool_route","capability_scope","confinement_current","effect_class"},
            role="ASSISTANT_TOOL_CONFINEMENT",
            ref=route_control_root["ref"],
            sha256=route_control_root["sha256"],
        )
        _require_attempt_binding_equal(route_control, binding, "issued_receipt:assistant_tool_confinement")
        if route_control["target_binding_sha256"] != top["target_binding_evidence"]["sha256"] or route_control["authority_sha256"] != top["authority_evidence"]["sha256"]:
            raise ValidationError("issued_receipt:assistant_tool_confinement_binding")
        if not route_control["tool_route"] or not route_control["capability_scope"] or route_control["confinement_current"] is not True:
            raise ValidationError("issued_receipt:assistant_tool_confinement_missing")
        if route_control["effect_class"] != "PROJECT_INSTALLATION_ATTEMPT":
            raise ValidationError("issued_receipt:assistant_tool_effect_class")

    envelope = _closed_evidence_record(
        resolved_evidence.get("attempt_action_envelope_evidence"),
        label="issued_receipt:action_envelope",
        keys={"role","ref","sha256","operator_decision_packet_sha256","authority_sha256","target_binding_sha256","attempt_binding","attempt_plan_sha256","pre_dispatch_recheck_sha256","effect_class","route_control_sha256"},
        role="ATTEMPT_ACTION_ENVELOPE",
        ref=top["attempt_action_envelope_evidence"]["ref"],
        sha256=top["attempt_action_envelope_evidence"]["sha256"],
    )
    _require_attempt_binding_equal(envelope, binding, "issued_receipt:action_envelope")
    if envelope["operator_decision_packet_sha256"] != top["operator_decision_packet_evidence"]["sha256"]:
        raise ValidationError("issued_receipt:envelope_packet_binding")
    if envelope["authority_sha256"] != top["authority_evidence"]["sha256"]:
        raise ValidationError("issued_receipt:envelope_authority_binding")
    if envelope["target_binding_sha256"] != top["target_binding_evidence"]["sha256"]:
        raise ValidationError("issued_receipt:envelope_target_binding")
    if envelope["attempt_plan_sha256"] != plan["sha256"] or envelope["pre_dispatch_recheck_sha256"] != recheck["sha256"]:
        raise ValidationError("issued_receipt:envelope_pre_dispatch_binding")
    if envelope["effect_class"] != "PROJECT_INSTALLATION_ATTEMPT":
        raise ValidationError("issued_receipt:envelope_effect_class")
    if envelope["route_control_sha256"] != route_control["sha256"]:
        raise ValidationError("issued_receipt:envelope_route_control_binding")

    root_refs = [roots[field]["ref"] for field in p["evidence_roots"]["keys"]]
    if len(set(root_refs)) != len(root_refs):
        raise ValidationError("issued_receipt:evidence_root_refs_not_distinct")

    env_binding = _closed_evidence_record(
        resolved_evidence.get("in_situ_environment_binding_evidence"),
        label="issued_receipt:in_situ_environment_binding",
        keys={"role","ref","sha256","target_binding_sha256","candidate_digest","environment_locator","environment_matches_expected"},
        role="IN_SITU_ENVIRONMENT_BINDING",
        ref=(resolved_evidence.get("in_situ_environment_binding_evidence") or {}).get("ref"),
        sha256=(resolved_evidence.get("in_situ_environment_binding_evidence") or {}).get("sha256"),
    )
    if env_binding["target_binding_sha256"] != top["target_binding_evidence"]["sha256"]:
        raise ValidationError("issued_receipt:in_situ_environment_target_binding")
    if env_binding["candidate_digest"] != binding["candidate_digest"] or not env_binding["environment_locator"]:
        raise ValidationError("issued_receipt:in_situ_environment_candidate")
    if env_binding["environment_matches_expected"] is not True:
        raise ValidationError("issued_receipt:in_situ_environment_mismatch")
    if env_binding["environment_locator"] != selector["environment_locator"]:
        raise ValidationError("issued_receipt:environment_locator_mismatch_selector")

    root_roles = {
        "cold_start_runtime_readback": "COLD_START_RUNTIME_READBACK",
        "in_situ_project_qualification": "IN_SITU_PROJECT_QUALIFICATION",
        "install_base_outcome_readback": "INSTALL_BASE_OUTCOME_READBACK",
        "post_install_environment_check": "POST_INSTALL_ENVIRONMENT_CHECK",
    }
    for field, semantic_role in root_roles.items():
        root_ref = roots[field]
        keys = {"role","ref","sha256","attempt_binding","result"}
        if field == "in_situ_project_qualification":
            keys = keys | {"environment_binding_sha256"}
        ev = _closed_evidence_record(
            resolved_evidence.get(field),
            label=f"issued_receipt:root:{field}",
            keys=keys,
            role=semantic_role,
            ref=root_ref["ref"],
            sha256=root_ref["sha256"],
        )
        _require_attempt_binding_equal(ev, binding, f"issued_receipt:root:{field}")
        if ev["result"] != root_ref["result"]:
            raise ValidationError(f"issued_receipt:root_result_mismatch:{field}")
        if field == "in_situ_project_qualification" and ev["environment_binding_sha256"] != env_binding["sha256"]:
            raise ValidationError("issued_receipt:in_situ_environment_binding_mismatch")

    ref_records = [packet, selector, target, authority, plan, recheck, envelope, env_binding, route_control]
    ref_records.extend(resolved_evidence[field] for field in root_roles)
    seen_refs: dict[str,str] = {}
    for record in ref_records:
        ref = record["ref"]
        digest = record["sha256"]
        if ref in seen_refs:
            raise ValidationError(f"issued_receipt:canonical_ref_reused:{ref}")
        seen_refs[ref] = digest

    return p["issued_mode"]["claim"]

def _to_decimal_json(value: Any) -> Any:
    if isinstance(value, bool) or value is None or isinstance(value, str):
        return value
    if isinstance(value, int):
        return Decimal(value)
    if isinstance(value, list):
        return [_to_decimal_json(x) for x in value]
    if isinstance(value, dict):
        return {k:_to_decimal_json(v) for k,v in value.items()}
    return value

def validate_validation_report(text: str) -> None:
    lines = text.splitlines()
    if not lines or not lines[0].startswith(VALIDATION_REPORT_PREFIX):
        raise ValidationError("validation_report:machine_header_missing")
    if sum(1 for line in lines if line.startswith(VALIDATION_REPORT_PREFIX)) != 1:
        raise ValidationError("validation_report:machine_header_duplicate")
    payload = strict_json_loads(lines[0][len(VALIDATION_REPORT_PREFIX):])
    if _standard_json(payload) != VALIDATION_REPORT_MACHINE:
        raise ValidationError("validation_report:machine_header_semantics")

def validate(root: pathlib.Path) -> dict[str,Any]:
    errors: list[str] = []
    def check(label: str, fn: Callable[[], None]) -> None:
        try:
            fn()
        except Exception as exc:
            errors.append(f"{label}:{type(exc).__name__}:{exc}")

    project = root / "project"
    schema_path = root / "schemas/native-project/vera-r9a0-native-contract.schema.json"

    contract = schema = manifest = package = receipt_template = None
    try:
        contract = strict_json_load(project / "VERA_R9A0_NATIVE_CONTRACT.json")
    except Exception as exc:
        errors.append(f"contract_load:{type(exc).__name__}:{exc}")
    try:
        schema = strict_json_load(schema_path)
    except Exception as exc:
        errors.append(f"schema_load:{type(exc).__name__}:{exc}")
    if contract is not None and schema is not None:
        check("contract_schema", lambda: validate_contract(contract, schema))

    try:
        manifest = strict_json_load(project / "VERA_R9A0_MANIFEST.json")
        check("manifest", lambda: validate_manifest(manifest))
    except Exception as exc:
        errors.append(f"manifest_load:{type(exc).__name__}:{exc}")

    try:
        package = strict_json_load(project / "VERA_R9A0_PACKAGE.json")
        check("package", lambda: validate_package(package))
    except Exception as exc:
        errors.append(f"package_load:{type(exc).__name__}:{exc}")

    try:
        receipt_template = strict_json_load(project / "VERA_R9A0_INSTALLATION_RECEIPT_TEMPLATE.yaml")
        check("receipt_template", lambda: validate_receipt_template(receipt_template))
    except Exception as exc:
        errors.append(f"receipt_template_load:{type(exc).__name__}:{exc}")

    try:
        native_text = (project / "VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt").read_text(encoding="utf-8")
        check("native", lambda: validate_native_instructions(native_text))
    except Exception as exc:
        errors.append(f"native_load:{type(exc).__name__}:{exc}")

    try:
        report = (project / "VERA_R9A0_VALIDATION_REPORT.md").read_text(encoding="utf-8")
        check("validation_report", lambda: validate_validation_report(report))
    except Exception as exc:
        errors.append(f"validation_report_load:{type(exc).__name__}:{exc}")

    if manifest is not None:
        try:
            checksum_path = project / "VERA_R9A0_CHECKSUMS.sha256"
            reject_symlink_ancestry(root, checksum_path)
            ctext = checksum_path.read_text(encoding="utf-8")
            check("checksums", lambda: validate_checksums(root, manifest, ctext))
        except Exception as exc:
            errors.append(f"checksums_load:{type(exc).__name__}:{exc}")

    return {"status":"PASS" if not errors else "FAIL","errors":errors}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate the R9A0 native Project candidate.")
    parser.add_argument("--root", default=".", help="candidate repository root")
    parser.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = parser.parse_args(argv)
    result = validate(pathlib.Path(args.root).resolve())
    if args.json:
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    else:
        print(result["status"])
        for error in result["errors"]:
            print(error, file=sys.stderr)
    return 0 if result["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
