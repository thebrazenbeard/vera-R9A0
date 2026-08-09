#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, pathlib, re

RELEASE_ID = "VERA_PROJECT_INTEGRATION_R9A0_20260806_V1"
MANIFEST = "project/VERA_R9A0_MANIFEST.json"
CHECKSUMS = "project/VERA_R9A0_CHECKSUMS.sha256"
CONTRACT = "project/VERA_R9A0_NATIVE_CONTRACT.json"
NATIVE = "project/VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt"
SCHEMA = "schemas/native-project/vera-r9a0-native-contract.schema.json"

EXPECTED_MANIFEST_FILES = [
    "VERA_R9A0_PROJECT_INSTRUCTIONS.md",
    "VERA_R9A0_LAWS.md",
    "VERA_R9A0_GOVERNANCE.md",
    "VERA_R9A0_RUNTIME.md",
    "VERA_R9A0_STATE.md",
    "VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt",
    "VERA_R9A0_NATIVE_CONTRACT.json",
    "VERA_R9A0_RETRIEVAL.md",
    "VERA_R9A0_VOICE.md",
    "VERA_R9A0_RECOVERY.md",
    "VERA_R9A0_MANIFEST.json",
    "VERA_R9A0_PACKAGE.json",
    "VERA_R9A0_VALIDATION_REPORT.md",
    "VERA_R9A0_INSTALLATION_RECEIPT_TEMPLATE.yaml",
    "VERA_R9A0_COLD_START_PROTOCOL.md",
    "VERA_R9A0_POST_INSTALL_AUDIT.md",
]
CHECKSUM_LINE = re.compile(r"^(?P<digest>[0-9a-f]{64})  (?P<name>[^\r\n]+)$")

REQUIRED_NATIVE = [
    "Voss exclusively owns assignments",
    "Basic Memory Cloud is not part of the active R9A0 architecture",
    "identify the sequence, commit, path, receipt, or locator",
    "abstain if unresolved",
    "LIVE SPEECH RUNTIME",
    "Semantic content:",
    "Spoken rendering:",
    "Thank you",
    "direct current-time request",
    "privacy rationale",
    "correction immediately terminates",
    "unexplained audio or transcript cutoff",
    "20260806190126",
    "3156",
    "71b3fc4892df3a70e493e287542e68bfa1e5a798",
]
FORBIDDEN_NATIVE = [
    "Basic Memory is required",
    "inspect Basic Memory",
    "active-call instruction hot reload is confirmed",
    "automatic direct Live recall is confirmed",
    "safe database integration is approved",
    "same-runtime continuation is verified",
]

def _reject_duplicate_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate_json_key:{key}")
        result[key] = value
    return result

def _reject_nonfinite_json_constant(token: str) -> object:
    raise ValueError(f"non_finite_json_number:{token}")

def strict_json_loads(text: str) -> object:
    return json.loads(
        text,
        object_pairs_hook=_reject_duplicate_object,
        parse_constant=_reject_nonfinite_json_constant,
    )

def parse_checksums(text: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for lineno, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        match = CHECKSUM_LINE.fullmatch(line)
        if match is None:
            raise ValueError(f"line_{lineno}:expected_64_lower_hex_two_spaces_filename")
        digest = match.group("digest")
        name = match.group("name")
        if not name or name in result:
            raise ValueError(f"line_{lineno}:duplicate_or_empty_filename:{name}")
        result[name] = digest
    return result

def confined_project_path(project_root: pathlib.Path, name: str) -> tuple[pathlib.Path | None, str | None]:
    candidate_name = pathlib.PurePath(name)
    if candidate_name.is_absolute() or candidate_name.name != name or name in {".", ".."}:
        return None, f"manifest_path_invalid:{name}"
    path = project_root / name
    if path.is_symlink():
        return None, f"manifest_symlink_forbidden:{name}"
    try:
        if path.resolve(strict=False).parent != project_root.resolve(strict=False):
            return None, f"manifest_path_escape:{name}"
    except OSError as exc:
        return None, f"manifest_path_resolution:{name}:{exc}"
    return path, None

def validate(root: pathlib.Path) -> dict:
    errors: list[str] = []
    for rel in [MANIFEST, CHECKSUMS, CONTRACT, NATIVE, SCHEMA]:
        if not (root / rel).is_file():
            errors.append(f"missing:{rel}")

    try:
        manifest = strict_json_loads((root / MANIFEST).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"manifest_json:{exc}")
        manifest = {}
    try:
        contract = strict_json_loads((root / CONTRACT).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"contract_json:{exc}")
        contract = {}
    try:
        strict_json_loads((root / SCHEMA).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"schema_json:{exc}")

    files = manifest.get("files", [])
    if manifest.get("release_id") != RELEASE_ID:
        errors.append("manifest_release_id")
    if manifest.get("unique_file_count") != 16 or not isinstance(files, list) or len(files) != 16 or len(set(files)) != 16:
        errors.append("manifest_unique_file_count")
    if files != EXPECTED_MANIFEST_FILES:
        errors.append("manifest_file_membership")
    if manifest.get("basic_memory_active_dependency") is not False:
        errors.append("manifest_basic_memory_dependency")
    expected_surfaces = ["SUPABASE", "GITHUB", "GOOGLE_DRIVE", "NATIVE_PROJECT_FILES"]
    if manifest.get("active_surfaces") not in (None, expected_surfaces):
        errors.append("manifest_active_surfaces")
    if manifest.get("checksums_path") not in (None, pathlib.PurePath(CHECKSUMS).name):
        errors.append("manifest_checksums_path")
    if manifest.get("native_settings_path") not in (None, pathlib.PurePath(NATIVE).name):
        errors.append("manifest_native_settings_path")

    project_root = root / "project"
    safe_paths: dict[str, pathlib.Path] = {}
    for name in EXPECTED_MANIFEST_FILES:
        path, path_error = confined_project_path(project_root, name)
        if path_error is not None:
            errors.append(path_error)
            continue
        assert path is not None
        if not path.is_file():
            errors.append(f"manifest_missing_file:{name}")
            continue
        safe_paths[name] = path

    checksum_map: dict[str, str] = {}
    if (root / CHECKSUMS).exists():
        try:
            checksum_map = parse_checksums((root / CHECKSUMS).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            errors.append(f"checksums_format:{exc}")
    if set(checksum_map) != set(EXPECTED_MANIFEST_FILES):
        errors.append("checksum_file_set")
    for name, path in safe_paths.items():
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        if checksum_map.get(name) != digest:
            errors.append(f"checksum_mismatch:{name}")

    native = (root / NATIVE).read_text(encoding="utf-8") if (root / NATIVE).exists() else ""
    if len(native) > 8000:
        errors.append(f"native_character_limit:{len(native)}")
    for phrase in REQUIRED_NATIVE:
        if phrase.lower() not in native.lower():
            errors.append(f"native_missing:{phrase}")
    for phrase in FORBIDDEN_NATIVE:
        if phrase.lower() in native.lower():
            errors.append(f"native_forbidden:{phrase}")

    if contract.get("release_id") != RELEASE_ID:
        errors.append("contract_release_id")
    if contract.get("active_surfaces") != ["SUPABASE","GITHUB","GOOGLE_DRIVE","NATIVE_PROJECT_FILES"]:
        errors.append("contract_active_surfaces")
    if contract.get("legacy_memory", {}).get("active_dependency") is not False:
        errors.append("contract_basic_memory_dependency")
    if contract.get("legacy_memory", {}).get("archive_sha256") != "beeddd73b8172c988868f1ca7a9ab8c1287f0f6753705121a17335ed1020dffb":
        errors.append("contract_archive_digest")
    if contract.get("retrieval", {}).get("abstain_when_unresolved") is not True:
        errors.append("contract_retrieval_abstention")
    if contract.get("installation", {}).get("generation_state") != "INSTALLATION_UNVERIFIED":
        errors.append("contract_generation_state")
    supabase = contract.get("supabase", {})
    if supabase.get("temporary_project") != "agvhmutlrolbaijzlbqk":
        errors.append("contract_supabase_target")
    if supabase.get("production_prohibited") != "klmbpaigzeguvnpccqzz":
        errors.append("contract_production_boundary")
    if supabase.get("external_security_state") != "SECURITY_REMEDIATION_APPROVED":
        errors.append("contract_security_state")
    if supabase.get("mune_approval_sequence") != 3156:
        errors.append("contract_mune_security_approval")
    if supabase.get("database_contract_state") != "PROVISIONAL_PENDING_CORRECTED_SUCCESSOR_APPROVAL":
        errors.append("contract_database_gate")
    if contract.get("ci", {}).get("exact_head_success_required") is not True:
        errors.append("contract_ci_gate")
    if manifest.get("active_surfaces") is not None and manifest.get("active_surfaces") != contract.get("active_surfaces"):
        errors.append("manifest_contract_active_surfaces_parity")
    if manifest.get("installation_state_at_generation") is not None and manifest.get("installation_state_at_generation") != contract.get("installation", {}).get("generation_state"):
        errors.append("manifest_installation_generation_parity")

    computed = {}
    for name, path in safe_paths.items():
        computed[name] = {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "size": path.stat().st_size}
    return {
        "status": "PASS" if not errors else "FAIL",
        "errors": errors,
        "native_character_count": len(native),
        "manifest_file_count": len(files),
        "files": computed,
    }

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--json", action="store_true")
    args = parser.parse_args()
    result = validate(pathlib.Path(args.root))
    print(json.dumps(result, indent=2, sort_keys=True) if args.json else result["status"])
    return 0 if result["status"] == "PASS" else 1

if __name__ == "__main__":
    raise SystemExit(main())
