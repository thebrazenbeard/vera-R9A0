#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, pathlib

RELEASE_ID = "VERA_PROJECT_INTEGRATION_R9A0_20260806_V1"
MANIFEST = "project/VERA_R9A0_MANIFEST.json"
CHECKSUMS = "project/VERA_R9A0_CHECKSUMS.sha256"
CONTRACT = "project/VERA_R9A0_NATIVE_CONTRACT.json"
NATIVE = "project/VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt"
SCHEMA = "schemas/native-project/vera-r9a0-native-contract.schema.json"

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

def parse_checksums(text: str) -> dict[str, str]:
    result = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, name = line.split("  ", 1)
        result[name] = digest
    return result

def validate(root: pathlib.Path) -> dict:
    errors: list[str] = []
    for rel in [MANIFEST, CHECKSUMS, CONTRACT, NATIVE, SCHEMA]:
        if not (root / rel).is_file():
            errors.append(f"missing:{rel}")

    try:
        manifest = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"manifest_json:{exc}")
        manifest = {}
    try:
        contract = json.loads((root / CONTRACT).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"contract_json:{exc}")
        contract = {}
    try:
        json.loads((root / SCHEMA).read_text(encoding="utf-8"))
    except Exception as exc:
        errors.append(f"schema_json:{exc}")

    files = manifest.get("files", [])
    if manifest.get("release_id") != RELEASE_ID:
        errors.append("manifest_release_id")
    if manifest.get("unique_file_count") != 16 or len(files) != 16 or len(set(files)) != 16:
        errors.append("manifest_unique_file_count")
    if manifest.get("basic_memory_active_dependency") is not False:
        errors.append("manifest_basic_memory_dependency")
    for name in files:
        if not (root / "project" / name).is_file():
            errors.append(f"manifest_missing_file:{name}")

    checksum_map = parse_checksums((root / CHECKSUMS).read_text(encoding="utf-8")) if (root / CHECKSUMS).exists() else {}
    if set(checksum_map) != set(files):
        errors.append("checksum_file_set")
    for name in files:
        path = root / "project" / name
        if path.exists():
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

    computed = {}
    for name in files:
        path = root / "project" / name
        if path.exists():
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
