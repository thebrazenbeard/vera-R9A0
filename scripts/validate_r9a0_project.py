#!/usr/bin/env python3
from __future__ import annotations
import argparse, hashlib, json, pathlib

REQUIRED = [
    "project/VERA_R9A0_PROJECT_INSTRUCTIONS.md",
    "project/VERA_R9A0_LAWS.md",
    "project/VERA_R9A0_GOVERNANCE.md",
    "project/VERA_R9A0_RUNTIME.md",
    "project/VERA_R9A0_STATE.md",
    "project/VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt",
    "project/VERA_R9A0_NATIVE_CONTRACT.json",
    "schemas/native-project/vera-r9a0-native-contract.schema.json",
]
REQUIRED_NATIVE = [
    "Voss exclusively owns assignments",
    "completed installation receipt",
    "logical binding",
    "LIVE SPEECH RUNTIME",
    "Semantic content",
    "Spoken rendering",
    "agvhmutlrolbaijzlbqk",
    "klmbpaigzeguvnpccqzz",
    "consumer hidden prompt assembly",
]
FORBIDDEN_NATIVE = [
    "automatic direct Live recall is confirmed",
    "active-call instruction hot reload is confirmed",
    "same-runtime continuation is verified",
]

def validate(root: pathlib.Path) -> dict:
    errors = []
    for rel in REQUIRED:
        if not (root / rel).is_file():
            errors.append(f"missing:{rel}")

    native_path = root / "project/VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt"
    native = native_path.read_text(encoding="utf-8") if native_path.exists() else ""
    if len(native) > 8000:
        errors.append(f"native_character_limit:{len(native)}")
    for phrase in REQUIRED_NATIVE:
        if phrase.lower() not in native.lower():
            errors.append(f"native_missing:{phrase}")
    for phrase in FORBIDDEN_NATIVE:
        if phrase.lower() in native.lower():
            errors.append(f"native_forbidden:{phrase}")

    contract_path = root / "project/VERA_R9A0_NATIVE_CONTRACT.json"
    if contract_path.exists():
        try:
            contract = json.loads(contract_path.read_text(encoding="utf-8"))
        except Exception as exc:
            errors.append(f"contract_json:{exc}")
            contract = {}
        if contract.get("installation", {}).get("generation_state") != "INSTALLATION_UNVERIFIED":
            errors.append("contract_generation_state")
        if contract.get("installation", {}).get("receipt_precedence") != "COMPLETED_RECEIPT_AND_READBACK_OVERRIDE_GENERATION_METADATA_FOR_CURRENT_STATE":
            errors.append("contract_receipt_precedence")
        if contract.get("supabase", {}).get("temporary_project") != "agvhmutlrolbaijzlbqk":
            errors.append("contract_supabase_target")
        if contract.get("supabase", {}).get("production_prohibited") != "klmbpaigzeguvnpccqzz":
            errors.append("contract_production_boundary")

    files = {}
    for rel in REQUIRED:
        p = root / rel
        if p.exists():
            data = p.read_bytes()
            files[rel] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    return {"status":"PASS" if not errors else "FAIL","errors":errors,"native_character_count":len(native),"files":files}

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
