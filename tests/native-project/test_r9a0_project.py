from __future__ import annotations
import importlib.util, json, pathlib, unittest, hashlib, shutil, tempfile

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("validator", ROOT / "scripts/validate_r9a0_project.py")
validator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(validator)

def text(name: str) -> str:
    return (ROOT / "project" / name).read_text(encoding="utf-8")

class R9A0NativeProjectTests(unittest.TestCase):
    def test_01_validator_passes(self):
        result = validator.validate(ROOT)
        self.assertEqual(result["status"], "PASS", result["errors"])

    def test_02_native_instructions_fit_limit(self):
        self.assertLessEqual(len(text("VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt")), 8000)

    def test_03_manifest_has_16_unique_files(self):
        m = json.loads(text("VERA_R9A0_MANIFEST.json"))
        self.assertEqual(m["unique_file_count"], 16)
        self.assertEqual(len(m["files"]), len(set(m["files"])))
        self.assertEqual(m["files"], validator.EXPECTED_MANIFEST_FILES)

    def test_04_checksums_cover_manifest(self):
        m = json.loads(text("VERA_R9A0_MANIFEST.json"))
        checks = validator.parse_checksums(text("VERA_R9A0_CHECKSUMS.sha256"))
        self.assertEqual(set(m["files"]), set(checks))

    def test_05_checksums_match(self):
        checks = validator.parse_checksums(text("VERA_R9A0_CHECKSUMS.sha256"))
        for name, digest in checks.items():
            self.assertEqual(hashlib.sha256((ROOT/"project"/name).read_bytes()).hexdigest(), digest)

    def test_06_basic_memory_not_active_surface(self):
        c = json.loads(text("VERA_R9A0_NATIVE_CONTRACT.json"))
        self.assertNotIn("BASIC_MEMORY", c["active_surfaces"])
        self.assertFalse(c["legacy_memory"]["active_dependency"])

    def test_07_archive_digest_preserved(self):
        c = json.loads(text("VERA_R9A0_NATIVE_CONTRACT.json"))
        self.assertEqual(c["legacy_memory"]["archive_sha256"], "beeddd73b8172c988868f1ca7a9ab8c1287f0f6753705121a17335ed1020dffb")

    def test_08_retrieval_refresh_gate(self):
        self.assertIn("refresh the relevant exposed", text("VERA_R9A0_PROJECT_INSTRUCTIONS.md"))

    def test_09_retrieval_evidence_locator(self):
        self.assertIn("sequence, commit, file, receipt, or locator", text("VERA_R9A0_PROJECT_INSTRUCTIONS.md"))

    def test_10_retrieval_abstention(self):
        self.assertIn("abstain", text("VERA_R9A0_RETRIEVAL.md").lower())

    def test_11_false_recovery_claim_prohibited(self):
        self.assertIn("never say a record was recovered", text("VERA_R9A0_PROJECT_INSTRUCTIONS.md").lower())

    def test_12_voice_incomplete_input_clarified(self):
        self.assertIn("ask one concise clarification", text("VERA_R9A0_VOICE.md"))

    def test_13_voice_thank_you_not_closure(self):
        self.assertIn("Do not treat `Thank you` as a farewell", text("VERA_R9A0_VOICE.md"))

    def test_14_voice_time_lookup(self):
        self.assertIn("current-time questions", text("VERA_R9A0_VOICE.md"))

    def test_15_voice_no_privacy_fabrication(self):
        self.assertIn("fabricated privacy rationale", text("VERA_R9A0_VOICE.md"))

    def test_16_voice_correction_supersedes(self):
        self.assertIn("correction terminates the obsolete route", text("VERA_R9A0_VOICE.md"))

    def test_17_voice_same_chat_context(self):
        self.assertIn("same-chat context", text("VERA_R9A0_VOICE.md"))

    def test_18_voice_fact_inference_separation(self):
        self.assertIn("Distinguish fact from inference", text("VERA_R9A0_VOICE.md"))

    def test_19_voice_no_filler_substitution(self):
        self.assertIn("Do not replace execution", text("VERA_R9A0_VOICE.md"))

    def test_20_voice_truncation_failure(self):
        self.assertIn("unexplained audio or transcript cutoff as failed verification", text("VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt"))

    def test_21_installation_unverified(self):
        c = json.loads(text("VERA_R9A0_NATIVE_CONTRACT.json"))
        self.assertEqual(c["installation"]["generation_state"], "INSTALLATION_UNVERIFIED")

    def test_22_security_remediation_approved(self):
        c = json.loads(text("VERA_R9A0_NATIVE_CONTRACT.json"))
        self.assertEqual(c["supabase"]["external_security_state"], "SECURITY_REMEDIATION_APPROVED")
        self.assertEqual(c["supabase"]["mune_approval_sequence"], 3156)

    def test_23_database_contract_still_provisional(self):
        c = json.loads(text("VERA_R9A0_NATIVE_CONTRACT.json"))
        self.assertEqual(c["supabase"]["database_contract_state"], "PROVISIONAL_PENDING_CORRECTED_SUCCESSOR_APPROVAL")

    def test_24_exact_head_ci_required(self):
        c = json.loads(text("VERA_R9A0_NATIVE_CONTRACT.json"))
        self.assertTrue(c["ci"]["exact_head_success_required"])
        self.assertTrue(c["ci"]["local_only_acceptance_prohibited"])

    def test_25_cold_start_without_basic_memory(self):
        cold = text("VERA_R9A0_COLD_START_PROTOCOL.md")
        self.assertIn("Disable or make unavailable the Basic Memory connector", cold)
        self.assertIn("RECOVERY_REQUIRED", cold)

    def test_26_checksum_parser_rejects_duplicate_same_entry(self):
        line = "a" * 64 + "  VERA_R9A0_PROJECT_INSTRUCTIONS.md\n"
        with self.assertRaises(ValueError):
            validator.parse_checksums(line + line)

    def test_27_checksum_parser_rejects_duplicate_conflicting_entry(self):
        name = "VERA_R9A0_PROJECT_INSTRUCTIONS.md"
        with self.assertRaises(ValueError):
            validator.parse_checksums("a" * 64 + f"  {name}\n" + "b" * 64 + f"  {name}\n")

    def test_28_checksum_parser_rejects_malformed_digest(self):
        with self.assertRaises(ValueError):
            validator.parse_checksums("xyz  VERA_R9A0_PROJECT_INSTRUCTIONS.md\n")

    def test_29_manifest_rejects_traversal_even_with_consistent_checksum(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            manifest_path = root / "project/VERA_R9A0_MANIFEST.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            original = manifest["files"][0]
            manifest["files"][0] = "../escape.txt"
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            escape = root / "escape.txt"
            escape.write_text("external package impostor", encoding="utf-8")
            checks = validator.parse_checksums((root / "project/VERA_R9A0_CHECKSUMS.sha256").read_text(encoding="utf-8"))
            checks.pop(original)
            checks["../escape.txt"] = hashlib.sha256(escape.read_bytes()).hexdigest()
            (root / "project/VERA_R9A0_CHECKSUMS.sha256").write_text(
                "\n".join(f"{digest}  {name}" for name, digest in checks.items()) + "\n",
                encoding="utf-8",
            )
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("manifest_file_membership", result["errors"])

    def test_30_manifest_rejects_absolute_entry(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            manifest_path = root / "project/VERA_R9A0_MANIFEST.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"][0] = str((root / "outside.txt").resolve())
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("manifest_file_membership", result["errors"])

    def test_31_manifest_rejects_symlink_member(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            name = validator.EXPECTED_MANIFEST_FILES[0]
            member = root / "project" / name
            target = root / "outside.txt"
            target.write_text("external package impostor", encoding="utf-8")
            member.unlink()
            member.symlink_to(target)
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn(f"manifest_symlink_forbidden:{name}", result["errors"])

    def test_32_strict_json_rejects_duplicate_top_level_key(self):
        with self.assertRaisesRegex(ValueError, "duplicate_json_key:release_id"):
            validator.strict_json_loads('{"release_id":"ATTACK","release_id":"EXPECTED"}')

    def test_33_strict_json_rejects_duplicate_nested_key(self):
        with self.assertRaisesRegex(ValueError, "duplicate_json_key:generation_state"):
            validator.strict_json_loads('{"installation":{"generation_state":"ATTACK","generation_state":"EXPECTED"}}')

    def test_34_strict_json_rejects_nonfinite_numbers(self):
        for token in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(token=token), self.assertRaisesRegex(ValueError, "non_finite_json_number"):
                validator.strict_json_loads('{"value":' + token + '}')

    def test_35_manifest_installation_generation_must_match_contract(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            manifest_path = root / "project/VERA_R9A0_MANIFEST.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["installation_state_at_generation"] = "INSTALLED_VERIFIED"
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            checks = validator.parse_checksums((root / "project/VERA_R9A0_CHECKSUMS.sha256").read_text(encoding="utf-8"))
            checks["VERA_R9A0_MANIFEST.json"] = hashlib.sha256(manifest_path.read_bytes()).hexdigest()
            (root / "project/VERA_R9A0_CHECKSUMS.sha256").write_text(
                "\n".join(f"{checks[name]}  {name}" for name in validator.EXPECTED_MANIFEST_FILES) + "\n",
                encoding="utf-8",
            )
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("manifest_installation_generation_parity", result["errors"])

    def test_36_manifest_control_paths_are_exact(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            manifest_path = root / "project/VERA_R9A0_MANIFEST.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["checksums_path"] = "wrong.sha256"
            manifest["native_settings_path"] = "wrong.txt"
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("manifest_checksums_path", result["errors"])
            self.assertIn("manifest_native_settings_path", result["errors"])

    def test_37_manifest_active_surfaces_must_match_contract(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            manifest_path = root / "project/VERA_R9A0_MANIFEST.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["active_surfaces"] = ["SUPABASE", "GITHUB"]
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("manifest_active_surfaces", result["errors"])

    def test_38_manifest_top_level_must_be_object(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            (root / "project/VERA_R9A0_MANIFEST.json").write_text("[]\n", encoding="utf-8")
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("manifest_json_top_level_not_object", result["errors"])

    def test_39_contract_top_level_must_be_object(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            (root / "project/VERA_R9A0_NATIVE_CONTRACT.json").write_text("[]\n", encoding="utf-8")
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("contract_json_top_level_not_object", result["errors"])

    def test_40_schema_top_level_must_be_object(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            (root / "schemas/native-project/vera-r9a0-native-contract.schema.json").write_text("[]\n", encoding="utf-8")
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("schema_json_top_level_not_object", result["errors"])

    def test_41_manifest_files_must_be_strings_before_set_operations(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            manifest_path = root / "project/VERA_R9A0_MANIFEST.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"][0] = {"not": "a filename"}
            manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("manifest_files_not_list_of_strings", result["errors"])

    def test_42_contract_nested_semantic_containers_must_be_objects(self):
        cases = [
            ("legacy_memory", [], "contract_legacy_memory_not_object"),
            ("retrieval", [], "contract_retrieval_not_object"),
            ("installation", [], "contract_installation_not_object"),
            ("supabase", "not-an-object", "contract_supabase_not_object"),
            ("ci", [], "contract_ci_not_object"),
        ]
        for field, bad_value, expected_error in cases:
            with self.subTest(field=field), tempfile.TemporaryDirectory() as d:
                root = pathlib.Path(d)
                shutil.copytree(ROOT / "project", root / "project")
                shutil.copytree(ROOT / "schemas", root / "schemas")
                contract_path = root / "project/VERA_R9A0_NATIVE_CONTRACT.json"
                contract = json.loads(contract_path.read_text(encoding="utf-8"))
                contract[field] = bad_value
                contract_path.write_text(json.dumps(contract, indent=2) + "\n", encoding="utf-8")
                result = validator.validate(root)
                self.assertEqual(result["status"], "FAIL")
                self.assertIn(expected_error, result["errors"])

    def test_43_native_invalid_utf8_is_typed_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            (root / "project/VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt").write_bytes(b"\xff")
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("native_utf8", result["errors"])

    def test_44_checksum_invalid_utf8_is_typed_failure(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            (root / "project/VERA_R9A0_CHECKSUMS.sha256").write_bytes(b"\xff")
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("checksums_utf8", result["errors"])

    def test_45_checksum_control_input_symlink_is_forbidden(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            ledger = root / "project/VERA_R9A0_CHECKSUMS.sha256"
            target = root / "outside-checksums.sha256"
            target.write_text(ledger.read_text(encoding="utf-8"), encoding="utf-8")
            ledger.unlink()
            ledger.symlink_to(target)
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("checksums_symlink_forbidden", result["errors"])

    def test_46_schema_control_input_symlink_is_forbidden(self):
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            schema_path = root / "schemas/native-project/vera-r9a0-native-contract.schema.json"
            target = root / "outside-schema.json"
            target.write_text(schema_path.read_text(encoding="utf-8"), encoding="utf-8")
            schema_path.unlink()
            schema_path.symlink_to(target)
            result = validator.validate(root)
            self.assertEqual(result["status"], "FAIL")
            self.assertIn("schema_symlink_forbidden", result["errors"])

    def test_47_governed_json_invalid_utf8_is_typed_failure(self):
        cases = [
            ("project/VERA_R9A0_MANIFEST.json", "manifest_utf8"),
            ("project/VERA_R9A0_NATIVE_CONTRACT.json", "contract_utf8"),
            ("schemas/native-project/vera-r9a0-native-contract.schema.json", "schema_utf8"),
        ]
        for rel, expected_error in cases:
            with self.subTest(rel=rel), tempfile.TemporaryDirectory() as d:
                root = pathlib.Path(d)
                shutil.copytree(ROOT / "project", root / "project")
                shutil.copytree(ROOT / "schemas", root / "schemas")
                (root / rel).write_bytes(b"\xff")
                result = validator.validate(root)
                self.assertEqual(result["status"], "FAIL")
                self.assertIn(expected_error, result["errors"])

    def _validate_package_bytes_with_matching_checksum(self, data: bytes) -> dict:
        with tempfile.TemporaryDirectory() as d:
            root = pathlib.Path(d)
            shutil.copytree(ROOT / "project", root / "project")
            shutil.copytree(ROOT / "schemas", root / "schemas")
            package_path = root / "project/VERA_R9A0_PACKAGE.json"
            package_path.write_bytes(data)
            checks = validator.parse_checksums((root / "project/VERA_R9A0_CHECKSUMS.sha256").read_text(encoding="utf-8"))
            checks["VERA_R9A0_PACKAGE.json"] = hashlib.sha256(data).hexdigest()
            (root / "project/VERA_R9A0_CHECKSUMS.sha256").write_text(
                "\n".join(f"{checks[name]}  {name}" for name in validator.EXPECTED_MANIFEST_FILES) + "\n",
                encoding="utf-8",
            )
            return validator.validate(root)

    def test_48_malformed_package_fails_even_with_matching_checksum(self):
        result = self._validate_package_bytes_with_matching_checksum(b"{")
        self.assertEqual(result["status"], "FAIL")
        self.assertTrue(any(error.startswith("package_json:") for error in result["errors"]), result["errors"])

    def test_49_package_top_level_must_be_object(self):
        result = self._validate_package_bytes_with_matching_checksum(b"[]\n")
        self.assertIn("package_json_top_level_not_object", result["errors"])

    def test_50_package_rejects_duplicate_keys(self):
        result = self._validate_package_bytes_with_matching_checksum(b'{"x":1,"x":2}\n')
        self.assertTrue(any("package_json:duplicate_json_key:x" in error for error in result["errors"]), result["errors"])

    def test_51_package_rejects_nonfinite_numbers(self):
        result = self._validate_package_bytes_with_matching_checksum(b'{"x":NaN}\n')
        self.assertTrue(any("package_json:non_finite_json_number:NaN" in error for error in result["errors"]), result["errors"])

    def test_52_package_invalid_utf8_is_typed_failure(self):
        result = self._validate_package_bytes_with_matching_checksum(b"\xff")
        self.assertIn("package_utf8", result["errors"])

if __name__ == "__main__":
    unittest.main()
