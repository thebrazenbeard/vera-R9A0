from __future__ import annotations
import importlib.util, json, pathlib, unittest, hashlib

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

if __name__ == "__main__":
    unittest.main()
