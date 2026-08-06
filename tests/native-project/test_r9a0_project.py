from __future__ import annotations
import importlib.util, json, pathlib, unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("validator", ROOT / "scripts/validate_r9a0_project.py")
validator = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(validator)

class R9A0NativeProjectTests(unittest.TestCase):
    def test_slice_passes_validator(self):
        result = validator.validate(ROOT)
        self.assertEqual(result["status"], "PASS", result["errors"])

    def test_native_instructions_fit_limit(self):
        text = (ROOT / "project/VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt").read_text(encoding="utf-8")
        self.assertLessEqual(len(text), 8000)

    def test_installation_receipt_precedence(self):
        contract = json.loads((ROOT / "project/VERA_R9A0_NATIVE_CONTRACT.json").read_text(encoding="utf-8"))
        self.assertEqual(
            contract["installation"]["receipt_precedence"],
            "COMPLETED_RECEIPT_AND_READBACK_OVERRIDE_GENERATION_METADATA_FOR_CURRENT_STATE",
        )

    def test_voss_delegated_authority(self):
        text = (ROOT / "project/VERA_R9A0_PROJECT_INSTRUCTIONS.md").read_text(encoding="utf-8")
        self.assertIn("does not require routine renewed confirmation", text)

    def test_immediate_correction_uptake(self):
        text = (ROOT / "project/VERA_R9A0_PROJECT_INSTRUCTIONS.md").read_text(encoding="utf-8")
        self.assertIn("Apply an executable correction in the next response", text)

    def test_voice_content_and_rendering_are_separate(self):
        text = (ROOT / "project/VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt").read_text(encoding="utf-8")
        self.assertIn("Semantic content:", text)
        self.assertIn("Spoken rendering:", text)

    def test_unavailable_voice_internals_remain_unavailable(self):
        text = (ROOT / "project/VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt").read_text(encoding="utf-8")
        self.assertIn("Do not assert consumer hidden prompt assembly", text)
        self.assertNotIn("active-call instruction hot reload is confirmed", text)

    def test_supabase_boundary(self):
        text = (ROOT / "project/VERA_R9A0_PROJECT_INSTRUCTIONS.md").read_text(encoding="utf-8")
        self.assertIn("agvhmutlrolbaijzlbqk", text)
        self.assertIn("klmbpaigzeguvnpccqzz", text)
        self.assertIn("r9a0_", text)

if __name__ == "__main__":
    unittest.main()
