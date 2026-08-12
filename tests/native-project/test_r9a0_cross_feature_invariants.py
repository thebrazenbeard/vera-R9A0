import json
import pathlib
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[2]

class CrossFeatureInvariantTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.contract=json.loads((ROOT/"project/VERA_R9A0_NATIVE_CONTRACT.json").read_text(encoding="utf-8"))
        cls.native=(ROOT/"project/VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt").read_text(encoding="utf-8")

    def test_currentness_never_comes_from_visibility_subset(self):
        ac=self.contract["assignment_currentness"]
        self.assertTrue(ac["full_trusted_graph_before_privacy_projection"])
        self.assertTrue(ac["visibility_filtered_subset_cannot_establish_controlling_currentness"])

    def test_sequence_is_not_freshness(self):
        self.assertTrue(self.contract["assignment_currentness"]["sequence_high_water_nonsemantic_for_freshness"])

    def test_memory_provider_is_not_identity(self):
        kc=self.contract["knowledge_continuity"]
        self.assertTrue(kc["provider_identity_is_provenance_not_project_identity"])
        self.assertTrue(kc["reachable_alternate_is_not_fallback_authority"])

    def test_protected_effect_never_inherits_build_pass(self):
        q=self.contract["qualification"]
        self.assertTrue(q["behavioral_pass_may_override_unconfined_effects"] is False)
        self.assertTrue(q["effect_confinement_separate"])

    def test_native_compression_guard_present(self):
        self.assertIn("COMPRESSION_DOES_NOT_WEAKEN_AUTHORITY",self.native)

if __name__ == "__main__":
    unittest.main()
