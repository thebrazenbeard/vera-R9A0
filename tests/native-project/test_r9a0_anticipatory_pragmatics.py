from __future__ import annotations
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIX = pathlib.Path(__file__).resolve().parent / "fixtures/anticipatory_pragmatics_v1"
CONTRACT = json.loads((ROOT / "project/VERA_R9A0_NATIVE_CONTRACT.json").read_text(encoding="utf-8"))
AP = CONTRACT["anticipatory_pragmatics"]


def resolve(case):
    protected = set(AP["protected_axes"])
    axes = tuple(AP["presentation_axes"])
    eligible = [c for c in case["candidates"] if c.get("admissible_evidence_ids")]
    if any(set(c.get("protected_axis_changes", [])) & protected for c in eligible):
        return {"discard_all": True, "hints": {}}
    out = {}
    for axis in axes:
        contenders = []
        for cand in eligible:
            if cand.get("axis") != axis:
                continue
            contenders.append((cand["authority_rank"], cand.get("value"), tuple(cand["admissible_evidence_ids"])))
        if not contenders:
            out[axis] = "unset"
            continue
        best_rank = min(x[0] for x in contenders)
        best = [x for x in contenders if x[0] == best_rank]
        values = {x[1] for x in best}
        out[axis] = next(iter(values)) if len(values) == 1 else "unset"
    return {"discard_all": False, "hints": out}


class AnticipatoryPragmaticsTests(unittest.TestCase):
    def test_contract_frozen_nonpersistence(self):
        self.assertTrue(AP["deterministic"])
        self.assertTrue(AP["read_only"])
        self.assertTrue(AP["turn_local"])
        self.assertFalse(AP["persistence_or_store_calls"])
        self.assertFalse(AP["extra_inference_for_style"])
        self.assertFalse(AP["paid_dependency"])
        self.assertFalse(AP["private_chain_of_thought_serialization"])
        self.assertFalse(AP["broad_personal_retrieval_solely_for_style"])
        self.assertTrue(AP["non_unset_hint_requires_admitted_evidence"])
        self.assertEqual(AP["equal_derived_authority_conflict"], "UNSET")
        self.assertEqual(AP["protected_divergence_result"], "DISCARD_ALL_HINTS")

    def test_fixtures(self):
        files = sorted(FIX.glob("*.json"))
        self.assertEqual(len(files), 12)
        for path in files:
            with self.subTest(path=path.name):
                case = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(set(case), {"case_id", "purpose", "candidates", "expected"})
                self.assertEqual(resolve(case), case["expected"])


if __name__ == "__main__":
    unittest.main()
