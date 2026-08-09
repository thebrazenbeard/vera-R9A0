from __future__ import annotations
import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIX = pathlib.Path(__file__).resolve().parent / "fixtures/safety_contamination_v1"
CONTRACT = json.loads((ROOT / "project/VERA_R9A0_NATIVE_CONTRACT.json").read_text(encoding="utf-8"))
SAFE = CONTRACT["safety_semantic_gate"]

NON_AFFIRMING = {"DENY", "QUOTE", "REJECT", "MOCK", "NON_AFFIRMING_ECHO"}

def adjudicate_span(span):
    origin = span["origin"]
    stance = span["stance"]
    if origin == "UNKNOWN":
        return "UNRESOLVED"
    if span.get("corrected"):
        return "INADMISSIBLE"
    if origin == "ASSISTANT_INTRODUCED":
        return "INADMISSIBLE"
    if origin == "USER_RESPONSE_TO_ASSISTANT_FRAME" and stance in NON_AFFIRMING:
        return "INADMISSIBLE"
    if origin == "GOVERNED_PRIOR_CONTEXT":
        return "ADMISSIBLE" if span.get("historical_qualified") and span.get("lifecycle_current") else "INADMISSIBLE"
    if origin == "USER_DIRECT":
        return "ADMISSIBLE"
    if origin == "USER_RESPONSE_TO_ASSISTANT_FRAME" and stance == "AFFIRM":
        return "ADMISSIBLE"
    return "UNRESOLVED"

def resolve(case):
    rows = []
    self_risk = []
    for span in case["spans"]:
        result = adjudicate_span(span)
        rows.append({"id": span["id"], "admissibility": result})
        if (
            result == "ADMISSIBLE"
            and span["referent_subject"] == "SELF"
            and span["semantic_domain"] == "SAFETY_HARM"
            and span.get("risk_bearing", False)
        ):
            self_risk.append(span["id"])
    return {"adjudication": rows, "self_risk_evidence_ids": self_risk}

class SafetyContaminationTests(unittest.TestCase):
    def test_contract_gate_is_before_ap_and_retrieval_bypass_is_forbidden(self):
        self.assertEqual(SAFE["unit"], "PROPOSITION_OR_SPAN")
        self.assertFalse(SAFE["assistant_origin_may_self_bootstrap"])
        self.assertFalse(SAFE["correction_creates_timeless_safe_state"])
        self.assertTrue(SAFE["retrieved_risk_spans_require_same_gate"])
        self.assertFalse(SAFE["ap_may_mutate_locked_safety_state"])

    def test_fixtures(self):
        files = sorted(FIX.glob("*.json"))
        self.assertEqual(len(files), 18)
        for path in files:
            with self.subTest(path=path.name):
                case = json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(set(case), {"case_id", "purpose", "spans", "expected"})
                self.assertEqual(resolve(case), case["expected"])

if __name__ == "__main__":
    unittest.main()
