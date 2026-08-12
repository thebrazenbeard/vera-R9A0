import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
FIX = pathlib.Path(__file__).parent / "fixtures" / "assignment_currentness_v1"

TERMINAL = {"COMPLETE", "CANCEL", "TERMINAL_BLOCK"}
OWNER_PRESERVING = {"AMEND", "SUPERSEDE", "REACTIVATE", "DEPENDENCY_BLOCK", "DEPENDENCY_RELEASE"}


def resolve(case):
    if case.get("source_completeness") != "COMPLETE":
        return {"assignment_state":"UNRESOLVED","owner":None,"blocking_state":"UNRESOLVED","workload_capacity":"UNRESOLVED","effect_eligible":False,"receipt_stale":False}
    authority = case.get("authority_binding_state")
    if authority not in {"VALID", "TARGET_MOVED"}:
        return {"assignment_state":"UNRESOLVED","owner":None,"blocking_state":"UNRESOLVED","workload_capacity":"UNRESOLVED","effect_eligible":False,"receipt_stale":False}
    events = sorted((e for e in case.get("events", []) if e.get("admitted") is True), key=lambda e:e.get("order",0))
    roots = [e for e in events if e.get("relation") == "ASSIGN"]
    if len(roots) != 1:
        return {"assignment_state":"UNRESOLVED","owner":None,"blocking_state":"UNRESOLVED","workload_capacity":"UNRESOLVED","effect_eligible":False,"receipt_stale":False}
    root = roots[0]
    children = {}
    for e in events:
        p=e.get("predecessor")
        if p:
            children.setdefault(p,[]).append(e)
    if any(len(v)>1 for v in children.values()):
        return {"assignment_state":"CONFLICTED","owner":None,"blocking_state":"UNRESOLVED","workload_capacity":"UNRESOLVED","effect_eligible":False,"receipt_stale":False}
    owner=root.get("owner")
    state="CURRENT_ASSIGNED"
    blocking="NONE"
    current=root
    seen={root["id"]}
    while True:
        nxts=children.get(current["id"],[])
        if not nxts:
            break
        nxt=nxts[0]
        if nxt["id"] in seen:
            return {"assignment_state":"CONFLICTED","owner":None,"blocking_state":"UNRESOLVED","workload_capacity":"UNRESOLVED","effect_eligible":False,"receipt_stale":False}
        seen.add(nxt["id"])
        rel=nxt.get("relation")
        if rel == "REROUTE": owner=nxt.get("owner")
        elif rel in OWNER_PRESERVING and nxt.get("owner") not in {None,owner}: state="CONFLICTED"
        if rel == "DEPENDENCY_BLOCK": blocking="DEPENDENCY_BLOCKED"
        elif rel == "DEPENDENCY_RELEASE": blocking="NONE"
        elif rel == "TERMINAL_BLOCK": blocking="TERMINAL_BLOCKED"; state="NON_CURRENT"
        elif rel in {"COMPLETE","CANCEL"}: state="NON_CURRENT"
        elif rel == "REACTIVATE": state="CURRENT_ASSIGNED"; blocking="NONE"
        current=nxt
    receipt_stale=case.get("receipt_state") == "STALE"
    workload = "COUNTS_EXECUTABLE" if state=="CURRENT_ASSIGNED" and blocking=="NONE" else "DOES_NOT_COUNT"
    effect = state=="CURRENT_ASSIGNED" and blocking=="NONE" and authority=="VALID" and not receipt_stale
    return {"assignment_state":state,"owner":owner,"blocking_state":blocking,"workload_capacity":workload,"effect_eligible":effect,"receipt_stale":receipt_stale}


class AssignmentCurrentnessTests(unittest.TestCase):
    def test_all_frozen_rebound_fixtures(self):
        files=sorted(FIX.glob("*.json"))
        self.assertEqual(len(files),20)
        for path in files:
            with self.subTest(path=path.name):
                case=json.loads(path.read_text(encoding="utf-8"))
                self.assertEqual(resolve(case),case["expected"])

    def test_contract_currentness_axes(self):
        contract=json.loads((ROOT/"project/VERA_R9A0_NATIVE_CONTRACT.json").read_text(encoding="utf-8"))
        ac=contract["assignment_currentness"]
        self.assertEqual(ac["lane_identity"],"ROOT_ASSIGN_EVENT_ID")
        self.assertTrue(ac["full_trusted_graph_before_privacy_projection"])
        self.assertTrue(ac["visibility_filtered_subset_cannot_establish_controlling_currentness"])
        self.assertTrue(ac["sequence_high_water_nonsemantic_for_freshness"])
        self.assertTrue(ac["factual_executability_distinct_workload_projection"])
        self.assertFalse(ac["universal_effect_eligible"])

    def test_unadmitted_newer_event_cannot_reroute(self):
        case=json.loads((FIX/"12_unauthorized_newer_event_rejected.json").read_text())
        self.assertEqual(resolve(case)["owner"],"bob")

    def test_source_incomplete_fails_closed_before_terminal_text(self):
        case=json.loads((FIX/"20_source_completeness_transition_fail_closed.json").read_text())
        self.assertEqual(resolve(case)["assignment_state"],"UNRESOLVED")


if __name__ == "__main__":
    unittest.main()
