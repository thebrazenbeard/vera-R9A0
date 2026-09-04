from __future__ import annotations

import json
import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[2]
PROJECT = ROOT / "project"


def read(name: str) -> str:
    return (PROJECT / name).read_text(encoding="utf-8")


class ProtocolExecutionV2Tests(unittest.TestCase):
    def setUp(self) -> None:
        self.full = read("VERA_R9A0_PROJECT_INSTRUCTIONS.md")
        self.native = read("VERA_R9A0_NATIVE_PROJECT_INSTRUCTIONS.txt")
        self.runtime = read("VERA_R9A0_RUNTIME.md")
        self.governance = read("VERA_R9A0_GOVERNANCE.md")
        self.laws = read("VERA_R9A0_LAWS.md")
        self.contract = json.loads(read("VERA_R9A0_NATIVE_CONTRACT.json"))

    def test_current_specific_assignment_does_not_require_second_lease(self) -> None:
        self.assertIn("without a second bespoke lease", self.full)
        self.assertIn("no second lease", self.native)
        self.assertIn("without a second bespoke lease", self.governance)
        self.assertIn("no second lease", self.laws)

    def test_effect_classes_are_preserved_across_projection_family(self) -> None:
        for text in (self.full, self.native, self.runtime, self.governance, self.laws):
            for token in ("Class 0", "Class 1", "Class 2", "Class 3"):
                # Native compression omits the space by design.
                if text is self.native:
                    self.assertIn(token.replace(" ", ""), text)
                else:
                    self.assertIn(token, text)

    def test_repository_local_stewardship_is_a_real_boundary(self) -> None:
        self.assertIn("Patrick-designated repository-local steward", self.full)
        self.assertIn("repo steward", self.native)
        self.assertIn("repository-local steward", self.runtime)
        self.assertIn("Patrick-designated repository-local steward", self.governance)
        self.assertIn("Patrick-designated repository-local steward", self.laws)

    def test_archived_voss_role_cannot_self_authorize(self) -> None:
        self.assertNotIn("Voss is the designated R9A0 controller role", self.full)
        self.assertNotIn("Voss owns R9A0 routing", self.governance)
        self.assertIn("including Voss, grant no current authority", self.full)
        self.assertIn("including Voss, grant no current authority", self.governance)
        self.assertIn("including Voss, grant no current authority", self.laws)

    def test_old_universal_writer_lease_phrasing_is_absent(self) -> None:
        self.assertNotIn(
            "The implementation writer is whichever role holds the fresh exact branch and path writer lease",
            self.full,
        )
        self.assertNotIn(
            "Verify the writer lease and immutable head when implementation is involved",
            self.runtime,
        )
        self.assertNotIn(
            "active implementation writer is whichever role holds the exact current repository/branch/path writer lease",
            self.governance,
        )

    def test_lease_and_action_consumption_remain_separate_in_native_contract(self) -> None:
        self.assertIs(
            self.contract["assignment_currentness"]["capability_lease_action_consumption_separate"],
            True,
        )

    def test_correction_performs_still_current_blocked_act(self) -> None:
        self.assertIn("complete that act before explaining the old mistake", self.runtime)
        self.assertIn("correction completes still-current blocked act before explanation", self.native)

    def test_good_enough_rule_blocks_perfection_paralysis(self) -> None:
        self.assertIn("no unresolved HIGH/MEDIUM defects", self.full if "no unresolved HIGH/MEDIUM defects" in self.full else self.runtime)
        self.assertIn("PASS+H/M=0", self.native)
        self.assertIn("HIGH/MEDIUM", self.laws)

    def test_native_projection_stays_within_accepted_budget(self) -> None:
        accepted = int(self.contract["native_instructions"]["accepted_max_characters"])
        self.assertLessEqual(len(self.native), accepted)


if __name__ == "__main__":
    unittest.main()
