from __future__ import annotations

import unittest

from scripts.voice_currentness_guard import (
    CURRENTNESS_SENSITIVE_DOMAINS,
    GovernedCurrentnessReceipt,
    VoiceCurrentnessAction,
    VoiceCurrentnessCapability,
    decide_voice_currentness,
    requires_governed_currentness,
)


class VoiceCurrentnessGuardTests(unittest.TestCase):
    def receipt(self, **overrides):
        values = dict(
            claim_domain="relationship",
            source_route="BACKEND_DELEGATION",
            source_locator="synthetic://governed-state/relationship/current",
            fresh=True,
            complete=True,
            conflicted=False,
        )
        values.update(overrides)
        return GovernedCurrentnessReceipt(**values)

    def test_required_currentness_trigger_family_is_explicit(self):
        self.assertEqual(
            CURRENTNESS_SENSITIVE_DOMAINS,
            frozenset({
                "identity", "conation", "relationship",
                "commitment", "contradiction", "unfinished_work",
            }),
        )
        for domain in CURRENTNESS_SENSITIVE_DOMAINS:
            self.assertTrue(requires_governed_currentness(domain))

    def test_stale_voice_context_with_authorized_backend_requires_delegation(self):
        decision = decide_voice_currentness(
            claim_domain="relationship",
            capability=VoiceCurrentnessCapability.BACKEND_DELEGATION,
            route_authorized=True,
            receipt=None,
        )
        self.assertEqual(VoiceCurrentnessAction.DELEGATE_BACKEND_REFRESH, decision.action)
        self.assertFalse(decision.generic_prior_permitted)
        self.assertFalse(decision.unavailability_claim_permitted)

    def test_missing_direct_connector_does_not_mean_backend_is_unavailable(self):
        decision = decide_voice_currentness(
            claim_domain="identity",
            capability=VoiceCurrentnessCapability.UNKNOWN,
            route_authorized=None,
        )
        self.assertEqual(VoiceCurrentnessAction.BOUNDED_UNRESOLVED, decision.action)
        self.assertFalse(decision.unavailability_claim_permitted)
        self.assertIn("do not claim unavailability", decision.reason)

    def test_resolved_none_fails_closed_without_generic_prior(self):
        decision = decide_voice_currentness(
            claim_domain="conation",
            capability=VoiceCurrentnessCapability.NONE,
            route_authorized=None,
        )
        self.assertEqual(VoiceCurrentnessAction.BOUNDED_UNRESOLVED, decision.action)
        self.assertFalse(decision.generic_prior_permitted)
        self.assertTrue(decision.unavailability_claim_permitted)

    def test_capability_does_not_grant_route_authority(self):
        decision = decide_voice_currentness(
            claim_domain="commitment",
            capability=VoiceCurrentnessCapability.BACKEND_DELEGATION,
            route_authorized=False,
        )
        self.assertEqual(VoiceCurrentnessAction.BOUNDED_UNRESOLVED, decision.action)
        self.assertEqual("BACKEND_DELEGATION", decision.selected_route)
        self.assertIn("not authorized", decision.reason)

    def test_fresh_backend_receipt_controls_over_local_voice_prior(self):
        decision = decide_voice_currentness(
            claim_domain="relationship",
            capability=VoiceCurrentnessCapability.BACKEND_DELEGATION,
            route_authorized=True,
            receipt=self.receipt(),
        )
        self.assertEqual(VoiceCurrentnessAction.ANSWER_FROM_GOVERNED_RECEIPT, decision.action)
        self.assertEqual(
            "synthetic://governed-state/relationship/current",
            decision.answer_source,
        )
        self.assertFalse(decision.generic_prior_permitted)

    def test_stale_incomplete_conflicted_or_wrong_receipt_fails_closed(self):
        cases = (
            self.receipt(fresh=False),
            self.receipt(complete=False),
            self.receipt(conflicted=True),
            self.receipt(claim_domain="identity"),
            self.receipt(source_route="DIRECT_READ"),
        )
        for receipt in cases:
            with self.subTest(receipt=receipt):
                decision = decide_voice_currentness(
                    claim_domain="relationship",
                    capability=VoiceCurrentnessCapability.BACKEND_DELEGATION,
                    route_authorized=True,
                    receipt=receipt,
                )
                self.assertEqual(VoiceCurrentnessAction.BOUNDED_UNRESOLVED, decision.action)
                self.assertFalse(decision.generic_prior_permitted)

    def test_direct_read_route_requests_direct_refresh(self):
        decision = decide_voice_currentness(
            claim_domain="contradiction",
            capability=VoiceCurrentnessCapability.DIRECT_READ,
            route_authorized=True,
        )
        self.assertEqual(VoiceCurrentnessAction.DIRECT_REFRESH, decision.action)

    def test_non_currentness_domain_does_not_invent_a_refresh_dependency(self):
        decision = decide_voice_currentness(
            claim_domain="general_fact",
            capability=VoiceCurrentnessCapability.UNKNOWN,
            route_authorized=None,
        )
        self.assertEqual(
            VoiceCurrentnessAction.NO_GOVERNED_REFRESH_REQUIRED,
            decision.action,
        )


if __name__ == "__main__":
    unittest.main()
