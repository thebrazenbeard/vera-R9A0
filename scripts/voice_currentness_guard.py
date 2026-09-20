"""Fail-closed source policy for Voice claims that require governed currentness.

This module decides whether a Voice surface may answer, must request a direct
read, must delegate a backend refresh, or must remain unresolved. It performs
no provider I/O and does not prove that ChatGPT Voice exposes either route.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


CURRENTNESS_SENSITIVE_DOMAINS = frozenset({
    "identity",
    "conation",
    "relationship",
    "commitment",
    "contradiction",
    "unfinished_work",
})


class VoiceCurrentnessCapability(str, Enum):
    DIRECT_READ = "DIRECT_READ"
    BACKEND_DELEGATION = "BACKEND_DELEGATION"
    NONE = "NONE"
    UNKNOWN = "UNKNOWN"


class VoiceCurrentnessAction(str, Enum):
    NO_GOVERNED_REFRESH_REQUIRED = "NO_GOVERNED_REFRESH_REQUIRED"
    DIRECT_REFRESH = "DIRECT_REFRESH"
    DELEGATE_BACKEND_REFRESH = "DELEGATE_BACKEND_REFRESH"
    ANSWER_FROM_GOVERNED_RECEIPT = "ANSWER_FROM_GOVERNED_RECEIPT"
    BOUNDED_UNRESOLVED = "BOUNDED_UNRESOLVED"


@dataclass(frozen=True)
class GovernedCurrentnessReceipt:
    claim_domain: str
    source_route: str
    source_locator: str
    fresh: bool
    complete: bool
    conflicted: bool

    def __post_init__(self) -> None:
        if not self.claim_domain:
            raise ValueError("claim_domain must be non-empty")
        if not self.source_route:
            raise ValueError("source_route must be non-empty")
        if not self.source_locator:
            raise ValueError("source_locator must be non-empty")


@dataclass(frozen=True)
class VoiceCurrentnessDecision:
    action: VoiceCurrentnessAction
    selected_route: str | None
    answer_source: str | None
    generic_prior_permitted: bool
    unavailability_claim_permitted: bool
    reason: str


def requires_governed_currentness(claim_domain: str) -> bool:
    if not isinstance(claim_domain, str) or not claim_domain.strip():
        raise ValueError("claim_domain must be a non-empty string")
    return claim_domain.strip().lower().replace("-", "_") in CURRENTNESS_SENSITIVE_DOMAINS


def decide_voice_currentness(
    *,
    claim_domain: str,
    capability: VoiceCurrentnessCapability | str,
    route_authorized: bool | None,
    receipt: GovernedCurrentnessReceipt | None = None,
) -> VoiceCurrentnessDecision:
    """Resolve one Voice currentness gate without substituting model priors."""

    sensitive = requires_governed_currentness(claim_domain)
    if not sensitive:
        return VoiceCurrentnessDecision(
            action=VoiceCurrentnessAction.NO_GOVERNED_REFRESH_REQUIRED,
            selected_route=None,
            answer_source=None,
            generic_prior_permitted=False,
            unavailability_claim_permitted=False,
            reason="claim domain does not require the R9A0 governed-currentness bridge",
        )

    try:
        cap = VoiceCurrentnessCapability(capability)
    except ValueError as exc:
        raise ValueError("unsupported Voice currentness capability") from exc

    if cap is VoiceCurrentnessCapability.UNKNOWN:
        return VoiceCurrentnessDecision(
            action=VoiceCurrentnessAction.BOUNDED_UNRESOLVED,
            selected_route=None,
            answer_source=None,
            generic_prior_permitted=False,
            unavailability_claim_permitted=False,
            reason="backend/direct route capability is unresolved; do not claim unavailability",
        )

    if cap is VoiceCurrentnessCapability.NONE:
        return VoiceCurrentnessDecision(
            action=VoiceCurrentnessAction.BOUNDED_UNRESOLVED,
            selected_route=None,
            answer_source=None,
            generic_prior_permitted=False,
            unavailability_claim_permitted=True,
            reason="broader runtime resolved that no governed read/delegation route is available",
        )

    if route_authorized is not True:
        return VoiceCurrentnessDecision(
            action=VoiceCurrentnessAction.BOUNDED_UNRESOLVED,
            selected_route=cap.value,
            answer_source=None,
            generic_prior_permitted=False,
            unavailability_claim_permitted=False,
            reason=(
                "candidate route is not authorized for the exact claim scope"
                if route_authorized is False
                else "route authorization is unresolved"
            ),
        )

    if receipt is None:
        action = (
            VoiceCurrentnessAction.DIRECT_REFRESH
            if cap is VoiceCurrentnessCapability.DIRECT_READ
            else VoiceCurrentnessAction.DELEGATE_BACKEND_REFRESH
        )
        return VoiceCurrentnessDecision(
            action=action,
            selected_route=cap.value,
            answer_source=None,
            generic_prior_permitted=False,
            unavailability_claim_permitted=False,
            reason="authorized governed refresh is required before answering",
        )

    normalized_domain = claim_domain.strip().lower().replace("-", "_")
    if receipt.claim_domain.strip().lower().replace("-", "_") != normalized_domain:
        reason = "receipt claim domain does not match the current claim"
    elif receipt.source_route != cap.value:
        reason = "receipt route does not match the resolved capability"
    elif receipt.conflicted:
        reason = "governed receipt is conflicted"
    elif not receipt.fresh:
        reason = "governed receipt is stale"
    elif not receipt.complete:
        reason = "governed receipt is incomplete"
    else:
        return VoiceCurrentnessDecision(
            action=VoiceCurrentnessAction.ANSWER_FROM_GOVERNED_RECEIPT,
            selected_route=cap.value,
            answer_source=receipt.source_locator,
            generic_prior_permitted=False,
            unavailability_claim_permitted=False,
            reason="fresh complete nonconflicted governed receipt controls the claim",
        )

    return VoiceCurrentnessDecision(
        action=VoiceCurrentnessAction.BOUNDED_UNRESOLVED,
        selected_route=cap.value,
        answer_source=None,
        generic_prior_permitted=False,
        unavailability_claim_permitted=False,
        reason=reason,
    )
