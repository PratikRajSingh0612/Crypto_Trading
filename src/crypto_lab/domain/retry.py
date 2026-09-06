"""The immutable retry policy embedded in every experiment specification.

Stage 5 plan section 3.4, under specification sections 11.3, 11.5 and 22.2.1.
``RetryPolicy`` lives in ``domain`` so that ``configuration`` can project onto it
while keeping its single inward dependency on ``domain`` (plan section 2.3). The
sole projection is ``crypto_lab.configuration.retry_policy.retry_policy_from_config``.

Every field is required. Specification section 11.5 says the policy "has no
optional fields" and that its terminal-state collection "is an explicit empty
array when no states are automatically retried". The configuration defaults of
section 22.2.1 -- one attempt, no automatic states, no delay -- belong to
``RetryConfig`` and reach a policy only through the projection, which is what
lets Task 9's generated ``retry-policy-v1`` schema publish all five names as
``required``.

``automatically_retry_terminal_states`` follows the rule the merged
``RetryConfig`` already applies: duplicate and foreign values are rejected, and
accepted members are normalized to the fixed order ``FAILED``, ``TIMED_OUT``,
``UNAVAILABLE`` before hashing (specification 11.5), so a permutation never
changes an experiment's identity. The normalizer is re-expressed here rather
than imported, because ``domain`` may not import ``configuration``.

Task 5 extends this module with the retry-decision record and the six gates.
"""

from __future__ import annotations

from typing import Final, Literal

from pydantic import Field, field_validator

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.lifecycle import RetryTerminalState

MAX_ATTEMPTS_PER_SLOT: Final = 5
MAX_RETRY_DELAY_SECONDS: Final = 300
_RETRY_ORDER: Final = tuple(RetryTerminalState)


def _ordered_retry_terminal_states(value: object) -> tuple[RetryTerminalState, ...]:
    """Reject duplicates and foreign values; return the fixed canonical order."""
    if not isinstance(value, list | tuple):
        raise ValueError("retry states must be an array")
    if not all(isinstance(item, str | RetryTerminalState) for item in value):
        raise ValueError("retry states must be strings")
    try:
        items = tuple(RetryTerminalState(item) for item in value)
    except ValueError as error:
        raise ValueError("retry states contain a foreign value") from error
    if len(set(items)) != len(items):
        raise ValueError("retry states must be unique")
    return tuple(item for item in _RETRY_ORDER if item in items)


class RetryPolicy(CanonicalModel):
    """Specification section 11.3: the immutable bounded automatic-retry policy.

    ``maximum_attempts_per_slot`` counts the initial attempt and every successor
    already created for the slot, so the value ``1`` always disables automatic
    retry (specification 11.5). The fresh-availability requirement for an
    ``UNAVAILABLE`` predecessor is fixed ``true`` in Project 1.
    """

    schema_version: Literal["1.0.0"]
    maximum_attempts_per_slot: int = Field(ge=1, le=MAX_ATTEMPTS_PER_SLOT)
    automatically_retry_terminal_states: tuple[RetryTerminalState, ...] = Field(
        max_length=len(_RETRY_ORDER),
        # Pydantic emits no `uniqueItems` for a tuple; the runtime rule below
        # rejects duplicates, so the published schema must agree.
        json_schema_extra={"uniqueItems": True},
    )
    retry_delay_seconds: int = Field(ge=0, le=MAX_RETRY_DELAY_SECONDS)
    require_fresh_availability_observation_for_unavailable: Literal[True]

    @field_validator("automatically_retry_terminal_states", mode="before")
    @classmethod
    def normalize_retry_states(cls, value: object) -> tuple[RetryTerminalState, ...]:
        return _ordered_retry_terminal_states(value)
