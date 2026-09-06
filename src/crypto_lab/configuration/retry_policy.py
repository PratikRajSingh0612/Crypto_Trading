"""The sole projection from configuration onto the domain retry policy.

Stage 5 plan section 3.4: ``retry_policy_from_config`` is the only place where
configuration values become a ``RetryPolicy``. Specification sections 16.2 and
22.2.1 require the configuration-derived policy and the one embedded in
``ExperimentSpec.retry_policy`` to be byte-equivalent after canonical
normalization before an experiment is queued; ``assert_queue_freeze`` (plan
section 7 check 2) compares exactly the bytes this projection produces.

``RetryConfig`` has already rejected duplicate and foreign terminal states and
normalized their order, and ``RetryPolicy`` applies the same rule on its own
side, so the projection is a field-for-field copy that adds the envelope
version. It is the configuration package's only edge into ``crypto_lab.domain.retry``,
in the permitted ``configuration -> domain`` direction (specification 27.1).
"""

from __future__ import annotations

from crypto_lab.configuration.models import RetryConfig
from crypto_lab.domain.retry import RetryPolicy


def retry_policy_from_config(retry: RetryConfig) -> RetryPolicy:
    """Project the strict ``scheduler.retry`` object onto ``RetryPolicy``."""
    return RetryPolicy(
        schema_version="1.0.0",
        maximum_attempts_per_slot=retry.maximum_attempts_per_slot,
        automatically_retry_terminal_states=retry.automatically_retry_terminal_states,
        retry_delay_seconds=retry.retry_delay_seconds,
        require_fresh_availability_observation_for_unavailable=(
            retry.require_fresh_availability_observation_for_unavailable
        ),
    )
