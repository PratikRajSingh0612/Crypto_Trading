"""One correlation context across a local command.

Specification 30.2: one correlation context follows a local command through
the experiment service, repository transactions, process supervision, event
ingestion, artifact finalization, diagnostics and audit events. The type is
``CorrelationContext`` and its instances are named ``correlation_scope``
because the Stage 4 bare-name scan forbids ``context`` as an identifier (plan
2.6 "Bare-name and text scans").

``derive`` narrows and never widens: it adds identifiers that were absent,
accepts a present identifier restated with the same value, and refuses to
replace a present identifier with a different one, to remove one, or to touch
anything but the three narrowing identifiers. ``event`` stamps the scope's
identifiers onto a new ``AuditEvent`` through the injected clock and identity
source; the model's own refusals (an invocation-requiring action without an
invocation, details outside the redaction fixed point) propagate unchanged.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Final, Self

from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.audit.models import (
    CORE_ACTOR,
    AuditAction,
    AuditActor,
    AuditEvent,
    AuditOutcome,
    audit_details_hash,
)
from crypto_lab.audit.sink import AuditEventIds
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.diagnostics import DiagnosticDetailValue
from crypto_lab.domain.identifiers import (
    ArtifactId,
    CorrelationId,
    ExperimentId,
    InvocationId,
    RunId,
)
from crypto_lab.domain.ports import Clock

_NARROWING_IDENTIFIERS: Final = ("experiment_id", "run_id", "invocation_id")


class CorrelationContext(CanonicalModel):
    """The correlation identifier and the identifiers narrowed so far."""

    correlation_id: CorrelationId
    experiment_id: ExperimentId | MISSING = MISSING  # type: ignore[valid-type]
    run_id: RunId | MISSING = MISSING  # type: ignore[valid-type]
    invocation_id: InvocationId | MISSING = MISSING  # type: ignore[valid-type]

    def _present_identifiers(self) -> dict[str, str]:
        present: dict[str, str] = {}
        for name in _NARROWING_IDENTIFIERS:
            value = getattr(self, name)
            if isinstance(value, str):
                present[name] = value
        return present

    def derive(self, **narrower: str) -> Self:
        """Return the scope narrowed by ``narrower``; never widened or rekeyed."""
        for name in narrower:
            if name not in _NARROWING_IDENTIFIERS:
                raise ValueError(f"{name} is not a narrowing identifier")
        merged = self._present_identifiers()
        for name, value in narrower.items():
            if not isinstance(value, str):
                raise ValueError("derive only adds identifiers; it never removes one")
            current = merged.get(name)
            if current is not None and current != value:
                raise ValueError(
                    f"derive refuses the conflicting replacement of {name}"
                )
            merged[name] = value
        return type(self)(correlation_id=self.correlation_id, **merged)

    def event(
        self,
        action: AuditAction,
        outcome: AuditOutcome,
        details: Mapping[str, DiagnosticDetailValue],
        *,
        clock: Clock,
        ids: AuditEventIds,
        actor: AuditActor = CORE_ACTOR,
        artifact_id: ArtifactId | MISSING = MISSING,  # type: ignore[valid-type]
    ) -> AuditEvent:
        """Build the audit event of one action under this scope."""
        payload: dict[str, object] = {
            "schema_version": "1.0.0",
            "audit_event_id": ids.new_audit_event_id(),
            "action": action,
            "actor": actor,
            "outcome": outcome,
            **self._present_identifiers(),
            "timestamp_utc": clock.now_utc(),
            "correlation_id": self.correlation_id,
            "details_hash": audit_details_hash(details),
            "details": dict(details),
        }
        if isinstance(artifact_id, str):
            payload["artifact_id"] = artifact_id
        return AuditEvent.model_validate(payload)


__all__ = ("CorrelationContext",)
