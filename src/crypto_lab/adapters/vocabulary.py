"""The closed Stage 6 protocol vocabularies (Stage 6 plan section 3.4) and the
negotiable schema names (plan section 5.2).

Every enum is a ``StrEnum`` whose values equal its member names. Specification
section 11.1 fixes uppercase serialization for enums, so the lower-case labels
of the section 14.4 event table (``heartbeat``, ``artifact_produced``) are read
as labels and serialized as ``HEARTBEAT`` and ``ARTIFACT_PRODUCED``; that is
the plan's declared reading, asserted member by member in
``tests/unit/adapters/test_protocol_vocabulary.py``.

``SemanticStatus`` and ``ValidationOutcome`` are the specification 11.5 enums.
``ProtocolIntegrityStatus`` names specification 14.1's protocol-integrity
status, ``NegotiationOutcome`` the two outcomes of 14.2, and
``ReconciliationVerdict`` the seven verdicts of plan section 9.3.
``AdapterDiagnosticCategory`` is the closed subset of ``DiagnosticCategory``
an adapter may claim (plan section 3.9); every other category is core-owned,
and a wire diagnostic naming one is a schema failure rather than a claim.

``NEGOTIABLE_SCHEMA_NAMES`` lives here so that Task 2's ``NegotiatedVersions``
and Task 3's ``CoreProtocolSupport`` consume one constant without a cycle. The
descriptor is the registered Stage 3 entry; the other four are Stage 6 Task 9
entries. Each maps to ``urn:crypto-lab:schema:protocol:<name>:1.0.0``, where
``<name>`` is the schema name without its ``protocol.`` prefix.
"""

from __future__ import annotations

from enum import StrEnum
from typing import Final


class SemanticStatus(StrEnum):
    """Specification section 11.5: the adapter's declared semantic status."""

    SUCCEEDED = "SUCCEEDED"
    SUCCEEDED_WITH_WARNINGS = "SUCCEEDED_WITH_WARNINGS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"


class ValidationOutcome(StrEnum):
    """Specification section 11.5: the outcome of the ``validate`` command."""

    VALID = "VALID"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"
    INVALID = "INVALID"


class ProtocolEventType(StrEnum):
    """Specification section 14.4: the six stdout event types, uppercase."""

    HEARTBEAT = "HEARTBEAT"
    PROGRESS = "PROGRESS"
    WARNING = "WARNING"
    DIAGNOSTIC = "DIAGNOSTIC"
    ARTIFACT_PRODUCED = "ARTIFACT_PRODUCED"
    FINAL_RESULT = "FINAL_RESULT"


class NegotiationOutcome(StrEnum):
    """Specification section 14.2: negotiation selects or fails closed."""

    NEGOTIATED = "NEGOTIATED"
    FAILED = "FAILED"


class ProtocolIntegrityStatus(StrEnum):
    """Specification section 14.1: whether the stdout protocol stayed trusted."""

    INTACT = "INTACT"
    VIOLATED = "VIOLATED"


class ReconciliationVerdict(StrEnum):
    """Stage 6 plan section 9.3: the verdict of one command reconciliation."""

    DESCRIBED = "DESCRIBED"
    DESCRIBE_UNAVAILABLE = "DESCRIBE_UNAVAILABLE"
    VALIDATED_READY = "VALIDATED_READY"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"
    RESULT_FINALIZATION_ELIGIBLE = "RESULT_FINALIZATION_ELIGIBLE"


class AdapterDiagnosticCategory(StrEnum):
    """Stage 6 plan section 3.9: the three categories an adapter may claim."""

    ENGINE_RUNTIME = "ENGINE_RUNTIME"
    ADAPTER_UNAVAILABILITY = "ADAPTER_UNAVAILABILITY"
    COMPATIBILITY = "COMPATIBILITY"


#: Stage 6 plan section 5.2. Sorted, because every collection that carries these
#: names (``NegotiatedVersions.schema_versions``, ``CoreProtocolSupport``) is a
#: sorted ``SupportedSchemaVersion`` tuple and the listed order has no meaning.
NEGOTIABLE_SCHEMA_NAMES: Final[tuple[str, ...]] = (
    "protocol.adapter-command-request-envelope",
    "protocol.adapter-descriptor",
    "protocol.adapter-result-manifest",
    "protocol.adapter-validation-result",
    "protocol.protocol-event-envelope",
)
