"""Compiled protocol limits and the ``ProtocolLimits`` snapshot (Stage 6 plan
section 3.2).

Every bound the protocol applies is a compiled literal here, so the parsers,
validators and models of later tasks share one ceiling with the request
snapshot the adapter receives (specification 11.5: "share compiled ceilings
with process and artifact readers"). The configuration-derived values are
copied as literals rather than imported, because ``adapters`` may import only
``domain`` (specification 27.1); ``tests/unit/adapters/test_protocol_limits.py``
proves the copies equal to the ``configuration`` bounds.

Declared readings recorded by the plan: ``MAX_DESCRIPTOR_OUTPUT_BYTES`` and
``MAX_VALIDATION_RESULT_BYTES`` reuse the event ceiling because specification
24.3 bounds every output but names no ceiling for those two files;
``MAX_SEQUENCE`` is the published ledger bound specification 11.5 requires;
``RESULT_MANIFEST_RELATIVE_PATH`` fixes the ``--result`` file name directly
under the work directory; ``MIN_RESULT_MANIFEST_BYTES`` and ``MIN_STDERR_BYTES``
are the configuration floors under the plan's ``MIN_EVENT_LINE_BYTES`` naming.

``ProtocolLimits`` is the nested value object the request carries (trust class
K); it has no envelope version (plan 3.1) and no defaults, so every snapshot is
explicit material. ``PROTOCOL_LIMITS_DEFAULT`` is the instance built from the
``ProcessConfig``, ``ProtocolConfig`` and ``LoggingConfig`` defaults.
"""

from __future__ import annotations

from typing import Final, Self

from pydantic import Field, model_validator

from crypto_lab.domain.base import CanonicalModel

#: Specification 10.4: the single protocol version the core supports.
PROTOCOL_VERSION: Final = "1.0.0"
#: Specification 14.7; ``ProtocolConfig.max_event_bytes`` bounds.
MAX_EVENT_LINE_BYTES: Final = 1_048_576
MIN_EVENT_LINE_BYTES: Final = 4_096
#: Specification 14.7; ``ProtocolConfig.max_manifest_bytes`` bounds.
MAX_RESULT_MANIFEST_BYTES: Final = 16_777_216
MIN_RESULT_MANIFEST_BYTES: Final = 65_536
#: Specification 14.7; ``LoggingConfig.max_stderr_bytes_per_invocation`` bounds.
MAX_STDERR_BYTES: Final = 52_428_800
MIN_STDERR_BYTES: Final = 1_048_576
#: Declared reading: the event ceiling reused for the two output files.
MAX_DESCRIPTOR_OUTPUT_BYTES: Final = 1_048_576
MAX_VALIDATION_RESULT_BYTES: Final = 1_048_576
#: Declared reading: the published sequence bound of one invocation's ledger.
MAX_SEQUENCE: Final = 1_000_000
#: Declared readings: collection bounds.
MAX_CANDIDATE_ARTIFACTS: Final = 256
MAX_CANDIDATE_METRICS: Final = 256
#: Mirrors ``domain.command_invocation.MAX_DIAGNOSTIC_IDS`` (asserted equal).
MAX_ADAPTER_DIAGNOSTICS: Final = 64
MAX_WARNINGS: Final = 64
MAX_APPROXIMATIONS: Final = 64
#: Mirrors ``Diagnostic.causal_diagnostic_ids`` (asserted equal).
MAX_CAUSAL_EVENT_IDS: Final = 32
#: Declared reading: exact in JSON number space.
MAX_DECLARED_SIZE_BYTES: Final = 2**53 - 1
MAX_COUNTER: Final = 2**53 - 1
#: Plan section 3.3: the candidate-path grammar bounds.
MAX_RELATIVE_PATH_CHARACTERS: Final = 512
MAX_PATH_SEGMENTS: Final = 32
MAX_SEGMENT_CHARACTERS: Final = 255
#: Plan section 7.6: the escaped contamination sample bound.
MAX_CONTAMINATION_SAMPLE_BYTES: Final = 256
#: ``AdaptersConfig.entries`` bound, copied as a literal.
MAX_CATALOG_ENTRIES: Final = 32
#: Declared reading: the ``--result`` file name directly under the work dir.
RESULT_MANIFEST_RELATIVE_PATH: Final = "adapter-result-manifest.json"
#: ``ProcessConfig`` bounds copied as literals; the threshold is at least twice
#: the interval, enforced by ``ProtocolLimits``.
HEARTBEAT_INTERVAL_BOUNDS: Final[tuple[int, int]] = (1, 300)
MISSING_HEARTBEAT_BOUNDS: Final[tuple[int, int]] = (2, 900)


class ProtocolLimits(CanonicalModel):
    """The protocol limits snapshotted into one request (plan section 3.2).

    A nested value object: no envelope version, every field required, every
    bound the corresponding configuration bound. The missing-heartbeat threshold
    must be at least twice the heartbeat interval (``ProcessConfig`` rule).
    """

    max_event_bytes: int = Field(ge=MIN_EVENT_LINE_BYTES, le=MAX_EVENT_LINE_BYTES)
    max_manifest_bytes: int = Field(
        ge=MIN_RESULT_MANIFEST_BYTES, le=MAX_RESULT_MANIFEST_BYTES
    )
    max_stderr_bytes: int = Field(ge=MIN_STDERR_BYTES, le=MAX_STDERR_BYTES)
    heartbeat_interval_seconds: int = Field(
        ge=HEARTBEAT_INTERVAL_BOUNDS[0], le=HEARTBEAT_INTERVAL_BOUNDS[1]
    )
    missing_heartbeat_seconds: int = Field(
        ge=MISSING_HEARTBEAT_BOUNDS[0], le=MISSING_HEARTBEAT_BOUNDS[1]
    )

    @model_validator(mode="after")
    def validate_heartbeat_ratio(self) -> Self:
        if self.missing_heartbeat_seconds < 2 * self.heartbeat_interval_seconds:
            raise ValueError(
                "missing heartbeat threshold must be at least twice the interval"
            )
        return self


#: The ``ProcessConfig`` (15, 45), ``ProtocolConfig`` and ``LoggingConfig``
#: defaults as one explicit snapshot.
PROTOCOL_LIMITS_DEFAULT: Final = ProtocolLimits(
    max_event_bytes=MAX_EVENT_LINE_BYTES,
    max_manifest_bytes=MAX_RESULT_MANIFEST_BYTES,
    max_stderr_bytes=MAX_STDERR_BYTES,
    heartbeat_interval_seconds=15,
    missing_heartbeat_seconds=45,
)
