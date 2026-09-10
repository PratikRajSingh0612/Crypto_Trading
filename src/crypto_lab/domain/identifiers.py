"""Validated canonical identifiers and normalized names."""

from __future__ import annotations

from typing import Annotated
from uuid import UUID

from pydantic import AfterValidator, StringConstraints, WithJsonSchema
from pydantic.json_schema import JsonSchemaValue

_UUID4 = r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}"


def exact_string_schema(
    runtime_pattern: str,
    *,
    min_length: int | None = None,
    max_length: int | None = None,
) -> JsonSchemaValue:
    """Return a string schema whose pattern has an absolute ECMA-compatible end."""
    if not runtime_pattern.endswith("$"):
        raise ValueError("runtime pattern must end with '$'")
    schema: JsonSchemaValue = {
        "type": "string",
        "pattern": runtime_pattern[:-1] + r"(?![\s\S])",
    }
    if min_length is not None:
        schema["minLength"] = min_length
    if max_length is not None:
        schema["maxLength"] = max_length
    return schema


def validate_prefixed_uuid4(value: str, prefix: str) -> str:
    """Return one exact lowercase canonical prefixed UUID4."""
    if not value.startswith(prefix):
        raise ValueError(f"identifier must start with {prefix!r}")
    suffix = value.removeprefix(prefix)
    parsed = UUID(suffix)
    if parsed.version != 4 or str(parsed) != suffix:
        raise ValueError("identifier must contain a lowercase canonical UUID4")
    return value


def _experiment_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "exp_")


def _run_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "run_")


def _artifact_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "art_")


def _dataset_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "ds_")


def _strategy_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "strat_")


def _strategy_version_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "strv_")


def _invocation_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "inv_")


def _event_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "evt_")


def _candidate_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "cand_")


def _diagnostic_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "diag_")


def _audit_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "audit_")


def _partition_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "part_")


def _approximation_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "appx_")


def _availability_observation_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "avail_")


def _logical_slot_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "slot_")


def _request_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "req_")


def _adapter_manifest_id(value: str) -> str:
    return validate_prefixed_uuid4(value, "amf_")


type ExperimentId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^exp_{_UUID4}$"),
    AfterValidator(_experiment_id),
    WithJsonSchema(exact_string_schema(rf"^exp_{_UUID4}$")),
]
type RunId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^run_{_UUID4}$"),
    AfterValidator(_run_id),
    WithJsonSchema(exact_string_schema(rf"^run_{_UUID4}$")),
]
type ArtifactId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^art_{_UUID4}$"),
    AfterValidator(_artifact_id),
    WithJsonSchema(exact_string_schema(rf"^art_{_UUID4}$")),
]
type DatasetId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^ds_{_UUID4}$"),
    AfterValidator(_dataset_id),
    WithJsonSchema(exact_string_schema(rf"^ds_{_UUID4}$")),
]
type StrategyId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^strat_{_UUID4}$"),
    AfterValidator(_strategy_id),
    WithJsonSchema(exact_string_schema(rf"^strat_{_UUID4}$")),
]
type StrategyVersionId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^strv_{_UUID4}$"),
    AfterValidator(_strategy_version_id),
    WithJsonSchema(exact_string_schema(rf"^strv_{_UUID4}$")),
]
type InvocationId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^inv_{_UUID4}$"),
    AfterValidator(_invocation_id),
    WithJsonSchema(exact_string_schema(rf"^inv_{_UUID4}$")),
]
type EventId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^evt_{_UUID4}$"),
    AfterValidator(_event_id),
    WithJsonSchema(exact_string_schema(rf"^evt_{_UUID4}$")),
]
type CandidateArtifactId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^cand_{_UUID4}$"),
    AfterValidator(_candidate_id),
    WithJsonSchema(exact_string_schema(rf"^cand_{_UUID4}$")),
]
type DiagnosticId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^diag_{_UUID4}$"),
    AfterValidator(_diagnostic_id),
    WithJsonSchema(exact_string_schema(rf"^diag_{_UUID4}$")),
]
type AuditEventId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^audit_{_UUID4}$"),
    AfterValidator(_audit_id),
    WithJsonSchema(exact_string_schema(rf"^audit_{_UUID4}$")),
]
type DatasetPartitionId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^part_{_UUID4}$"),
    AfterValidator(_partition_id),
    WithJsonSchema(exact_string_schema(rf"^part_{_UUID4}$")),
]
type ApproximationId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^appx_{_UUID4}$"),
    AfterValidator(_approximation_id),
    WithJsonSchema(exact_string_schema(rf"^appx_{_UUID4}$")),
]
type AvailabilityObservationId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^avail_{_UUID4}$"),
    AfterValidator(_availability_observation_id),
    WithJsonSchema(exact_string_schema(rf"^avail_{_UUID4}$")),
]
type LogicalSlotId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^slot_{_UUID4}$"),
    AfterValidator(_logical_slot_id),
    WithJsonSchema(exact_string_schema(rf"^slot_{_UUID4}$")),
]
#: Stage 6 plan section 4: derived by ``request_id_for`` in ``domain/hashing.py``
#: from the run or describe-invocation anchor, never drawn.
type RequestId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^req_{_UUID4}$"),
    AfterValidator(_request_id),
    WithJsonSchema(exact_string_schema(rf"^req_{_UUID4}$")),
]
#: Stage 6 plan section 4: adapter-minted and format-checked only.
type AdapterManifestId = Annotated[
    str,
    StringConstraints(strict=True, pattern=rf"^amf_{_UUID4}$"),
    AfterValidator(_adapter_manifest_id),
    WithJsonSchema(exact_string_schema(rf"^amf_{_UUID4}$")),
]
type Sha256 = Annotated[
    str,
    StringConstraints(strict=True, pattern=r"^[0-9a-f]{64}$"),
    WithJsonSchema(exact_string_schema(r"^[0-9a-f]{64}$")),
]
type NormalizedIdentifier = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
    ),
    WithJsonSchema(
        exact_string_schema(
            r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$",
            min_length=1,
            max_length=128,
        )
    ),
]
type AssetCode = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=32,
        pattern=r"^[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*$",
    ),
    WithJsonSchema(
        exact_string_schema(
            r"^[A-Z][A-Z0-9]*(?:[._-][A-Z0-9]+)*$",
            min_length=1,
            max_length=32,
        )
    ),
]

_URL_SAFE_PATTERN = r"^[A-Za-z0-9_-]+$"
_CORRELATION_ID_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._:-]*$"

#: The raw attempt token of one run attempt (Stage 5 plan section 3.3).
#: Temporary sensitive correlation material: it is hashed by
#: ``attempt_token_hash`` before it reaches any persisted record and is never a
#: field of one, so no registered schema for a persisted record publishes this
#: projection; the three temporary wire contracts of Stage 6 do.
type AttemptToken = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=32,
        max_length=1024,
        pattern=_URL_SAFE_PATTERN,
    ),
    WithJsonSchema(
        exact_string_schema(
            _URL_SAFE_PATTERN,
            min_length=32,
            max_length=1024,
        )
    ),
]
#: The same constraints as the ``artifacts.ownership`` alias of the same name,
#: defined separately because ``domain`` may not import ``artifacts``.
type CorrelationId = Annotated[
    str,
    StringConstraints(
        strict=True,
        min_length=1,
        max_length=128,
        pattern=_CORRELATION_ID_PATTERN,
    ),
    WithJsonSchema(
        exact_string_schema(
            _CORRELATION_ID_PATTERN,
            min_length=1,
            max_length=128,
        )
    ),
]
