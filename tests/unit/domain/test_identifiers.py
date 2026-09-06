from __future__ import annotations

import pytest
from jsonschema import Draft202012Validator
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError
from pydantic import TypeAdapter, ValidationError

from crypto_lab.domain.identifiers import (
    ArtifactId,
    AssetCode,
    AttemptToken,
    AuditEventId,
    CandidateArtifactId,
    CorrelationId,
    DatasetId,
    DatasetPartitionId,
    DiagnosticId,
    EventId,
    ExperimentId,
    InvocationId,
    LogicalSlotId,
    NormalizedIdentifier,
    RunId,
    Sha256,
    StrategyId,
    StrategyVersionId,
)

_UUID4 = "12345678-1234-4234-8234-123456789abc"
_ID_CASES: list[tuple[TypeAdapter[str], str]] = [
    (TypeAdapter(ExperimentId), "exp_"),
    (TypeAdapter(RunId), "run_"),
    (TypeAdapter(ArtifactId), "art_"),
    (TypeAdapter(DatasetId), "ds_"),
    (TypeAdapter(StrategyId), "strat_"),
    (TypeAdapter(StrategyVersionId), "strv_"),
    (TypeAdapter(InvocationId), "inv_"),
    (TypeAdapter(EventId), "evt_"),
    (TypeAdapter(CandidateArtifactId), "cand_"),
    (TypeAdapter(DiagnosticId), "diag_"),
    (TypeAdapter(AuditEventId), "audit_"),
    (TypeAdapter(DatasetPartitionId), "part_"),
    (TypeAdapter(LogicalSlotId), "slot_"),
]


@pytest.mark.parametrize(("adapter", "prefix"), _ID_CASES)
def test_prefixed_uuid4_alias_accepts_only_its_canonical_family(
    adapter: TypeAdapter[str],
    prefix: str,
) -> None:
    value = f"{prefix}{_UUID4}"
    assert adapter.validate_python(value) == value
    for invalid in (
        f"wrong_{_UUID4}",
        f"{prefix}12345678-1234-1234-8234-123456789abc",
        f"{prefix}00000000-0000-0000-0000-000000000000",
        f"{prefix}{_UUID4.upper()}",
        f"{prefix}{{{_UUID4}}}",
        _UUID4,
        f" {value}",
        f"{value} ",
    ):
        with pytest.raises(ValidationError):
            adapter.validate_python(invalid)


@pytest.mark.parametrize(
    ("adapter", "valid", "invalid"),
    [
        (
            TypeAdapter(Sha256),
            "a" * 64,
            ("A" * 64, "a" * 63, "g" * 64, " " + "a" * 64),
        ),
        (
            TypeAdapter(NormalizedIdentifier),
            "schema.registry-v1",
            ("Schema", "two words", "", "_leading", "trailing_"),
        ),
        (
            TypeAdapter(AssetCode),
            "BTC.USDT-V1",
            ("btc", "two words", "", "_BTC", "BTC!"),
        ),
        (
            # Temporary sensitive correlation material: 32-1024 URL-safe characters.
            TypeAdapter(AttemptToken),
            "A1b2C3d4E5f6G7h8-_" + "z" * 14,
            (
                "a" * 31,
                "a" * 1025,
                "",
                "a" * 31 + " ",
                "a" * 31 + "!",
                " " + "a" * 32,
                "a" * 16 + "." + "a" * 16,
            ),
        ),
        (
            # The same constraints as the `artifacts.ownership` alias, defined
            # separately because `domain` may not import `artifacts`.
            TypeAdapter(CorrelationId),
            "stage5.task1:run-1",
            (
                "",
                ".leading",
                "-leading",
                ":leading",
                "_leading",
                "two words",
                "a" * 129,
                "slash/ed",
            ),
        ),
    ],
)
def test_constrained_string_aliases(
    adapter: TypeAdapter[str],
    valid: str,
    invalid: tuple[str, ...],
) -> None:
    assert adapter.validate_python(valid) == valid
    for value in invalid:
        with pytest.raises(ValidationError):
            adapter.validate_python(value)
    with pytest.raises(ValidationError):
        adapter.validate_python(1)


@pytest.mark.parametrize(
    ("adapter", "valid"),
    [
        *((adapter, f"{prefix}{_UUID4}") for adapter, prefix in _ID_CASES),
        (TypeAdapter(Sha256), "a" * 64),
        (TypeAdapter(NormalizedIdentifier), "schema.registry-v1"),
        (TypeAdapter(AssetCode), "BTC.USDT-V1"),
        (TypeAdapter(AttemptToken), "a" * 32),
        (TypeAdapter(CorrelationId), "stage5.task1:run-1"),
    ],
)
def test_identifier_schemas_reject_terminal_newline(
    adapter: TypeAdapter[str],
    valid: str,
) -> None:
    schemas = (
        adapter.json_schema(mode="validation"),
        adapter.json_schema(mode="serialization"),
    )
    for schema in schemas:
        assert schema["pattern"].endswith(r"(?![\s\S])")
        validator = Draft202012Validator(schema)
        validator.validate(valid)
        for terminator in ("\n", "\r", "\r\n"):
            with pytest.raises(ValidationError):
                adapter.validate_python(valid + terminator)
            with pytest.raises(JsonSchemaValidationError):
                validator.validate(valid + terminator)
