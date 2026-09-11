"""Stage 6 Task 5: validation results, result manifests and the sanitized manifest
(plan sections 3.10, 3.11, 4, 8, 12.4, 13; specification 10.2, 11.3, 11.5, 14.1,
14.7, 15.7, 19.4, 21.2.1).

The token-free ``AdapterValidationResult`` and its exact-byte ``result_hash``, the
permissive ``OutputHeader`` and the two typed parse outcomes, the token-bearing
``AdapterResultManifest`` with its status coupling, the two byte-level parsers
(ceiling before decoding, strict UTF-8, repeated keys, the header, the version
check, redaction before strict validation, the path-located classification), the
core-derived ``SanitizedAdapterResultManifest`` with its ``SANITIZED_ADAPTER_RESULT_
MANIFEST_V1`` identity, and every parser never raising on adapter-controlled bytes.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Final, Literal, Never, get_args

import pytest
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab import adapters as adapters_package
from crypto_lab.adapters import manifests
from crypto_lab.adapters.diagnostics import (
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_RESULT_MANIFEST_INVALID,
    PROTOCOL_UNSUPPORTED_VERSION,
    PROTOCOL_VALIDATION_RESULT_INVALID,
)
from crypto_lab.adapters.envelopes import NegotiatedVersions
from crypto_lab.adapters.events import (
    AdapterDiagnostic,
    ArtifactDeclarationRecord,
    ArtifactProducedPayload,
    ProtocolEventSummary,
    ProtocolWarning,
)
from crypto_lab.adapters.limits import (
    MAX_ADAPTER_DIAGNOSTICS,
    MAX_APPROXIMATIONS,
    MAX_CANDIDATE_ARTIFACTS,
    MAX_CANDIDATE_METRICS,
    MAX_RESULT_MANIFEST_BYTES,
    MAX_VALIDATION_RESULT_BYTES,
    MAX_WARNINGS,
)
from crypto_lab.adapters.manifests import (
    AdapterResultManifest,
    AdapterValidationResult,
    CandidateArtifactDeclaration,
    CandidateMetric,
    ManifestParse,
    OutputHeader,
    RunProvenance,
    SanitizedAdapterResultManifest,
    SanitizedCandidateArtifactDeclaration,
    ValidationResultParse,
    parse_result_manifest,
    parse_validation_result,
    redact_validation_result,
    sanitize_result_manifest,
    sanitized_manifest_hash,
    validation_result_hash,
)
from crypto_lab.adapters.sanitization import REDACTION_PLACEHOLDER
from crypto_lab.adapters.vocabulary import (
    NEGOTIABLE_SCHEMA_NAMES,
    SemanticStatus,
    ValidationOutcome,
)
from crypto_lab.domain.base import SCHEMA_VERSION
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.descriptors import SupportedSchemaVersion
from crypto_lab.domain.hashing import (
    HashingProfile,
    _uuid4_shaped,
    attempt_token_hash,
    candidate_artifact_id_for,
    request_id_for,
    sha256_bytes,
)
from doubles.experiments import (
    ATTEMPT_TOKEN,
    DATASET_HASH,
    EXPERIMENT_ID,
    INVOCATION_ID,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    REQUEST_HASH,
    RUN_ID,
    SLOT_A,
    STRATEGY_HASH,
)

_MODES: Final[tuple[Literal["python", "json"], ...]] = ("python", "json")
_STARTED: Final = "2026-09-11T10:00:00Z"
_COMPLETED: Final = "2026-09-11T10:05:00Z"
_HASH: Final = "a" * 64
_OTHER_HASH: Final = "b" * 64
_SPEC_HASH: Final = "3" * 64
_CONFIGURATION_HASH: Final = "4" * 64
#: A token that is also a valid lowercase identifier and a valid path segment (plan
#: 7.4: "a token drawn from the letter-leading subset of the AttemptToken grammar");
#: no hex digit, so it never occurs inside a fixture hash.
_IDENTIFIER_TOKEN: Final = "z" * 32
_WRONG_TOKEN: Final = "B" * 32
#: An all-digit token, which a JSON document can spell as a number.
_DIGIT_TOKEN: Final = "9" * 32
_TOKEN_HASH: Final = attempt_token_hash(ATTEMPT_TOKEN)
_REQUEST_ID: Final = request_id_for(RUN_ID)
_STAGE4_BARE_NAMES: Final = frozenset(
    {"buffer", "context", "note", "problem", "compose", "Loader", "get_snippet"}
)
_PURE_ROOTS: Final = frozenset(
    {"__future__", "json", "typing", "pydantic", "crypto_lab"}
)
_VALIDATION_CODES: Final = frozenset(
    {PROTOCOL_VALIDATION_RESULT_INVALID, PROTOCOL_UNSUPPORTED_VERSION}
)
_MANIFEST_CODES: Final = frozenset(
    {
        ARTIFACT_RESULT_MANIFEST_INVALID,
        PROTOCOL_UNSUPPORTED_VERSION,
        ARTIFACT_PATH_BOUNDARY_VIOLATION,
    }
)
_NON_SUCCESS: Final = (
    SemanticStatus.FAILED,
    SemanticStatus.CANCELLED,
    SemanticStatus.TIMED_OUT,
    SemanticStatus.NOT_APPLICABLE,
    SemanticStatus.UNAVAILABLE,
)
#: Plan section 14 Task 5: the Task 5 public surface of ``crypto_lab.adapters``.
_TASK5_EXPORTS: Final = frozenset(
    {
        "AdapterResultManifest",
        "AdapterValidationResult",
        "CandidateArtifactDeclaration",
        "CandidateMetric",
        "ManifestParse",
        "OutputHeader",
        "RunProvenance",
        "SanitizedAdapterResultManifest",
        "SanitizedCandidateArtifactDeclaration",
        "ValidationResultParse",
        "parse_result_manifest",
        "parse_validation_result",
        "redact_validation_result",
        "sanitize_result_manifest",
        "sanitized_manifest_hash",
        "validation_result_hash",
    }
)
_VALIDATION_FIELDS: Final = (
    "schema_version",
    "protocol_version",
    "request_id",
    "invocation_id",
    "run_id",
    "attempt_token_hash",
    "outcome",
    "diagnostics",
    "validated_at_utc",
    "result_hash",
)
_PROVENANCE_FIELDS: Final = (
    "experiment_spec_hash",
    "request_hash",
    "strategy_version_hash",
    "dataset_version_hash",
    "configuration_hash",
    "adapter",
    "engine",
    "negotiated_versions",
    "comparison_level",
    "logical_slot_id",
    "attempt_number",
)
_DECLARATION_FIELDS: Final = (
    "relative_path",
    "artifact_kind",
    "media_type",
    "declared_size_bytes",
    "declared_sha256",
)
_METRIC_FIELDS: Final = (
    "metric_name",
    "value",
    "value_status",
    "unit",
    "methodology_version",
    "comparison_level",
)
_MANIFEST_FIELDS: Final = (
    "schema_version",
    "protocol_version",
    "adapter_manifest_id",
    "experiment_id",
    "run_id",
    "invocation_id",
    "attempt_token",
    "semantic_status",
    "started_at_utc",
    "completed_at_utc",
    "provenance",
    "candidate_artifacts",
    "candidate_metrics",
    "diagnostics",
    "warnings",
    "approximations",
)
_SANITIZED_DECLARATION_FIELDS: Final = (
    "candidate_artifact_id",
    "source_event_id",
    "artifact_kind",
    "media_type",
    "declared_size_bytes",
    "declared_sha256",
)
_SANITIZED_FIELDS: Final = (
    "schema_version",
    "protocol_version",
    "adapter_manifest_id",
    "experiment_id",
    "run_id",
    "invocation_id",
    "attempt_token_hash",
    "semantic_status",
    "started_at_utc",
    "completed_at_utc",
    "provenance",
    "candidate_artifact_ids",
    "candidate_declarations",
    "candidate_metrics",
    "diagnostics",
    "warnings",
    "approximations",
    "source_adapter_result_manifest_hash",
    "sanitized_adapter_result_manifest_hash",
)
_HEADER_FIELDS: Final = (
    "protocol_version",
    "schema_version",
    "invocation_id",
    "run_id",
    "request_id",
    "attempt_token_hash",
)
_VALIDATION_PARSE_FIELDS: Final = (
    "byte_length",
    "source_hash",
    "header",
    "result",
    "failure_code",
    "redactions",
)
_MANIFEST_PARSE_FIELDS: Final = (
    "byte_length",
    "source_hash",
    "header",
    "manifest",
    "failure_code",
    "redactions",
)
#: Recorded once from the stdlib formula beside each golden test (Task 3/4 precedent);
#: filled on the first GREEN and pinned as regression goldens.
_VALIDATION_GOLDEN: Final = (
    "0ae2cfe3cfaa5c286d850106ce29f65ac6381b521e03a14fde45acc29cedc174"
)
_SANITIZED_GOLDEN: Final = (
    "d9f49b8ea18c8edb2c6e13ed96c9a57ce08e20ec4ecf6cd30f09318ac632edfa"
)


def _missing(value: object) -> bool:
    return value is MISSING


def _forbidden(*_args: object, **_kwargs: object) -> Never:
    raise AssertionError("Task 5 performed runtime work")


def _derived(prefix: str, seed: str) -> str:
    return f"{prefix}_{_uuid4_shaped(sha256_bytes(seed.encode('utf-8')))}"


def _event_id(seed: object) -> str:
    return _derived("evt", str(seed))


def _stdlib_digest(document: object) -> str:
    return hashlib.sha256(
        json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


_MANIFEST_ID: Final = _derived("amf", "manifest")
_APPROXIMATION_A: Final = _derived("appx", "approximation-a")
_APPROXIMATION_B: Final = _derived("appx", "approximation-b")
_NEGOTIATED: Final = NegotiatedVersions(
    protocol_version="1.0.0",
    schema_versions=tuple(
        SupportedSchemaVersion(schema_name=name, schema_version="1.0.0")
        for name in NEGOTIABLE_SCHEMA_NAMES
    ),
    capability_vocabulary_version="capabilities/v1",
)
_PROVENANCE: Final[dict[str, Any]] = {
    "experiment_spec_hash": _SPEC_HASH,
    "request_hash": REQUEST_HASH,
    "strategy_version_hash": STRATEGY_HASH,
    "dataset_version_hash": DATASET_HASH,
    "configuration_hash": _CONFIGURATION_HASH,
    "adapter": {"adapter_name": "adapter.alpha", "adapter_version": "1.0.0"},
    "engine": {"engine_name": "engine.alpha", "engine_version": "2.3.4"},
    "negotiated_versions": _NEGOTIATED.model_dump(mode="json"),
    "comparison_level": "LEVEL_2",
    "logical_slot_id": SLOT_A,
    "attempt_number": 1,
}
_DIAGNOSTIC: Final[dict[str, Any]] = {
    "error_code": "ENGINE.DATA_GAP",
    "category": "ENGINE_RUNTIME",
    "severity": "ERROR",
    "message": "one bar missing",
    "retriable": True,
    "details": {"bars": 1},
    "causal_event_ids": [],
}
_WARNING: Final[dict[str, Any]] = {
    "warning_code": "ADAPTER.APPROXIMATED_FILLS",
    "message": "fills approximated at bar close",
    "impact": "Level 3 comparison prevented.",
    "prevented_comparison_levels": ["LEVEL_3"],
}
_DECLARATION: Final[dict[str, Any]] = {
    "relative_path": "results/native.bin",
    "artifact_kind": "engine.native",
    "media_type": "application/octet-stream",
    "declared_size_bytes": 12,
    "declared_sha256": _HASH,
}
_SECOND_DECLARATION: Final[dict[str, Any]] = {
    "relative_path": "results/normalized.json",
    "artifact_kind": "normalized.result",
    "media_type": "application/json",
    "declared_size_bytes": 34,
    "declared_sha256": _OTHER_HASH,
}
_METRIC: Final[dict[str, Any]] = {
    "metric_name": "total.return",
    "value": "0.125",
    "value_status": "DEFINED",
    "unit": "ratio",
    "methodology_version": "1.0.0",
    "comparison_level": "LEVEL_2",
}
_UNDEFINED_METRIC: Final[dict[str, Any]] = {
    "metric_name": "sharpe",
    "value_status": "UNDEFINED",
    "unit": "ratio",
    "methodology_version": "1.0.0",
    "comparison_level": "LEVEL_2",
}


def _validation_document(**updates: Any) -> dict[str, Any]:
    """A conformant ``VALID`` result; ``result_hash`` recomputed over the updates
    unless supplied, so a test can pin the wrong-hash case explicitly."""
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "request_id": _REQUEST_ID,
        "invocation_id": INVOCATION_ID,
        "run_id": RUN_ID,
        "attempt_token_hash": _TOKEN_HASH,
        "outcome": "VALID",
        "diagnostics": [],
        "validated_at_utc": _STARTED,
    }
    supplied = "result_hash" in updates
    result_hash = updates.pop("result_hash", None)
    document.update(updates)
    document["result_hash"] = result_hash if supplied else _stdlib_digest(document)
    return document


def _manifest_document(**updates: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "adapter_manifest_id": _MANIFEST_ID,
        "experiment_id": EXPERIMENT_ID,
        "run_id": RUN_ID,
        "invocation_id": INVOCATION_ID,
        "attempt_token": ATTEMPT_TOKEN,
        "semantic_status": "SUCCEEDED",
        "started_at_utc": _STARTED,
        "completed_at_utc": _COMPLETED,
        "provenance": _PROVENANCE,
        "candidate_artifacts": [_DECLARATION],
        "candidate_metrics": [_METRIC, _UNDEFINED_METRIC],
        "diagnostics": [],
        "warnings": [],
        "approximations": [],
    }
    document.update(updates)
    return document


def _encode(document: dict[str, Any]) -> bytes:
    # ``ensure_ascii`` so a lone-surrogate fixture is a JSON escape, never a byte.
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def _validation(**updates: Any) -> AdapterValidationResult:
    return AdapterValidationResult.model_validate_json(
        json.dumps(_validation_document(**updates))
    )


def _manifest(**updates: Any) -> AdapterResultManifest:
    return AdapterResultManifest.model_validate_json(
        json.dumps(_manifest_document(**updates))
    )


def _parse_validation(
    output: bytes,
    *,
    max_bytes: int = MAX_VALIDATION_RESULT_BYTES,
    token: str = ATTEMPT_TOKEN,
) -> ValidationResultParse:
    return parse_validation_result(output, max_bytes=max_bytes, token=token)


def _parse_manifest(
    output: bytes,
    *,
    max_bytes: int = MAX_RESULT_MANIFEST_BYTES,
    token: str = ATTEMPT_TOKEN,
) -> ManifestParse:
    return parse_result_manifest(output, max_bytes=max_bytes, token=token)


def _summary(*declarations: dict[str, Any], **updates: Any) -> ProtocolEventSummary:
    records = tuple(
        ArtifactDeclarationRecord(
            event_id=_event_id(f"artifact:{index}"),
            payload=ArtifactProducedPayload.model_validate(declaration),
        )
        for index, declaration in enumerate(declarations, start=1)
    )
    facts: dict[str, Any] = {
        "accepted_count": len(records),
        "last_sequence": len(records),
        "artifact_declarations": records,
        "warnings": (),
        "adapter_diagnostics": (),
        "redactions": 0,
    }
    facts.update(updates)
    return ProtocolEventSummary.model_validate(facts)


def _sanitized(**manifest_updates: Any) -> SanitizedAdapterResultManifest:
    parsed = _parse_manifest(_encode(_manifest_document(**manifest_updates)))
    declarations = manifest_updates.get("candidate_artifacts", [_DECLARATION])
    return sanitize_result_manifest(parsed, _summary(*declarations))


def _resanitized(
    base: SanitizedAdapterResultManifest, **changes: Any
) -> SanitizedAdapterResultManifest:
    """``base`` with ``changes`` applied and its self-hash recomputed."""
    draft = SanitizedAdapterResultManifest.model_construct(**{**dict(base), **changes})
    payload = draft.model_dump(mode="python")
    payload["sanitized_adapter_result_manifest_hash"] = sanitized_manifest_hash(draft)
    return SanitizedAdapterResultManifest.model_validate(payload)


def _candidate_id(relative_path: str) -> str:
    return candidate_artifact_id_for(RUN_ID, INVOCATION_ID, relative_path)


def _conformant_header(**updates: Any) -> OutputHeader:
    facts: dict[str, Any] = {
        "protocol_version": "1.0.0",
        "schema_version": "1.0.0",
        "invocation_id": INVOCATION_ID,
        "run_id": RUN_ID,
        "request_id": _REQUEST_ID,
        "attempt_token_hash": _TOKEN_HASH,
    }
    facts.update(updates)
    return OutputHeader.model_validate(
        {key: value for key, value in facts.items() if value is not None}
    )


# --- Inventory, field order and purity ----------------------------------------------


def test_the_package_exports_the_task_five_surface_sorted() -> None:
    exported = adapters_package.__all__
    assert _TASK5_EXPORTS <= set(exported), sorted(_TASK5_EXPORTS - set(exported))
    assert len(set(exported)) == len(exported)
    constants = [name for name in exported if name.isupper()]
    classes = [name for name in exported if not name.isupper() and name[0].isupper()]
    functions = [name for name in exported if name[0].islower()]
    assert list(exported) == [*constants, *classes, *functions]
    for group in (constants, classes, functions):
        assert group == sorted(group)
    for name in ("_PLACEHOLDER_HASH", "CandidateArtifact", "MetricValue"):
        assert name not in exported


@pytest.mark.parametrize(
    ("model", "expected", "optional"),
    [
        (RunProvenance, _PROVENANCE_FIELDS, ()),
        (CandidateArtifactDeclaration, _DECLARATION_FIELDS, ()),
        (CandidateMetric, _METRIC_FIELDS, ("value",)),
        (AdapterValidationResult, _VALIDATION_FIELDS, ()),
        (OutputHeader, _HEADER_FIELDS, _HEADER_FIELDS),
        (
            ValidationResultParse,
            _VALIDATION_PARSE_FIELDS,
            ("header", "result", "failure_code"),
        ),
        (AdapterResultManifest, _MANIFEST_FIELDS, ()),
        (ManifestParse, _MANIFEST_PARSE_FIELDS, ("header", "manifest", "failure_code")),
        (SanitizedCandidateArtifactDeclaration, _SANITIZED_DECLARATION_FIELDS, ()),
        (SanitizedAdapterResultManifest, _SANITIZED_FIELDS, ()),
    ],
    ids=lambda value: value.__name__ if isinstance(value, type) else "fields",
)
def test_each_model_declares_exactly_the_plan_fields_in_order(
    model: type[Any], expected: tuple[str, ...], optional: tuple[str, ...]
) -> None:
    assert tuple(model.model_fields) == expected
    for name, field in model.model_fields.items():
        assert field.is_required() is (name not in optional), name


def test_version_literals_and_envelope_conventions_are_exact() -> None:
    """Plan 3.1: the three top-level records carry both exact literals; every nested
    value object, reader and parse outcome carries neither."""
    for model in (
        AdapterValidationResult,
        AdapterResultManifest,
        SanitizedAdapterResultManifest,
    ):
        fields = model.model_fields
        assert get_args(fields["schema_version"].annotation) == (SCHEMA_VERSION,)
        assert get_args(fields["protocol_version"].annotation) == (SCHEMA_VERSION,)
    nested: list[type[Any]] = [
        RunProvenance,
        CandidateArtifactDeclaration,
        CandidateMetric,
        SanitizedCandidateArtifactDeclaration,
        ValidationResultParse,
        ManifestParse,
    ]
    for record in nested:
        assert "schema_version" not in record.model_fields, record.__name__
        assert "protocol_version" not in record.model_fields, record.__name__
    # The header reads both versions permissively as bounded text, never literals.
    for name in ("schema_version", "protocol_version"):
        assert get_args(OutputHeader.model_fields[name].annotation) != (SCHEMA_VERSION,)
    assert get_args(CandidateMetric.model_fields["value_status"].annotation) == (
        "DEFINED",
        "UNDEFINED",
    )


def test_only_the_wire_manifest_carries_the_raw_token() -> None:
    """Section 13: the four-class allowlist; among the Task 5 models exactly one."""
    token_free: list[type[Any]] = [
        RunProvenance,
        CandidateArtifactDeclaration,
        CandidateMetric,
        AdapterValidationResult,
        OutputHeader,
        ValidationResultParse,
        SanitizedCandidateArtifactDeclaration,
        SanitizedAdapterResultManifest,
    ]
    for model in token_free:
        assert "attempt_token" not in model.model_fields, model.__name__
        for field in model.model_fields.values():
            assert "AttemptToken" not in repr(field.annotation), model.__name__
    token_field = AdapterResultManifest.model_fields["attempt_token"]
    assert repr(token_field.annotation) == "AttemptToken"
    assert token_field.repr is False
    # The parse outcome carries the wire manifest (W) and nothing else token-typed.
    for name, field in ManifestParse.model_fields.items():
        if name != "manifest":
            assert "AttemptToken" not in repr(field.annotation), name
    assert OutputHeader.model_config.get("extra") == "ignore"
    assert "attempt_token_hash" in OutputHeader.model_fields
    for model in (AdapterValidationResult, SanitizedAdapterResultManifest):
        assert "attempt_token_hash" in model.model_fields


def _scan(source: str) -> tuple[set[str], set[str], set[str]]:
    """The Stage 4 bare-name scan: import roots, first-party packages and every name
    the source mentions (bound, attribute or called); ambient calls are refused."""
    tree = ast.parse(source)
    roots: set[str] = set()
    packages: set[str] = set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
            if node.module.startswith("crypto_lab."):
                packages.add(node.module.split(".")[1])
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        if isinstance(node, ast.Call):
            target = node.func
            called = (
                target.id
                if isinstance(target, ast.Name)
                else getattr(target, "attr", "")
            )
            assert called not in {"open", "now", "utcnow", "today"}, ast.dump(node)
    return roots, packages, names


def test_the_module_imports_only_pure_roots_and_uses_no_forbidden_name() -> None:
    source = Path(manifests.__file__ or "").read_text(encoding="utf-8")
    roots, packages, names = _scan(source)
    assert roots <= _PURE_ROOTS, sorted(roots - _PURE_ROOTS)
    assert packages <= {"domain", "adapters"}, sorted(packages)
    assert names & _STAGE4_BARE_NAMES == set()
    assert "subprocess" not in source
    # The still-deferred neighbours of the Task 5 names are never defined here.
    defined = {
        node.name
        for node in ast.walk(ast.parse(source))
        if isinstance(node, ast.ClassDef | ast.FunctionDef)
    }
    assert defined & {"CandidateArtifact", "MetricValue", "CommandResult"} == set()


def test_the_bare_name_scan_finds_a_planted_name() -> None:
    planted = "Loader = compose(problem)\nresult = Loader.compose\n"
    assert _scan(planted)[2] & _STAGE4_BARE_NAMES == {"Loader", "compose", "problem"}
    with pytest.raises(AssertionError):
        _scan("value = now()\n")


def test_task_five_launches_reads_and_connects_to_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("subprocess.Popen", _forbidden)
    monkeypatch.setattr("socket.create_connection", _forbidden)
    monkeypatch.setattr("os.getenv", _forbidden)
    monkeypatch.setattr("builtins.open", _forbidden)
    parsed = _parse_manifest(_encode(_manifest_document()))
    assert not _missing(parsed.manifest)
    sanitize_result_manifest(parsed, _summary(_DECLARATION))
    result = _parse_validation(_encode(_validation_document()))
    assert not _missing(result.result)
    _parse_validation(b"noise")
    _parse_manifest(b"\xff")


# --- AdapterValidationResult ---------------------------------------------------------


def test_a_conformant_validation_result_validates_in_both_modes_and_is_frozen() -> None:
    document = _validation_document()
    from_json = AdapterValidationResult.model_validate_json(json.dumps(document))
    from_python = AdapterValidationResult.model_validate(
        from_json.model_dump(mode="python")
    )
    assert from_python == from_json
    assert from_json.outcome is ValidationOutcome.VALID
    assert from_json.model_dump(mode="json") == document
    with pytest.raises(ValidationError, match="frozen"):
        from_json.outcome = ValidationOutcome.INVALID
    with pytest.raises(ValidationError, match="extra_forbidden"):
        AdapterValidationResult.model_validate_json(
            json.dumps({**document, "unexpected": 1})
        )


def test_the_result_hash_must_recompute_and_is_stdlib_reproducible() -> None:
    """Plan 4: ``result_hash = sha256(canonical_json_bytes(result without
    result_hash))``, reproducible with ``hashlib`` and ``json.dumps`` alone."""
    result = _validation()
    document = _validation_document()
    without_hash = {
        key: value for key, value in document.items() if key != "result_hash"
    }
    assert validation_result_hash(result) == _stdlib_digest(without_hash)
    assert validation_result_hash(result) == result.result_hash
    payload = result.model_dump(mode="python")
    del payload["result_hash"]
    assert validation_result_hash(result) == sha256_bytes(canonical_json_bytes(payload))
    assert validation_result_hash(result) == _VALIDATION_GOLDEN, validation_result_hash(
        result
    )
    with pytest.raises(ValueError, match="result_hash") as captured:
        _validation(result_hash=_OTHER_HASH)
    assert ATTEMPT_TOKEN not in str(captured.value)
    assert _TOKEN_HASH not in str(captured.value)
    with pytest.raises(TypeError, match="AdapterValidationResult"):
        validation_result_hash(_manifest())  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("protocol_version", "1.0.1"),
        ("request_id", request_id_for(OTHER_RUN_ID)),
        ("invocation_id", OTHER_INVOCATION_ID),
        ("run_id", OTHER_RUN_ID),
        ("attempt_token_hash", attempt_token_hash(_WRONG_TOKEN)),
        ("outcome", "INVALID"),
        ("diagnostics", [_DIAGNOSTIC]),
        ("validated_at_utc", _COMPLETED),
    ],
)
def test_every_material_validation_field_moves_the_result_hash(
    field: str, value: Any
) -> None:
    base = _validation_document()
    changed = _validation_document(**{field: value})
    assert changed["result_hash"] != base["result_hash"]
    if field != "protocol_version":
        # Every admitted change validates with its own hash and is refused with the
        # base hash; the version literal cannot be admitted at all (plan 5.1).
        if field == "outcome":
            changed = _validation_document(outcome=value, diagnostics=[_DIAGNOSTIC])
        result = AdapterValidationResult.model_validate_json(json.dumps(changed))
        assert result.result_hash == changed["result_hash"]
        with pytest.raises(ValueError, match="result_hash"):
            AdapterValidationResult.model_validate_json(
                json.dumps({**changed, "result_hash": base["result_hash"]})
            )


@pytest.mark.parametrize("outcome", ["NOT_APPLICABLE", "UNAVAILABLE", "INVALID"])
def test_the_three_non_valid_outcomes_require_a_diagnostic(outcome: str) -> None:
    with pytest.raises(ValueError, match="at least one diagnostic"):
        _validation(outcome=outcome)
    result = _validation(outcome=outcome, diagnostics=[_DIAGNOSTIC])
    assert result.outcome is ValidationOutcome(outcome)
    assert len(result.diagnostics) == 1
    assert isinstance(result.diagnostics[0], AdapterDiagnostic)


def test_a_valid_outcome_admits_zero_or_more_diagnostics_and_bounds_them() -> None:
    assert _validation().diagnostics == ()
    assert len(_validation(diagnostics=[_DIAGNOSTIC]).diagnostics) == 1
    many = [
        {**_DIAGNOSTIC, "message": f"m{index}"}
        for index in range(MAX_ADAPTER_DIAGNOSTICS)
    ]
    assert len(_validation(diagnostics=many).diagnostics) == MAX_ADAPTER_DIAGNOSTICS
    with pytest.raises(ValidationError, match="too_long"):
        _validation(diagnostics=[*many, _DIAGNOSTIC])


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"schema_version": "2.0.0"}, "literal_error"),
        ({"protocol_version": "1.0"}, "literal_error"),
        ({"request_id": RUN_ID}, "req_"),
        ({"invocation_id": RUN_ID}, "inv_"),
        ({"run_id": INVOCATION_ID}, "run_"),
        ({"attempt_token_hash": "A" * 64}, "string_pattern_mismatch"),
        ({"attempt_token_hash": ATTEMPT_TOKEN}, "string_pattern_mismatch"),
        ({"outcome": "valid"}, "enum"),
        ({"validated_at_utc": "2026-09-11T10:00:00"}, "canonical UTC"),
        ({"validated_at_utc": "2026-02-30T00:00:00Z"}, "valid datetime"),
        ({"diagnostics": [{**_DIAGNOSTIC, "error_code": "PROTOCOL.X"}]}, "pattern"),
        ({"attempt_token": ATTEMPT_TOKEN}, "extra_forbidden"),
    ],
    ids=[
        "schema-version",
        "protocol-version",
        "request-id",
        "invocation-id",
        "run-id",
        "uppercase-hash",
        "token-as-hash",
        "lowercase-outcome",
        "naive-timestamp",
        "impossible-date",
        "core-namespace-diagnostic",
        "raw-token-field",
    ],
)
def test_the_validation_result_rejects_strict_type_and_identity_violations(
    updates: dict[str, Any], expected: str
) -> None:
    with pytest.raises(ValidationError, match=expected) as captured:
        _validation(**updates)
    assert ATTEMPT_TOKEN not in str(captured.value)


def test_the_validation_result_schema_publishes_the_outcome_rule_and_is_closed() -> (
    None
):
    """Preventive for Task 9 (schema 32): both modes render identically, every object
    is closed, the outcome->diagnostics rule is three ``if``/``then`` clauses."""
    schema = TypeAdapter(AdapterValidationResult).json_schema(mode="validation")
    Draft202012Validator.check_schema(schema)
    assert schema == TypeAdapter(AdapterValidationResult).json_schema(
        mode="serialization"
    )
    assert schema["additionalProperties"] is False
    for name, definition in schema["$defs"].items():
        if definition.get("type") == "object":
            assert definition["additionalProperties"] is False, name
    assert "UtcDateTime" not in schema["$defs"]
    assert schema["required"] == list(_VALIDATION_FIELDS)
    for name in ("schema_version", "protocol_version"):
        assert schema["properties"][name]["const"] == SCHEMA_VERSION
    validator = Draft202012Validator(schema)
    baseline = _validation_document()
    assert validator.is_valid(baseline)
    assert not validator.is_valid({**baseline, "unexpected": 1})
    for outcome in ("NOT_APPLICABLE", "UNAVAILABLE", "INVALID"):
        assert not validator.is_valid({**baseline, "outcome": outcome})
        assert validator.is_valid(
            {**baseline, "outcome": outcome, "diagnostics": [_DIAGNOSTIC]}
        )
    assert validator.is_valid({**baseline, "diagnostics": [_DIAGNOSTIC]})


# --- parse_validation_result ---------------------------------------------------------


def test_valid_bytes_parse_to_a_result_with_its_header_and_hashes() -> None:
    output = _encode(_validation_document())
    parsed = _parse_validation(output)
    assert parsed.byte_length == len(output)
    assert parsed.source_hash == hashlib.sha256(output).hexdigest()
    assert parsed.result == _validation()
    assert _missing(parsed.failure_code)
    assert parsed.redactions == 0
    assert parsed.header == _conformant_header()
    assert parsed == _parse_validation(output)
    assert (
        ValidationResultParse.model_validate(parsed.model_dump(mode="python")) == parsed
    )
    with pytest.raises(ValidationError, match="frozen"):
        parsed.redactions = 1


def test_oversized_validation_bytes_are_never_decoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Plan 3.11 and specification 14.7: the ceiling applies before decoding."""
    monkeypatch.setattr(json, "loads", _forbidden)
    output = _encode(_validation_document()) + b"\xff\xfe"
    parsed = _parse_validation(output, max_bytes=len(output) - 1)
    assert parsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    assert _missing(parsed.header)
    assert _missing(parsed.result)
    assert parsed.redactions == 0
    assert parsed.byte_length == len(output)
    assert parsed.source_hash == sha256_bytes(output)


def test_validation_bytes_at_the_ceiling_parse_and_one_more_does_not() -> None:
    output = _encode(_validation_document())
    assert not _missing(_parse_validation(output, max_bytes=len(output)).result)
    assert _parse_validation(output, max_bytes=len(output) - 1).failure_code == (
        PROTOCOL_VALIDATION_RESULT_INVALID
    )
    assert _parse_validation(b"", max_bytes=1).failure_code == (
        PROTOCOL_VALIDATION_RESULT_INVALID
    )


_NON_OBJECT_OUTPUTS: Final[list[bytes]] = [
    b"",
    b"\xff\xfe",
    b"\xef\xbb\xbf" + _encode(_validation_document()),
    _encode(_validation_document()).decode("utf-8").encode("utf-16"),
    b"[]",
    b'"text"',
    b"1",
    b"null",
    b"not json",
    _encode(_validation_document()) + b" {}",
    _encode(_validation_document())[:-1],
    b"[" * 100_000,
    b'{"run_id": 1, "run_id": 2}',
    b'{"diagnostics": [{"details": {"a": 1, "a": 2}}]}',
    b'{"run_id": ' + b"9" * 5000 + b"}",
]
_NON_OBJECT_IDS: Final[list[str]] = [
    "empty",
    "invalid-utf8",
    "bom",
    "utf16",
    "array",
    "string",
    "number",
    "null",
    "text",
    "trailing-document",
    "truncated",
    "deep-nesting",
    "repeated-key",
    "repeated-nested-key",
    "huge-integer-literal",
]


@pytest.mark.parametrize("output", _NON_OBJECT_OUTPUTS, ids=_NON_OBJECT_IDS)
def test_validation_bytes_that_are_not_a_json_object_carry_no_header(
    output: bytes,
) -> None:
    parsed = _parse_validation(output)
    assert parsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    assert _missing(parsed.header)
    assert _missing(parsed.result)
    assert parsed.redactions == 0
    assert parsed.byte_length == len(output)
    assert parsed.source_hash == sha256_bytes(output)


def test_key_order_is_not_a_repeated_key_for_either_parser() -> None:
    reordered = dict(reversed(list(_validation_document().items())))
    output = json.dumps(reordered, separators=(",", ":")).encode("utf-8")
    assert output != _encode(_validation_document())
    assert _parse_validation(output).result == _validation()
    manifest = dict(reversed(list(_manifest_document().items())))
    manifest_output = json.dumps(manifest, separators=(",", ":")).encode("utf-8")
    assert _parse_manifest(manifest_output).manifest == _manifest()


def test_an_unknown_field_populates_the_header_and_is_validation_result_invalid() -> (
    None
):
    parsed = _parse_validation(_encode(_validation_document(unexpected=1)))
    assert parsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    assert _missing(parsed.result)
    assert parsed.header == _conformant_header()
    assert parsed.redactions == 0


@pytest.mark.parametrize("field", ["protocol_version", "schema_version"])
def test_an_unsupported_version_is_named_by_the_validation_header(field: str) -> None:
    """Plan 5.1/9.4: a readable unsupported version is the version code, before any
    redaction, so ``redactions`` is zero even when the document carries the token."""
    document = _validation_document(
        **{field: "2.0.0"}, diagnostics=[{**_DIAGNOSTIC, "message": ATTEMPT_TOKEN}]
    )
    parsed = _parse_validation(_encode(document))
    assert parsed.failure_code == PROTOCOL_UNSUPPORTED_VERSION
    assert _missing(parsed.result)
    assert getattr(parsed.header, field) == "2.0.0"
    assert parsed.header.invocation_id == INVOCATION_ID
    assert parsed.redactions == 0
    assert ATTEMPT_TOKEN not in parsed.model_dump_json()
    # A wrongly typed version is not readable, so it is the generic code.
    unreadable = _parse_validation(_encode(_validation_document(**{field: 1})))
    assert unreadable.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    assert _missing(getattr(unreadable.header, field))


@pytest.mark.parametrize(
    ("updates", "absent"),
    [
        ({"invocation_id": 1}, "invocation_id"),
        ({"invocation_id": ""}, "invocation_id"),
        ({"invocation_id": "x" * 129}, "invocation_id"),
        ({"run_id": [RUN_ID]}, "run_id"),
        ({"run_id": None}, "run_id"),
        ({"request_id": {"id": _REQUEST_ID}}, "request_id"),
        ({"attempt_token_hash": "a" * 63}, "attempt_token_hash"),
        ({"attempt_token_hash": "A" * 64}, "attempt_token_hash"),
        ({"attempt_token_hash": 7}, "attempt_token_hash"),
        ({"protocol_version": ""}, "protocol_version"),
        ({"schema_version": "x" * 129}, "schema_version"),
    ],
)
def test_a_wrongly_typed_or_overlong_header_field_reads_as_missing(
    updates: dict[str, Any], absent: str
) -> None:
    """Plan 3.11: the header never fails on a JSON object; the reconciler reports
    identity from the absence. The document stays strict-invalid."""
    parsed = _parse_validation(_encode(_validation_document(**updates)))
    assert parsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    assert _missing(getattr(parsed.header, absent))
    for field in _HEADER_FIELDS:
        if field != absent:
            assert not _missing(getattr(parsed.header, field)), field


def test_a_header_identity_differing_from_the_records_is_carried_not_judged() -> None:
    """Plan 3.11/9.2: the parser records identity; the reconciler (Task 6) compares
    it. A foreign but strict-valid document therefore parses to a result."""
    foreign = _validation_document(
        invocation_id=OTHER_INVOCATION_ID,
        run_id=OTHER_RUN_ID,
        request_id=request_id_for(OTHER_RUN_ID),
        attempt_token_hash=attempt_token_hash(_WRONG_TOKEN),
    )
    parsed = _parse_validation(_encode(foreign))
    assert not _missing(parsed.result)
    assert parsed.header.invocation_id == OTHER_INVOCATION_ID
    assert parsed.header.run_id == OTHER_RUN_ID
    assert parsed.header.request_id == request_id_for(OTHER_RUN_ID)
    assert parsed.header.attempt_token_hash == attempt_token_hash(_WRONG_TOKEN)
    # A mis-identified *and* malformed document yields both the header and the code.
    both = _parse_validation(_encode({**foreign, "unexpected": 1}))
    assert both.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    assert both.header.invocation_id == OTHER_INVOCATION_ID


def test_a_raw_token_in_the_document_is_hashed_into_the_header_never_carried() -> None:
    """Plan 3.11: the header hashes a raw ``attempt_token`` at once and stores only
    the hash; the raw value appears nowhere in the parse. The document itself is a
    contract violation (an unknown field and a redaction), so no result exists."""
    document = _validation_document(attempt_token=_WRONG_TOKEN)
    del document["attempt_token_hash"]
    parsed = _parse_validation(_encode(document))
    assert parsed.header.attempt_token_hash == attempt_token_hash(_WRONG_TOKEN)
    assert parsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    assert _missing(parsed.result)
    dumped = parsed.model_dump_json()
    assert _WRONG_TOKEN not in dumped
    assert _WRONG_TOKEN not in repr(parsed)
    # The raw token takes precedence over a declared hash when both are present.
    both = _parse_validation(_encode(_validation_document(attempt_token=_WRONG_TOKEN)))
    assert both.header.attempt_token_hash == attempt_token_hash(_WRONG_TOKEN)
    # A wrongly typed or over-long raw token reads as MISSING when no hash is declared.
    for hostile in (5, "", "x" * 1025):
        unreadable = dict(document)
        unreadable["attempt_token"] = hostile
        assert _missing(
            _parse_validation(_encode(unreadable)).header.attempt_token_hash
        )
    # ... and falls back to the declared hash when one is present.
    fallback = _parse_validation(_encode(_validation_document(attempt_token=5)))
    assert fallback.header.attempt_token_hash == _TOKEN_HASH


def test_a_raw_token_in_a_diagnostic_message_yields_redactions_and_no_result() -> None:
    """Plan 3.10/3.11: a validation result is token-free by contract, so any redaction
    is ``PROTOCOL.VALIDATION_RESULT_INVALID`` with ``result`` absent."""
    document = _validation_document(
        outcome="INVALID",
        diagnostics=[
            {**_DIAGNOSTIC, "message": f"engine said {ATTEMPT_TOKEN}"},
            {
                **_DIAGNOSTIC,
                "details": {"engine_log": f"{ATTEMPT_TOKEN}/{ATTEMPT_TOKEN}"},
            },
        ],
    )
    parsed = _parse_validation(_encode(document))
    assert parsed.redactions == 3
    assert _missing(parsed.result)
    assert parsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    assert parsed.header == _conformant_header()
    assert ATTEMPT_TOKEN not in parsed.model_dump_json()
    assert ATTEMPT_TOKEN not in repr(parsed)


def test_a_result_hash_precomputed_over_the_redacted_spelling_still_fails() -> None:
    """Declared reading R2: the token-free contract is enforced explicitly. An adapter
    that wrote the token but hashed the placeholder spelling would otherwise pass
    strict validation over the redacted document with a redaction count."""
    tokened = {**_DIAGNOSTIC, "message": f"engine said {ATTEMPT_TOKEN}"}
    redacted = {**_DIAGNOSTIC, "message": f"engine said {REDACTION_PLACEHOLDER}"}
    precomputed = _validation_document(outcome="INVALID", diagnostics=[redacted])
    document = _validation_document(
        outcome="INVALID",
        diagnostics=[tokened],
        result_hash=precomputed["result_hash"],
    )
    # Control: the redacted spelling is itself a strict-valid, redaction-free result.
    control = _parse_validation(_encode(precomputed))
    assert not _missing(control.result)
    assert control.redactions == 0
    parsed = _parse_validation(_encode(document))
    assert parsed.redactions == 1
    assert _missing(parsed.result)
    assert parsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID


def test_a_token_as_a_top_level_key_or_in_a_key_is_counted_or_refused() -> None:
    in_key = _validation_document(
        outcome="INVALID",
        diagnostics=[{**_DIAGNOSTIC, "details": {f"k{ATTEMPT_TOKEN}": "v"}}],
    )
    parsed = _parse_validation(_encode(in_key))
    assert parsed.redactions == 1
    assert parsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    assert ATTEMPT_TOKEN not in parsed.model_dump_json()
    collapse = _validation_document(
        outcome="INVALID",
        diagnostics=[
            {
                **_DIAGNOSTIC,
                "details": {f"k{ATTEMPT_TOKEN}": 1, f"k{REDACTION_PLACEHOLDER}": 2},
            }
        ],
    )
    collapsed = _parse_validation(_encode(collapse))
    assert collapsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    assert collapsed.redactions == 0
    assert ATTEMPT_TOKEN not in collapsed.model_dump_json()


def _escaped_json_text(value: str) -> str:
    """``value`` spelled entirely with JSON backslash-u escapes."""
    return "".join(f"\\u{ord(character):04x}" for character in value)


def test_a_json_escaped_token_is_decoded_and_redacted() -> None:
    document = _validation_document(
        outcome="INVALID",
        diagnostics=[{**_DIAGNOSTIC, "message": "TOKEN"}],
    )
    text = json.dumps(document, sort_keys=True, separators=(",", ":"))
    escaped = text.replace('"TOKEN"', f'"{_escaped_json_text(ATTEMPT_TOKEN)}"')
    assert ATTEMPT_TOKEN not in escaped
    parsed = _parse_validation(escaped.encode("ascii"))
    assert parsed.redactions == 1
    assert parsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    assert ATTEMPT_TOKEN not in parsed.model_dump_json()


@pytest.mark.parametrize("field", ["invocation_id", "run_id", "request_id"])
def test_a_lone_surrogate_escape_reads_as_missing_and_never_raises(field: str) -> None:
    surrogate = chr(0xD800)
    parsed = _parse_validation(
        _encode(_validation_document(**{field: surrogate}, result_hash=_HASH))
    )
    assert parsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    assert _missing(getattr(parsed.header, field))
    assert not _missing(parsed.header.attempt_token_hash)
    canonical_json_bytes(parsed.header)
    with pytest.raises(ValidationError):
        OutputHeader.model_validate({field: surrogate})


def test_a_deeply_nested_field_is_invalid_and_never_raises() -> None:
    """Task 4 handoff: a document the C decoder accepts may exceed the interpreter's
    recursion limit in the redaction walk or the re-serialization; both reduce to
    the failure code with the header intact."""
    depth = 1200
    prefix = _encode(_validation_document())[:-1]
    nested = prefix + b',"nested":' + b"[" * depth + b"1" + b"]" * depth + b"}"
    assert isinstance(json.loads(nested), dict)
    parsed = _parse_validation(nested)
    assert parsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    assert not _missing(parsed.header)
    assert _missing(parsed.result)
    deeper = prefix + b',"nested":' + b"[" * 100_000 + b"]" * 100_000 + b"}"
    assert _parse_validation(deeper).failure_code == PROTOCOL_VALIDATION_RESULT_INVALID


def test_a_non_finite_number_keeps_the_header_and_is_invalid() -> None:
    document = _validation_document(
        outcome="INVALID", diagnostics=[{**_DIAGNOSTIC, "details": {"x": 1}}]
    )
    text = json.dumps(document, sort_keys=True, separators=(",", ":"))
    for spelling in ("NaN", "Infinity", "-Infinity", "1e400"):
        hostile = text.replace('"x":1', f'"x":{spelling}')
        assert hostile != text
        parsed = _parse_validation(hostile.encode("utf-8"))
        assert parsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID, spelling
        assert not _missing(parsed.header), spelling


def test_validation_parse_arguments_are_type_and_bound_checked() -> None:
    output = _encode(_validation_document())
    with pytest.raises(TypeError, match="bytes"):
        parse_validation_result(output.decode(), max_bytes=10, token=ATTEMPT_TOKEN)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="max_bytes"):
        parse_validation_result(output, max_bytes="10", token=ATTEMPT_TOKEN)  # type: ignore[arg-type]
    for bound in (0, MAX_VALIDATION_RESULT_BYTES + 1):
        with pytest.raises(ValueError, match="max_bytes"):
            parse_validation_result(output, max_bytes=bound, token=ATTEMPT_TOKEN)
    assert not _missing(
        parse_validation_result(
            output, max_bytes=MAX_VALIDATION_RESULT_BYTES, token=ATTEMPT_TOKEN
        ).result
    )
    with pytest.raises(TypeError, match="token"):
        parse_validation_result(output, max_bytes=10, token=b"x")  # type: ignore[arg-type]
    for bad in ("", "x" * 1025):
        with pytest.raises(ValueError, match="token"):
            parse_validation_result(output, max_bytes=10, token=bad)


def test_the_validation_parse_record_restates_its_invariants() -> None:
    facts: dict[str, Any] = {"byte_length": 3, "source_hash": _HASH, "redactions": 0}
    header = _conformant_header()
    result = _validation()
    with pytest.raises(ValueError, match="exactly one"):
        ValidationResultParse.model_validate(facts)
    with pytest.raises(ValueError, match="exactly one"):
        ValidationResultParse.model_validate(
            {
                **facts,
                "header": header,
                "result": result,
                "failure_code": PROTOCOL_VALIDATION_RESULT_INVALID,
            }
        )
    with pytest.raises(ValueError, match="header"):
        ValidationResultParse.model_validate({**facts, "result": result})
    with pytest.raises(ValueError, match="agreeing"):
        ValidationResultParse.model_validate(
            {
                **facts,
                "header": _conformant_header(invocation_id=OTHER_INVOCATION_ID),
                "result": result,
            }
        )
    with pytest.raises(ValueError, match="redactions"):
        ValidationResultParse.model_validate(
            {**facts, "redactions": 1, "header": header, "result": result}
        )
    with pytest.raises(ValueError, match="redactions"):
        ValidationResultParse.model_validate(
            {
                **facts,
                "redactions": 1,
                "header": _conformant_header(protocol_version="2.0.0"),
                "failure_code": PROTOCOL_UNSUPPORTED_VERSION,
            }
        )
    with pytest.raises(ValueError, match="without a header"):
        ValidationResultParse.model_validate(
            {**facts, "failure_code": PROTOCOL_UNSUPPORTED_VERSION}
        )
    with pytest.raises(ValueError, match="validation parse code"):
        ValidationResultParse.model_validate(
            {
                **facts,
                "header": header,
                "failure_code": ARTIFACT_RESULT_MANIFEST_INVALID,
            }
        )
    with pytest.raises(ValueError, match="UNSUPPORTED_VERSION"):
        ValidationResultParse.model_validate(
            {**facts, "header": header, "failure_code": PROTOCOL_UNSUPPORTED_VERSION}
        )
    with pytest.raises(ValueError, match="UNSUPPORTED_VERSION"):
        ValidationResultParse.model_validate(
            {
                **facts,
                "header": _conformant_header(schema_version="9.9.9"),
                "failure_code": PROTOCOL_VALIDATION_RESULT_INVALID,
            }
        )
    with pytest.raises(ValidationError, match="extra_forbidden"):
        ValidationResultParse.model_validate(
            {**facts, "header": header, "result": result, "sample": "x"}
        )
    # Every well-formed shape validates.
    ValidationResultParse.model_validate({**facts, "header": header, "result": result})
    ValidationResultParse.model_validate(
        {**facts, "failure_code": PROTOCOL_VALIDATION_RESULT_INVALID}
    )
    ValidationResultParse.model_validate(
        {
            **facts,
            "redactions": 2,
            "header": header,
            "failure_code": PROTOCOL_VALIDATION_RESULT_INVALID,
        }
    )
    ValidationResultParse.model_validate(
        {
            **facts,
            "header": _conformant_header(protocol_version="2.0.0"),
            "failure_code": PROTOCOL_UNSUPPORTED_VERSION,
        }
    )


def test_the_output_header_ignores_unknown_keys_but_stays_strict() -> None:
    header = OutputHeader.model_validate({"invocation_id": INVOCATION_ID, "x": 1})
    assert header.invocation_id == INVOCATION_ID
    assert _missing(header.run_id)
    assert "x" not in header.model_dump()
    with pytest.raises(ValidationError):
        OutputHeader.model_validate({"invocation_id": 1})
    with pytest.raises(ValidationError):
        OutputHeader.model_validate({"attempt_token_hash": "A" * 64})
    with pytest.raises(ValidationError, match="frozen"):
        header.run_id = RUN_ID


def test_redact_validation_result_redacts_every_string_and_the_top_level_token() -> (
    None
):
    """Declared reading R3: one redaction algorithm (``redact_payload``) with no exempt
    key, because a validation result is token-free by contract."""
    document: dict[str, Any] = {
        "attempt_token": ATTEMPT_TOKEN,
        "nested": {"attempt_token": {"attempt_token": ATTEMPT_TOKEN}},
        "list": [ATTEMPT_TOKEN, {"k": ATTEMPT_TOKEN}],
        f"key-{ATTEMPT_TOKEN}": 1,
        "n": 1,
    }
    before = json.dumps(document, sort_keys=True)
    redacted, count = redact_validation_result(document, ATTEMPT_TOKEN)
    assert count == 5
    assert json.dumps(document, sort_keys=True) == before
    assert ATTEMPT_TOKEN not in json.dumps(redacted)
    assert isinstance(redacted, dict)
    assert redacted["attempt_token"] == REDACTION_PLACEHOLDER
    assert redacted["nested"] == {
        "attempt_token": {"attempt_token": REDACTION_PLACEHOLDER}
    }
    assert redact_validation_result(["x", 1, None], ATTEMPT_TOKEN) == (
        ["x", 1, None],
        0,
    )
    with pytest.raises(TypeError, match="token"):
        redact_validation_result({}, 1)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="token"):
        redact_validation_result({}, "")
    with pytest.raises(ValueError, match="collapse"):
        redact_validation_result(
            {f"k{ATTEMPT_TOKEN}": 1, f"k{REDACTION_PLACEHOLDER}": 2}, ATTEMPT_TOKEN
        )


# --- AdapterResultManifest -----------------------------------------------------------


def test_a_conformant_manifest_validates_hides_its_token_and_round_trips() -> None:
    document = _manifest_document()
    from_json = AdapterResultManifest.model_validate_json(json.dumps(document))
    from_python = AdapterResultManifest.model_validate(
        from_json.model_dump(mode="python")
    )
    assert from_python == from_json
    assert from_json.semantic_status is SemanticStatus.SUCCEEDED
    assert from_json.model_dump(mode="json") == document
    assert ATTEMPT_TOKEN not in repr(from_json)
    assert ATTEMPT_TOKEN not in str(from_json)
    assert from_json.model_dump_json().count(ATTEMPT_TOKEN) == 1
    with pytest.raises(ValidationError, match="frozen"):
        from_json.semantic_status = SemanticStatus.FAILED
    with pytest.raises(ValidationError, match="extra_forbidden") as captured:
        AdapterResultManifest.model_validate_json(
            json.dumps({**document, "unexpected": 1})
        )
    assert ATTEMPT_TOKEN not in str(captured.value)
    with pytest.raises(ValidationError, match="extra_forbidden"):
        _manifest(attempt_token_hash=_TOKEN_HASH)


def test_completion_before_start_is_rejected_and_equality_is_admitted() -> None:
    with pytest.raises(ValueError, match="completed_at_utc"):
        _manifest(started_at_utc=_COMPLETED, completed_at_utc=_STARTED)
    equal = _manifest(started_at_utc=_STARTED, completed_at_utc=_STARTED)
    assert equal.started_at_utc == equal.completed_at_utc


def test_succeeded_forbids_warnings_and_succeeded_with_warnings_requires_one() -> None:
    with pytest.raises(ValueError, match="warning"):
        _manifest(semantic_status="SUCCEEDED", warnings=[_WARNING])
    with pytest.raises(ValueError, match="warning"):
        _manifest(semantic_status="SUCCEEDED_WITH_WARNINGS", warnings=[])
    warned = _manifest(semantic_status="SUCCEEDED_WITH_WARNINGS", warnings=[_WARNING])
    assert isinstance(warned.warnings[0], ProtocolWarning)
    # A success manifest may carry diagnostics; success is governed by warnings.
    assert (
        _manifest(diagnostics=[_DIAGNOSTIC]).semantic_status is SemanticStatus.SUCCEEDED
    )


@pytest.mark.parametrize("status", [status.value for status in _NON_SUCCESS])
def test_every_non_success_status_requires_a_diagnostic_and_no_candidate(
    status: str,
) -> None:
    with pytest.raises(ValueError, match="diagnostic"):
        _manifest(semantic_status=status, candidate_artifacts=[])
    with pytest.raises(ValueError, match="candidate"):
        _manifest(semantic_status=status, diagnostics=[_DIAGNOSTIC])
    manifest = _manifest(
        semantic_status=status, diagnostics=[_DIAGNOSTIC], candidate_artifacts=[]
    )
    assert manifest.semantic_status is SemanticStatus(status)
    assert manifest.candidate_artifacts == ()
    # Metrics, warnings and approximations stay admitted on a non-success manifest.
    _manifest(
        semantic_status=status,
        diagnostics=[_DIAGNOSTIC],
        candidate_artifacts=[],
        warnings=[_WARNING],
        approximations=[_APPROXIMATION_A],
    )


def test_duplicate_declaration_paths_and_metric_names_are_rejected() -> None:
    with pytest.raises(ValueError, match="relative_path"):
        _manifest(
            candidate_artifacts=[
                _DECLARATION,
                {**_SECOND_DECLARATION, "relative_path": "results/native.bin"},
            ]
        )
    with pytest.raises(ValueError, match="metric_name"):
        _manifest(candidate_metrics=[_METRIC, {**_METRIC, "value": "1"}])
    two = _manifest(candidate_artifacts=[_DECLARATION, _SECOND_DECLARATION])
    assert len(two.candidate_artifacts) == 2
    # Near miss: a path differing only by case is another path under the grammar.
    _manifest(
        candidate_artifacts=[
            _DECLARATION,
            {**_DECLARATION, "relative_path": "results/Native.bin"},
        ]
    )


def _many(
    template: dict[str, Any], key: str, count: int, spelling: str
) -> list[dict[str, Any]]:
    return [{**template, key: spelling.format(index)} for index in range(count)]


def test_the_manifest_collections_are_bounded_at_the_compiled_limits() -> None:
    declarations = _many(
        _DECLARATION, "relative_path", MAX_CANDIDATE_ARTIFACTS, "results/{}.bin"
    )
    assert len(_manifest(candidate_artifacts=declarations).candidate_artifacts) == (
        MAX_CANDIDATE_ARTIFACTS
    )
    with pytest.raises(ValidationError, match="too_long"):
        _manifest(
            candidate_artifacts=[
                *declarations,
                {**_DECLARATION, "relative_path": "results/extra.bin"},
            ]
        )
    metrics = _many(_METRIC, "metric_name", MAX_CANDIDATE_METRICS, "metric.m{}")
    assert len(_manifest(candidate_metrics=metrics).candidate_metrics) == (
        MAX_CANDIDATE_METRICS
    )
    with pytest.raises(ValidationError, match="too_long"):
        _manifest(candidate_metrics=[*metrics, {**_METRIC, "metric_name": "extra"}])
    diagnostics = _many(_DIAGNOSTIC, "message", MAX_ADAPTER_DIAGNOSTICS + 1, "m{}")
    with pytest.raises(ValidationError, match="too_long"):
        _manifest(diagnostics=diagnostics)
    warnings = _many(_WARNING, "message", MAX_WARNINGS + 1, "w{}")
    with pytest.raises(ValidationError, match="too_long"):
        _manifest(semantic_status="SUCCEEDED_WITH_WARNINGS", warnings=warnings)
    approximations = sorted(
        _derived("appx", f"approximation-{index}")
        for index in range(MAX_APPROXIMATIONS + 1)
    )
    with pytest.raises(ValidationError, match="too_long"):
        _manifest(approximations=approximations)
    assert len(_manifest(approximations=approximations[:-1]).approximations) == (
        MAX_APPROXIMATIONS
    )


def test_approximations_must_be_sorted_and_unique() -> None:
    ordered = sorted((_APPROXIMATION_A, _APPROXIMATION_B))
    assert _manifest(approximations=ordered).approximations == tuple(ordered)
    with pytest.raises(ValueError, match="sorted"):
        _manifest(approximations=list(reversed(ordered)))
    with pytest.raises(ValueError, match="unique"):
        _manifest(approximations=[_APPROXIMATION_A, _APPROXIMATION_A])


def test_candidate_metric_value_status_pairs_with_its_value() -> None:
    defined = CandidateMetric.model_validate_json(json.dumps(_METRIC))
    assert str(defined.value) == "0.125"
    assert defined.model_dump(mode="json")["value"] == "0.125"
    undefined = CandidateMetric.model_validate_json(json.dumps(_UNDEFINED_METRIC))
    assert _missing(undefined.value)
    assert "value" not in undefined.model_dump(mode="json")
    with pytest.raises(ValueError, match="value_status"):
        CandidateMetric.model_validate_json(
            json.dumps({**_METRIC, "value_status": "UNDEFINED"})
        )
    with pytest.raises(ValueError, match="value_status"):
        CandidateMetric.model_validate_json(
            json.dumps({**_UNDEFINED_METRIC, "value_status": "DEFINED"})
        )
    with pytest.raises(ValidationError, match="canonical"):
        CandidateMetric.model_validate_json(json.dumps({**_METRIC, "value": "0.1250"}))
    with pytest.raises(ValidationError, match="literal_error"):
        CandidateMetric.model_validate_json(
            json.dumps({**_METRIC, "value_status": "MISSING"})
        )
    with pytest.raises(ValidationError, match="string_pattern_mismatch"):
        CandidateMetric.model_validate_json(json.dumps({**_METRIC, "unit": "Ratio"}))


def test_run_provenance_is_the_spec_ten_three_list_with_bounded_attempts() -> None:
    provenance = RunProvenance.model_validate_json(json.dumps(_PROVENANCE))
    assert provenance.negotiated_versions == _NEGOTIATED
    assert provenance.model_dump(mode="json") == _PROVENANCE
    for attempt in (0, 6):
        with pytest.raises(ValidationError):
            RunProvenance.model_validate_json(
                json.dumps({**_PROVENANCE, "attempt_number": attempt})
            )
    with pytest.raises(ValidationError, match="enum"):
        RunProvenance.model_validate_json(
            json.dumps({**_PROVENANCE, "comparison_level": "LEVEL_4"})
        )
    with pytest.raises(ValidationError, match="slot_"):
        RunProvenance.model_validate_json(
            json.dumps({**_PROVENANCE, "logical_slot_id": RUN_ID})
        )


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"relative_path": "../escape.bin"}, "candidate path"),
        ({"relative_path": "C:/escape.bin"}, "candidate path"),
        ({"relative_path": "results/CON"}, "reserved"),
        ({"relative_path": "a" * 513}, "string_too_long"),
        ({"artifact_kind": "Engine"}, "string_pattern_mismatch"),
        ({"media_type": "Application/Octet-Stream"}, "string_pattern_mismatch"),
        ({"declared_size_bytes": -1}, "greater_than_equal"),
        ({"declared_size_bytes": 2**53}, "less_than_equal"),
        ({"declared_sha256": "A" * 64}, "string_pattern_mismatch"),
    ],
)
def test_the_declaration_reuses_the_path_grammar_and_the_declared_bounds(
    updates: dict[str, Any], expected: str
) -> None:
    with pytest.raises(ValidationError, match=expected):
        CandidateArtifactDeclaration.model_validate_json(
            json.dumps({**_DECLARATION, **updates})
        )
    declaration = CandidateArtifactDeclaration.model_validate_json(
        json.dumps(_DECLARATION)
    )
    assert declaration.model_dump(mode="json") == _DECLARATION
    # The same five values validate as the event payload: one shape, two classes.
    assert ArtifactProducedPayload.model_validate(_DECLARATION).model_dump() == (
        declaration.model_dump()
    )


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"schema_version": "2.0.0"}, "literal_error"),
        ({"protocol_version": "0.9.0"}, "literal_error"),
        ({"adapter_manifest_id": RUN_ID}, "amf_"),
        ({"experiment_id": RUN_ID}, "exp_"),
        ({"run_id": EXPERIMENT_ID}, "run_"),
        ({"invocation_id": RUN_ID}, "inv_"),
        ({"attempt_token": "short"}, "string_too_short"),
        ({"attempt_token": "!" * 32}, "string_pattern_mismatch"),
        ({"attempt_token": _TOKEN_HASH[:31] + "/"}, "string_pattern_mismatch"),
        ({"semantic_status": "succeeded"}, "enum"),
        ({"started_at_utc": "2026-09-11T10:00:00+00:00"}, "canonical UTC"),
        ({"completed_at_utc": "2026-09-11T24:00:00Z"}, "valid datetime"),
    ],
)
def test_the_manifest_rejects_strict_type_and_identity_violations(
    updates: dict[str, Any], expected: str
) -> None:
    with pytest.raises(ValidationError, match=expected) as captured:
        _manifest(**updates)
    assert ATTEMPT_TOKEN not in str(captured.value)


@pytest.mark.parametrize(
    "model", [AdapterResultManifest, SanitizedAdapterResultManifest]
)
def test_the_manifest_schemas_publish_the_status_coupling_and_are_closed(
    model: type[Any],
) -> None:
    """Preventive for Task 9 (schemas 33 and 34): both modes render identically, every
    object is closed, uniqueItems is published, and the status coupling is published
    as ``if``/``then`` clauses that reject exactly what the runtime rejects."""
    schema = TypeAdapter(model).json_schema(mode="validation")
    Draft202012Validator.check_schema(schema)
    assert schema == TypeAdapter(model).json_schema(mode="serialization")
    assert schema["additionalProperties"] is False
    for name, definition in schema["$defs"].items():
        if definition.get("type") == "object":
            assert definition["additionalProperties"] is False, name
    assert "UtcDateTime" not in schema["$defs"]
    assert schema["required"] == list(model.model_fields)
    assert schema["properties"]["approximations"]["uniqueItems"] is True
    validator = Draft202012Validator(schema)
    candidates: dict[str, Any]
    no_candidates: dict[str, Any]
    if model is AdapterResultManifest:
        baseline = _manifest_document()
        candidates = {"candidate_artifacts": [_DECLARATION]}
        no_candidates = {"candidate_artifacts": []}
        for field in ("candidate_artifacts", "candidate_metrics"):
            assert schema["properties"][field]["uniqueItems"] is True
    else:
        base = _sanitized()
        baseline = base.model_dump(mode="json")
        candidates = {
            "candidate_artifact_ids": baseline["candidate_artifact_ids"],
            "candidate_declarations": baseline["candidate_declarations"],
        }
        no_candidates = {"candidate_artifact_ids": [], "candidate_declarations": []}
        assert schema["properties"]["candidate_artifact_ids"]["uniqueItems"] is True
    assert validator.is_valid(baseline)
    assert not validator.is_valid({**baseline, "unexpected": 1})
    assert not validator.is_valid({**baseline, "warnings": [_WARNING]})
    assert not validator.is_valid(
        {**baseline, "semantic_status": "SUCCEEDED_WITH_WARNINGS"}
    )
    assert validator.is_valid(
        {
            **baseline,
            "semantic_status": "SUCCEEDED_WITH_WARNINGS",
            "warnings": [_WARNING],
        }
    )
    for status in _NON_SUCCESS:
        assert not validator.is_valid(
            {**baseline, "semantic_status": status.value, **no_candidates}
        )
        assert not validator.is_valid(
            {
                **baseline,
                "semantic_status": status.value,
                "diagnostics": [_DIAGNOSTIC],
                **candidates,
            }
        )
        assert validator.is_valid(
            {
                **baseline,
                "semantic_status": status.value,
                "diagnostics": [_DIAGNOSTIC],
                **no_candidates,
            }
        )
    # The metric rule is published on the nested definition.
    metric_schema = TypeAdapter(CandidateMetric).json_schema()
    metric_validator = Draft202012Validator(metric_schema)
    assert metric_validator.is_valid(_METRIC)
    assert metric_validator.is_valid(_UNDEFINED_METRIC)
    assert not metric_validator.is_valid({**_METRIC, "value_status": "UNDEFINED"})
    assert not metric_validator.is_valid(
        {**_UNDEFINED_METRIC, "value_status": "DEFINED"}
    )


# --- parse_result_manifest -----------------------------------------------------------


def test_valid_manifest_bytes_parse_with_header_and_source_hash() -> None:
    output = _encode(_manifest_document())
    parsed = _parse_manifest(output)
    assert parsed.byte_length == len(output)
    assert parsed.source_hash == hashlib.sha256(output).hexdigest()
    assert parsed.manifest == _manifest()
    assert _missing(parsed.failure_code)
    assert parsed.redactions == 0
    assert parsed.header == _conformant_header(request_id=None)
    assert _missing(parsed.header.request_id)
    assert parsed.header.attempt_token_hash == _TOKEN_HASH
    assert ATTEMPT_TOKEN not in repr(parsed)
    assert parsed.model_dump_json().count(ATTEMPT_TOKEN) == 1
    assert parsed == _parse_manifest(output)
    with pytest.raises(ValidationError, match="frozen"):
        parsed.redactions = 1


def test_oversized_manifest_bytes_are_never_decoded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(json, "loads", _forbidden)
    output = _encode(_manifest_document()) + b"\xff"
    parsed = _parse_manifest(output, max_bytes=len(output) - 1)
    assert parsed.failure_code == ARTIFACT_RESULT_MANIFEST_INVALID
    assert _missing(parsed.header)
    assert _missing(parsed.manifest)
    assert parsed.redactions == 0
    assert parsed.byte_length == len(output)
    assert parsed.source_hash == sha256_bytes(output)


def test_manifest_bytes_at_the_ceiling_parse_and_one_more_does_not() -> None:
    output = _encode(_manifest_document())
    assert not _missing(_parse_manifest(output, max_bytes=len(output)).manifest)
    assert _parse_manifest(output, max_bytes=len(output) - 1).failure_code == (
        ARTIFACT_RESULT_MANIFEST_INVALID
    )


@pytest.mark.parametrize("output", _NON_OBJECT_OUTPUTS, ids=_NON_OBJECT_IDS)
def test_manifest_bytes_that_are_not_a_json_object_carry_no_header(
    output: bytes,
) -> None:
    parsed = _parse_manifest(output)
    assert parsed.failure_code == ARTIFACT_RESULT_MANIFEST_INVALID
    assert _missing(parsed.header)
    assert _missing(parsed.manifest)
    assert parsed.redactions == 0
    assert parsed.byte_length == len(output)


def test_an_unknown_field_populates_the_manifest_header_and_is_invalid() -> None:
    parsed = _parse_manifest(_encode(_manifest_document(unexpected=1)))
    assert parsed.failure_code == ARTIFACT_RESULT_MANIFEST_INVALID
    assert _missing(parsed.manifest)
    assert parsed.header == _conformant_header(request_id=None)


@pytest.mark.parametrize("field", ["protocol_version", "schema_version"])
def test_an_unsupported_version_is_named_by_the_manifest_header(field: str) -> None:
    parsed = _parse_manifest(_encode(_manifest_document(**{field: "2.0.0"})))
    assert parsed.failure_code == PROTOCOL_UNSUPPORTED_VERSION
    assert _missing(parsed.manifest)
    assert getattr(parsed.header, field) == "2.0.0"
    assert parsed.header.attempt_token_hash == _TOKEN_HASH


@pytest.mark.parametrize(
    "value",
    [
        "C:/escape.bin",
        "../escape.bin",
        "results/../x.bin",
        "results/CON",
        "",
        "a" * 513,
        7,
    ],
    ids=[
        "drive",
        "parent",
        "interior-parent",
        "reserved",
        "empty",
        "long",
        "wrong-type",
    ],
)
def test_a_declaration_path_escape_is_recorded_as_a_path_boundary_violation(
    value: Any,
) -> None:
    document = _manifest_document(
        candidate_artifacts=[
            _DECLARATION,
            {**_SECOND_DECLARATION, "relative_path": value},
        ]
    )
    parsed = _parse_manifest(_encode(document))
    assert parsed.failure_code == ARTIFACT_PATH_BOUNDARY_VIOLATION
    assert _missing(parsed.manifest)
    assert parsed.header == _conformant_header(request_id=None)
    assert ATTEMPT_TOKEN not in parsed.model_dump_json()


def test_an_absent_path_and_a_path_named_key_elsewhere_are_manifest_invalid() -> None:
    """Declared reading R8: only an error located at a declaration's own
    ``relative_path`` is the path violation."""
    absent = dict(_DECLARATION)
    del absent["relative_path"]
    assert (
        _parse_manifest(
            _encode(_manifest_document(candidate_artifacts=[absent]))
        ).failure_code
        == ARTIFACT_RESULT_MANIFEST_INVALID
    )
    for document in (
        _manifest_document(relative_path="C:/escape.bin"),
        _manifest_document(candidate_metrics=[{**_METRIC, "relative_path": "C:/x"}]),
        _manifest_document(provenance={**_PROVENANCE, "relative_path": "../x"}),
        _manifest_document(candidate_artifacts=["results/native.bin"]),
    ):
        parsed = _parse_manifest(_encode(document))
        assert parsed.failure_code == ARTIFACT_RESULT_MANIFEST_INVALID, document
        assert not _missing(parsed.header)
    # A diagnostic detail key spelled ``relative_path`` is bounded data, not a path
    # field: the manifest is strict-valid and the text is carried as declared.
    data = _parse_manifest(
        _encode(
            _manifest_document(
                diagnostics=[
                    {**_DIAGNOSTIC, "details": {"relative_path": "C:/escape.bin"}}
                ]
            )
        )
    )
    assert _missing(data.failure_code)
    assert data.manifest.diagnostics[0].details == {"relative_path": "C:/escape.bin"}


def test_the_path_located_classification_wins_over_every_other_error() -> None:
    document = _manifest_document(
        candidate_artifacts=[{**_DECLARATION, "relative_path": "C:/escape.bin"}],
        unexpected=1,
        semantic_status="FAILED",
    )
    assert _parse_manifest(_encode(document)).failure_code == (
        ARTIFACT_PATH_BOUNDARY_VIOLATION
    )


def test_the_manifests_own_token_in_text_is_redacted_in_place_and_counted() -> None:
    """Plan 3.11: every text field is redacted with the run's token before strict
    validation; the manifest stays strict-valid and its ``attempt_token`` field is
    retained verbatim for the hash comparison."""
    document = _manifest_document(
        semantic_status="SUCCEEDED_WITH_WARNINGS",
        warnings=[{**_WARNING, "message": f"engine said {ATTEMPT_TOKEN}"}],
        diagnostics=[
            {**_DIAGNOSTIC, "message": ATTEMPT_TOKEN, "details": {"log": ATTEMPT_TOKEN}}
        ],
    )
    parsed = _parse_manifest(_encode(document))
    assert parsed.redactions == 3
    assert _missing(parsed.failure_code)
    manifest = parsed.manifest
    assert manifest.attempt_token == ATTEMPT_TOKEN
    assert manifest.warnings[0].message == f"engine said {REDACTION_PLACEHOLDER}"
    assert manifest.diagnostics[0].message == REDACTION_PLACEHOLDER
    assert manifest.diagnostics[0].details == {"log": REDACTION_PLACEHOLDER}
    dumped = parsed.model_dump_json()
    assert dumped.count(ATTEMPT_TOKEN) == 1
    assert ATTEMPT_TOKEN not in repr(parsed)
    assert parsed.header.attempt_token_hash == _TOKEN_HASH


def test_a_token_in_an_identifier_field_is_manifest_invalid_after_redaction() -> None:
    document = _manifest_document(
        attempt_token=_IDENTIFIER_TOKEN,
        candidate_artifacts=[{**_DECLARATION, "artifact_kind": _IDENTIFIER_TOKEN}],
    )
    # Control: without redaction the same document is a strict-valid manifest.
    control = AdapterResultManifest.model_validate_json(_encode(document))
    assert control.candidate_artifacts[0].artifact_kind == _IDENTIFIER_TOKEN
    parsed = _parse_manifest(_encode(document), token=_IDENTIFIER_TOKEN)
    assert parsed.failure_code == ARTIFACT_RESULT_MANIFEST_INVALID
    assert parsed.redactions == 1
    assert _missing(parsed.manifest)
    assert _IDENTIFIER_TOKEN not in parsed.model_dump_json()
    # Control: the manifest's own attempt_token key is exempt, so a conformant
    # document under the same token is redaction-free and strict-valid.
    conformant = _parse_manifest(
        _encode(_manifest_document(attempt_token=_IDENTIFIER_TOKEN)),
        token=_IDENTIFIER_TOKEN,
    )
    assert conformant.redactions == 0
    assert not _missing(conformant.manifest)


def test_a_token_as_a_relative_path_is_a_path_boundary_violation() -> None:
    document = _manifest_document(
        attempt_token=_IDENTIFIER_TOKEN,
        candidate_artifacts=[{**_DECLARATION, "relative_path": _IDENTIFIER_TOKEN}],
    )
    control = AdapterResultManifest.model_validate_json(_encode(document))
    assert control.candidate_artifacts[0].relative_path == _IDENTIFIER_TOKEN
    parsed = _parse_manifest(_encode(document), token=_IDENTIFIER_TOKEN)
    assert parsed.failure_code == ARTIFACT_PATH_BOUNDARY_VIOLATION
    assert parsed.redactions == 1
    assert _IDENTIFIER_TOKEN not in parsed.model_dump_json()


def test_a_manifest_carrying_another_token_is_recorded_for_the_reconciler() -> None:
    """Declared reading R10: the parser hashes the manifest's own token into the header
    and redacts with the run's; identity is the reconciler's check (3)."""
    parsed = _parse_manifest(_encode(_manifest_document(attempt_token=_WRONG_TOKEN)))
    assert not _missing(parsed.manifest)
    assert parsed.header.attempt_token_hash == attempt_token_hash(_WRONG_TOKEN)
    assert parsed.header.attempt_token_hash != _TOKEN_HASH
    assert parsed.redactions == 0
    assert _WRONG_TOKEN not in repr(parsed)
    for hostile in (5, "", "x" * 1025):
        unreadable = _parse_manifest(_encode(_manifest_document(attempt_token=hostile)))
        assert _missing(unreadable.header.attempt_token_hash)
        assert unreadable.failure_code == ARTIFACT_RESULT_MANIFEST_INVALID


def test_a_manifest_header_hash_comes_only_from_the_raw_token() -> None:
    """Cross-check finding: the manifest's identity proof is possession of the raw
    token (plan 3.11: hashed at once, "otherwise MISSING"); a declared
    ``attempt_token_hash`` key, which every core record already carries, must not
    stand in for it, or a stale writer would pass the reconciler's identity check and
    be classified as a schema failure. The declared-hash source exists for the
    token-free validation result alone."""
    document = _manifest_document(attempt_token_hash=_TOKEN_HASH)
    del document["attempt_token"]
    parsed = _parse_manifest(_encode(document))
    assert _missing(parsed.header.attempt_token_hash)
    assert parsed.failure_code == ARTIFACT_RESULT_MANIFEST_INVALID
    assert _missing(parsed.manifest)
    for hostile in (5, "", "x" * 1025):
        beside = _manifest_document(
            attempt_token=hostile, attempt_token_hash=_TOKEN_HASH
        )
        assert _missing(_parse_manifest(_encode(beside)).header.attempt_token_hash)
    # Control: the validation result carries its declared hash (specification 14.1
    # "attempt-hash identity"), and a raw token found beside it is hashed instead.
    declared = _parse_validation(_encode(_validation_document()))
    assert declared.header.attempt_token_hash == _TOKEN_HASH
    beside_raw = _parse_validation(
        _encode(_validation_document(attempt_token=_WRONG_TOKEN))
    )
    assert beside_raw.header.attempt_token_hash == attempt_token_hash(_WRONG_TOKEN)


def test_a_header_field_that_outgrows_its_bound_under_redaction_reads_as_missing() -> (
    None
):
    """Preventive (began green): the parser admits a token of any length from 1
    character, so redaction can lengthen a header value; the bound is re-checked
    after redaction and an outgrown value reads as MISSING rather than leaving a
    2,400-character header field behind."""
    short = "A"
    grown = _parse_manifest(_encode(_manifest_document(run_id="A" * 100)), token=short)
    assert _missing(grown.header.run_id)
    assert grown.header.invocation_id == INVOCATION_ID
    assert grown.failure_code == ARTIFACT_RESULT_MANIFEST_INVALID
    within = _parse_manifest(_encode(_manifest_document(run_id="A" * 4)), token=short)
    assert within.header.run_id == REDACTION_PLACEHOLDER * 4
    assert "A" * 4 not in within.header.run_id


def test_a_declared_hash_that_spells_the_token_reads_as_missing() -> None:
    """Reviewer note: a run token that is itself lowercase hex could be padded into a
    64-character ``attempt_token_hash`` and echoed through the header. The declared
    value is redacted before its shape is checked, so it reads as MISSING and the
    parse stays token-free (R14) for this placement too."""
    document = _validation_document(attempt_token_hash=_DIGIT_TOKEN * 2)
    parsed = _parse_validation(_encode(document), token=_DIGIT_TOKEN)
    assert _missing(parsed.header.attempt_token_hash)
    assert parsed.failure_code == PROTOCOL_VALIDATION_RESULT_INVALID
    assert _DIGIT_TOKEN not in parsed.model_dump_json()
    assert _DIGIT_TOKEN not in repr(parsed)
    # Control: the same document under another run token carries the declared hash.
    control = _parse_validation(_encode(document), token=ATTEMPT_TOKEN)
    assert control.header.attempt_token_hash == _DIGIT_TOKEN * 2


def test_a_token_in_a_nested_attempt_token_key_is_redacted_not_exempt() -> None:
    parsed = _parse_manifest(
        _encode(
            _manifest_document(
                provenance={**_PROVENANCE, "attempt_token": ATTEMPT_TOKEN}
            )
        )
    )
    assert parsed.failure_code == ARTIFACT_RESULT_MANIFEST_INVALID
    assert parsed.redactions == 1
    assert parsed.model_dump_json().count(ATTEMPT_TOKEN) == 0


def test_an_all_digit_token_spelled_as_a_json_number_cannot_survive() -> None:
    """Prompt section 18: the redaction walk leaves numbers untouched, so the token
    must be refused by the strict bounds instead; no strict integer field admits a
    thirty-two digit value."""
    document = _manifest_document(
        attempt_token=_DIGIT_TOKEN,
        diagnostics=[{**_DIAGNOSTIC, "details": {"n": int(_DIGIT_TOKEN)}}],
    )
    parsed = _parse_manifest(_encode(document), token=_DIGIT_TOKEN)
    assert parsed.failure_code == ARTIFACT_RESULT_MANIFEST_INVALID
    assert parsed.redactions == 0
    assert _DIGIT_TOKEN not in parsed.model_dump_json()
    sized = _manifest_document(
        attempt_token=_DIGIT_TOKEN,
        candidate_artifacts=[
            {**_DECLARATION, "declared_size_bytes": int(_DIGIT_TOKEN)}
        ],
    )
    assert _parse_manifest(_encode(sized), token=_DIGIT_TOKEN).failure_code == (
        ARTIFACT_RESULT_MANIFEST_INVALID
    )


def test_a_key_collapse_under_redaction_is_manifest_invalid() -> None:
    document = _manifest_document(
        diagnostics=[
            {
                **_DIAGNOSTIC,
                "details": {f"k{ATTEMPT_TOKEN}": 1, f"k{REDACTION_PLACEHOLDER}": 2},
            }
        ]
    )
    parsed = _parse_manifest(_encode(document))
    assert parsed.failure_code == ARTIFACT_RESULT_MANIFEST_INVALID
    assert parsed.redactions == 0
    assert ATTEMPT_TOKEN not in parsed.model_dump_json()


def test_a_deeply_nested_manifest_field_is_invalid_and_never_raises() -> None:
    depth = 1200
    prefix = _encode(_manifest_document())[:-1]
    nested = prefix + b',"nested":' + b"[" * depth + b"1" + b"]" * depth + b"}"
    assert isinstance(json.loads(nested), dict)
    parsed = _parse_manifest(nested)
    assert parsed.failure_code == ARTIFACT_RESULT_MANIFEST_INVALID
    assert not _missing(parsed.header)
    assert _missing(parsed.manifest)
    assert ATTEMPT_TOKEN not in parsed.model_dump_json()


def _repeated(document: dict[str, Any], key: str, value: Any) -> bytes:
    inner = json.dumps(document, sort_keys=True, separators=(",", ":"))[1:-1]
    repeated = json.dumps({key: value}, separators=(",", ":"))[1:-1]
    return b"{" + repeated.encode("utf-8") + b"," + inner.encode("utf-8") + b"}"


def _raw_number(output: bytes, key: str, current: int, digits: int) -> bytes:
    marker = f'"{key}":{current}'.encode()
    assert marker in output
    return output.replace(marker, f'"{key}":'.encode() + b"9" * digits, 1)


@pytest.mark.parametrize(
    "output",
    [
        _repeated(_manifest_document(), "attempt_token", _WRONG_TOKEN),
        _repeated(_manifest_document(), "invocation_id", OTHER_INVOCATION_ID),
        _repeated(_manifest_document(), "protocol_version", "2.0.0"),
        _encode(_manifest_document()).replace(
            b'"provenance":{', b'"provenance":{"request_hash":"x",', 1
        ),
        _encode(_manifest_document(invocation_id=chr(0xD800))),
        _encode(_manifest_document(attempt_token=chr(0xD800) * 32)),
        _encode(_manifest_document(semantic_status=chr(0xD800))),
        _encode(_manifest_document(warnings=[{**_WARNING, "message": chr(0xDC00)}])),
        _raw_number(_encode(_manifest_document()), "attempt_number", 1, 5000),
        _raw_number(_encode(_manifest_document()), "declared_size_bytes", 12, 5000),
        _encode(_manifest_document(candidate_metrics=[{**_METRIC, "value": 1e400}])),
        _encode(_manifest_document(**{ATTEMPT_TOKEN: 1})),
        _encode(_manifest_document(started_at_utc=ATTEMPT_TOKEN)),
        _encode(_manifest_document(adapter_manifest_id=ATTEMPT_TOKEN)),
        _encode(_manifest_document(run_id=ATTEMPT_TOKEN)),
        _encode(_manifest_document(approximations=[ATTEMPT_TOKEN])),
        b'{"invocation_id": "' + b"x" * 200_000 + b'"}',
        json.dumps(_manifest_document(), ensure_ascii=True).encode("utf-8"),
    ],
    ids=[
        "repeated-token",
        "repeated-invocation",
        "repeated-version",
        "repeated-nested-key",
        "surrogate-invocation",
        "surrogate-token",
        "surrogate-status",
        "surrogate-message",
        "huge-attempt-digits",
        "huge-size-digits",
        "float-overflow",
        "token-as-key",
        "token-as-timestamp",
        "token-as-manifest-id",
        "token-as-run-id",
        "token-as-approximation",
        "long-string",
        "ascii-escaped",
    ],
)
def test_hostile_manifests_parse_or_fail_but_never_raise_or_leak(output: bytes) -> None:
    parsed = _parse_manifest(output)
    dumped = parsed.model_dump_json()
    assert ATTEMPT_TOKEN not in repr(parsed)
    if _missing(parsed.manifest):
        assert parsed.failure_code in _MANIFEST_CODES
        assert ATTEMPT_TOKEN not in dumped
    else:
        assert dumped.count(ATTEMPT_TOKEN) == 1
    # The same bytes through the validation parser never raise or leak either.
    other = _parse_validation(output)
    if _missing(other.result):
        assert other.failure_code in _VALIDATION_CODES
    assert ATTEMPT_TOKEN not in other.model_dump_json()


def test_manifest_parse_arguments_are_type_and_bound_checked() -> None:
    output = _encode(_manifest_document())
    with pytest.raises(TypeError, match="bytes"):
        parse_result_manifest(output.decode(), max_bytes=10, token=ATTEMPT_TOKEN)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="max_bytes"):
        parse_result_manifest(output, max_bytes=1.5, token=ATTEMPT_TOKEN)  # type: ignore[arg-type]
    for bound in (0, MAX_RESULT_MANIFEST_BYTES + 1):
        with pytest.raises(ValueError, match="max_bytes"):
            parse_result_manifest(output, max_bytes=bound, token=ATTEMPT_TOKEN)
    with pytest.raises(TypeError, match="token"):
        parse_result_manifest(output, max_bytes=10, token=None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="token"):
        parse_result_manifest(output, max_bytes=10, token="")


def test_the_manifest_parse_record_restates_its_invariants() -> None:
    facts: dict[str, Any] = {"byte_length": 3, "source_hash": _HASH, "redactions": 0}
    header = _conformant_header(request_id=None)
    manifest = _manifest()
    with pytest.raises(ValueError, match="exactly one"):
        ManifestParse.model_validate(facts)
    with pytest.raises(ValueError, match="header"):
        ManifestParse.model_validate({**facts, "manifest": manifest})
    with pytest.raises(ValueError, match="agreeing"):
        ManifestParse.model_validate(
            {
                **facts,
                "header": _conformant_header(
                    request_id=None, attempt_token_hash=attempt_token_hash(_WRONG_TOKEN)
                ),
                "manifest": manifest,
            }
        )
    with pytest.raises(ValueError, match="without a header"):
        ManifestParse.model_validate(
            {**facts, "failure_code": ARTIFACT_PATH_BOUNDARY_VIOLATION}
        )
    with pytest.raises(ValueError, match="manifest parse code"):
        ManifestParse.model_validate(
            {
                **facts,
                "header": header,
                "failure_code": PROTOCOL_VALIDATION_RESULT_INVALID,
            }
        )
    with pytest.raises(ValueError, match="UNSUPPORTED_VERSION"):
        ManifestParse.model_validate(
            {**facts, "header": header, "failure_code": PROTOCOL_UNSUPPORTED_VERSION}
        )
    with pytest.raises(ValueError, match="UNSUPPORTED_VERSION"):
        ManifestParse.model_validate(
            {
                **facts,
                "header": _conformant_header(request_id=None, protocol_version="2.0.0"),
                "failure_code": ARTIFACT_PATH_BOUNDARY_VIOLATION,
            }
        )
    ManifestParse.model_validate({**facts, "header": header, "manifest": manifest})
    ManifestParse.model_validate(
        {**facts, "redactions": 4, "header": header, "manifest": manifest}
    )
    ManifestParse.model_validate(
        {**facts, "header": header, "failure_code": ARTIFACT_PATH_BOUNDARY_VIOLATION}
    )
    ManifestParse.model_validate(
        {**facts, "failure_code": ARTIFACT_RESULT_MANIFEST_INVALID}
    )


# --- sanitize_result_manifest and SanitizedAdapterResultManifest ----------------------


def test_sanitization_derives_identities_hashes_and_carries_no_path_or_token() -> None:
    """Plan Task 5 Step 1: the core derives every candidate identity, the token becomes
    its hash, the source hash is the exact bytes, the sanitized hash recomputes and
    differs from the source hash, and no raw token or path leaves."""
    output = _encode(
        _manifest_document(candidate_artifacts=[_SECOND_DECLARATION, _DECLARATION])
    )
    parsed = _parse_manifest(output)
    summary = _summary(_DECLARATION, _SECOND_DECLARATION)
    sanitized = sanitize_result_manifest(parsed, summary)
    expected_ids = {
        "results/native.bin": _candidate_id("results/native.bin"),
        "results/normalized.json": _candidate_id("results/normalized.json"),
    }
    assert sanitized.candidate_artifact_ids == tuple(sorted(expected_ids.values()))
    assert tuple(d.candidate_artifact_id for d in sanitized.candidate_declarations) == (
        sanitized.candidate_artifact_ids
    )
    by_id = {d.candidate_artifact_id: d for d in sanitized.candidate_declarations}
    native = by_id[expected_ids["results/native.bin"]]
    assert native.source_event_id == summary.artifact_declarations[0].event_id
    assert native.artifact_kind == "engine.native"
    assert native.media_type == "application/octet-stream"
    assert native.declared_size_bytes == 12
    assert native.declared_sha256 == _HASH
    normalized = by_id[expected_ids["results/normalized.json"]]
    assert normalized.source_event_id == summary.artifact_declarations[1].event_id
    assert sanitized.attempt_token_hash == _TOKEN_HASH
    assert sanitized.source_adapter_result_manifest_hash == sha256_bytes(output)
    assert sanitized.source_adapter_result_manifest_hash == parsed.source_hash
    assert sanitized.sanitized_adapter_result_manifest_hash == sanitized_manifest_hash(
        sanitized
    )
    assert sanitized.sanitized_adapter_result_manifest_hash != (
        sanitized.source_adapter_result_manifest_hash
    )
    for field in (
        "schema_version",
        "protocol_version",
        "adapter_manifest_id",
        "experiment_id",
        "run_id",
        "invocation_id",
        "semantic_status",
        "started_at_utc",
        "completed_at_utc",
        "provenance",
        "candidate_metrics",
        "diagnostics",
        "warnings",
        "approximations",
    ):
        assert getattr(sanitized, field) == getattr(parsed.manifest, field), field
    for text in (
        canonical_json_bytes(sanitized).decode("utf-8"),
        sanitized.model_dump_json(),
        repr(sanitized),
    ):
        assert ATTEMPT_TOKEN not in text
        assert "relative_path" not in text
        assert "results/native.bin" not in text
        assert "results/normalized.json" not in text
        assert '"attempt_token":' not in text
    assert "relative_path" not in SanitizedCandidateArtifactDeclaration.model_fields


def test_the_sanitized_hash_golden_is_the_profile_over_the_content_fields() -> None:
    """Plan 4: ``SANITIZED_ADAPTER_RESULT_MANIFEST_V1`` over the canonical sanitized
    content with only the self-hash omitted, reproducible from the stdlib formula
    over the profile envelope."""
    sanitized = _sanitized()
    content = sanitized.model_dump(mode="json")
    del content["sanitized_adapter_result_manifest_hash"]
    envelope = {
        "schema_version": "1.0.0",
        "hashing_profile": HashingProfile.SANITIZED_ADAPTER_RESULT_MANIFEST_V1.value,
        "payload": content,
    }
    assert sanitized_manifest_hash(sanitized) == _stdlib_digest(envelope)
    assert sanitized_manifest_hash(sanitized) == _SANITIZED_GOLDEN, (
        sanitized_manifest_hash(sanitized)
    )
    with pytest.raises(TypeError, match="SanitizedAdapterResultManifest"):
        sanitized_manifest_hash(_manifest())  # type: ignore[arg-type]
    payload = sanitized.model_dump(mode="python")
    payload["sanitized_adapter_result_manifest_hash"] = _OTHER_HASH
    with pytest.raises(
        ValueError, match="sanitized_adapter_result_manifest_hash"
    ) as captured:
        SanitizedAdapterResultManifest.model_validate(payload)
    assert ATTEMPT_TOKEN not in str(captured.value)


@pytest.mark.parametrize(
    "changes",
    [
        {"adapter_manifest_id": _derived("amf", "other")},
        {"experiment_id": _derived("exp", "other")},
        {"run_id": OTHER_RUN_ID},
        {"invocation_id": OTHER_INVOCATION_ID},
        {"attempt_token_hash": attempt_token_hash(_WRONG_TOKEN)},
        {
            "semantic_status": SemanticStatus.SUCCEEDED_WITH_WARNINGS,
            "warnings": (ProtocolWarning.model_validate_json(json.dumps(_WARNING)),),
        },
        {
            "started_at_utc": _manifest(
                started_at_utc="2026-09-11T09:59:59Z"
            ).started_at_utc
        },
        {
            "completed_at_utc": _manifest(
                completed_at_utc="2026-09-11T10:05:01Z"
            ).completed_at_utc
        },
        {
            "provenance": RunProvenance.model_validate_json(
                json.dumps({**_PROVENANCE, "attempt_number": 2})
            )
        },
        {
            "candidate_metrics": (
                CandidateMetric.model_validate_json(json.dumps(_METRIC)),
            )
        },
        {
            "diagnostics": (
                AdapterDiagnostic.model_validate_json(json.dumps(_DIAGNOSTIC)),
            )
        },
        {"approximations": (_APPROXIMATION_A,)},
        {"source_adapter_result_manifest_hash": _OTHER_HASH},
    ],
    ids=[
        "manifest-id",
        "experiment",
        "run",
        "invocation",
        "token-hash",
        "status-and-warnings",
        "started",
        "completed",
        "provenance",
        "metrics",
        "diagnostics",
        "approximations",
        "source-hash",
    ],
)
def test_every_material_sanitized_field_moves_the_sanitized_hash(
    changes: dict[str, Any],
) -> None:
    base = _sanitized()
    changed = _resanitized(base, **changes)
    for name, value in changes.items():
        assert getattr(changed, name) == value
    assert changed.sanitized_adapter_result_manifest_hash != (
        base.sanitized_adapter_result_manifest_hash
    )
    payload = changed.model_dump(mode="python")
    payload["sanitized_adapter_result_manifest_hash"] = (
        base.sanitized_adapter_result_manifest_hash
    )
    with pytest.raises(ValueError, match="sanitized_adapter_result_manifest_hash"):
        SanitizedAdapterResultManifest.model_validate(payload)


def test_a_candidate_declaration_change_moves_the_sanitized_hash() -> None:
    base = _sanitized()
    declaration = base.candidate_declarations[0]
    for change in (
        {"declared_sha256": _OTHER_HASH},
        {"declared_size_bytes": 13},
        {"source_event_id": _event_id("other")},
        {"artifact_kind": "engine.other"},
        {"media_type": "application/json"},
    ):
        replaced = SanitizedCandidateArtifactDeclaration.model_validate(
            {**declaration.model_dump(mode="python"), **change}
        )
        changed = _resanitized(base, candidate_declarations=(replaced,))
        assert changed.sanitized_adapter_result_manifest_hash != (
            base.sanitized_adapter_result_manifest_hash
        ), change
    # The identity itself is material too (paired with the identity tuple).
    other_id = _candidate_id("results/other.bin")
    replaced = SanitizedCandidateArtifactDeclaration.model_validate(
        {**declaration.model_dump(mode="python"), "candidate_artifact_id": other_id}
    )
    changed = _resanitized(
        base, candidate_artifact_ids=(other_id,), candidate_declarations=(replaced,)
    )
    assert changed.sanitized_adapter_result_manifest_hash != (
        base.sanitized_adapter_result_manifest_hash
    )


def test_the_sanitized_hash_is_invariant_under_key_permutation_of_the_dump() -> None:
    base = _sanitized()
    dumped = base.model_dump(mode="python")
    permuted = {name: dumped[name] for name in reversed(list(dumped))}
    assert list(permuted) != list(dumped)
    assert SanitizedAdapterResultManifest.model_validate(permuted) == base
    dumped_json = base.model_dump(mode="json")
    permuted_json = {name: dumped_json[name] for name in reversed(list(dumped_json))}
    from_json = SanitizedAdapterResultManifest.model_validate_json(
        json.dumps(permuted_json)
    )
    assert from_json == base
    assert (
        sanitized_manifest_hash(from_json)
        == base.sanitized_adapter_result_manifest_hash
    )


def test_sanitization_is_deterministic_under_wire_declaration_order() -> None:
    """Declared reading R5: declarations are canonicalized by identity, so two wire
    manifests differing only in declaration order sanitize to the same content and
    differ only in their exact-byte source hash."""
    summary = _summary(_DECLARATION, _SECOND_DECLARATION)
    forward = _parse_manifest(
        _encode(
            _manifest_document(candidate_artifacts=[_DECLARATION, _SECOND_DECLARATION])
        )
    )
    reverse = _parse_manifest(
        _encode(
            _manifest_document(candidate_artifacts=[_SECOND_DECLARATION, _DECLARATION])
        )
    )
    assert forward.source_hash != reverse.source_hash
    first = sanitize_result_manifest(forward, summary)
    second = sanitize_result_manifest(reverse, summary)
    assert sanitize_result_manifest(forward, summary) == first
    excluded = {
        "source_adapter_result_manifest_hash",
        "sanitized_adapter_result_manifest_hash",
    }
    assert first.model_dump(exclude=excluded) == second.model_dump(exclude=excluded)
    assert first.sanitized_adapter_result_manifest_hash != (
        second.sanitized_adapter_result_manifest_hash
    )


def test_sanitization_requires_a_parsed_manifest_and_its_accepted_events() -> None:
    """Plan 9.2: ``sanitize_result_manifest`` is never called when a declaration lacks
    its event; that precondition is a caller error, never an adapter outcome."""
    parsed = _parse_manifest(_encode(_manifest_document()))
    with pytest.raises(ValueError, match="parsed manifest"):
        sanitize_result_manifest(_parse_manifest(b"{}"), _summary(_DECLARATION))
    with pytest.raises(ValueError, match="accepted"):
        sanitize_result_manifest(parsed, _summary())
    with pytest.raises(ValueError, match="accepted"):
        sanitize_result_manifest(parsed, _summary(_SECOND_DECLARATION))
    with pytest.raises(ValueError, match="differs"):
        sanitize_result_manifest(
            parsed, _summary({**_DECLARATION, "declared_size_bytes": 13})
        )
    with pytest.raises(TypeError, match="ManifestParse"):
        sanitize_result_manifest(parsed.manifest, _summary(_DECLARATION))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="ProtocolEventSummary"):
        sanitize_result_manifest(parsed, None)  # type: ignore[arg-type]
    # Extra accepted declarations (abandoned candidates) are ignored.
    extra = sanitize_result_manifest(
        parsed, _summary(_SECOND_DECLARATION, _DECLARATION)
    )
    assert extra.candidate_artifact_ids == (_candidate_id("results/native.bin"),)
    assert extra.candidate_declarations[0].source_event_id == _event_id("artifact:2")


def test_a_failed_manifest_without_candidates_sanitizes_to_evidence_material() -> None:
    sanitized = _sanitized(
        semantic_status="FAILED", diagnostics=[_DIAGNOSTIC], candidate_artifacts=[]
    )
    assert sanitized.semantic_status is SemanticStatus.FAILED
    assert sanitized.candidate_artifact_ids == ()
    assert sanitized.candidate_declarations == ()
    assert len(sanitized.diagnostics) == 1
    assert sanitized.attempt_token_hash == _TOKEN_HASH
    assert ATTEMPT_TOKEN not in sanitized.model_dump_json()


def test_the_sanitized_manifest_restates_the_coupling_and_identity_rules() -> None:
    base = _sanitized()
    with pytest.raises(ValueError, match="warning"):
        _resanitized(
            base, warnings=(ProtocolWarning.model_validate_json(json.dumps(_WARNING)),)
        )
    with pytest.raises(ValueError, match="warning"):
        _resanitized(base, semantic_status=SemanticStatus.SUCCEEDED_WITH_WARNINGS)
    with pytest.raises(ValueError, match="diagnostic"):
        _resanitized(
            base,
            semantic_status=SemanticStatus.FAILED,
            candidate_artifact_ids=(),
            candidate_declarations=(),
        )
    with pytest.raises(ValueError, match="candidate"):
        _resanitized(
            base,
            semantic_status=SemanticStatus.FAILED,
            diagnostics=(
                AdapterDiagnostic.model_validate_json(json.dumps(_DIAGNOSTIC)),
            ),
        )
    with pytest.raises(ValueError, match="candidate_artifact_ids"):
        _resanitized(base, candidate_declarations=())
    with pytest.raises(ValueError, match="candidate_artifact_ids"):
        _resanitized(base, candidate_artifact_ids=(_candidate_id("results/other.bin"),))
    two = _sanitized(candidate_artifacts=[_DECLARATION, _SECOND_DECLARATION])
    with pytest.raises(ValueError, match="candidate_artifact_ids"):
        _resanitized(
            two,
            candidate_artifact_ids=tuple(reversed(two.candidate_artifact_ids)),
            candidate_declarations=tuple(reversed(two.candidate_declarations)),
        )
    with pytest.raises(ValueError, match="completed_at_utc"):
        _resanitized(
            base,
            completed_at_utc=_manifest(
                started_at_utc="2026-09-11T09:00:00Z",
                completed_at_utc="2026-09-11T09:00:00Z",
            ).started_at_utc,
        )
    with pytest.raises(ValidationError, match="extra_forbidden"):
        SanitizedAdapterResultManifest.model_validate(
            {**base.model_dump(mode="python"), "attempt_token": ATTEMPT_TOKEN}
        )
    with pytest.raises(ValidationError, match="frozen"):
        base.semantic_status = SemanticStatus.FAILED
    # Both modes round-trip the sanitized record.
    for mode in _MODES:
        dumped = base.model_dump(mode=mode)
        restored = (
            SanitizedAdapterResultManifest.model_validate(dumped)
            if mode == "python"
            else SanitizedAdapterResultManifest.model_validate_json(json.dumps(dumped))
        )
        assert restored == base
