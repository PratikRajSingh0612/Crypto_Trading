"""Stage 6 Task 5: the sanitized manifest is a deterministic function of its inputs.

Properties over ``sanitize_result_manifest`` and the ``SANITIZED_ADAPTER_RESULT_
MANIFEST_V1`` identity (plan sections 4 and 14 Task 5; specification 10.2, 19.4):
the same (manifest bytes, summary) always sanitizes to the same record; a wire
manifest re-spelled with other key order, whitespace or declaration order sanitizes
to the same content and differs only in its exact-byte source hash; the sanitized
hash never equals the source hash; the identity is invariant under key permutation
of the sanitized dump and moves under every material mutation; and the validation
result identity has the same two properties. ``deadline=None`` because every
example validates several nested strict models and the suite may run under load.
"""

from __future__ import annotations

import json
from typing import Any, Final

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from crypto_lab.adapters.envelopes import NegotiatedVersions
from crypto_lab.adapters.events import (
    AdapterDiagnostic,
    ArtifactDeclarationRecord,
    ArtifactProducedPayload,
    ProtocolEventSummary,
    ProtocolWarning,
)
from crypto_lab.adapters.limits import MAX_RESULT_MANIFEST_BYTES
from crypto_lab.adapters.manifests import (
    AdapterValidationResult,
    RunProvenance,
    SanitizedAdapterResultManifest,
    SanitizedCandidateArtifactDeclaration,
    parse_result_manifest,
    sanitize_result_manifest,
    sanitized_manifest_hash,
    validation_result_hash,
)
from crypto_lab.adapters.vocabulary import NEGOTIABLE_SCHEMA_NAMES, SemanticStatus
from crypto_lab.domain.descriptors import SupportedSchemaVersion
from crypto_lab.domain.hashing import (
    _uuid4_shaped,
    attempt_token_hash,
    candidate_artifact_id_for,
    request_id_for,
    sha256_bytes,
)
from doubles.experiments import (
    ATTEMPT_TOKEN,
    EXPERIMENT_ID,
    INVOCATION_ID,
    REQUEST_HASH,
    RUN_ID,
    SLOT_A,
)

_HEX: Final = st.text(alphabet="0123456789abcdef", min_size=64, max_size=64)
_SEEDS: Final = st.text(min_size=1, max_size=12)
_SEGMENTS: Final = st.from_regex(r"[a-z][a-z0-9]{0,7}", fullmatch=True)
#: ``codec="utf-8"`` admits only encodable characters, so no lone surrogate is drawn.
_MESSAGES: Final = st.text(
    alphabet=st.characters(codec="utf-8", exclude_characters='\\"'),
    min_size=1,
    max_size=32,
)
_TOKENS: Final = st.text(
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-",
    min_size=32,
    max_size=64,
)
_STARTED: Final = "2026-09-11T10:00:00Z"
_COMPLETED: Final = "2026-09-11T10:05:00Z"
_NEGOTIATED: Final = NegotiatedVersions(
    protocol_version="1.0.0",
    schema_versions=tuple(
        SupportedSchemaVersion(schema_name=name, schema_version="1.0.0")
        for name in NEGOTIABLE_SCHEMA_NAMES
    ),
    capability_vocabulary_version="capabilities/v1",
)
_PROVENANCE: Final[dict[str, Any]] = {
    "experiment_spec_hash": "3" * 64,
    "request_hash": REQUEST_HASH,
    "strategy_version_hash": "1" * 64,
    "dataset_version_hash": "2" * 64,
    "configuration_hash": "4" * 64,
    "adapter": {"adapter_name": "adapter.alpha", "adapter_version": "1.0.0"},
    "engine": {"engine_name": "engine.alpha", "engine_version": "2.3.4"},
    "negotiated_versions": _NEGOTIATED.model_dump(mode="json"),
    "comparison_level": "LEVEL_2",
    "logical_slot_id": SLOT_A,
    "attempt_number": 1,
}
_HASH_FIELDS: Final[set[str]] = {
    "source_adapter_result_manifest_hash",
    "sanitized_adapter_result_manifest_hash",
}


def _derived(prefix: str, seed: str) -> str:
    return f"{prefix}_{_uuid4_shaped(sha256_bytes(seed.encode('utf-8')))}"


def _diagnostic(message: str) -> dict[str, Any]:
    return {
        "error_code": "ENGINE.DATA_GAP",
        "category": "ENGINE_RUNTIME",
        "severity": "ERROR",
        "message": message,
        "retriable": True,
        "details": {},
        "causal_event_ids": [],
    }


def _warning(message: str) -> dict[str, Any]:
    return {
        "warning_code": "ADAPTER.APPROXIMATED_FILLS",
        "message": message,
        "impact": "Level 3 comparison prevented.",
        "prevented_comparison_levels": ["LEVEL_3"],
    }


@st.composite
def declarations(draw: st.DrawFn) -> list[dict[str, Any]]:
    """Zero to three declarations with unique relative paths."""
    count = draw(st.integers(min_value=0, max_value=3))
    paths = draw(
        st.lists(_SEGMENTS, min_size=count, max_size=count, unique=True).map(
            lambda names: [f"results/{name}.bin" for name in names]
        )
    )
    return [
        {
            "relative_path": path,
            "artifact_kind": "engine.native",
            "media_type": "application/octet-stream",
            "declared_size_bytes": draw(st.integers(min_value=0, max_value=10**9)),
            "declared_sha256": draw(_HEX),
        }
        for path in paths
    ]


@st.composite
def manifest_documents(draw: st.DrawFn) -> dict[str, Any]:
    """A strict-valid wire manifest in one of three status shapes."""
    shape = draw(st.sampled_from(["SUCCEEDED", "SUCCEEDED_WITH_WARNINGS", "FAILED"]))
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "adapter_manifest_id": _derived("amf", draw(_SEEDS)),
        "experiment_id": EXPERIMENT_ID,
        "run_id": RUN_ID,
        "invocation_id": INVOCATION_ID,
        "attempt_token": ATTEMPT_TOKEN,
        "semantic_status": shape,
        "started_at_utc": _STARTED,
        "completed_at_utc": _COMPLETED,
        "provenance": {**_PROVENANCE, "configuration_hash": draw(_HEX)},
        "candidate_artifacts": [] if shape == "FAILED" else draw(declarations()),
        "candidate_metrics": [
            {
                "metric_name": "total.return",
                "value": str(draw(st.integers(min_value=-999, max_value=999))),
                "value_status": "DEFINED",
                "unit": "ratio",
                "methodology_version": "1.0.0",
                "comparison_level": "LEVEL_2",
            }
        ],
        "diagnostics": [_diagnostic(draw(_MESSAGES))] if shape == "FAILED" else [],
        "warnings": (
            [_warning(draw(_MESSAGES))] if shape == "SUCCEEDED_WITH_WARNINGS" else []
        ),
        "approximations": [],
    }
    return document


def _summary_for(document: dict[str, Any]) -> ProtocolEventSummary:
    records = tuple(
        ArtifactDeclarationRecord(
            event_id=_derived("evt", declaration["relative_path"]),
            payload=ArtifactProducedPayload.model_validate(declaration),
        )
        for declaration in document["candidate_artifacts"]
    )
    return ProtocolEventSummary.model_validate(
        {
            "accepted_count": len(records),
            "last_sequence": len(records),
            "artifact_declarations": records,
            "warnings": (),
            "adapter_diagnostics": (),
            "redactions": 0,
        }
    )


def _spell(document: dict[str, Any], *, order: list[str], indent: int | None) -> bytes:
    permuted = {name: document[name] for name in order}
    return json.dumps(permuted, indent=indent, ensure_ascii=False).encode("utf-8")


def _sanitize(
    output: bytes, summary: ProtocolEventSummary
) -> SanitizedAdapterResultManifest:
    parsed = parse_result_manifest(
        output, max_bytes=MAX_RESULT_MANIFEST_BYTES, token=ATTEMPT_TOKEN
    )
    assert parsed.failure_code.__class__ is not str, parsed.failure_code
    return sanitize_result_manifest(parsed, summary)


def _resanitized(
    base: SanitizedAdapterResultManifest, **changes: Any
) -> SanitizedAdapterResultManifest:
    draft = SanitizedAdapterResultManifest.model_construct(**{**dict(base), **changes})
    payload = draft.model_dump(mode="python")
    payload["sanitized_adapter_result_manifest_hash"] = sanitized_manifest_hash(draft)
    return SanitizedAdapterResultManifest.model_validate(payload)


# --- Determinism and spelling invariance ----------------------------------------------


@settings(max_examples=60, deadline=None)
@given(
    document=manifest_documents(),
    order=st.permutations(
        [
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
        ]
    ),
    indent=st.sampled_from([None, 1, 2]),
    reverse_declarations=st.booleans(),
)
def test_the_sanitized_manifest_is_a_deterministic_function_of_its_inputs(
    document: dict[str, Any],
    order: list[str],
    indent: int | None,
    reverse_declarations: bool,
) -> None:
    summary = _summary_for(document)
    canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
    first = _sanitize(canonical, summary)
    assert _sanitize(canonical, summary) == first
    assert first.source_adapter_result_manifest_hash == sha256_bytes(canonical)
    assert first.sanitized_adapter_result_manifest_hash == sanitized_manifest_hash(
        first
    )
    assert first.sanitized_adapter_result_manifest_hash != (
        first.source_adapter_result_manifest_hash
    )
    assert first.attempt_token_hash == attempt_token_hash(ATTEMPT_TOKEN)
    assert ATTEMPT_TOKEN not in first.model_dump_json()
    respelled_document = dict(document)
    if reverse_declarations:
        respelled_document["candidate_artifacts"] = list(
            reversed(document["candidate_artifacts"])
        )
    respelled = _spell(respelled_document, order=order, indent=indent)
    second = _sanitize(respelled, summary)
    assert second.model_dump(exclude=_HASH_FIELDS) == first.model_dump(
        exclude=_HASH_FIELDS
    )
    if respelled == canonical:
        assert second == first
    else:
        assert second.source_adapter_result_manifest_hash != (
            first.source_adapter_result_manifest_hash
        )
        assert second.sanitized_adapter_result_manifest_hash != (
            first.sanitized_adapter_result_manifest_hash
        )
    expected_ids = tuple(
        sorted(
            candidate_artifact_id_for(RUN_ID, INVOCATION_ID, d["relative_path"])
            for d in document["candidate_artifacts"]
        )
    )
    assert first.candidate_artifact_ids == expected_ids
    assert tuple(d.candidate_artifact_id for d in first.candidate_declarations) == (
        expected_ids
    )


@settings(max_examples=40, deadline=None)
@given(document=manifest_documents(), order=st.permutations(list(range(19))))
def test_the_sanitized_identity_is_invariant_under_key_permutation_of_the_dump(
    document: dict[str, Any], order: list[int]
) -> None:
    base = _sanitize(
        json.dumps(document, sort_keys=True, separators=(",", ":")).encode(),
        _summary_for(document),
    )
    dumped = base.model_dump(mode="json")
    names = list(dumped)
    assert len(names) == 19
    permuted = {names[index]: dumped[names[index]] for index in order}
    restored = SanitizedAdapterResultManifest.model_validate_json(json.dumps(permuted))
    assert restored == base
    assert (
        sanitized_manifest_hash(restored) == base.sanitized_adapter_result_manifest_hash
    )


# --- Material mutations ---------------------------------------------------------------


@st.composite
def sanitized_mutations(draw: st.DrawFn) -> tuple[str, dict[str, Any]]:
    """Exactly one material field replaced by another admitted, different value; the
    status change is paired with the warnings that make it admissible."""
    field = draw(
        st.sampled_from(
            [
                "adapter_manifest_id",
                "experiment_id",
                "run_id",
                "invocation_id",
                "attempt_token_hash",
                "semantic_status",
                "provenance",
                "candidate_declarations",
                "candidate_metrics",
                "diagnostics",
                "approximations",
                "source_adapter_result_manifest_hash",
            ]
        )
    )
    seed = draw(_SEEDS)
    if field == "adapter_manifest_id":
        return field, {field: _derived("amf", seed)}
    if field == "experiment_id":
        return field, {field: _derived("exp", seed)}
    if field == "run_id":
        return field, {field: _derived("run", seed)}
    if field == "invocation_id":
        return field, {field: _derived("inv", seed)}
    if field == "attempt_token_hash":
        return field, {field: attempt_token_hash(draw(_TOKENS))}
    if field == "semantic_status":
        return field, {
            field: SemanticStatus.SUCCEEDED_WITH_WARNINGS,
            "warnings": (
                ProtocolWarning.model_validate_json(
                    json.dumps(_warning(draw(_MESSAGES)))
                ),
            ),
        }
    if field == "provenance":
        return field, {
            field: RunProvenance.model_validate_json(
                json.dumps({**_PROVENANCE, "strategy_version_hash": draw(_HEX)})
            )
        }
    if field == "candidate_declarations":
        return field, {"declared_sha256": draw(_HEX)}
    if field == "candidate_metrics":
        return field, {field: ()}
    if field == "diagnostics":
        return field, {
            field: (
                AdapterDiagnostic.model_validate_json(json.dumps(_diagnostic(seed))),
            )
        }
    if field == "approximations":
        return field, {field: (_derived("appx", seed),)}
    return field, {field: draw(_HEX)}


@settings(max_examples=120, deadline=None)
@given(mutation=sanitized_mutations())
def test_every_material_sanitized_field_moves_the_identity(
    mutation: tuple[str, dict[str, Any]],
) -> None:
    field, changes = mutation
    base_document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "adapter_manifest_id": _derived("amf", "base"),
        "experiment_id": EXPERIMENT_ID,
        "run_id": RUN_ID,
        "invocation_id": INVOCATION_ID,
        "attempt_token": ATTEMPT_TOKEN,
        "semantic_status": "SUCCEEDED",
        "started_at_utc": _STARTED,
        "completed_at_utc": _COMPLETED,
        "provenance": _PROVENANCE,
        "candidate_artifacts": [
            {
                "relative_path": "results/native.bin",
                "artifact_kind": "engine.native",
                "media_type": "application/octet-stream",
                "declared_size_bytes": 12,
                "declared_sha256": "a" * 64,
            }
        ],
        "candidate_metrics": [
            {
                "metric_name": "total.return",
                "value": "0.125",
                "value_status": "DEFINED",
                "unit": "ratio",
                "methodology_version": "1.0.0",
                "comparison_level": "LEVEL_2",
            }
        ],
        "diagnostics": [],
        "warnings": [],
        "approximations": [],
    }
    base = _sanitize(
        json.dumps(base_document, sort_keys=True, separators=(",", ":")).encode(),
        _summary_for(base_document),
    )
    if field == "candidate_declarations":
        declaration = base.candidate_declarations[0]
        changes = {
            field: (
                SanitizedCandidateArtifactDeclaration.model_validate(
                    {**declaration.model_dump(mode="python"), **changes}
                ),
            )
        }
    if all(getattr(base, name) == value for name, value in changes.items()):
        return  # a drawn value that happens to equal the base is not a mutation
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
    with pytest.raises(
        ValueError, match="sanitized_adapter_result_manifest_hash"
    ) as captured:
        SanitizedAdapterResultManifest.model_validate(payload)
    assert ATTEMPT_TOKEN not in str(captured.value)


# --- The validation result identity ---------------------------------------------------


def _validation_document(**updates: Any) -> dict[str, Any]:
    document: dict[str, Any] = {
        "schema_version": "1.0.0",
        "protocol_version": "1.0.0",
        "request_id": request_id_for(RUN_ID),
        "invocation_id": INVOCATION_ID,
        "run_id": RUN_ID,
        "attempt_token_hash": attempt_token_hash(ATTEMPT_TOKEN),
        "outcome": "VALID",
        "diagnostics": [],
        "validated_at_utc": _STARTED,
    }
    document.update(updates)
    return document


@settings(max_examples=40, deadline=None)
@given(
    order=st.permutations(list(range(10))),
    outcome=st.sampled_from(["VALID", "NOT_APPLICABLE", "UNAVAILABLE", "INVALID"]),
    message=_MESSAGES,
)
def test_the_validation_identity_is_invariant_under_key_permutation(
    order: list[int], outcome: str, message: str
) -> None:
    document = _validation_document(
        outcome=outcome,
        diagnostics=[] if outcome == "VALID" else [_diagnostic(message)],
    )
    document["result_hash"] = sha256_bytes(
        json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    )
    names = list(document)
    assert len(names) == 10
    permuted = {names[index]: document[names[index]] for index in order}
    result = AdapterValidationResult.model_validate_json(json.dumps(permuted))
    assert validation_result_hash(result) == document["result_hash"]
    restored = AdapterValidationResult.model_validate(result.model_dump(mode="python"))
    assert restored == result


@settings(max_examples=60, deadline=None)
@given(
    field=st.sampled_from(
        [
            "request_id",
            "invocation_id",
            "run_id",
            "attempt_token_hash",
            "validated_at_utc",
        ]
    ),
    seed=_SEEDS,
    token=_TOKENS,
)
def test_every_material_validation_field_moves_the_identity(
    field: str, seed: str, token: str
) -> None:
    base = _validation_document()
    value: str
    if field == "request_id":
        value = request_id_for(_derived("run", seed))
    elif field == "invocation_id":
        value = _derived("inv", seed)
    elif field == "run_id":
        value = _derived("run", seed)
    elif field == "attempt_token_hash":
        value = attempt_token_hash(token)
    else:
        value = _COMPLETED
    if base[field] == value:
        return
    changed = {**base, field: value}
    digests = [
        sha256_bytes(
            json.dumps(
                document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode("utf-8")
        )
        for document in (base, changed)
    ]
    assert digests[0] != digests[1]
    result = AdapterValidationResult.model_validate_json(
        json.dumps({**changed, "result_hash": digests[1]})
    )
    assert validation_result_hash(result) == digests[1]
    with pytest.raises(ValueError, match="result_hash"):
        AdapterValidationResult.model_validate_json(
            json.dumps({**changed, "result_hash": digests[0]})
        )
