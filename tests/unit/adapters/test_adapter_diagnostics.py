"""Stage 6 Task 1: the closed Stage 6 diagnostic table and factory (Stage 6 plan
section 9.4).

The twenty-five codes are asserted against their category, retry posture and
severity; the hard-block column is proven to be exactly the Stage 5 category
partition; `PROCESS.UNRECOGNIZED_PROCESS_EXIT` is proven to have the Stage 5
posture and to mint the identical `Diagnostic` through both factories; identity
is proven content-derived; and every `Diagnostic` rule the factory checks up
front is proven in both directions.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from typing import cast

import pytest
from pydantic import JsonValue, TypeAdapter
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters import diagnostics as stage6
from crypto_lab.adapters.diagnostics import (
    STAGE6_DIAGNOSTIC_CODES,
    Stage6DiagnosticPosture,
    stage6_diagnostic,
    stage6_failure,
)
from crypto_lab.domain.aggregation import REASON_LATE_NOT_APPLICABLE
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticSeverity,
)
from crypto_lab.domain.hashing import (
    HashingProfile,
    _uuid4_shaped,
    candidate_artifact_id_for,
    profile_hash,
    request_id_for,
    sha256_bytes,
)
from crypto_lab.domain.identifiers import CandidateArtifactId, RequestId
from crypto_lab.domain.results import Failure
from crypto_lab.domain.retry import (
    HARD_BLOCKING_DIAGNOSTIC_CATEGORIES,
    RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES,
)
from crypto_lab.experiments.diagnostics import (
    STAGE5_DIAGNOSTIC_CODES,
    UNRECOGNIZED_PROCESS_EXIT,
    stage5_diagnostic,
)

_D = DiagnosticCategory
_S = DiagnosticSeverity
_UUID = "12345678-1234-4234-8234-123456789abc"
_EXPERIMENT = f"exp_{_UUID}"
_RUN = f"run_{_UUID}"
_INVOCATION = f"inv_{_UUID}"
_CAUSE = "diag_22345678-1234-4234-8234-123456789abc"
_INSTANT = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
_LATER = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
#: Plan section 9.4, read literally: code, category, retriable, severity, hard
#: block. The module constant carrying each code is the code with its dot
#: replaced by an underscore (`PROTOCOL.MALFORMED_JSONL` -> `PROTOCOL_MALFORMED_JSONL`).
_TABLE: list[tuple[str, DiagnosticCategory, bool, DiagnosticSeverity, bool]] = [
    ("PROTOCOL.STDOUT_CONTAMINATION", _D.PROTOCOL, False, _S.ERROR, True),
    ("PROTOCOL.MALFORMED_JSONL", _D.PROTOCOL, False, _S.ERROR, True),
    ("PROTOCOL.EVENT_TOO_LARGE", _D.PROTOCOL, False, _S.ERROR, True),
    ("PROTOCOL.IDENTITY_OR_SEQUENCE_VIOLATION", _D.PROTOCOL, False, _S.ERROR, True),
    ("PROTOCOL.UNSUPPORTED_VERSION", _D.PROTOCOL, False, _S.ERROR, True),
    ("PROTOCOL.ADAPTER_REPORTED_VIOLATION", _D.PROTOCOL, False, _S.ERROR, True),
    ("PROTOCOL.VALIDATION_RESULT_INVALID", _D.PROTOCOL, False, _S.ERROR, True),
    ("PROTOCOL.DESCRIBE_OUTPUT_INVALID", _D.PROTOCOL, False, _S.ERROR, True),
    ("SCHEMA.REQUEST_INVALID", _D.SCHEMA_VALIDATION, False, _S.ERROR, True),
    ("COMPAT.NOT_APPLICABLE", _D.COMPATIBILITY, False, _S.ERROR, True),
    ("COMPAT.LATE_NOT_APPLICABLE", _D.COMPATIBILITY, False, _S.ERROR, True),
    ("ADAPTER.UNAVAILABLE", _D.ADAPTER_UNAVAILABILITY, True, _S.ERROR, False),
    ("ENGINE.RUNTIME_FAILURE", _D.ENGINE_RUNTIME, True, _S.ERROR, False),
    ("PROCESS.UNRECOGNIZED_PROCESS_EXIT", _D.ENGINE_RUNTIME, True, _S.ERROR, False),
    ("PROCESS.STDERR_TRUNCATED", _D.ENGINE_RUNTIME, True, _S.WARNING, False),
    ("PROCESS.MISSING_HEARTBEAT", _D.TIMEOUT, True, _S.WARNING, False),
    ("PROCESS.DESCRIBE_TIMED_OUT", _D.TIMEOUT, False, _S.ERROR, False),
    ("PROCESS.VALIDATE_TIMED_OUT", _D.TIMEOUT, True, _S.ERROR, False),
    ("PROCESS.START_TIMED_OUT", _D.TIMEOUT, True, _S.ERROR, False),
    ("PROCESS.RUN_TIMED_OUT", _D.TIMEOUT, True, _S.ERROR, False),
    ("PROCESS.CANCELLED", _D.CANCELLATION, False, _S.ERROR, True),
    ("ARTIFACT.RESULT_MANIFEST_INVALID", _D.ARTIFACT_CORRUPTION, False, _S.ERROR, True),
    ("ARTIFACT.PATH_BOUNDARY_VIOLATION", _D.ARTIFACT_CORRUPTION, False, _S.ERROR, True),
    ("ARTIFACT.VALIDATION_FAILED", _D.ARTIFACT_CORRUPTION, False, _S.ERROR, True),
    ("SECURITY.SENSITIVE_MATERIAL_LEAKAGE", _D.SECURITY, False, _S.ERROR, True),
]
_CODES = [row[0] for row in _TABLE]
_COMMAND_CATEGORIES = frozenset(
    {_D.ENGINE_RUNTIME, _D.PROTOCOL, _D.TIMEOUT, _D.CANCELLATION}
)
_COMMAND_CODES = [row[0] for row in _TABLE if row[1] in _COMMAND_CATEGORIES]
_OTHER_CODES = [row[0] for row in _TABLE if row[1] not in _COMMAND_CATEGORIES]


def _mint(code: str, **overrides: object) -> Diagnostic:
    """Every correlation supplied, so any code in the table is constructible."""
    kwargs: dict[str, object] = {
        "source_component": "adapters.test",
        "timestamp_utc": _INSTANT,
        "experiment_id": _EXPERIMENT,
        "run_id": _RUN,
        "invocation_id": _INVOCATION,
        "details": {"native_exit_value": 3},
        "causal_diagnostic_ids": (),
    }
    kwargs.update(overrides)
    return stage6_diagnostic(code, "the message", **kwargs)  # type: ignore[arg-type]


# --- The table --------------------------------------------------------------------


def test_the_stage_six_code_table_is_exactly_the_twenty_five_plan_codes() -> None:
    assert isinstance(STAGE6_DIAGNOSTIC_CODES, Mapping)
    assert len(STAGE6_DIAGNOSTIC_CODES) == 25
    assert set(STAGE6_DIAGNOSTIC_CODES) == set(_CODES)
    assert len(set(_CODES)) == 25
    for code, category, retriable, severity, _hard in _TABLE:
        assert getattr(stage6, code.replace(".", "_")) == code
        posture = STAGE6_DIAGNOSTIC_CODES[code]
        assert type(posture) is Stage6DiagnosticPosture
        assert posture.category is category
        assert posture.retriable is retriable
        assert posture.severity is severity
    with pytest.raises(FrozenInstanceError):
        STAGE6_DIAGNOSTIC_CODES[_CODES[0]].retriable = True  # type: ignore[misc]


def test_the_hard_block_column_is_the_stage_five_category_partition() -> None:
    """Plan 9.4's hard-block column restates the Stage 5 retry partition
    (`domain/retry.py`), so a reclassified category would fail both."""
    for code, category, _retriable, _severity, hard in _TABLE:
        assert hard is (category in HARD_BLOCKING_DIAGNOSTIC_CATEGORIES), code
        assert (not hard) is (category in RETRY_PERMITTING_DIAGNOSTIC_CATEGORIES), code
    assert {row[1] for row in _TABLE} == {
        _D.PROTOCOL,
        _D.SCHEMA_VALIDATION,
        _D.COMPATIBILITY,
        _D.ADAPTER_UNAVAILABILITY,
        _D.ENGINE_RUNTIME,
        _D.TIMEOUT,
        _D.CANCELLATION,
        _D.ARTIFACT_CORRUPTION,
        _D.SECURITY,
    }


def test_late_not_applicable_is_the_imported_aggregation_reason_object() -> None:
    assert stage6.COMPAT_LATE_NOT_APPLICABLE is REASON_LATE_NOT_APPLICABLE
    assert REASON_LATE_NOT_APPLICABLE == "COMPAT.LATE_NOT_APPLICABLE"
    assert REASON_LATE_NOT_APPLICABLE in STAGE6_DIAGNOSTIC_CODES


def test_unrecognized_process_exit_has_the_stage_five_posture_and_identity() -> None:
    """Both tables carry the code with an identical posture, and both factories
    mint the identical `Diagnostic` for identical inputs, so the harness can mint
    the diagnostic Stage 5's `EXITED` transition demands (plan 9.4)."""
    five = STAGE5_DIAGNOSTIC_CODES[UNRECOGNIZED_PROCESS_EXIT]
    six = STAGE6_DIAGNOSTIC_CODES[stage6.PROCESS_UNRECOGNIZED_PROCESS_EXIT]
    assert stage6.PROCESS_UNRECOGNIZED_PROCESS_EXIT == UNRECOGNIZED_PROCESS_EXIT
    assert (six.category, six.retriable) == (five.category, five.retriable)
    assert six.severity is _S.ERROR
    kwargs: dict[str, object] = {
        "source_component": "contract.harness",
        "timestamp_utc": _INSTANT,
        "experiment_id": _EXPERIMENT,
        "run_id": _RUN,
        "invocation_id": _INVOCATION,
        "details": {"native_exit_value": 3},
        "causal_diagnostic_ids": (_CAUSE,),
    }
    assert stage6_diagnostic(UNRECOGNIZED_PROCESS_EXIT, "exit 3", **kwargs) == (  # type: ignore[arg-type]
        stage5_diagnostic(UNRECOGNIZED_PROCESS_EXIT, "exit 3", **kwargs)  # type: ignore[arg-type]
    )
    assert set(STAGE5_DIAGNOSTIC_CODES) & set(STAGE6_DIAGNOSTIC_CODES) == {
        UNRECOGNIZED_PROCESS_EXIT
    }


@pytest.mark.parametrize(
    "code",
    [
        *(
            code
            for code in STAGE5_DIAGNOSTIC_CODES
            if code != UNRECOGNIZED_PROCESS_EXIT
        ),
        "PROTOCOL.NOPE",
        "protocol.stdout_contamination",
        "",
    ],
)
def test_a_code_outside_the_table_is_rejected(code: str) -> None:
    with pytest.raises(ValueError, match="not a Stage 6 code"):
        _mint(code)
    with pytest.raises(ValueError, match="not a Stage 6 code"):
        stage6_failure(
            code, "x", source_component="adapters.test", timestamp_utc=_INSTANT
        )


# --- The Diagnostic rules checked up front, both directions ------------------------


@pytest.mark.parametrize("code", _COMMAND_CODES)
def test_every_command_category_code_requires_an_invocation(code: str) -> None:
    with pytest.raises(ValueError, match="requires invocation_id"):
        _mint(code, invocation_id=MISSING)
    minted = _mint(code)
    assert minted.invocation_id == _INVOCATION
    assert minted.category in _COMMAND_CATEGORIES


@pytest.mark.parametrize("code", _OTHER_CODES)
def test_every_other_code_accepts_an_absent_invocation(code: str) -> None:
    minted = _mint(code, invocation_id=MISSING)
    dumped = minted.model_dump(mode="json")
    assert "invocation_id" not in dumped
    assert minted.category not in _COMMAND_CATEGORIES
    bare = _mint(code, experiment_id=MISSING, run_id=MISSING, invocation_id=MISSING)
    assert {"experiment_id", "run_id", "invocation_id"}.isdisjoint(
        bare.model_dump(mode="json")
    )


def test_a_run_correlation_requires_an_experiment_correlation() -> None:
    with pytest.raises(ValueError, match="requires an experiment correlation"):
        _mint("ADAPTER.UNAVAILABLE", experiment_id=MISSING)
    minted = _mint("ADAPTER.UNAVAILABLE", run_id=MISSING)
    assert minted.experiment_id == _EXPERIMENT
    assert "run_id" not in minted.model_dump(mode="json")


@pytest.mark.parametrize(
    "details",
    [
        {"attempt_token": "a" * 32},
        {"attemptToken": "a" * 32},
        {"nested": {"Auth-Token": "x"}},
        {"api_key": "x"},
        {"customer_api_key": "x"},
    ],
)
def test_secret_like_detail_keys_are_rejected_before_identity_is_derived(
    details: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="secret-like") as captured:
        _mint("ADAPTER.UNAVAILABLE", details=details)
    assert "a" * 32 not in str(captured.value)


@pytest.mark.parametrize(
    "details",
    [
        {"ratio": 0.5},
        {"count": 2**63},
        {"message": "x" * 2049},
        {"k": list(range(65))},
        {"groups": [{f"key{index}": index for index in range(64)} for _ in range(4)]},
        {"payload": ["x" * 2_048 for _ in range(8)]},
    ],
)
def test_unbounded_or_untyped_detail_values_are_rejected_by_name(
    details: dict[str, object],
) -> None:
    """Every `Diagnostic.details` rule, including the node and byte ceilings,
    is applied before hashing and names itself, never a validation error."""
    with pytest.raises(ValueError, match="diagnostic detail") as captured:
        _mint("ADAPTER.UNAVAILABLE", details=details)
    assert type(captured.value) is ValueError


# --- Posture, severity and identity --------------------------------------------------


@pytest.mark.parametrize(("code", "category", "retriable", "severity", "hard"), _TABLE)
def test_every_minted_diagnostic_takes_its_posture_from_the_table(
    code: str,
    category: DiagnosticCategory,
    retriable: bool,
    severity: DiagnosticSeverity,
    hard: bool,
) -> None:
    del hard
    minted = _mint(code, causal_diagnostic_ids=(_CAUSE,))
    assert minted.schema_version == "1.0.0"
    assert minted.error_code == code
    assert minted.category is category
    assert minted.retriable is retriable
    assert minted.severity is severity
    assert minted.message == "the message"
    assert minted.source_component == "adapters.test"
    assert minted.timestamp_utc == _INSTANT
    assert minted.details == {"native_exit_value": 3}
    assert minted.causal_diagnostic_ids == (_CAUSE,)
    assert minted.diagnostic_id.startswith("diag_")
    assert (minted.experiment_id, minted.run_id, minted.invocation_id) == (
        _EXPERIMENT,
        _RUN,
        _INVOCATION,
    )


def test_identity_is_a_function_of_content_alone() -> None:
    base = _mint("PROTOCOL.MALFORMED_JSONL")
    assert _mint("PROTOCOL.MALFORMED_JSONL") == base
    later = _mint("PROTOCOL.MALFORMED_JSONL", timestamp_utc=_LATER)
    assert later.diagnostic_id == base.diagnostic_id
    assert later.timestamp_utc == _LATER != base.timestamp_utc
    variants = (
        stage6_diagnostic(
            "PROTOCOL.MALFORMED_JSONL",
            "another message",
            source_component="adapters.test",
            timestamp_utc=_INSTANT,
            experiment_id=_EXPERIMENT,
            run_id=_RUN,
            invocation_id=_INVOCATION,
            details={"native_exit_value": 3},
        ),
        _mint("PROTOCOL.MALFORMED_JSONL", details={"native_exit_value": 4}),
        _mint("PROTOCOL.MALFORMED_JSONL", details={}),
        _mint("PROTOCOL.MALFORMED_JSONL", source_component="adapters.other"),
        _mint("PROTOCOL.MALFORMED_JSONL", run_id=MISSING),
        _mint("PROTOCOL.MALFORMED_JSONL", experiment_id=MISSING, run_id=MISSING),
        _mint("PROTOCOL.MALFORMED_JSONL", invocation_id=f"inv_2{_UUID[1:]}"),
        _mint("PROTOCOL.MALFORMED_JSONL", causal_diagnostic_ids=(_CAUSE,)),
        _mint("PROTOCOL.STDOUT_CONTAMINATION"),
    )
    identities = {variant.diagnostic_id for variant in variants}
    assert base.diagnostic_id not in identities
    assert len(identities) == len(variants)


def test_details_default_to_an_empty_object_and_are_copied() -> None:
    supplied: dict[str, object] = {"native_exit_value": 3}
    minted = _mint("ADAPTER.UNAVAILABLE", details=supplied)
    supplied["native_exit_value"] = 4
    assert minted.details == {"native_exit_value": 3}
    absent = _mint("ADAPTER.UNAVAILABLE", details=None)
    assert absent.details == {}
    assert absent.diagnostic_id != minted.diagnostic_id


# --- The derived identities of plan section 4 (hashing profiles) --------------------


class _StrSubclass(str):
    pass


def test_request_id_for_is_deterministic_prefixed_and_anchor_sensitive() -> None:
    """Plan section 4: `req_` + `_uuid4_shaped(sha256_bytes(anchor))`, derived
    rather than drawn, so no `IdentitySource` method is added; the run request
    anchors on the run identity and a describe on its invocation identity."""
    first = request_id_for(_RUN)
    assert first == request_id_for(_RUN)
    assert first.startswith("req_")
    assert TypeAdapter(RequestId).validate_python(first) == first
    assert first == f"req_{_uuid4_shaped(sha256_bytes(_RUN.encode()))}"
    assert request_id_for(_INVOCATION) != first
    assert request_id_for(f"run_2{_UUID[1:]}") != first
    assert request_id_for(_INVOCATION) == (
        f"req_{_uuid4_shaped(sha256_bytes(_INVOCATION.encode()))}"
    )
    for anchor in (_EXPERIMENT, f"run_{_UUID.upper()}", _UUID, "", "run_", "inv_x"):
        with pytest.raises(ValueError, match=r"identifier must|UUID"):
            request_id_for(anchor)
    for foreign in (1, None, _StrSubclass(_RUN)):
        with pytest.raises(TypeError, match="built-in string"):
            request_id_for(cast("str", foreign))


def test_candidate_artifact_id_for_is_deterministic_and_sensitive_to_each_input() -> (
    None
):
    """Plan section 4: `cand_` + `_uuid4_shaped(profile_hash(...))` under
    `CANDIDATE_ARTIFACT_IDENTITY_V1`, so a restart derives the same identity."""
    base = candidate_artifact_id_for(_RUN, _INVOCATION, "results/native.bin")
    assert base == candidate_artifact_id_for(_RUN, _INVOCATION, "results/native.bin")
    assert base.startswith("cand_")
    assert TypeAdapter(CandidateArtifactId).validate_python(base) == base
    expected_payload: dict[str, JsonValue] = {
        "run_id": _RUN,
        "invocation_id": _INVOCATION,
        "relative_path": "results/native.bin",
    }
    assert base == "cand_" + _uuid4_shaped(
        profile_hash(HashingProfile.CANDIDATE_ARTIFACT_IDENTITY_V1, expected_payload)
    )
    variants = {
        candidate_artifact_id_for(
            f"run_2{_UUID[1:]}", _INVOCATION, "results/native.bin"
        ),
        candidate_artifact_id_for(_RUN, f"inv_2{_UUID[1:]}", "results/native.bin"),
        candidate_artifact_id_for(_RUN, _INVOCATION, "results/Native.bin"),
        candidate_artifact_id_for(_RUN, _INVOCATION, "results/native.bin/"),
    }
    assert base not in variants
    assert len(variants) == 4
    with pytest.raises(ValueError, match="identifier must"):
        candidate_artifact_id_for(_INVOCATION, _INVOCATION, "results/native.bin")
    with pytest.raises(ValueError, match="identifier must"):
        candidate_artifact_id_for(_RUN, _RUN, "results/native.bin")
    with pytest.raises(ValueError, match="must not be empty"):
        candidate_artifact_id_for(_RUN, _INVOCATION, "")
    for foreign in (b"x", 1, _StrSubclass("x")):
        with pytest.raises(TypeError, match="built-in string"):
            candidate_artifact_id_for(_RUN, _INVOCATION, cast("str", foreign))
    with pytest.raises(TypeError, match="built-in string"):
        candidate_artifact_id_for(cast("str", 1), _INVOCATION, "x")


def test_the_four_stage_six_profiles_have_the_plan_values_in_order() -> None:
    """Plan section 4's table, appended after the eight Stage 5 members."""
    stage6_profiles = (
        HashingProfile.ADAPTER_REQUEST_V1,
        HashingProfile.RUN_EVENT_CONTENT_V1,
        HashingProfile.SANITIZED_ADAPTER_RESULT_MANIFEST_V1,
        HashingProfile.CANDIDATE_ARTIFACT_IDENTITY_V1,
    )
    assert tuple(profile.value for profile in stage6_profiles) == (
        "adapter-request/v1",
        "run-event-content/v1",
        "sanitized-adapter-result-manifest/v1",
        "candidate-artifact-identity/v1",
    )
    assert tuple(HashingProfile)[8:] == stage6_profiles
    assert len(HashingProfile) == 12


def test_the_four_stage_six_profiles_are_domain_separated() -> None:
    payload: dict[str, JsonValue] = {"value": "same"}
    stage6_profiles = (
        HashingProfile.ADAPTER_REQUEST_V1,
        HashingProfile.RUN_EVENT_CONTENT_V1,
        HashingProfile.SANITIZED_ADAPTER_RESULT_MANIFEST_V1,
        HashingProfile.CANDIDATE_ARTIFACT_IDENTITY_V1,
    )
    digests = {profile_hash(profile, payload) for profile in stage6_profiles}
    assert len(digests) == 4
    assert digests.isdisjoint(
        profile_hash(profile, payload)
        for profile in HashingProfile
        if profile not in stage6_profiles
    )


def test_stage6_failure_wraps_exactly_the_stage6_diagnostic() -> None:
    failure = stage6_failure(
        "PROCESS.CANCELLED",
        "cancelled by the harness",
        source_component="contract.harness",
        timestamp_utc=_INSTANT,
        experiment_id=_EXPERIMENT,
        run_id=_RUN,
        invocation_id=_INVOCATION,
        details={"grace_seconds": 10},
        causal_diagnostic_ids=(_CAUSE,),
    )
    assert isinstance(failure, Failure)
    assert failure.outcome == "FAILURE"
    assert failure.diagnostics == (
        stage6_diagnostic(
            "PROCESS.CANCELLED",
            "cancelled by the harness",
            source_component="contract.harness",
            timestamp_utc=_INSTANT,
            experiment_id=_EXPERIMENT,
            run_id=_RUN,
            invocation_id=_INVOCATION,
            details={"grace_seconds": 10},
            causal_diagnostic_ids=(_CAUSE,),
        ),
    )
