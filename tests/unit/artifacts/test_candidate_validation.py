"""Stage 9 Task 4: the phase-1 candidate checks (plan 4.3 phase 1, 6.4; specification
14.7, 19.2 step 2, 24.3; readings 18 and 19).

``validate_candidate`` rechecks confinement, bounds the size before anything is
parsed, admits a closed media set, parses JSON kinds as inert bytes, hashes and
scans in one stream, rechecks the identity after hashing and compares the
adapter's declared size and hash against the core's own observation. Every step
leaves a ``ValidationObservation``; the observations tuple accompanies both
outcomes so the finalizer can tell a proven corruption (``ARTIFACT.VALIDATION_FAILED``
at ``SIZE`` or ``HASH``) from a quarantine and from a storage failure
(``ARTIFACT.MOVE_FAILED``, reading 26) by the failed observation's code.

The candidate builders here are shared with ``test_content_hashing.py``.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import os
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

import pytest
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_MOVE_FAILED,
    ARTIFACT_VALIDATION_FAILED,
    SECURITY_SENSITIVE_MATERIAL_LEAKAGE,
)
from crypto_lab.artifacts.hashing import HashScan, StreamingContentHasher
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactSourceRole,
    CandidateArtifact,
    CandidateArtifactProducerKind,
    CandidateArtifactState,
    ValidationObservation,
)
from crypto_lab.artifacts.ownership import (
    ArtifactOwnerRef,
    RunArtifactOwner,
    SystemArtifactOwner,
    artifact_owner_hash,
)
from crypto_lab.artifacts.paths import (
    ConfinedPath,
    confine_candidate_path,
    recheck_confined_path,
)
from crypto_lab.artifacts.validation import (
    ADMITTED_MEDIA_TYPES,
    DEFAULT_CEILINGS,
    JSON_MEDIA_TYPES,
    MAX_CANDIDATE_BYTES,
    MAX_JSON_PARSE_BYTES,
    MAX_MANIFEST_BYTES,
    MAX_STDERR_EVIDENCE_BYTES,
    TEXT_MEDIA_TYPES,
    CandidateValidation,
    ValidatedCandidate,
    ValidationCeilings,
    validate_candidate,
)
from crypto_lab.domain.diagnostics import DiagnosticCategory
from crypto_lab.domain.engine_run import AttemptTokenMaterial
from crypto_lab.domain.hashing import (
    artifact_id_for,
    candidate_artifact_id_for,
    core_candidate_artifact_id_for,
)
from crypto_lab.domain.results import Failure, Success
from doubles.experiments import (
    ATTEMPT_TOKEN,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_RUN_ID,
    RUN_ID,
)

NOW = datetime(2026, 8, 10, 1, 2, 3, tzinfo=UTC)
NATIVE_PATH = "results/native.bin"
NATIVE_MEDIA = "application/octet-stream"
JSON_PATH = "results/normalized.json"
JSON_MEDIA = "application/json"
TEXT_MEDIA = "text/plain"
STDERR_RELATIVE = "stderr.txt"
RUN_OWNER = RunArtifactOwner(
    owner_kind="RUN",
    experiment_id=EXPERIMENT_ID,
    run_id=RUN_ID,
    invocation_id=INVOCATION_ID,
)
SYSTEM_OWNER = SystemArtifactOwner(
    owner_kind="SYSTEM", core_component="artifacts", correlation_id="task4"
)
TOKEN = AttemptTokenMaterial(run_id=RUN_ID, attempt_token=ATTEMPT_TOKEN)
FOREIGN_TOKEN = AttemptTokenMaterial(run_id=OTHER_RUN_ID, attempt_token=ATTEMPT_TOKEN)
DIGEST_SHAPED = "7" * 64
_P = ArtifactFinalizationPurpose
_R = ArtifactSourceRole
_K = CandidateArtifactProducerKind
_S = CandidateArtifactState


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def adapter_candidate(
    data: bytes,
    *,
    relative_path: str = NATIVE_PATH,
    media: str = NATIVE_MEDIA,
    kind: str = "engine.native",
    declared_size: int | None = None,
    declared_hash: str | None = None,
) -> CandidateArtifact:
    """A ``RUN``-owned ``RESULT`` candidate the adapter declared, at ``VALIDATING``."""
    return CandidateArtifact(
        schema_version="1.0.0",
        candidate_artifact_id=candidate_artifact_id_for(
            RUN_ID, INVOCATION_ID, relative_path
        ),
        owner=RUN_OWNER,
        finalization_purpose=_P.RESULT,
        source_role=_R.ENGINE_NATIVE_RESULT,
        producer_kind=_K.ADAPTER,
        artifact_kind=kind,
        staging_relative_path=relative_path,
        state=_S.VALIDATING,
        adapter_declared_size=len(data) if declared_size is None else declared_size,
        adapter_declared_hash=sha256_of(data)
        if declared_hash is None
        else declared_hash,
        adapter_declared_media_type=media,
        validation_observations=(),
        created_at_utc=INSTANT,
        updated_at_utc=INSTANT,
        revision=2,
    )


def core_candidate(
    *,
    owner: ArtifactOwnerRef = RUN_OWNER,
    role: ArtifactSourceRole = _R.CORE_EVIDENCE,
    relative_path: str = STDERR_RELATIVE,
    kind: str = "stderr.capture",
) -> CandidateArtifact:
    """A core-produced ``EVIDENCE`` candidate staged under its correlation."""
    staging_path = f"INVOCATION/{INVOCATION_ID}/{relative_path}"
    return CandidateArtifact(
        schema_version="1.0.0",
        candidate_artifact_id=core_candidate_artifact_id_for(
            artifact_owner_hash(owner), "INVOCATION", INVOCATION_ID, relative_path
        ),
        owner=owner,
        finalization_purpose=_P.EVIDENCE,
        source_role=role,
        producer_kind=_K.CORE,
        artifact_kind=kind,
        staging_relative_path=staging_path,
        state=_S.VALIDATING,
        validation_observations=(),
        created_at_utc=INSTANT,
        updated_at_utc=INSTANT,
        revision=2,
    )


def stage_candidate(
    root: Path, candidate: CandidateArtifact, data: bytes
) -> ConfinedPath:
    leaf = root.joinpath(*candidate.staging_relative_path.split("/"))
    leaf.parent.mkdir(parents=True, exist_ok=True)
    leaf.write_bytes(data)
    confined = confine_candidate_path(
        root, candidate.staging_relative_path, now_utc=NOW
    )
    assert isinstance(confined, Success)
    return confined.value


def validate(
    candidate: CandidateArtifact, confined: ConfinedPath, **overrides: Any
) -> CandidateValidation:
    arguments: dict[str, Any] = {
        "hasher": StreamingContentHasher(),
        "token": TOKEN if candidate.producer_kind is _K.ADAPTER else MISSING,
        "ceilings": DEFAULT_CEILINGS,
        "now_utc": NOW,
    }
    if candidate.producer_kind is _K.CORE:
        arguments["media_type"] = TEXT_MEDIA
    arguments.update(overrides)
    return validate_candidate(candidate, confined, **arguments)


def stages(validation: CandidateValidation) -> tuple[tuple[str, str], ...]:
    return tuple(
        (observation.stage, observation.outcome)
        for observation in validation.observations
    )


def failed_with(validation: CandidateValidation, stage: str, code: str) -> str:
    """The failing stage, its code, and the diagnostic the observation names."""
    assert isinstance(validation.result, Failure)
    diagnostic = validation.result.diagnostics[0]
    assert diagnostic.error_code == code
    last = validation.observations[-1]
    assert (last.stage, last.outcome) == (stage, "FAILED")
    assert last.error_code == code
    assert last.diagnostic_id == diagnostic.diagnostic_id
    assert all(
        observation.outcome == "PASSED" for observation in validation.observations[:-1]
    )
    return diagnostic.message


def succeeded(validation: CandidateValidation) -> ValidatedCandidate:
    assert isinstance(validation.result, Success), validation.result
    value = validation.result.value
    assert isinstance(value, ValidatedCandidate)
    assert value.observations == validation.observations
    assert all(observation.outcome == "PASSED" for observation in value.observations)
    return value


# --- Plan Task 4 Step 1 ---------------------------------------------------------------


def test_engine_output_untrusted_until_validated(tmp_path: Path) -> None:
    """Specification 24.3: the declared size, hash and media are claims; the core's
    own observation is what the finalized facts are built from."""
    data = b"native engine bytes"
    truthful = adapter_candidate(data)
    confined = stage_candidate(tmp_path, truthful, data)
    validated = succeeded(validate(truthful, confined))
    digest = sha256_of(data)
    assert validated.candidate_artifact_id == truthful.candidate_artifact_id
    assert validated.content_hash == digest
    assert validated.size_bytes == len(data)
    assert validated.media_type == NATIVE_MEDIA
    assert validated.finalized_relative_path == f"objects/{digest[:2]}/{digest}"
    assert validated.artifact_id == artifact_id_for(
        truthful.candidate_artifact_id, digest
    )
    assert validated.identity == confined.identity
    assert stages(validate(truthful, confined)) == (
        ("PATH", "PASSED"),
        ("SIZE", "PASSED"),
        ("MEDIA", "PASSED"),
        ("REDACTION", "PASSED"),
        ("HASH", "PASSED"),
    )
    hashed = validated.observations[-1]
    assert (hashed.observed_size_bytes, hashed.observed_sha256) == (len(data), digest)
    assert validated.observations[1].observed_size_bytes == len(data)

    lying_size = adapter_candidate(data, declared_size=len(data) + 1)
    size_failed = validate(lying_size, stage_candidate(tmp_path, lying_size, data))
    message = failed_with(size_failed, "SIZE", ARTIFACT_VALIDATION_FAILED)
    assert "declaration" in message
    assert stages(size_failed) == (("PATH", "PASSED"), ("SIZE", "FAILED"))

    lying_media = adapter_candidate(data, media="application/x-msdownload")
    media_failed = validate(lying_media, stage_candidate(tmp_path, lying_media, data))
    assert "admitted" in failed_with(media_failed, "MEDIA", ARTIFACT_VALIDATION_FAILED)


def test_sizes_bounded_before_parsing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Specification 24.3: sizes are bounded before expensive processing; the JSON
    parser is never reached for a candidate over the parse ceiling."""
    calls: list[str] = []
    original = json.loads

    def spying_loads(text: str, **kwargs: Any) -> Any:
        calls.append(text[:8])
        return original(text, **kwargs)

    # The validation module calls ``json.loads`` through the module attribute.
    monkeypatch.setattr(json, "loads", spying_loads)
    oversized = MAX_JSON_PARSE_BYTES + 1
    candidate = adapter_candidate(
        b"", relative_path=JSON_PATH, media=JSON_MEDIA, declared_size=oversized
    )
    leaf = tmp_path.joinpath(*JSON_PATH.split("/"))
    leaf.parent.mkdir(parents=True)
    with leaf.open("wb") as handle:
        handle.truncate(oversized)
    confined = confine_candidate_path(tmp_path, JSON_PATH, now_utc=NOW)
    assert isinstance(confined, Success)
    validation = validate(candidate, confined.value)
    assert "parse ceiling" in failed_with(
        validation, "SIZE", ARTIFACT_VALIDATION_FAILED
    )
    assert calls == []
    # The candidate ceiling itself, with a caller-supplied bound.
    data = b"0123456789"
    bounded = adapter_candidate(data)
    staged = stage_candidate(tmp_path, bounded, data)
    small = ValidationCeilings(max_bytes=4, max_parse_bytes=4)
    validation = validate(bounded, staged, ceilings=small)
    assert "ceiling" in failed_with(validation, "SIZE", ARTIFACT_VALIDATION_FAILED)
    assert calls == []
    assert MAX_JSON_PARSE_BYTES == 16 * 2**20
    assert MAX_MANIFEST_BYTES == 16 * 2**20
    assert MAX_STDERR_EVIDENCE_BYTES == 50 * 2**20
    assert MAX_CANDIDATE_BYTES == 2**53 - 1
    assert DEFAULT_CEILINGS == ValidationCeilings(
        max_bytes=MAX_CANDIDATE_BYTES, max_parse_bytes=MAX_JSON_PARSE_BYTES
    )


def test_declared_hash_mismatch_is_corrupt(tmp_path: Path) -> None:
    """A proven content mismatch keeps the corruption classification."""
    data = b"native engine bytes"
    candidate = adapter_candidate(data, declared_hash=DIGEST_SHAPED)
    validation = validate(candidate, stage_candidate(tmp_path, candidate, data))
    message = failed_with(validation, "HASH", ARTIFACT_VALIDATION_FAILED)
    assert "declaration" in message
    assert isinstance(validation.result, Failure)
    assert validation.result.diagnostics[0].category is (
        DiagnosticCategory.ARTIFACT_CORRUPTION
    )
    assert stages(validation) == (
        ("PATH", "PASSED"),
        ("SIZE", "PASSED"),
        ("MEDIA", "PASSED"),
        ("REDACTION", "PASSED"),
        ("HASH", "FAILED"),
    )
    failed = validation.observations[-1]
    assert isinstance(failed, ValidationObservation)
    assert not isinstance(failed.observed_size_bytes, int)
    assert not isinstance(failed.observed_sha256, str)


def test_adapter_output_cannot_request_paths_or_imports(tmp_path: Path) -> None:
    """Specification 24.3:1775: a JSON candidate is bytes; keys that look like
    imports, executions or absolute destinations are neither read nor acted on."""
    document = {
        "import": "os",
        "exec": "del artifacts",
        "__class__": "crypto_lab.cli.main",
        "destination": "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "unc": "\\\\server\\share\\escape",
        "nested": [{"eval": "1+1"}, {"path": "../../escape.bin"}],
    }
    data = json.dumps(document).encode("utf-8")
    candidate = adapter_candidate(data, relative_path=JSON_PATH, media=JSON_MEDIA)
    confined = stage_candidate(tmp_path, candidate, data)
    validated = succeeded(validate(candidate, confined))
    assert confined.path.read_bytes() == data
    assert validated.content_hash == sha256_of(data)
    assert {field.name for field in dataclasses.fields(ValidatedCandidate)} == {
        "candidate_artifact_id",
        "artifact_id",
        "content_hash",
        "size_bytes",
        "media_type",
        "finalized_relative_path",
        "identity",
        "observations",
    }
    assert ("SCHEMA", "PASSED") in stages(validate(candidate, confined))
    assert not (tmp_path / "escape.bin").exists()


@pytest.mark.parametrize(
    ("data", "word"),
    [
        (b'{"a": 1, "a": 2}', "well-formed"),
        (b'{"a": NaN}', "well-formed"),
        (b'{"a": Infinity}', "well-formed"),
        (b'{"a": "\\ud800"}', "well-formed"),
        (b'{"\\ud800": 1}', "well-formed"),
        (b'{"a": "\xff"}', "UTF-8"),
        (b"not json at all", "well-formed"),
        (b"", "well-formed"),
        (b'{"a": 1} trailing', "well-formed"),
    ],
)
def test_a_json_candidate_must_be_one_strict_document(
    tmp_path: Path, data: bytes, word: str
) -> None:
    candidate = adapter_candidate(data, relative_path=JSON_PATH, media=JSON_MEDIA)
    validation = validate(candidate, stage_candidate(tmp_path, candidate, data))
    assert word in failed_with(validation, "SCHEMA", ARTIFACT_VALIDATION_FAILED)
    assert stages(validation) == (
        ("PATH", "PASSED"),
        ("SIZE", "PASSED"),
        ("MEDIA", "PASSED"),
        ("SCHEMA", "FAILED"),
    )


def test_lone_surrogates_in_object_keys_are_refused_at_every_depth(
    tmp_path: Path,
) -> None:
    """24.3: a lone surrogate escape in an object key -- top-level, or nested in
    objects and arrays at any depth -- is not one well-formed document and is
    refused at ``SCHEMA``; ordinary Unicode keys and a valid surrogate-pair
    escape, as key or value, are accepted."""
    refused = (
        b'{"\\ud800": 1}',
        b'{"a": {"\\udc00": 1}}',
        b'{"a": [1, {"b": {"\\udbff": null}}]}',
        b'[{"\\ud800": {"ok": 1}}]',
        b'{"a": [[{"\\udfff": []}]]}',
    )
    for index, data in enumerate(refused):
        candidate = adapter_candidate(data, relative_path=JSON_PATH, media=JSON_MEDIA)
        validation = validate(
            candidate, stage_candidate(tmp_path / f"refused{index}", candidate, data)
        )
        assert "well-formed" in failed_with(
            validation, "SCHEMA", ARTIFACT_VALIDATION_FAILED
        ), data
        assert stages(validation) == (
            ("PATH", "PASSED"),
            ("SIZE", "PASSED"),
            ("MEDIA", "PASSED"),
            ("SCHEMA", "FAILED"),
        ), data
    cjk_key = chr(0x65E5) + chr(0x672C)  # two BMP characters, raw UTF-8 below
    emoji_key = chr(0x1F600)  # a non-BMP character: the pair 😀
    accepted = (
        json.dumps(
            {cjk_key: 1, emoji_key: {cjk_key: [{emoji_key: True}]}},
            ensure_ascii=False,
        ).encode("utf-8"),
        b'{"\\ud83d\\ude00": 1, "a": {"\\ud83d\\ude00": [{"\\ud83d\\ude00": 2}]}}',
        b'{"a": "\\ud83d\\ude00", "\\u65e5\\u672c": "\\u65e5"}',
    )
    for index, data in enumerate(accepted):
        candidate = adapter_candidate(data, relative_path=JSON_PATH, media=JSON_MEDIA)
        validation = validate(
            candidate, stage_candidate(tmp_path / f"accepted{index}", candidate, data)
        )
        assert ("SCHEMA", "PASSED") in stages(validation), data
        assert succeeded(validation).content_hash == sha256_of(data)


def test_a_json_document_with_scalar_values_is_well_formed(tmp_path: Path) -> None:
    """Numbers, booleans and null are well-formed JSON values: the strict decode
    passes over them (nothing in the document is read) and a bare scalar is one
    document too."""
    data = b'{"count": 1, "flags": [true, false, null, 2.5], "name": "x"}'
    candidate = adapter_candidate(data, relative_path=JSON_PATH, media=JSON_MEDIA)
    validation = validate(candidate, stage_candidate(tmp_path, candidate, data))
    assert ("SCHEMA", "PASSED") in stages(validation)
    succeeded(validation)
    scalar = b"42"
    bare = adapter_candidate(scalar, relative_path=JSON_PATH, media=JSON_MEDIA)
    succeeded(validate(bare, stage_candidate(tmp_path / "bare", bare, scalar)))


def test_media_type_closed_set(tmp_path: Path) -> None:
    assert ADMITTED_MEDIA_TYPES == frozenset(
        {
            "application/json",
            "application/x-ndjson",
            "text/plain",
            "text/csv",
            "application/octet-stream",
        }
    )
    assert TEXT_MEDIA_TYPES == ADMITTED_MEDIA_TYPES - {"application/octet-stream"}
    assert JSON_MEDIA_TYPES == frozenset({"application/json"})
    data = b"stderr line\n"
    evidence = core_candidate()
    confined = stage_candidate(tmp_path, evidence, data)
    assert succeeded(validate(evidence, confined)).media_type == TEXT_MEDIA
    refused = validate(evidence, confined, media_type="application/x-msdownload")
    assert "admitted" in failed_with(refused, "MEDIA", ARTIFACT_VALIDATION_FAILED)
    with pytest.raises(ValueError, match="media_type is required for a CORE"):
        validate(evidence, confined, media_type=MISSING)
    with pytest.raises(ValueError, match="media type"):
        validate(evidence, confined, media_type="not a media type")
    adapter = adapter_candidate(data)
    staged = stage_candidate(tmp_path, adapter, data)
    with pytest.raises(ValueError, match="ADAPTER candidate declares"):
        validate(adapter, staged, media_type=NATIVE_MEDIA)


# --- Leakage, mutation, correlation and the caller contract ---------------------------


def test_result_scans_the_exact_token_and_evidence_scans_token_shape(
    tmp_path: Path,
) -> None:
    """Plan 4.3 phase 1: a RESULT candidate is scanned for the raw token; an EVIDENCE
    text candidate for any token-shaped run, so a digest-looking placeholder is
    never mistaken for absence."""
    leaking = ATTEMPT_TOKEN.encode("utf-8").join([b'{"a": "', b'"}'])
    result_leak = adapter_candidate(leaking, relative_path=JSON_PATH, media=JSON_MEDIA)
    validation = validate(result_leak, stage_candidate(tmp_path, result_leak, leaking))
    message = failed_with(validation, "REDACTION", SECURITY_SENSITIVE_MATERIAL_LEAKAGE)
    assert "attempt token" in message
    assert ATTEMPT_TOKEN not in message
    assert stages(validation) == (
        ("PATH", "PASSED"),
        ("SIZE", "PASSED"),
        ("MEDIA", "PASSED"),
        ("SCHEMA", "PASSED"),
        ("REDACTION", "FAILED"),
    )
    # A digest in a RESULT text candidate is not the token: accepted.
    digest_text = f'{{"hash": "{DIGEST_SHAPED}"}}'.encode()
    result_digest = adapter_candidate(
        digest_text, relative_path=JSON_PATH, media=JSON_MEDIA
    )
    succeeded(
        validate(result_digest, stage_candidate(tmp_path, result_digest, digest_text))
    )
    # The same digest in EVIDENCE text is token-shaped material: leakage.
    evidence_root = tmp_path / "evidence"
    evidence = core_candidate()
    shaped = validate(evidence, stage_candidate(evidence_root, evidence, digest_text))
    message = failed_with(shaped, "REDACTION", SECURITY_SENSITIVE_MATERIAL_LEAKAGE)
    assert "token-shaped" in message
    clean = validate(
        evidence, stage_candidate(evidence_root, evidence, b"plain stderr text\n")
    )
    succeeded(clean)
    # Binary EVIDENCE is not text: the shape detector does not run over it.
    binary = core_candidate(relative_path="capture.bin", kind="protocol.capture")
    staged = stage_candidate(evidence_root, binary, digest_text)
    succeeded(validate(binary, staged, media_type=NATIVE_MEDIA))


def test_the_token_contract_is_checked_before_any_io(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    data = b"native engine bytes"
    adapter = adapter_candidate(data)
    confined = stage_candidate(tmp_path, adapter, data)
    evidence = core_candidate()
    evidence_confined = stage_candidate(tmp_path / "evidence", evidence, data)

    def refuse_open(*args: object, **kwargs: object) -> None:
        raise AssertionError("a contract refusal opened a file")

    monkeypatch.setattr(Path, "open", refuse_open)
    with pytest.raises(ValueError, match="RESULT candidate requires the attempt token"):
        validate(adapter, confined, token=MISSING)
    with pytest.raises(ValueError, match="EVIDENCE candidate takes no attempt token"):
        validate(evidence, evidence_confined, token=TOKEN)
    with pytest.raises(ValueError, match="token belongs to another run"):
        validate(adapter, confined, token=FOREIGN_TOKEN)
    with pytest.raises(ValueError, match="confined path is not the candidate"):
        validate(adapter, evidence_confined)
    with pytest.raises(TypeError, match="CandidateArtifact"):
        validate_candidate(
            evidence_confined,  # type: ignore[arg-type]
            confined,
            hasher=StreamingContentHasher(),
            token=TOKEN,
            ceilings=DEFAULT_CEILINGS,
            now_utc=NOW,
        )
    with pytest.raises(TypeError, match="ConfinedPath"):
        validate(adapter, confined.path)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="ContentHasher"):
        validate(adapter, confined, hasher=object())
    with pytest.raises(TypeError, match="ValidationCeilings"):
        validate(adapter, confined, ceilings=(4, 4))


def test_mutation_between_confinement_and_validation_fails_at_path(
    tmp_path: Path,
) -> None:
    data = b"native engine bytes"
    candidate = adapter_candidate(data)
    confined = stage_candidate(tmp_path, candidate, data)
    confined.path.unlink()
    confined.path.write_bytes(data + b" and more")
    validation = validate(candidate, confined)
    message = failed_with(validation, "PATH", ARTIFACT_VALIDATION_FAILED)
    assert "changed while finalizing" in message
    assert stages(validation) == (("PATH", "FAILED"),)


def test_diagnostics_carry_the_owner_correlation(tmp_path: Path) -> None:
    data = b"native engine bytes"
    run_candidate = adapter_candidate(data, declared_hash=DIGEST_SHAPED)
    validation = validate(run_candidate, stage_candidate(tmp_path, run_candidate, data))
    assert isinstance(validation.result, Failure)
    diagnostic = validation.result.diagnostics[0]
    assert (diagnostic.experiment_id, diagnostic.run_id, diagnostic.invocation_id) == (
        EXPERIMENT_ID,
        RUN_ID,
        INVOCATION_ID,
    )
    assert diagnostic.timestamp_utc == NOW
    system = core_candidate(owner=SYSTEM_OWNER)
    shaped = validate(
        system,
        stage_candidate(tmp_path / "system", system, DIGEST_SHAPED.encode()),
    )
    assert isinstance(shaped.result, Failure)
    system_diagnostic = shaped.result.diagnostics[0]
    assert not isinstance(system_diagnostic.experiment_id, str)
    assert not isinstance(system_diagnostic.run_id, str)
    assert not isinstance(system_diagnostic.invocation_id, str)


class _UnreadableHasher:
    """A ``ContentHasher`` whose stream fails with a plain storage error."""

    def sha256_stream(self, source: BinaryIO) -> str:
        raise OSError(5, "Input/output error")

    def sha256_and_scan(
        self,
        source: BinaryIO,
        token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
        *,
        detect_token_shape: bool = False,
    ) -> HashScan:
        raise OSError(5, "Input/output error")


def storage_failure(
    validation: CandidateValidation, confined: ConfinedPath, content: bytes
) -> str:
    """Reading 26's posture: ``PERSISTENCE``, not retriable, never a corruption
    classification; the owner correlation kept; nothing of the candidate --
    neither its path nor its bytes -- in the message; the bytes untouched."""
    assert isinstance(validation.result, Failure)
    diagnostic = validation.result.diagnostics[0]
    assert diagnostic.error_code == ARTIFACT_MOVE_FAILED
    assert diagnostic.category is not DiagnosticCategory.ARTIFACT_CORRUPTION
    assert diagnostic.category is DiagnosticCategory.PERSISTENCE
    assert diagnostic.retriable is False
    assert (diagnostic.experiment_id, diagnostic.run_id, diagnostic.invocation_id) == (
        EXPERIMENT_ID,
        RUN_ID,
        INVOCATION_ID,
    )
    assert str(confined.path) not in diagnostic.message
    assert confined.relative not in diagnostic.message
    assert content.decode("utf-8") not in diagnostic.message
    assert confined.path.read_bytes() == content
    return diagnostic.message


def test_schema_read_failure_is_a_storage_failure_not_corruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reading 26: a JSON candidate whose bytes could not be read at ``SCHEMA`` was
    not proven malformed; the refusal is ``ARTIFACT.MOVE_FAILED`` recorded at that
    stage, and a corruption classification is never minted."""
    data = b'{"a": "schema bytes"}'
    candidate = adapter_candidate(data, relative_path=JSON_PATH, media=JSON_MEDIA)
    confined = stage_candidate(tmp_path, candidate, data)
    original_open = Path.open

    def refuse_candidate_read(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == confined.path:
            raise OSError(5, "Input/output error")
        return original_open(self, *args, **kwargs)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", refuse_candidate_read)
        validation = validate(candidate, confined)
    assert "could not be read" in failed_with(
        validation, "SCHEMA", ARTIFACT_MOVE_FAILED
    )
    assert "could not be read" in storage_failure(validation, confined, data)
    assert stages(validation) == (
        ("PATH", "PASSED"),
        ("SIZE", "PASSED"),
        ("MEDIA", "PASSED"),
        ("SCHEMA", "FAILED"),
    )
    # Positive control: the same bytes, readable, are one well-formed document.
    succeeded(validate(candidate, confined))


def test_hash_read_failure_is_a_storage_failure_not_corruption(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reading 26: a candidate whose stream failed at ``HASH`` -- at the hasher
    port with a plain ``OSError`` or at the real reader with a sharing refusal --
    was neither hashed nor proven wrong; the refusal is ``ARTIFACT.MOVE_FAILED``
    at ``HASH`` and the proven-mismatch posture of that stage is not minted."""
    data = b"native engine bytes"
    candidate = adapter_candidate(data)
    confined = stage_candidate(tmp_path, candidate, data)
    at_port = validate(candidate, confined, hasher=_UnreadableHasher())
    assert "could not be read" in failed_with(at_port, "HASH", ARTIFACT_MOVE_FAILED)
    assert "could not be read" in storage_failure(at_port, confined, data)
    assert stages(at_port) == (
        ("PATH", "PASSED"),
        ("SIZE", "PASSED"),
        ("MEDIA", "PASSED"),
        ("HASH", "FAILED"),
    )
    failed = at_port.observations[-1]
    assert not isinstance(failed.observed_size_bytes, int)
    assert not isinstance(failed.observed_sha256, str)
    original_open = Path.open

    def refuse_candidate_read(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == confined.path:
            raise PermissionError(13, "Permission denied")
        return original_open(self, *args, **kwargs)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", refuse_candidate_read)
        at_reader = validate(candidate, confined)
    assert "could not be read" in failed_with(at_reader, "HASH", ARTIFACT_MOVE_FAILED)
    storage_failure(at_reader, confined, data)
    assert stages(at_reader) == stages(at_port)
    # Positive control: the same bytes, readable, validate against the declaration.
    succeeded(validate(candidate, confined))


class _RecordingHasher:
    """A ``ContentHasher`` that records the descriptor of every handle it reads
    and delegates to the streaming hasher (plan 4.1 stream entry points); the
    optional ``on_stream`` hook runs as each stream begins."""

    def __init__(self, on_stream: Callable[[], None] | None = None) -> None:
        self._inner = StreamingContentHasher()
        self._on_stream = on_stream
        self.descriptors: list[int] = []

    def _begin(self, source: BinaryIO) -> None:
        self.descriptors.append(source.fileno())
        if self._on_stream is not None:
            self._on_stream()

    def sha256_stream(self, source: BinaryIO) -> str:
        self._begin(source)
        return self._inner.sha256_stream(source)

    def sha256_and_scan(
        self,
        source: BinaryIO,
        token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
        *,
        detect_token_shape: bool = False,
    ) -> HashScan:
        self._begin(source)
        return self._inner.sha256_and_scan(
            source, token, detect_token_shape=detect_token_shape
        )


class _SwappedHandle:
    """The handle opened on a substitute: reads as the handle does and, once the
    handle is closed, runs the restore that renames the original back."""

    def __init__(self, inner: BinaryIO, restore: Callable[[], None]) -> None:
        self._inner = inner
        self._restore = restore

    def __enter__(self) -> _SwappedHandle:
        return self

    def __exit__(self, *exc: object) -> None:
        try:
            self._inner.close()
        finally:
            self._restore()

    def read(self, size: int = -1) -> bytes:
        return self._inner.read(size)

    def fileno(self) -> int:
        return self._inner.fileno()


def test_a_substitute_swapped_around_the_open_is_refused_at_hash(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reading 18 and plan 4.3 phase 1: the hash and the scan run over a handle
    whose ``fstat`` identity is compared with the confined identity before and
    after the stream. A same-size substitute renamed into place after the path
    inspection and renamed away again once the handle closes leaves the path
    identity restored -- a recheck by path alone sees nothing -- so the refusal
    must come from the handle's own identity, before a byte of it is streamed."""
    data = b"plain stderr text\n"
    substitute_data = b"other stderr line\n"
    assert len(substitute_data) == len(data)
    assert substitute_data != data
    evidence = core_candidate()
    confined = stage_candidate(tmp_path, evidence, data)
    aside = tmp_path / "aside.txt"
    substitute = tmp_path / "substitute.txt"
    substitute.write_bytes(substitute_data)
    recording = _RecordingHasher()
    original_open = Path.open
    swaps: list[str] = []

    def restore() -> None:
        confined.path.rename(substitute)
        aside.rename(confined.path)
        swaps.append("restored")

    def swapping_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        if self == confined.path and args == ("rb",):
            confined.path.rename(aside)
            substitute.rename(confined.path)
            swaps.append("swapped")
            return _SwappedHandle(original_open(self, *args, **kwargs), restore)
        return original_open(self, *args, **kwargs)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", swapping_open)
        validation = validate(evidence, confined, hasher=recording)
    assert swaps == ["swapped", "restored"]
    # Control: the original is back under its path with its identity intact, so
    # the by-path recheck accepts it; only the handle could have told.
    assert confined.path.read_bytes() == data
    assert substitute.read_bytes() == substitute_data
    assert isinstance(recheck_confined_path(confined, now_utc=NOW), Success)
    message = failed_with(validation, "HASH", ARTIFACT_VALIDATION_FAILED)
    assert "changed" in message
    assert recording.descriptors == []
    assert stages(validation) == (
        ("PATH", "PASSED"),
        ("SIZE", "PASSED"),
        ("MEDIA", "PASSED"),
        ("HASH", "FAILED"),
    )
    # Positive control: unswapped, the same candidate validates with its digest.
    validated = succeeded(validate(evidence, confined, hasher=recording))
    assert validated.content_hash == sha256_of(data)
    assert len(recording.descriptors) == 1


def test_hash_and_scan_stream_the_identity_checked_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The one ``rb`` handle of the HASH step is the one the hasher streams, and
    its ``fstat`` identity is read exactly twice -- once before the stream begins
    and once after it -- on that same descriptor; no other path is opened for
    the hash."""
    data = b"native engine bytes"
    candidate = adapter_candidate(data)
    confined = stage_candidate(tmp_path, candidate, data)
    fstats: list[int] = []
    fstats_before_stream: list[int] = []
    recording = _RecordingHasher(
        on_stream=lambda: fstats_before_stream.append(len(fstats))
    )
    original_fstat = os.fstat

    def spying_fstat(fd: int) -> os.stat_result:
        fstats.append(fd)
        return original_fstat(fd)

    opens: list[tuple[Path, tuple[Any, ...]]] = []
    original_open = Path.open

    def spying_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        opens.append((self, args))
        return original_open(self, *args, **kwargs)

    with monkeypatch.context() as patched:
        patched.setattr(os, "fstat", spying_fstat)
        patched.setattr(Path, "open", spying_open)
        validation = validate(candidate, confined, hasher=recording)
    validated = succeeded(validation)
    assert validated.content_hash == sha256_of(data)
    assert validated.identity == confined.identity
    assert len(recording.descriptors) == 1
    assert fstats == [recording.descriptors[0]] * 2
    assert fstats_before_stream == [1]  # one before the stream, so one after it
    assert opens == [(confined.path, ("rb",))]


# --- The SCHEMA read: the same handle bridge, its bytes bound to the digest -----------

MALFORMED_JSON = b'{"a": 1, "a": 2}'
WELL_FORMED_TWIN = b'{"a": 1, "b": 2}'


class _SubstitutingHandle:
    """A handle on the candidate's own descriptor -- its ``fileno`` and so its
    ``fstat`` identity are the real file's -- whose reads yield other bytes, as a
    file rewritten in place under an unchanged identity would; ``on_read`` sees
    the size of every read as it is asked for."""

    def __init__(
        self, inner: BinaryIO, data: bytes, on_read: Callable[[int], None]
    ) -> None:
        self._inner = inner
        self._data = data
        self._on_read = on_read
        self._position = 0

    def __enter__(self) -> _SubstitutingHandle:
        return self

    def __exit__(self, *exc: object) -> None:
        self._inner.close()

    def read(self, size: int = -1) -> bytes:
        self._on_read(size)
        remaining = self._data[self._position :]
        chunk = remaining if size < 0 else remaining[:size]
        self._position += len(chunk)
        return chunk

    def fileno(self) -> int:
        return self._inner.fileno()


def test_a_substitute_swapped_around_the_schema_open_is_refused_at_schema(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Reading 18 over the ``SCHEMA`` read: a JSON candidate's bytes are read for
    the strict decode through the store's identity-checked handle bridge, the same
    one the ``HASH`` step streams through. A same-size well-formed twin renamed
    into place for the ``SCHEMA`` open alone and renamed away again once that
    handle closes -- the malformed original back under its path before ``HASH``,
    so the stream digests exactly the declared bytes -- must not yield a
    ``ValidatedCandidate``: the refusal comes from the handle's own identity at
    ``SCHEMA``, before a byte of the twin is decoded, and nothing is hashed."""
    assert len(WELL_FORMED_TWIN) == len(MALFORMED_JSON)
    assert json.loads(WELL_FORMED_TWIN) == {"a": 1, "b": 2}
    candidate = adapter_candidate(
        MALFORMED_JSON, relative_path=JSON_PATH, media=JSON_MEDIA
    )
    confined = stage_candidate(tmp_path, candidate, MALFORMED_JSON)
    aside = tmp_path / "aside.json"
    substitute = tmp_path / "substitute.json"
    substitute.write_bytes(WELL_FORMED_TWIN)
    recording = _RecordingHasher()
    original_open = Path.open
    swaps: list[str] = []

    def restore() -> None:
        confined.path.rename(substitute)
        aside.rename(confined.path)
        swaps.append("restored")

    def swapping_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        # The first ``rb`` open of the candidate is the SCHEMA read; the HASH
        # open that follows finds the malformed original restored.
        if self == confined.path and args == ("rb",) and not swaps:
            confined.path.rename(aside)
            substitute.rename(confined.path)
            swaps.append("swapped")
            return _SwappedHandle(original_open(self, *args, **kwargs), restore)
        return original_open(self, *args, **kwargs)

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", swapping_open)
        validation = validate(candidate, confined, hasher=recording)
    assert swaps == ["swapped", "restored"]
    # Control: the malformed original is back under its path with its identity
    # intact, so the by-path recheck accepts it; only the handle could have told.
    assert confined.path.read_bytes() == MALFORMED_JSON
    assert substitute.read_bytes() == WELL_FORMED_TWIN
    assert isinstance(recheck_confined_path(confined, now_utc=NOW), Success)
    assert not isinstance(validation.result, Success), validation.result
    message = failed_with(validation, "SCHEMA", ARTIFACT_VALIDATION_FAILED)
    assert "changed" in message
    assert recording.descriptors == []
    assert stages(validation) == (
        ("PATH", "PASSED"),
        ("SIZE", "PASSED"),
        ("MEDIA", "PASSED"),
        ("SCHEMA", "FAILED"),
    )
    # Positive controls: unswapped, the malformed original is refused at SCHEMA
    # by its own bytes, and the twin staged honestly validates with its digest.
    assert "well-formed" in failed_with(
        validate(candidate, confined, hasher=recording),
        "SCHEMA",
        ARTIFACT_VALIDATION_FAILED,
    )
    assert recording.descriptors == []
    honest = adapter_candidate(
        WELL_FORMED_TWIN, relative_path=JSON_PATH, media=JSON_MEDIA
    )
    validated = succeeded(
        validate(
            honest,
            stage_candidate(tmp_path / "honest", honest, WELL_FORMED_TWIN),
            hasher=recording,
        )
    )
    assert validated.content_hash == sha256_of(WELL_FORMED_TWIN)
    assert len(recording.descriptors) == 1


def test_schema_bytes_that_differ_from_the_hashed_bytes_are_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bytes decoded at ``SCHEMA`` are bound to the bytes the ``HASH`` step
    digests. A handle on the candidate's own descriptor -- every identity check
    passes -- whose reads yield a same-size well-formed twin while the malformed
    original is what ``HASH`` streams (its digest the declared one) must not yield
    a ``ValidatedCandidate``: the digest of the schema bytes and the authoritative
    digest differ, refused at ``HASH`` with the changed-while-hashing posture.
    The ``SCHEMA`` read asks for exactly the observed size, once, never more."""
    candidate = adapter_candidate(
        MALFORMED_JSON, relative_path=JSON_PATH, media=JSON_MEDIA
    )
    confined = stage_candidate(tmp_path, candidate, MALFORMED_JSON)
    recording = _RecordingHasher()
    original_open = Path.open
    reads: list[int] = []
    substituted: list[Path] = []

    def substituting_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        handle = original_open(self, *args, **kwargs)
        if self == confined.path and args == ("rb",) and not substituted:
            substituted.append(self)
            return _SubstitutingHandle(handle, WELL_FORMED_TWIN, reads.append)
        return handle

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", substituting_open)
        validation = validate(candidate, confined, hasher=recording)
    assert substituted == [confined.path]
    assert reads == [len(MALFORMED_JSON)]
    assert confined.path.read_bytes() == MALFORMED_JSON
    assert not isinstance(validation.result, Success), validation.result
    message = failed_with(validation, "HASH", ARTIFACT_VALIDATION_FAILED)
    assert "changed" in message
    assert len(recording.descriptors) == 1
    assert stages(validation) == (
        ("PATH", "PASSED"),
        ("SIZE", "PASSED"),
        ("MEDIA", "PASSED"),
        ("SCHEMA", "PASSED"),
        ("REDACTION", "PASSED"),
        ("HASH", "FAILED"),
    )
    failed = validation.observations[-1]
    assert not isinstance(failed.observed_size_bytes, int)
    assert not isinstance(failed.observed_sha256, str)
    # Positive control: the same handle yielding the file's own bytes validates,
    # with the same single bounded read.
    data = b'{"a": "schema bytes"}'
    honest = adapter_candidate(data, relative_path=JSON_PATH, media=JSON_MEDIA)
    honest_confined = stage_candidate(tmp_path / "honest", honest, data)
    reads.clear()
    substituted.clear()

    def echoing_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        handle = original_open(self, *args, **kwargs)
        if self == honest_confined.path and args == ("rb",) and not substituted:
            substituted.append(self)
            return _SubstitutingHandle(handle, data, reads.append)
        return handle

    with monkeypatch.context() as patched:
        patched.setattr(Path, "open", echoing_open)
        validated = succeeded(validate(honest, honest_confined, hasher=recording))
    assert validated.content_hash == sha256_of(data)
    assert reads == [len(data)]


def test_the_schema_read_streams_an_identity_checked_handle(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A JSON candidate is opened ``rb`` exactly twice -- the ``SCHEMA`` read and
    the ``HASH`` stream -- and each handle's ``fstat`` identity is read twice on
    its own descriptor: once before the bytes pass through it and once after,
    while it is still open. The ``HASH`` handle is the one the hasher streams;
    no other path is opened."""
    data = b'{"a": "schema bytes"}'
    candidate = adapter_candidate(data, relative_path=JSON_PATH, media=JSON_MEDIA)
    confined = stage_candidate(tmp_path, candidate, data)
    fstats: list[int] = []
    fstats_before_stream: list[int] = []
    recording = _RecordingHasher(
        on_stream=lambda: fstats_before_stream.append(len(fstats))
    )
    original_fstat = os.fstat

    def spying_fstat(fd: int) -> os.stat_result:
        fstats.append(fd)
        return original_fstat(fd)

    opens: list[tuple[Path, tuple[Any, ...]]] = []
    schema_descriptors: list[int] = []
    schema_reads: list[tuple[int, int]] = []  # (fstats so far, size asked for)
    original_open = Path.open

    def spying_open(self: Path, *args: Any, **kwargs: Any) -> Any:
        opens.append((self, args))
        handle = original_open(self, *args, **kwargs)
        if self == confined.path and len(opens) == 1:
            schema_descriptors.append(handle.fileno())
            return _SubstitutingHandle(
                handle,
                data,
                lambda size: schema_reads.append((len(fstats), size)),
            )
        return handle

    with monkeypatch.context() as patched:
        patched.setattr(os, "fstat", spying_fstat)
        patched.setattr(Path, "open", spying_open)
        validation = validate(candidate, confined, hasher=recording)
    validated = succeeded(validation)
    assert validated.content_hash == sha256_of(data)
    assert validated.identity == confined.identity
    assert opens == [(confined.path, ("rb",)), (confined.path, ("rb",))]
    assert len(schema_descriptors) == 1
    assert len(recording.descriptors) == 1
    # Two fstats on the SCHEMA descriptor, then two on the HASH descriptor.
    assert fstats == [schema_descriptors[0]] * 2 + [recording.descriptors[0]] * 2
    assert schema_reads == [(1, len(data))]  # one before the read, so one after
    assert fstats_before_stream == [3]  # one before the stream, so one after it


def test_ceilings_are_validated_values() -> None:
    with pytest.raises(ValueError, match="positive"):
        ValidationCeilings(max_bytes=0, max_parse_bytes=0)
    with pytest.raises(ValueError, match="parse ceiling"):
        ValidationCeilings(max_bytes=4, max_parse_bytes=8)
    with pytest.raises(TypeError, match="integers"):
        ValidationCeilings(max_bytes=4.0, max_parse_bytes=2)  # type: ignore[arg-type]
    with pytest.raises(dataclasses.FrozenInstanceError):
        DEFAULT_CEILINGS.max_bytes = 1  # type: ignore[misc]
