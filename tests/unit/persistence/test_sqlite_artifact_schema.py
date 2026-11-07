"""The Stage 9 tables, their CHECKs, foreign keys, unique indexes and triggers
(Stage 9 plan 3.3, 3.4, 6.6; Task 5), exercised row by row through raw statements.

Every refusal case starts from a row the table admits -- the same encoders the
repositories use build it -- and changes one fact, so each CHECK, each unique
index and each trigger event of plan 3.3 and 3.4 is reached by a statement whose
only defect is the one under test. SQLite runs ``BEFORE`` triggers before the row
constraints, so where a trigger and a CHECK guard the same fact the trigger's
message is the one observed and recorded here. A persistence refusal classifies
through ``SqliteDatabase.classify`` as ``CORE.INVARIANT_VIOLATION`` (CHECK, foreign
key, trigger) or ``PERSISTENCE.CONCURRENCY_CONFLICT`` (a repeated identity or
unique tuple); the positive controls prove the baseline rows and the lawful
updates are admitted. The named tests cover reading 10 (``stderr_artifact_id``
targets core evidence of the describe adapter or the same run), the sanitized
manifest token and path exclusion, reading 11 (success requires a manifest and a
manifest requires a ``RUNNING`` run with a snapshotted deadline and an ``EXITED``
run-command invocation), ``RESTRICT`` on every foreign key, the reviewed object
digest and the sixteen-rule-to-object trigger inventory.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Final

import pytest
from sqlalchemy import text

from crypto_lab.artifacts.journal import FinalizationJournalState
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    CandidateArtifactProducerKind,
    CandidateArtifactState,
    finalized_relative_path_for,
)
from crypto_lab.artifacts.ownership import artifact_owner_hash
from crypto_lab.domain.lifecycle import (
    CommandInvocationState,
    CommandKind,
    EngineRunState,
)
from crypto_lab.persistence.artifact_codecs import (
    encode_artifact_ref,
    encode_audit_event,
    encode_candidate_artifact,
    encode_finalization_journal_entry,
)
from crypto_lab.persistence.codecs import utc_to_micros
from crypto_lab.persistence.diagnostics import (
    CONCURRENCY_CONFLICT,
    INVARIANT_VIOLATION,
)
from crypto_lab.persistence.schema import (
    EXPECTED_SCHEMA_OBJECTS,
    STAGE9_TRIGGER_RULES,
    STAGE9_TRIGGER_SQL,
)
from doubles.artifacts import (
    ADAPTER_OWNER,
    ATTEMPT_TOKEN_HASH,
    CANDIDATE_ID,
    DEADLINE,
    OTHER_CANDIDATE_ID,
    RUN_MANIFEST_HASH,
    RUN_MANIFEST_ID,
    RUN_OWNER,
    SANITIZED_MANIFEST_HASH,
    SOURCE_MANIFEST_HASH,
    SYSTEM_OWNER,
    THIRD_CANDIDATE_ID,
    sample_artifact_manifest,
    sample_audit_event,
    sample_candidate,
    sample_journal,
    sample_ref,
)
from doubles.experiments import (
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_EXPERIMENT_ID,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    RUN_ID,
    SLOT_B,
    UUID_B,
    UUID_C,
    UUID_D,
    UUID_E,
    sample_invocation,
    sample_run,
)
from persistence_support.artifacts import STAGE9_TABLES, ArtifactHarness
from persistence_support.harness import commit, ok, put_invocation, put_run

from .test_sqlite_schema import _EXPECTED_OBJECTS_DIGEST

_S = CandidateArtifactState
_P = CandidateArtifactProducerKind
_F = ArtifactFinalizationPurpose
_J = FinalizationJournalState
_T0: Final = utc_to_micros(INSTANT)
_DEADLINE_MICROS: Final = utc_to_micros(DEADLINE)
_FK: Final = "FOREIGN KEY constraint failed"
_OWNER_ROLE: Final = "candidate owner kind does not admit"
_MATCH_CANDIDATE: Final = "FINALIZING candidate"
_RUN_EVIDENCE: Final = "core EVIDENCE reference of the same run"
_TARGET_RUN_OWNER: Final = "RUN-owned reference of the same run"
_MEMBER_MANIFEST: Final = "registered manifest of the run"
_REQUIRES_RUNNING: Final = "run manifest requires a RUNNING run"
_VALIDATE: Final = "requires a VALIDATE invocation"
_ADVANCE: Final = "states advance PREPARED, MOVED, REGISTERED or ABANDONED only"
_SUCCESS_NEEDS_MANIFEST: Final = "run success requires a registered run manifest"
_STDERR: Final = "stderr_artifact_id targets core EVIDENCE"

_NEW_CANDIDATE_ID: Final = f"cand_{UUID_D}"
_FROZEN_CANDIDATE_ID: Final = f"cand_{UUID_E}"
_VALIDATE_INVOCATION_ID: Final = OTHER_INVOCATION_ID
_SECOND_VALIDATE_INVOCATION_ID: Final = f"inv_{UUID_C}"
_DESCRIBE_INVOCATION_ID: Final = f"inv_{UUID_D}"
_UNKNOWN_INVOCATION_ID: Final = f"inv_{UUID_E}"
_UNKNOWN_RUN_ID: Final = f"run_{UUID_D}"
_UNKNOWN_ARTIFACT_ID: Final = f"art_{UUID_E}"
_RUN_OWNER_HASH: Final = artifact_owner_hash(RUN_OWNER)
_SYSTEM_OWNER_HASH: Final = artifact_owner_hash(SYSTEM_OWNER)
_ADAPTER_OWNER_HASH: Final = artifact_owner_hash(ADAPTER_OWNER)
_UNKNOWN_HASH: Final = "e" * 64
_PRESEEDED_SANITIZED_HASH: Final = "5" * 64
_PRESEEDED_SOURCE_HASH: Final = "6" * 64

# The committed pre-state every case starts from (the fixture plants it).
_RESULT_CANDIDATE: Final = sample_candidate(state=_S.FINALIZING)
_OTHER_RESULT_CANDIDATE: Final = sample_candidate(
    state=_S.FINALIZING, candidate_artifact_id=OTHER_CANDIDATE_ID
)
_EVIDENCE_CANDIDATE: Final = sample_candidate(
    "RUN",
    _F.EVIDENCE,
    producer=_P.CORE,
    state=_S.FINALIZING,
    candidate_artifact_id=THIRD_CANDIDATE_ID,
)
_FROZEN_CANDIDATE: Final = sample_candidate(
    "SYSTEM",
    _F.EVIDENCE,
    producer=_P.CORE,
    state=_S.QUARANTINED,
    candidate_artifact_id=_FROZEN_CANDIDATE_ID,
)
_RESULT_REF: Final = sample_ref(_OTHER_RESULT_CANDIDATE)
_RESULT_MANIFEST: Final = sample_artifact_manifest(_RESULT_REF)
_EVIDENCE_REF: Final = sample_ref(_EVIDENCE_CANDIDATE)
_EVIDENCE_MANIFEST: Final = sample_artifact_manifest(_EVIDENCE_REF)
_REF_UNDER_TEST: Final = sample_ref(_RESULT_CANDIDATE)
_MANIFEST_UNDER_TEST: Final = sample_artifact_manifest(_REF_UNDER_TEST)
_SECOND_RESULT_REF: Final = sample_ref(_OTHER_RESULT_CANDIDATE, content_hash="c" * 64)
_PRESEEDED_SANITIZED_ROW: Final[dict[str, object]] = {
    "sanitized_adapter_result_manifest_hash": _PRESEEDED_SANITIZED_HASH,
    "run_id": RUN_ID,
    "run_invocation_id": INVOCATION_ID,
    "experiment_id": EXPERIMENT_ID,
    "attempt_token_hash": ATTEMPT_TOKEN_HASH,
    "source_adapter_result_manifest_hash": _PRESEEDED_SOURCE_HASH,
    "semantic_status": "SUCCEEDED",
    "manifest_json": '{"attempt_token_hash":"' + ATTEMPT_TOKEN_HASH + '"}',
    "evidence_artifact_id": None,
    "recorded_at_utc": _T0,
}

# The rows each table admits: the case rows are these with one fact changed.
_BASELINE: Final[dict[str, dict[str, object]]] = {
    "candidate_artifacts": dict(
        encode_candidate_artifact(
            sample_candidate(candidate_artifact_id=_NEW_CANDIDATE_ID)
        )
    ),
    "artifact_refs": dict(encode_artifact_ref(_REF_UNDER_TEST, _MANIFEST_UNDER_TEST)),
    "sanitized_adapter_result_manifests": {
        **_PRESEEDED_SANITIZED_ROW,
        "sanitized_adapter_result_manifest_hash": SANITIZED_MANIFEST_HASH,
        "source_adapter_result_manifest_hash": SOURCE_MANIFEST_HASH,
    },
    "run_manifests": {
        "manifest_id": RUN_MANIFEST_ID,
        "schema_version": "1.0.0",
        "run_id": RUN_ID,
        "experiment_id": EXPERIMENT_ID,
        "run_invocation_id": INVOCATION_ID,
        "attempt_token_hash": ATTEMPT_TOKEN_HASH,
        "sanitized_adapter_result_manifest_hash": _PRESEEDED_SANITIZED_HASH,
        "semantic_status": "SUCCEEDED",
        "process_exit_category": "SUCCESS",
        "manifest_json": '{"run_id":"' + RUN_ID + '"}',
        "run_manifest_hash": RUN_MANIFEST_HASH,
        "registered_at_utc": _T0,
    },
    "run_artifacts": {
        "run_id": RUN_ID,
        "artifact_id": _EVIDENCE_REF.artifact_id,
        "link_role": "RUN_EVIDENCE",
        "experiment_id": EXPERIMENT_ID,
        "run_manifest_id": None,
    },
    "finalization_journal": dict(
        encode_finalization_journal_entry(sample_journal(purpose=_F.RESULT))
    ),
    "audit_events": dict(encode_audit_event(sample_audit_event())),
    "adapter_validation_results": {
        "invocation_id": _VALIDATE_INVOCATION_ID,
        "run_id": RUN_ID,
        "experiment_id": EXPERIMENT_ID,
        "validation_result_hash": "d" * 64,
        "outcome": "PASSED",
        "result_json": '{"outcome":"PASSED"}',
        "evidence_artifact_id": None,
        "recorded_at_utc": _T0,
    },
}
_EVIDENCE_JOURNAL_ROW: Final[dict[str, object]] = dict(
    encode_finalization_journal_entry(sample_journal(purpose=_F.EVIDENCE))
)
_SECOND_RESULT_JOURNAL_ROW: Final[dict[str, object]] = dict(
    encode_finalization_journal_entry(
        sample_journal(
            purpose=_F.RESULT,
            candidate_artifact_ids=(OTHER_CANDIDATE_ID,),
            source_adapter_result_manifest_hash="b" * 64,
        )
    )
)
_REGISTERED_JOURNAL_ROW: Final[dict[str, object]] = dict(
    encode_finalization_journal_entry(
        sample_journal(
            _J.REGISTERED,
            _F.RESULT,
            candidate_artifact_ids=(OTHER_CANDIDATE_ID,),
            source_adapter_result_manifest_hash="c" * 64,
        )
    )
)
_SECOND_RESULT_REF_ROW: Final[dict[str, object]] = dict(
    encode_artifact_ref(
        _SECOND_RESULT_REF, sample_artifact_manifest(_SECOND_RESULT_REF)
    )
)
_JOURNAL_ID: Final = str(_BASELINE["finalization_journal"]["finalization_id"])
_REGISTERED_JOURNAL_ID: Final = str(_REGISTERED_JOURNAL_ROW["finalization_id"])
_AUDIT_ID: Final = str(_BASELINE["audit_events"]["audit_event_id"])


def _plant(table: str, row: Mapping[str, object]) -> Callable[[ArtifactHarness], None]:
    def plant(harness: ArtifactHarness) -> None:
        harness.plant_raw(table, dict(row))

    return plant


#: The extra committed rows a case may need before its statement.
_PLANTS: Final[dict[str, Callable[[ArtifactHarness], None]]] = {
    "run_manifest": _plant("run_manifests", _BASELINE["run_manifests"]),
    "evidence_link": _plant("run_artifacts", _BASELINE["run_artifacts"]),
    "result_journal": _plant("finalization_journal", _BASELINE["finalization_journal"]),
    "evidence_journal": _plant("finalization_journal", _EVIDENCE_JOURNAL_ROW),
    "registered_journal": _plant("finalization_journal", _REGISTERED_JOURNAL_ROW),
    "audit": _plant("audit_events", _BASELINE["audit_events"]),
    "validation_result": _plant(
        "adapter_validation_results", _BASELINE["adapter_validation_results"]
    ),
}


@dataclass(frozen=True)
class Case:
    """One refused statement: an insert of the baseline row (or ``row``) with
    ``overrides`` applied, or the explicit ``statement`` with its ``parameters``."""

    label: str
    table: str
    overrides: Mapping[str, object] = field(default_factory=dict)
    row: Mapping[str, object] | None = None
    statement: str | None = None
    parameters: tuple[object, ...] = ()
    expected: str = INVARIANT_VIOLATION
    fragment: str = ""
    needs: frozenset[str] = frozenset()


def _update(
    label: str,
    table: str,
    statement: str,
    *parameters: object,
    fragment: str,
    needs: frozenset[str] = frozenset(),
) -> Case:
    return Case(
        label,
        table,
        statement=statement,
        parameters=parameters,
        fragment=fragment,
        needs=needs,
    )


_CASES: Final[tuple[Case, ...]] = (
    # -- candidate_artifacts (plan 3.3 row 1, 3.4 rules 1-3) -------------------
    Case(
        "candidate: identity prefix",
        "candidate_artifacts",
        {"candidate_artifact_id": f"xand_{UUID_D}"},
        fragment="ck_candidate_artifacts_candidate_artifact_id",
    ),
    Case(
        "candidate: schema version",
        "candidate_artifacts",
        {"schema_version": "2.0.0"},
        fragment="ck_candidate_artifacts_schema_version",
    ),
    Case(
        "candidate: state outside the five",
        "candidate_artifacts",
        {"state": "FINALIZED"},
        fragment="ck_candidate_artifacts_state",
    ),
    Case(
        "candidate: ADAPTER without a declared size",
        "candidate_artifacts",
        {"adapter_declared_size": None},
        fragment="ck_candidate_artifacts_adapter_declared_shape",
    ),
    Case(
        "candidate: ADAPTER without a declared media type",
        "candidate_artifacts",
        {"adapter_declared_media_type": None},
        fragment="ck_candidate_artifacts_adapter_declared_shape",
    ),
    Case(
        "candidate: CORE with a declared hash",
        "candidate_artifacts",
        {
            "producer_kind": "CORE",
            "source_role": "NORMALIZED_RESULT",
            "adapter_declared_size": None,
            "adapter_declared_media_type": None,
            "source_event_id": None,
        },
        fragment="ck_candidate_artifacts_core_declared_shape",
    ),
    Case(
        "candidate: CORE with a source event",
        "candidate_artifacts",
        {
            "producer_kind": "CORE",
            "source_role": "NORMALIZED_RESULT",
            "adapter_declared_size": None,
            "adapter_declared_hash": None,
            "adapter_declared_media_type": None,
        },
        fragment="ck_candidate_artifacts_core_declared_shape",
    ),
    Case(
        "candidate: an invocation without its run",
        "candidate_artifacts",
        {
            "producer_kind": "CORE",
            "source_role": "NORMALIZED_RESULT",
            "adapter_declared_size": None,
            "adapter_declared_hash": None,
            "adapter_declared_media_type": None,
            "source_event_id": None,
            "run_id": None,
        },
        fragment="ck_candidate_artifacts_invocation_requires_run",
    ),
    Case(
        "candidate: negative declared size",
        "candidate_artifacts",
        {"adapter_declared_size": -1},
        fragment="ck_candidate_artifacts_adapter_declared_size",
    ),
    Case(
        "candidate: declared hash not 64 hex",
        "candidate_artifacts",
        {"adapter_declared_hash": "Z" * 64},
        fragment="ck_candidate_artifacts_adapter_declared_hash",
    ),
    Case(
        "candidate: declared media type too short",
        "candidate_artifacts",
        {"adapter_declared_media_type": "ab"},
        fragment="ck_candidate_artifacts_adapter_declared_media_type",
    ),
    Case(
        "candidate: observations not an array",
        "candidate_artifacts",
        {"observations_json": "{}"},
        fragment="ck_candidate_artifacts_observations_json",
    ),
    Case(
        "candidate: observations hash not 64 hex",
        "candidate_artifacts",
        {"observations_hash": "x" * 64},
        fragment="ck_candidate_artifacts_observations_hash",
    ),
    Case(
        "candidate: source event prefix",
        "candidate_artifacts",
        {"source_event_id": f"xvt_{UUID_D}"},
        fragment="ck_candidate_artifacts_source_event_id",
    ),
    Case(
        "candidate: adapter manifest identity shape",
        "candidate_artifacts",
        {"source_adapter_manifest_id": "amf_bogus"},
        fragment="ck_candidate_artifacts_source_adapter_manifest_id",
    ),
    Case(
        "candidate: updated before created",
        "candidate_artifacts",
        {"updated_at_utc": _T0 - 1},
        fragment="ck_candidate_artifacts_updated_after_created",
    ),
    Case(
        "candidate: revision zero",
        "candidate_artifacts",
        {"revision": 0},
        fragment="ck_candidate_artifacts_revision",
    ),
    Case(
        "candidate: owner row absent (owner-role trigger)",
        "candidate_artifacts",
        {"owner_hash": _UNKNOWN_HASH},
        fragment=_OWNER_ROLE,
    ),
    Case(
        "candidate: SYSTEM owner for a RESULT (owner-role trigger)",
        "candidate_artifacts",
        {"owner_hash": _SYSTEM_OWNER_HASH},
        fragment=_OWNER_ROLE,
    ),
    Case(
        "candidate: EVIDENCE by an ADAPTER producer (owner-role trigger)",
        "candidate_artifacts",
        {"finalization_purpose": "EVIDENCE"},
        fragment=_OWNER_ROLE,
    ),
    Case(
        "candidate: purpose outside the enum (owner-role trigger)",
        "candidate_artifacts",
        {"finalization_purpose": "OTHER"},
        fragment=_OWNER_ROLE,
    ),
    Case(
        "candidate: run differs from the owner's (owner-role trigger)",
        "candidate_artifacts",
        {"run_id": OTHER_RUN_ID},
        fragment=_OWNER_ROLE,
    ),
    Case(
        "candidate: invocation differs from the owner's (owner-role trigger)",
        "candidate_artifacts",
        {"invocation_id": _VALIDATE_INVOCATION_ID},
        fragment=_OWNER_ROLE,
    ),
    Case(
        "candidate: duplicate owner, purpose and staging path",
        "candidate_artifacts",
        {"staging_relative_path": _RESULT_CANDIDATE.staging_relative_path},
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: candidate_artifacts.owner_hash",
    ),
    Case(
        "candidate: duplicate identity",
        "candidate_artifacts",
        {
            "candidate_artifact_id": CANDIDATE_ID,
            "staging_relative_path": "results/twin.bin",
        },
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: candidate_artifacts.candidate_artifact_id",
    ),
    _update(
        "candidate: staging path is immutable",
        "candidate_artifacts",
        "UPDATE candidate_artifacts SET staging_relative_path = ? "
        "WHERE candidate_artifact_id = ?",
        "results/moved.bin",
        CANDIDATE_ID,
        fragment="immutable",
    ),
    _update(
        "candidate: owner is immutable",
        "candidate_artifacts",
        "UPDATE candidate_artifacts SET owner_hash = ? WHERE candidate_artifact_id = ?",
        _SYSTEM_OWNER_HASH,
        CANDIDATE_ID,
        fragment="immutable",
    ),
    _update(
        "candidate: declared facts are immutable",
        "candidate_artifacts",
        "UPDATE candidate_artifacts SET adapter_declared_size = ? "
        "WHERE candidate_artifact_id = ?",
        13,
        CANDIDATE_ID,
        fragment="immutable",
    ),
    _update(
        "candidate: a quarantined candidate is frozen",
        "candidate_artifacts",
        "UPDATE candidate_artifacts SET revision = revision + 1 "
        "WHERE candidate_artifact_id = ?",
        _FROZEN_CANDIDATE_ID,
        fragment="frozen",
    ),
    _update(
        "candidate: a quarantined candidate admits no state change",
        "candidate_artifacts",
        "UPDATE candidate_artifacts SET state = 'CORRUPT' "
        "WHERE candidate_artifact_id = ?",
        _FROZEN_CANDIDATE_ID,
        fragment="frozen",
    ),
    # -- artifact_refs (plan 3.3 row 2, 3.4 rules 4-5) -------------------------
    Case(
        "ref: identity prefix",
        "artifact_refs",
        {"artifact_id": f"xrt_{UUID_D}"},
        fragment="ck_artifact_refs_artifact_id",
    ),
    Case(
        "ref: state other than FINALIZED",
        "artifact_refs",
        {"state": "FINALIZING"},
        fragment="ck_artifact_refs_state",
    ),
    Case(
        "ref: path does not address the content hash",
        "artifact_refs",
        {"finalized_relative_path": finalized_relative_path_for("f" * 64)},
        fragment="ck_artifact_refs_path_addresses_hash",
    ),
    Case(
        "ref: manifest not a JSON object",
        "artifact_refs",
        {"manifest_json": "[]"},
        fragment="ck_artifact_refs_manifest_json",
    ),
    Case(
        "ref: manifest hash not 64 hex",
        "artifact_refs",
        {"artifact_manifest_hash": "g" * 64},
        fragment="ck_artifact_refs_artifact_manifest_hash",
    ),
    Case(
        "ref: negative size",
        "artifact_refs",
        {"size_bytes": -1},
        fragment="ck_artifact_refs_size_bytes",
    ),
    Case(
        "ref: media type too short",
        "artifact_refs",
        {"media_type": "ab"},
        fragment="ck_artifact_refs_media_type",
    ),
    Case(
        "ref: validation profile",
        "artifact_refs",
        {"validation_profile": "artifact-validation/v2"},
        fragment="ck_artifact_refs_validation_profile",
    ),
    Case(
        "ref: finalized before created",
        "artifact_refs",
        {"finalized_at_utc": _T0 - 1},
        fragment="ck_artifact_refs_finalized_after_created",
    ),
    Case(
        "ref: source candidate not FINALIZING (match trigger)",
        "artifact_refs",
        {
            "source_candidate_artifact_id": _FROZEN_CANDIDATE_ID,
            "owner_hash": _SYSTEM_OWNER_HASH,
            "finalization_purpose": "EVIDENCE",
            "source_role": "CORE_EVIDENCE",
            "producer_kind": "CORE",
            "artifact_kind": _FROZEN_CANDIDATE.artifact_kind,
        },
        fragment=_MATCH_CANDIDATE,
    ),
    Case(
        "ref: source candidate absent (match trigger)",
        "artifact_refs",
        {"source_candidate_artifact_id": _NEW_CANDIDATE_ID},
        fragment=_MATCH_CANDIDATE,
    ),
    Case(
        "ref: owner differs from the candidate's (match trigger)",
        "artifact_refs",
        {"owner_hash": _SYSTEM_OWNER_HASH},
        fragment=_MATCH_CANDIDATE,
    ),
    Case(
        "ref: role differs from the candidate's (match trigger)",
        "artifact_refs",
        {"source_role": "NORMALIZED_RESULT"},
        fragment=_MATCH_CANDIDATE,
    ),
    Case(
        "ref: kind differs from the candidate's (match trigger)",
        "artifact_refs",
        {"artifact_kind": "another-kind"},
        fragment=_MATCH_CANDIDATE,
    ),
    Case(
        "ref: a second reference for one candidate",
        "artifact_refs",
        row=_SECOND_RESULT_REF_ROW,
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: artifact_refs.source_candidate_artifact_id",
    ),
    Case(
        "ref: duplicate manifest hash",
        "artifact_refs",
        {"artifact_manifest_hash": _RESULT_MANIFEST.artifact_manifest_hash},
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: artifact_refs.artifact_manifest_hash",
    ),
    Case(
        "ref: duplicate identity",
        "artifact_refs",
        row=dict(encode_artifact_ref(_RESULT_REF, _RESULT_MANIFEST)),
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: artifact_refs.",
    ),
    _update(
        "ref: never updated",
        "artifact_refs",
        "UPDATE artifact_refs SET media_type = ? WHERE artifact_id = ?",
        "text/plain",
        _RESULT_REF.artifact_id,
        fragment="insert-only",
    ),
    _update(
        "ref: never deleted",
        "artifact_refs",
        "DELETE FROM artifact_refs WHERE artifact_id = ?",
        _RESULT_REF.artifact_id,
        fragment="insert-only",
    ),
    # -- sanitized_adapter_result_manifests (plan 3.3 row 7, 3.4 rule 14) ------
    Case(
        "sanitized: hash not 64 hex",
        "sanitized_adapter_result_manifests",
        {"sanitized_adapter_result_manifest_hash": "g" * 64},
        fragment="ck_sanitized_adapter_result_manifests_sanitized",
    ),
    Case(
        "sanitized: run absent",
        "sanitized_adapter_result_manifests",
        {"run_id": _UNKNOWN_RUN_ID},
        fragment=_FK,
    ),
    Case(
        "sanitized: experiment differs from the run's",
        "sanitized_adapter_result_manifests",
        {"experiment_id": OTHER_EXPERIMENT_ID},
        fragment=_FK,
    ),
    Case(
        "sanitized: invocation absent",
        "sanitized_adapter_result_manifests",
        {"run_invocation_id": _UNKNOWN_INVOCATION_ID},
        fragment=_FK,
    ),
    Case(
        "sanitized: empty semantic status",
        "sanitized_adapter_result_manifests",
        {"semantic_status": ""},
        fragment="ck_sanitized_adapter_result_manifests_semantic_status",
    ),
    Case(
        "sanitized: a raw attempt token key",
        "sanitized_adapter_result_manifests",
        {"manifest_json": '{"attempt_token":"raw"}'},
        fragment="ck_sanitized_adapter_result_manifests_manifest_json",
    ),
    Case(
        "sanitized: a relative path key",
        "sanitized_adapter_result_manifests",
        {"manifest_json": '{"candidates":[{"relative_path":"x.bin"}]}'},
        fragment="ck_sanitized_adapter_result_manifests_manifest_json",
    ),
    Case(
        "sanitized: evidence is a RESULT reference (evidence trigger)",
        "sanitized_adapter_result_manifests",
        {"evidence_artifact_id": _RESULT_REF.artifact_id},
        fragment=_RUN_EVIDENCE,
    ),
    Case(
        "sanitized: evidence absent (evidence trigger)",
        "sanitized_adapter_result_manifests",
        {"evidence_artifact_id": _UNKNOWN_ARTIFACT_ID},
        fragment=_RUN_EVIDENCE,
    ),
    Case(
        "sanitized: duplicate run, invocation and source hash",
        "sanitized_adapter_result_manifests",
        {
            "sanitized_adapter_result_manifest_hash": "7" * 64,
            "source_adapter_result_manifest_hash": _PRESEEDED_SOURCE_HASH,
        },
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: sanitized_adapter_result_manifests.run_id",
    ),
    Case(
        "sanitized: duplicate identity",
        "sanitized_adapter_result_manifests",
        {"sanitized_adapter_result_manifest_hash": _PRESEEDED_SANITIZED_HASH},
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: sanitized_adapter_result_manifests.",
    ),
    _update(
        "sanitized: evidence link to a RESULT reference (evidence trigger)",
        "sanitized_adapter_result_manifests",
        "UPDATE sanitized_adapter_result_manifests SET evidence_artifact_id = ? "
        "WHERE sanitized_adapter_result_manifest_hash = ?",
        _RESULT_REF.artifact_id,
        _PRESEEDED_SANITIZED_HASH,
        fragment="linked once",
    ),
    # -- run_manifests (plan 3.3 row 4, 3.4 rules 8-9) --------------------------
    Case(
        "manifest: identity prefix",
        "run_manifests",
        {"manifest_id": f"xmf_{UUID_D}"},
        fragment="ck_run_manifests_manifest_id",
    ),
    Case(
        "manifest: a non-success semantic status",
        "run_manifests",
        {"semantic_status": "FAILED"},
        fragment="ck_run_manifests_semantic_status",
    ),
    Case(
        "manifest: exit category outside the enum",
        "run_manifests",
        {"process_exit_category": "CRASHED"},
        fragment="ck_run_manifests_process_exit_category",
    ),
    Case(
        "manifest: sanitized manifest absent",
        "run_manifests",
        {"sanitized_adapter_result_manifest_hash": "8" * 64},
        fragment=_FK,
    ),
    Case(
        "manifest: run manifest hash not 64 hex",
        "run_manifests",
        {"run_manifest_hash": "g" * 64},
        fragment="ck_run_manifests_run_manifest_hash",
    ),
    Case(
        "manifest: token hash differs from the run's (running trigger)",
        "run_manifests",
        {"attempt_token_hash": "7" * 64},
        fragment=_REQUIRES_RUNNING,
    ),
    Case(
        "manifest: a VALIDATE invocation (running trigger)",
        "run_manifests",
        {"run_invocation_id": _VALIDATE_INVOCATION_ID},
        fragment=_REQUIRES_RUNNING,
    ),
    Case(
        "manifest: a second manifest for one run",
        "run_manifests",
        {"manifest_id": f"rmf_{UUID_B}", "run_manifest_hash": "9" * 64},
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: run_manifests.run_id",
        needs=frozenset({"run_manifest"}),
    ),
    Case(
        "manifest: duplicate identity",
        "run_manifests",
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: run_manifests.",
        needs=frozenset({"run_manifest"}),
    ),
    _update(
        "manifest: never updated",
        "run_manifests",
        "UPDATE run_manifests SET semantic_status = ? WHERE manifest_id = ?",
        "SUCCEEDED_WITH_WARNINGS",
        RUN_MANIFEST_ID,
        fragment="insert-only",
        needs=frozenset({"run_manifest"}),
    ),
    _update(
        "manifest: never deleted",
        "run_manifests",
        "DELETE FROM run_manifests WHERE manifest_id = ?",
        RUN_MANIFEST_ID,
        fragment="insert-only",
        needs=frozenset({"run_manifest"}),
    ),
    # -- run_artifacts (plan 3.3 row 3, 3.4 rules 6-7) --------------------------
    Case(
        "link: role outside the two",
        "run_artifacts",
        {"link_role": "EVIDENCE"},
        fragment="ck_run_artifacts_link_role",
    ),
    Case(
        "link: a member without its manifest (member trigger)",
        "run_artifacts",
        {
            "link_role": "RESULT_MANIFEST_MEMBER",
            "artifact_id": _RESULT_REF.artifact_id,
        },
        fragment=_MEMBER_MANIFEST,
    ),
    Case(
        "link: a member naming an absent manifest (member trigger)",
        "run_artifacts",
        {
            "link_role": "RESULT_MANIFEST_MEMBER",
            "artifact_id": _RESULT_REF.artifact_id,
            "run_manifest_id": f"rmf_{UUID_B}",
        },
        fragment=_MEMBER_MANIFEST,
    ),
    Case(
        "link: evidence carrying a manifest",
        "run_artifacts",
        {"run_manifest_id": RUN_MANIFEST_ID},
        fragment="ck_run_artifacts_manifest_shape",
        needs=frozenset({"run_manifest"}),
    ),
    Case(
        "link: evidence role to a RESULT reference (owner trigger)",
        "run_artifacts",
        {"artifact_id": _RESULT_REF.artifact_id},
        fragment=_TARGET_RUN_OWNER,
    ),
    Case(
        "link: member role to an EVIDENCE reference (owner trigger)",
        "run_artifacts",
        {"link_role": "RESULT_MANIFEST_MEMBER", "run_manifest_id": RUN_MANIFEST_ID},
        fragment=_TARGET_RUN_OWNER,
        needs=frozenset({"run_manifest"}),
    ),
    Case(
        "link: reference absent (owner trigger)",
        "run_artifacts",
        {"artifact_id": _UNKNOWN_ARTIFACT_ID},
        fragment=_TARGET_RUN_OWNER,
    ),
    Case(
        "link: run differs from the owner's (owner trigger)",
        "run_artifacts",
        {"run_id": OTHER_RUN_ID},
        fragment=_TARGET_RUN_OWNER,
    ),
    Case(
        "link: experiment differs from the owner's (owner trigger)",
        "run_artifacts",
        {"experiment_id": OTHER_EXPERIMENT_ID},
        fragment=_TARGET_RUN_OWNER,
    ),
    Case(
        "link: duplicate identity",
        "run_artifacts",
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: run_artifacts.",
        needs=frozenset({"evidence_link"}),
    ),
    # -- finalization_journal (plan 3.3 row 5, 3.4 rule 12) ---------------------
    Case(
        "journal: identity prefix",
        "finalization_journal",
        {"finalization_id": f"xin_{UUID_D}"},
        fragment="ck_finalization_journal_finalization_id",
    ),
    Case(
        "journal: state outside the four",
        "finalization_journal",
        {"state": "FINALIZED"},
        fragment="ck_finalization_journal_state",
    ),
    Case(
        "journal: RESULT without a deadline",
        "finalization_journal",
        {"finalization_deadline_utc": None},
        fragment="ck_finalization_journal_result_shape",
    ),
    Case(
        "journal: RESULT with a correlation",
        "finalization_journal",
        {"correlation_kind": "AUDIT", "correlation_id": f"audit_{UUID_D}"},
        fragment="ck_finalization_journal_result_shape",
    ),
    Case(
        "journal: EVIDENCE with a run",
        "finalization_journal",
        row={**_EVIDENCE_JOURNAL_ROW, "run_id": RUN_ID},
        fragment="ck_finalization_journal_evidence_shape",
    ),
    Case(
        "journal: EVIDENCE correlation kind outside the three",
        "finalization_journal",
        row={**_EVIDENCE_JOURNAL_ROW, "correlation_kind": "BOGUS"},
        fragment="ck_finalization_journal_correlation_kind",
    ),
    Case(
        "journal: ABANDONED without a reason",
        "finalization_journal",
        {"state": "ABANDONED"},
        fragment="ck_finalization_journal_abandon_shape",
    ),
    Case(
        "journal: PREPARED with a reason",
        "finalization_journal",
        {"abandon_reason": "ARTIFACT.VALIDATION_FAILED"},
        fragment="ck_finalization_journal_abandon_shape",
    ),
    Case(
        "journal: lease past the deadline",
        "finalization_journal",
        {"lease_expires_at_utc": _DEADLINE_MICROS + 1},
        fragment="ck_finalization_journal_lease_within_deadline",
    ),
    Case(
        "journal: deadline before preparation",
        "finalization_journal",
        {"finalization_deadline_utc": _T0 - 1, "lease_expires_at_utc": _T0 - 2},
        fragment="ck_finalization_journal_deadline_after_prepared",
    ),
    Case(
        "journal: empty candidate set",
        "finalization_journal",
        {"candidate_ids_json": "[]"},
        fragment="ck_finalization_journal_candidate_ids_json",
    ),
    Case(
        "journal: empty plan",
        "finalization_journal",
        {"planned_json": "[]"},
        fragment="ck_finalization_journal_planned_json",
    ),
    Case(
        "journal: owner absent",
        "finalization_journal",
        {"owner_hash": _UNKNOWN_HASH},
        fragment=_FK,
    ),
    Case(
        "journal: invocation absent",
        "finalization_journal",
        {"run_invocation_id": _UNKNOWN_INVOCATION_ID},
        fragment=_FK,
    ),
    Case(
        "journal: duplicate RESULT identity",
        "finalization_journal",
        {"finalization_id": f"fin_{UUID_D}"},
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: finalization_journal.",
        needs=frozenset({"result_journal"}),
    ),
    Case(
        "journal: a second active RESULT lease for one run",
        "finalization_journal",
        row=_SECOND_RESULT_JOURNAL_ROW,
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: finalization_journal.run_id",
        needs=frozenset({"result_journal"}),
    ),
    Case(
        "journal: duplicate EVIDENCE identity",
        "finalization_journal",
        row={**_EVIDENCE_JOURNAL_ROW, "finalization_id": f"fin_{UUID_D}"},
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: finalization_journal.owner_hash",
        needs=frozenset({"evidence_journal"}),
    ),
    Case(
        "journal: duplicate identity",
        "finalization_journal",
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: finalization_journal.",
        needs=frozenset({"result_journal"}),
    ),
    _update(
        "journal: PREPARED cannot leap to REGISTERED (monotonic trigger)",
        "finalization_journal",
        "UPDATE finalization_journal SET state = 'REGISTERED' "
        "WHERE finalization_id = ?",
        _JOURNAL_ID,
        fragment=_ADVANCE,
        needs=frozenset({"result_journal"}),
    ),
    _update(
        "journal: a terminal entry never moves (monotonic trigger)",
        "finalization_journal",
        "UPDATE finalization_journal SET state = 'MOVED' WHERE finalization_id = ?",
        _REGISTERED_JOURNAL_ID,
        fragment=_ADVANCE,
        needs=frozenset({"registered_journal"}),
    ),
    _update(
        "journal: the deadline is immutable (monotonic trigger)",
        "finalization_journal",
        "UPDATE finalization_journal SET finalization_deadline_utc = ? "
        "WHERE finalization_id = ?",
        _DEADLINE_MICROS + 1,
        _JOURNAL_ID,
        fragment="deadline is immutable",
        needs=frozenset({"result_journal"}),
    ),
    # -- audit_events (plan 3.3 row 6, 3.4 rule 13) -----------------------------
    Case(
        "audit: identity prefix",
        "audit_events",
        {"audit_event_id": f"xudit_{UUID_D}"},
        fragment="ck_audit_events_audit_event_id",
    ),
    Case(
        "audit: action outside the twenty-five",
        "audit_events",
        {"action": "ARTIFACT_RENAMED"},
        fragment="ck_audit_events_action",
    ),
    Case(
        "audit: actor kind outside the three",
        "audit_events",
        {"actor_kind": "ROBOT"},
        fragment="ck_audit_events_actor_kind",
    ),
    Case(
        "audit: ADAPTER actor without a name",
        "audit_events",
        {"actor_kind": "ADAPTER"},
        fragment="ck_audit_events_actor_shape",
    ),
    Case(
        "audit: CORE actor with an adapter name",
        "audit_events",
        {"actor_adapter_name": "adapter.alpha", "actor_adapter_version": "1.0.0"},
        fragment="ck_audit_events_actor_shape",
    ),
    Case(
        "audit: outcome outside the three",
        "audit_events",
        {"outcome": "PENDING"},
        fragment="ck_audit_events_outcome",
    ),
    Case(
        "audit: details not a JSON object",
        "audit_events",
        {"details_json": "[]"},
        fragment="ck_audit_events_details_json",
    ),
    Case(
        "audit: details beyond 16 KiB",
        "audit_events",
        {"details_json": '{"blob":"' + "x" * 17_000 + '"}'},
        fragment="ck_audit_events_details_json",
    ),
    Case(
        "audit: details hash not 64 hex",
        "audit_events",
        {"details_hash": "g" * 64},
        fragment="ck_audit_events_details_hash",
    ),
    Case(
        "audit: a run fact without its invocation",
        "audit_events",
        {"action": "RUN_SUCCEEDED", "invocation_id": None},
        fragment="ck_audit_events_invocation_required",
    ),
    Case(
        "audit: empty correlation",
        "audit_events",
        {"correlation_id": ""},
        fragment="ck_audit_events_correlation_id",
    ),
    Case(
        "audit: duplicate identity",
        "audit_events",
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: audit_events.audit_event_id",
        needs=frozenset({"audit"}),
    ),
    _update(
        "audit: never updated",
        "audit_events",
        "UPDATE audit_events SET outcome = 'FAILED' WHERE audit_event_id = ?",
        _AUDIT_ID,
        fragment="append-only",
        needs=frozenset({"audit"}),
    ),
    _update(
        "audit: never deleted",
        "audit_events",
        "DELETE FROM audit_events WHERE audit_event_id = ?",
        _AUDIT_ID,
        fragment="append-only",
        needs=frozenset({"audit"}),
    ),
    # -- adapter_validation_results (plan 3.3 row 8, 3.4 rule 15) ---------------
    Case(
        "validation: a RUN invocation (validate trigger)",
        "adapter_validation_results",
        {"invocation_id": INVOCATION_ID},
        fragment=_VALIDATE,
    ),
    Case(
        "validation: invocation absent (validate trigger)",
        "adapter_validation_results",
        {"invocation_id": _UNKNOWN_INVOCATION_ID},
        fragment=_VALIDATE,
    ),
    Case(
        "validation: run differs from the invocation's (validate trigger)",
        "adapter_validation_results",
        {"run_id": OTHER_RUN_ID},
        fragment=_VALIDATE,
    ),
    Case(
        "validation: evidence is a RESULT reference (validate trigger)",
        "adapter_validation_results",
        {"evidence_artifact_id": _RESULT_REF.artifact_id},
        fragment=_VALIDATE,
    ),
    Case(
        "validation: empty outcome",
        "adapter_validation_results",
        {"outcome": ""},
        fragment="ck_adapter_validation_results_outcome",
    ),
    Case(
        "validation: result not a JSON object",
        "adapter_validation_results",
        {"result_json": "[]"},
        fragment="ck_adapter_validation_results_result_json",
    ),
    Case(
        "validation: result hash not 64 hex",
        "adapter_validation_results",
        {"validation_result_hash": "g" * 64},
        fragment="ck_adapter_validation_results_validation_result_hash",
    ),
    Case(
        "validation: duplicate result hash",
        "adapter_validation_results",
        {"invocation_id": _SECOND_VALIDATE_INVOCATION_ID},
        expected=CONCURRENCY_CONFLICT,
        fragment="adapter_validation_results.validation_result_hash",
        needs=frozenset({"validation_result"}),
    ),
    Case(
        "validation: duplicate identity",
        "adapter_validation_results",
        {"validation_result_hash": "a" * 64},
        expected=CONCURRENCY_CONFLICT,
        fragment="UNIQUE constraint failed: adapter_validation_results.invocation_id",
        needs=frozenset({"validation_result"}),
    ),
    _update(
        "validation: evidence link to a RESULT reference (validate trigger)",
        "adapter_validation_results",
        "UPDATE adapter_validation_results SET evidence_artifact_id = ? "
        "WHERE invocation_id = ?",
        _RESULT_REF.artifact_id,
        _VALIDATE_INVOCATION_ID,
        fragment="linked once",
        needs=frozenset({"validation_result"}),
    ),
    # -- engine_runs and command_invocations (plan 3.4 rules 10, 11, 16) --------
    _update(
        "run: the snapshotted deadline is immutable",
        "engine_runs",
        "UPDATE engine_runs SET finalization_deadline_utc = ? WHERE run_id = ?",
        _DEADLINE_MICROS + 1,
        RUN_ID,
        fragment="deadline is immutable",
    ),
    _update(
        "run: success without a registered manifest",
        "engine_runs",
        "UPDATE engine_runs SET state = 'SUCCEEDED', revision = revision + 1 "
        "WHERE run_id = ?",
        RUN_ID,
        fragment=_SUCCESS_NEEDS_MANIFEST,
    ),
    _update(
        "invocation: stderr targeting a RESULT reference (stderr trigger)",
        "command_invocations",
        "UPDATE command_invocations SET stderr_artifact_id = ?, "
        "revision = revision + 1 WHERE invocation_id = ?",
        _RESULT_REF.artifact_id,
        INVOCATION_ID,
        fragment=_STDERR,
    ),
)


@pytest.fixture
def schema_harness(artifact_harness: ArtifactHarness) -> ArtifactHarness:
    """The committed pre-state: the RESULT parents, two ``VALIDATE`` invocations,
    three ``FINALIZING`` candidates, one quarantined candidate, a RESULT and an
    EVIDENCE reference, and one sanitized manifest row."""
    artifact_harness.seed_result_prestate()
    lifecycle = artifact_harness.lifecycle()
    for identity in (_VALIDATE_INVOCATION_ID, _SECOND_VALIDATE_INVOCATION_ID):
        put_invocation(
            lifecycle,
            sample_invocation(
                CommandInvocationState.EXITED,
                kind=CommandKind.VALIDATE,
                invocation_id=identity,
            ),
        )
    for candidate in (
        _RESULT_CANDIDATE,
        _OTHER_RESULT_CANDIDATE,
        _EVIDENCE_CANDIDATE,
        _FROZEN_CANDIDATE,
    ):
        artifact_harness.put_candidate(candidate)
    artifact_harness.put_ref(_RESULT_REF, _RESULT_MANIFEST)
    artifact_harness.put_ref(_EVIDENCE_REF, _EVIDENCE_MANIFEST)
    artifact_harness.plant_raw(
        "sanitized_adapter_result_manifests", dict(_PRESEEDED_SANITIZED_ROW)
    )
    return artifact_harness


@pytest.mark.parametrize("case", _CASES, ids=[case.label for case in _CASES])
def test_tables_constraints_and_triggers(
    schema_harness: ArtifactHarness, case: Case
) -> None:
    for need in sorted(case.needs):
        _PLANTS[need](schema_harness)
    if case.statement is None:
        base = case.row if case.row is not None else _BASELINE[case.table]
        refusal = schema_harness.refuse_insert(case.table, {**base, **case.overrides})
    else:
        refusal = schema_harness.refuse(case.statement, case.parameters)
    assert refusal.code == case.expected, refusal
    assert case.fragment in refusal.message, refusal


def test_every_baseline_row_and_lawful_update_is_admitted(
    schema_harness: ArtifactHarness,
) -> None:
    """The positive controls: each case's starting row inserts, the lawful
    updates pass every trigger, and no foreign key is left dangling."""
    for table in STAGE9_TABLES:
        schema_harness.plant_raw(table, dict(_BASELINE[table]))
    schema_harness.plant_raw("finalization_journal", dict(_EVIDENCE_JOURNAL_ROW))
    schema_harness.execute(
        "UPDATE candidate_artifacts SET revision = revision + 1, updated_at_utc = ? "
        "WHERE candidate_artifact_id = ?",
        (_T0 + 1, CANDIDATE_ID),
    )
    schema_harness.execute(
        "UPDATE finalization_journal SET state = 'MOVED', revision = revision + 1 "
        "WHERE finalization_id = ?",
        (_JOURNAL_ID,),
    )
    sanitized_link = (
        "UPDATE sanitized_adapter_result_manifests SET evidence_artifact_id = ? "
        "WHERE sanitized_adapter_result_manifest_hash = ?"
    )
    validation_link = (
        "UPDATE adapter_validation_results SET evidence_artifact_id = ? "
        "WHERE invocation_id = ?"
    )
    evidence = _EVIDENCE_REF.artifact_id
    schema_harness.execute(sanitized_link, (evidence, _PRESEEDED_SANITIZED_HASH))
    schema_harness.execute(validation_link, (evidence, _VALIDATE_INVOCATION_ID))
    schema_harness.execute(
        "INSERT INTO run_artifacts (run_id, artifact_id, link_role, experiment_id, "
        "run_manifest_id) VALUES (?, ?, ?, ?, ?)",
        (
            RUN_ID,
            _RESULT_REF.artifact_id,
            "RESULT_MANIFEST_MEMBER",
            EXPERIMENT_ID,
            RUN_MANIFEST_ID,
        ),
    )
    # Once linked, a second evidence link is refused on both manifest tables.
    relink = schema_harness.refuse(
        sanitized_link, (evidence, _PRESEEDED_SANITIZED_HASH)
    )
    assert relink.code == INVARIANT_VIOLATION
    assert "linked once" in relink.message
    relink = schema_harness.refuse(validation_link, (evidence, _VALIDATE_INVOCATION_ID))
    assert relink.code == INVARIANT_VIOLATION
    assert "linked once" in relink.message
    with schema_harness.database.read_only() as connection:
        assert connection.execute(text("PRAGMA foreign_key_check")).all() == []
    assert schema_harness.count("run_artifacts") == 2
    assert schema_harness.count("finalization_journal") == 2
    assert len(schema_harness.committed_refs()) == 3
    assert len(schema_harness.committed_candidates()) == 5


def test_stderr_artifact_id_targets_core_evidence_only(
    schema_harness: ArtifactHarness,
) -> None:
    """Reading 10, both halves of 23.3.1:1703: a ``RUN`` or ``VALIDATE`` invocation's
    stderr capture is ``CORE_EVIDENCE`` owned by the same run; a ``DESCRIBE``
    invocation's is owned by the describe adapter; nothing else is admitted."""
    describe = sample_invocation(
        CommandInvocationState.EXITED,
        kind=CommandKind.DESCRIBE,
        invocation_id=_DESCRIBE_INVOCATION_ID,
    )
    put_invocation(schema_harness.lifecycle(), describe)
    adapter_candidate = sample_candidate(
        "ADAPTER",
        _F.EVIDENCE,
        producer=_P.CORE,
        state=_S.FINALIZING,
        candidate_artifact_id=_NEW_CANDIDATE_ID,
        staging_relative_path=f"INVOCATION/{_DESCRIBE_INVOCATION_ID}/stderr.txt",
    )
    schema_harness.put_candidate(adapter_candidate)
    adapter_ref = sample_ref(adapter_candidate)
    schema_harness.put_ref(adapter_ref, sample_artifact_manifest(adapter_ref))
    link = (
        "UPDATE command_invocations SET stderr_artifact_id = ?, "
        "revision = revision + 1 WHERE invocation_id = ?"
    )
    refusals = (
        (_RESULT_REF.artifact_id, INVOCATION_ID),
        (adapter_ref.artifact_id, INVOCATION_ID),
        (_EVIDENCE_REF.artifact_id, _DESCRIBE_INVOCATION_ID),
        (_RESULT_REF.artifact_id, _DESCRIBE_INVOCATION_ID),
        (_UNKNOWN_ARTIFACT_ID, INVOCATION_ID),
    )
    for artifact_id, invocation_id in refusals:
        refusal = schema_harness.refuse(link, (artifact_id, invocation_id))
        assert refusal.code == INVARIANT_VIOLATION, (artifact_id, invocation_id)
        assert _STDERR in refusal.message
    # The two lawful halves: run evidence for the run and validate invocations,
    # adapter evidence for the describe invocation.
    schema_harness.execute(link, (_EVIDENCE_REF.artifact_id, INVOCATION_ID))
    schema_harness.execute(link, (_EVIDENCE_REF.artifact_id, _VALIDATE_INVOCATION_ID))
    schema_harness.execute(link, (adapter_ref.artifact_id, _DESCRIBE_INVOCATION_ID))
    with schema_harness.database.read_only() as connection:
        stored = connection.execute(
            text(
                "SELECT invocation_id, stderr_artifact_id FROM command_invocations "
                "WHERE stderr_artifact_id IS NOT NULL ORDER BY invocation_id"
            )
        ).all()
    assert sorted((str(row[0]), str(row[1])) for row in stored) == sorted(
        (
            (INVOCATION_ID, _EVIDENCE_REF.artifact_id),
            (_VALIDATE_INVOCATION_ID, _EVIDENCE_REF.artifact_id),
            (_DESCRIBE_INVOCATION_ID, adapter_ref.artifact_id),
        )
    )


def test_sanitized_manifest_row_has_no_token_or_path(
    schema_harness: ArtifactHarness,
) -> None:
    """Plan 3.3: the string CHECK on the canonical text refuses the quoted keys
    ``"attempt_token":`` and ``"relative_path":`` anywhere in the document and
    never the legitimate ``attempt_token_hash`` key."""
    base = _BASELINE["sanitized_adapter_result_manifests"]
    admitted = '{"attempt_token_hash":"' + ATTEMPT_TOKEN_HASH + '","nested":{"x":1}}'
    schema_harness.plant_raw(
        "sanitized_adapter_result_manifests", {**base, "manifest_json": admitted}
    )
    for document in (
        '{"attempt_token":"' + "t" * 16 + '"}',
        '{"outer":{"attempt_token":"x"}}',
        '{"relative_path":"results/native.bin"}',
        '{"candidates":[{"relative_path":"a.bin"}]}',
        '{"attempt_token_hash":"' + ATTEMPT_TOKEN_HASH + '","attempt_token":"x"}',
    ):
        refusal = schema_harness.refuse_insert(
            "sanitized_adapter_result_manifests",
            {
                **base,
                "sanitized_adapter_result_manifest_hash": "7" * 64,
                "source_adapter_result_manifest_hash": "8" * 64,
                "manifest_json": document,
            },
        )
        assert refusal.code == INVARIANT_VIOLATION, document
        assert "ck_sanitized_adapter_result_manifests_manifest_json" in refusal.message
    assert schema_harness.count("sanitized_adapter_result_manifests") == 2


def test_success_requires_manifest_and_manifest_requires_running(
    artifact_harness: ArtifactHarness,
) -> None:
    """Reading 11: a run reaches a success state only with a registered manifest,
    and a manifest registers only for a ``RUNNING`` run with a snapshotted
    deadline and an ``EXITED`` run-command invocation."""
    prestate = artifact_harness.seed_result_prestate(deadline=None)
    lifecycle = artifact_harness.lifecycle()
    artifact_harness.plant_raw(
        "sanitized_adapter_result_manifests", dict(_PRESEEDED_SANITIZED_ROW)
    )
    success = (
        "UPDATE engine_runs SET state = ?, revision = revision + 1 WHERE run_id = ?"
    )
    for state in ("SUCCEEDED", "SUCCEEDED_WITH_WARNINGS"):
        refusal = artifact_harness.refuse(success, (state, RUN_ID))
        assert refusal.code == INVARIANT_VIOLATION
        assert _SUCCESS_NEEDS_MANIFEST in refusal.message
    # The run is RUNNING but its deadline is not snapshotted: no manifest.
    no_deadline = artifact_harness.refuse_insert(
        "run_manifests", dict(_BASELINE["run_manifests"])
    )
    assert no_deadline.code == INVARIANT_VIOLATION
    assert _REQUIRES_RUNNING in no_deadline.message
    transaction = artifact_harness.begin()
    ok(
        transaction.result_leases.snapshot_deadline(
            prestate.run.revision, RUN_ID, DEADLINE
        )
    )
    commit(transaction)
    # A run-command invocation that has not EXITED admits no manifest.
    open_invocation = f"inv_{UUID_E}"
    put_invocation(
        lifecycle,
        sample_invocation(
            CommandInvocationState.RUNNING, invocation_id=open_invocation
        ),
    )
    not_exited = artifact_harness.refuse_insert(
        "run_manifests",
        {**_BASELINE["run_manifests"], "run_invocation_id": open_invocation},
    )
    assert not_exited.code == INVARIANT_VIOLATION
    assert _REQUIRES_RUNNING in not_exited.message
    # A run that is not RUNNING admits no manifest either.
    pending_invocation = f"inv_{UUID_D}"
    put_run(
        lifecycle,
        sample_run(EngineRunState.PENDING, run_id=OTHER_RUN_ID, logical_slot_id=SLOT_B),
    )
    put_invocation(
        lifecycle,
        sample_invocation(
            CommandInvocationState.EXITED,
            invocation_id=pending_invocation,
            run_id=OTHER_RUN_ID,
        ),
    )
    artifact_harness.plant_raw(
        "sanitized_adapter_result_manifests",
        {
            **_PRESEEDED_SANITIZED_ROW,
            "sanitized_adapter_result_manifest_hash": "8" * 64,
            "run_id": OTHER_RUN_ID,
            "run_invocation_id": pending_invocation,
        },
    )
    pending = artifact_harness.refuse_insert(
        "run_manifests",
        {
            **_BASELINE["run_manifests"],
            "manifest_id": f"rmf_{UUID_C}",
            "run_id": OTHER_RUN_ID,
            "run_invocation_id": pending_invocation,
            "sanitized_adapter_result_manifest_hash": "8" * 64,
            "run_manifest_hash": "a" * 64,
        },
    )
    assert pending.code == INVARIANT_VIOLATION
    assert _REQUIRES_RUNNING in pending.message
    # The run that is RUNNING with its deadline and an EXITED run-command
    # invocation admits the manifest, and only then its success state.
    artifact_harness.plant_raw("run_manifests", dict(_BASELINE["run_manifests"]))
    before = artifact_harness.database.consistency_report()
    assert before.success_without_manifest == 0
    artifact_harness.execute(success, ("SUCCEEDED", RUN_ID))
    after = artifact_harness.database.consistency_report()
    assert after.success_without_manifest == 0
    with artifact_harness.database.read_only() as connection:
        state = connection.execute(
            text("SELECT state FROM engine_runs WHERE run_id = :r"), {"r": RUN_ID}
        ).scalar_one()
    assert state == "SUCCEEDED"
    # The manifest is never updated or deleted once registered.
    gone = artifact_harness.refuse(
        "DELETE FROM run_manifests WHERE manifest_id = ?", (RUN_MANIFEST_ID,)
    )
    assert gone.code == INVARIANT_VIOLATION
    assert "insert-only" in gone.message


def test_restrict_everywhere(schema_harness: ArtifactHarness) -> None:
    """Plan 3.3: every Stage 9 foreign key is ``RESTRICT`` on update and delete
    (no cascade anywhere), and a referenced parent row cannot be removed."""
    expected_counts = {
        "candidate_artifacts": 2,
        "artifact_refs": 2,
        "sanitized_adapter_result_manifests": 3,
        "run_manifests": 3,
        "run_artifacts": 3,
        "finalization_journal": 2,
        "audit_events": 0,
        "adapter_validation_results": 3,
    }
    with schema_harness.database.read_only() as connection:
        for table in STAGE9_TABLES:
            rows = connection.execute(text(f"PRAGMA foreign_key_list({table})")).all()
            keys = {row._mapping["id"] for row in rows}
            assert len(keys) == expected_counts[table], table
            for row in rows:
                assert row._mapping["on_update"] == "RESTRICT", (table, row)
                assert row._mapping["on_delete"] == "RESTRICT", (table, row)
    # A FINALIZING candidate with a reference cannot be deleted (the key itself:
    # candidates carry no delete trigger), while an unreferenced one can.
    referenced = schema_harness.refuse(
        "DELETE FROM candidate_artifacts WHERE candidate_artifact_id = ?",
        (OTHER_CANDIDATE_ID,),
    )
    assert referenced.code == INVARIANT_VIOLATION
    assert _FK in referenced.message
    schema_harness.execute(
        "DELETE FROM candidate_artifacts WHERE candidate_artifact_id = ?",
        (CANDIDATE_ID,),
    )
    # A sanitized manifest referenced by the run manifest cannot be deleted.
    schema_harness.plant_raw("run_manifests", dict(_BASELINE["run_manifests"]))
    parent = schema_harness.refuse(
        "DELETE FROM sanitized_adapter_result_manifests "
        "WHERE sanitized_adapter_result_manifest_hash = ?",
        (_PRESEEDED_SANITIZED_HASH,),
    )
    assert parent.code == INVARIANT_VIOLATION
    assert _FK in parent.message
    # The Stage 8 parents refuse deletion by their own triggers before the key.
    for statement, parameters in (
        ("DELETE FROM artifact_owners WHERE owner_hash = ?", (_RUN_OWNER_HASH,)),
        ("DELETE FROM engine_runs WHERE run_id = ?", (RUN_ID,)),
        ("DELETE FROM command_invocations WHERE invocation_id = ?", (INVOCATION_ID,)),
    ):
        assert schema_harness.refuse(statement, parameters).code == INVARIANT_VIOLATION
    assert len(schema_harness.committed_candidates()) == 3
    assert _ADAPTER_OWNER_HASH != _RUN_OWNER_HASH


def test_pinned_objects_digest() -> None:
    """The reviewed ``sqlite_master`` expectation, re-pinned by Task 5 for the eight
    tables, the column, the indexes and the triggers (plan 6.6)."""
    digest = hashlib.sha256(repr(EXPECTED_SCHEMA_OBJECTS).encode("utf-8")).hexdigest()
    assert digest == _EXPECTED_OBJECTS_DIGEST, digest
    tables = {row.name for row in EXPECTED_SCHEMA_OBJECTS if row.type == "table"}
    assert set(STAGE9_TABLES) <= tables


def test_trigger_objects_realize_the_sixteen_rules(
    schema_harness: ArtifactHarness,
) -> None:
    """Plan 3.4 names sixteen rules; SQLite admits one event per trigger, so the
    three insert-only/append-only rules and the two evidence-link rules are two
    objects each: twenty-one trigger objects, every one present in the database."""
    assert len(STAGE9_TRIGGER_RULES) == 16
    assert len(STAGE9_TRIGGER_SQL) == 21
    names = [statement.split()[2] for statement in STAGE9_TRIGGER_SQL]
    by_rule: dict[str, list[str]] = {rule: [] for rule in STAGE9_TRIGGER_RULES}
    longest_first = sorted(STAGE9_TRIGGER_RULES, key=len, reverse=True)
    for name in names:
        rule = next(
            rule
            for rule in longest_first
            if name == f"trg_{rule}" or name.startswith(f"trg_{rule}_")
        )
        by_rule[rule].append(name)
    two_object_rules = {
        "artifact_refs_insert_only",
        "run_manifests_insert_only",
        "audit_events_append_only",
        "sanitized_manifest_evidence_is_run_evidence",
        "validation_result_invocation_is_validate",
    }
    for rule, objects in by_rule.items():
        assert len(objects) == (2 if rule in two_object_rules else 1), rule
    with schema_harness.database.read_only() as connection:
        stored = {
            str(name)
            for name in connection.execute(
                text("SELECT name FROM sqlite_master WHERE type = 'trigger'")
            ).scalars()
        }
    assert set(names) <= stored
    assert len(set(names)) == 21
    assert any(" BEFORE INSERT " in statement for statement in STAGE9_TRIGGER_SQL)
    assert any(" BEFORE UPDATE " in statement for statement in STAGE9_TRIGGER_SQL)
    assert any(" BEFORE DELETE " in statement for statement in STAGE9_TRIGGER_SQL)
    assert not any("CASCADE" in statement for statement in STAGE9_TRIGGER_SQL)
