"""Stage 9 Task 1: the core-generated artifact manifest and its owner lineage
(plan 3.1 rows ``ArtifactManifest``, ``ArtifactLineage``; specification 19.4, 20.2)."""

from __future__ import annotations

import json
from typing import Any, cast

import pytest
from pydantic import JsonValue, ValidationError

from crypto_lab.artifacts.manifest import (
    ARTIFACT_VALIDATION_PROFILE,
    ArtifactLineage,
    ArtifactManifest,
    artifact_manifest_hash,
)
from crypto_lab.artifacts.models import finalized_relative_path_for
from crypto_lab.domain.hashing import HashingProfile, artifact_id_for, profile_hash

_EXP = "exp_12345678-1234-4234-8234-123456789abc"
_EXP2 = "exp_22345678-1234-4234-8234-123456789abc"
_RUN = "run_12345678-1234-4234-8234-123456789abc"
_RUN2 = "run_22345678-1234-4234-8234-123456789abc"
_INV = "inv_12345678-1234-4234-8234-123456789abc"
_INV2 = "inv_22345678-1234-4234-8234-123456789abc"
_DS = "ds_12345678-1234-4234-8234-123456789abc"
_STRV = "strv_12345678-1234-4234-8234-123456789abc"
_EVT = "evt_12345678-1234-4234-8234-123456789abc"
_AMF = "amf_12345678-1234-4234-8234-123456789abc"
_DIAG = "diag_12345678-1234-4234-8234-123456789abc"
_DIAG2 = "diag_22345678-1234-4234-8234-123456789abc"
_CAND = "cand_12345678-1234-4234-8234-123456789abc"
_CAND2 = "cand_22345678-1234-4234-8234-123456789abc"
_HASH = "a" * 64
_HASH2 = "b" * 64
_T0 = "2026-08-10T01:02:03Z"
_T1 = "2026-08-10T01:02:08Z"
_EARLIER = "2026-08-10T01:02:00Z"


def _owner(kind: str = "RUN", *, invocation: bool = True) -> dict[str, Any]:
    owners: dict[str, dict[str, Any]] = {
        "RUN": {"owner_kind": "RUN", "experiment_id": _EXP, "run_id": _RUN},
        "EXPERIMENT": {"owner_kind": "EXPERIMENT", "experiment_id": _EXP},
        "DATASET": {"owner_kind": "DATASET", "dataset_id": _DS},
        "STRATEGY": {"owner_kind": "STRATEGY", "strategy_version_id": _STRV},
        "ADAPTER": {
            "owner_kind": "ADAPTER",
            "adapter_name": "adapter.alpha",
            "adapter_version": "1.0.0",
        },
        "SYSTEM": {
            "owner_kind": "SYSTEM",
            "core_component": "artifacts",
            "correlation_id": "stage9",
        },
    }
    owner = dict(owners[kind])
    if kind == "RUN" and invocation:
        owner["invocation_id"] = _INV
    return owner


def _run_lineage(**overrides: Any) -> dict[str, Any]:
    lineage: dict[str, Any] = {
        "experiment_id": _EXP,
        "run_id": _RUN,
        "invocation_id": _INV,
        "source_event_id": _EVT,
        "source_adapter_manifest_id": _AMF,
    }
    lineage.update(overrides)
    return lineage


def _lineage_without(field: str) -> dict[str, Any]:
    return {key: value for key, value in _run_lineage().items() if key != field}


def _unhashed(**overrides: Any) -> dict[str, Any]:
    """Row 1 of 3.1.1: an adapter-produced RUN-owned RESULT manifest, hash absent."""
    payload: dict[str, Any] = {
        "schema_version": "1.0.0",
        "artifact_id": artifact_id_for(_CAND, _HASH),
        "artifact_kind": "engine-native-report",
        "media_type": "application/octet-stream",
        "finalized_relative_path": finalized_relative_path_for(_HASH),
        "size_bytes": 12,
        "content_hash": _HASH,
        "producer_kind": "ADAPTER",
        "source_candidate_artifact_id": _CAND,
        "owner": _owner(),
        "finalization_purpose": "RESULT",
        "source_role": "ENGINE_NATIVE_RESULT",
        "lineage": _run_lineage(),
        "validation_profile": "artifact-validation/v1",
        "validation_diagnostic_ids": [],
        "created_at_utc": _T0,
        "finalized_at_utc": _T1,
    }
    payload.update(overrides)
    return payload


def _hashed(payload: dict[str, Any]) -> dict[str, Any]:
    content = {
        key: value for key, value in payload.items() if key != "artifact_manifest_hash"
    }
    return {
        **payload,
        "artifact_manifest_hash": profile_hash(
            HashingProfile.ARTIFACT_MANIFEST_V1, cast("dict[str, JsonValue]", content)
        ),
    }


def _manifest(**overrides: Any) -> dict[str, Any]:
    return _hashed(_unhashed(**overrides))


def _evidence_manifest(kind: str, role: str, lineage: dict[str, Any]) -> dict[str, Any]:
    return _manifest(
        owner=_owner(kind),
        finalization_purpose="EVIDENCE",
        source_role=role,
        producer_kind="CORE",
        artifact_kind="core-evidence",
        lineage=lineage,
    )


def _load(payload: dict[str, Any]) -> ArtifactManifest:
    return ArtifactManifest.model_validate_json(json.dumps(payload))


def _rejects(payload: dict[str, Any], match: str | None = None) -> None:
    with pytest.raises(ValidationError, match=match):
        _load(payload)


def test_manifest_fields_and_owner_lineage() -> None:
    """The six owner variants, each with exactly its lineage (19.4:1421, 20.2:1456)."""
    run = _load(_manifest())
    assert run.lineage.run_id == _RUN
    assert not isinstance(run.lineage.source_hash, str)
    variants = {
        "RUN": (
            "CORE_EVIDENCE",
            {"experiment_id": _EXP, "run_id": _RUN, "invocation_id": _INV},
        ),
        "SYSTEM": ("CORE_EVIDENCE", {}),
        "ADAPTER": ("ADAPTER_DESCRIPTOR_EVIDENCE", {}),
        "EXPERIMENT": ("EXPERIMENT_INPUT", {"source_hash": _HASH2}),
        "DATASET": ("DATASET_INPUT", {"source_hash": _HASH2}),
        "STRATEGY": ("STRATEGY_INPUT", {"source_hash": _HASH2}),
    }
    for kind, (role, lineage) in variants.items():
        manifest = _load(_evidence_manifest(kind, role, lineage))
        assert manifest.owner.owner_kind == kind
        assert not isinstance(manifest.lineage.source_event_id, str)
        assert not isinstance(manifest.lineage.source_adapter_manifest_id, str)
    assert len(variants) == 6
    # RUN lineage equals the owner's identities and nothing else carries them.
    _rejects(_manifest(lineage=_run_lineage(experiment_id=_EXP2)), "experiment_id")
    _rejects(_manifest(lineage=_run_lineage(run_id=_RUN2)), "run_id")
    _rejects(_manifest(lineage=_run_lineage(invocation_id=_INV2)), "invocation_id")
    without_invocation = _manifest(
        owner=_owner(invocation=False),
        finalization_purpose="EVIDENCE",
        source_role="CORE_EVIDENCE",
        producer_kind="CORE",
        lineage={"experiment_id": _EXP, "run_id": _RUN},
    )
    assert not isinstance(_load(without_invocation).lineage.invocation_id, str)
    run_lineage = {"experiment_id": _EXP, "run_id": _RUN, "invocation_id": _INV}
    _rejects(
        _hashed({**without_invocation, "lineage": run_lineage}),
        "invocation_id",
    )
    for field in ("experiment_id", "run_id"):
        _rejects(_manifest(lineage=_lineage_without(field)))
    for kind in ("SYSTEM", "ADAPTER", "EXPERIMENT", "DATASET", "STRATEGY"):
        role, lineage = variants[kind]
        for field, value in (
            ("experiment_id", _EXP),
            ("run_id", _RUN),
            ("invocation_id", _INV),
            ("source_event_id", _EVT),
            ("source_adapter_manifest_id", _AMF),
        ):
            _rejects(_evidence_manifest(kind, role, {**lineage, field: value}))
    # The input snapshots carry the registry fact hash; the others never do.
    for kind in ("EXPERIMENT", "DATASET", "STRATEGY"):
        _rejects(_evidence_manifest(kind, variants[kind][0], {}), "source_hash")
    for kind in ("RUN", "SYSTEM", "ADAPTER"):
        role, lineage = variants[kind]
        _rejects(_evidence_manifest(kind, role, {**lineage, "source_hash": _HASH2}))
    # Adapter provenance belongs to the ADAPTER producer alone.
    _rejects(_manifest(lineage=_run_lineage(source_adapter_manifest_id=None)))
    _rejects(
        _manifest(lineage=_lineage_without("source_adapter_manifest_id")),
        "source_adapter_manifest_id",
    )
    no_event = _load(_manifest(lineage=_lineage_without("source_event_id")))
    assert not isinstance(no_event.lineage.source_event_id, str)
    _rejects(
        _evidence_manifest(
            "RUN", "CORE_EVIDENCE", {**run_lineage, "source_event_id": _EVT}
        ),
        "CORE",
    )


def test_self_hash_omitted_by_named_profile() -> None:
    manifest = _load(_manifest())
    recomputed = artifact_manifest_hash(manifest)
    assert recomputed == manifest.artifact_manifest_hash
    content = json.loads(manifest.model_dump_json())
    del content["artifact_manifest_hash"]
    assert recomputed == profile_hash(HashingProfile.ARTIFACT_MANIFEST_V1, content)
    assert recomputed != profile_hash(HashingProfile.ARTIFACT_IDENTITY_V1, content)
    _rejects(_unhashed(artifact_manifest_hash=_HASH2), "artifact_manifest_hash")
    # Every field is hash material: a changed field keeps the old hash out.
    stale = _manifest()
    changed = {**stale, "size_bytes": 13}
    _rejects(changed, "artifact_manifest_hash")
    assert _load(_hashed(changed)).size_bytes == 13
    with pytest.raises(TypeError, match="ArtifactManifest"):
        artifact_manifest_hash("manifest")  # type: ignore[arg-type]


def test_staging_path_never_in_finalized_field() -> None:
    for path in (
        "results/native.bin",
        f"INVOCATION/{_INV}/stderr.txt",
        f"objects/ab/{_HASH}",
        f"objects/aa/{_HASH}/extra",
        f"objects/aa/{_HASH2}",
        f"objects/{_HASH}",
        "",
    ):
        _rejects(_manifest(finalized_relative_path=path))
    assert _load(_manifest()).finalized_relative_path == f"objects/aa/{_HASH}"
    _rejects(_manifest(content_hash=_HASH2))
    _rejects(_manifest(artifact_id=artifact_id_for(_CAND2, _HASH)), "artifact_id")
    _rejects(_manifest(finalized_at_utc=_EARLIER), "finalized_at_utc")
    _rejects(_manifest(validation_profile="artifact-validation/v2"))
    assert ARTIFACT_VALIDATION_PROFILE == "artifact-validation/v1"


def test_correction_links_superseded_artifact() -> None:
    superseded = artifact_id_for(_CAND2, _HASH2)
    manifest = _load(_manifest(lineage=_run_lineage(superseded_artifact_id=superseded)))
    assert manifest.lineage.superseded_artifact_id == superseded
    own_id = artifact_id_for(_CAND, _HASH)
    _rejects(
        _manifest(lineage=_run_lineage(superseded_artifact_id=own_id)), "supersede"
    )
    _rejects(_manifest(lineage=_run_lineage(superseded_artifact_id=None)))
    _rejects(_manifest(lineage=_run_lineage(unexpected=1)), "extra")
    _rejects(_manifest(unexpected=1), "extra")
    with pytest.raises(ValidationError):
        ArtifactLineage.model_validate_json(json.dumps({"run_id": None}))


def test_validation_diagnostic_ids_and_role_table() -> None:
    assert _load(
        _manifest(validation_diagnostic_ids=[_DIAG, _DIAG2])
    ).validation_diagnostic_ids == (_DIAG, _DIAG2)
    _rejects(_manifest(validation_diagnostic_ids=[_DIAG2, _DIAG]), "sorted")
    _rejects(_manifest(validation_diagnostic_ids=[_DIAG, _DIAG]), "unique")
    _rejects(_manifest(finalization_purpose="EVIDENCE"))
    _rejects(_manifest(source_role="CORE_EVIDENCE"))
    _rejects(_manifest(owner=_owner("SYSTEM")))
    _rejects(_manifest(owner=_owner(invocation=False)), "invocation")
    _rejects(_evidence_manifest("DATASET", "CORE_EVIDENCE", {"source_hash": _HASH2}))
    _rejects(_manifest(size_bytes=-1))
    _rejects(_manifest(media_type="x"))
