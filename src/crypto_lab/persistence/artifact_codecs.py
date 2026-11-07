"""Lossless row codecs for the Stage 9 artifact, journal and audit records.

Stage 9 plan sections 3.3 and 6.6 (Task 5), the Stage 8 codec conventions of
``persistence/codecs.py`` applied to the new rows: ingress is the inverse
projection of an already-validated record (text, enum, hash and identifier
columns copied verbatim, instants as integer microseconds, booleans as ``0``/``1``,
every nested tuple a canonical-JSON snapshot column), ``NULL`` encodes exactly one
``MISSING``, and egress rebuilds a JSON-mode payload that the record re-validates
through ``model_validate_json`` over ``canonical_json_bytes`` so every invariant is
re-checked (reading 10: egress re-validates and refuses a reinterpretation).

The rows store the owner by ``owner_hash`` alone (plan 1.5 note 11: every Stage 9
table references ``artifact_owners.owner_hash`` directly); the repositories read the
owner row and pass the rebuilt ``ArtifactOwnerRef`` into the decoders, which place it
in the payload where the record expects it. The candidate's ``run_id`` and
``invocation_id`` columns are denormalized from a ``RUN`` owner for the foreign key
and are never read back into the record. The reference row carries the canonical
``ArtifactManifest`` beside the ``ArtifactRef`` (``manifest_json``,
``artifact_manifest_hash``); ``decode_artifact_manifest`` re-validates it, which
recomputes the self-hash. The journal's typed ``EvidenceCorrelation`` is flattened
to ``correlation_kind``/``correlation_id`` and rebuilt from the kind's field. The
audit actor is flattened to three columns; ``audit_sequence`` is assigned by SQLite
and is not a record field (reading 9). No codec names or stores a raw attempt
token: the journal and manifest rows carry ``attempt_token_hash`` only.

Decoders take the injected ``Clock`` as a keyword and stamp any ``Failure`` from it.
The module imports no SQLAlchemy and names the tables as literals.
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Any, Final

from crypto_lab.artifacts.journal import FinalizationJournalEntry
from crypto_lab.artifacts.manifest import ArtifactManifest
from crypto_lab.artifacts.models import ArtifactRef, CandidateArtifact
from crypto_lab.artifacts.ownership import (
    ArtifactOwnerRef,
    RunArtifactOwner,
    artifact_owner_hash,
)
from crypto_lab.audit.models import AuditEvent
from crypto_lab.domain.canonical_json import canonical_json_text
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.ports import Clock
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.persistence.codecs import (
    Payload,
    RowValues,
    _Columns,
    _dump,
    _egress,
    _put,
    utc_to_micros,
)

__all__ = [
    "decode_artifact_manifest",
    "decode_artifact_ref",
    "decode_audit_event",
    "decode_candidate_artifact",
    "decode_finalization_journal_entry",
    "egress_payload_artifact_ref",
    "egress_payload_audit_event",
    "egress_payload_candidate_artifact",
    "egress_payload_finalization_journal_entry",
    "encode_artifact_ref",
    "encode_audit_event",
    "encode_candidate_artifact",
    "encode_finalization_journal_entry",
]

#: ``EvidenceCorrelation``: the identifier field each kind carries (plan 3.1).
_CORRELATION_FIELDS: Final[dict[str, str]] = {
    "INVOCATION": "invocation_id",
    "DIAGNOSTIC": "diagnostic_id",
    "AUDIT": "audit_event_id",
}
_JOURNAL_OPTIONAL_TEXT: Final[tuple[str, ...]] = (
    "abandon_reason",
    "run_id",
    "run_invocation_id",
    "attempt_token_hash",
    "source_adapter_result_manifest_hash",
    "sanitized_adapter_result_manifest_hash",
)
_JOURNAL_OPTIONAL_INSTANT: Final[tuple[str, ...]] = ("finalization_deadline_utc",)
_JOURNAL_OPTIONAL_INTEGER: Final[tuple[str, ...]] = (
    "expected_run_revision",
    "expected_invocation_revision",
)
_AUDIT_OPTIONAL_TEXT: Final[tuple[str, ...]] = (
    "experiment_id",
    "run_id",
    "invocation_id",
    "artifact_id",
)


def _snapshot(value: object) -> str:
    return canonical_json_text(value)


def _owner_payload(owner: ArtifactOwnerRef) -> dict[str, Any]:
    return _dump(owner)


def _run_facts(owner: ArtifactOwnerRef) -> tuple[str | None, str | None]:
    """The denormalized ``run_id``/``invocation_id`` of a ``RUN`` owner (plan 3.3)."""
    if not isinstance(owner, RunArtifactOwner):
        return None, None
    invocation = owner.invocation_id
    return owner.run_id, invocation if isinstance(invocation, str) else None


# --------------------------------------------------------------------------
# candidate_artifacts
# --------------------------------------------------------------------------


def encode_candidate_artifact(record: CandidateArtifact) -> RowValues:
    """The ``candidate_artifacts`` row of one validated ``CandidateArtifact``."""
    dumped = _dump(record)
    observations = _snapshot(dumped["validation_observations"])
    run_id, invocation_id = _run_facts(record.owner)
    return {
        "candidate_artifact_id": dumped["candidate_artifact_id"],
        "schema_version": dumped["schema_version"],
        "owner_hash": artifact_owner_hash(record.owner),
        "finalization_purpose": dumped["finalization_purpose"],
        "source_role": dumped["source_role"],
        "producer_kind": dumped["producer_kind"],
        "artifact_kind": dumped["artifact_kind"],
        "staging_relative_path": dumped["staging_relative_path"],
        "state": dumped["state"],
        "adapter_declared_size": dumped.get("adapter_declared_size"),
        "adapter_declared_hash": dumped.get("adapter_declared_hash"),
        "adapter_declared_media_type": dumped.get("adapter_declared_media_type"),
        "observations_json": observations,
        "observations_hash": sha256_bytes(observations.encode("utf-8")),
        "source_event_id": dumped.get("source_event_id"),
        "source_adapter_manifest_id": dumped.get("source_adapter_manifest_id"),
        "run_id": run_id,
        "invocation_id": invocation_id,
        "created_at_utc": utc_to_micros(record.created_at_utc),
        "updated_at_utc": utc_to_micros(record.updated_at_utc),
        "revision": dumped["revision"],
    }


def egress_payload_candidate_artifact(
    row: Mapping[str, object], *, owner: ArtifactOwnerRef
) -> Payload:
    columns = _Columns(row)
    payload: Payload = {
        "schema_version": columns.text("schema_version"),
        "candidate_artifact_id": columns.text("candidate_artifact_id"),
        "owner": _owner_payload(owner),
        "finalization_purpose": columns.text("finalization_purpose"),
        "source_role": columns.text("source_role"),
        "producer_kind": columns.text("producer_kind"),
        "artifact_kind": columns.text("artifact_kind"),
        "staging_relative_path": columns.text("staging_relative_path"),
        "state": columns.text("state"),
        "validation_observations": columns.json("observations_json"),
        "created_at_utc": columns.instant("created_at_utc"),
        "updated_at_utc": columns.instant("updated_at_utc"),
        "revision": columns.integer("revision"),
    }
    _put(
        payload,
        "adapter_declared_size",
        columns.optional_integer("adapter_declared_size"),
    )
    for column in (
        "adapter_declared_hash",
        "adapter_declared_media_type",
        "source_event_id",
        "source_adapter_manifest_id",
    ):
        _put(payload, column, columns.optional_text(column))
    return payload


def decode_candidate_artifact(
    row: Mapping[str, object], *, owner: ArtifactOwnerRef, clock: Clock
) -> Result[CandidateArtifact]:
    outcome = _egress(
        table="candidate_artifacts",
        identity_column="candidate_artifact_id",
        row=row,
        build=lambda values: egress_payload_candidate_artifact(values, owner=owner),
        validate=CandidateArtifact.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    return Success[CandidateArtifact](outcome="SUCCESS", value=outcome)


# --------------------------------------------------------------------------
# artifact_refs (the reference beside its canonical manifest)
# --------------------------------------------------------------------------


def encode_artifact_ref(record: ArtifactRef, manifest: ArtifactManifest) -> RowValues:
    """The ``artifact_refs`` row of one ``ArtifactRef`` and its ``ArtifactManifest``.

    The two records describe one finalized artifact; a disagreement between them
    is a programming error and raises ``ValueError`` before any row is built.
    """
    if (
        manifest.artifact_id != record.artifact_id
        or manifest.content_hash != record.content_hash
        or manifest.size_bytes != record.size_bytes
        or manifest.source_candidate_artifact_id != record.source_candidate_artifact_id
        or manifest.owner != record.owner
        or manifest.finalization_purpose is not record.finalization_purpose
        or manifest.source_role is not record.source_role
        or manifest.producer_kind is not record.producer_kind
    ):
        raise ValueError("the manifest must describe the same finalized artifact")
    dumped = _dump(record)
    return {
        "artifact_id": dumped["artifact_id"],
        "schema_version": dumped["schema_version"],
        "owner_hash": artifact_owner_hash(record.owner),
        "finalization_purpose": dumped["finalization_purpose"],
        "source_role": dumped["source_role"],
        "producer_kind": dumped["producer_kind"],
        "artifact_kind": dumped["artifact_kind"],
        "finalized_relative_path": dumped["finalized_relative_path"],
        "content_hash": dumped["content_hash"],
        "size_bytes": dumped["size_bytes"],
        "media_type": dumped["media_type"],
        "source_candidate_artifact_id": dumped["source_candidate_artifact_id"],
        "validation_profile": dumped["validation_profile"],
        "manifest_json": _snapshot(_dump(manifest)),
        "artifact_manifest_hash": manifest.artifact_manifest_hash,
        "created_at_utc": utc_to_micros(record.created_at_utc),
        "finalized_at_utc": utc_to_micros(record.finalized_at_utc),
        "state": dumped["state"],
    }


def egress_payload_artifact_ref(
    row: Mapping[str, object], *, owner: ArtifactOwnerRef
) -> Payload:
    columns = _Columns(row)
    return {
        "schema_version": columns.text("schema_version"),
        "artifact_id": columns.text("artifact_id"),
        "owner": _owner_payload(owner),
        "finalization_purpose": columns.text("finalization_purpose"),
        "artifact_kind": columns.text("artifact_kind"),
        "finalized_relative_path": columns.text("finalized_relative_path"),
        "content_hash": columns.text("content_hash"),
        "size_bytes": columns.integer("size_bytes"),
        "media_type": columns.text("media_type"),
        "source_role": columns.text("source_role"),
        "source_candidate_artifact_id": columns.text("source_candidate_artifact_id"),
        "producer_kind": columns.text("producer_kind"),
        "validation_profile": columns.text("validation_profile"),
        "created_at_utc": columns.instant("created_at_utc"),
        "finalized_at_utc": columns.instant("finalized_at_utc"),
        "state": columns.text("state"),
    }


def decode_artifact_ref(
    row: Mapping[str, object], *, owner: ArtifactOwnerRef, clock: Clock
) -> Result[ArtifactRef]:
    outcome = _egress(
        table="artifact_refs",
        identity_column="artifact_id",
        row=row,
        build=lambda values: egress_payload_artifact_ref(values, owner=owner),
        validate=ArtifactRef.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    return Success[ArtifactRef](outcome="SUCCESS", value=outcome)


def decode_artifact_manifest(
    row: Mapping[str, object], *, clock: Clock
) -> Result[ArtifactManifest]:
    """The canonical manifest stored beside the reference, re-validated (and
    therefore self-hash-recomputed) on every read."""

    def build(values: Mapping[str, object]) -> Payload:
        columns = _Columns(values)
        manifest = columns.json_object("manifest_json")
        if manifest.get("artifact_manifest_hash") != columns.text(
            "artifact_manifest_hash"
        ):
            raise ValueError(
                "manifest_json does not carry the row's artifact_manifest_hash"
            )
        return dict(manifest)

    outcome = _egress(
        table="artifact_refs",
        identity_column="artifact_id",
        row=row,
        build=build,
        validate=ArtifactManifest.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    return Success[ArtifactManifest](outcome="SUCCESS", value=outcome)


# --------------------------------------------------------------------------
# finalization_journal
# --------------------------------------------------------------------------


def encode_finalization_journal_entry(entry: FinalizationJournalEntry) -> RowValues:
    """The ``finalization_journal`` row of one validated journal entry."""
    dumped = _dump(entry)
    correlation = dumped.get("correlation")
    deadline = entry.finalization_deadline_utc
    values: RowValues = {
        "finalization_id": dumped["finalization_id"],
        "schema_version": dumped["schema_version"],
        "finalization_purpose": dumped["finalization_purpose"],
        "owner_hash": artifact_owner_hash(entry.owner),
        "source_role": dumped["source_role"],
        "candidate_ids_json": _snapshot(dumped["candidate_artifact_ids"]),
        "candidate_set_hash": dumped["candidate_set_hash"],
        "state": dumped["state"],
        "abandon_reason": dumped.get("abandon_reason"),
        "prepared_at_utc": utc_to_micros(entry.prepared_at_utc),
        "finalization_deadline_utc": (
            utc_to_micros(deadline) if isinstance(deadline, datetime) else None
        ),
        "lease_expires_at_utc": utc_to_micros(entry.lease_expires_at_utc),
        "expected_run_revision": dumped.get("expected_run_revision"),
        "expected_invocation_revision": dumped.get("expected_invocation_revision"),
        "run_id": dumped.get("run_id"),
        "run_invocation_id": dumped.get("run_invocation_id"),
        "attempt_token_hash": dumped.get("attempt_token_hash"),
        "source_adapter_result_manifest_hash": dumped.get(
            "source_adapter_result_manifest_hash"
        ),
        "sanitized_adapter_result_manifest_hash": dumped.get(
            "sanitized_adapter_result_manifest_hash"
        ),
        "correlation_kind": None,
        "correlation_id": None,
        "planned_json": _snapshot(dumped["planned_paths"]),
        "observed_json": _snapshot(dumped["observed"]),
        "updated_at_utc": utc_to_micros(entry.updated_at_utc),
        "revision": dumped["revision"],
    }
    if isinstance(correlation, dict):
        kind = str(correlation["kind"])
        values["correlation_kind"] = kind
        values["correlation_id"] = str(correlation[_CORRELATION_FIELDS[kind]])
    return values


def egress_payload_finalization_journal_entry(
    row: Mapping[str, object], *, owner: ArtifactOwnerRef
) -> Payload:
    columns = _Columns(row)
    payload: Payload = {
        "schema_version": columns.text("schema_version"),
        "finalization_id": columns.text("finalization_id"),
        "finalization_purpose": columns.text("finalization_purpose"),
        "owner": _owner_payload(owner),
        "source_role": columns.text("source_role"),
        "candidate_artifact_ids": columns.json("candidate_ids_json"),
        "candidate_set_hash": columns.text("candidate_set_hash"),
        "state": columns.text("state"),
        "prepared_at_utc": columns.instant("prepared_at_utc"),
        "lease_expires_at_utc": columns.instant("lease_expires_at_utc"),
        "planned_paths": columns.json("planned_json"),
        "observed": columns.json("observed_json"),
        "updated_at_utc": columns.instant("updated_at_utc"),
        "revision": columns.integer("revision"),
    }
    for column in _JOURNAL_OPTIONAL_TEXT:
        _put(payload, column, columns.optional_text(column))
    for column in _JOURNAL_OPTIONAL_INSTANT:
        _put(payload, column, columns.optional_instant(column))
    for column in _JOURNAL_OPTIONAL_INTEGER:
        _put(payload, column, columns.optional_integer(column))
    kind = columns.optional_text("correlation_kind")
    identifier = columns.optional_text("correlation_id")
    if (kind is None) != (identifier is None):
        raise ValueError("correlation_kind and correlation_id are present together")
    if kind is not None and identifier is not None:
        field = _CORRELATION_FIELDS.get(kind)
        if field is None:
            raise ValueError("correlation_kind is not an evidence correlation kind")
        payload["correlation"] = {"kind": kind, field: identifier}
    return payload


def decode_finalization_journal_entry(
    row: Mapping[str, object], *, owner: ArtifactOwnerRef, clock: Clock
) -> Result[FinalizationJournalEntry]:
    outcome = _egress(
        table="finalization_journal",
        identity_column="finalization_id",
        row=row,
        build=lambda values: egress_payload_finalization_journal_entry(
            values, owner=owner
        ),
        validate=FinalizationJournalEntry.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    return Success[FinalizationJournalEntry](outcome="SUCCESS", value=outcome)


# --------------------------------------------------------------------------
# audit_events
# --------------------------------------------------------------------------


def encode_audit_event(event: AuditEvent) -> RowValues:
    """The ``audit_events`` row of one validated event; ``audit_sequence`` is
    SQLite's to assign (reading 9) and is absent here."""
    dumped = _dump(event)
    actor = dumped["actor"]
    return {
        "audit_event_id": dumped["audit_event_id"],
        "schema_version": dumped["schema_version"],
        "action": dumped["action"],
        "actor_kind": actor["kind"],
        "actor_adapter_name": actor.get("adapter_name"),
        "actor_adapter_version": actor.get("adapter_version"),
        "outcome": dumped["outcome"],
        "experiment_id": dumped.get("experiment_id"),
        "run_id": dumped.get("run_id"),
        "invocation_id": dumped.get("invocation_id"),
        "artifact_id": dumped.get("artifact_id"),
        "timestamp_utc": utc_to_micros(event.timestamp_utc),
        "correlation_id": dumped["correlation_id"],
        "details_json": _snapshot(dumped["details"]),
        "details_hash": dumped["details_hash"],
    }


def egress_payload_audit_event(row: Mapping[str, object]) -> Payload:
    columns = _Columns(row)
    actor: dict[str, object] = {"kind": columns.text("actor_kind")}
    _put(actor, "adapter_name", columns.optional_text("actor_adapter_name"))
    _put(actor, "adapter_version", columns.optional_text("actor_adapter_version"))
    payload: Payload = {
        "schema_version": columns.text("schema_version"),
        "audit_event_id": columns.text("audit_event_id"),
        "action": columns.text("action"),
        "actor": actor,
        "outcome": columns.text("outcome"),
        "timestamp_utc": columns.instant("timestamp_utc"),
        "correlation_id": columns.text("correlation_id"),
        "details_hash": columns.text("details_hash"),
        "details": columns.json_object("details_json"),
    }
    for column in _AUDIT_OPTIONAL_TEXT:
        _put(payload, column, columns.optional_text(column))
    return payload


def decode_audit_event(
    row: Mapping[str, object], *, clock: Clock
) -> Result[AuditEvent]:
    outcome = _egress(
        table="audit_events",
        identity_column="audit_event_id",
        row=row,
        build=egress_payload_audit_event,
        validate=AuditEvent.model_validate_json,
        clock=clock,
    )
    if isinstance(outcome, Failure):
        return outcome
    return Success[AuditEvent](outcome="SUCCESS", value=outcome)
