"""The six Stage 9 repositories over one transaction's connection (plan 4.1, Task 5).

``SqliteCandidateArtifactRepository``, ``SqliteArtifactRepository`` and
``SqliteFinalizationJournalRepository`` carry the record-typed members the Task 6
``CandidateArtifactRepository``, ``ArtifactRepository`` and
``FinalizationJournalRepository`` ports name, with the Stage 8 section 4.3.1 order
verbatim: pre-read, a missing identity is ``CORE.INVARIANT_VIOLATION`` containing
``does not exist``, a stale revision is ``PERSISTENCE.CONCURRENCY_CONFLICT``, a
wrong replacement step or a refused domain transition is the invariant, and a
conditional update whose row count is zero is the conflict. Every record read is
re-validated on egress through the Stage 9 codecs with its owner rebuilt from
``artifact_owners`` (reading 10; the egress refuses a reinterpretation). The
reference repository is the only writer of ``artifact_refs``: the registrar stages
each ``(ArtifactRef, ArtifactManifest)`` pair on the transaction with
``stage_reference`` and ``record_finalization(result)`` inserts exactly the staged
pairs the result's mappings name, validating every mapping before its first
insert -- staged, restating its mapping, carrying the result's owner and purpose,
sourced from a ``FINALIZING`` candidate -- so a refusal at a later mapping inserts
nothing (the table trigger refuses a non-``FINALIZING`` source the same way, so
the repository answer is the invariant and never a raised error).
``list_recoverable`` excludes a ``FINALIZING`` candidate that already has a
reference (plan RV-12, 19.1:1358).

``SqliteRunManifestRepository``, ``SqliteSanitizedManifestRepository``,
``SqliteValidationResultRepository`` and ``SqliteRunArtifactRepository`` are typed
over domain-typed facts (identifiers, hashes, canonical text, instants), never
over ``RunManifest``, ``ManifestParse`` or ``experiments`` types, so the
persistence layer stays importable by the artifact finalizer's unit of work
without reaching ``experiments`` (plan 4.1). Their write boundaries (``add``,
``link``) consume the read-only structural interfaces ``RunManifestFactsView``,
``SanitizedManifestFactsView``, ``ValidationResultFactsView`` and
``RunArtifactLinkView``, so a caller's facts type satisfies them by shape and
never by inheriting a persistence type; the frozen dataclasses
``RunManifestFacts``, ``SanitizedManifestFacts``, ``ValidationResultFacts`` and
``RunArtifactLink`` are the repositories' own values of those shapes (what ``get``
and ``list_for_run`` answer). Rows are insert-only or write-once (the evidence
link), exactly as the Stage 9 triggers enforce.

No repository here names a raw attempt token: the journal and manifest rows carry
``attempt_token_hash`` alone.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Final, Protocol

from pydantic import BaseModel, InstanceOf
from pydantic.experimental.missing_sentinel import MISSING
from sqlalchemy import insert, select, update
from sqlalchemy.engine import Connection, RowMapping
from sqlalchemy.exc import DBAPIError

from crypto_lab.artifacts.journal import (
    FinalizationJournalEntry,
    FinalizationJournalRuleViolation,
    FinalizationJournalState,
    assert_journal_transition,
)
from crypto_lab.artifacts.manifest import ArtifactManifest
from crypto_lab.artifacts.models import (
    ArtifactFinalizationPurpose,
    ArtifactRef,
    CandidateArtifact,
    CandidateArtifactRuleViolation,
    CandidateArtifactState,
    CandidateFinalization,
    FinalizationResult,
    assert_candidate_transition,
)
from crypto_lab.artifacts.ownership import ArtifactOwnerRef, artifact_owner_hash
from crypto_lab.domain.identifiers import (
    ArtifactId,
    CandidateArtifactId,
    ExperimentId,
    FinalizationId,
    InvocationId,
    RunId,
    RunManifestId,
    Sha256,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.persistence.artifact_codecs import (
    decode_artifact_manifest,
    decode_artifact_ref,
    decode_candidate_artifact,
    decode_finalization_journal_entry,
    encode_artifact_ref,
    encode_candidate_artifact,
    encode_finalization_journal_entry,
)
from crypto_lab.persistence.codecs import micros_to_utc_text, utc_to_micros
from crypto_lab.persistence.registries import SqliteArtifactOwnerRegistry
from crypto_lab.persistence.repositories import TransactionScope, _revision_refusal
from crypto_lab.persistence.schema import (
    RUN_ARTIFACT_LINK_ROLES,
    AdapterValidationResultRow,
    ArtifactRefRow,
    CandidateArtifactRow,
    FinalizationJournalRow,
    RunArtifactRow,
    RunManifestRow,
    SanitizedAdapterResultManifestRow,
)

__all__ = [
    "RunArtifactLink",
    "RunArtifactLinkView",
    "RunManifestFacts",
    "RunManifestFactsView",
    "SanitizedManifestFacts",
    "SanitizedManifestFactsView",
    "SqliteArtifactRepository",
    "SqliteCandidateArtifactRepository",
    "SqliteFinalizationJournalRepository",
    "SqliteRunArtifactRepository",
    "SqliteRunManifestRepository",
    "SqliteSanitizedManifestRepository",
    "SqliteValidationResultRepository",
    "ValidationResultFacts",
    "ValidationResultFactsView",
]

_MAX_LISTING: Final = 1024
_OPEN_JOURNAL_STATES: Final = (
    FinalizationJournalState.PREPARED.value,
    FinalizationJournalState.MOVED.value,
)
#: The long primary-key column of the sanitized manifest table, named once.
_SANITIZED_HASH: Final = (
    SanitizedAdapterResultManifestRow.sanitized_adapter_result_manifest_hash
)


def _values(row: RowMapping) -> dict[str, object]:
    return {str(key): value for key, value in row.items()}


def _none() -> Success[None]:
    return Success[None](outcome="SUCCESS", value=None)


def _absent() -> Success[Any]:
    nothing: Any = MISSING
    return Success(outcome="SUCCESS", value=nothing)


def _instant(value: object) -> datetime:
    return datetime.fromisoformat(micros_to_utc_text(int(str(value))))


def _optional_text(value: object) -> str | MISSING:  # type: ignore[valid-type]
    return value if isinstance(value, str) else MISSING


# --------------------------------------------------------------------------
# Domain-typed facts of the four registration tables (plan 4.1)
# --------------------------------------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class RunManifestFacts:
    """One ``run_manifests`` row: the manifest's identities, hashes and canonical
    text; never the ``RunManifest`` record itself (``experiments`` owns it)."""

    manifest_id: RunManifestId
    run_id: RunId
    experiment_id: ExperimentId
    run_invocation_id: InvocationId
    attempt_token_hash: Sha256
    sanitized_adapter_result_manifest_hash: Sha256
    semantic_status: str
    process_exit_category: str
    manifest_json: str
    run_manifest_hash: Sha256
    registered_at_utc: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class SanitizedManifestFacts:
    """One ``sanitized_adapter_result_manifests`` row (plan 3.3)."""

    sanitized_adapter_result_manifest_hash: Sha256
    run_id: RunId
    run_invocation_id: InvocationId
    experiment_id: ExperimentId
    attempt_token_hash: Sha256
    source_adapter_result_manifest_hash: Sha256
    semantic_status: str
    manifest_json: str
    evidence_artifact_id: ArtifactId | MISSING  # type: ignore[valid-type]
    recorded_at_utc: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class ValidationResultFacts:
    """One ``adapter_validation_results`` row (plan 3.3, reading 8)."""

    invocation_id: InvocationId
    run_id: RunId
    experiment_id: ExperimentId
    validation_result_hash: Sha256
    outcome: str
    result_json: str
    evidence_artifact_id: ArtifactId | MISSING  # type: ignore[valid-type]
    recorded_at_utc: datetime


@dataclass(frozen=True, slots=True, kw_only=True)
class RunArtifactLink:
    """One ``run_artifacts`` row: a ``RUN``-owned reference linked to its run."""

    run_id: RunId
    artifact_id: ArtifactId
    link_role: str
    experiment_id: ExperimentId
    run_manifest_id: RunManifestId | MISSING  # type: ignore[valid-type]


# --------------------------------------------------------------------------
# The read-only facts interfaces the registration boundaries consume (plan 4.1)
# --------------------------------------------------------------------------
#
# ``add`` and ``link`` are typed over these structural, read-only shapes rather
# than over the dataclasses above, so a caller's facts type satisfies the boundary
# by shape and never by inheriting a persistence type. The dataclasses satisfy
# the same shapes and remain the repositories' own answer values.


class RunManifestFactsView(Protocol):
    """The read-only facts of one ``run_manifests`` row, as ``add`` consumes them."""

    @property
    def manifest_id(self) -> RunManifestId: ...

    @property
    def run_id(self) -> RunId: ...

    @property
    def experiment_id(self) -> ExperimentId: ...

    @property
    def run_invocation_id(self) -> InvocationId: ...

    @property
    def attempt_token_hash(self) -> Sha256: ...

    @property
    def sanitized_adapter_result_manifest_hash(self) -> Sha256: ...

    @property
    def semantic_status(self) -> str: ...

    @property
    def process_exit_category(self) -> str: ...

    @property
    def manifest_json(self) -> str: ...

    @property
    def run_manifest_hash(self) -> Sha256: ...

    @property
    def registered_at_utc(self) -> datetime: ...


class SanitizedManifestFactsView(Protocol):
    """The read-only facts of one ``sanitized_adapter_result_manifests`` row."""

    @property
    def sanitized_adapter_result_manifest_hash(self) -> Sha256: ...

    @property
    def run_id(self) -> RunId: ...

    @property
    def run_invocation_id(self) -> InvocationId: ...

    @property
    def experiment_id(self) -> ExperimentId: ...

    @property
    def attempt_token_hash(self) -> Sha256: ...

    @property
    def source_adapter_result_manifest_hash(self) -> Sha256: ...

    @property
    def semantic_status(self) -> str: ...

    @property
    def manifest_json(self) -> str: ...

    @property
    def evidence_artifact_id(self) -> ArtifactId | MISSING: ...  # type: ignore[valid-type]

    @property
    def recorded_at_utc(self) -> datetime: ...


class ValidationResultFactsView(Protocol):
    """The read-only facts of one ``adapter_validation_results`` row."""

    @property
    def invocation_id(self) -> InvocationId: ...

    @property
    def run_id(self) -> RunId: ...

    @property
    def experiment_id(self) -> ExperimentId: ...

    @property
    def validation_result_hash(self) -> Sha256: ...

    @property
    def outcome(self) -> str: ...

    @property
    def result_json(self) -> str: ...

    @property
    def evidence_artifact_id(self) -> ArtifactId | MISSING: ...  # type: ignore[valid-type]

    @property
    def recorded_at_utc(self) -> datetime: ...


class RunArtifactLinkView(Protocol):
    """The read-only facts of one ``run_artifacts`` row, as ``link`` consumes them."""

    @property
    def run_id(self) -> RunId: ...

    @property
    def artifact_id(self) -> ArtifactId: ...

    @property
    def link_role(self) -> str: ...

    @property
    def experiment_id(self) -> ExperimentId: ...

    @property
    def run_manifest_id(self) -> RunManifestId | MISSING: ...  # type: ignore[valid-type]


def _staged_mismatch(
    result: FinalizationResult, mapping: CandidateFinalization, ref: ArtifactRef
) -> str | None:
    """Why the staged ``ref`` may not be recorded for ``mapping`` of ``result``,
    or ``None``: it must restate the mapping's candidate, content hash and size,
    and carry the finalization's owner and purpose (plan 4.1: the registrar
    records the references of one finalization, never another owner's or
    another purpose's)."""
    subject = f"artifact {mapping.artifact_id}"
    if (
        ref.source_candidate_artifact_id != mapping.candidate_artifact_id
        or ref.content_hash != mapping.content_hash
        or ref.size_bytes != mapping.size_bytes
    ):
        return f"{subject} does not match its mapping"
    if artifact_owner_hash(ref.owner) != artifact_owner_hash(result.owner):
        return f"{subject} does not carry the finalization's owner"
    if ref.finalization_purpose is not result.finalization_purpose:
        return f"{subject} does not carry the finalization's purpose"
    return None


def _owner(
    connection: Connection, scope: TransactionScope, owner_hash: str
) -> Result[ArtifactOwnerRef]:
    """The owner row rebuilt for one record read (reading 10).

    The registry classifies its own refusal without a scope to store it in, so the
    result passes through ``absorb``: an I/O-class refusal at the owner read
    logically fails the transaction exactly as a refusal at the record's own
    statement does (Stage 8 reading 3, the ``_GuardedArtifactOwners`` precedent);
    a missing or torn owner row is the invariant and passes through unchanged.
    """
    return scope.absorb(
        SqliteArtifactOwnerRegistry(connection, clock=scope.clock).get(owner_hash)
    )


# --------------------------------------------------------------------------
# candidate_artifacts
# --------------------------------------------------------------------------


class SqliteCandidateArtifactRepository:
    """The candidate lifecycle repository (plan 4.1)."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def get(
        self, candidate_artifact_id: CandidateArtifactId
    ) -> Result[CandidateArtifact]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            row = (
                opened.execute(
                    select(CandidateArtifactRow).where(
                        CandidateArtifactRow.candidate_artifact_id
                        == candidate_artifact_id
                    )
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="candidate_artifacts",
                operation="get",
                identity=candidate_artifact_id,
            )
        if row is None:
            return self._scope.missing(
                "candidate artifact", candidate_artifact_id, table="candidate_artifacts"
            )
        return self._decode(opened, row)

    def _decode(self, opened: Connection, row: RowMapping) -> Result[CandidateArtifact]:
        owner = _owner(opened, self._scope, str(row["owner_hash"]))
        if isinstance(owner, Failure):
            return owner
        return decode_candidate_artifact(
            _values(row), owner=owner.value, clock=self._scope.clock
        )

    def add(self, record: CandidateArtifact) -> Result[None]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        if not isinstance(record, CandidateArtifact):
            # Plan 3.5: a reference offered as a candidate is refused at the
            # boundary as the invariant, never raised by the codec.
            return self._scope.invariant(
                "the candidate repository stores CandidateArtifact records only",
                table="candidate_artifacts",
                operation="add",
                identity=str(getattr(record, "candidate_artifact_id", "*")),
            )
        try:
            opened.execute(
                insert(CandidateArtifactRow).values(**encode_candidate_artifact(record))
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="candidate_artifacts",
                operation="add",
                identity=record.candidate_artifact_id,
            )
        return _none()

    def compare_and_swap(
        self,
        expected_revision: int,
        replacement: CandidateArtifact,
        *,
        registered_mapping: CandidateFinalization | MISSING = MISSING,  # type: ignore[valid-type]
    ) -> Result[CandidateArtifact]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        identity = replacement.candidate_artifact_id
        try:
            row = (
                opened.execute(
                    select(CandidateArtifactRow).where(
                        CandidateArtifactRow.candidate_artifact_id == identity
                    )
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="candidate_artifacts",
                operation="compare_and_swap",
                identity=identity,
            )
        refusal = _revision_refusal(
            self._scope,
            row,
            expected_revision=expected_revision,
            replacement_revision=replacement.revision,
            kind="candidate artifact",
            table="candidate_artifacts",
            identity=identity,
        )
        if refusal is not None:
            return refusal
        assert row is not None  # noqa: S101 - narrowed by _revision_refusal
        stored = self._decode(opened, row)
        if isinstance(stored, Failure):
            return stored
        try:
            assert_candidate_transition(
                stored.value, replacement, registered_mapping=registered_mapping
            )
        except CandidateArtifactRuleViolation as violation:
            return self._scope.invariant(
                str(violation),
                table="candidate_artifacts",
                operation="compare_and_swap",
                identity=identity,
            )
        try:
            outcome = opened.execute(
                update(CandidateArtifactRow)
                .where(
                    CandidateArtifactRow.candidate_artifact_id == identity,
                    CandidateArtifactRow.revision == expected_revision,
                )
                .values(**encode_candidate_artifact(replacement))
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="candidate_artifacts",
                operation="compare_and_swap",
                identity=identity,
            )
        if outcome.rowcount != 1:
            return self._scope.conflict(
                f"candidate artifact {identity} was not updated at revision "
                f"{expected_revision}",
                table="candidate_artifacts",
                operation="compare_and_swap",
                identity=identity,
            )
        return Success[CandidateArtifact](outcome="SUCCESS", value=replacement)

    def list_recoverable(
        self,
        states: Sequence[CandidateArtifactState],
        owner: ArtifactOwnerRef | MISSING = MISSING,  # type: ignore[valid-type]
        purpose: ArtifactFinalizationPurpose | MISSING = MISSING,  # type: ignore[valid-type]
        limit: int = _MAX_LISTING,
    ) -> Result[tuple[CandidateArtifact, ...]]:
        """Candidates in ``states`` for the optional owner and purpose, excluding a
        ``FINALIZING`` candidate that already has a reference (RV-12)."""
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        statement = (
            select(CandidateArtifactRow)
            .where(CandidateArtifactRow.state.in_([state.value for state in states]))
            .where(
                ~CandidateArtifactRow.candidate_artifact_id.in_(
                    select(ArtifactRefRow.source_candidate_artifact_id)
                )
            )
            .order_by(CandidateArtifactRow.candidate_artifact_id)
            .limit(limit)
        )
        if isinstance(owner, BaseModel):
            statement = statement.where(
                CandidateArtifactRow.owner_hash == artifact_owner_hash(owner)
            )
        if isinstance(purpose, ArtifactFinalizationPurpose):
            statement = statement.where(
                CandidateArtifactRow.finalization_purpose == purpose.value
            )
        try:
            rows = opened.execute(statement).mappings().all()
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="candidate_artifacts",
                operation="list_recoverable",
                identity="*",
            )
        decoded: list[CandidateArtifact] = []
        for row in rows:
            item = self._decode(opened, row)
            if isinstance(item, Failure):
                return item
            decoded.append(item.value)
        return Success[tuple[CandidateArtifact, ...]](
            outcome="SUCCESS", value=tuple(decoded)
        )


# --------------------------------------------------------------------------
# artifact_refs
# --------------------------------------------------------------------------


class SqliteArtifactRepository:
    """The finalized-reference repository: the only writer of ``artifact_refs``."""

    __slots__ = ("_scope", "_staged")

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope
        self._staged: dict[str, tuple[ArtifactRef, ArtifactManifest]] = {}

    def get(self, artifact_id: ArtifactId) -> Result[ArtifactRef]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            row = (
                opened.execute(
                    select(ArtifactRefRow).where(
                        ArtifactRefRow.artifact_id == artifact_id
                    )
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error, table="artifact_refs", operation="get", identity=artifact_id
            )
        if row is None:
            return self._scope.missing("artifact", artifact_id, table="artifact_refs")
        return self._decode(opened, row)

    def get_manifest(self, artifact_id: ArtifactId) -> Result[ArtifactManifest]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            row = (
                opened.execute(
                    select(ArtifactRefRow).where(
                        ArtifactRefRow.artifact_id == artifact_id
                    )
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="artifact_refs",
                operation="get_manifest",
                identity=artifact_id,
            )
        if row is None:
            return self._scope.missing("artifact", artifact_id, table="artifact_refs")
        return decode_artifact_manifest(_values(row), clock=self._scope.clock)

    def _decode(self, opened: Connection, row: RowMapping) -> Result[ArtifactRef]:
        owner = _owner(opened, self._scope, str(row["owner_hash"]))
        if isinstance(owner, Failure):
            return owner
        return decode_artifact_ref(
            _values(row), owner=owner.value, clock=self._scope.clock
        )

    def list_by_owner(
        self,
        owner: ArtifactOwnerRef,
        purpose: ArtifactFinalizationPurpose | MISSING = MISSING,  # type: ignore[valid-type]
    ) -> Result[tuple[ArtifactRef, ...]]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        owner_hash = artifact_owner_hash(owner)
        statement = (
            select(ArtifactRefRow)
            .where(ArtifactRefRow.owner_hash == owner_hash)
            .order_by(ArtifactRefRow.artifact_id)
        )
        if isinstance(purpose, ArtifactFinalizationPurpose):
            statement = statement.where(
                ArtifactRefRow.finalization_purpose == purpose.value
            )
        try:
            rows = opened.execute(statement).mappings().all()
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="artifact_refs",
                operation="list_by_owner",
                identity=owner_hash,
            )
        decoded: list[ArtifactRef] = []
        for row in rows:
            item = self._decode(opened, row)
            if isinstance(item, Failure):
                return item
            decoded.append(item.value)
        return Success[tuple[ArtifactRef, ...]](outcome="SUCCESS", value=tuple(decoded))

    def stage_reference(
        self, ref: ArtifactRef, manifest: ArtifactManifest
    ) -> Result[None]:
        """Stage one reference and its manifest for ``record_finalization``.

        A payload of another record type -- a candidate offered as a reference --
        is refused at this boundary as the invariant (plan 3.5: the two shapes
        never inhabit each other's repository), never raised.
        """
        if not isinstance(ref, ArtifactRef) or not isinstance(
            manifest, ArtifactManifest
        ):
            return self._scope.invariant(
                "the reference repository stages ArtifactRef records beside their "
                "ArtifactManifest only",
                table="artifact_refs",
                operation="stage_reference",
                identity=str(getattr(ref, "artifact_id", "*")),
            )
        try:
            encode_artifact_ref(ref, manifest)
        except ValueError as error:
            return self._scope.invariant(
                str(error),
                table="artifact_refs",
                operation="stage_reference",
                identity=ref.artifact_id,
            )
        self._staged[ref.artifact_id] = (ref, manifest)
        return _none()

    def record_finalization(
        self, result: FinalizationResult
    ) -> Result[tuple[ArtifactRef, ...]]:
        """Insert exactly the staged references the result's mappings name.

        Two phases. Every mapping is validated first -- staged on this
        transaction, restating its mapping, carrying the finalization's owner
        and purpose, and sourced from a ``FINALIZING`` candidate -- so a refusal
        at a later mapping issues no insert and the batch is recorded whole or
        not at all; the validated pairs are then inserted in mapping order. A
        statement the database refuses in either phase is the classified
        failure (the I/O class closes the transaction), exactly as before.
        """
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        identity = result.finalization_id
        validated: list[tuple[ArtifactRef, ArtifactManifest]] = []
        for mapping in result.candidate_to_artifact_refs:
            staged = self._staged.get(mapping.artifact_id)
            if staged is None:
                return self._refusal(
                    f"artifact {mapping.artifact_id} was not staged on this "
                    "transaction",
                    identity,
                )
            mismatch = _staged_mismatch(result, mapping, staged[0])
            if mismatch is not None:
                return self._refusal(mismatch, identity)
            try:
                state = opened.execute(
                    select(CandidateArtifactRow.state).where(
                        CandidateArtifactRow.candidate_artifact_id
                        == mapping.candidate_artifact_id
                    )
                ).scalar_one_or_none()
            except DBAPIError as error:
                return self._scope.refused(
                    error,
                    table="artifact_refs",
                    operation="record_finalization",
                    identity=identity,
                )
            if state != CandidateArtifactState.FINALIZING.value:
                return self._refusal(
                    f"candidate artifact {mapping.candidate_artifact_id} is not "
                    "FINALIZING",
                    identity,
                )
            validated.append(staged)
        inserted: list[ArtifactRef] = []
        for ref, manifest in validated:
            try:
                opened.execute(
                    insert(ArtifactRefRow).values(**encode_artifact_ref(ref, manifest))
                )
            except DBAPIError as error:
                return self._scope.refused(
                    error,
                    table="artifact_refs",
                    operation="record_finalization",
                    identity=identity,
                )
            inserted.append(ref)
        for ref in inserted:
            del self._staged[ref.artifact_id]
        return Success[tuple[ArtifactRef, ...]](
            outcome="SUCCESS", value=tuple(inserted)
        )

    def _refusal(self, message: str, identity: str) -> Failure:
        """A validation refusal of ``record_finalization``: the invariant."""
        return self._scope.invariant(
            message,
            table="artifact_refs",
            operation="record_finalization",
            identity=identity,
        )


# --------------------------------------------------------------------------
# finalization_journal
# --------------------------------------------------------------------------


class SqliteFinalizationJournalRepository:
    """The purpose-discriminated journal repository (plan 4.1, 4.3)."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def get(self, finalization_id: FinalizationId) -> Result[FinalizationJournalEntry]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            row = (
                opened.execute(
                    select(FinalizationJournalRow).where(
                        FinalizationJournalRow.finalization_id == finalization_id
                    )
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="finalization_journal",
                operation="get",
                identity=finalization_id,
            )
        if row is None:
            return self._scope.missing(
                "finalization", finalization_id, table="finalization_journal"
            )
        return self._decode(opened, row)

    def _decode(
        self, opened: Connection, row: RowMapping
    ) -> Result[FinalizationJournalEntry]:
        owner = _owner(opened, self._scope, str(row["owner_hash"]))
        if isinstance(owner, Failure):
            return owner
        return decode_finalization_journal_entry(
            _values(row), owner=owner.value, clock=self._scope.clock
        )

    def prepare(self, entry: FinalizationJournalEntry) -> Result[None]:
        """The ``PREPARED`` insert; any other state is the invariant."""
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        if entry.state is not FinalizationJournalState.PREPARED:
            return self._scope.invariant(
                f"finalization {entry.finalization_id} must be prepared in state "
                f"PREPARED, not {entry.state.value}",
                table="finalization_journal",
                operation="prepare",
                identity=entry.finalization_id,
            )
        try:
            opened.execute(
                insert(FinalizationJournalRow).values(
                    **encode_finalization_journal_entry(entry)
                )
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="finalization_journal",
                operation="prepare",
                identity=entry.finalization_id,
            )
        return _none()

    def compare_and_swap(
        self, expected_revision: int, replacement: FinalizationJournalEntry
    ) -> Result[FinalizationJournalEntry]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        identity = replacement.finalization_id
        try:
            row = (
                opened.execute(
                    select(FinalizationJournalRow).where(
                        FinalizationJournalRow.finalization_id == identity
                    )
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="finalization_journal",
                operation="compare_and_swap",
                identity=identity,
            )
        refusal = _revision_refusal(
            self._scope,
            row,
            expected_revision=expected_revision,
            replacement_revision=replacement.revision,
            kind="finalization",
            table="finalization_journal",
            identity=identity,
        )
        if refusal is not None:
            return refusal
        assert row is not None  # noqa: S101 - narrowed by _revision_refusal
        stored = self._decode(opened, row)
        if isinstance(stored, Failure):
            return stored
        try:
            assert_journal_transition(stored.value, replacement)
        except FinalizationJournalRuleViolation as violation:
            return self._scope.invariant(
                str(violation),
                table="finalization_journal",
                operation="compare_and_swap",
                identity=identity,
            )
        try:
            outcome = opened.execute(
                update(FinalizationJournalRow)
                .where(
                    FinalizationJournalRow.finalization_id == identity,
                    FinalizationJournalRow.revision == expected_revision,
                )
                .values(**encode_finalization_journal_entry(replacement))
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="finalization_journal",
                operation="compare_and_swap",
                identity=identity,
            )
        if outcome.rowcount != 1:
            return self._scope.conflict(
                f"finalization {identity} was not updated at revision "
                f"{expected_revision}",
                table="finalization_journal",
                operation="compare_and_swap",
                identity=identity,
            )
        return Success[FinalizationJournalEntry](outcome="SUCCESS", value=replacement)

    def list_open(
        self,
        purpose: ArtifactFinalizationPurpose | MISSING = MISSING,  # type: ignore[valid-type]
        limit: int = _MAX_LISTING,
    ) -> Result[tuple[FinalizationJournalEntry, ...]]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        statement = (
            select(FinalizationJournalRow)
            .where(FinalizationJournalRow.state.in_(_OPEN_JOURNAL_STATES))
            .order_by(
                FinalizationJournalRow.prepared_at_utc,
                FinalizationJournalRow.finalization_id,
            )
            .limit(limit)
        )
        if isinstance(purpose, ArtifactFinalizationPurpose):
            statement = statement.where(
                FinalizationJournalRow.finalization_purpose == purpose.value
            )
        try:
            rows = opened.execute(statement).mappings().all()
        except DBAPIError as error:
            return self._scope.refused(
                error, table="finalization_journal", operation="list_open", identity="*"
            )
        decoded: list[FinalizationJournalEntry] = []
        for row in rows:
            item = self._decode(opened, row)
            if isinstance(item, Failure):
                return item
            decoded.append(item.value)
        return Success[tuple[FinalizationJournalEntry, ...]](
            outcome="SUCCESS", value=tuple(decoded)
        )

    def find_result_identity(
        self, run_invocation_id: InvocationId, source_hash: Sha256
    ) -> Result[FinalizationJournalEntry | MISSING]:  # type: ignore[valid-type]
        return self._find(
            select(FinalizationJournalRow).where(
                FinalizationJournalRow.finalization_purpose
                == ArtifactFinalizationPurpose.RESULT.value,
                FinalizationJournalRow.run_invocation_id == run_invocation_id,
                FinalizationJournalRow.source_adapter_result_manifest_hash
                == source_hash,
            ),
            operation="find_result_identity",
            identity=run_invocation_id,
        )

    def find_evidence_identity(
        self,
        owner_hash: Sha256,
        kind: str,
        correlation_id: str,
        set_hash: Sha256,
    ) -> Result[FinalizationJournalEntry | MISSING]:  # type: ignore[valid-type]
        return self._find(
            select(FinalizationJournalRow).where(
                FinalizationJournalRow.finalization_purpose
                == ArtifactFinalizationPurpose.EVIDENCE.value,
                FinalizationJournalRow.owner_hash == owner_hash,
                FinalizationJournalRow.correlation_kind == kind,
                FinalizationJournalRow.correlation_id == correlation_id,
                FinalizationJournalRow.candidate_set_hash == set_hash,
            ),
            operation="find_evidence_identity",
            identity=owner_hash,
        )

    def _find(
        self, statement: Any, *, operation: str, identity: str
    ) -> Result[FinalizationJournalEntry | MISSING]:  # type: ignore[valid-type]
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            row = opened.execute(statement).mappings().first()
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="finalization_journal",
                operation=operation,
                identity=identity,
            )
        if row is None:
            return _absent()
        return self._decode(opened, row)


# --------------------------------------------------------------------------
# run_manifests, sanitized_adapter_result_manifests, adapter_validation_results,
# run_artifacts (the registration facts of plan 4.1)
# --------------------------------------------------------------------------


def _facts_insert(
    scope: TransactionScope,
    table: str,
    operation: str,
    identity: str,
    statement: Any,
) -> Result[None]:
    opened = scope.open_statement()
    if isinstance(opened, Failure):
        return opened
    try:
        opened.execute(statement)
    except DBAPIError as error:
        return scope.refused(error, table=table, operation=operation, identity=identity)
    return _none()


def _link_evidence(
    scope: TransactionScope,
    table: str,
    identity: str,
    statement: Any,
) -> Result[None]:
    opened = scope.open_statement()
    if isinstance(opened, Failure):
        return opened
    try:
        outcome = opened.execute(statement)
    except DBAPIError as error:
        return scope.refused(
            error, table=table, operation="link_evidence", identity=identity
        )
    if outcome.rowcount != 1:
        return scope.conflict(
            f"{table} row {identity} was not linked (absent or already linked)",
            table=table,
            operation="link_evidence",
            identity=identity,
        )
    return _none()


class SqliteRunManifestRepository:
    """``run_manifests``: insert-only, one per successful run (reading 11)."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def add(self, facts: RunManifestFactsView) -> Result[None]:
        return _facts_insert(
            self._scope,
            "run_manifests",
            "add",
            facts.manifest_id,
            insert(RunManifestRow).values(
                manifest_id=facts.manifest_id,
                schema_version="1.0.0",
                run_id=facts.run_id,
                experiment_id=facts.experiment_id,
                run_invocation_id=facts.run_invocation_id,
                attempt_token_hash=facts.attempt_token_hash,
                sanitized_adapter_result_manifest_hash=(
                    facts.sanitized_adapter_result_manifest_hash
                ),
                semantic_status=facts.semantic_status,
                process_exit_category=facts.process_exit_category,
                manifest_json=facts.manifest_json,
                run_manifest_hash=facts.run_manifest_hash,
                registered_at_utc=utc_to_micros(facts.registered_at_utc),
            ),
        )

    def get(self, run_id: RunId) -> Result[RunManifestFacts | MISSING]:  # type: ignore[valid-type]
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            row = (
                opened.execute(
                    select(RunManifestRow).where(RunManifestRow.run_id == run_id)
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error, table="run_manifests", operation="get", identity=run_id
            )
        if row is None:
            return _absent()
        return Success[InstanceOf[RunManifestFacts]](
            outcome="SUCCESS",
            value=RunManifestFacts(
                manifest_id=str(row["manifest_id"]),
                run_id=str(row["run_id"]),
                experiment_id=str(row["experiment_id"]),
                run_invocation_id=str(row["run_invocation_id"]),
                attempt_token_hash=str(row["attempt_token_hash"]),
                sanitized_adapter_result_manifest_hash=str(
                    row["sanitized_adapter_result_manifest_hash"]
                ),
                semantic_status=str(row["semantic_status"]),
                process_exit_category=str(row["process_exit_category"]),
                manifest_json=str(row["manifest_json"]),
                run_manifest_hash=str(row["run_manifest_hash"]),
                registered_at_utc=_instant(row["registered_at_utc"]),
            ),
        )


class SqliteSanitizedManifestRepository:
    """``sanitized_adapter_result_manifests``: insert-once, evidence linked once."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def add(self, facts: SanitizedManifestFactsView) -> Result[None]:
        evidence = facts.evidence_artifact_id
        return _facts_insert(
            self._scope,
            "sanitized_adapter_result_manifests",
            "add",
            facts.sanitized_adapter_result_manifest_hash,
            insert(SanitizedAdapterResultManifestRow).values(
                sanitized_adapter_result_manifest_hash=(
                    facts.sanitized_adapter_result_manifest_hash
                ),
                run_id=facts.run_id,
                run_invocation_id=facts.run_invocation_id,
                experiment_id=facts.experiment_id,
                attempt_token_hash=facts.attempt_token_hash,
                source_adapter_result_manifest_hash=(
                    facts.source_adapter_result_manifest_hash
                ),
                semantic_status=facts.semantic_status,
                manifest_json=facts.manifest_json,
                evidence_artifact_id=evidence if isinstance(evidence, str) else None,
                recorded_at_utc=utc_to_micros(facts.recorded_at_utc),
            ),
        )

    def get(
        self, sanitized_adapter_result_manifest_hash: Sha256
    ) -> Result[SanitizedManifestFacts | MISSING]:  # type: ignore[valid-type]
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            row = (
                opened.execute(
                    select(SanitizedAdapterResultManifestRow).where(
                        _SANITIZED_HASH == sanitized_adapter_result_manifest_hash
                    )
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="sanitized_adapter_result_manifests",
                operation="get",
                identity=sanitized_adapter_result_manifest_hash,
            )
        if row is None:
            return _absent()
        return Success[InstanceOf[SanitizedManifestFacts]](
            outcome="SUCCESS",
            value=SanitizedManifestFacts(
                sanitized_adapter_result_manifest_hash=str(
                    row["sanitized_adapter_result_manifest_hash"]
                ),
                run_id=str(row["run_id"]),
                run_invocation_id=str(row["run_invocation_id"]),
                experiment_id=str(row["experiment_id"]),
                attempt_token_hash=str(row["attempt_token_hash"]),
                source_adapter_result_manifest_hash=str(
                    row["source_adapter_result_manifest_hash"]
                ),
                semantic_status=str(row["semantic_status"]),
                manifest_json=str(row["manifest_json"]),
                evidence_artifact_id=_optional_text(row["evidence_artifact_id"]),
                recorded_at_utc=_instant(row["recorded_at_utc"]),
            ),
        )

    def link_evidence(
        self, sanitized_adapter_result_manifest_hash: Sha256, artifact_id: ArtifactId
    ) -> Result[None]:
        return _link_evidence(
            self._scope,
            "sanitized_adapter_result_manifests",
            sanitized_adapter_result_manifest_hash,
            update(SanitizedAdapterResultManifestRow)
            .where(
                _SANITIZED_HASH == sanitized_adapter_result_manifest_hash,
                SanitizedAdapterResultManifestRow.evidence_artifact_id.is_(None),
            )
            .values(evidence_artifact_id=artifact_id),
        )


class SqliteValidationResultRepository:
    """``adapter_validation_results``: insert-once, evidence linked once (reading 8)."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def add(self, facts: ValidationResultFactsView) -> Result[None]:
        evidence = facts.evidence_artifact_id
        return _facts_insert(
            self._scope,
            "adapter_validation_results",
            "add",
            facts.invocation_id,
            insert(AdapterValidationResultRow).values(
                invocation_id=facts.invocation_id,
                run_id=facts.run_id,
                experiment_id=facts.experiment_id,
                validation_result_hash=facts.validation_result_hash,
                outcome=facts.outcome,
                result_json=facts.result_json,
                evidence_artifact_id=evidence if isinstance(evidence, str) else None,
                recorded_at_utc=utc_to_micros(facts.recorded_at_utc),
            ),
        )

    def get(
        self, invocation_id: InvocationId
    ) -> Result[ValidationResultFacts | MISSING]:  # type: ignore[valid-type]
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            row = (
                opened.execute(
                    select(AdapterValidationResultRow).where(
                        AdapterValidationResultRow.invocation_id == invocation_id
                    )
                )
                .mappings()
                .first()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error,
                table="adapter_validation_results",
                operation="get",
                identity=invocation_id,
            )
        if row is None:
            return _absent()
        return Success[InstanceOf[ValidationResultFacts]](
            outcome="SUCCESS",
            value=ValidationResultFacts(
                invocation_id=str(row["invocation_id"]),
                run_id=str(row["run_id"]),
                experiment_id=str(row["experiment_id"]),
                validation_result_hash=str(row["validation_result_hash"]),
                outcome=str(row["outcome"]),
                result_json=str(row["result_json"]),
                evidence_artifact_id=_optional_text(row["evidence_artifact_id"]),
                recorded_at_utc=_instant(row["recorded_at_utc"]),
            ),
        )

    def link_evidence(
        self, invocation_id: InvocationId, artifact_id: ArtifactId
    ) -> Result[None]:
        return _link_evidence(
            self._scope,
            "adapter_validation_results",
            invocation_id,
            update(AdapterValidationResultRow)
            .where(
                AdapterValidationResultRow.invocation_id == invocation_id,
                AdapterValidationResultRow.evidence_artifact_id.is_(None),
            )
            .values(evidence_artifact_id=artifact_id),
        )


class SqliteRunArtifactRepository:
    """``run_artifacts``: the ``RUN``-owner-only links (plan 3.3)."""

    __slots__ = ("_scope",)

    def __init__(self, scope: TransactionScope) -> None:
        self._scope = scope

    def link(self, link: RunArtifactLinkView) -> Result[None]:
        if link.link_role not in RUN_ARTIFACT_LINK_ROLES:
            return self._scope.invariant(
                f"{link.link_role} is not a run artifact link role",
                table="run_artifacts",
                operation="link",
                identity=link.artifact_id,
            )
        manifest = link.run_manifest_id
        return _facts_insert(
            self._scope,
            "run_artifacts",
            "link",
            link.artifact_id,
            insert(RunArtifactRow).values(
                run_id=link.run_id,
                artifact_id=link.artifact_id,
                link_role=link.link_role,
                experiment_id=link.experiment_id,
                run_manifest_id=manifest if isinstance(manifest, str) else None,
            ),
        )

    def list_for_run(self, run_id: RunId) -> Result[tuple[RunArtifactLink, ...]]:
        opened = self._scope.open_statement()
        if isinstance(opened, Failure):
            return opened
        try:
            rows = (
                opened.execute(
                    select(RunArtifactRow)
                    .where(RunArtifactRow.run_id == run_id)
                    .order_by(RunArtifactRow.link_role, RunArtifactRow.artifact_id)
                )
                .mappings()
                .all()
            )
        except DBAPIError as error:
            return self._scope.refused(
                error, table="run_artifacts", operation="list_for_run", identity=run_id
            )
        return Success[tuple[RunArtifactLink, ...]](
            outcome="SUCCESS",
            value=tuple(
                RunArtifactLink(
                    run_id=str(row["run_id"]),
                    artifact_id=str(row["artifact_id"]),
                    link_role=str(row["link_role"]),
                    experiment_id=str(row["experiment_id"]),
                    run_manifest_id=_optional_text(row["run_manifest_id"]),
                )
                for row in rows
            ),
        )
