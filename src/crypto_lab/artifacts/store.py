"""The content-addressed artifact store: preflight, atomic move, quarantine and
the one core-staging writer.

Stage 9 plan 6.1, 6.2 and 6.5 under specification 19.2:1405, 22.5 and 28.5
(readings 20, 21 and 26). ``ArtifactStore.open`` runs the 22.5 preflight before
anything is written: each root is an absolute, drive-lettered local path (a UNC
root is refused before any filesystem call), exists as a directory -- the
quarantine root may be created, so while it is absent its parent must exist and
is examined in its stead; once it exists it is examined itself, and a file or an
uninspectable root is refused -- carries no reparse point
on or above it, and the three roots share one volume by ``st_dev`` (plan 6.1 names
the staging and artifacts roots; the quarantine root is held to the same volume
because every quarantine is a rename, and while it does not exist yet its parent
stands in for it). Only after every one of those checks has passed does the store
create ``objects/`` and ``manifests/`` under the artifacts root and the quarantine
root with ``mkdir(exist_ok=True)``, inside ``open`` and never at import, so a
refused preflight has written nothing. ``atomic_move``
reopens the source, compares the ``fstat`` identity of that handle with the
confined identity, ``fsync``s it, and renames with ``Path.rename`` -- the one move
primitive, which refuses an existing target on Windows so finalized content is
never overwritten; an existing target is re-hashed and an equal blob deduplicates
(the candidate bytes are removed) while a differing one is
``CORE.INVARIANT_VIOLATION``. The store owns the one bridge to the plan 4.1
stream port: it opens the confined candidate once, compares the ``fstat`` identity
of that handle with the confined identity before and after the ``ContentHasher``
streams it -- while the handle is still open, so a substitute swapped in around
the open and swapped away again is caught by the handle and not missed by a
later look at the path. ``hash_confined`` is that bridge over ``sha256_stream``
(how the dedup branch hashes the candidate and how ``write_staged`` re-hashes an
existing staged file once it is confined); ``scan_confined`` is the same bridge
over ``sha256_and_scan`` for the phase-1 ``HASH`` step of ``validation.py``, which
may not import ``os`` itself, and ``read_confined`` the same bridge over one
bounded ``read`` for its ``SCHEMA`` step, so the bytes decoded there were read
from a handle whose identity was checked before and after the read as well. The
existing finalized blob of the dedup branch is the one blob opened by path here
and handed to the same stream.
``quarantine_move`` uses the same primitive toward the plan 6.2 layout
``<quarantine_root>/<entry_id>/<original relative path>`` and writes
``quarantine.json`` exclusive-create once per entry; it admits candidate paths
alone. ``quarantine_orphan`` is the Task 6 RV-9 file-map correction: the
recovery-only quarantine of an orphan file beneath this store's ``objects/``
root whose ordinary name the candidate grammar refuses or whose layout is no
canonical object (a content-address leaf under any directory but its own
shard), confined by ``confine_orphan_path`` and moved by the same primitive to
the same layout -- the entry keyed by the identity the caller derived, the bytes
at the very root-relative path they were found at -- with the metadata validated
and serialized before any byte moves and every directory of the destination path
refused while it is a reparse point. ``canonical_content_address`` is the one
classifier of a canonical object the store and the RV-9 sweep share: the
supported store is a case-insensitive Windows volume, so a root-relative path is
the complete layout ``objects/<hh>/<sha256>`` when it equals that layout compared
case-folded as ``is_within_root`` compares (a case-only rename of a shard or a
leaf leaves the very same file at the very same path there), and it is nothing
else -- a content-address leaf under any other directory is misplaced content,
never canonical. ``write_staged`` is the only writer into core
staging: the relative path passes the lexical grammar, the chain below the owner
root is checked for reparse points before anything is created, the file is opened
``xb``, written and ``fsync``ed, and an existing file is confined before it is
read -- a reparse-point or hard-linked leaf is refused unread -- then re-hashed
through the identity-checked handle: equal bytes replay, differing bytes are an
invariant violation.

This is the one ``os`` importer of ``src/crypto_lab`` (plan 2.6) and the only two
``os`` attributes read are ``fstat`` and ``fsync``; no ``shutil``, no ``replace``.
``PROCESS.PATH_PREFLIGHT_REJECTED`` and ``CORE.INVARIANT_VIOLATION`` are restated
here with their Stage 7 postures because ``artifacts`` may not import
``process_supervision`` (pinned equal by test); every other refusal is an
``ARTIFACT.*`` code of ``artifacts/diagnostics.py``. A storage refusal of a move,
a write or a deletion is ``ARTIFACT.MOVE_FAILED`` (reading 26). No message carries
a path.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path, PureWindowsPath
from typing import Annotated, BinaryIO, Final, Literal, cast

from pydantic import (
    AfterValidator,
    InstanceOf,
    JsonValue,
    StringConstraints,
    TypeAdapter,
    ValidationError,
)
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.artifacts.diagnostics import (
    ARTIFACT_MOVE_FAILED,
    ARTIFACT_PATH_BOUNDARY_VIOLATION,
    ARTIFACT_SOURCE_COMPONENT,
    ARTIFACT_VALIDATION_FAILED,
    ArtifactDiagnosticPosture,
    artifact_failure,
)
from crypto_lab.artifacts.hashing import (
    ContentHasher,
    HashScan,
    StreamingContentHasher,
)
from crypto_lab.artifacts.models import (
    MAX_RELATIVE_PATH_CHARACTERS,
    SizeBytes,
    finalized_relative_path_for,
)
from crypto_lab.artifacts.paths import (
    CHANGED_WHILE_FINALIZING,
    ConfinedPath,
    confine_candidate_path,
    confine_orphan_path,
    file_identity_of,
    lexical_candidate_path,
    lexical_orphan_path,
)
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticDetailValue,
    DiagnosticSeverity,
    ErrorCode,
)
from crypto_lab.domain.engine_run import AttemptTokenMaterial
from crypto_lab.domain.hashing import (
    HashingProfile,
    _uuid4_shaped,
    profile_hash,
    sha256_bytes,
)
from crypto_lab.domain.identifiers import Sha256, validate_prefixed_uuid4
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.domain.time import CalendarValidUtcDateTime

#: The two non-artifact codes the store mints, restated with their Stage 7
#: postures (``artifacts`` may not import ``process_supervision``; pinned by test).
PROCESS_PATH_PREFLIGHT_REJECTED: Final = "PROCESS.PATH_PREFLIGHT_REJECTED"
CORE_INVARIANT_VIOLATION: Final = "CORE.INVARIANT_VIOLATION"
STORE_DIAGNOSTIC_POSTURES: Final[Mapping[str, ArtifactDiagnosticPosture]] = {
    PROCESS_PATH_PREFLIGHT_REJECTED: ArtifactDiagnosticPosture(
        DiagnosticCategory.USER_CONFIGURATION, False, DiagnosticSeverity.ERROR
    ),
    CORE_INVARIANT_VIOLATION: ArtifactDiagnosticPosture(
        DiagnosticCategory.INTERNAL_INVARIANT, False, DiagnosticSeverity.ERROR
    ),
}
#: Plan 6.2: the fixed names of the layout.
OBJECTS_SEGMENT: Final = "objects"
MANIFESTS_SEGMENT: Final = "manifests"
QUARANTINE_METADATA_NAME: Final = "quarantine.json"
#: Win32 attributes, spelled locally (plan 2.6: no ``stat`` import).
_FILE_ATTRIBUTE_DIRECTORY: Final = 0x10
_FILE_ATTRIBUTE_REPARSE_POINT: Final = 0x400
_SHA256_HEX: Final = frozenset("0123456789abcdef")
_ENTRY_ID_CHARACTERS: Final = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._- "
)
_MAX_ENTRY_ID_CHARACTERS: Final = 255
_MAX_METADATA_BYTES: Final = 65_536
#: The bound of the quarantine listing walk.
_MAX_WALK_DEPTH: Final = 64
_ERROR_CODE_ADAPTER: TypeAdapter[str] = TypeAdapter(ErrorCode)


def same_volume(left: Path, right: Path) -> bool:
    """Reading 20: whether two existing paths share ``Path.stat().st_dev``."""
    return left.stat().st_dev == right.stat().st_dev


@dataclass(frozen=True, slots=True)
class MoveOutcome:
    """One completed ``atomic_move``: deduplicated when an equal blob existed."""

    source: Path
    target: Path
    deduplicated: bool


@dataclass(frozen=True, slots=True)
class QuarantineOutcome:
    """One completed ``quarantine_move``; the metadata is written once per entry."""

    entry_id: str
    target: Path
    metadata_path: Path
    metadata_written: bool


@dataclass(frozen=True, slots=True)
class QuarantineEntry:
    """One quarantine entry as listed: metadata facts when readable, its files."""

    entry_id: str
    reason_code: str | None
    quarantined_at_utc: datetime | None
    files: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class RemovalReport:
    """The outcome of ``remove_raw_bytes`` per path, in the order given."""

    removed: tuple[Path, ...]
    missing: tuple[Path, ...]
    failed: tuple[Path, ...]


#: The root-relative path of quarantined bytes: bounded and structurally
#: validated by the orphan grammar -- every rule and bound of the candidate
#: grammar with the character class alone relaxed (its superset, pinned by test)
#: -- so the metadata carries nothing that grammar refused, whether the bytes
#: came through the candidate quarantine (whose path the candidate grammar had
#: already admitted) or the orphan quarantine.
type _QuarantineRelativePath = Annotated[
    str,
    StringConstraints(
        strict=True, min_length=1, max_length=MAX_RELATIVE_PATH_CHARACTERS
    ),
    AfterValidator(lexical_orphan_path),
]


class QuarantineMetadata(CanonicalModel):
    """Plan 6.2: the ``quarantine.json`` of one entry -- reason code, instant,
    source path facts and the content hash when the caller knew it.
    ``relative_path`` is the root-relative path the bytes were found at and, the
    layout being ``<quarantine_root>/<entry_id>/<original relative path>``, the
    entry-relative path they lie at now: the candidate quarantine and the orphan
    quarantine (Task 6 RV-9 correction) alike. ``sha256`` is present when the
    caller knew the digest (a canonical object); an orphan claims none."""

    schema_version: Literal["1.0.0"]
    entry_id: str
    reason_code: ErrorCode
    quarantined_at_utc: CalendarValidUtcDateTime
    source_root: str
    relative_path: _QuarantineRelativePath
    size_bytes: SizeBytes
    sha256: Sha256 | MISSING = MISSING  # type: ignore[valid-type]


def _attributes(path: Path) -> int:
    """The Win32 attributes of ``path`` itself; a reparse point is not followed."""
    return int(getattr(path.lstat(), "st_file_attributes", 0))


def _is_reparse_point(attributes: int) -> bool:
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _is_directory(attributes: int) -> bool:
    return bool(attributes & _FILE_ATTRIBUTE_DIRECTORY)


def _reparse_point_on_or_above(path: Path) -> bool:
    """Whether ``path`` or any existing ancestor up to the drive is a reparse point
    (``roots.py`` mirrored, reading 19)."""
    for candidate in (path, *path.parents):
        try:
            attributes = _attributes(candidate)
        except OSError:
            continue
        if _is_reparse_point(attributes):
            return True
    return False


def _volume_probe(root: Path) -> Path:
    """The existing path whose ``st_dev`` stands for a root the store may create:
    the root itself once it exists, its parent while it does not."""
    try:
        _attributes(root)
    except OSError:
        return root.parent
    return root


def _lexical_root_refusal(root: Path) -> str | None:
    if not root.is_absolute():
        return "root_not_absolute"
    drive = PureWindowsPath(root).drive
    if len(drive) != 2 or not drive[0].isalpha() or drive[1] != ":":
        return "root_unc"
    return None


def _physical_root_refusal(root: Path, *, may_be_created: bool) -> str | None:
    """``root`` itself is examined when it exists; a root the store may create is
    examined through its parent only while it is absent. An inspection error other
    than absence refuses as ``root_not_directory`` rather than implying absence
    (the ``roots.py`` posture); the reparse walk always starts at ``root`` itself."""
    try:
        attributes = _attributes(root)
    except (FileNotFoundError, NotADirectoryError):
        if not may_be_created:
            return "root_missing"
        try:
            attributes = _attributes(root.parent)
        except (FileNotFoundError, NotADirectoryError):
            return "root_missing"
        except OSError:
            return "root_not_directory"
    except OSError:
        return "root_not_directory"
    if _reparse_point_on_or_above(root):
        return "ancestor_reparse_point"
    if not _is_directory(attributes):
        return "root_not_directory"
    return None


def _is_sha256_hex(value: str) -> bool:
    return len(value) == 64 and set(value) <= _SHA256_HEX


def canonical_content_address(relative: str) -> str | None:
    """The digest a root-relative path under the artifacts root addresses as a
    canonical object, or ``None`` when the path is no canonical object (plan 6.2,
    RV-9). The supported store is a case-insensitive Windows volume, on which a
    case-only rename of a shard directory or of a leaf leaves the very same file
    at the very same path, so the path is compared case-folded -- the fold
    ``is_within_root`` compares resolved paths with -- against the complete
    layout ``objects/<hh>/<sha256>`` of its folded leaf, the shard equal to the
    digest's prefix. The complete layout is required: a content-address leaf
    under any other directory (``objects/.x/<sha256>``, ``objects/zz/<sha256>``),
    a bare digest, a projection or a leaf of any other shape is misplaced or
    foreign content the store never wrote, and the answer is ``None``. Purely
    textual; nothing is consulted on the filesystem."""
    if type(relative) is not str:
        raise TypeError("relative path must be a built-in string")
    folded = relative.casefold()
    digest = folded.rsplit("/", 1)[-1]
    if not _is_sha256_hex(digest) or folded != finalized_relative_path_for(digest):
        return None
    return digest


def _require_sha256_hex(value: str, label: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{label} must be a built-in string")
    if not _is_sha256_hex(value):
        raise ValueError(f"{label} must be 64 lowercase hex digits")


def _require_entry_id(entry_id: str) -> None:
    if type(entry_id) is not str:
        raise TypeError("entry id must be a built-in string")
    if (
        not entry_id
        or len(entry_id) > _MAX_ENTRY_ID_CHARACTERS
        or not set(entry_id) <= _ENTRY_ID_CHARACTERS
        or entry_id[0] in ".- "
        or entry_id.endswith((".", " "))
    ):
        raise ValueError("entry id must be a plain single path segment")


def _require_error_code(reason: str) -> None:
    if type(reason) is not str:
        raise TypeError("reason must be a built-in string")
    try:
        _ERROR_CODE_ADAPTER.validate_python(reason)
    except ValidationError as error:
        raise ValueError("reason must be an error code") from error


def _store_diagnostic(
    code: str,
    *,
    message: str,
    now_utc: datetime,
    details: Mapping[str, DiagnosticDetailValue],
) -> Diagnostic:
    """One of the two restated codes, with the ``DIAGNOSTIC_IDENTITY_V1`` identity
    the Stage 7 factory derives (the instant excluded)."""
    posture = STORE_DIAGNOSTIC_POSTURES[code]
    detail_payload: dict[str, DiagnosticDetailValue] = dict(details)
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "error_code": code,
        "category": posture.category.value,
        "severity": posture.severity.value,
        "source_component": ARTIFACT_SOURCE_COMPONENT,
        "message": message,
        "retriable": posture.retriable,
        "details": cast("JsonValue", detail_payload),
        "causal_diagnostic_ids": [],
    }
    identity = _uuid4_shaped(
        profile_hash(HashingProfile.DIAGNOSTIC_IDENTITY_V1, payload)
    )
    return Diagnostic.model_validate(
        {
            "schema_version": "1.0.0",
            "diagnostic_id": f"diag_{identity}",
            "severity": posture.severity,
            "error_code": code,
            "category": posture.category,
            "message": message,
            "source_component": ARTIFACT_SOURCE_COMPONENT,
            "retriable": posture.retriable,
            "timestamp_utc": now_utc,
            "details": detail_payload,
            "causal_diagnostic_ids": (),
        }
    )


def _store_failure(
    code: str,
    *,
    message: str,
    now_utc: datetime,
    details: Mapping[str, DiagnosticDetailValue] | None = None,
) -> Failure:
    return Failure(
        outcome="FAILURE",
        diagnostics=(
            _store_diagnostic(
                code, message=message, now_utc=now_utc, details=details or {}
            ),
        ),
    )


def _move_failed(message: str, now_utc: datetime) -> Failure:
    return artifact_failure(ARTIFACT_MOVE_FAILED, message=message, now_utc=now_utc)


def _identity_refusal(
    handle: BinaryIO, confined: ConfinedPath, now_utc: datetime
) -> Failure | None:
    """Reading 18: the ``fstat`` identity of an open handle against the confined
    identity; a difference is ``ARTIFACT.VALIDATION_FAILED``."""
    if file_identity_of(os.fstat(handle.fileno())) != confined.identity:
        return artifact_failure(
            ARTIFACT_VALIDATION_FAILED,
            message=CHANGED_WHILE_FINALIZING,
            now_utc=now_utc,
        )
    return None


def _stream_confined[T](
    confined: ConfinedPath,
    stream: Callable[[BinaryIO], T],
    now_utc: datetime,
) -> T | Failure:
    """Plan 4.1 and reading 18, the one handle bridge: open the confined candidate
    once, compare the ``fstat`` identity of that handle with the confined identity,
    hand the same handle to ``stream`` and compare the identity again while it is
    still open, so a file swapped before or changed while streaming is
    ``ARTIFACT.VALIDATION_FAILED``; a refused open or read is the storage posture
    ``ARTIFACT.MOVE_FAILED`` (reading 26)."""
    try:
        with confined.path.open("rb") as handle:
            before = _identity_refusal(handle, confined, now_utc)
            if before is not None:
                return before
            value = stream(handle)
            after = _identity_refusal(handle, confined, now_utc)
    except OSError:
        return _move_failed("the candidate could not be read while hashing", now_utc)
    if after is not None:
        return after
    return value


def scan_confined(
    confined: ConfinedPath,
    hasher: ContentHasher,
    token: AttemptTokenMaterial | MISSING,  # type: ignore[valid-type]
    *,
    detect_token_shape: bool,
    now_utc: datetime,
) -> Result[HashScan]:
    """The handle bridge for the phase-1 ``HASH`` step (plan 4.3): the digest and
    the token scan of ``hasher.sha256_and_scan`` over the one identity-checked
    handle, so the bytes hashed and scanned are the bytes whose identity was
    confined -- never a substitute swapped in around the open."""
    if not isinstance(confined, ConfinedPath):
        raise TypeError("confined must be a ConfinedPath")
    if not isinstance(hasher, ContentHasher):
        raise TypeError("hasher must implement ContentHasher")

    def stream(handle: BinaryIO) -> HashScan:
        return hasher.sha256_and_scan(
            handle, token, detect_token_shape=detect_token_shape
        )

    scan = _stream_confined(confined, stream, now_utc)
    if isinstance(scan, Failure):
        return scan
    return Success[InstanceOf[HashScan]](outcome="SUCCESS", value=scan)


def read_confined(
    confined: ConfinedPath, *, limit: int, now_utc: datetime
) -> Result[bytes]:
    """The handle bridge for the phase-1 ``SCHEMA`` step (plan 4.3): at most
    ``limit`` bytes of the one identity-checked handle, read once, so the bytes
    the caller decodes are bytes of the file whose identity was confined -- never
    a substitute swapped in around the open. ``limit`` is the caller's already
    bounded size (at or below its parse ceiling); nothing beyond it is read."""
    if not isinstance(confined, ConfinedPath):
        raise TypeError("confined must be a ConfinedPath")
    if type(limit) is not int:
        raise TypeError("limit must be a built-in integer")
    if limit < 0:
        raise ValueError("limit must not be negative")

    def stream(handle: BinaryIO) -> bytes:
        return handle.read(limit)

    data = _stream_confined(confined, stream, now_utc)
    if isinstance(data, Failure):
        return data
    return Success[bytes](outcome="SUCCESS", value=data)


class ArtifactStore:
    """Plan 6.1, 6.2 and 6.5: the content-addressed store over three preflighted
    roots. Construct through ``open``."""

    def __init__(
        self,
        staging_root: Path,
        artifacts_root: Path,
        quarantine_root: Path,
        hasher: ContentHasher,
    ) -> None:
        self._staging_root = staging_root
        self._artifacts_root = artifacts_root
        self._quarantine_root = quarantine_root
        self._objects_root = artifacts_root / OBJECTS_SEGMENT
        self._manifests_root = artifacts_root / MANIFESTS_SEGMENT
        self._hasher = hasher

    @classmethod
    def open(
        cls,
        staging_root: Path,
        artifacts_root: Path,
        quarantine_root: Path,
        *,
        now_utc: datetime,
        hasher: ContentHasher | None = None,
    ) -> Result[ArtifactStore]:
        """The 22.5 preflight, then the layout (plan 6.1)."""
        roots = (
            ("staging", staging_root, False),
            ("artifacts", artifacts_root, False),
            ("quarantine", quarantine_root, True),
        )
        for label, root, _ in roots:
            if not isinstance(root, Path):
                raise TypeError(f"{label} root must be a Path")

        def refuse(reason: str, message: str, root: Path) -> Failure:
            return _store_failure(
                PROCESS_PATH_PREFLIGHT_REJECTED,
                message=message,
                now_utc=now_utc,
                details={"reason": reason, "path_length": len(str(root))},
            )

        for label, root, _ in roots:
            lexical = _lexical_root_refusal(root)
            if lexical is not None:
                return refuse(
                    lexical, f"the {label} root is not an absolute local path", root
                )
        for label, root, may_be_created in roots:
            physical = _physical_root_refusal(root, may_be_created=may_be_created)
            if physical is not None:
                return refuse(physical, f"the {label} root failed preflight", root)
        # Reading 20: the volume check completes before anything is created; a
        # quarantine root that does not exist yet is probed through its parent.
        quarantine_probe = _volume_probe(quarantine_root)
        if not (
            same_volume(staging_root, artifacts_root)
            and same_volume(staging_root, quarantine_probe)
        ):
            return refuse(
                "volume_mismatch", "the roots are not on one volume", artifacts_root
            )
        store = cls(
            staging_root,
            artifacts_root,
            quarantine_root,
            StreamingContentHasher() if hasher is None else hasher,
        )
        try:
            store._objects_root.mkdir(exist_ok=True)
            store._manifests_root.mkdir(exist_ok=True)
            quarantine_root.mkdir(exist_ok=True)
        except OSError:
            return refuse(
                "layout_not_creatable",
                "the store layout could not be created",
                artifacts_root,
            )
        return Success[InstanceOf[ArtifactStore]](outcome="SUCCESS", value=store)

    @property
    def staging_root(self) -> Path:
        return self._staging_root

    @property
    def artifacts_root(self) -> Path:
        return self._artifacts_root

    @property
    def quarantine_root(self) -> Path:
        return self._quarantine_root

    @property
    def objects_root(self) -> Path:
        return self._objects_root

    @property
    def manifests_root(self) -> Path:
        return self._manifests_root

    def finalized_path_for(self, sha256: str) -> Path:
        """``<artifacts_root>/objects/<hh>/<sha256>`` (plan 6.2)."""
        return self._artifacts_root.joinpath(
            *finalized_relative_path_for(sha256).split("/")
        )

    def manifest_path_for(self, artifact_id: str) -> Path:
        """``<artifacts_root>/manifests/<artifact_id>.json`` (plan 6.2)."""
        if type(artifact_id) is not str:
            raise TypeError("artifact id must be a built-in string")
        validate_prefixed_uuid4(artifact_id, "art_")
        return self._manifests_root / f"{artifact_id}.json"

    def preflight_planned_path(
        self, path: Path, *, file_ceiling: int, now_utc: datetime
    ) -> Result[None]:
        """22.5:1655: refuse a planned path longer than the Stage 7 file ceiling
        the caller hands in; the rejection always runs."""
        if type(file_ceiling) is not int or file_ceiling < 1:
            raise ValueError("file ceiling must be a positive integer")
        length = len(str(path))
        if length > file_ceiling:
            return _store_failure(
                PROCESS_PATH_PREFLIGHT_REJECTED,
                message="the planned artifact path exceeds the file ceiling",
                now_utc=now_utc,
                details={
                    "reason": "ceiling_exceeded",
                    "path_length": length,
                    "ceiling": file_ceiling,
                },
            )
        return Success[None](outcome="SUCCESS", value=None)

    def _reopen_and_fsync(
        self, confined: ConfinedPath, now_utc: datetime
    ) -> Failure | None:
        """Plan 6.5: reopen by path, compare the handle identity, ``fsync``."""
        try:
            with confined.path.open("r+b") as handle:
                refusal = _identity_refusal(handle, confined, now_utc)
                if refusal is not None:
                    return refusal
                os.fsync(handle.fileno())
        except OSError:
            return _move_failed(
                "the candidate could not be reopened for the move", now_utc
            )
        return None

    def hash_confined(
        self, confined: ConfinedPath, *, now_utc: datetime
    ) -> Result[Sha256]:
        """Plan 4.1 and reading 18: the store's digest of a confined candidate
        through the one handle bridge -- opened once, ``fstat`` identity compared
        before and after ``sha256_stream`` on that same handle; a swap or a change
        is ``ARTIFACT.VALIDATION_FAILED``, a refused open or read
        ``ARTIFACT.MOVE_FAILED`` (reading 26)."""
        if not isinstance(confined, ConfinedPath):
            raise TypeError("confined must be a ConfinedPath")
        digest = _stream_confined(confined, self._hasher.sha256_stream, now_utc)
        if isinstance(digest, Failure):
            return digest
        return Success[Sha256](outcome="SUCCESS", value=digest)

    def _hash_path(self, path: Path) -> Sha256:
        """Stream a blob the store holds no confined identity for -- the existing
        finalized blob of the dedup branch -- through the port; an ``OSError`` is
        the caller's to classify as a storage failure."""
        with path.open("rb") as handle:
            return self._hasher.sha256_stream(handle)

    def _content_address_of(self, target: Path) -> str:
        name = target.name
        if not _is_sha256_hex(name) or target != self._objects_root / name[:2] / name:
            raise ValueError("target must be the content-addressed path under objects/")
        return name

    def atomic_move(
        self, confined: ConfinedPath, target: Path, *, now_utc: datetime
    ) -> Result[MoveOutcome]:
        """Plan 6.5 and reading 21: the one move primitive into the store."""
        if not isinstance(confined, ConfinedPath):
            raise TypeError("confined must be a ConfinedPath")
        if not isinstance(target, Path):
            raise TypeError("target must be a Path")
        expected = self._content_address_of(target)
        prepared = self._reopen_and_fsync(confined, now_utc)
        if prepared is not None:
            return prepared
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return _move_failed("the finalized shard could not be created", now_utc)
        try:
            confined.path.rename(target)
        except FileExistsError:
            return self._deduplicate(confined, target, expected, now_utc)
        except OSError:
            return _move_failed("the candidate could not be moved", now_utc)
        return Success[InstanceOf[MoveOutcome]](
            outcome="SUCCESS",
            value=MoveOutcome(source=confined.path, target=target, deduplicated=False),
        )

    def _deduplicate(
        self, confined: ConfinedPath, target: Path, expected: str, now_utc: datetime
    ) -> Result[MoveOutcome]:
        """Reading 21: both the existing blob and the candidate must hash to the
        content address before the candidate bytes are removed -- the blob streamed
        by path, the candidate through its identity-checked handle; a differing
        digest is an invariant violation, a blob that cannot be read is a storage
        failure (reading 26), and in neither case is anything overwritten or
        deleted."""
        try:
            existing = self._hash_path(target)
        except OSError:
            return _move_failed(
                "the existing finalized blob could not be read", now_utc
            )
        candidate = self.hash_confined(confined, now_utc=now_utc)
        if isinstance(candidate, Failure):
            return candidate
        if existing != expected or candidate.value != expected:
            return _store_failure(
                CORE_INVARIANT_VIOLATION,
                message="an existing finalized blob differs from the content hash",
                now_utc=now_utc,
            )
        try:
            confined.path.unlink()
        except OSError:
            return _move_failed(
                "the deduplicated candidate could not be removed", now_utc
            )
        return Success[InstanceOf[MoveOutcome]](
            outcome="SUCCESS",
            value=MoveOutcome(source=confined.path, target=target, deduplicated=True),
        )

    def quarantine_move(
        self,
        confined: ConfinedPath,
        entry_id: str,
        reason: str,
        *,
        now_utc: datetime,
        sha256: str | MISSING = MISSING,  # type: ignore[valid-type]
    ) -> Result[QuarantineOutcome]:
        """Plan 6.2 and 6.5: the same primitive toward the quarantine root, and
        ``quarantine.json`` exclusive-create once per entry. Admits candidate
        paths alone: an orphan confinement, whose relative path the candidate
        grammar refuses, is refused here before the reopen, the rename or the
        metadata -- it is quarantined through ``quarantine_orphan``."""
        if not isinstance(confined, ConfinedPath):
            raise TypeError("confined must be a ConfinedPath")
        _require_entry_id(entry_id)
        _require_error_code(reason)
        if isinstance(sha256, str):
            _require_sha256_hex(sha256, "sha256")
        try:
            lexical_candidate_path(confined.relative)
        except ValueError as error:
            raise ValueError(
                "quarantine_move admits a candidate path alone; an orphan is "
                "quarantined through quarantine_orphan"
            ) from error
        prepared = self._reopen_and_fsync(confined, now_utc)
        if prepared is not None:
            return prepared
        entry_root = self._quarantine_root / entry_id
        target = entry_root.joinpath(*confined.relative.split("/"))
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return _move_failed("the quarantine entry could not be created", now_utc)
        try:
            confined.path.rename(target)
        except FileExistsError:
            return _store_failure(
                CORE_INVARIANT_VIOLATION,
                message="a quarantine target already exists",
                now_utc=now_utc,
            )
        except OSError:
            return _move_failed("the candidate could not be quarantined", now_utc)
        metadata_path = entry_root / QUARANTINE_METADATA_NAME
        facts: dict[str, object] = {
            "schema_version": "1.0.0",
            "entry_id": entry_id,
            "reason_code": reason,
            "quarantined_at_utc": now_utc,
            "source_root": str(confined.root),
            "relative_path": confined.relative,
            "size_bytes": confined.identity.st_size,
        }
        if isinstance(sha256, str):
            facts["sha256"] = sha256
        metadata = QuarantineMetadata.model_validate(facts)
        written = self._write_metadata(
            metadata_path, canonical_json_bytes(metadata), now_utc
        )
        if isinstance(written, Failure):
            return written
        return Success[InstanceOf[QuarantineOutcome]](
            outcome="SUCCESS",
            value=QuarantineOutcome(
                entry_id=entry_id,
                target=target,
                metadata_path=metadata_path,
                metadata_written=written,
            ),
        )

    def quarantine_orphan(
        self,
        confined: ConfinedPath,
        entry_id: str,
        reason: str,
        *,
        now_utc: datetime,
    ) -> Result[QuarantineOutcome]:
        """Task 6 RV-9 file-map correction: quarantine an orphan file beneath this
        store's ``objects/`` root -- a file the store never wrote, confined by
        ``confine_orphan_path`` because its ordinary name is outside the candidate
        grammar or because its layout is no canonical object -- to the plan 6.2
        layout ``<quarantine_root>/<entry_id>/<original relative path>``: the entry
        keyed by the identity the caller derived, the bytes at the very
        root-relative path they were found at.

        Every rule precedes every filesystem action: the entry id and reason
        grammars, the entry id forming one candidate-grammar segment; the source
        rooted at this store's artifacts root beneath ``objects/`` at a path that
        is no canonical object by ``canonical_content_address`` -- the complete
        layout ``objects/<hh>/<sha256>`` with the shard matching the leaf, in any
        case the supported case-insensitive store spells it, is quarantined
        through ``quarantine_move`` with its digest claim, while a leaf that
        merely resembles a content address under any other directory is
        misplaced content and an orphan here, with no digest claimed for it; and
        the metadata, validated and serialized here so a refused representation
        strands nothing. The orphan confinement is then repeated and its identity
        compared (a change is ``ARTIFACT.VALIDATION_FAILED``), the handle
        identity is compared and ``fsync``ed by the shared primitive, a reparse
        point where the entry root or any directory of the destination path
        belongs is refused before the walk creates anything on its far side, the
        same-volume rename never overwrites, and ``quarantine.json`` -- the path
        as ``relative_path``, no digest -- is written exclusive-create once per
        entry.
        """
        if not isinstance(confined, ConfinedPath):
            raise TypeError("confined must be a ConfinedPath")
        _require_entry_id(entry_id)
        _require_error_code(reason)
        try:
            lexical_candidate_path(entry_id)
        except ValueError as error:
            raise ValueError("entry id must form a candidate path segment") from error
        if confined.root != self._artifacts_root:
            raise ValueError("an orphan is confined under this store's artifacts root")
        segments = confined.relative.split("/")
        if len(segments) < 2 or segments[0] != OBJECTS_SEGMENT:
            raise ValueError("an orphan lies beneath objects/")
        if canonical_content_address(confined.relative) is not None:
            raise ValueError(
                "a canonical content address is quarantined through quarantine_move"
            )
        try:
            metadata = QuarantineMetadata.model_validate(
                {
                    "schema_version": "1.0.0",
                    "entry_id": entry_id,
                    "reason_code": reason,
                    "quarantined_at_utc": now_utc,
                    "source_root": str(confined.root),
                    "relative_path": confined.relative,
                    "size_bytes": confined.identity.st_size,
                }
            )
        except ValueError:
            return artifact_failure(
                ARTIFACT_VALIDATION_FAILED,
                message="the orphan admits no quarantine metadata",
                now_utc=now_utc,
            )
        payload = canonical_json_bytes(metadata)
        rechecked = confine_orphan_path(
            confined.root, confined.relative, now_utc=now_utc
        )
        if isinstance(rechecked, Failure):
            return rechecked
        if rechecked.value.identity != confined.identity:
            return artifact_failure(
                ARTIFACT_VALIDATION_FAILED,
                message=CHANGED_WHILE_FINALIZING,
                now_utc=now_utc,
            )
        prepared = self._reopen_and_fsync(confined, now_utc)
        if prepared is not None:
            return prepared
        entry_root = self._quarantine_root / entry_id
        target = entry_root.joinpath(*segments)
        destination_directories = [entry_root]
        for segment in segments[:-1]:
            destination_directories.append(destination_directories[-1] / segment)
        for component in destination_directories:
            try:
                attributes = _attributes(component)
            except OSError:
                continue
            if _is_reparse_point(attributes):
                return artifact_failure(
                    ARTIFACT_PATH_BOUNDARY_VIOLATION,
                    message="the quarantine destination is a reparse point",
                    now_utc=now_utc,
                )
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return _move_failed("the quarantine entry could not be created", now_utc)
        try:
            confined.path.rename(target)
        except FileExistsError:
            return _store_failure(
                CORE_INVARIANT_VIOLATION,
                message="a quarantine target already exists",
                now_utc=now_utc,
            )
        except OSError:
            return _move_failed("the orphan could not be quarantined", now_utc)
        metadata_path = entry_root / QUARANTINE_METADATA_NAME
        written = self._write_metadata(metadata_path, payload, now_utc)
        if isinstance(written, Failure):
            return written
        return Success[InstanceOf[QuarantineOutcome]](
            outcome="SUCCESS",
            value=QuarantineOutcome(
                entry_id=entry_id,
                target=target,
                metadata_path=metadata_path,
                metadata_written=written,
            ),
        )

    def _write_metadata(
        self, metadata_path: Path, payload: bytes, now_utc: datetime
    ) -> bool | Failure:
        """``quarantine.json`` exclusive-create: ``True`` once written and
        ``fsync``ed, ``False`` when the entry already carries one (never
        overwritten), the storage posture when the write is refused."""
        try:
            with metadata_path.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            return False
        except OSError:
            return _move_failed("the quarantine metadata could not be written", now_utc)
        return True

    def quarantine_entries(self) -> tuple[QuarantineEntry, ...]:
        """Every entry directory of the quarantine root, by name; a reparse point
        or a file at the root is not an entry and is never entered."""
        entries: list[QuarantineEntry] = []
        for child in sorted(self._quarantine_root.iterdir()):
            attributes = _attributes(child)
            if _is_reparse_point(attributes) or not _is_directory(attributes):
                continue
            entries.append(self._entry_of(child))
        return tuple(entries)

    def _entry_of(self, entry_root: Path) -> QuarantineEntry:
        reason: str | None = None
        instant: datetime | None = None
        try:
            with (entry_root / QUARANTINE_METADATA_NAME).open("rb") as handle:
                metadata = QuarantineMetadata.model_validate_json(
                    handle.read(_MAX_METADATA_BYTES)
                )
        except (OSError, ValueError):
            pass
        else:
            reason = metadata.reason_code
            instant = metadata.quarantined_at_utc
        files: list[str] = []
        pending: list[tuple[Path, int]] = [(entry_root, 0)]
        while pending:
            directory, depth = pending.pop()
            for child in directory.iterdir():
                attributes = _attributes(child)
                relative = child.relative_to(entry_root).as_posix()
                if _is_reparse_point(attributes):
                    continue
                # A directory at the depth bound is recorded as one entry, the
                # ``roots.py`` walk's own convention.
                if _is_directory(attributes) and depth + 1 < _MAX_WALK_DEPTH:
                    pending.append((child, depth + 1))
                elif relative != QUARANTINE_METADATA_NAME:
                    files.append(relative)
        return QuarantineEntry(
            entry_id=entry_root.name,
            reason_code=reason,
            quarantined_at_utc=instant,
            files=tuple(sorted(files)),
        )

    def remove_raw_bytes(self, paths: tuple[Path, ...]) -> RemovalReport:
        """Plan 4.3 phase 6: unlink raw-bearing files; a path whose inspection
        raises ``FileNotFoundError`` is reported as missing, while a directory, a
        reparse point, a path whose inspection fails for any other reason or a
        refused unlink is failed -- only actual absence implies absence, so an
        uninspectable source is retained."""
        removed: list[Path] = []
        missing: list[Path] = []
        failed: list[Path] = []
        for path in paths:
            if not isinstance(path, Path) or not path.is_absolute():
                raise ValueError("raw byte paths must be absolute Paths")
            try:
                attributes = _attributes(path)
            except FileNotFoundError:
                missing.append(path)
                continue
            except OSError:
                failed.append(path)
                continue
            if _is_reparse_point(attributes) or _is_directory(attributes):
                failed.append(path)
                continue
            try:
                path.unlink()
            except OSError:
                failed.append(path)
                continue
            removed.append(path)
        return RemovalReport(
            removed=tuple(removed), missing=tuple(missing), failed=tuple(failed)
        )

    def write_staged(
        self,
        owner_hash: str,
        staging_relative_path: str,
        payload: bytes,
        *,
        now_utc: datetime,
    ) -> Result[ConfinedPath]:
        """Plan 6.5: the only writer into core staging."""
        _require_sha256_hex(owner_hash, "owner hash")
        if type(payload) is not bytes:
            raise TypeError("payload must be bytes")
        try:
            relative = lexical_candidate_path(staging_relative_path)
        except ValueError as error:
            return artifact_failure(
                ARTIFACT_PATH_BOUNDARY_VIOLATION,
                message=f"staging path refused: {error}",
                now_utc=now_utc,
            )
        owner_root = self._staging_root / owner_hash
        target = owner_root.joinpath(*relative.split("/"))
        if _reparse_point_on_or_above(target.parent):
            return artifact_failure(
                ARTIFACT_PATH_BOUNDARY_VIOLATION,
                message="an existing component of the staging path is a reparse point",
                now_utc=now_utc,
            )
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
        except OSError:
            return _move_failed("the staging directory could not be created", now_utc)
        try:
            with target.open("xb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
        except FileExistsError:
            return self._replay_staged(owner_root, relative, payload, now_utc)
        except OSError:
            return _move_failed("the staged file could not be written", now_utc)
        return confine_candidate_path(owner_root, relative, now_utc=now_utc)

    def _replay_staged(
        self,
        owner_root: Path,
        relative: str,
        payload: bytes,
        now_utc: datetime,
    ) -> Result[ConfinedPath]:
        """An existing staged file is confined first -- a reparse point, a second
        hard link or a leaf outside the root is refused before a byte of it is
        read -- and then hashed through the identity-checked handle of
        ``hash_confined``; equal bytes replay, differing bytes are an invariant
        violation."""
        confined = confine_candidate_path(owner_root, relative, now_utc=now_utc)
        if isinstance(confined, Failure):
            return confined
        existing = self.hash_confined(confined.value, now_utc=now_utc)
        if isinstance(existing, Failure):
            return existing
        if existing.value != sha256_bytes(payload):
            return _store_failure(
                CORE_INVARIANT_VIOLATION,
                message="an existing staged file differs from the payload",
                now_utc=now_utc,
            )
        return confined


__all__ = (
    "CORE_INVARIANT_VIOLATION",
    "MANIFESTS_SEGMENT",
    "OBJECTS_SEGMENT",
    "PROCESS_PATH_PREFLIGHT_REJECTED",
    "QUARANTINE_METADATA_NAME",
    "STORE_DIAGNOSTIC_POSTURES",
    "ArtifactStore",
    "MoveOutcome",
    "QuarantineEntry",
    "QuarantineMetadata",
    "QuarantineOutcome",
    "RemovalReport",
    "canonical_content_address",
    "read_confined",
    "same_volume",
    "scan_confined",
)
