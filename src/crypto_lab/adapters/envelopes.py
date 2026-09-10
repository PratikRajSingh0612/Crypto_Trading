"""Request envelopes and request material (Stage 6 plan sections 3.6, 4, 5.1, 5.2
and 6.1; specification 11.3, 14.2 and 14.3).

Three wire records cross the adapter trust boundary from the core side:
``DescribeRequestPayload`` (token-free), ``EngineRunRequest`` (token-bearing, one
per attempt) and ``AdapterCommandRequestEnvelope`` (the command-discriminated
wrapper the launcher writes). All three are trust class W: temporary request
material, never persisted, never finalized (specification 10.2). The nested value
objects ``WorkDirectoryReference``, ``RunConfigurationSnapshot`` and
``NegotiatedVersions`` carry no envelope version (plan 3.1), and
``SanitizedEngineRunRequest`` is the class-C snapshot with ``attempt_token_hash``
in the token's place, built only by ``sanitize_engine_run_request``.

**Request identity.** ``request_hash`` is the ``ADAPTER_REQUEST_V1`` profile over
the pre-attempt material alone (plan 4): ``experiment_id``, ``logical_slot_id``,
``attempt_number``, the strategy, dataset, configuration and experiment-spec
hashes, the slot's ``adapter`` and ``engine``, the ``configuration_snapshot``,
``comparison_level``, ``negotiated_versions`` and
``assigned_work_dir.authorized_root``. The named exclusions are every field minted
by or after ``create_attempt`` -- ``run_id``, ``request_id``, ``attempt_token``,
``attempt_token_hash``, ``assigned_work_dir.relative_path``, ``created_at_utc`` --
plus ``schema_version``, ``protocol_version`` and ``request_hash`` itself, so
``request_material_hash`` computes it before the run exists and
``request_hash_of`` recomputes it from the finished raw or sanitized request. For
``DESCRIBE`` the same profile covers the canonical describe payload. The payload
is assembled in exactly one place, ``_run_material_payload``. ``payload_hash``
and every other exact-byte hash stay outside the profile envelope so a
conforming adapter can verify them with ``hashlib`` alone.

**Versions.** Both version fields are the exact literal ``"1.0.0"`` (plan 5.1):
the core supports one protocol version and a future version is a new model and a
new ``$id``. ``NegotiatedVersions.schema_versions`` names exactly the five
``NEGOTIABLE_SCHEMA_NAMES`` (plan 5.2). Every version collection is sorted
numerically -- ``parse_semantic_version`` for versions and the integer after
``capabilities/v`` for vocabularies -- the rule the merged descriptor applies, so
``1.9.0`` precedes ``1.10.0``.

**The raw token.** ``EngineRunRequest.attempt_token`` is the single field of this
module annotated ``AttemptToken``; it is hidden from ``repr`` and ``str``, it is
dumped because the launcher must write it, and ``request_envelope_bytes`` is the
only function that emits it. ``CanonicalModel`` hides validation input, so no
error text can echo it; the validator messages below name fields, never values.

Task-local readings, declared rather than inferred silently:

- ``request_hash_of`` is total over the three request-material types; the
  describe identity of plan 4 and 6.1 is reached through it rather than through a
  second public name.
- ``request_material_hash`` requires the experiment's frozen ``slot_compatibility``
  (present in every state that admits an attempt), because the snapshot copies the
  slot's approximation identities from it; a slot the spec does not select, or a
  missing frozen slot, is a ``ValueError``.
- ``build_engine_run_request`` checks the token's run and its hash against the
  run's durable ``attempt_token_hash`` (specification 15.6 and 15.7: the computed
  token hash must match durable facts), the run's experiment, the slot's adapter
  and engine against the run record, and the recomputed material against
  ``run.request_hash`` before any model is built, so a mismatch is a named
  ``ValueError`` and never a validation error carrying request material.
  ``created_at_utc`` is the caller's injected-clock instant, copied verbatim.
- ``build_request_envelope`` requires the invocation to be ``STARTING`` (the
  envelope is written at launch, after the paired-clock deadline exists), pairs
  the payload type with the invocation's command kind by name first (a
  ``ValueError`` naming ``DESCRIBE``; the model restates the pairing as its own
  validator for envelopes built without the builder), and requires the
  invocation's ``run_id``, ``request_hash`` and adapter identity to agree with the
  payload (specification 14.3: the envelope, invocation and attempt identity are
  one coherent unit). The ``request_hash`` agreement holds for ``VALIDATE`` as
  well as ``RUN``, although Stage 5 admission pins it only for ``RUN``. The
  describe ``request_id`` anchors on the invocation identity; a run payload must
  already carry ``request_id_for(run_id)`` (plan 6.1, 9.2), so a foreign identity
  is refused here rather than blamed on the adapter that echoes it.
- Neither model pins ``request_id`` to its anchor: plan 3.6 lists no such
  validator and plan 14 Task 2 proves the profile's exclusions with an
  independently varied ``request_id``; derivation is the builders' rule.
- Every ``ValueError`` these builders raise interpolates identifiers, hashes,
  states and command kinds only, never a token, a payload, a dump or a ``repr``.
- Published exactly (plan 12.3), beyond the plan-mandated command<->payload
  pairing: the per-command ``timeout_seconds`` maximum on the envelope and the
  exact five names by position on ``NegotiatedVersions.schema_versions``.
  Runtime-only (for the Task 9 register): the deadline arithmetic, the
  ``payload_hash``/``request_hash`` recomputations, ``payload.request_id ==
  request_id``, the ``comparison_level`` agreement, the positive
  ``starting_balance``, and the numeric sortedness of the version collections.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import ClassVar, Final, Literal, Self, cast

from pydantic import ConfigDict, Field, JsonValue, field_validator, model_validator
from pydantic.experimental.missing_sentinel import MISSING
from pydantic.json_schema import JsonSchemaValue

from crypto_lab.adapters.limits import MAX_APPROXIMATIONS, ProtocolLimits
from crypto_lab.adapters.paths import RelativeCandidatePath
from crypto_lab.adapters.vocabulary import NEGOTIABLE_SCHEMA_NAMES
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.capability_names import VocabularyVersion
from crypto_lab.domain.command_invocation import (
    MAX_RUN_TIMEOUT_SECONDS,
    MIN_TIMEOUT_SECONDS,
    CommandInvocationRecord,
    command_timeout_bounds,
)
from crypto_lab.domain.comparison_levels import ComparisonLevel
from crypto_lab.domain.descriptors import SupportedSchemaVersion
from crypto_lab.domain.engine_run import AttemptTokenMaterial, EngineRunRecord
from crypto_lab.domain.experiment import (
    AdapterIdentity,
    EngineIdentity,
    ExecutionAssumptions,
    ExperimentRecord,
    FeeAssumptions,
    SelectedEngineSlot,
    SlippageAssumptions,
    SlotCompatibility,
)
from crypto_lab.domain.hashing import (
    HashingProfile,
    attempt_token_hash,
    profile_hash,
    request_id_for,
    sha256_bytes,
)
from crypto_lab.domain.identifiers import (
    ApproximationId,
    AttemptToken,
    ExperimentId,
    InvocationId,
    LogicalSlotId,
    NormalizedIdentifier,
    RequestId,
    RunId,
    Sha256,
)
from crypto_lab.domain.lifecycle import CommandInvocationState, CommandKind
from crypto_lab.domain.records import Money
from crypto_lab.domain.retry import MAX_ATTEMPTS_PER_SLOT
from crypto_lab.domain.time import CalendarValidUtcDateTime
from crypto_lab.domain.versioning import SemanticVersion, parse_semantic_version

#: Plan 3.6: the one authorized root label a request may name; the absolute
#: directory travels only on the argument array (specification 11.3).
AUTHORIZED_ROOT: Final = "RUNTIME_ROOT"
_VOCABULARY_PREFIX: Final = "capabilities/v"
_NEGOTIABLE_COUNT: Final = len(NEGOTIABLE_SCHEMA_NAMES)
_NEGOTIABLE_SET: Final[frozenset[str]] = frozenset(NEGOTIABLE_SCHEMA_NAMES)
#: The payload union members in annotation order (``DescribeRequestPayload |
#: EngineRunRequest``), by bare class name, and the command each one serves.
_PAYLOAD_MODELS: Final[tuple[str, ...]] = ("DescribeRequestPayload", "EngineRunRequest")
_PAYLOAD_BY_COMMAND: Final[tuple[tuple[CommandKind, str], ...]] = (
    (CommandKind.DESCRIBE, "DescribeRequestPayload"),
    (CommandKind.VALIDATE, "EngineRunRequest"),
    (CommandKind.RUN, "EngineRunRequest"),
)


def _is_missing(value: object) -> bool:
    return value is MISSING


def _unique_sorted_versions(
    value: tuple[str, ...],
    label: str,
) -> tuple[str, ...]:
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must be unique")
    if value != tuple(sorted(value, key=parse_semantic_version)):
        raise ValueError(f"{label} must be numerically sorted")
    return value


def _unique_sorted_schema_versions(
    value: tuple[SupportedSchemaVersion, ...],
    label: str,
) -> tuple[SupportedSchemaVersion, ...]:
    """The merged ``AdapterDescriptor.validate_schema_versions`` rule."""
    keys = tuple(
        (item.schema_name, parse_semantic_version(item.schema_version))
        for item in value
    )
    if len(set(keys)) != len(keys):
        raise ValueError(f"{label} must be unique")
    if keys != tuple(sorted(keys)):
        raise ValueError(f"{label} must be sorted")
    return value


def _vocabulary_ordinal(value: str) -> int:
    return int(value.removeprefix(_VOCABULARY_PREFIX))


def _unique_sorted_vocabularies(
    value: tuple[str, ...],
    label: str,
) -> tuple[str, ...]:
    if len(set(value)) != len(value):
        raise ValueError(f"{label} must be unique")
    if value != tuple(sorted(value, key=_vocabulary_ordinal)):
        raise ValueError(f"{label} must be numerically sorted")
    return value


class DescribeRequestPayload(CanonicalModel):
    """The token-free ``describe`` payload (plan 3.6; specification 14.2, 14.3).

    ``bootstrap_schema_version`` first, per the fixed bootstrap fields of
    specification 14.2; then the catalog identity the core expects the adapter
    to describe and the versions the core supports, each collection bounded,
    unique and numerically sorted. Vocabulary versions sort by the integer after
    ``capabilities/v`` -- the plan 3.8 and 5.3 rule, applied here as the declared
    reading of plan 3.6's "sorted unique" so the describe, bootstrap and
    negotiation collections share one order.
    """

    bootstrap_schema_version: Literal["1.0.0"]
    adapter_name: NormalizedIdentifier
    adapter_version: SemanticVersion
    executable_hash: Sha256
    core_supported_protocol_versions: tuple[SemanticVersion, ...] = Field(
        min_length=1, max_length=32, json_schema_extra={"uniqueItems": True}
    )
    core_supported_schema_versions: tuple[SupportedSchemaVersion, ...] = Field(
        min_length=1, max_length=128, json_schema_extra={"uniqueItems": True}
    )
    core_capability_vocabulary_versions: tuple[VocabularyVersion, ...] = Field(
        min_length=1, max_length=8, json_schema_extra={"uniqueItems": True}
    )

    @field_validator("core_supported_protocol_versions")
    @classmethod
    def validate_protocol_versions(
        cls,
        value: tuple[SemanticVersion, ...],
    ) -> tuple[SemanticVersion, ...]:
        return _unique_sorted_versions(value, "core supported protocol versions")

    @field_validator("core_supported_schema_versions")
    @classmethod
    def validate_schema_versions(
        cls,
        value: tuple[SupportedSchemaVersion, ...],
    ) -> tuple[SupportedSchemaVersion, ...]:
        return _unique_sorted_schema_versions(value, "core supported schema versions")

    @field_validator("core_capability_vocabulary_versions")
    @classmethod
    def validate_vocabulary_versions(
        cls,
        value: tuple[VocabularyVersion, ...],
    ) -> tuple[VocabularyVersion, ...]:
        return _unique_sorted_vocabularies(value, "core capability vocabulary versions")


class WorkDirectoryReference(CanonicalModel):
    """An authorized root label plus a safe relative reference (plan 3.6).

    Specification 11.3: the work directory is absolute in the launcher but
    serialized as an authorized root plus safe relative references. A nested
    value object, so it carries no envelope version.
    """

    authorized_root: Literal["RUNTIME_ROOT"]
    relative_path: RelativeCandidatePath


class RunConfigurationSnapshot(CanonicalModel):
    """The material assumptions and protocol limits the adapter needs (plan 3.6).

    Copied from the frozen ``ExperimentSpec``, the frozen slot compatibility
    (``approximation_ids``, so the adapter can echo them in its manifest) and the
    queued configuration (``limits``). The declared reading of specification
    11.3 ``configuration_snapshot``, 13.4 and 15.3. A nested value object.
    """

    starting_balance: Money
    fee_assumptions: FeeAssumptions
    slippage_assumptions: SlippageAssumptions
    execution_assumptions: ExecutionAssumptions
    comparison_level: ComparisonLevel
    approximation_ids: tuple[ApproximationId, ...] = Field(
        max_length=MAX_APPROXIMATIONS, json_schema_extra={"uniqueItems": True}
    )
    limits: ProtocolLimits

    @field_validator("starting_balance")
    @classmethod
    def validate_starting_balance(cls, value: Money) -> Money:
        """The ``ExperimentSpec`` rule restated: released ``Money`` admits zero."""
        if value.amount <= 0:
            raise ValueError("starting balance must be positive")
        return value

    @field_validator("approximation_ids")
    @classmethod
    def validate_approximation_ids(
        cls,
        value: tuple[ApproximationId, ...],
    ) -> tuple[ApproximationId, ...]:
        """Order carries no meaning, so it is canonicalized by rejection."""
        if len(set(value)) != len(value):
            raise ValueError("approximation identifiers must be unique")
        if value != tuple(sorted(value)):
            raise ValueError("approximation identifiers must be sorted")
        return value


def _negotiated_schema_extra(schema: JsonSchemaValue) -> None:
    """Publish the exact-five-names rule of ``schema_versions`` as ``prefixItems``.

    Sorted by name over the closed five-name set fixes every position, so the
    rule is exactly expressible (plan 12.3): position ``i`` names
    ``NEGOTIABLE_SCHEMA_NAMES[i]``. With five ``prefixItems`` and ``maxItems`` 5
    the per-element ``items`` reference never applies, so each prefix item
    restates the emitted ``SupportedSchemaVersion`` reference in an ``allOf``
    beside the ``schema_name`` constant. The emitted reference is reused for the
    same reason as in ``_envelope_schema_extra``.
    """
    field = schema["properties"]["schema_versions"]
    items = field.get("items")
    if not isinstance(items, dict) or set(items) != {"$ref"}:
        raise RuntimeError("the emitted schema_versions items is not a bare $ref")
    field["prefixItems"] = [
        {
            "allOf": [
                {"$ref": items["$ref"]},
                {
                    "properties": {"schema_name": {"const": name}},
                    "required": ["schema_name"],
                },
            ]
        }
        for name in NEGOTIABLE_SCHEMA_NAMES
    ]


class NegotiatedVersions(CanonicalModel):
    """The versions negotiation chose, pinned in the request (plan 3.6, 5.2).

    Specification 14.2: "chosen versions are pinned in the request". Exactly the
    five negotiable schema names, once each, sorted (published exactly as
    ``prefixItems`` by ``_negotiated_schema_extra``); the protocol version is the
    single literal the core supports. The per-name ``schema_version`` values are
    deliberately constrained only as ``SemanticVersion``: they are negotiation's
    selection (Task 3) from the adapter's declared lists, not a rule of this
    record. A nested value object.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_negotiated_schema_extra
    )

    protocol_version: Literal["1.0.0"]
    schema_versions: tuple[SupportedSchemaVersion, ...] = Field(
        min_length=_NEGOTIABLE_COUNT,
        max_length=_NEGOTIABLE_COUNT,
        json_schema_extra={"uniqueItems": True},
    )
    capability_vocabulary_version: VocabularyVersion

    @field_validator("schema_versions")
    @classmethod
    def validate_schema_versions(
        cls,
        value: tuple[SupportedSchemaVersion, ...],
    ) -> tuple[SupportedSchemaVersion, ...]:
        names = tuple(item.schema_name for item in value)
        if len(set(names)) != len(names) or set(names) != _NEGOTIABLE_SET:
            raise ValueError(
                "schema_versions must name exactly the negotiable schema names, "
                "once each"
            )
        return _unique_sorted_schema_versions(value, "negotiated schema versions")


class EngineRunRequest(CanonicalModel):
    """The temporary immutable adapter payload for one attempt (plan 3.6).

    Specification 11.3's row in order, plus the pinned ``negotiated_versions``
    and the two provenance hashes the manifest must echo. Trust class W and
    token-bearing: never persisted or finalized; its authoritative snapshot is
    ``SanitizedEngineRunRequest``. The token is hidden from ``repr``.
    """

    schema_version: Literal["1.0.0"]
    protocol_version: Literal["1.0.0"]
    request_id: RequestId
    experiment_id: ExperimentId
    run_id: RunId
    logical_slot_id: LogicalSlotId
    attempt_number: int = Field(ge=1, le=MAX_ATTEMPTS_PER_SLOT)
    attempt_token: AttemptToken = Field(repr=False)
    strategy_version_hash: Sha256
    dataset_version_hash: Sha256
    adapter: AdapterIdentity
    engine: EngineIdentity
    configuration_snapshot: RunConfigurationSnapshot
    configuration_hash: Sha256
    comparison_level: ComparisonLevel
    negotiated_versions: NegotiatedVersions
    assigned_work_dir: WorkDirectoryReference
    experiment_spec_hash: Sha256
    request_hash: Sha256
    created_at_utc: CalendarValidUtcDateTime

    @model_validator(mode="after")
    def validate_material_agreement(self) -> Self:
        _require_request_agreement(self)
        return self


class SanitizedEngineRunRequest(CanonicalModel):
    """The class-C snapshot of a request: ``attempt_token_hash`` in the token's
    place, every other field identical (plan 3.6). Unpublished; built only by
    ``sanitize_engine_run_request``."""

    schema_version: Literal["1.0.0"]
    protocol_version: Literal["1.0.0"]
    request_id: RequestId
    experiment_id: ExperimentId
    run_id: RunId
    logical_slot_id: LogicalSlotId
    attempt_number: int = Field(ge=1, le=MAX_ATTEMPTS_PER_SLOT)
    attempt_token_hash: Sha256
    strategy_version_hash: Sha256
    dataset_version_hash: Sha256
    adapter: AdapterIdentity
    engine: EngineIdentity
    configuration_snapshot: RunConfigurationSnapshot
    configuration_hash: Sha256
    comparison_level: ComparisonLevel
    negotiated_versions: NegotiatedVersions
    assigned_work_dir: WorkDirectoryReference
    experiment_spec_hash: Sha256
    request_hash: Sha256
    created_at_utc: CalendarValidUtcDateTime

    @model_validator(mode="after")
    def validate_material_agreement(self) -> Self:
        _require_request_agreement(self)
        return self


def _envelope_schema_extra(schema: JsonSchemaValue) -> None:
    """Publish the command<->payload pairing as three ``if``/``then`` clauses.

    Plan 3.6: the pairing is exactly expressible, so the committed bytes reject
    a swapped payload as the runtime does. Pydantic renders ``payload`` as a bare
    two-member ``anyOf`` in annotation order; each clause pins one member by the
    ``command`` constant. The branch references are the ones pydantic just
    emitted (the ``strategy/expressions.py`` precedent): at hook time they are
    internal defs-refs that pydantic remaps afterwards, so a hand-built
    ``#/$defs/...`` would dangle. The emitted shape is pinned before it is reused.
    """
    branches = schema["properties"]["payload"].get("anyOf")
    if (
        not isinstance(branches, list)
        or len(branches) != len(_PAYLOAD_MODELS)
        or any(set(branch) != {"$ref"} for branch in branches)
    ):
        raise RuntimeError("the emitted payload union is not a bare anyOf of $refs")
    references: dict[str, str] = {}
    for model, branch in zip(_PAYLOAD_MODELS, branches, strict=True):
        reference = branch["$ref"]
        # The internal defs-ref is module-qualified (`pkg__module__Class`) and may
        # carry pydantic's `-Input__N` mode and counter suffix; only the bare class
        # name before the first `-` is pinned. Class names carry no `-`.
        emitted_name = str(reference).rsplit("/", 1)[-1].split("-", 1)[0]
        if not isinstance(reference, str) or not (
            emitted_name == model or emitted_name.endswith(f"__{model}")
        ):
            raise RuntimeError(
                "the payload union branches are not in annotation order: "
                f"{[branch['$ref'] for branch in branches]!r}"
            )
        references[model] = reference
    schema.setdefault("allOf", []).extend(
        {
            "if": {
                "properties": {"command": {"const": kind.value}},
                "required": ["command"],
            },
            "then": {
                "properties": {
                    "payload": {"$ref": references[model]},
                    "timeout_seconds": {
                        "maximum": command_timeout_bounds(kind).maximum_seconds
                    },
                }
            },
        }
        for kind, model in _PAYLOAD_BY_COMMAND
    )


class AdapterCommandRequestEnvelope(CanonicalModel):
    """The temporary command-discriminated request wrapper (plan 3.6; spec 14.3).

    Field order follows specification 11.3 (``schema_version`` first, the plan's
    resolution of the 14.3 listing). The header never carries the token: it is
    inside the ``EngineRunRequest`` payload exactly once and absent from a
    describe envelope. Trust class W, never persisted.
    """

    model_config: ClassVar[ConfigDict] = ConfigDict(
        json_schema_extra=_envelope_schema_extra
    )

    schema_version: Literal["1.0.0"]
    protocol_version: Literal["1.0.0"]
    request_id: RequestId
    invocation_id: InvocationId
    command: CommandKind
    created_at_utc: CalendarValidUtcDateTime
    timeout_seconds: int = Field(ge=MIN_TIMEOUT_SECONDS, le=MAX_RUN_TIMEOUT_SECONDS)
    deadline_utc: CalendarValidUtcDateTime
    payload_hash: Sha256
    payload: DescribeRequestPayload | EngineRunRequest

    @model_validator(mode="after")
    def validate_header_and_payload(self) -> Self:
        describe = isinstance(self.payload, DescribeRequestPayload)
        if describe is not (self.command is CommandKind.DESCRIBE):
            raise ValueError(
                "a DESCRIBE envelope carries a DescribeRequestPayload and a "
                "VALIDATE or RUN envelope an EngineRunRequest"
            )
        bounds = command_timeout_bounds(self.command)
        if not bounds.minimum_seconds <= self.timeout_seconds <= bounds.maximum_seconds:
            raise ValueError(
                f"timeout_seconds must be within {bounds.minimum_seconds}.."
                f"{bounds.maximum_seconds} for {self.command.value}"
            )
        if self.deadline_utc != self.created_at_utc + timedelta(
            seconds=self.timeout_seconds
        ):
            raise ValueError("deadline_utc must equal created_at_utc + timeout_seconds")
        if (
            isinstance(self.payload, EngineRunRequest)
            and self.payload.request_id != self.request_id
        ):
            raise ValueError("request_id must equal payload.request_id")
        if self.payload_hash != payload_hash_of(self.payload):
            raise ValueError(
                "payload_hash must equal the SHA-256 of the canonical payload"
            )
        return self


# --- Hashes and identity ----------------------------------------------------------


def payload_hash_of(payload: DescribeRequestPayload | EngineRunRequest) -> Sha256:
    """Plan 4: ``sha256(canonical_json_bytes(payload))``, exact-byte and
    stdlib-reproducible, deliberately outside the profile envelope."""
    if not isinstance(payload, DescribeRequestPayload | EngineRunRequest):
        raise TypeError(
            "payload must be a DescribeRequestPayload or an EngineRunRequest"
        )
    return sha256_bytes(canonical_json_bytes(payload))


def _json(value: CanonicalModel) -> JsonValue:
    return cast("JsonValue", value.model_dump(mode="json"))


def _run_material_payload(
    *,
    experiment_id: ExperimentId,
    logical_slot_id: LogicalSlotId,
    attempt_number: int,
    strategy_version_hash: Sha256,
    dataset_version_hash: Sha256,
    configuration_hash: Sha256,
    experiment_spec_hash: Sha256,
    adapter: AdapterIdentity,
    engine: EngineIdentity,
    configuration_snapshot: RunConfigurationSnapshot,
    comparison_level: ComparisonLevel,
    negotiated_versions: NegotiatedVersions,
) -> dict[str, JsonValue]:
    """The ``ADAPTER_REQUEST_V1`` payload of plan 4, assembled in one place.

    Exactly the pre-attempt material; ``assigned_work_dir`` carries only its
    ``authorized_root``. No identity, token, instant, version literal or self-hash
    enters.
    """
    return {
        "experiment_id": experiment_id,
        "logical_slot_id": logical_slot_id,
        "attempt_number": attempt_number,
        "strategy_version_hash": strategy_version_hash,
        "dataset_version_hash": dataset_version_hash,
        "configuration_hash": configuration_hash,
        "experiment_spec_hash": experiment_spec_hash,
        "adapter": _json(adapter),
        "engine": _json(engine),
        "configuration_snapshot": _json(configuration_snapshot),
        "comparison_level": comparison_level.value,
        "negotiated_versions": _json(negotiated_versions),
        "assigned_work_dir": {"authorized_root": AUTHORIZED_ROOT},
    }


def request_hash_of(
    request: DescribeRequestPayload | EngineRunRequest | SanitizedEngineRunRequest,
) -> Sha256:
    """Recompute the ``ADAPTER_REQUEST_V1`` identity of request material (plan 4).

    Total over the three request-material types: the describe payload hashes as
    its complete canonical document (the catalog-level describe identity of plan
    4 and 6.1); a raw or sanitized run request hashes as the pre-attempt material
    of ``_run_material_payload``, so both recompute the hash ``create_attempt``
    was given. Any other value is a programming error.
    """
    if isinstance(request, DescribeRequestPayload):
        payload = cast("dict[str, JsonValue]", request.model_dump(mode="json"))
    elif isinstance(request, EngineRunRequest | SanitizedEngineRunRequest):
        payload = _run_material_payload(
            experiment_id=request.experiment_id,
            logical_slot_id=request.logical_slot_id,
            attempt_number=request.attempt_number,
            strategy_version_hash=request.strategy_version_hash,
            dataset_version_hash=request.dataset_version_hash,
            configuration_hash=request.configuration_hash,
            experiment_spec_hash=request.experiment_spec_hash,
            adapter=request.adapter,
            engine=request.engine,
            configuration_snapshot=request.configuration_snapshot,
            comparison_level=request.comparison_level,
            negotiated_versions=request.negotiated_versions,
        )
    else:
        raise TypeError(
            "request material must be a DescribeRequestPayload, an EngineRunRequest "
            "or a SanitizedEngineRunRequest"
        )
    return profile_hash(HashingProfile.ADAPTER_REQUEST_V1, payload)


def _require_request_agreement(
    request: EngineRunRequest | SanitizedEngineRunRequest,
) -> None:
    """Plan 3.6 validators, shared by the raw and the sanitized request."""
    if request.comparison_level is not request.configuration_snapshot.comparison_level:
        raise ValueError(
            "comparison_level must equal configuration_snapshot.comparison_level"
        )
    if request.request_hash != request_hash_of(request):
        raise ValueError(
            "request_hash must equal the recomputed ADAPTER_REQUEST_V1 material hash"
        )


# --- Building request material -------------------------------------------------------


def _selected_slot(
    experiment: ExperimentRecord,
    logical_slot_id: str,
) -> tuple[SelectedEngineSlot, SlotCompatibility]:
    """The spec's slot and its frozen compatibility, or a named ``ValueError``."""
    if not isinstance(experiment, ExperimentRecord):
        raise TypeError("experiment must be an ExperimentRecord")
    selected = [
        slot
        for slot in experiment.spec.selected_engine_slots
        if slot.logical_slot_id == logical_slot_id
    ]
    if not selected:
        raise ValueError(
            f"{logical_slot_id} is not a selected slot of experiment "
            f"{experiment.experiment_id}"
        )
    if _is_missing(experiment.slot_compatibility):
        raise ValueError(
            "the experiment carries no frozen slot_compatibility; request material "
            "exists only from QUEUED onward"
        )
    # The record validator aligns the frozen entries with the selected slots, so
    # the matching entry always exists once the collection is present.
    frozen = next(
        entry
        for entry in experiment.slot_compatibility
        if entry.logical_slot_id == logical_slot_id
    )
    return selected[0], frozen


def _material(
    experiment: ExperimentRecord,
    slot: SelectedEngineSlot,
    frozen: SlotCompatibility,
    *,
    attempt_number: int,
    negotiated: NegotiatedVersions,
    limits: ProtocolLimits,
) -> tuple[RunConfigurationSnapshot, Sha256]:
    if type(attempt_number) is not int:
        raise TypeError("attempt_number must be a built-in integer")
    if not 1 <= attempt_number <= MAX_ATTEMPTS_PER_SLOT:
        raise ValueError(f"attempt_number must be within 1..{MAX_ATTEMPTS_PER_SLOT}")
    if not isinstance(negotiated, NegotiatedVersions):
        raise TypeError("negotiated must be a NegotiatedVersions record")
    if not isinstance(limits, ProtocolLimits):
        raise TypeError("limits must be a ProtocolLimits snapshot")
    spec = experiment.spec
    snapshot = RunConfigurationSnapshot(
        starting_balance=spec.starting_balance,
        fee_assumptions=spec.fee_assumptions,
        slippage_assumptions=spec.slippage_assumptions,
        execution_assumptions=spec.execution_assumptions,
        comparison_level=spec.comparison_level,
        approximation_ids=frozen.approximation_ids,
        limits=limits,
    )
    digest = profile_hash(
        HashingProfile.ADAPTER_REQUEST_V1,
        _run_material_payload(
            experiment_id=experiment.experiment_id,
            logical_slot_id=slot.logical_slot_id,
            attempt_number=attempt_number,
            strategy_version_hash=spec.strategy_version_hash,
            dataset_version_hash=spec.dataset_version_hash,
            configuration_hash=spec.configuration_hash,
            experiment_spec_hash=experiment.spec_hash,
            adapter=slot.adapter,
            engine=slot.engine,
            configuration_snapshot=snapshot,
            comparison_level=spec.comparison_level,
            negotiated_versions=negotiated,
        ),
    )
    return snapshot, digest


def request_material_hash(
    *,
    experiment: ExperimentRecord,
    logical_slot_id: LogicalSlotId,
    attempt_number: int,
    negotiated: NegotiatedVersions,
    limits: ProtocolLimits,
) -> Sha256:
    """Plan 6.1 step 1: the attempt's ``request_hash``, before the attempt exists.

    Assembles the pre-attempt material from the frozen spec, the frozen slot
    compatibility, the negotiated versions and the limits; the caller passes the
    result to ``create_attempt`` or ``create_successor``. Pure over its arguments.
    """
    slot, frozen = _selected_slot(experiment, logical_slot_id)
    _, digest = _material(
        experiment,
        slot,
        frozen,
        attempt_number=attempt_number,
        negotiated=negotiated,
        limits=limits,
    )
    return digest


def build_engine_run_request(
    *,
    run: EngineRunRecord,
    experiment: ExperimentRecord,
    token: AttemptTokenMaterial,
    negotiated: NegotiatedVersions,
    limits: ProtocolLimits,
    created_at_utc: datetime,
) -> EngineRunRequest:
    """Plan 6.1 step 2: the request of one created attempt.

    Copies the material ``request_material_hash`` hashed, adds the fields minted
    by ``create_attempt`` (``run_id``, the derived ``request_id``, the raw token,
    ``request_hash = run.request_hash``, the relative work path) and the
    caller's instant, and requires the recomputed material to equal
    ``run.request_hash`` before any model is built. Reads no clock: the instant
    is a parameter.
    """
    if not isinstance(run, EngineRunRecord):
        raise TypeError("run must be an EngineRunRecord")
    if not isinstance(token, AttemptTokenMaterial):
        raise TypeError("token must be AttemptTokenMaterial")
    if token.run_id != run.run_id:
        raise ValueError("the attempt token belongs to another run")
    if attempt_token_hash(token.attempt_token) != run.attempt_token_hash:
        raise ValueError(
            f"the attempt token does not belong to run {run.run_id}: its hash is not "
            "the run's attempt_token_hash"
        )
    if run.experiment_id != experiment.experiment_id:
        raise ValueError("the run belongs to another experiment")
    slot, frozen = _selected_slot(experiment, run.logical_slot_id)
    if run.adapter != slot.adapter:
        raise ValueError("the run's adapter is not the selected slot's adapter")
    if run.engine != slot.engine:
        raise ValueError("the run's engine is not the selected slot's engine")
    snapshot, digest = _material(
        experiment,
        slot,
        frozen,
        attempt_number=run.attempt_number,
        negotiated=negotiated,
        limits=limits,
    )
    if digest != run.request_hash:
        raise ValueError(
            "run.request_hash does not equal the recomputed request material hash"
        )
    spec = experiment.spec
    return EngineRunRequest(
        schema_version="1.0.0",
        protocol_version="1.0.0",
        request_id=request_id_for(run.run_id),
        experiment_id=run.experiment_id,
        run_id=run.run_id,
        logical_slot_id=run.logical_slot_id,
        attempt_number=run.attempt_number,
        attempt_token=token.attempt_token,
        strategy_version_hash=spec.strategy_version_hash,
        dataset_version_hash=spec.dataset_version_hash,
        adapter=slot.adapter,
        engine=slot.engine,
        configuration_snapshot=snapshot,
        configuration_hash=spec.configuration_hash,
        comparison_level=spec.comparison_level,
        negotiated_versions=negotiated,
        assigned_work_dir=WorkDirectoryReference(
            authorized_root=AUTHORIZED_ROOT,
            relative_path=f"runs/{run.run_id}/work",
        ),
        experiment_spec_hash=experiment.spec_hash,
        request_hash=run.request_hash,
        created_at_utc=created_at_utc,
    )


def sanitize_engine_run_request(request: EngineRunRequest) -> SanitizedEngineRunRequest:
    """Plan 3.6: the class-C snapshot, the raw token replaced by its hash."""
    if not isinstance(request, EngineRunRequest):
        raise TypeError("request must be an EngineRunRequest")
    payload = request.model_dump(mode="python")
    token = payload.pop("attempt_token")
    payload["attempt_token_hash"] = attempt_token_hash(token)
    return SanitizedEngineRunRequest.model_validate(payload)


def build_request_envelope(
    *,
    invocation: CommandInvocationRecord,
    payload: DescribeRequestPayload | EngineRunRequest,
) -> AdapterCommandRequestEnvelope:
    """Plan 6.1: the envelope of one ``STARTING`` invocation.

    Copies ``invocation_id``, ``timeout_seconds`` and ``deadline_utc``, takes
    ``created_at_utc`` from ``launch_attempted_at_utc`` (the one instant that
    satisfies the deadline rule) and computes ``payload_hash``. A describe
    envelope's ``request_id`` is ``request_id_for(invocation.invocation_id)``; a
    run envelope's is the payload's. The invocation must be linked to the
    payload's run, carry the payload's ``request_hash`` and name the payload's
    adapter.
    """
    if not isinstance(invocation, CommandInvocationRecord):
        raise TypeError("invocation must be a CommandInvocationRecord")
    if not isinstance(payload, DescribeRequestPayload | EngineRunRequest):
        raise TypeError(
            "payload must be a DescribeRequestPayload or an EngineRunRequest"
        )
    if invocation.state is not CommandInvocationState.STARTING:
        raise ValueError(
            "the request envelope is written at launch: the invocation must be "
            f"STARTING, not {invocation.state.value}"
        )
    describe = isinstance(payload, DescribeRequestPayload)
    if describe is not (invocation.command_kind is CommandKind.DESCRIBE):
        raise ValueError(
            "a DESCRIBE invocation takes a DescribeRequestPayload; VALIDATE and RUN "
            "take an EngineRunRequest"
        )
    if isinstance(payload, DescribeRequestPayload):
        if (payload.adapter_name, payload.adapter_version) != (
            invocation.adapter_name,
            invocation.adapter_version,
        ):
            raise ValueError(
                "the describe payload names another adapter than the invocation"
            )
        if invocation.request_hash != request_hash_of(payload):
            raise ValueError(
                "invocation.request_hash does not equal the describe request "
                "material hash"
            )
        request_id: str = request_id_for(invocation.invocation_id)
    else:
        if invocation.run_id != payload.run_id:
            raise ValueError(
                "the invocation is linked to another run_id than the payload"
            )
        if payload.request_id != request_id_for(payload.run_id):
            raise ValueError(
                "payload.request_id must be the request_id derived from the run"
            )
        if invocation.request_hash != payload.request_hash:
            raise ValueError(
                "invocation.request_hash does not equal payload.request_hash"
            )
        if payload.adapter != AdapterIdentity(
            adapter_name=invocation.adapter_name,
            adapter_version=invocation.adapter_version,
        ):
            raise ValueError("the payload names another adapter than the invocation")
        request_id = payload.request_id
    return AdapterCommandRequestEnvelope(
        schema_version="1.0.0",
        protocol_version="1.0.0",
        request_id=request_id,
        invocation_id=invocation.invocation_id,
        command=invocation.command_kind,
        created_at_utc=invocation.launch_attempted_at_utc,
        timeout_seconds=invocation.timeout_seconds,
        deadline_utc=invocation.deadline_utc,
        payload_hash=payload_hash_of(payload),
        payload=payload,
    )


def request_envelope_bytes(envelope: AdapterCommandRequestEnvelope) -> bytes:
    """The canonical JSON the launcher writes to ``--request`` (plan 6.1).

    The only token-bearing byte string the core hands out: a run envelope carries
    the raw attempt token exactly once, inside its payload (``payload_hash_of``
    serializes the same canonical payload internally and returns only the
    digest). It is never persisted, logged, hashed into a durable record or
    finalized; the launcher writes it under the command-specific temporary root
    and removes it with the command (specification 14.7).
    """
    if not isinstance(envelope, AdapterCommandRequestEnvelope):
        raise TypeError("envelope must be an AdapterCommandRequestEnvelope")
    return canonical_json_bytes(envelope)
