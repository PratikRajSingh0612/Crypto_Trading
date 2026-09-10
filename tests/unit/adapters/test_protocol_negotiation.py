"""Stage 6 Task 3: the bootstrap descriptor envelope, protocol negotiation and the
describe parse and observation projections (Stage 6 plan sections 3.8, 3.11, 5.1-5.4).

`BootstrapDescriptorEnvelope` is the untrusted describe output whose header mirrors
the nested `AdapterDescriptor`; `negotiate_protocol` is the pure selection over the
numerically sorted intersections that fails closed to `ADAPTER.UNAVAILABLE`;
`parse_bootstrap_descriptor` applies the byte ceiling before decoding and reads the
header permissively so identity can be reported before schema classification; and
`describe_availability_observation` projects any terminal describe into the Stage 4
observation. Task 3 owns no schema registration (the registry stays at 27) and mints
no `Diagnostic`.
"""

from __future__ import annotations

import ast
import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Final, Literal, Never, get_args

import pytest
from jsonschema import Draft202012Validator
from pydantic import TypeAdapter, ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab import adapters as adapters_package
from crypto_lab.adapters import negotiation
from crypto_lab.adapters.diagnostics import (
    ADAPTER_UNAVAILABLE,
    PROCESS_CANCELLED,
    PROCESS_DESCRIBE_TIMED_OUT,
    PROTOCOL_DESCRIBE_OUTPUT_INVALID,
    PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
    PROTOCOL_UNSUPPORTED_VERSION,
    STAGE6_DIAGNOSTIC_CODES,
)
from crypto_lab.adapters.envelopes import NegotiatedVersions
from crypto_lab.adapters.limits import MAX_DESCRIPTOR_OUTPUT_BYTES, PROTOCOL_VERSION
from crypto_lab.adapters.negotiation import (
    CORE_PROTOCOL_SUPPORT,
    NEGOTIATION_POLICY_VERSION,
    BootstrapDescriptorEnvelope,
    CoreProtocolSupport,
    DescriptorHeader,
    DescriptorParse,
    NegotiationResult,
    describe_availability_observation,
    negotiate_protocol,
    negotiated_versions_of,
    parse_bootstrap_descriptor,
)
from crypto_lab.adapters.vocabulary import (
    NEGOTIABLE_SCHEMA_NAMES,
    NegotiationOutcome,
    ReconciliationVerdict,
)
from crypto_lab.domain.base import SCHEMA_VERSION
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.descriptors import (
    AdapterDescriptor,
    EngineDescriptor,
    OperatingSystem,
    RuntimeAvailabilityObservation,
    SupportedSchemaVersion,
)
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.identifiers import NormalizedIdentifier

_MODES: Final[tuple[Literal["python", "json"], ...]] = ("python", "json")
_HASH: Final = "a" * 64
_OTHER_HASH: Final = "b" * 64
_OBSERVATION_ID: Final = "avail_2c4d6e80-1f3a-4b5c-9d8e-7f6a5b4c3d2e"
_OBSERVED: Final = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
_EXPIRES: Final = _OBSERVED + timedelta(hours=1)
_EXECUTABLE_PATH: Final = "C:/adapters/fake_adapter.py"
_FOREIGN_SCHEMA: Final = "protocol.zzz-other"
#: Recorded once from ``sha256(json.dumps(dump, sort_keys=True, separators=(",", ":"),
#: ensure_ascii=False))`` over the fixture descriptor's JSON dump and over the
#: conformant envelope's canonical bytes; pinned as regression goldens.
_DESCRIPTOR_GOLDEN: Final = (
    "59436507b3aa50ae482c59cdffa40ce1f8ca378b1e2f1bd03a4f3c29078c1413"
)
_ENVELOPE_GOLDEN: Final = (
    "ee0afebb9f54490cf06a367e3668f75a9a8c9a4921ab7c0d2ca875ff2650ae5c"
)
_ENVELOPE_FIELDS: Final = (
    "bootstrap_schema_version",
    "adapter_name",
    "adapter_version",
    "engine_name",
    "engine_version",
    "executable_hash",
    "supported_protocol_versions",
    "supported_schema_versions",
    "capability_vocabulary_versions",
    "descriptor_payload_hash",
    "descriptor",
)
_SUPPORT_FIELDS: Final = (
    "protocol_versions",
    "schema_versions",
    "vocabulary_versions",
    "negotiation_policy_version",
)
_RESULT_FIELDS: Final = (
    "schema_version",
    "adapter_name",
    "adapter_version",
    "candidate_protocol_versions",
    "candidate_schema_versions",
    "candidate_vocabulary_versions",
    "selected_protocol_version",
    "selected_schema_versions",
    "selected_vocabulary_version",
    "negotiation_policy_version",
    "outcome",
    "reason_codes",
)
_SELECTED_FIELDS: Final = (
    "selected_protocol_version",
    "selected_schema_versions",
    "selected_vocabulary_version",
)
_HEADER_FIELDS: Final = (
    "bootstrap_schema_version",
    "adapter_name",
    "adapter_version",
    "executable_hash",
)
_PARSE_FIELDS: Final = (
    "byte_length",
    "source_hash",
    "header",
    "envelope",
    "failure_code",
)
#: Plan section 14 Task 3: the Task 3 public surface of ``crypto_lab.adapters``.
_TASK3_EXPORTS: Final = frozenset(
    {
        "CORE_PROTOCOL_SUPPORT",
        "BootstrapDescriptorEnvelope",
        "CoreProtocolSupport",
        "DescriptorHeader",
        "DescriptorParse",
        "NegotiationResult",
        "describe_availability_observation",
        "negotiate_protocol",
        "negotiated_versions_of",
        "parse_bootstrap_descriptor",
    }
)
#: The standard-library subset of the Stage 3 allowlist that reaches no filesystem,
#: environment, clock, random or process source, plus pydantic and the project;
#: ``json`` parses the describe output and is not in the plan 2.6 design-rule denylist.
_PURE_ROOTS: Final = frozenset(
    {"__future__", "datetime", "json", "typing", "pydantic", "crypto_lab"}
)
_STAGE4_BARE_NAMES: Final = frozenset(
    {"buffer", "context", "note", "problem", "compose", "Loader"}
)
_RUN_VERDICTS: Final = (
    ReconciliationVerdict.VALIDATED_READY,
    ReconciliationVerdict.NOT_APPLICABLE,
    ReconciliationVerdict.UNAVAILABLE,
    ReconciliationVerdict.FAILED,
    ReconciliationVerdict.RESULT_FINALIZATION_ELIGIBLE,
)


def _missing(value: object) -> bool:
    return value is MISSING


# --- Fixture material -----------------------------------------------------------


def _schema(name: str, version: str = SCHEMA_VERSION) -> SupportedSchemaVersion:
    return SupportedSchemaVersion(schema_name=name, schema_version=version)


def _negotiable(version: str = SCHEMA_VERSION) -> tuple[SupportedSchemaVersion, ...]:
    return tuple(_schema(name, version) for name in NEGOTIABLE_SCHEMA_NAMES)


def _engine(**updates: object) -> EngineDescriptor:
    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "engine_name": "fake.engine",
        "engine_version": "1.0.0",
        "engine_family": "fake.family",
        "planned_role": "Offline fake adapter.",
        "known_limitations": (),
    }
    payload.update(updates)
    return EngineDescriptor.model_validate(payload)


def _descriptor(**updates: object) -> AdapterDescriptor:
    payload: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "adapter_name": "fake.conformant",
        "adapter_version": "1.0.0",
        "engine": _engine(),
        "supported_protocol_versions": ("1.0.0",),
        "supported_schema_versions": _negotiable(),
        "capability_vocabulary_version": "capabilities/v1",
        "native_capabilities": ("data.ohlcv", "market.spot"),
        "approximated_capabilities": (),
        "unsupported_capabilities": (),
        "supported_operating_systems": (OperatingSystem.WINDOWS,),
        "runtime_requirements": ("CPython 3.12",),
        "network_required": False,
        "credentials_required": False,
        "known_modeling_limitations": (),
        "executable_hash": _HASH,
    }
    payload.update(updates)
    return AdapterDescriptor.model_validate(payload)


def _envelope_payload(descriptor: AdapterDescriptor) -> dict[str, object]:
    """The conformant header for ``descriptor``: every mirrored field copied."""
    return {
        "bootstrap_schema_version": SCHEMA_VERSION,
        "adapter_name": descriptor.adapter_name,
        "adapter_version": descriptor.adapter_version,
        "engine_name": descriptor.engine.engine_name,
        "engine_version": descriptor.engine.engine_version,
        "executable_hash": descriptor.executable_hash,
        "supported_protocol_versions": descriptor.supported_protocol_versions,
        "supported_schema_versions": descriptor.supported_schema_versions,
        "capability_vocabulary_versions": (descriptor.capability_vocabulary_version,),
        "descriptor_payload_hash": sha256_bytes(canonical_json_bytes(descriptor)),
        "descriptor": descriptor,
    }


def _envelope(
    descriptor: AdapterDescriptor | None = None, /, **updates: object
) -> BootstrapDescriptorEnvelope:
    payload = _envelope_payload(_descriptor() if descriptor is None else descriptor)
    payload.update(updates)
    return BootstrapDescriptorEnvelope.model_validate(payload)


def _support(**updates: object) -> CoreProtocolSupport:
    payload = CORE_PROTOCOL_SUPPORT.model_dump(mode="python")
    payload.update(updates)
    return CoreProtocolSupport.model_validate(payload)


def _result(**updates: object) -> NegotiationResult:
    """The NEGOTIATED baseline of a conformant envelope against the core support."""
    payload = negotiate_protocol(_envelope()).model_dump(mode="python")
    payload.update(updates)
    return NegotiationResult.model_validate(payload)


def _failed_result(**updates: object) -> NegotiationResult:
    """The FAILED baseline: the adapter supports no common protocol version."""
    descriptor = _descriptor(supported_protocol_versions=("2.0.0",))
    payload = negotiate_protocol(_envelope(descriptor)).model_dump(mode="python")
    payload.update(updates)
    return NegotiationResult.model_validate(payload)


def _bytes(envelope: BootstrapDescriptorEnvelope | None = None) -> bytes:
    return canonical_json_bytes(_envelope() if envelope is None else envelope)


def _document(**updates: object) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(_bytes())
    document.update(updates)
    return document


def _encode(document: dict[str, Any]) -> bytes:
    return json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _parse(
    output: bytes, max_bytes: int = MAX_DESCRIPTOR_OUTPUT_BYTES
) -> DescriptorParse:
    return parse_bootstrap_descriptor(output, max_bytes=max_bytes)


def _observation(**updates: object) -> RuntimeAvailabilityObservation:
    kwargs: dict[str, Any] = {
        "adapter_name": "fake.conformant",
        "adapter_version": "1.0.0",
        "verdict": ReconciliationVerdict.DESCRIBED,
        "primary_code": MISSING,
        "descriptor": _descriptor(),
        "observation_id": _OBSERVATION_ID,
        "executable_path": _EXECUTABLE_PATH,
        "executable_hash": _HASH,
        "runtime_version": "3.12.13",
        "operating_system": OperatingSystem.WINDOWS,
        "observed_at_utc": _OBSERVED,
        "expires_at_utc": _EXPIRES,
    }
    kwargs.update(updates)
    return describe_availability_observation(**kwargs)


def _stdlib_digest(document: object) -> str:
    return hashlib.sha256(
        json.dumps(
            document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
        ).encode("utf-8")
    ).hexdigest()


def _conformant_header() -> DescriptorHeader:
    return DescriptorHeader(
        bootstrap_schema_version="1.0.0",
        adapter_name="fake.conformant",
        adapter_version="1.0.0",
        executable_hash=_HASH,
    )


def _forbidden(*_args: object, **_kwargs: object) -> Never:
    raise AssertionError("Task 3 performed runtime work")


# --- Inventory, field order and purity ----------------------------------------------


def test_the_package_exports_the_task_three_surface_sorted() -> None:
    """The package surface gains exactly the ten Task 3 names in the RUF022 order."""
    exported = adapters_package.__all__
    assert _TASK3_EXPORTS <= set(exported)
    assert len(set(exported)) == len(exported)
    constants = [name for name in exported if name.isupper()]
    classes = [name for name in exported if not name.isupper() and name[0].isupper()]
    functions = [name for name in exported if name[0].islower()]
    assert list(exported) == [*constants, *classes, *functions]
    for group in (constants, classes, functions):
        assert group == sorted(group)
    assert NEGOTIATION_POLICY_VERSION == "negotiation/v1"
    assert "NEGOTIATION_POLICY_VERSION" not in exported


@pytest.mark.parametrize(
    ("model", "expected", "optional"),
    [
        (BootstrapDescriptorEnvelope, _ENVELOPE_FIELDS, ()),
        (CoreProtocolSupport, _SUPPORT_FIELDS, ()),
        (NegotiationResult, _RESULT_FIELDS, _SELECTED_FIELDS),
        (DescriptorHeader, _HEADER_FIELDS, _HEADER_FIELDS),
        (DescriptorParse, _PARSE_FIELDS, ("header", "envelope", "failure_code")),
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
    """Plan 3.1 and 12.3: the bootstrap envelope carries ``bootstrap_schema_version``
    instead of ``schema_version``; the result carries no ``protocol_version``; the
    support record is trust class K without an envelope version."""
    envelope_fields = BootstrapDescriptorEnvelope.model_fields
    assert get_args(envelope_fields["bootstrap_schema_version"].annotation) == (
        SCHEMA_VERSION,
    )
    assert "schema_version" not in envelope_fields
    assert "protocol_version" not in envelope_fields
    result_fields = NegotiationResult.model_fields
    assert "protocol_version" not in result_fields
    assert get_args(result_fields["schema_version"].annotation) == (SCHEMA_VERSION,)
    assert get_args(result_fields["negotiation_policy_version"].annotation) == (
        NEGOTIATION_POLICY_VERSION,
    )
    support_fields = CoreProtocolSupport.model_fields
    assert "schema_version" not in support_fields
    assert get_args(support_fields["negotiation_policy_version"].annotation) == (
        NEGOTIATION_POLICY_VERSION,
    )
    assert PROTOCOL_VERSION == SCHEMA_VERSION == "1.0.0"


def test_the_module_imports_only_pure_roots_and_uses_no_forbidden_name() -> None:
    """Preventive (begins green once the module exists): plan 2.6 design rules,
    the Stage 4 bare-name scan and section 13."""
    source = Path(negotiation.__file__ or "").read_text(encoding="utf-8")
    tree = ast.parse(source)
    roots: set[str] = set()
    project_packages: set[str] = set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
            if node.module.startswith("crypto_lab."):
                project_packages.add(node.module.split(".")[1])
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
    assert roots <= _PURE_ROOTS, sorted(roots - _PURE_ROOTS)
    assert project_packages <= {"domain", "adapters"}, sorted(project_packages)
    assert names & _STAGE4_BARE_NAMES == set()
    assert "subprocess" not in source
    assert "AttemptToken" not in source
    assert "attempt_token" not in source


def test_no_task_three_model_carries_a_token_or_a_mutable_public_mapping() -> None:
    """Preventive (began green): section 13 and plan 3.1 on the five Task 3 models."""
    for model in (
        BootstrapDescriptorEnvelope,
        CoreProtocolSupport,
        NegotiationResult,
        DescriptorHeader,
        DescriptorParse,
    ):
        assert "attempt_token" not in model.model_fields
        assert "attempt_token_hash" not in model.model_fields
        for field in model.model_fields.values():
            assert "dict" not in repr(field.annotation)


def test_task_three_launches_reads_and_connects_to_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Preventive (began green). Dotted-string targets on purpose: this module imports
    no ``subprocess``, so Task 9's exact tests-tree importer allowlist (plan Task 9
    Step 2) is unchanged."""
    monkeypatch.setattr("subprocess.Popen", _forbidden)
    monkeypatch.setattr("socket.create_connection", _forbidden)
    monkeypatch.setattr("os.getenv", _forbidden)
    envelope = _envelope()
    result = negotiate_protocol(envelope)
    negotiated_versions_of(result)
    _parse(_bytes(envelope))
    _observation()


def test_the_core_protocol_support_constant_is_exactly_the_plan_values() -> None:
    support = CORE_PROTOCOL_SUPPORT
    assert support.protocol_versions == (PROTOCOL_VERSION,)
    assert support.schema_versions == _negotiable()
    assert tuple(item.schema_name for item in support.schema_versions) == (
        NEGOTIABLE_SCHEMA_NAMES
    )
    assert {item.schema_version for item in support.schema_versions} == {SCHEMA_VERSION}
    assert support.vocabulary_versions == ("capabilities/v1",)
    assert support.negotiation_policy_version == NEGOTIATION_POLICY_VERSION
    with pytest.raises(ValidationError, match="frozen"):
        support.protocol_versions = ("2.0.0",)


# --- BootstrapDescriptorEnvelope -----------------------------------------------------


def test_a_conformant_envelope_validates_round_trips_and_is_frozen() -> None:
    envelope = _envelope()
    assert envelope.descriptor == _descriptor()
    assert envelope.descriptor_payload_hash == sha256_bytes(
        canonical_json_bytes(envelope.descriptor)
    )
    python_dump = envelope.model_dump(mode="python")
    assert BootstrapDescriptorEnvelope.model_validate(python_dump) == envelope
    assert BootstrapDescriptorEnvelope.model_validate_json(_bytes(envelope)) == envelope
    json_text = json.dumps(envelope.model_dump(mode="json"))
    assert BootstrapDescriptorEnvelope.model_validate_json(json_text) == envelope
    assert canonical_json_bytes(envelope) == canonical_json_bytes(_envelope())
    for mode in _MODES:
        assert tuple(envelope.model_dump(mode=mode)) == _ENVELOPE_FIELDS
    with pytest.raises(ValidationError, match="frozen"):
        envelope.adapter_version = "2.0.0"
    assert isinstance(envelope.supported_protocol_versions, tuple)
    assert isinstance(envelope.supported_schema_versions, tuple)
    assert isinstance(envelope.capability_vocabulary_versions, tuple)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("adapter_name", "fake.other"),
        ("adapter_version", "2.0.0"),
        ("engine_name", "other.engine"),
        ("engine_version", "9.9.9"),
        ("executable_hash", _OTHER_HASH),
        ("supported_protocol_versions", ("1.0.0", "1.1.0")),
        ("supported_schema_versions", _negotiable()[:4]),
    ],
)
def test_each_mirrored_header_field_must_equal_the_descriptor(
    field: str, value: object
) -> None:
    """Plan 3.8: header/descriptor disagreement rejected for each of the seven."""
    with pytest.raises(ValidationError, match="must equal the descriptor") as captured:
        _envelope(**{field: value})
    assert field in str(captured.value)


def test_the_descriptor_payload_hash_must_recompute_and_is_stdlib_reproducible() -> (
    None
):
    """The two rejections had the import-level RED; the stdlib-reproducibility half
    is preventive (began green), plan 4."""
    descriptor = _descriptor()
    expected = _stdlib_digest(descriptor.model_dump(mode="json"))
    assert _envelope(descriptor).descriptor_payload_hash == expected
    with pytest.raises(ValidationError, match="descriptor_payload_hash"):
        _envelope(descriptor, descriptor_payload_hash=_OTHER_HASH)
    # A descriptor differing in one field yields another hash, so a stale hash
    # paired with an edited descriptor is refused as well.
    edited = _descriptor(network_required=True)
    with pytest.raises(ValidationError, match="descriptor_payload_hash"):
        _envelope(edited, descriptor_payload_hash=expected)


def test_the_fixture_hashes_match_their_recorded_goldens() -> None:
    """Literal goldens beside the stdlib derivation, so the canonical rendering of a
    descriptor and of the envelope cannot drift together unnoticed."""
    descriptor = _descriptor()
    descriptor_hash = sha256_bytes(canonical_json_bytes(descriptor))
    output = _bytes()
    envelope_hash = hashlib.sha256(output).hexdigest()
    assert descriptor_hash == _DESCRIPTOR_GOLDEN, descriptor_hash
    assert _envelope(descriptor).descriptor_payload_hash == _DESCRIPTOR_GOLDEN
    assert _stdlib_digest(descriptor.model_dump(mode="json")) == _DESCRIPTOR_GOLDEN
    assert envelope_hash == _ENVELOPE_GOLDEN, envelope_hash
    assert _parse(output).source_hash == _ENVELOPE_GOLDEN


def test_the_descriptor_vocabulary_must_be_among_the_declared_versions() -> None:
    with pytest.raises(ValidationError, match="must be among"):
        _envelope(capability_vocabulary_versions=("capabilities/v2",))
    envelope = _envelope(
        capability_vocabulary_versions=("capabilities/v1", "capabilities/v2")
    )
    assert envelope.descriptor.capability_vocabulary_version == "capabilities/v1"


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"supported_protocol_versions": ("1.10.0", "1.9.0")}, r"numerically sorted"),
        ({"supported_protocol_versions": ("1.0.0", "1.0.0")}, r"must be unique"),
        ({"supported_protocol_versions": ()}, r"at least 1"),
        (
            {"supported_protocol_versions": tuple(f"1.{n}.0" for n in range(33))},
            r"at most 32",
        ),
        (
            {"supported_schema_versions": tuple(reversed(_negotiable()))},
            r"must be sorted",
        ),
        (
            {"supported_schema_versions": (*_negotiable(), _negotiable()[0])},
            r"must be unique",
        ),
        (
            {
                "supported_schema_versions": (
                    _schema("protocol.x", "1.10.0"),
                    _schema("protocol.x", "1.9.0"),
                )
            },
            r"must be sorted",
        ),
        (
            {"capability_vocabulary_versions": ("capabilities/v10", "capabilities/v9")},
            r"numerically sorted",
        ),
        (
            {"capability_vocabulary_versions": ("capabilities/v1", "capabilities/v1")},
            r"must be unique",
        ),
        ({"capability_vocabulary_versions": ()}, r"at least 1"),
        (
            {
                "capability_vocabulary_versions": tuple(
                    f"capabilities/v{n}" for n in range(1, 10)
                )
            },
            r"at most 8",
        ),
    ],
)
def test_envelope_collections_reject_lexical_order_duplicates_and_bounds(
    updates: dict[str, object], expected: str
) -> None:
    """Plan 3.8 and Task 3 Step 1: lexically sorted but numerically unsorted tuples
    (``1.10.0`` before ``1.9.0``) are rejected by the field validator, before the
    header/descriptor comparison runs."""
    with pytest.raises(ValidationError, match=expected):
        _envelope(**updates)


def test_numerically_sorted_collections_beside_ten_are_accepted() -> None:
    descriptor = _descriptor(
        supported_protocol_versions=("1.9.0", "1.10.0"),
        capability_vocabulary_version="capabilities/v10",
    )
    envelope = _envelope(
        descriptor,
        capability_vocabulary_versions=("capabilities/v9", "capabilities/v10"),
    )
    assert envelope.supported_protocol_versions == ("1.9.0", "1.10.0")
    assert envelope.capability_vocabulary_versions == (
        "capabilities/v9",
        "capabilities/v10",
    )


def test_the_envelope_rejects_unknown_fields_and_other_bootstrap_versions() -> None:
    marker = "INPUT_MARKER_MUST_NOT_APPEAR"
    with pytest.raises(ValidationError, match="extra_forbidden") as captured:
        _envelope(protocol_version=marker)
    assert marker not in str(captured.value)
    with pytest.raises(ValidationError, match="bootstrap_schema_version"):
        _envelope(bootstrap_schema_version="2.0.0")
    with pytest.raises(ValidationError, match="bootstrap_schema_version"):
        _envelope(bootstrap_schema_version="1.0")


@pytest.mark.parametrize("mode", ["validation", "serialization"])
def test_the_envelope_schema_is_generable_closed_and_identical_in_both_modes(
    mode: Literal["validation", "serialization"],
) -> None:
    """Preventive for Task 9 (schema 27): both modes render, every object is closed,
    the sorted-unique tuples publish ``uniqueItems``, no legacy ``UtcDateTime``."""
    schema = TypeAdapter(BootstrapDescriptorEnvelope).json_schema(mode=mode)
    Draft202012Validator.check_schema(schema)
    assert schema == TypeAdapter(BootstrapDescriptorEnvelope).json_schema(
        mode="validation"
    )
    assert schema["additionalProperties"] is False
    for name, definition in schema["$defs"].items():
        if definition.get("type") == "object":
            assert definition["additionalProperties"] is False, name
    assert "UtcDateTime" not in schema["$defs"]
    version = schema["properties"]["bootstrap_schema_version"]
    assert version["const"] == SCHEMA_VERSION
    assert version["type"] == "string"
    for field in (
        "supported_protocol_versions",
        "supported_schema_versions",
        "capability_vocabulary_versions",
    ):
        assert schema["properties"][field]["uniqueItems"] is True
    assert schema["required"] == list(_ENVELOPE_FIELDS)
    validator = Draft202012Validator(schema)
    document = _envelope().model_dump(mode="json")
    assert validator.is_valid(document)
    assert not validator.is_valid({**document, "unexpected": 1})
    assert not validator.is_valid({**document, "bootstrap_schema_version": "2.0.0"})


# --- CoreProtocolSupport -------------------------------------------------------------


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"protocol_versions": ("1.10.0", "1.9.0")}, r"numerically sorted"),
        ({"protocol_versions": ("1.0.0", "1.0.0")}, r"must be unique"),
        ({"protocol_versions": ()}, r"at least 1"),
        (
            {"schema_versions": (*_negotiable(), _schema(_FOREIGN_SCHEMA))},
            r"negotiable schema names",
        ),
        ({"schema_versions": _negotiable()[:4]}, r"negotiable schema names"),
        ({"schema_versions": tuple(reversed(_negotiable()))}, r"must be sorted"),
        (
            {"vocabulary_versions": ("capabilities/v10", "capabilities/v9")},
            r"numerically sorted",
        ),
        ({"vocabulary_versions": ()}, r"at least 1"),
        (
            {"negotiation_policy_version": "negotiation/v2"},
            r"negotiation_policy_version",
        ),
        ({"unexpected": True}, r"extra_forbidden"),
    ],
)
def test_core_support_rejects_unsorted_duplicate_foreign_or_unknown_values(
    updates: dict[str, object], expected: str
) -> None:
    with pytest.raises(ValidationError, match=expected):
        _support(**updates)


def test_core_support_accepts_several_versions_per_schema_name_sorted() -> None:
    name = NEGOTIABLE_SCHEMA_NAMES[0]
    support = _support(
        schema_versions=(
            _schema(name, "1.0.0"),
            _schema(name, "1.9.0"),
            _schema(name, "1.10.0"),
            *_negotiable()[1:],
        )
    )
    assert len(support.schema_versions) == len(NEGOTIABLE_SCHEMA_NAMES) + 2
    with pytest.raises(ValidationError, match="must be sorted"):
        _support(
            schema_versions=(
                _schema(name, "1.0.0"),
                _schema(name, "1.10.0"),
                _schema(name, "1.9.0"),
                *_negotiable()[1:],
            )
        )


# --- NegotiationResult ---------------------------------------------------------------


@pytest.mark.parametrize("field", _SELECTED_FIELDS)
def test_a_negotiated_result_requires_every_selected_field(field: str) -> None:
    payload = _result().model_dump(mode="python")
    del payload[field]
    with pytest.raises(ValidationError, match="NEGOTIATED result"):
        NegotiationResult.model_validate(payload)


def test_a_negotiated_result_carries_no_reason_code() -> None:
    with pytest.raises(ValidationError, match="NEGOTIATED result"):
        _result(reason_codes=(ADAPTER_UNAVAILABLE,))


@pytest.mark.parametrize("field", _SELECTED_FIELDS)
def test_a_failed_result_forbids_each_selected_field(field: str) -> None:
    negotiated = _result()
    with pytest.raises(ValidationError, match="FAILED result"):
        _failed_result(**{field: getattr(negotiated, field)})


def test_a_failed_result_requires_a_reason_code() -> None:
    with pytest.raises(ValidationError, match="FAILED result"):
        _failed_result(reason_codes=())
    failed = _failed_result()
    assert failed.outcome is NegotiationOutcome.FAILED
    assert failed.reason_codes == (ADAPTER_UNAVAILABLE,)
    for field in _SELECTED_FIELDS:
        assert _missing(getattr(failed, field)), field
    dumped = failed.model_dump(mode="python")
    assert not any(field in dumped for field in _SELECTED_FIELDS)


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"selected_protocol_version": "1.1.0"}, r"selected_protocol_version"),
        (
            {"selected_schema_versions": _negotiable("1.1.0")},
            r"selected schema version",
        ),
        (
            {"selected_vocabulary_version": "capabilities/v2"},
            r"selected_vocabulary_version",
        ),
    ],
)
def test_selected_values_must_belong_to_the_candidate_intersections(
    updates: dict[str, object], expected: str
) -> None:
    """Specification 11.3: selected values belong to intersections."""
    with pytest.raises(ValidationError, match=expected):
        _result(**updates)


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (_negotiable()[:4], r"negotiable schema names|at least 5"),
        (
            (*_negotiable()[:4], _schema(_FOREIGN_SCHEMA)),
            r"negotiable schema names",
        ),
        ((*_negotiable()[:4], _negotiable()[0]), r"must be unique"),
        (tuple(reversed(_negotiable())), r"must be sorted"),
    ],
)
def test_selected_schema_versions_name_exactly_the_negotiable_names(
    value: tuple[SupportedSchemaVersion, ...], expected: str
) -> None:
    with pytest.raises(ValidationError, match=expected):
        _result(selected_schema_versions=value)


@pytest.mark.parametrize(
    ("updates", "expected"),
    [
        ({"candidate_protocol_versions": ("1.10.0", "1.9.0")}, r"numerically sorted"),
        ({"candidate_protocol_versions": ("1.0.0", "1.0.0")}, r"must be unique"),
        (
            {"candidate_schema_versions": tuple(reversed(_negotiable()))},
            r"must be sorted",
        ),
        (
            {"candidate_schema_versions": (*_negotiable(), _schema(_FOREIGN_SCHEMA))},
            r"negotiable schema names",
        ),
        (
            {"candidate_vocabulary_versions": ("capabilities/v10", "capabilities/v9")},
            r"numerically sorted",
        ),
        ({"reason_codes": ("B.B", "A.A")}, r"must be sorted"),
        ({"reason_codes": ("A.A", "A.A")}, r"must be unique"),
        ({"reason_codes": tuple(f"A.C{n}" for n in range(9))}, r"at most 8"),
        ({"reason_codes": ("lowercase.code",)}, r"reason_codes"),
    ],
)
def test_result_collections_are_sorted_unique_and_bounded(
    updates: dict[str, object], expected: str
) -> None:
    base = _failed_result if "reason_codes" in updates else _result
    with pytest.raises(ValidationError, match=expected):
        base(**updates)


def test_the_result_rejects_unknown_fields_and_other_versions() -> None:
    with pytest.raises(ValidationError, match="extra_forbidden"):
        _result(protocol_version="1.0.0")
    with pytest.raises(ValidationError, match="schema_version"):
        _result(schema_version="2.0.0")
    with pytest.raises(ValidationError, match="negotiation_policy_version"):
        _result(negotiation_policy_version="negotiation/v2")
    with pytest.raises(ValidationError, match="outcome"):
        _result(outcome="MAYBE")


def test_both_result_shapes_round_trip_in_both_modes_and_are_frozen() -> None:
    for result in (_result(), _failed_result()):
        python_dump = result.model_dump(mode="python")
        assert NegotiationResult.model_validate(python_dump) == result
        assert NegotiationResult.model_validate_json(result.model_dump_json()) == result
        canonical = canonical_json_bytes(result)
        assert NegotiationResult.model_validate_json(canonical) == result
        assert canonical == canonical_json_bytes(
            NegotiationResult.model_validate(python_dump)
        )
        with pytest.raises(ValidationError, match="frozen"):
            result.outcome = NegotiationOutcome.FAILED
    assert tuple(_result().model_dump(mode="python")) == _RESULT_FIELDS
    assert tuple(_failed_result().model_dump(mode="python")) == tuple(
        name for name in _RESULT_FIELDS if name not in _SELECTED_FIELDS
    )


def test_the_published_result_schema_pins_the_outcome_biconditional() -> None:
    """Preventive for Task 9 (schema 28; plan 3.8 and 12.4): the NEGOTIATED/FAILED
    biconditional, the five names by position and the negotiable-name enumeration
    are published exactly and both generation modes render identically."""
    schema = TypeAdapter(NegotiationResult).json_schema(mode="validation")
    Draft202012Validator.check_schema(schema)
    assert TypeAdapter(NegotiationResult).json_schema(mode="serialization") == schema
    assert schema["additionalProperties"] is False
    assert "UtcDateTime" not in schema["$defs"]
    assert "protocol_version" not in schema["properties"]
    assert schema["required"] == [
        name for name in _RESULT_FIELDS if name not in _SELECTED_FIELDS
    ]
    for field in (
        "candidate_protocol_versions",
        "candidate_schema_versions",
        "candidate_vocabulary_versions",
        "selected_schema_versions",
        "reason_codes",
    ):
        assert schema["properties"][field]["uniqueItems"] is True, field
    selected = schema["properties"]["selected_schema_versions"]
    assert selected["minItems"] == 5
    assert selected["maxItems"] == 5
    names = [
        item["allOf"][1]["properties"]["schema_name"]["const"]
        for item in selected["prefixItems"]
    ]
    assert names == list(NEGOTIABLE_SCHEMA_NAMES)
    for item in selected["prefixItems"]:
        assert item["allOf"][0] == {"$ref": "#/$defs/SupportedSchemaVersion"}
    candidates = schema["properties"]["candidate_schema_versions"]["items"]["allOf"]
    assert candidates[0] == {"$ref": "#/$defs/SupportedSchemaVersion"}
    assert candidates[1]["properties"]["schema_name"]["enum"] == list(
        NEGOTIABLE_SCHEMA_NAMES
    )
    clauses = [clause for clause in schema["allOf"] if "if" in clause]
    assert [clause["if"]["properties"]["outcome"]["const"] for clause in clauses] == [
        "NEGOTIATED",
        "FAILED",
    ]
    validator = Draft202012Validator(schema)
    negotiated = _result().model_dump(mode="json")
    failed = _failed_result().model_dump(mode="json")
    assert validator.is_valid(negotiated)
    assert validator.is_valid(failed)
    for field in _SELECTED_FIELDS:
        without = dict(negotiated)
        del without[field]
        assert not validator.is_valid(without), field
        assert not validator.is_valid({**failed, field: negotiated[field]}), field
    assert not validator.is_valid({**negotiated, "reason_codes": [ADAPTER_UNAVAILABLE]})
    assert not validator.is_valid({**failed, "reason_codes": []})
    reversed_selection = list(reversed(negotiated["selected_schema_versions"]))
    assert not validator.is_valid(
        {**negotiated, "selected_schema_versions": reversed_selection}
    )
    foreign_candidates = [
        *negotiated["candidate_schema_versions"],
        {"schema_name": _FOREIGN_SCHEMA, "schema_version": "1.0.0"},
    ]
    assert not validator.is_valid(
        {**negotiated, "candidate_schema_versions": foreign_candidates}
    )
    assert not validator.is_valid({**negotiated, "outcome": "MAYBE"})


# --- negotiate_protocol --------------------------------------------------------------


def test_a_conformant_envelope_negotiates_the_core_support() -> None:
    envelope = _envelope()
    result = negotiate_protocol(envelope)
    assert result.outcome is NegotiationOutcome.NEGOTIATED
    assert result.adapter_name == envelope.adapter_name
    assert result.adapter_version == envelope.adapter_version
    assert result.candidate_protocol_versions == ("1.0.0",)
    assert result.candidate_schema_versions == _negotiable()
    assert result.candidate_vocabulary_versions == ("capabilities/v1",)
    assert result.selected_protocol_version == "1.0.0"
    assert result.selected_schema_versions == _negotiable()
    assert result.selected_vocabulary_version == "capabilities/v1"
    assert result.negotiation_policy_version == NEGOTIATION_POLICY_VERSION
    assert result.reason_codes == ()
    assert result == negotiate_protocol(envelope, CORE_PROTOCOL_SUPPORT)
    assert negotiated_versions_of(result) == NegotiatedVersions(
        protocol_version="1.0.0",
        schema_versions=_negotiable(),
        capability_vocabulary_version="capabilities/v1",
    )


def test_the_highest_common_protocol_is_selected_numerically() -> None:
    """Plan Task 3 Step 1: ``1.10.0`` over ``1.9.0`` from numerically sorted lists
    whose lexical order differs; the candidates are the sorted intersection."""
    support = _support(protocol_versions=("1.9.0", "1.10.0", "2.0.0"))
    descriptor = _descriptor(supported_protocol_versions=("1.9.0", "1.10.0", "3.0.0"))
    result = negotiate_protocol(_envelope(descriptor), support)
    assert result.outcome is NegotiationOutcome.NEGOTIATED
    assert result.candidate_protocol_versions == ("1.9.0", "1.10.0")
    assert result.selected_protocol_version == "1.10.0"
    with pytest.raises(ValueError, match=r"1\.10\.0 is not the protocol version"):
        negotiated_versions_of(result)


def _numeric_key(item: SupportedSchemaVersion) -> tuple[str, tuple[int, ...]]:
    parts = tuple(int(part) for part in item.schema_version.split("."))
    return (item.schema_name, parts)


def test_the_highest_common_schema_version_is_selected_per_name() -> None:
    name = NEGOTIABLE_SCHEMA_NAMES[2]
    versions = (_schema(name, "1.0.0"), _schema(name, "1.9.0"), _schema(name, "1.10.0"))
    others = tuple(item for item in _negotiable() if item.schema_name != name)
    support = _support(
        schema_versions=tuple(sorted((*versions, *others), key=_numeric_key))
    )
    declared = (*versions, *others, _schema(_FOREIGN_SCHEMA, "4.0.0"))
    descriptor = _descriptor(
        supported_schema_versions=tuple(sorted(declared, key=_numeric_key))
    )
    result = negotiate_protocol(_envelope(descriptor), support)
    assert result.outcome is NegotiationOutcome.NEGOTIATED
    candidate_versions = [
        item.schema_version
        for item in result.candidate_schema_versions
        if item.schema_name == name
    ]
    assert candidate_versions == ["1.0.0", "1.9.0", "1.10.0"]
    candidate_names = {item.schema_name for item in result.candidate_schema_versions}
    assert _FOREIGN_SCHEMA not in candidate_names
    selected = {
        item.schema_name: item.schema_version
        for item in result.selected_schema_versions
    }
    assert selected[name] == "1.10.0"
    assert all(selected[other.schema_name] == "1.0.0" for other in others)


def test_an_adapter_omitting_a_negotiable_schema_name_fails_closed() -> None:
    descriptor = _descriptor(supported_schema_versions=_negotiable()[:4])
    result = negotiate_protocol(_envelope(descriptor))
    assert result.outcome is NegotiationOutcome.FAILED
    assert result.reason_codes == (ADAPTER_UNAVAILABLE,)
    assert result.candidate_schema_versions == _negotiable()[:4]
    assert result.candidate_protocol_versions == ("1.0.0",)
    assert result.candidate_vocabulary_versions == ("capabilities/v1",)
    for field in _SELECTED_FIELDS:
        assert _missing(getattr(result, field)), field
    with pytest.raises(ValueError, match="FAILED negotiation"):
        negotiated_versions_of(result)


def test_a_disjoint_protocol_version_fails_closed() -> None:
    result = _failed_result()
    assert result.candidate_protocol_versions == ()
    assert result.candidate_schema_versions == _negotiable()
    assert result.candidate_vocabulary_versions == ("capabilities/v1",)
    assert result.reason_codes == (ADAPTER_UNAVAILABLE,)


def test_a_disjoint_vocabulary_fails_closed() -> None:
    descriptor = _descriptor(capability_vocabulary_version="capabilities/v2")
    envelope = _envelope(
        descriptor, capability_vocabulary_versions=("capabilities/v2",)
    )
    result = negotiate_protocol(envelope)
    assert result.outcome is NegotiationOutcome.FAILED
    assert result.candidate_vocabulary_versions == ()
    assert result.reason_codes == (ADAPTER_UNAVAILABLE,)


def test_a_selected_vocabulary_differing_from_the_declared_one_fails_closed() -> None:
    """Plan 5.3: the highest common vocabulary must be the one the descriptor's
    capability claims were made in; the core never silently selects another."""
    support = _support(vocabulary_versions=("capabilities/v1", "capabilities/v2"))
    envelope = _envelope(
        capability_vocabulary_versions=("capabilities/v1", "capabilities/v2")
    )
    result = negotiate_protocol(envelope, support)
    assert result.outcome is NegotiationOutcome.FAILED
    assert result.candidate_vocabulary_versions == (
        "capabilities/v1",
        "capabilities/v2",
    )
    assert _missing(result.selected_vocabulary_version)
    declared_highest = _envelope(
        _descriptor(capability_vocabulary_version="capabilities/v2"),
        capability_vocabulary_versions=("capabilities/v1", "capabilities/v2"),
    )
    agreed = negotiate_protocol(declared_highest, support)
    assert agreed.outcome is NegotiationOutcome.NEGOTIATED
    assert agreed.selected_vocabulary_version == "capabilities/v2"


def test_vocabulary_selection_is_numeric_not_lexical() -> None:
    support = _support(vocabulary_versions=("capabilities/v9", "capabilities/v10"))
    envelope = _envelope(
        _descriptor(capability_vocabulary_version="capabilities/v10"),
        capability_vocabulary_versions=("capabilities/v9", "capabilities/v10"),
    )
    result = negotiate_protocol(envelope, support)
    assert result.selected_vocabulary_version == "capabilities/v10"
    assert result.candidate_vocabulary_versions == (
        "capabilities/v9",
        "capabilities/v10",
    )


def test_multiple_failures_carry_the_single_reason_code_once() -> None:
    descriptor = _descriptor(
        supported_protocol_versions=("2.0.0",),
        supported_schema_versions=_negotiable()[:3],
        capability_vocabulary_version="capabilities/v3",
    )
    envelope = _envelope(
        descriptor, capability_vocabulary_versions=("capabilities/v3",)
    )
    result = negotiate_protocol(envelope)
    assert result.outcome is NegotiationOutcome.FAILED
    assert result.reason_codes == (ADAPTER_UNAVAILABLE,)
    assert result.candidate_protocol_versions == ()
    assert result.candidate_schema_versions == _negotiable()[:3]
    assert result.candidate_vocabulary_versions == ()


def test_negotiation_is_pure_deterministic_and_type_checked() -> None:
    envelope = _envelope()
    before = envelope.model_dump(mode="python")
    first = negotiate_protocol(envelope)
    second = negotiate_protocol(envelope)
    assert first == second
    assert canonical_json_bytes(first) == canonical_json_bytes(second)
    assert envelope.model_dump(mode="python") == before
    with pytest.raises(TypeError, match="BootstrapDescriptorEnvelope"):
        negotiate_protocol(_descriptor())  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="CoreProtocolSupport"):
        negotiate_protocol(envelope, NegotiatedVersions)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="NegotiationResult"):
        negotiated_versions_of(envelope)  # type: ignore[arg-type]


# --- parse_bootstrap_descriptor ------------------------------------------------------


def test_valid_bytes_parse_to_an_envelope_with_header_and_hashes() -> None:
    envelope = _envelope()
    output = _bytes(envelope)
    parsed = _parse(output)
    assert parsed.byte_length == len(output)
    assert parsed.source_hash == hashlib.sha256(output).hexdigest()
    assert parsed.envelope == envelope
    assert _missing(parsed.failure_code)
    assert parsed.header == _conformant_header()
    assert parsed == _parse(output)
    assert DescriptorParse.model_validate(parsed.model_dump(mode="python")) == parsed
    with pytest.raises(ValidationError, match="frozen"):
        parsed.byte_length = 0


def test_oversized_bytes_are_never_decoded(monkeypatch: pytest.MonkeyPatch) -> None:
    """Plan 3.11: the ceiling applies before decoding, so the bytes may be anything.

    The module parses with the standard-library ``json`` module (asserted by the
    purity test), so patching ``json.loads`` proves no decode was attempted."""
    monkeypatch.setattr(json, "loads", _forbidden)
    output = _bytes() + b"\xff\xfe"
    parsed = _parse(output, max_bytes=len(output) - 1)
    assert parsed.failure_code == PROTOCOL_DESCRIBE_OUTPUT_INVALID
    assert _missing(parsed.header)
    assert _missing(parsed.envelope)
    assert parsed.byte_length == len(output)
    assert parsed.source_hash == sha256_bytes(output)


def test_bytes_exactly_at_the_ceiling_are_parsed_and_one_more_is_not() -> None:
    output = _bytes()
    assert not _missing(_parse(output, max_bytes=len(output)).envelope)
    assert _parse(output, max_bytes=len(output) - 1).failure_code == (
        PROTOCOL_DESCRIBE_OUTPUT_INVALID
    )


@pytest.mark.parametrize(
    "output",
    [
        b"",
        b"\xff\xfe",
        b"\xef\xbb\xbf" + _bytes(),
        _bytes().decode("utf-8").encode("utf-16"),
        b"[]",
        b'"text"',
        b"1",
        b"null",
        b"not json",
        _bytes() + b" {}",
        _bytes()[:-1],
        b"[" * 100_000,
    ],
    ids=[
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
    ],
)
def test_bytes_that_are_not_a_json_object_carry_no_header(output: bytes) -> None:
    parsed = _parse(output)
    assert parsed.failure_code == PROTOCOL_DESCRIBE_OUTPUT_INVALID
    assert _missing(parsed.header)
    assert _missing(parsed.envelope)
    assert parsed.byte_length == len(output)
    assert parsed.source_hash == sha256_bytes(output)


def test_an_unknown_field_populates_the_header_and_is_describe_output_invalid() -> None:
    parsed = _parse(_encode(_document(unexpected=1)))
    assert parsed.failure_code == PROTOCOL_DESCRIBE_OUTPUT_INVALID
    assert _missing(parsed.envelope)
    assert parsed.header == _conformant_header()


def test_an_unsupported_bootstrap_version_is_named_by_the_header() -> None:
    parsed = _parse(_encode(_document(bootstrap_schema_version="2.0.0")))
    assert parsed.failure_code == PROTOCOL_UNSUPPORTED_VERSION
    assert _missing(parsed.envelope)
    assert parsed.header.bootstrap_schema_version == "2.0.0"
    assert parsed.header.adapter_name == "fake.conformant"


@pytest.mark.parametrize(
    ("updates", "absent"),
    [
        ({"bootstrap_schema_version": 1}, "bootstrap_schema_version"),
        ({"bootstrap_schema_version": ""}, "bootstrap_schema_version"),
        ({"bootstrap_schema_version": "x" * 65}, "bootstrap_schema_version"),
        ({"adapter_name": None}, "adapter_name"),
        ({"adapter_name": "x" * 129}, "adapter_name"),
        ({"adapter_version": ["1.0.0"]}, "adapter_version"),
        ({"executable_hash": "a" * 65}, "executable_hash"),
        ({"executable_hash": 0}, "executable_hash"),
    ],
)
def test_a_wrongly_typed_empty_or_overlong_header_field_reads_as_missing(
    updates: dict[str, object], absent: str
) -> None:
    """Plan 3.11: the header never fails on a JSON object; an unreadable version is
    a strict-validation failure, not ``PROTOCOL.UNSUPPORTED_VERSION``."""
    parsed = _parse(_encode(_document(**updates)))
    assert parsed.failure_code == PROTOCOL_DESCRIBE_OUTPUT_INVALID
    assert _missing(getattr(parsed.header, absent))
    for field in _HEADER_FIELDS:
        if field != absent:
            assert not _missing(getattr(parsed.header, field)), field


@pytest.mark.parametrize("field", ["adapter_name", "bootstrap_schema_version"])
def test_a_lone_surrogate_escape_reads_as_missing_and_never_raises(field: str) -> None:
    """Cross-check finding: ``json.loads`` accepts the escape ``\\ud800`` and yields a
    string pydantic cannot represent, so the reader must treat a non-UTF-8-encodable
    value as MISSING rather than let the header construction raise (plan 3.11: the
    header readers never fail on a JSON object). The escape is built at runtime."""
    surrogate = chr(0xD800)
    parsed = _parse(_encode(_document(**{field: surrogate})))
    assert parsed.failure_code == PROTOCOL_DESCRIBE_OUTPUT_INVALID
    assert _missing(getattr(parsed.header, field))
    assert _missing(parsed.envelope)
    assert not _missing(parsed.header.adapter_version)
    canonical_json_bytes(parsed.header)
    # Control: the strict header itself refuses the value, so the predicate is
    # load-bearing rather than redundant.
    with pytest.raises(ValidationError):
        DescriptorHeader.model_validate({field: surrogate})


def _duplicated(output: bytes, *, first: bytes = b"", last: bytes = b"") -> bytes:
    """Repeat a top-level key: ``first`` goes after the opening brace, ``last``
    before the closing brace, so the repeated key has a definite position."""
    assert output.startswith(b"{")
    assert output.endswith(b"}")
    return b"{" + first + output[1:-1] + last + b"}"


@pytest.mark.parametrize(
    "output",
    [
        _duplicated(_bytes(), first=b'"bootstrap_schema_version":"2.0.0",'),
        _duplicated(_bytes(), last=b',"bootstrap_schema_version":"2.0.0"'),
        _duplicated(_bytes(), first=b'"adapter_name":"fake.other",'),
        _duplicated(
            _bytes(), last=b',"executable_hash":"' + _OTHER_HASH.encode() + b'"'
        ),
        _bytes().replace(
            b'"descriptor":{', b'"descriptor":{"network_required":true,', 1
        ),
    ],
    ids=[
        "version-first",
        "version-last",
        "adapter-name-first",
        "hash-last",
        "nested-descriptor",
    ],
)
def test_a_repeated_key_is_not_a_json_object_under_the_protocol(output: bytes) -> None:
    """Cross-check finding: the permissive and the strict parser may keep different
    values of a repeated key, so a repeated key anywhere is rejected before either
    value is read (header MISSING, never an exception, never UNSUPPORTED_VERSION)."""
    parsed = _parse(output)
    assert parsed.failure_code == PROTOCOL_DESCRIBE_OUTPUT_INVALID
    assert _missing(parsed.header)
    assert _missing(parsed.envelope)
    assert parsed.byte_length == len(output)


def test_key_order_is_not_a_repeated_key() -> None:
    """Control: a document with the same keys in another order is one JSON object."""
    reordered = dict(reversed(list(_document().items())))
    output = json.dumps(reordered, separators=(",", ":")).encode("utf-8")
    assert output != _bytes()
    parsed = _parse(output)
    assert parsed.envelope == _envelope()
    assert parsed.source_hash == sha256_bytes(output)


def test_a_header_field_of_exactly_the_alias_bound_is_read() -> None:
    """Preventive (began green): the header bound equals the identifier alias bound."""
    long_name = "a" * 128
    TypeAdapter(NormalizedIdentifier).validate_python(long_name)
    parsed = _parse(_encode(_document(adapter_name=long_name)))
    assert parsed.header.adapter_name == long_name
    assert parsed.failure_code == PROTOCOL_DESCRIBE_OUTPUT_INVALID


def test_a_header_identity_differing_from_the_descriptor_is_carried_by_the_header() -> (
    None
):
    """The reconciler's identity check (plan 5.4 check 4) reads the header before the
    recorded failure code, so the header carries the adapter's own claim."""
    document = _document(adapter_name="fake.other", executable_hash=_OTHER_HASH)
    parsed = _parse(_encode(document))
    assert parsed.failure_code == PROTOCOL_DESCRIBE_OUTPUT_INVALID
    assert parsed.header.adapter_name == "fake.other"
    assert parsed.header.executable_hash == _OTHER_HASH
    assert _missing(parsed.envelope)


def test_parse_arguments_are_type_and_bound_checked() -> None:
    text = _bytes().decode("utf-8")
    with pytest.raises(TypeError, match="bytes"):
        parse_bootstrap_descriptor(text, max_bytes=1024)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="max_bytes"):
        parse_bootstrap_descriptor(_bytes(), max_bytes=True)
    with pytest.raises(ValueError, match="max_bytes"):
        parse_bootstrap_descriptor(_bytes(), max_bytes=0)
    with pytest.raises(ValueError, match="max_bytes"):
        parse_bootstrap_descriptor(_bytes(), max_bytes=MAX_DESCRIPTOR_OUTPUT_BYTES + 1)
    parsed = _parse(_bytes(), max_bytes=MAX_DESCRIPTOR_OUTPUT_BYTES)
    assert not _missing(parsed.envelope)


def test_the_parse_record_restates_its_invariants() -> None:
    """Preventive (began green) except the converse UNSUPPORTED_VERSION case, which
    had its own RED (the cross-check-driven RED D)."""
    envelope = _envelope()
    header = _conformant_header()
    facts: dict[str, object] = {"byte_length": 1, "source_hash": _HASH}
    exactly_one = "exactly one of envelope and failure_code"
    with pytest.raises(ValidationError, match=exactly_one):
        DescriptorParse.model_validate(facts)
    with pytest.raises(ValidationError, match=exactly_one):
        DescriptorParse.model_validate(
            {
                **facts,
                "header": header,
                "envelope": envelope,
                "failure_code": PROTOCOL_UNSUPPORTED_VERSION,
            }
        )
    with pytest.raises(ValidationError, match="describe parse code"):
        DescriptorParse.model_validate(
            {
                **facts,
                "header": header,
                "failure_code": PROTOCOL_IDENTITY_OR_SEQUENCE_VIOLATION,
            }
        )
    with pytest.raises(ValidationError, match="without a header"):
        DescriptorParse.model_validate(
            {**facts, "failure_code": PROTOCOL_UNSUPPORTED_VERSION}
        )
    with pytest.raises(ValidationError, match="readable unsupported"):
        DescriptorParse.model_validate(
            {**facts, "header": header, "failure_code": PROTOCOL_UNSUPPORTED_VERSION}
        )
    with pytest.raises(ValidationError, match="unsupported version records"):
        DescriptorParse.model_validate(
            {
                **facts,
                "header": DescriptorHeader(bootstrap_schema_version="2.0.0"),
                "failure_code": PROTOCOL_DESCRIBE_OUTPUT_INVALID,
            }
        )
    with pytest.raises(ValidationError, match="header agreeing"):
        DescriptorParse.model_validate({**facts, "envelope": envelope})
    with pytest.raises(ValidationError, match="header agreeing"):
        DescriptorParse.model_validate(
            {
                **facts,
                "header": DescriptorHeader(adapter_name="fake.other"),
                "envelope": envelope,
            }
        )
    with pytest.raises(ValidationError, match="byte_length"):
        DescriptorParse.model_validate(
            {
                **facts,
                "byte_length": -1,
                "failure_code": PROTOCOL_DESCRIBE_OUTPUT_INVALID,
            }
        )
    parsed = DescriptorParse.model_validate(
        {**facts, "header": header, "envelope": envelope}
    )
    assert parsed.envelope == envelope


def test_the_descriptor_header_ignores_unknown_keys_but_stays_strict() -> None:
    """Preventive (began green): plan 3.1's ``extra="ignore"`` header reader."""
    header = DescriptorHeader.model_validate(
        {"adapter_name": "fake.conformant", "other": 1}
    )
    assert header.adapter_name == "fake.conformant"
    assert _missing(header.adapter_version)
    with pytest.raises(ValidationError, match="string"):
        DescriptorHeader.model_validate({"adapter_name": 1})
    with pytest.raises(ValidationError, match="frozen"):
        header.adapter_name = "x"


# --- describe_availability_observation ---------------------------------------------


def test_a_described_verdict_mints_an_available_observation_from_the_descriptor() -> (
    None
):
    descriptor = _descriptor(network_required=True, credentials_required=True)
    observation = _observation(descriptor=descriptor)
    assert observation.available is True
    assert _missing(observation.reason_code)
    assert observation.network_required is True
    assert observation.credentials_required is True
    assert observation.schema_version == "1.0.0"
    assert observation.availability_observation_id == _OBSERVATION_ID
    assert observation.adapter_name == "fake.conformant"
    assert observation.adapter_version == "1.0.0"
    assert observation.executable_path == _EXECUTABLE_PATH
    assert observation.executable_hash == _HASH
    assert observation.runtime_version == "3.12.13"
    assert observation.operating_system is OperatingSystem.WINDOWS
    assert observation.observed_at_utc == _OBSERVED
    assert observation.expires_at_utc == _EXPIRES
    assert _observation().network_required is False
    assert _observation().credentials_required is False


def test_a_described_verdict_requires_no_primary_code_and_a_descriptor() -> None:
    with pytest.raises(ValueError, match="no primary code"):
        _observation(primary_code=ADAPTER_UNAVAILABLE)
    with pytest.raises(ValueError, match="requires its descriptor"):
        _observation(descriptor=MISSING)


def test_describe_unavailable_mints_the_primary_code_as_the_reason() -> None:
    with_descriptor = _observation(
        verdict=ReconciliationVerdict.DESCRIBE_UNAVAILABLE,
        primary_code=ADAPTER_UNAVAILABLE,
        descriptor=_descriptor(network_required=True),
    )
    assert with_descriptor.available is False
    assert with_descriptor.reason_code == ADAPTER_UNAVAILABLE
    assert with_descriptor.network_required is True
    assert with_descriptor.credentials_required is False
    without = _observation(
        verdict=ReconciliationVerdict.DESCRIBE_UNAVAILABLE,
        primary_code=PROTOCOL_DESCRIBE_OUTPUT_INVALID,
        descriptor=MISSING,
    )
    assert without.available is False
    assert without.reason_code == PROTOCOL_DESCRIBE_OUTPUT_INVALID
    assert without.network_required is False
    assert without.credentials_required is False


def test_a_timed_out_describe_projects_the_deadline_code_without_a_descriptor() -> None:
    observation = _observation(
        verdict=MISSING, primary_code=PROCESS_DESCRIBE_TIMED_OUT, descriptor=MISSING
    )
    assert observation.available is False
    assert observation.reason_code == PROCESS_DESCRIBE_TIMED_OUT
    assert observation.network_required is False
    assert observation.credentials_required is False


@pytest.mark.parametrize(
    "verdict",
    [ReconciliationVerdict.DESCRIBE_UNAVAILABLE, MISSING],
    ids=["unavailable", "absent"],
)
def test_an_unavailable_projection_requires_a_primary_code(verdict: object) -> None:
    with pytest.raises(ValueError, match="requires a primary code"):
        _observation(verdict=verdict, primary_code=MISSING, descriptor=MISSING)


@pytest.mark.parametrize("verdict", _RUN_VERDICTS, ids=lambda v: v.value)
def test_validate_and_run_verdicts_are_rejected(verdict: ReconciliationVerdict) -> None:
    with pytest.raises(ValueError, match="validate or run verdict"):
        _observation(verdict=verdict, primary_code=MISSING)
    with pytest.raises(ValueError, match="validate or run verdict"):
        _observation(
            verdict=verdict, primary_code=ADAPTER_UNAVAILABLE, descriptor=MISSING
        )
    with pytest.raises(TypeError, match="ReconciliationVerdict"):
        _observation(verdict=verdict.value)


def test_a_cancelled_describe_mints_no_observation() -> None:
    assert PROCESS_CANCELLED in STAGE6_DIAGNOSTIC_CODES
    with pytest.raises(ValueError, match="cancelled describe"):
        _observation(
            verdict=ReconciliationVerdict.DESCRIBE_UNAVAILABLE,
            primary_code=PROCESS_CANCELLED,
            descriptor=MISSING,
        )
    with pytest.raises(ValueError, match="cancelled describe"):
        _observation(
            verdict=MISSING, primary_code=PROCESS_CANCELLED, descriptor=MISSING
        )


@pytest.mark.parametrize("code", ["CORE.INVARIANT_VIOLATION", "not-a-code", ""])
def test_the_primary_code_must_be_a_stage_six_code(code: str) -> None:
    with pytest.raises(ValueError, match="not a Stage 6 code"):
        _observation(verdict=MISSING, primary_code=code, descriptor=MISSING)


@pytest.mark.parametrize(
    "updates",
    [
        {"adapter_name": "fake.other"},
        {"adapter_version": "2.0.0"},
        {"executable_hash": _OTHER_HASH},
    ],
    ids=["name", "version", "hash"],
)
def test_a_descriptor_with_another_identity_is_refused(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValueError, match="descriptor's identity"):
        _observation(**updates)
    with pytest.raises(ValueError, match="descriptor's identity"):
        _observation(
            verdict=ReconciliationVerdict.DESCRIBE_UNAVAILABLE,
            primary_code=ADAPTER_UNAVAILABLE,
            **updates,
        )
    with pytest.raises(TypeError, match="AdapterDescriptor"):
        _observation(descriptor=_engine())


def test_the_observation_model_rules_still_apply_to_the_projection() -> None:
    with pytest.raises(ValidationError, match="expiry must follow"):
        _observation(expires_at_utc=_OBSERVED)
    with pytest.raises(ValidationError):
        _observation(observation_id="run_2c4d6e80-1f3a-4b5c-9d8e-7f6a5b4c3d2e")
    with pytest.raises(ValidationError):
        _observation(observed_at_utc=datetime(2026, 9, 10, 12, 0))  # noqa: DTZ001
    observation = _observation()
    assert (
        RuntimeAvailabilityObservation.model_validate_json(
            observation.model_dump_json()
        )
        == observation
    )
