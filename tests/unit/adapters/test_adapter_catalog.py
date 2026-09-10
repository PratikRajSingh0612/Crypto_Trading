"""Stage 6 Task 1: the explicit adapter catalog (Stage 6 plan section 3.5).

`AdapterCatalogEntry` is the core-owned, configuration-shaped record of one
registered executable; `AdapterCatalog` is the specification 8.2 port; and
`FrozenAdapterCatalog` is the pure clock-injected implementation that never
scans a directory. A missing identity is an ordinary availability fact and comes
back as `ADAPTER.UNAVAILABLE` inside a `Failure`, stamped with the injected
clock's instant, never raised.
"""

from __future__ import annotations

import ast
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Literal, cast

import pytest
from pydantic import TypeAdapter, ValidationError

from crypto_lab.adapters import catalog, diagnostics, limits, paths, vocabulary
from crypto_lab.adapters.catalog import (
    AbsoluteLocalExecutablePath,
    AdapterCatalog,
    AdapterCatalogEntry,
    FrozenAdapterCatalog,
    validate_absolute_local_executable_path,
)
from crypto_lab.adapters.limits import MAX_CATALOG_ENTRIES
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import (
    MAX_DETAIL_STRING,
    DiagnosticCategory,
    DiagnosticDetailValue,
    DiagnosticSeverity,
)
from crypto_lab.domain.experiment import EngineIdentity
from crypto_lab.domain.results import Failure, Success
from doubles.experiments import CountingClock, FixedClock

_INSTANT = datetime(2026, 9, 10, 12, 0, tzinfo=UTC)
_LATER = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)
_FIELD_ORDER = (
    "adapter_name",
    "adapter_version",
    "engine",
    "executable_path",
    "executable_hash",
    "runtime_metadata",
)
#: Every root a Task 1 module may import: the standard-library subset of the
#: Stage 3 allowlist that reaches no filesystem, environment, clock, random or
#: process source, plus pydantic and the project itself.
_PURE_ROOTS = frozenset(
    {
        "__future__",
        "collections",
        "dataclasses",
        "datetime",
        "enum",
        "re",
        "typing",
        "pydantic",
        "crypto_lab",
    }
)
_TASK1_MODULES = [vocabulary, limits, paths, catalog, diagnostics]


def _engine() -> EngineIdentity:
    return EngineIdentity(engine_name="fake.engine", engine_version="1.0.0")


def _entry(**overrides: object) -> AdapterCatalogEntry:
    payload: dict[str, object] = {
        "adapter_name": "fake.conformant",
        "adapter_version": "1.0.0",
        "engine": _engine(),
        "executable_path": "C:/adapters/fake_adapter.py",
        "executable_hash": "a" * 64,
        "runtime_metadata": {},
    }
    payload.update(overrides)
    return AdapterCatalogEntry.model_validate(payload)


def _catalog(
    *entries: AdapterCatalogEntry, clock: FixedClock | None = None
) -> FrozenAdapterCatalog:
    return FrozenAdapterCatalog(entries, clock=clock or FixedClock(_INSTANT))


def _failure(result: object) -> Failure:
    assert isinstance(result, Failure)
    return result


# --- AdapterCatalogEntry -------------------------------------------------------


def test_the_entry_declares_exactly_the_plan_fields_in_order() -> None:
    """Trust class K (plan 3.1 and 3.5): unpublished, so no envelope version."""
    assert tuple(AdapterCatalogEntry.model_fields) == _FIELD_ORDER
    assert "schema_version" not in AdapterCatalogEntry.model_fields
    for field in AdapterCatalogEntry.model_fields.values():
        assert field.is_required()


def test_the_entry_rejects_unknown_fields_and_hides_their_input() -> None:
    marker = "INPUT_MARKER_MUST_NOT_APPEAR"
    payload = _entry().model_dump(mode="python")
    payload["environment"] = marker
    with pytest.raises(ValidationError, match="extra_forbidden") as captured:
        AdapterCatalogEntry.model_validate(payload)
    assert marker not in str(captured.value)


def test_the_entry_is_frozen_round_trips_and_dumps_detached_copies() -> None:
    entry = _entry(runtime_metadata={"runtime": "cpython-3.12", "flags": ["-I"]})
    with pytest.raises(ValidationError, match="frozen"):
        entry.adapter_version = "2.0.0"
    modes: tuple[Literal["python", "json"], ...] = ("python", "json")
    for mode in modes:
        dumped = entry.model_dump(mode=mode)
        assert dumped["runtime_metadata"] is not entry.runtime_metadata
        assert (
            dumped["runtime_metadata"]["flags"] is not entry.runtime_metadata["flags"]
        )
        dumped["runtime_metadata"]["flags"].append("-B")
        assert entry.runtime_metadata["flags"] == ["-I"]
    assert AdapterCatalogEntry.model_validate(entry.model_dump(mode="python")) == entry
    assert AdapterCatalogEntry.model_validate_json(entry.model_dump_json()) == entry
    assert canonical_json_bytes(_entry()) == (
        b'{"adapter_name":"fake.conformant","adapter_version":"1.0.0",'
        b'"engine":{"engine_name":"fake.engine","engine_version":"1.0.0"},'
        b'"executable_hash":"' + b"a" * 64 + b'",'
        b'"executable_path":"C:/adapters/fake_adapter.py","runtime_metadata":{}}'
    )


@pytest.mark.parametrize(
    "value",
    [
        "C:/adapters/fake_adapter.py",
        "d:\\Adapters\\Fake Adapter\\fake.py",
        "Z:/x",
        "C:/a..b/fake.py",
    ],
)
def test_an_absolute_local_windows_executable_path_is_accepted(value: str) -> None:
    assert _entry(executable_path=value).executable_path == value


@pytest.mark.parametrize(
    ("value", "rule"),
    [
        ("adapters/fake_adapter.py", "absolute local Windows path"),
        ("/adapters/fake_adapter.py", "absolute local Windows path"),
        ("\\\\server\\share\\fake_adapter.py", "absolute local Windows path"),
        ("//server/share/fake_adapter.py", "absolute local Windows path"),
        ("C:adapters/fake_adapter.py", "absolute local Windows path"),
        ("..", "absolute local Windows path"),
        ("C:/adapters/../fake_adapter.py", "'..' segment"),
        ("C:\\adapters\\..\\fake_adapter.py", "'..' segment"),
        ("C:/..", "'..' segment"),
        # The reused `ExecutablePath` rules still apply underneath.
        (" C:/adapters/fake_adapter.py", "surrounding whitespace"),
        ("C:/adapters/fake\x00adapter.py", "control character"),
        ("", "at least 1 character"),
    ],
)
def test_a_relative_traversing_or_malformed_executable_path_is_rejected(
    value: str,
    rule: str,
) -> None:
    with pytest.raises(ValidationError, match=rule):
        _entry(executable_path=value)


@pytest.mark.parametrize(
    "runtime_metadata",
    [
        {"api_key": "forbidden"},
        {"nested": {"Auth-Token": "forbidden"}},
        {"attempt_token": "a" * 32},
        {"attemptToken": "forbidden"},
        {"credentials": "forbidden"},
        {"ratio": 0.5},
        {"count": 2**63},
        {"message": "x" * 2049},
        {"items": list(range(65))},
        {f"key{index}": index for index in range(65)},
        {"payload": ["x" * 2_048 for _ in range(8)]},
        {"groups": [{f"key{index}": index for index in range(64)} for _ in range(4)]},
        None,
    ],
)
def test_secret_like_oversized_or_untyped_runtime_metadata_is_rejected(
    runtime_metadata: object,
) -> None:
    with pytest.raises(ValidationError):
        _entry(runtime_metadata=runtime_metadata)


def test_runtime_metadata_rejects_excessive_depth() -> None:
    nested: object = "leaf"
    for _ in range(10):
        nested = {"nested": nested}
    with pytest.raises(ValidationError, match="maximum depth"):
        _entry(runtime_metadata={"root": nested})


def test_bounded_non_secret_runtime_metadata_is_accepted() -> None:
    metadata: dict[str, DiagnosticDetailValue] = {
        "runtime": "cpython-3.12",
        "flags": ["-I", "-B"],
        "network": False,
        "port": None,
        "retries": 0,
        "nested": {"depth": 2},
    }
    entry = _entry(runtime_metadata=metadata)
    assert entry.runtime_metadata == metadata
    assert entry.model_dump(mode="json")["runtime_metadata"] == metadata


# --- AdapterCatalog and FrozenAdapterCatalog -------------------------------------


def test_the_port_is_a_runtime_checkable_protocol_with_exactly_two_operations() -> None:
    """Specification 8.2 verbatim: `get(adapter_name, adapter_version)` and
    `list_registered()`; the frozen catalog satisfies it structurally."""
    assert isinstance(_catalog(), AdapterCatalog)
    members = {
        name
        for name in vars(AdapterCatalog)
        if not name.startswith("_") and callable(vars(AdapterCatalog)[name])
    }
    assert members == {"get", "list_registered"}

    class _Half:
        def get(self, adapter_name: str, adapter_version: str) -> object:
            return (adapter_name, adapter_version)

    assert not isinstance(_Half(), AdapterCatalog)


def test_a_registered_identity_is_returned_without_reading_the_clock() -> None:
    clock = CountingClock(_INSTANT)
    alpha = _entry(adapter_name="fake.alpha")
    beta = _entry(adapter_name="fake.beta", adapter_version="1.2.0")
    registry = _catalog(alpha, beta, clock=clock)
    result = registry.get("fake.beta", "1.2.0")
    assert isinstance(result, Success)
    assert result.value is beta
    assert registry.list_registered() == (alpha, beta)
    assert type(registry.list_registered()) is tuple
    assert clock.reads == 0


def test_a_missing_identity_is_an_unavailable_failure_stamped_by_the_clock() -> None:
    clock = CountingClock(_INSTANT)
    registry = _catalog(_entry(), clock=clock)
    result = _failure(registry.get("fake.absent", "1.0.0"))
    assert clock.reads == 1
    (diagnostic,) = result.diagnostics
    assert diagnostic.error_code == "ADAPTER.UNAVAILABLE"
    assert diagnostic.category is DiagnosticCategory.ADAPTER_UNAVAILABILITY
    assert diagnostic.severity is DiagnosticSeverity.ERROR
    assert diagnostic.retriable is True
    assert diagnostic.source_component == "adapters.catalog"
    assert diagnostic.timestamp_utc == _INSTANT
    assert diagnostic.details == {
        "adapter_name": "fake.absent",
        "adapter_version": "1.0.0",
    }
    assert diagnostic.causal_diagnostic_ids == ()
    dumped = diagnostic.model_dump(mode="json")
    for absent in ("experiment_id", "run_id", "invocation_id", "engine"):
        assert absent not in dumped
    # A registered name at an unregistered version is the same availability fact.
    version_miss = _failure(registry.get("fake.conformant", "9.9.9"))
    assert version_miss.diagnostics[0].details["adapter_version"] == "9.9.9"
    assert clock.reads == 2


def test_the_unavailability_identity_is_derived_from_the_request_not_the_clock() -> (
    None
):
    early = _failure(_catalog(_entry(), clock=FixedClock(_INSTANT)).get("x.y", "1.0.0"))
    late = _failure(_catalog(_entry(), clock=FixedClock(_LATER)).get("x.y", "1.0.0"))
    other = _failure(_catalog(_entry(), clock=FixedClock(_INSTANT)).get("x.z", "1.0.0"))
    assert early.diagnostics[0].diagnostic_id == late.diagnostics[0].diagnostic_id
    assert early.diagnostics[0].timestamp_utc != late.diagnostics[0].timestamp_utc
    assert early.diagnostics[0].diagnostic_id != other.diagnostics[0].diagnostic_id


def test_lookups_take_built_in_strings_only() -> None:
    registry = _catalog(_entry())
    with pytest.raises(TypeError, match="built-in strings"):
        registry.get(cast("str", None), "1.0.0")
    with pytest.raises(TypeError, match="built-in strings"):
        registry.get("fake.conformant", cast("str", 1))


def test_lookups_are_bounded_by_the_diagnostic_detail_string() -> None:
    """Every identity a `Diagnostic` detail string can carry still yields the
    plan's `Failure`; only a longer one, which no `Failure` could carry, is
    refused by name, so `get` never raises a validation error."""
    registry = _catalog(_entry())
    longest = "a" * MAX_DETAIL_STRING
    assert MAX_DETAIL_STRING == 2_048
    name_miss = _failure(registry.get(longest, "1.0.0"))
    assert name_miss.diagnostics[0].details["adapter_name"] == longest
    version_miss = _failure(registry.get("fake.absent", longest))
    assert version_miss.diagnostics[0].details["adapter_version"] == longest
    with pytest.raises(ValueError, match="detail string bound"):
        registry.get(longest + "a", "1.0.0")
    with pytest.raises(ValueError, match="detail string bound"):
        registry.get("fake.absent", longest + "a")


def test_an_empty_catalog_is_valid_and_registers_nothing() -> None:
    registry = _catalog()
    assert registry.list_registered() == ()
    assert isinstance(registry.get("fake.conformant", "1.0.0"), Failure)


def test_duplicate_or_unsorted_identities_are_rejected_at_construction() -> None:
    first = _entry(adapter_name="fake.alpha")
    same = _entry(adapter_name="fake.alpha", executable_hash="b" * 64)
    later = _entry(adapter_name="fake.beta")
    with pytest.raises(ValueError, match="unique"):
        _catalog(first, same)
    with pytest.raises(ValueError, match="sorted"):
        _catalog(later, first)
    with pytest.raises(ValueError, match="sorted"):
        _catalog(
            _entry(adapter_name="fake.alpha", adapter_version="1.1.0"),
            _entry(adapter_name="fake.alpha", adapter_version="1.0.0"),
        )
    assert _catalog(first, later).list_registered() == (first, later)


def test_the_catalog_holds_at_most_the_configured_entry_bound() -> None:
    entries = tuple(
        _entry(adapter_name=f"fake.adapter-{index:02d}")
        for index in range(MAX_CATALOG_ENTRIES + 1)
    )
    assert len(_catalog(*entries[:MAX_CATALOG_ENTRIES]).list_registered()) == 32
    with pytest.raises(ValueError, match="at most 32 entries"):
        _catalog(*entries)


def test_construction_requires_a_tuple_of_entries_and_an_injected_clock() -> None:
    entry = _entry()
    with pytest.raises(TypeError, match="must be a tuple"):
        FrozenAdapterCatalog(
            cast("tuple[AdapterCatalogEntry, ...]", [entry]), clock=FixedClock(_INSTANT)
        )
    with pytest.raises(TypeError, match="AdapterCatalogEntry"):
        FrozenAdapterCatalog(
            cast("tuple[AdapterCatalogEntry, ...]", (entry.model_dump(),)),
            clock=FixedClock(_INSTANT),
        )
    with pytest.raises(TypeError, match="injected Clock"):
        FrozenAdapterCatalog((entry,), clock=cast("FixedClock", object()))
    with pytest.raises(TypeError, match="injected Clock"):
        FrozenAdapterCatalog((entry,), clock=cast("FixedClock", _INSTANT))


def test_the_catalog_is_a_frozen_slotted_dataclass_without_a_mutable_surface() -> None:
    entry = _entry()
    registry = _catalog(entry)
    with pytest.raises(FrozenInstanceError):
        registry.entries = ()  # type: ignore[misc]
    with pytest.raises(FrozenInstanceError):
        registry.clock = FixedClock(_LATER)  # type: ignore[misc]
    assert not hasattr(registry, "__dict__")
    assert registry.entries == (entry,)
    # The clock takes no part in equality or repr; the entries do.
    assert registry == _catalog(entry, clock=FixedClock(_LATER))
    assert registry != _catalog()
    assert "clock" not in repr(registry)
    with pytest.raises(TypeError, match="clock"):
        FrozenAdapterCatalog((entry,))  # type: ignore[call-arg]


def test_the_absolute_local_rule_is_reusable_as_a_function_and_an_alias() -> None:
    """Plan 3.7 binds Task 2's command paths to the same rule, so it is one
    module-level function and one alias rather than a model-bound validator."""
    assert validate_absolute_local_executable_path("C:/x/y.exe") == "C:/x/y.exe"
    with pytest.raises(ValueError, match="absolute local Windows path"):
        validate_absolute_local_executable_path("x/y.exe")
    with pytest.raises(ValueError, match=r"'\.\.' segment"):
        validate_absolute_local_executable_path("C:/x/../y.exe")
    adapter = TypeAdapter(AbsoluteLocalExecutablePath)
    assert adapter.validate_python("D:\\x\\y.exe") == "D:\\x\\y.exe"
    for invalid in ("x/y.exe", "C:/x/../y.exe", " C:/x", "C:/x\x00", ""):
        with pytest.raises(ValidationError):
            adapter.validate_python(invalid)


# --- Preventive: the Task 1 modules reach no filesystem, environment or process ---


@pytest.mark.parametrize("module", _TASK1_MODULES, ids=lambda m: m.__name__)
def test_each_task_one_module_imports_only_pure_roots_and_carries_no_token(
    module: ModuleType,
) -> None:
    """Preventive (begins green): plan 2.6 design rules and section 13. The
    catalog never scans, no module opens a file, reads a clock or the
    environment, imports outside `domain` and `adapters`, or carries the raw
    `AttemptToken` annotation (Task 1 owns no token-bearing material)."""
    source = Path(module.__file__ or "").read_text(encoding="utf-8")
    tree = ast.parse(source)
    roots: set[str] = set()
    project_packages: set[str] = set()
    imported_names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                roots.add(alias.name.partition(".")[0])
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
            imported_names.update(alias.name for alias in node.names)
            if node.module.startswith("crypto_lab."):
                project_packages.add(node.module.split(".")[1])
        elif isinstance(node, ast.Call):
            target = node.func
            called = (
                target.id
                if isinstance(target, ast.Name)
                else getattr(target, "attr", "")
            )
            assert called != "open", ast.dump(node)
    assert roots <= _PURE_ROOTS, sorted(roots - _PURE_ROOTS)
    assert project_packages <= {"domain", "adapters"}, sorted(project_packages)
    assert "AttemptToken" not in imported_names
    assert "attempt_token" not in source
    assert "subprocess" not in source
