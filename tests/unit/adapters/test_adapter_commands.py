"""Stage 6 Task 2: the adapter command contract (Stage 6 plan section 3.7).

`AdapterCommand` is the core-owned, configuration-shaped launch contract (trust
class K): the command kind, the catalog entry that is the sole source of the
executable, the invocation identity, the core-selected absolute paths the kind
requires and the snapshotted timeout. It carries no request material by value,
so it is never token-bearing. `argument_array` renders specification 14.1 exactly;
the executable itself is prepended by whoever launches, and Stage 6 never launches.
"""

from __future__ import annotations

from typing import Any, Final

import pytest
from pydantic import ValidationError

from crypto_lab.adapters.catalog import AdapterCatalogEntry
from crypto_lab.adapters.commands import AdapterCommand, argument_array
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.command_invocation import command_timeout_bounds
from crypto_lab.domain.experiment import EngineIdentity
from crypto_lab.domain.lifecycle import CommandKind
from doubles.experiments import INVOCATION_ID, RUN_ID

_FIELD_ORDER: Final = (
    "command_kind",
    "catalog_entry",
    "invocation_id",
    "request_path",
    "output_path",
    "work_dir",
    "result_path",
    "timeout_seconds",
)
_REQUEST_PATH: Final = f"C:/runtime/commands/{INVOCATION_ID}/request.json"
_OUTPUT_PATH: Final = f"C:/runtime/commands/{INVOCATION_ID}/output.json"
_WORK_DIR: Final = f"C:\\runtime\\runs\\{RUN_ID}\\work"
_RESULT_PATH: Final = f"C:\\runtime\\runs\\{RUN_ID}\\work\\adapter-result-manifest.json"
#: Request material an adapter command must never carry by value (plan 3.7, 13).
_REQUEST_MATERIAL_NAMES: Final = frozenset(
    {
        "attempt_token",
        "attempt_token_hash",
        "payload",
        "payload_hash",
        "request_id",
        "request_hash",
        "run_id",
        "experiment_id",
        "logical_slot_id",
        "attempt_number",
    }
)


def _entry(**overrides: object) -> AdapterCatalogEntry:
    payload: dict[str, object] = {
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "engine": EngineIdentity(engine_name="engine.alpha", engine_version="2.3.4"),
        "executable_path": "C:/adapters/alpha/adapter.exe",
        "executable_hash": "e" * 64,
        "runtime_metadata": {},
    }
    payload.update(overrides)
    return AdapterCatalogEntry.model_validate(payload)


def _fields(kind: CommandKind, **overrides: object) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "command_kind": kind,
        "catalog_entry": _entry(),
        "invocation_id": INVOCATION_ID,
        "request_path": _REQUEST_PATH,
        "timeout_seconds": 120,
    }
    if kind is CommandKind.RUN:
        payload["work_dir"] = _WORK_DIR
        payload["result_path"] = _RESULT_PATH
    else:
        payload["output_path"] = _OUTPUT_PATH
    payload.update(overrides)
    return payload


def _command(
    kind: CommandKind = CommandKind.RUN, **overrides: object
) -> AdapterCommand:
    return AdapterCommand.model_validate(_fields(kind, **overrides))


def _is_missing(value: object) -> bool:
    return repr(value) == "MISSING"


# --- Shape --------------------------------------------------------------------------


def test_the_command_declares_exactly_the_plan_fields_in_order() -> None:
    """Trust class K (plan 3.1 and 3.7): unpublished, so no envelope version."""
    assert tuple(AdapterCommand.model_fields) == _FIELD_ORDER
    assert "schema_version" not in AdapterCommand.model_fields
    governed = {"output_path", "work_dir", "result_path"}
    for name, field in AdapterCommand.model_fields.items():
        assert field.is_required() is (name not in governed)
    assert (
        AdapterCommand.model_fields["catalog_entry"].annotation is AdapterCatalogEntry
    )


def test_the_command_carries_no_request_material_by_value() -> None:
    assert not set(AdapterCommand.model_fields) & _REQUEST_MATERIAL_NAMES
    command = _command()
    text = canonical_json_bytes(command).decode()
    for name in _REQUEST_MATERIAL_NAMES:
        assert f'"{name}"' not in text


@pytest.mark.parametrize("kind", list(CommandKind))
def test_each_kind_accepts_exactly_its_governed_paths(kind: CommandKind) -> None:
    command = _command(kind)
    assert command.command_kind is kind
    assert command.request_path == _REQUEST_PATH
    if kind is CommandKind.RUN:
        assert _is_missing(command.output_path)
        assert command.work_dir == _WORK_DIR
        assert command.result_path == _RESULT_PATH
    else:
        assert command.output_path == _OUTPUT_PATH
        assert _is_missing(command.work_dir)
        assert _is_missing(command.result_path)


@pytest.mark.parametrize(
    ("kind", "changes", "reason"),
    [
        (CommandKind.RUN, {"output_path": _OUTPUT_PATH}, "output_path"),
        (CommandKind.RUN, {"work_dir": None}, "work_dir"),
        (CommandKind.RUN, {"result_path": None}, "result_path"),
        (CommandKind.VALIDATE, {"work_dir": _WORK_DIR}, "work_dir"),
        (CommandKind.VALIDATE, {"result_path": _RESULT_PATH}, "result_path"),
        (CommandKind.VALIDATE, {"output_path": None}, "output_path"),
        (CommandKind.DESCRIBE, {"work_dir": _WORK_DIR}, "work_dir"),
        (CommandKind.DESCRIBE, {"result_path": _RESULT_PATH}, "result_path"),
        (CommandKind.DESCRIBE, {"output_path": None}, "output_path"),
    ],
    ids=lambda value: value.value if isinstance(value, CommandKind) else "",
)
def test_a_path_the_kind_prohibits_or_requires_is_enforced(
    kind: CommandKind, changes: dict[str, object], reason: str
) -> None:
    """``None`` in ``changes`` removes the key; the record uses ``MISSING`` for
    absence and never accepts ``None`` (plan 3.1)."""
    payload = _fields(kind)
    for name, value in changes.items():
        if value is None:
            payload.pop(name)
        else:
            payload[name] = value
    with pytest.raises(ValidationError, match=reason):
        AdapterCommand.model_validate(payload)
    payload = _fields(kind)
    for name in changes:
        payload[name] = None
    with pytest.raises(ValidationError):
        AdapterCommand.model_validate(payload)


@pytest.mark.parametrize(
    "path",
    [
        "runs/x/request.json",
        "./request.json",
        "../request.json",
        "C:/runtime/../request.json",
        "C:\\runtime\\..\\request.json",
        "\\\\server\\share\\request.json",
        "/runtime/request.json",
        " C:/runtime/request.json",
        "C:/runtime/request.json\x00",
        "",
    ],
)
@pytest.mark.parametrize(
    "field", ["request_path", "output_path", "work_dir", "result_path"]
)
def test_a_relative_traversing_or_malformed_path_is_rejected_anywhere(
    field: str, path: str
) -> None:
    kind = (
        CommandKind.RUN
        if field in {"work_dir", "result_path"}
        else CommandKind.VALIDATE
    )
    with pytest.raises(ValidationError, match=field):
        _command(kind, **{field: path})


@pytest.mark.parametrize(
    ("kind", "timeout_seconds"),
    [
        (CommandKind.DESCRIBE, 0),
        (CommandKind.DESCRIBE, 301),
        (CommandKind.VALIDATE, 0),
        (CommandKind.VALIDATE, 1801),
        (CommandKind.RUN, 0),
        (CommandKind.RUN, 604801),
    ],
)
def test_the_timeout_stays_within_the_kinds_bounds(
    kind: CommandKind, timeout_seconds: int
) -> None:
    with pytest.raises(ValidationError, match="timeout_seconds"):
        _command(kind, timeout_seconds=timeout_seconds)
    bounds = command_timeout_bounds(kind)
    for edge in (bounds.minimum_seconds, bounds.maximum_seconds):
        assert _command(kind, timeout_seconds=edge).timeout_seconds == edge
    with pytest.raises(ValidationError, match="timeout_seconds"):
        _command(kind, timeout_seconds=True)


def test_the_command_is_strict_frozen_closed_and_round_trips() -> None:
    command = _command()
    with pytest.raises(ValidationError, match="frozen"):
        command.timeout_seconds = 1
    with pytest.raises(ValidationError, match="frozen"):
        command.catalog_entry.executable_path = "C:/other.exe"
    dumped = command.model_dump(mode="python")
    dumped["attempt_token"] = "A" * 32
    with pytest.raises(ValidationError, match="extra_forbidden") as captured:
        AdapterCommand.model_validate(dumped)
    assert "A" * 32 not in str(captured.value)
    with pytest.raises(ValidationError, match="command_kind"):
        _command(command_kind="RUN")
    with pytest.raises(ValidationError, match="invocation_id"):
        _command(invocation_id=RUN_ID)
    assert AdapterCommand.model_validate(command.model_dump()) == command
    assert AdapterCommand.model_validate_json(command.model_dump_json()) == command
    assert "output_path" not in command.model_dump(mode="json")
    assert canonical_json_bytes(command) == canonical_json_bytes(_command())
    assert b"work_dir" in canonical_json_bytes(command)
    assert b"output_path" not in canonical_json_bytes(command)


# --- argument_array -------------------------------------------------------------------


def test_argument_array_renders_specification_fourteen_one_byte_exact() -> None:
    assert argument_array(_command(CommandKind.DESCRIBE)) == (
        "describe",
        "--request",
        _REQUEST_PATH,
        "--output",
        _OUTPUT_PATH,
    )
    assert argument_array(_command(CommandKind.VALIDATE)) == (
        "validate",
        "--request",
        _REQUEST_PATH,
        "--output",
        _OUTPUT_PATH,
    )
    assert argument_array(_command(CommandKind.RUN)) == (
        "run",
        "--request",
        _REQUEST_PATH,
        "--work-dir",
        _WORK_DIR,
        "--result",
        _RESULT_PATH,
    )


def test_argument_array_never_includes_the_executable_and_takes_only_a_command() -> (
    None
):
    for kind in CommandKind:
        rendered = argument_array(_command(kind))
        assert type(rendered) is tuple
        assert all(type(item) is str for item in rendered)
        assert "C:/adapters/alpha/adapter.exe" not in rendered
        assert rendered[0] == kind.value.lower()
    with pytest.raises(TypeError, match="AdapterCommand"):
        argument_array(_fields(CommandKind.RUN))  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="AdapterCommand"):
        argument_array(_entry())  # type: ignore[arg-type]
