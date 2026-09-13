"""Stage 7 Task 2: the six structural supervision ports (plan sections 2.3 and 3.4).

All six are ``typing.Protocol`` classes, ``runtime_checkable``, with no implementation
and no I/O. ``ProcessSupervisor`` is the application-facing port specification 8.1
places in ``process_supervision``; ``InvocationLifecycle`` is the structural port the
supervisor drives and the ``experiments`` layer implements without importing this
package, so every type reachable from it is a ``domain`` or ``adapters`` type;
``LaunchedProcess``, ``ProcessController``, ``SupervisionObserver`` and
``ReconciliationSource`` use the plan 3.3 records freely. The cases below pin the
exact member sets, the ``async`` shape of ``invoke``, the keyword-only ``close``
flags, structural conformance in both directions, the return types the later tasks
rely on, and the module's import closure.
"""

from __future__ import annotations

import ast
import inspect
from collections.abc import Callable
from pathlib import Path
from typing import IO, Protocol, cast, get_type_hints

from crypto_lab.adapters.commands import AdapterCommand
from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.ports import CancellationToken
from crypto_lab.domain.results import Result
from crypto_lab.process_supervision import models as models_module
from crypto_lab.process_supervision import ports as ports_module
from crypto_lab.process_supervision.models import (
    CleanupReport,
    InterruptOutcome,
    LaunchFailure,
    LaunchSpecification,
    ProcessInspection,
    RunReconciliationFacts,
    SupervisionOutcome,
    SupervisionTraceEntry,
    TerminationReport,
)
from crypto_lab.process_supervision.ports import (
    InvocationLifecycle,
    LaunchedProcess,
    ProcessController,
    ProcessSupervisor,
    ReconciliationSource,
    SupervisionObserver,
)

_PORTS: tuple[type, ...] = (
    ProcessSupervisor,
    InvocationLifecycle,
    LaunchedProcess,
    ProcessController,
    SupervisionObserver,
    ReconciliationSource,
)
_LIFECYCLE_MEMBERS = {
    "load",
    "linked_run",
    "begin_start",
    "request_envelope",
    "record_process_start",
    "record_terminal",
    "enrich",
    "append_event",
    "resolve_external_winner",
}
_LAUNCHED_PROPERTIES = {
    "pid",
    "creation_identity",
    "stdout",
    "stderr",
    "job_available",
    "job_error_code",
    "image_path",
}
#: The plan 2.6 import closure of ``ports.py``: typing, the sentinel and the project.
_PURE_ROOTS = frozenset({"__future__", "typing", "pydantic", "crypto_lab"})


def _public_members(port: type) -> set[str]:
    # the merged tests/unit/domain/test_domain_ports.py helper skips properties (not
    # callable); this one keeps them
    return {
        name
        for name, value in vars(port).items()
        if not name.startswith("_") and (callable(value) or isinstance(value, property))
    }


def _noop(self: object, *args: object, **kwargs: object) -> None:
    del self, args, kwargs


def _conforming(port: type, *, without: str | None = None) -> object:
    """A minimal structural double of ``port``, optionally missing one member."""
    namespace: dict[str, object] = {}
    for name, value in vars(port).items():
        if name.startswith("_") or name == without:
            continue
        if isinstance(value, property):
            namespace[name] = property(lambda self: None)
        elif callable(value):
            namespace[name] = _noop
    return type(f"Conforming{port.__name__}", (), namespace)()


def _getter(name: str) -> Callable[..., object]:
    """The getter of one ``LaunchedProcess`` property, for its return hint."""
    member = vars(LaunchedProcess)[name]
    assert isinstance(member, property)
    assert member.fget is not None
    return member.fget


def _annotation_names(node: ast.ClassDef) -> set[str]:
    names: set[str] = set()
    for item in node.body:
        if not isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        for argument in (
            *item.args.posonlyargs,
            *item.args.args,
            *item.args.kwonlyargs,
        ):
            if argument.annotation is not None:
                names.update(
                    n.id
                    for n in ast.walk(argument.annotation)
                    if isinstance(n, ast.Name)
                )
        if item.returns is not None:
            names.update(
                n.id for n in ast.walk(item.returns) if isinstance(n, ast.Name)
            )
    return names


def _module_tree() -> ast.Module:
    source = ports_module.__file__
    assert source is not None
    return ast.parse(Path(source).read_text(encoding="utf-8"))


def _class_node(name: str) -> ast.ClassDef:
    (node,) = (
        item
        for item in _module_tree().body
        if isinstance(item, ast.ClassDef) and item.name == name
    )
    return node


# --------------------------------------------------------------------------
# The plan's Step 1 sketch, verbatim
# --------------------------------------------------------------------------


def test_the_six_ports_are_runtime_checkable_protocols_with_exact_members() -> None:
    assert _public_members(ProcessSupervisor) == {"invoke"}
    assert _public_members(InvocationLifecycle) == {
        "load",
        "linked_run",
        "begin_start",
        "request_envelope",
        "record_process_start",
        "record_terminal",
        "enrich",
        "append_event",
        "resolve_external_winner",
    }
    assert _public_members(ProcessController) == {"launch", "inspect", "terminate_tree"}
    assert _public_members(LaunchedProcess) == {
        "pid",
        "creation_identity",
        "stdout",
        "stderr",
        "wait",
        "interrupt",
        "terminate_tree",
        "cancel_read",
        "close",
        "job_available",
        "job_error_code",
        "image_path",
    }
    assert _public_members(SupervisionObserver) == {"observe"}
    assert _public_members(ReconciliationSource) == {
        "list_reconciliation_targets",
        "run_facts",
    }
    assert set(inspect.signature(LaunchedProcess.close).parameters) == {
        "self",
        "close_stdout",
        "close_stderr",
    }
    assert inspect.iscoroutinefunction(ProcessSupervisor.invoke)


# --------------------------------------------------------------------------
# Protocol shape and structural conformance
# --------------------------------------------------------------------------


def test_every_port_is_a_runtime_checkable_protocol_that_object_fails() -> None:
    for port in _PORTS:
        assert Protocol in cast("tuple[object, ...]", port.__mro__), port
        assert getattr(port, "_is_protocol", False) is True, port
        assert getattr(port, "_is_runtime_protocol", False) is True, port
        assert not isinstance(object(), port), port
    assert {port.__name__ for port in _PORTS} == set(ports_module.__all__)
    assert list(ports_module.__all__) == sorted(ports_module.__all__)


def test_a_structural_double_conforms_and_a_missing_member_breaks_conformance() -> None:
    for port in _PORTS:
        assert isinstance(_conforming(port), port), port
        for member in sorted(_public_members(port)):
            assert not isinstance(_conforming(port, without=member), port), (
                port,
                member,
            )


def test_the_ports_are_distinct_contracts() -> None:
    observer = _conforming(SupervisionObserver)
    assert isinstance(observer, SupervisionObserver)
    for other in _PORTS:
        if other is not SupervisionObserver:
            assert not isinstance(observer, other), other
    lifecycle = _conforming(InvocationLifecycle)
    assert isinstance(lifecycle, InvocationLifecycle)
    assert not isinstance(lifecycle, ReconciliationSource)
    assert not isinstance(lifecycle, ProcessController)


def test_the_launched_process_exposes_its_facts_as_properties() -> None:
    for name in _LAUNCHED_PROPERTIES:
        assert isinstance(vars(LaunchedProcess)[name], property), name
    for name in _public_members(LaunchedProcess) - _LAUNCHED_PROPERTIES:
        assert inspect.isfunction(vars(LaunchedProcess)[name]), name


# --------------------------------------------------------------------------
# Signatures and the return types later tasks build on
# --------------------------------------------------------------------------


def test_the_method_signatures_are_the_plan_signatures() -> None:
    close = inspect.signature(LaunchedProcess.close).parameters
    assert close["close_stdout"].kind is inspect.Parameter.KEYWORD_ONLY
    assert close["close_stderr"].kind is inspect.Parameter.KEYWORD_ONLY
    assert list(inspect.signature(LaunchedProcess.wait).parameters) == [
        "self",
        "timeout_seconds",
    ]
    assert list(inspect.signature(LaunchedProcess.cancel_read).parameters) == [
        "self",
        "native_thread_id",
    ]
    assert list(inspect.signature(LaunchedProcess.terminate_tree).parameters) == [
        "self",
        "exit_code",
    ]
    assert list(inspect.signature(ProcessController.terminate_tree).parameters) == [
        "self",
        "identity",
        "exit_code",
    ]
    assert list(inspect.signature(ProcessController.launch).parameters) == [
        "self",
        "specification",
    ]
    assert list(inspect.signature(ProcessSupervisor.invoke).parameters) == [
        "self",
        "command",
        "cancellation",
    ]
    for name in ("begin_start", "record_process_start", "record_terminal", "enrich"):
        parameters = inspect.signature(getattr(InvocationLifecycle, name)).parameters
        assert list(parameters)[:2] == ["self", "invocation_id"], name
        for parameter in list(parameters.values())[2:]:
            assert parameter.kind is inspect.Parameter.KEYWORD_ONLY, (name, parameter)
        assert "expected_revision" in parameters, name
    terminal = inspect.signature(InvocationLifecycle.record_terminal).parameters
    assert list(terminal) == [
        "self",
        "invocation_id",
        "expected_revision",
        "target_state",
        "primary",
        "additional",
        "native_exit_value",
    ]
    enrich = inspect.signature(InvocationLifecycle.enrich).parameters
    assert list(enrich) == [
        "self",
        "invocation_id",
        "expected_revision",
        "native_exit_value",
        "cleanup_complete",
        "additional",
    ]
    winner = inspect.signature(InvocationLifecycle.resolve_external_winner).parameters
    assert list(winner) == ["self", "invocation_id", "expected_revision", "primary"]


def test_the_return_and_parameter_types_are_the_plan_types() -> None:
    assert get_type_hints(LaunchedProcess.wait)["return"] == int | None
    assert get_type_hints(LaunchedProcess.wait)["timeout_seconds"] is float
    assert get_type_hints(LaunchedProcess.interrupt)["return"] is InterruptOutcome
    assert get_type_hints(LaunchedProcess.terminate_tree)["return"] is TerminationReport
    assert get_type_hints(LaunchedProcess.cancel_read)["return"] is bool
    assert get_type_hints(LaunchedProcess.close)["return"] is CleanupReport
    assert get_type_hints(_getter("stdout"))["return"] == IO[bytes]
    assert get_type_hints(_getter("stderr"))["return"] == IO[bytes]
    assert get_type_hints(_getter("pid"))["return"] is int
    assert get_type_hints(_getter("creation_identity"))["return"] is str
    assert get_type_hints(_getter("job_available"))["return"] is bool
    launch = get_type_hints(ProcessController.launch)
    assert launch["specification"] is LaunchSpecification
    assert launch["return"] == LaunchedProcess | LaunchFailure
    assert get_type_hints(ProcessController.inspect)["return"] is ProcessInspection
    assert get_type_hints(ProcessController.terminate_tree)["return"] is (
        TerminationReport
    )
    observe = get_type_hints(SupervisionObserver.observe)
    assert observe["entry"] is SupervisionTraceEntry
    assert observe["return"] is type(None)
    invoke = get_type_hints(ProcessSupervisor.invoke)
    assert invoke["command"] is AdapterCommand
    assert invoke["cancellation"] is CancellationToken
    # `Result` is the merged discriminated alias (plan 2.5 reading 1), so a
    # `Failure` is representable without naming it here.
    assert invoke["return"].__origin__ is Result
    assert invoke["return"].__args__ == (SupervisionOutcome,)
    load = get_type_hints(InvocationLifecycle.load)["return"]
    assert load.__origin__ is Result
    assert load.__args__ == (CommandInvocationRecord,)
    run_facts = get_type_hints(ReconciliationSource.run_facts)["return"]
    assert run_facts.__origin__ is Result
    assert run_facts.__args__ == (RunReconciliationFacts,)


# --------------------------------------------------------------------------
# The direction rule: the lifecycle port names no plan 3.3 record
# --------------------------------------------------------------------------


def test_the_lifecycle_port_reaches_only_domain_and_adapters_types() -> None:
    """Plan 3.4: ``experiments`` implements ``InvocationLifecycle`` without importing
    this package, so no parameter or return annotation may name a ``models`` name."""
    names = _annotation_names(_class_node("InvocationLifecycle"))
    assert names
    assert names.isdisjoint(set(models_module.__all__)), names & set(
        models_module.__all__
    )
    assert {"InvocationId", "CommandInvocationRecord", "EngineRunRecord"} <= names


def test_the_other_five_ports_use_the_plan_records() -> None:
    assert {"AdapterCommand", "CancellationToken", "SupervisionOutcome"} <= (
        _annotation_names(_class_node("ProcessSupervisor"))
    )
    assert {"InterruptOutcome", "TerminationReport", "CleanupReport"} <= (
        _annotation_names(_class_node("LaunchedProcess"))
    )
    assert {"LaunchSpecification", "LaunchFailure", "ProcessInspection"} <= (
        _annotation_names(_class_node("ProcessController"))
    )
    assert "SupervisionTraceEntry" in _annotation_names(
        _class_node("SupervisionObserver")
    )
    assert "RunReconciliationFacts" in _annotation_names(
        _class_node("ReconciliationSource")
    )


# --------------------------------------------------------------------------
# Purity: no implementation, no I/O, the reviewed import closure
# --------------------------------------------------------------------------


def test_the_module_defines_only_protocols_with_empty_bodies() -> None:
    tree = _module_tree()
    classes = [item for item in tree.body if isinstance(item, ast.ClassDef)]
    assert [item.name for item in classes] == [port.__name__ for port in _PORTS]
    assert not any(
        isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef) for item in tree.body
    )
    for class_node in classes:
        assert any(
            isinstance(base, ast.Name) and base.id == "Protocol"
            for base in class_node.bases
        ), class_node.name
        assert any(
            isinstance(decorator, ast.Name) and decorator.id == "runtime_checkable"
            for decorator in class_node.decorator_list
        ), class_node.name
        for item in class_node.body:
            if isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef):
                body = item.body
                assert len(body) == 1, (class_node.name, item.name)
                (statement,) = body
                assert isinstance(statement, ast.Expr), (class_node.name, item.name)
                assert isinstance(statement.value, ast.Constant), item.name


def test_the_module_imports_only_typing_the_sentinel_and_the_project() -> None:
    roots: set[str] = set()
    project: set[str] = set()
    for node in ast.walk(_module_tree()):
        modules: list[str] = []
        if isinstance(node, ast.Import):
            modules.extend(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            modules.append(node.module)
        for module in modules:
            roots.add(module.partition(".")[0])
            if module.startswith("crypto_lab"):
                project.add(module)
    assert roots <= _PURE_ROOTS, roots - _PURE_ROOTS
    for module in project:
        assert (
            module.startswith(("crypto_lab.domain.", "crypto_lab.adapters."))
            or module == "crypto_lab.process_supervision.models"
        ), module
    assert "crypto_lab.process_supervision.models" in project
    source = ports_module.__file__
    assert source is not None
    text = Path(source).read_text(encoding="utf-8")
    for forbidden in (
        "import subprocess",
        "import threading",
        "import asyncio",
        "import ctypes",
        "import os",
        "import time",
        "datetime.now",
        "time.time",
        "now_utc(",
        "os.environ",
        "import doubles",
        "from doubles",
    ):
        assert forbidden not in text, forbidden
