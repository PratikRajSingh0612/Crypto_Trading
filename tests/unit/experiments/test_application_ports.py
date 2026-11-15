"""Stage 10 plan Task 1: the inward application ports and their detached values.

The initial RED is the missing ``crypto_lab.experiments.application_ports`` module.
The ports are structural: ``persistence``, the CLI execution bridge and the
transaction facade implement them later, and ``experiments`` consumes them. Their
values are immutable and detached, built from ``domain`` and ``adapters`` facts only
-- no concrete SQL, configuration, CLI, process-supervision, artifact or audit type
-- and the existing six-member ``UnitOfWork`` is preserved, not extended.
"""

from __future__ import annotations

import ast
import inspect
from pathlib import Path
from typing import Final, TypeAliasType, get_args, get_origin, get_type_hints

import pytest
from pydantic import BaseModel, ValidationError

from crypto_lab.adapters.commands import AdapterCommand
from crypto_lab.configuration.models import ApplicationConfig
from crypto_lab.domain.experiment import ExperimentRecord
from crypto_lab.domain.lifecycle import CommandKind, ExperimentState
from crypto_lab.domain.ports import CancellationToken
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.experiments import application_ports as ports_module
from crypto_lab.experiments.application_ports import (
    ApplicationQueryPort,
    ApplicationTransactionPort,
    CommandExecutionPort,
    DurableWorkInventory,
    ExecutedCommand,
    RequeueAssessment,
    RequeueAssessmentPort,
)
from crypto_lab.experiments.ports import UnitOfWork
from crypto_lab.persistence.database import SqliteDatabase
from crypto_lab.process_supervision.models import SupervisionOutcome
from doubles.experiments import (
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    SLOT_A,
    SLOT_B,
    InMemoryBackingStore,
    InMemoryUnitOfWork,
    sample_experiment,
    sample_invocation,
    sample_retry_decision,
    sample_run,
)

#: The only first-party packages the ports module and its values may reach.
_ALLOWED_FIRST_PARTY: Final = (
    "crypto_lab.domain.",
    "crypto_lab.adapters.",
    "crypto_lab.experiments.ports",
    "crypto_lab.experiments.application_ports",
)
#: Concrete infrastructure and the packages the inward ports never reach.
_DENIED_FIRST_PARTY: Final = (
    "crypto_lab.persistence",
    "crypto_lab.configuration",
    "crypto_lab.cli",
    "crypto_lab.process_supervision",
    "crypto_lab.artifacts",
    "crypto_lab.audit",
    "crypto_lab.strategy",
    "crypto_lab.datasets",
    "crypto_lab.schema_registry",
)
_DENIED_ROOTS: Final = frozenset(
    {
        "alembic",
        "asyncio",
        "ctypes",
        "io",
        "os",
        "pathlib",
        "queue",
        "secrets",
        "signal",
        "sqlalchemy",
        "sqlite3",
        "subprocess",
        "threading",
        "time",
    }
)
_PORT_MEMBERS: Final[dict[type, frozenset[str]]] = {
    ApplicationQueryPort: frozenset({"work_inventory"}),
    RequeueAssessmentPort: frozenset({"assess_requeue"}),
    CommandExecutionPort: frozenset({"execute"}),
    ApplicationTransactionPort: frozenset({"unit_of_work"}),
}
_VALUES: Final[tuple[type[BaseModel], ...]] = (
    DurableWorkInventory,
    RequeueAssessment,
    ExecutedCommand,
)
#: The six repository members and three transaction methods of Stage 5's port.
_UNIT_OF_WORK_MEMBERS: Final = frozenset(
    {
        "experiments",
        "engine_runs",
        "command_invocations",
        "retry_decisions",
        "availability_observations",
        "diagnostics",
        "begin",
        "commit",
        "rollback",
    }
)


def _named_types(annotation: object) -> set[type]:
    """Every class an annotation names, through aliases, unions and generics."""
    found: set[type] = set()
    pending: list[object] = [annotation]
    seen: set[int] = set()
    while pending:
        item = pending.pop()
        if id(item) in seen:
            continue
        seen.add(id(item))
        if isinstance(item, TypeAliasType):
            pending.append(item.__value__)
            continue
        origin = get_origin(item)
        if origin is not None:
            pending.append(origin)
            pending.extend(get_args(item))
        elif isinstance(item, type):
            found.add(item)
        else:
            found.add(type(item))
    return found


def _reach_violations(types: set[type], where: str) -> list[str]:
    violations: list[str] = []
    for named in sorted(types, key=lambda value: f"{value.__module__}.{value!r}"):
        module = named.__module__
        if module.startswith("crypto_lab."):
            if module.startswith(_DENIED_FIRST_PARTY) or not module.startswith(
                _ALLOWED_FIRST_PARTY
            ):
                violations.append(f"{where}: {module}.{named.__qualname__}")
        elif module.partition(".")[0] in _DENIED_ROOTS:
            violations.append(f"{where}: {module}.{named.__qualname__}")
    return violations


def _public_members(cls: type) -> frozenset[str]:
    return frozenset(name for name in vars(cls) if not name.startswith("_"))


class _Ports:
    """One structural implementation of every port, for the conformance check."""

    def work_inventory(self) -> Result[DurableWorkInventory]:
        return Success[DurableWorkInventory](
            outcome="SUCCESS",
            value=DurableWorkInventory(
                experiments=(),
                engine_runs=(),
                command_invocations=(),
                retry_decisions=(),
            ),
        )

    def assess_requeue(
        self, inventory: DurableWorkInventory
    ) -> Result[RequeueAssessment]:
        del inventory
        return Success[RequeueAssessment](
            outcome="SUCCESS",
            value=RequeueAssessment(eligible_slots=(), fenced_slots=()),
        )

    async def execute(
        self, command: AdapterCommand, cancellation: CancellationToken
    ) -> Result[ExecutedCommand]:
        raise NotImplementedError((command, cancellation))

    def unit_of_work(self) -> UnitOfWork:
        return InMemoryUnitOfWork(InMemoryBackingStore())


def test_application_ports_are_inward_only() -> None:
    # Imports: domain, adapters and the Stage 5 port module only, absolute and direct.
    source = inspect.getsource(ports_module)
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0
            assert node.module is not None
            imported.add(node.module)
    assert {name.partition(".")[0] for name in imported} == {
        "__future__",
        "crypto_lab",
        "pydantic",
        "typing",
    }
    for name in sorted(imported):
        if name.startswith("crypto_lab"):
            assert name.startswith(_ALLOWED_FIRST_PARTY), name
    # Values and port signatures name no concrete or out-of-reach type.
    violations: list[str] = []
    for value in _VALUES:
        for field_name, field in value.model_fields.items():
            where = f"{value.__name__}.{field_name}"
            violations.extend(_reach_violations(_named_types(field.annotation), where))
    for port, members in _PORT_MEMBERS.items():
        assert _public_members(port) == members, port
        for member in sorted(members):
            hints = get_type_hints(getattr(port, member))
            for hint_name, hint in hints.items():
                where = f"{port.__name__}.{member}:{hint_name}"
                violations.extend(_reach_violations(_named_types(hint), where))
    assert violations == []
    assert inspect.iscoroutinefunction(CommandExecutionPort.execute)
    # Planted controls: the same reach check names each concrete type it must refuse
    # and admits the domain record beside them.
    planted = _reach_violations(
        {SupervisionOutcome, SqliteDatabase, ApplicationConfig, Path, ExperimentRecord},
        "planted",
    )
    assert len(planted) == 4
    for refused in ("process_supervision", "persistence", "configuration", "pathlib"):
        assert any(refused in violation for violation in planted), refused
    # The walk sees through the generic ``Result`` alias to every type it names (a
    # parametrized ``Success`` is Pydantic's own subclass of ``Success``).
    named = _named_types(Result[ExecutedCommand])
    assert {ExecutedCommand, Failure} <= named
    assert any(issubclass(candidate, Success) for candidate in named)
    # The six-member application unit of work is preserved and not extended here.
    assert _public_members(UnitOfWork) == _UNIT_OF_WORK_MEMBERS
    for name in dir(ports_module):
        candidate = getattr(ports_module, name)
        if isinstance(candidate, type) and candidate is not UnitOfWork:
            assert UnitOfWork not in candidate.__mro__, name
    # Structural conformance: one implementation satisfies every port.
    ports = _Ports()
    for port in _PORT_MEMBERS:
        assert isinstance(ports, port), port
    assert isinstance(ports.unit_of_work(), UnitOfWork)
    assert not isinstance(object(), ApplicationQueryPort)


def test_inventory_values_are_detached_complete_and_canonical() -> None:
    experiment = sample_experiment(ExperimentState.QUEUED)
    run = sample_run()
    run_invocation = sample_invocation()
    describe = sample_invocation(
        kind=CommandKind.DESCRIBE, invocation_id=OTHER_INVOCATION_ID
    )
    decision = sample_retry_decision()
    inventory = DurableWorkInventory(
        experiments=(experiment,),
        engine_runs=(run,),
        command_invocations=(run_invocation, describe),
        retry_decisions=(decision,),
    )
    assert inventory.experiments == (experiment,)
    assert inventory.command_invocations == (run_invocation, describe)
    with pytest.raises(ValidationError, match="frozen"):
        inventory.experiments = ()
    # A mutable caller list is refused rather than retained.
    with pytest.raises(ValidationError):
        DurableWorkInventory.model_validate(
            {
                "experiments": [experiment],
                "engine_runs": (),
                "command_invocations": (),
                "retry_decisions": (),
            }
        )
    with pytest.raises(ValidationError, match="extra"):
        DurableWorkInventory.model_validate(
            {
                "experiments": (),
                "engine_runs": (),
                "command_invocations": (),
                "retry_decisions": (),
                "journals": (),
            }
        )
    # Incomplete populations: a dangling reference is refused, never dropped.
    incomplete = (
        {"experiments": (), "engine_runs": (run,)},
        {"engine_runs": (), "command_invocations": (run_invocation,)},
        {"retry_decisions": (sample_retry_decision(predecessor_run_id=OTHER_RUN_ID),)},
    )
    for override in incomplete:
        fields = {
            "experiments": (experiment,),
            "engine_runs": (run,),
            "command_invocations": (),
            "retry_decisions": (),
            **override,
        }
        with pytest.raises(ValidationError, match="unknown"):
            DurableWorkInventory.model_validate(fields)
    # Canonical order: strictly ascending identities, so no duplicate either.
    later_run = sample_run(run_id=OTHER_RUN_ID, logical_slot_id=SLOT_B)
    for runs in ((later_run, run), (run, run)):
        with pytest.raises(ValidationError, match="ascending"):
            DurableWorkInventory(
                experiments=(experiment,),
                engine_runs=runs,
                command_invocations=(),
                retry_decisions=(),
            )
    assert DurableWorkInventory(
        experiments=(experiment,),
        engine_runs=(run, later_run),
        command_invocations=(),
        retry_decisions=(),
    ).engine_runs == (run, later_run)


def test_requeue_assessment_partitions_slots() -> None:
    assessment = RequeueAssessment(eligible_slots=(SLOT_A,), fenced_slots=(SLOT_B,))
    assert assessment.eligible_slots == (SLOT_A,)
    with pytest.raises(ValidationError, match="frozen"):
        assessment.fenced_slots = ()
    for eligible, fenced in (
        ((SLOT_A,), (SLOT_A,)),
        ((SLOT_B, SLOT_A), ()),
        ((), (SLOT_A, SLOT_A)),
    ):
        with pytest.raises(ValidationError, match=r"ascending|both"):
            RequeueAssessment(eligible_slots=eligible, fenced_slots=fenced)
    with pytest.raises(ValidationError):
        RequeueAssessment(eligible_slots=("slot_not-a-uuid",), fenced_slots=())
