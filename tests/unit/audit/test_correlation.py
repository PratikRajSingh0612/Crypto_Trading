"""Stage 9 Task 2: the correlation context (specification 30.2; plan Task 2
"Interfaces produced").

One context follows a local command; ``derive`` only adds identifiers that were
absent and refuses to replace one that is present with a different value, and
``event`` stamps the context's identifiers onto a new ``AuditEvent`` through the
injected clock and identity source. The module names its type
``CorrelationContext`` and its instances ``correlation_scope`` because the
Stage 4 bare-name scan forbids ``context``, ``buffer``, ``note`` and ``problem``
as identifiers (plan 2.6 "Bare-name and text scans").
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

import crypto_lab.audit.correlation as correlation_module
import crypto_lab.audit.jsonl as jsonl_module
import crypto_lab.audit.models as models_module
import crypto_lab.audit.redaction as redaction_module
import crypto_lab.audit.sink as sink_module
import crypto_lab.domain.metrics as metrics_module
from crypto_lab.audit.correlation import CorrelationContext
from crypto_lab.audit.models import (
    CORE_ACTOR,
    AuditAction,
    AuditEvent,
    AuditOutcome,
    audit_details_hash,
)
from doubles.artifacts import ADAPTER_ACTOR, CORRELATION_ID, SequentialAuditIds
from doubles.experiments import (
    ARTIFACT_ID,
    EXPERIMENT_ID,
    INSTANT,
    INVOCATION_ID,
    OTHER_EXPERIMENT_ID,
    OTHER_INVOCATION_ID,
    OTHER_RUN_ID,
    RUN_ID,
    FixedClock,
)

_FORBIDDEN_IDENTIFIERS = frozenset({"context", "buffer", "note", "problem"})
_NEW_MODULES = (
    correlation_module,
    jsonl_module,
    models_module,
    redaction_module,
    sink_module,
    metrics_module,
)


def _scope(**identifiers: str) -> CorrelationContext:
    return CorrelationContext(correlation_id=CORRELATION_ID, **identifiers)


def test_derive_narrows_never_widens() -> None:
    bare = _scope()
    assert not isinstance(bare.experiment_id, str)
    assert not isinstance(bare.run_id, str)
    assert not isinstance(bare.invocation_id, str)
    with_experiment = bare.derive(experiment_id=EXPERIMENT_ID)
    assert with_experiment.experiment_id == EXPERIMENT_ID
    assert with_experiment.correlation_id == CORRELATION_ID
    assert not isinstance(bare.experiment_id, str)  # the source is untouched
    with_run = with_experiment.derive(run_id=RUN_ID, invocation_id=INVOCATION_ID)
    assert (with_run.experiment_id, with_run.run_id, with_run.invocation_id) == (
        EXPERIMENT_ID,
        RUN_ID,
        INVOCATION_ID,
    )
    # Restating a present identifier with the same value is a no-op...
    assert with_run.derive(experiment_id=EXPERIMENT_ID, run_id=RUN_ID) == with_run
    assert with_run.derive() == with_run
    # ...and replacing one is refused, for every identifier.
    for replacement in (
        {"experiment_id": OTHER_EXPERIMENT_ID},
        {"run_id": OTHER_RUN_ID},
        {"invocation_id": OTHER_INVOCATION_ID},
    ):
        with pytest.raises(ValueError, match="conflicting"):
            with_run.derive(**replacement)
    # Nothing can be removed, renamed or widened.
    with pytest.raises(ValueError, match="only adds"):
        with_run.derive(experiment_id=MISSING)
    with pytest.raises(ValueError, match="not a narrowing identifier"):
        with_run.derive(correlation_id="other")
    with pytest.raises(ValueError, match="not a narrowing identifier"):
        bare.derive(artifact_id=ARTIFACT_ID)
    with pytest.raises(ValidationError):
        bare.derive(run_id="run_not-a-uuid")
    with pytest.raises(ValidationError, match="frozen"):
        bare.run_id = RUN_ID
    with pytest.raises(ValidationError, match="Extra inputs are not permitted"):
        CorrelationContext.model_validate(
            {"correlation_id": CORRELATION_ID, "artifact_id": ARTIFACT_ID}
        )
    with pytest.raises(ValidationError):
        CorrelationContext.model_validate({"correlation_id": "has space"})


def test_event_carries_context_ids() -> None:
    ids = SequentialAuditIds("correlation")
    clock = FixedClock(INSTANT)
    correlation_scope = _scope(
        experiment_id=EXPERIMENT_ID, run_id=RUN_ID, invocation_id=INVOCATION_ID
    )
    event = correlation_scope.event(
        AuditAction.FINALIZATION_PREPARED,
        AuditOutcome.SUCCEEDED,
        {"stage": "PREPARED"},
        clock=clock,
        ids=ids,
    )
    assert isinstance(event, AuditEvent)
    assert event.audit_event_id == ids.issued[0]
    assert event.action is AuditAction.FINALIZATION_PREPARED
    assert event.outcome is AuditOutcome.SUCCEEDED
    assert event.actor == CORE_ACTOR
    assert event.correlation_id == CORRELATION_ID
    assert (event.experiment_id, event.run_id, event.invocation_id) == (
        EXPERIMENT_ID,
        RUN_ID,
        INVOCATION_ID,
    )
    assert not isinstance(event.artifact_id, str)
    assert event.timestamp_utc == INSTANT
    assert event.details == {"stage": "PREPARED"}
    assert event.details_hash == audit_details_hash({"stage": "PREPARED"})
    clock.advance(5)
    second = correlation_scope.event(
        AuditAction.FINALIZATION_MOVED,
        AuditOutcome.FAILED,
        {},
        clock=clock,
        ids=ids,
        actor=ADAPTER_ACTOR,
        artifact_id=ARTIFACT_ID,
    )
    assert second.audit_event_id == ids.issued[1] != event.audit_event_id
    assert second.timestamp_utc == clock.now_utc() != INSTANT
    assert second.actor == ADAPTER_ACTOR
    assert second.artifact_id == ARTIFACT_ID
    # Absent context identifiers stay absent on the event.
    bare_event = _scope().event(
        AuditAction.RETENTION_DELETED,
        AuditOutcome.SUCCEEDED,
        {},
        clock=clock,
        ids=ids,
    )
    assert not isinstance(bare_event.experiment_id, str)
    assert not isinstance(bare_event.run_id, str)
    assert not isinstance(bare_event.invocation_id, str)
    # The model's refusals propagate: a command action without an invocation
    # and token-shaped details are not constructible through the context.
    with pytest.raises(ValidationError, match="requires invocation_id"):
        _scope(experiment_id=EXPERIMENT_ID, run_id=RUN_ID).event(
            AuditAction.RUN_FAILED, AuditOutcome.SUCCEEDED, {}, clock=clock, ids=ids
        )
    with pytest.raises(ValidationError, match="redaction fixed point"):
        correlation_scope.event(
            AuditAction.ARTIFACT_VALIDATED,
            AuditOutcome.SUCCEEDED,
            {"leak": "A" * 40},
            clock=clock,
            ids=ids,
        )
    assert len(ids.issued) == 5


def test_sequential_audit_ids_are_deterministic_and_distinct() -> None:
    first = SequentialAuditIds("seed")
    second = SequentialAuditIds("seed")
    drawn = tuple(first.new_audit_event_id() for _ in range(4))
    assert drawn == tuple(second.new_audit_event_id() for _ in range(4))
    assert len(set(drawn)) == 4
    assert all(identifier.startswith("audit_") for identifier in drawn)
    assert SequentialAuditIds("other").new_audit_event_id() != drawn[0]


def _identifier_hits(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    hits: list[str] = []

    def found(line: int, *names: str) -> None:
        hits.extend(
            f"{path.name}:{line}: {name}"
            for name in names
            if name in _FORBIDDEN_IDENTIFIERS
        )

    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            found(node.lineno, node.id)
        elif isinstance(node, ast.Attribute):
            found(node.lineno, node.attr)
        elif isinstance(node, ast.arg):
            found(node.lineno, node.arg)
        elif isinstance(node, ast.keyword) and node.arg is not None:
            found(node.lineno, node.arg)
        elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            found(node.lineno, node.name)
        elif isinstance(node, ast.alias):
            found(node.lineno, node.asname or node.name)
    return hits


def test_no_forbidden_identifier_names() -> None:
    """Plan 2.6: no ``context``, ``buffer``, ``note`` or ``problem`` identifier
    in the correlation module -- or in any other module Task 2 adds."""
    for module in _NEW_MODULES:
        assert module.__file__ is not None
        assert _identifier_hits(Path(module.__file__)) == [], module.__name__
    assert correlation_module.CorrelationContext is CorrelationContext
    source = Path(str(correlation_module.__file__)).read_text(encoding="utf-8")
    assert "correlation_scope" in source


@pytest.mark.parametrize(
    "planted",
    [
        "context = 1\n",
        "def f(buffer: int) -> None:\n    pass\n",
        "x.note = 2\n",
        "def problem() -> None:\n    pass\n",
        "g(note=1)\n",
        "import os as context\n",
    ],
)
def test_the_identifier_scan_detects_each_planted_form(
    tmp_path: Path, planted: str
) -> None:
    path = tmp_path / "planted.py"
    path.write_text(planted, encoding="utf-8")
    assert len(_identifier_hits(path)) == 1
    clean = tmp_path / "clean.py"
    clean.write_text("correlation_scope = 1\n", encoding="utf-8")
    assert _identifier_hits(clean) == []
