"""Stage 7 Task 1: the thread-safe cancellation token (plan sections 3.2 and 6.3).

``CancellationToken`` is a structural ``domain`` port; ``ThreadSafeCancellationToken``
is its production implementation and lives under ``process_supervision`` because it
is the one place that needs ``threading``. The token is set from any thread and read
by the supervision loop, so the cases below prove idempotency, structural conformance
to the port, cross-thread visibility without polling or sleeping, that a request
never clears, and that the module's only import root beyond the merged allowlist is
``threading``.
"""

from __future__ import annotations

import ast
import threading
from pathlib import Path

from crypto_lab.domain.ports import CancellationToken, Clock
from crypto_lab.process_supervision import cancellation as cancellation_module
from crypto_lab.process_supervision.cancellation import ThreadSafeCancellationToken

_JOIN_SECONDS = 5.0


def _public_methods(cls: type) -> set[str]:
    return {
        name
        for name, value in vars(cls).items()
        if not name.startswith("_") and callable(value)
    }


def test_the_token_is_idempotent_and_thread_safe() -> None:
    token = ThreadSafeCancellationToken()
    assert not token.is_cancellation_requested()
    token.request_cancellation()
    token.request_cancellation()
    assert token.is_cancellation_requested()
    assert isinstance(token, CancellationToken)


def test_the_token_exposes_exactly_the_two_port_members() -> None:
    assert _public_methods(ThreadSafeCancellationToken) == {
        "is_cancellation_requested",
        "request_cancellation",
    }
    assert _public_methods(CancellationToken) == _public_methods(
        ThreadSafeCancellationToken
    )
    token = ThreadSafeCancellationToken()
    assert not isinstance(token, Clock)
    assert not hasattr(token, "reset")
    assert not hasattr(token, "clear")


def test_a_request_from_another_thread_is_observed_without_polling() -> None:
    token = ThreadSafeCancellationToken()
    worker = threading.Thread(
        target=token.request_cancellation, name="stage7-task1-cancel"
    )
    worker.start()
    worker.join(timeout=_JOIN_SECONDS)
    assert not worker.is_alive()
    assert token.is_cancellation_requested()


def test_concurrent_requests_from_many_threads_leave_one_requested_token() -> None:
    token = ThreadSafeCancellationToken()
    release = threading.Event()

    def request_after_release() -> None:
        # A worker that never sees the release makes no request, so a scheduler
        # stall surfaces as the final assertion failing, never as a spurious
        # pre-release request.
        if release.wait(timeout=_JOIN_SECONDS):
            token.request_cancellation()

    workers = [
        threading.Thread(target=request_after_release, name=f"stage7-task1-{index}")
        for index in range(8)
    ]
    for worker in workers:
        worker.start()
    assert not token.is_cancellation_requested()
    release.set()
    for worker in workers:
        worker.join(timeout=_JOIN_SECONDS)
    assert all(not worker.is_alive() for worker in workers)
    assert token.is_cancellation_requested()


def test_tokens_are_independent_and_a_request_never_clears() -> None:
    first = ThreadSafeCancellationToken()
    second = ThreadSafeCancellationToken()
    first.request_cancellation()
    assert first.is_cancellation_requested()
    assert not second.is_cancellation_requested()
    for _ in range(3):
        assert first.is_cancellation_requested()
    assert not second.is_cancellation_requested()


def test_the_module_imports_only_threading_beyond_the_merged_roots() -> None:
    """Plan section 2.6: ``threading`` joins the Stage 3 root allowlist in Task 1
    and is confined to this module; the module defines no deferred name."""
    source = cancellation_module.__file__
    assert source is not None
    tree = ast.parse(Path(source).read_text(encoding="utf-8"))
    roots: set[str] = set()
    defined: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
        elif isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            defined.add(node.name)
    assert roots == {"__future__", "threading"}
    assert "CancellationToken" not in defined
    assert "ThreadSafeCancellationToken" in defined
