"""The command-invocation repository port, an ``adapters`` application port.

Specification section 8.1 assigns ``CommandInvocationRepository`` to the
"``adapters`` application port" owner, and section 27.1 permits
``experiments -> adapters``, so the protocol lives here (Stage 5 plan section
2.4). Its whole signature resolves inside ``domain``: ``CommandInvocationRecord``,
``InvocationId``, ``RunId``, ``CommandKind`` and ``Result``. It is a structural
contract only -- no session, connection, table, path or dictionary is exposed --
and the concrete implementation belongs to Stage 8's ``persistence`` package;
Stage 5 exercises it through the test-resident double of plan section 11.

``list_for_run`` is a declared extension beyond specification section 8.2's
operation list: plan section 6's ``create_invocation`` matrix reads the existing
invocations of a run to refuse a second open ``VALIDATE`` or ``RUN`` and to
recognise an identical-create replay. Its result is ordered deterministically by
``(created_at_utc, invocation_id)`` and covers every invocation of that run and
kind, terminal or not; the service applies the non-terminal filter.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from crypto_lab.domain.command_invocation import CommandInvocationRecord
from crypto_lab.domain.identifiers import InvocationId, RunId
from crypto_lab.domain.lifecycle import CommandKind
from crypto_lab.domain.results import Result


@runtime_checkable
class CommandInvocationRepository(Protocol):
    """Persist and compare-and-swap one command lifecycle (specification 8.1)."""

    def get(self, invocation_id: InvocationId) -> Result[CommandInvocationRecord]:
        """Return the stored record; a missing identity is a ``Failure``."""

    def add(self, record: CommandInvocationRecord) -> Result[None]:
        """Insert one new record; an existing identity or an open same-kind
        invocation for the same run is a ``PERSISTENCE.CONCURRENCY_CONFLICT``."""

    def compare_and_swap(
        self,
        expected_revision: int,
        replacement: CommandInvocationRecord,
    ) -> Result[CommandInvocationRecord]:
        """Replace the stored record when its revision equals ``expected_revision``.

        A mismatch or a missing row is ``PERSISTENCE.CONCURRENCY_CONFLICT``; the
        replacement must carry ``expected_revision + 1``.
        """

    def list_for_run(
        self,
        run_id: RunId,
        command_kind: CommandKind,
    ) -> Result[tuple[CommandInvocationRecord, ...]]:
        """Return every invocation of ``run_id`` and ``command_kind``, ordered by
        ``(created_at_utc, invocation_id)``."""
