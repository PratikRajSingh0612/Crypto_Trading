"""The thread-safe cancellation token the process supervisor takes (spec 8.2, 14.8).

``crypto_lab.domain.ports.CancellationToken`` is the structural port; this module
is its production implementation. ``request_cancellation`` may be called from any
thread -- a caller on the event loop, a timer, a test -- while the supervision loop
reads the token on its own decision thread, so the flag is a ``threading.Event``.
A request never clears and a second request is a no-op. No thread is started here
and nothing waits: the supervisor polls the token once per tick.
"""

from __future__ import annotations

import threading


class ThreadSafeCancellationToken:
    """Idempotent, thread-safe; ``request_cancellation`` is safe from any thread."""

    __slots__ = ("_event",)

    def __init__(self) -> None:
        self._event = threading.Event()

    def is_cancellation_requested(self) -> bool:
        return self._event.is_set()

    def request_cancellation(self) -> None:
        self._event.set()
