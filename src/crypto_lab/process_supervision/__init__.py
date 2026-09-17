"""Process supervision boundary for the research core.

Stage 7 (plan sections 2.3, 3.1 and 8), under specification sections 8, 8.1, 8.2, 14
and 15: the six structural ports of the boundary, the transient supervision and
reconciliation records, the Windows process controller with its Job Object cleanup, the
supervisor that drives one command from ``PENDING`` to its single enrichment, the
thread-safe cancellation token, the long-path probe and the restart reconciler over the
durable records. Every durable write leaves this package through the
``InvocationLifecycle`` port, which ``experiments`` implements without importing this
package, so the dependency direction of specification section 8 holds in both. The
Job Object the controller attaches is a cleanup mechanism and is not a security sandbox
(specification 15.4). Importing this package reads no clock, opens no file, binds no DLL
and launches no process.
"""

from crypto_lab.process_supervision.cancellation import ThreadSafeCancellationToken
from crypto_lab.process_supervision.models import (
    InvocationReconciliation,
    ReconciliationAction,
    ReconciliationReport,
    RunReconciliationFacts,
    SupervisionOutcome,
    SupervisionTraceEntry,
    SupervisionTraceKind,
)
from crypto_lab.process_supervision.ports import (
    InvocationLifecycle,
    LaunchedProcess,
    ProcessController,
    ProcessSupervisor,
    ReconciliationSource,
    SupervisionObserver,
)
from crypto_lab.process_supervision.reconciliation import reconcile_invocations
from crypto_lab.process_supervision.roots import PathPreflight, probe_long_path_support
from crypto_lab.process_supervision.supervisor import WindowsProcessSupervisor
from crypto_lab.process_supervision.windows_process import WindowsProcessController

__all__ = (
    "InvocationLifecycle",
    "InvocationReconciliation",
    "LaunchedProcess",
    "PathPreflight",
    "ProcessController",
    "ProcessSupervisor",
    "ReconciliationAction",
    "ReconciliationReport",
    "ReconciliationSource",
    "RunReconciliationFacts",
    "SupervisionObserver",
    "SupervisionOutcome",
    "SupervisionTraceEntry",
    "SupervisionTraceKind",
    "ThreadSafeCancellationToken",
    "WindowsProcessController",
    "WindowsProcessSupervisor",
    "probe_long_path_support",
    "reconcile_invocations",
)
