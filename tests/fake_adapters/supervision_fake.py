"""The Stage 7 fake adapter executable (Stage 7 plan section 9.1): six supervision
scenarios over the merged Stage 6 fake's helpers, never a real engine adapter.

A second stdlib-only script beside ``fake_adapter.py``. Its first statements insert its
own directory into ``sys.path`` (the ``-I`` flag omits the script directory) and import
the merged helpers; its import roots are exactly ``argparse``, ``fake_adapter``,
``json``, ``os``, ``signal``, ``subprocess``, ``sys`` and ``time``. Before calling
``load_request`` it widens the merged identity check in this process only, by
rebinding ``fake_adapter.KNOWN_ADAPTER_NAMES[command]`` to the union with its own table
(the merged script, run as a program, still exits ``10`` for every Stage 7 name), then
dispatches through its own ``DESCRIBE``, ``VALIDATE`` and ``RUN`` tables and exits
``10`` for any other name. The merged ``fake_adapter.py`` is not edited.

The scenarios: ``fake.cancellation-graceful`` installs a ``SIGBREAK`` handler that exits
``50`` and heartbeats until interrupted; ``fake.cancellation-ignores-interrupt`` ignores
``SIGBREAK`` and heartbeats until killed; ``fake.grandchild`` ignores ``SIGBREAK``,
spawns an ignoring sleeper in its own process group, reports ``grandchild_pid=<n>`` on
stderr
and heartbeats until terminated (attempt two of the same slot succeeds without
candidates, the stale-writer row of plan 10); ``fake.grandchild-inherits-stdout`` spawns
the sleeper with the root's stdout inherited, reports its pid, writes a ``SUCCEEDED``
manifest with no candidates and exits ``0`` at once; ``fake.stdout-flood`` emits 5000
heartbeats back to back before a ``SUCCEEDED`` manifest; ``fake.argv-echo`` echoes its
argument array, isolation flags, working directory and environment key list as one
canonical JSON line on stderr before the kind's ordinary output. Every sleep is a slice
of at most 0.2 seconds so a Python ``SIGBREAK`` handler can run between bytecodes
(plan 2.5 reading 4). The one ``subprocess.Popen`` call is a list argv with
``shell=False`` and is never a string command. No environment value is read: the echo
scenario reports key names only.
"""

import argparse
import json
import os
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import fake_adapter
from fake_adapter import (
    REQUEST_INVALID_EXIT,
    Request,
    RequestRefused,
    Run,
    Wire,
    bootstrap_envelope,
    canonical,
    emit_stderr,
    load_request,
    validation_result,
    write_bytes,
)

#: Plan 2.5 reading 4: a SIGBREAK handler runs only between bytecodes, never inside a
#: long sleep, so every cooperating scenario sleeps in slices this long.
SLEEP_SLICE_SECONDS = 0.2
#: The exit value of the cooperating scenario's SIGBREAK handler.
GRACEFUL_EXIT = 50
#: The stdout-flood row: this many heartbeats before the manifest.
FLOOD_HEARTBEATS = 5000
#: The sleeper both grandchild scenarios spawn: it ignores SIGBREAK and outlives the
#: root, so only tree termination can end it.
SLEEPER_PROGRAM = (
    "import signal, time; "
    "signal.signal(signal.SIGBREAK, signal.SIG_IGN); time.sleep(60)"
)


# --- Shared behaviour -----------------------------------------------------------------


def _heartbeat_until_ended(run: Run) -> int:
    """Heartbeat every slice until the process is interrupted or terminated."""
    while True:
        run.wire.heartbeat()
        time.sleep(SLEEP_SLICE_SECONDS)


def _exit_gracefully(signum: int, frame: object) -> None:
    del signum, frame
    os._exit(GRACEFUL_EXIT)


def spawn_sleeper(*, inherit_stdout: bool) -> int:
    """The script's one child launch: a list argv, no shell; the sleeper either inherits
    this process's stdout pipe (and joins its process group) or receives null handles in
    a new process group. Returns the sleeper's pid."""
    stdout = sys.stdout.fileno() if inherit_stdout else subprocess.DEVNULL
    creationflags = 0 if inherit_stdout else subprocess.CREATE_NEW_PROCESS_GROUP
    child = subprocess.Popen(  # noqa: S603 - reviewed fixed interpreter boundary
        [sys.executable, "-I", "-B", "-c", SLEEPER_PROGRAM],
        stdin=subprocess.DEVNULL,
        stdout=stdout,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        shell=False,
        creationflags=creationflags,
    )
    return child.pid


def _report_grandchild(pid: int) -> None:
    emit_stderr(f"grandchild_pid={pid}\n".encode())


def _succeed_without_candidates(run: Run) -> int:
    """One heartbeat, a ``SUCCEEDED`` manifest with no candidates, ``FINAL_RESULT``."""
    wire = run.wire
    wire.heartbeat()
    document = run.manifest("SUCCEEDED", [])
    wire.final(run.write_manifest(document), "SUCCEEDED")
    return 0


def _echo_arguments() -> None:
    """Plan 9.1: the argument array as received (``sys.orig_argv`` keeps the interpreter
    options and the script that ``sys.argv`` strips), the isolation flags, the working
    directory and the environment's key names — never a value."""
    document = {
        "argv": sys.orig_argv[1:],
        "arguments": sys.argv[1:],
        "isolated": sys.flags.isolated,
        "dont_write_bytecode": sys.flags.dont_write_bytecode,
        "cwd": os.getcwd(),
        "environment_keys": sorted(os.environ),
    }
    line = json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    emit_stderr(line + b"\n")


# --- The scenarios --------------------------------------------------------------------


def run_cancellation_graceful(run: Run) -> int:
    signal.signal(signal.SIGBREAK, _exit_gracefully)
    return _heartbeat_until_ended(run)


def run_cancellation_ignores_interrupt(run: Run) -> int:
    signal.signal(signal.SIGBREAK, signal.SIG_IGN)
    return _heartbeat_until_ended(run)


def run_grandchild(run: Run) -> int:
    if run.request.attempt_number >= 2:
        # The stale-writer row of plan 10: attempt two of the same slot succeeds.
        return _succeed_without_candidates(run)
    signal.signal(signal.SIGBREAK, signal.SIG_IGN)
    _report_grandchild(spawn_sleeper(inherit_stdout=False))
    return _heartbeat_until_ended(run)


def run_grandchild_inherits_stdout(run: Run) -> int:
    _report_grandchild(spawn_sleeper(inherit_stdout=True))
    return _succeed_without_candidates(run)


def run_stdout_flood(run: Run) -> int:
    wire = run.wire
    for _ in range(FLOOD_HEARTBEATS):
        wire.heartbeat()
    document = run.manifest("SUCCEEDED", [])
    wire.final(run.write_manifest(document), "SUCCEEDED")
    return 0


def describe_argv_echo(request: Request, output_path: str) -> int:
    _echo_arguments()
    write_bytes(output_path, canonical(bootstrap_envelope(request)))
    return 0


def validate_argv_echo(request: Request, output_path: str) -> int:
    _echo_arguments()
    wire = Wire(request)
    wire.heartbeat()
    wire.progress()
    write_bytes(
        output_path,
        canonical(
            validation_result(request, "VALID", [], validated_at_utc=wire.timestamp())
        ),
    )
    return 0


def run_argv_echo(run: Run) -> int:
    _echo_arguments()
    return _succeed_without_candidates(run)


DESCRIBE_SCENARIOS = {"fake.argv-echo": describe_argv_echo}
VALIDATE_SCENARIOS = {"fake.argv-echo": validate_argv_echo}
RUN_SCENARIOS = {
    "fake.cancellation-graceful": run_cancellation_graceful,
    "fake.cancellation-ignores-interrupt": run_cancellation_ignores_interrupt,
    "fake.grandchild": run_grandchild,
    "fake.grandchild-inherits-stdout": run_grandchild_inherits_stdout,
    "fake.stdout-flood": run_stdout_flood,
    "fake.argv-echo": run_argv_echo,
}
#: Plan 9.1: the names this script serves, per command; the union with the merged
#: table is bound into ``fake_adapter.KNOWN_ADAPTER_NAMES`` in this process only.
SUPERVISION_TABLES = {
    "describe": frozenset(DESCRIBE_SCENARIOS),
    "validate": frozenset(VALIDATE_SCENARIOS),
    "run": frozenset(RUN_SCENARIOS),
}


# --- Entry point (the merged argument array of plan 3.7) ------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="supervision_fake", add_help=False)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("describe", "validate"):
        command = commands.add_parser(name, add_help=False)
        command.add_argument("--request", required=True)
        command.add_argument("--output", required=True)
    run = commands.add_parser("run", add_help=False)
    run.add_argument("--request", required=True)
    run.add_argument("--work-dir", required=True, dest="work_dir")
    run.add_argument("--result", required=True)
    return parser


def main(argv: list[str]) -> int:
    try:
        arguments = _parser().parse_args(argv)
    except SystemExit:
        return REQUEST_INVALID_EXIT
    command = str(arguments.command)
    work_dir = str(arguments.work_dir) if command == "run" else None
    # Plan 9.1: the single, process-local widening of the merged identity check.
    fake_adapter.KNOWN_ADAPTER_NAMES[command] = fake_adapter.KNOWN_ADAPTER_NAMES[
        command
    ] | frozenset(SUPERVISION_TABLES[command])
    try:
        request = load_request(str(arguments.request), command, work_dir)
    except RequestRefused:
        return REQUEST_INVALID_EXIT
    if request.adapter_name not in SUPERVISION_TABLES[command]:
        return REQUEST_INVALID_EXIT
    if command == "describe":
        return DESCRIBE_SCENARIOS[request.adapter_name](request, str(arguments.output))
    if command == "validate":
        return VALIDATE_SCENARIOS[request.adapter_name](request, str(arguments.output))
    return RUN_SCENARIOS[request.adapter_name](
        Run(request, str(arguments.work_dir), str(arguments.result))
    )


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
