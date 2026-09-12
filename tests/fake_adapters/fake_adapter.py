"""The Stage 6 fake adapter executable (Stage 6 plan section 11.1): a deterministic
test fixture, never a real engine adapter.

One stdlib-only script (``argparse``, ``json``, ``hashlib``, ``sys``, ``os``,
``time``, ``datetime``; it imports neither ``crypto_lab`` nor ``pydantic``) that
implements specification 14.1's three sub-commands over the exact argument array of
plan 3.7, performs the adapter-side verification of plan 3.6 (exit ``10`` on any
failure, with no output file and no stdout byte), computes ``payload_hash``,
``result_hash``, ``descriptor_payload_hash``, ``attempt_token_hash`` and the manifest
file hash with ``hashlib`` over ``json.dumps(obj, sort_keys=True,
separators=(",", ":"), ensure_ascii=False).encode()``, writes stdout lines with
``sys.stdout.buffer.write(line + b"\\n")`` and never with text-mode ``print``, and
derives every ``event_id``, ``adapter_manifest_id`` and ``timestamp_utc`` from the
request, so a scenario's output is a pure function of its request.

The scenario is selected by the adapter identity carried in the request payload
(``DescribeRequestPayload.adapter_name`` for describe,
``EngineRunRequest.adapter.adapter_name`` otherwise), and may additionally dispatch
on the command and on ``attempt_number`` (row 47). Every behaviour is one row of
plan 11.2; the describe and validate scenarios reuse ``fake.conformant`` behaviour
unless their row says otherwise. It emulates no engine: candidate files are small
deterministic byte strings, metrics are literal decimal strings, and no market
data, order or portfolio concept appears. It reads no environment variable and no
clock other than ``time`` for the four timing rows (24-27), where the harness
provokes the missing-heartbeat, deadline and cancellation codes.
"""

import argparse
import hashlib
import json
import os
import sys
import time
from datetime import datetime, timedelta

FAKE_ADAPTER_VERSION = "1.0.0"
PROTOCOL_VERSION = "1.0.0"
SCHEMA_VERSION = "1.0.0"
BOOTSTRAP_SCHEMA_VERSION = "1.0.0"
CAPABILITY_VOCABULARY_VERSION = "capabilities/v1"
TOKEN_DOMAIN = b"crypto_lab:attempt-token:v1"
REQUEST_INVALID_EXIT = 10
CRASH_EXIT = 40
UNRECOGNIZED_EXIT = 3
HEADER_KEYS = frozenset(
    {
        "schema_version",
        "protocol_version",
        "request_id",
        "invocation_id",
        "command",
        "created_at_utc",
        "timeout_seconds",
        "deadline_utc",
        "payload_hash",
        "payload",
    }
)
NEGOTIABLE_SCHEMA_NAMES = (
    "protocol.adapter-command-request-envelope",
    "protocol.adapter-descriptor",
    "protocol.adapter-result-manifest",
    "protocol.adapter-validation-result",
    "protocol.protocol-event-envelope",
)
ENGINE_NAME = "fake.engine"
ENGINE_VERSION = "1.0.0"
MANIFEST_FILE_NAME = "adapter-result-manifest.json"
STALE_OUTPUT_FILE_NAME = "stale-output.json"
NATIVE_PATH = "results/native.bin"
NATIVE_KIND = "engine.native"
NATIVE_MEDIA = "application/octet-stream"
NATIVE_BYTES = b"fake native result\n"
NORMALIZED_PATH = "results/normalized.json"
NORMALIZED_KIND = "engine.normalized"
NORMALIZED_MEDIA = "application/json"
NORMALIZED_BYTES = b'{"equity":["10000","10012.5"]}\n'
OTHER_BYTES = b"other bytes the adapter never wrote\n"
WARNING_CODE = "ADAPTER.APPROXIMATED_FILLS"
WARNING_MESSAGE = "fills approximated at bar close"
WARNING_IMPACT = "Level 3 comparison prevented."
PHASE = "engine"
HEARTBEAT_PERIOD_SECONDS = 0.2
HEARTBEAT_SUCCESS_SECONDS = 1.5
LONG_SLEEP_SECONDS = 30.0
PROCESS_TIMEOUT_SLEEP_SECONDS = 3.0
PAD_WARNING_COUNT = 64
PAD_TEXT_CHARACTERS = 1024

Document = dict[str, object]


class RequestRefused(Exception):
    """The adapter-side verification of plan 3.6 failed: exit 10, write nothing."""


# --- Stdlib-reproducible hashes and identities (plan 4, 11.1) ----------------------


def canonical(document: object) -> bytes:
    return json.dumps(
        document, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def uuid4_shaped(digest: str) -> str:
    """The core's ``_uuid4_shaped`` reproduced: version nibble 4, variant in 89ab."""
    digits = list(digest[:32])
    digits[12] = "4"
    digits[16] = "89ab"[int(digits[16], 16) % 4]
    grouped = "".join(digits)
    return (
        f"{grouped[:8]}-{grouped[8:12]}-{grouped[12:16]}-"
        f"{grouped[16:20]}-{grouped[20:]}"
    )


def attempt_token_hash(token: str) -> str:
    return sha256_hex(TOKEN_DOMAIN + b"\x00" + token.encode("utf-8"))


def event_id(invocation_id: str, sequence: int) -> str:
    return f"evt_{uuid4_shaped(sha256_hex(f'{invocation_id}:{sequence}'.encode()))}"


def manifest_id(invocation_id: str) -> str:
    return f"amf_{uuid4_shaped(sha256_hex(f'{invocation_id}:manifest'.encode()))}"


def instant(created_at_utc: str, seconds: int) -> str:
    parsed = datetime.fromisoformat(created_at_utc.replace("Z", "+00:00"))
    return (parsed + timedelta(seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_bytes(path: str, data: bytes) -> None:
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(data)


def emit(line: bytes) -> None:
    """Plan 7.1 rule 2: byte-exact stdout lines, never text-mode ``print``."""
    sys.stdout.buffer.write(line + b"\n")
    sys.stdout.buffer.flush()


def emit_stderr(data: bytes) -> None:
    sys.stderr.buffer.write(data)
    sys.stderr.buffer.flush()


# --- The request (plan 3.6 adapter-side verification) ------------------------------


class Request:
    """The verified request envelope of one command."""

    def __init__(self, envelope: Document, payload: Document) -> None:
        self.envelope = envelope
        self.payload = payload
        self.invocation_id = str(envelope["invocation_id"])
        self.request_id = str(envelope["request_id"])
        self.created_at_utc = str(envelope["created_at_utc"])

    @property
    def adapter_name(self) -> str:
        if "adapter_name" in self.payload:
            return str(self.payload["adapter_name"])
        adapter = self.payload["adapter"]
        assert isinstance(adapter, dict)
        return str(adapter["adapter_name"])

    @property
    def adapter_version(self) -> str:
        if "adapter_version" in self.payload:
            return str(self.payload["adapter_version"])
        adapter = self.payload["adapter"]
        assert isinstance(adapter, dict)
        return str(adapter["adapter_version"])

    @property
    def run_id(self) -> str:
        return str(self.payload["run_id"])

    @property
    def token(self) -> str:
        return str(self.payload["attempt_token"])

    @property
    def attempt_number(self) -> int:
        value = self.payload["attempt_number"]
        assert isinstance(value, int)
        return value

    def limit(self, name: str) -> int:
        snapshot = self.payload["configuration_snapshot"]
        assert isinstance(snapshot, dict)
        limits = snapshot["limits"]
        assert isinstance(limits, dict)
        value = limits[name]
        assert isinstance(value, int)
        return value

    def snapshot(self, name: str) -> object:
        snapshot = self.payload["configuration_snapshot"]
        assert isinstance(snapshot, dict)
        return snapshot[name]


def _reject_repeated_keys(pairs: list[tuple[str, object]]) -> Document:
    document: Document = {}
    for key, value in pairs:
        if key in document:
            raise RequestRefused("repeated key")
        document[key] = value
    return document


def load_request(path: str, command: str, work_dir: str | None) -> Request:
    """Plan 3.6 (a)-(f); any failure is ``RequestRefused`` and exit 10."""
    try:
        with open(path, "rb") as handle:
            decoded = json.loads(
                handle.read().decode("utf-8"), object_pairs_hook=_reject_repeated_keys
            )
    except (OSError, ValueError) as error:
        raise RequestRefused(str(error)) from error
    if not isinstance(decoded, dict) or set(decoded) != HEADER_KEYS:
        raise RequestRefused("envelope keys")
    envelope: Document = decoded
    if (
        envelope["protocol_version"] != PROTOCOL_VERSION
        or envelope["schema_version"] != SCHEMA_VERSION
    ):
        raise RequestRefused("versions")
    payload = envelope["payload"]
    if not isinstance(payload, dict):
        raise RequestRefused("payload")
    if envelope["payload_hash"] != sha256_hex(canonical(payload)):
        raise RequestRefused("payload hash")
    if envelope["command"] != command.upper():
        raise RequestRefused("command")
    request = Request(envelope, payload)
    # The adapter identity the request names must be one this fake serves for this
    # command; an unknown name is refused (exit 10) for describe, validate and run
    # alike -- no command falls back to the conformant behaviour.
    try:
        name, version = request.adapter_name, request.adapter_version
    except (KeyError, AssertionError):
        raise RequestRefused("identity") from None
    if name not in KNOWN_ADAPTER_NAMES[command] or version != FAKE_ADAPTER_VERSION:
        raise RequestRefused("identity")
    if command == "describe":
        return request
    for key in ("run_id", "attempt_number", "attempt_token"):
        if key not in payload or not payload[key]:
            raise RequestRefused(key)
    if request.adapter_version != FAKE_ADAPTER_VERSION:
        raise RequestRefused("identity")
    if command == "run":
        assigned = payload["assigned_work_dir"]
        if not isinstance(assigned, dict) or work_dir is None:
            raise RequestRefused("work dir")
        relative = str(assigned["relative_path"])
        normalized = work_dir.replace("\\", "/").rstrip("/")
        if not normalized.endswith("/" + relative):
            raise RequestRefused("work dir tail")
    return request


# --- Describe (plan 3.8, rows 1, 21, 26, 43, 44) -----------------------------------


def descriptor(
    request: Request, *, protocol_versions: tuple[str, ...] = (PROTOCOL_VERSION,)
) -> Document:
    return {
        "schema_version": SCHEMA_VERSION,
        "adapter_name": request.adapter_name,
        "adapter_version": request.adapter_version,
        "engine": {
            "schema_version": SCHEMA_VERSION,
            "engine_name": ENGINE_NAME,
            "engine_version": ENGINE_VERSION,
            "engine_family": "fake.family",
            "planned_role": "Offline fake adapter.",
            "known_limitations": [],
        },
        "supported_protocol_versions": list(protocol_versions),
        "supported_schema_versions": [
            {"schema_name": name, "schema_version": SCHEMA_VERSION}
            for name in NEGOTIABLE_SCHEMA_NAMES
        ],
        "capability_vocabulary_version": CAPABILITY_VOCABULARY_VERSION,
        "native_capabilities": ["data.ohlcv", "market.spot"],
        "approximated_capabilities": [],
        "unsupported_capabilities": [],
        "supported_operating_systems": ["WINDOWS"],
        "runtime_requirements": ["CPython 3.12"],
        "network_required": False,
        "credentials_required": False,
        "known_modeling_limitations": [],
        "executable_hash": str(request.payload["executable_hash"]),
    }


def bootstrap_envelope(
    request: Request,
    *,
    bootstrap_version: str = BOOTSTRAP_SCHEMA_VERSION,
    protocol_versions: tuple[str, ...] = (PROTOCOL_VERSION,),
) -> Document:
    described = descriptor(request, protocol_versions=protocol_versions)
    engine = described["engine"]
    assert isinstance(engine, dict)
    return {
        "bootstrap_schema_version": bootstrap_version,
        "adapter_name": described["adapter_name"],
        "adapter_version": described["adapter_version"],
        "engine_name": engine["engine_name"],
        "engine_version": engine["engine_version"],
        "executable_hash": described["executable_hash"],
        "supported_protocol_versions": described["supported_protocol_versions"],
        "supported_schema_versions": described["supported_schema_versions"],
        "capability_vocabulary_versions": [CAPABILITY_VOCABULARY_VERSION],
        "descriptor_payload_hash": sha256_hex(canonical(described)),
        "descriptor": described,
    }


def describe_conformant(request: Request, output_path: str) -> int:
    write_bytes(output_path, canonical(bootstrap_envelope(request)))
    return 0


def describe_noise(request: Request, output_path: str) -> int:
    write_bytes(output_path, canonical(bootstrap_envelope(request)))
    sys.stdout.buffer.write(b"x")
    sys.stdout.buffer.flush()
    return 0


def describe_bad_version(request: Request, output_path: str) -> int:
    write_bytes(
        output_path, canonical(bootstrap_envelope(request, bootstrap_version="2.0.0"))
    )
    return 0


def describe_no_common_version(request: Request, output_path: str) -> int:
    write_bytes(
        output_path,
        canonical(bootstrap_envelope(request, protocol_versions=("2.0.0",))),
    )
    return 0


def describe_process_timeout(request: Request, output_path: str) -> int:
    time.sleep(PROCESS_TIMEOUT_SLEEP_SECONDS)
    return describe_conformant(request, output_path)


DESCRIBE_SCENARIOS = {
    "fake.conformant": describe_conformant,
    "fake.warnings": describe_conformant,
    "fake.unsupported-capability": describe_conformant,
    "fake.late-not-applicable": describe_conformant,
    "fake.temporarily-unavailable": describe_conformant,
    "fake.late-unavailable": describe_conformant,
    "fake.validation-failure": describe_conformant,
    "fake.malformed-json": describe_conformant,
    "fake.unknown-event": describe_conformant,
    "fake.duplicate-sequence": describe_conformant,
    "fake.replayed-sequence": describe_conformant,
    "fake.skipped-sequence": describe_conformant,
    "fake.wrong-invocation": describe_conformant,
    "fake.wrong-request-hash": describe_conformant,
    "fake.wrong-token": describe_conformant,
    "fake.wrong-token-proof": describe_conformant,
    "fake.oversized-line": describe_conformant,
    "fake.stdout-noise": describe_conformant,
    "fake.describe-noise": describe_noise,
    "fake.stderr-output": describe_conformant,
    "fake.stderr-flood": describe_conformant,
    "fake.heartbeat-success": describe_conformant,
    "fake.heartbeat-timeout": describe_conformant,
    "fake.process-timeout": describe_process_timeout,
    "fake.cancellation": describe_conformant,
    "fake.exit-10-run": describe_conformant,
    "fake.exit-40": describe_conformant,
    "fake.exit-50": describe_conformant,
    "fake.exit-60": describe_conformant,
    "fake.exit-70": describe_conformant,
    "fake.exit-unrecognized": describe_conformant,
    "fake.missing-manifest": describe_conformant,
    "fake.malformed-manifest": describe_conformant,
    "fake.disagreeing-manifest": describe_conformant,
    "fake.exit-0-not-applicable": describe_conformant,
    "fake.path-escape": describe_conformant,
    "fake.manifest-path-escape": describe_conformant,
    "fake.checksum-mismatch": describe_conformant,
    "fake.event-manifest-mismatch": describe_conformant,
    "fake.crash-before-first-event": describe_conformant,
    "fake.crash-after-partial-events": describe_conformant,
    "fake.token-in-warning": describe_conformant,
    "fake.token-in-candidate": describe_conformant,
    "fake.core-namespace-code": describe_conformant,
    "fake.describe-bad-version": describe_bad_version,
    "fake.describe-no-common-version": describe_no_common_version,
    "fake.second-final-result": describe_conformant,
    "fake.validate-emits-artifact": describe_conformant,
    "fake.stale-attempt-result": describe_conformant,
    "fake.partial-then-failed-manifest": describe_conformant,
    "fake.token-as-path": describe_conformant,
    "fake.token-as-phase": describe_conformant,
    "fake.oversized-manifest": describe_conformant,
    "fake.invalid-utf8-stdout": describe_conformant,
}


# --- The wire: events, diagnostics, warnings (plan 3.9, 7) -------------------------


def adapter_diagnostic(
    code: str, category: str, message: str, *, retriable: bool = True
) -> Document:
    return {
        "error_code": code,
        "category": category,
        "severity": "ERROR",
        "message": message,
        "retriable": retriable,
        "details": {},
        "causal_event_ids": [],
    }


def warning(message: str = WARNING_MESSAGE, code: str = WARNING_CODE) -> Document:
    return {
        "warning_code": code,
        "message": message,
        "impact": WARNING_IMPACT,
        "prevented_comparison_levels": ["LEVEL_3"],
    }


def declaration(path: str, kind: str, media: str, size: int, digest: str) -> Document:
    return {
        "relative_path": path,
        "artifact_kind": kind,
        "media_type": media,
        "declared_size_bytes": size,
        "declared_sha256": digest,
    }


class Wire:
    """The stdout protocol of one validate or run: sequence, identity, timestamps."""

    def __init__(
        self,
        request: Request,
        *,
        invocation_id: str | None = None,
        token: str | None = None,
    ) -> None:
        self.request = request
        self.invocation_id = (
            request.invocation_id if invocation_id is None else (invocation_id)
        )
        self.token = request.token if token is None else token
        self.sequence = 0
        self.counter = 0

    def line(self, sequence: int, event_type: str, payload: Document) -> bytes:
        return canonical(
            {
                "schema_version": SCHEMA_VERSION,
                "protocol_version": PROTOCOL_VERSION,
                "event_id": event_id(self.request.invocation_id, sequence),
                "invocation_id": self.invocation_id,
                "run_id": self.request.run_id,
                "attempt_token": self.token,
                "sequence": sequence,
                "event_type": event_type,
                "timestamp_utc": instant(self.request.created_at_utc, sequence),
                "payload": payload,
            }
        )

    def next(self, event_type: str, payload: Document) -> bytes:
        self.sequence += 1
        line = self.line(self.sequence, event_type, payload)
        emit(line)
        return line

    def heartbeat(self, *, phase: str = PHASE, counter: int | None = None) -> bytes:
        self.counter = self.counter + 1 if counter is None else counter
        return self.next(
            "HEARTBEAT", {"activity_counter": self.counter, "phase": phase}
        )

    def progress(self) -> bytes:
        return self.next(
            "PROGRESS", {"phase": PHASE, "completed_units": 1, "total_units": 2}
        )

    def warning(self, document: Document) -> bytes:
        return self.next("WARNING", {"warning": document})

    def diagnostic(self, document: Document) -> bytes:
        return self.next("DIAGNOSTIC", {"diagnostic": document})

    def artifact(self, declared: Document) -> bytes:
        return self.next("ARTIFACT_PRODUCED", declared)

    def final(self, digest: str, status: str) -> bytes:
        return self.next(
            "FINAL_RESULT",
            {
                "manifest_relative_path": MANIFEST_FILE_NAME,
                "source_adapter_result_manifest_hash": digest,
                "semantic_status": status,
            },
        )

    def timestamp(self) -> str:
        return instant(self.request.created_at_utc, self.sequence)


# --- Validate (plan 3.10, rows 2, 5, 7, 9, 18, 26, 46, 47) -------------------------


def validation_result(
    request: Request,
    outcome: str,
    diagnostics: list[Document],
    *,
    token_hash: str | None = None,
    validated_at_utc: str,
) -> Document:
    document: Document = {
        "schema_version": SCHEMA_VERSION,
        "protocol_version": PROTOCOL_VERSION,
        "request_id": request.request_id,
        "invocation_id": request.invocation_id,
        "run_id": request.run_id,
        "attempt_token_hash": (
            attempt_token_hash(request.token) if token_hash is None else token_hash
        ),
        "outcome": outcome,
        "diagnostics": diagnostics,
        "validated_at_utc": validated_at_utc,
    }
    document["result_hash"] = sha256_hex(canonical(document))
    return document


def validate_conformant(request: Request, output_path: str) -> int:
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


def _validate_with(
    request: Request,
    output_path: str,
    outcome: str,
    diagnostic_document: Document,
    exit_value: int,
) -> int:
    wire = Wire(request)
    wire.heartbeat()
    write_bytes(
        output_path,
        canonical(
            validation_result(
                request,
                outcome,
                [diagnostic_document],
                validated_at_utc=wire.timestamp(),
            )
        ),
    )
    return exit_value


def validate_unsupported_capability(request: Request, output_path: str) -> int:
    return _validate_with(
        request,
        output_path,
        "NOT_APPLICABLE",
        adapter_diagnostic(
            "ADAPTER.UNSUPPORTED_CAPABILITY",
            "COMPATIBILITY",
            "the strategy requires a capability this engine lacks",
            retriable=False,
        ),
        20,
    )


def validate_temporarily_unavailable(request: Request, output_path: str) -> int:
    return _validate_with(
        request,
        output_path,
        "UNAVAILABLE",
        adapter_diagnostic(
            "ADAPTER.ENGINE_OFFLINE",
            "ADAPTER_UNAVAILABILITY",
            "the engine runtime is temporarily unavailable",
        ),
        30,
    )


def validate_validation_failure(request: Request, output_path: str) -> int:
    return _validate_with(
        request,
        output_path,
        "INVALID",
        adapter_diagnostic(
            "ENGINE.INVALID_STRATEGY",
            "ENGINE_RUNTIME",
            "the strategy failed the engine's static validation",
            retriable=False,
        ),
        10,
    )


def validate_wrong_token_proof(request: Request, output_path: str) -> int:
    wire = Wire(request)
    wire.heartbeat()
    write_bytes(
        output_path,
        canonical(
            validation_result(
                request,
                "VALID",
                [],
                token_hash=attempt_token_hash("Z" * 32),
                validated_at_utc=wire.timestamp(),
            )
        ),
    )
    return 0


def validate_emits_artifact(request: Request, output_path: str) -> int:
    wire = Wire(request)
    wire.heartbeat()
    wire.artifact(
        declaration(
            NATIVE_PATH,
            NATIVE_KIND,
            NATIVE_MEDIA,
            len(NATIVE_BYTES),
            sha256_hex(NATIVE_BYTES),
        )
    )
    write_bytes(
        output_path,
        canonical(
            validation_result(request, "VALID", [], validated_at_utc=wire.timestamp())
        ),
    )
    return 0


def validate_process_timeout(request: Request, output_path: str) -> int:
    time.sleep(PROCESS_TIMEOUT_SLEEP_SECONDS)
    return validate_conformant(request, output_path)


def validate_stale_attempt_result(request: Request, output_path: str) -> int:
    """Row 47: attempt 1 is conformant; attempt 2 copies the stale output byte for
    byte from the command root (the child's cwd)."""
    if request.attempt_number == 1:
        return validate_conformant(request, output_path)
    command_root = os.path.dirname(os.path.abspath(output_path))
    with open(os.path.join(command_root, STALE_OUTPUT_FILE_NAME), "rb") as handle:
        stale = handle.read()
    write_bytes(output_path, stale)
    return 0


VALIDATE_SCENARIOS = {
    "fake.conformant": validate_conformant,
    "fake.unsupported-capability": validate_unsupported_capability,
    "fake.temporarily-unavailable": validate_temporarily_unavailable,
    "fake.validation-failure": validate_validation_failure,
    "fake.wrong-token-proof": validate_wrong_token_proof,
    "fake.validate-emits-artifact": validate_emits_artifact,
    "fake.process-timeout": validate_process_timeout,
    "fake.stale-attempt-result": validate_stale_attempt_result,
}


# --- Run (plan 3.10, 7, rows 3-52) -------------------------------------------------


class Run:
    """One run command: the wire plus the work directory and result path."""

    def __init__(self, request: Request, work_dir: str, result_path: str) -> None:
        self.request = request
        self.work_dir = work_dir
        self.result_path = result_path
        self.wire = Wire(request)

    def write_candidate(self, relative_path: str, content: bytes) -> tuple[int, str]:
        write_bytes(os.path.join(self.work_dir, *relative_path.split("/")), content)
        return len(content), sha256_hex(content)

    def manifest(
        self,
        status: str,
        candidates: list[Document],
        *,
        warnings: list[Document] | None = None,
        diagnostics: list[Document] | None = None,
        request_hash: str | None = None,
    ) -> Document:
        payload = self.request.payload
        return {
            "schema_version": SCHEMA_VERSION,
            "protocol_version": PROTOCOL_VERSION,
            "adapter_manifest_id": manifest_id(self.request.invocation_id),
            "experiment_id": payload["experiment_id"],
            "run_id": self.request.run_id,
            "invocation_id": self.request.invocation_id,
            "attempt_token": self.request.token,
            "semantic_status": status,
            "started_at_utc": instant(self.request.created_at_utc, 0),
            "completed_at_utc": self.wire.timestamp(),
            "provenance": {
                "experiment_spec_hash": payload["experiment_spec_hash"],
                "request_hash": (
                    payload["request_hash"] if request_hash is None else request_hash
                ),
                "strategy_version_hash": payload["strategy_version_hash"],
                "dataset_version_hash": payload["dataset_version_hash"],
                "configuration_hash": payload["configuration_hash"],
                "adapter": payload["adapter"],
                "engine": payload["engine"],
                "negotiated_versions": payload["negotiated_versions"],
                "comparison_level": payload["comparison_level"],
                "logical_slot_id": payload["logical_slot_id"],
                "attempt_number": payload["attempt_number"],
            },
            "candidate_artifacts": candidates,
            "candidate_metrics": [
                {
                    "metric_name": "total_return",
                    "value": "0.125",
                    "value_status": "DEFINED",
                    "unit": "ratio",
                    "methodology_version": "1.0.0",
                    "comparison_level": payload["comparison_level"],
                }
            ],
            "diagnostics": [] if diagnostics is None else diagnostics,
            "warnings": [] if warnings is None else warnings,
            "approximations": self.request.snapshot("approximation_ids"),
        }

    def write_manifest(self, document: Document) -> str:
        data = canonical(document)
        write_bytes(self.result_path, data)
        return sha256_hex(data)

    def write_manifest_bytes(self, data: bytes) -> str:
        write_bytes(self.result_path, data)
        return sha256_hex(data)


def failure_diagnostic() -> Document:
    return adapter_diagnostic(
        "ENGINE.CRASHED", "ENGINE_RUNTIME", "the engine reported a runtime failure"
    )


def run_success(
    run: Run,
    *,
    status: str = "SUCCEEDED",
    warning_document: Document | None = None,
    native_bytes: bytes = NATIVE_BYTES,
    event_native_digest: str | None = None,
    manifest_native_digest: str | None = None,
    request_hash: str | None = None,
) -> int:
    """Row 3 and its variants: two declared and written candidates, a manifest
    agreeing with the exit, then ``FINAL_RESULT``."""
    wire = run.wire
    wire.heartbeat()
    wire.progress()
    if warning_document is not None:
        wire.warning(warning_document)
    native_size, native_digest = run.write_candidate(NATIVE_PATH, native_bytes)
    normalized_size, normalized_digest = run.write_candidate(
        NORMALIZED_PATH, NORMALIZED_BYTES
    )
    event_digest = native_digest if event_native_digest is None else event_native_digest
    wire.artifact(
        declaration(NATIVE_PATH, NATIVE_KIND, NATIVE_MEDIA, native_size, event_digest)
    )
    wire.artifact(
        declaration(
            NORMALIZED_PATH,
            NORMALIZED_KIND,
            NORMALIZED_MEDIA,
            normalized_size,
            normalized_digest,
        )
    )
    manifest_digest = (
        event_digest if manifest_native_digest is None else manifest_native_digest
    )
    document = run.manifest(
        status,
        [
            declaration(
                NATIVE_PATH, NATIVE_KIND, NATIVE_MEDIA, native_size, manifest_digest
            ),
            declaration(
                NORMALIZED_PATH,
                NORMALIZED_KIND,
                NORMALIZED_MEDIA,
                normalized_size,
                normalized_digest,
            ),
        ],
        warnings=[] if warning_document is None else [warning_document],
        request_hash=request_hash,
    )
    wire.final(run.write_manifest(document), status)
    return 0


def run_conformant(run: Run) -> int:
    return run_success(run)


def run_warnings(run: Run) -> int:
    return run_success(
        run, status="SUCCEEDED_WITH_WARNINGS", warning_document=warning()
    )


def _late(run: Run, status: str, diagnostic_document: Document, exit_value: int) -> int:
    wire = run.wire
    wire.heartbeat()
    document = run.manifest(status, [], diagnostics=[diagnostic_document])
    wire.final(run.write_manifest(document), status)
    return exit_value


def run_late_not_applicable(run: Run) -> int:
    return _late(
        run,
        "NOT_APPLICABLE",
        adapter_diagnostic(
            "ADAPTER.UNSUPPORTED_CAPABILITY",
            "COMPATIBILITY",
            "the strategy requires a capability discovered missing after preflight",
            retriable=False,
        ),
        20,
    )


def run_late_unavailable(run: Run) -> int:
    return _late(
        run,
        "UNAVAILABLE",
        adapter_diagnostic(
            "ADAPTER.ENGINE_OFFLINE",
            "ADAPTER_UNAVAILABILITY",
            "the engine runtime became unavailable during the run",
        ),
        30,
    )


def run_malformed_json(run: Run) -> int:
    run.wire.heartbeat()
    emit(b'{"schema_version": ')
    return 0


def run_unknown_event(run: Run) -> int:
    wire = run.wire
    wire.counter = 1
    emit(wire.line(1, "TELEMETRY", {"activity_counter": 1, "phase": PHASE}))
    return 0


def run_duplicate_sequence(run: Run) -> int:
    wire = run.wire
    wire.heartbeat()
    wire.heartbeat()
    emit(wire.line(2, "HEARTBEAT", {"activity_counter": 3, "phase": PHASE}))
    return 0


def run_replayed_sequence(run: Run) -> int:
    wire = run.wire
    wire.heartbeat()
    second = wire.heartbeat()
    emit(second)
    wire.progress()
    native_size, native_digest = run.write_candidate(NATIVE_PATH, NATIVE_BYTES)
    normalized_size, normalized_digest = run.write_candidate(
        NORMALIZED_PATH, NORMALIZED_BYTES
    )
    native = declaration(
        NATIVE_PATH, NATIVE_KIND, NATIVE_MEDIA, native_size, native_digest
    )
    normalized = declaration(
        NORMALIZED_PATH,
        NORMALIZED_KIND,
        NORMALIZED_MEDIA,
        normalized_size,
        normalized_digest,
    )
    wire.artifact(native)
    wire.artifact(normalized)
    wire.final(
        run.write_manifest(run.manifest("SUCCEEDED", [native, normalized])), "SUCCEEDED"
    )
    return 0


def run_skipped_sequence(run: Run) -> int:
    wire = run.wire
    wire.heartbeat()
    emit(wire.line(3, "HEARTBEAT", {"activity_counter": 3, "phase": PHASE}))
    return 0


def run_wrong_invocation(run: Run) -> int:
    seed = f"foreign:{run.request.invocation_id}".encode()
    foreign = f"inv_{uuid4_shaped(sha256_hex(seed))}"
    run.wire = Wire(run.request, invocation_id=foreign)
    return run_success(run)


def run_wrong_request_hash(run: Run) -> int:
    return run_success(run, request_hash=sha256_hex(b"altered"))


def run_wrong_token(run: Run) -> int:
    token = run.request.token
    swapped = ("A" if token[0] != "A" else "B") + token[1:]
    run.wire = Wire(run.request, token=swapped)
    return run_success(run)


def run_oversized_line(run: Run) -> int:
    wire = run.wire
    wire.heartbeat()
    wire.sequence += 1
    wire.counter += 1
    body = wire.line(
        wire.sequence, "HEARTBEAT", {"activity_counter": wire.counter, "phase": PHASE}
    )
    padding = run.request.limit("max_event_bytes") + 1 - len(body)
    emit(body[:-1] + b" " * padding + b"}")
    return 0


def run_stdout_noise(run: Run) -> int:
    emit(b"starting engine")
    return run_success(run)


def run_stderr_output(run: Run) -> int:
    emit_stderr(b"engine warming up\n")
    emit_stderr(b"token=" + run.request.token.encode("utf-8") + b"\n")
    return run_success(run)


def run_stderr_flood(run: Run) -> int:
    limit = run.request.limit("max_stderr_bytes")
    chunk = (b"x" * 1023) + b"\n"
    written = 0
    while written < limit + 4096:
        emit_stderr(chunk)
        written += len(chunk)
    return run_success(run)


def run_heartbeat_success(run: Run) -> int:
    end = time.monotonic() + HEARTBEAT_SUCCESS_SECONDS
    while time.monotonic() < end:
        run.wire.heartbeat()
        time.sleep(HEARTBEAT_PERIOD_SECONDS)
    wire = run.wire
    wire.progress()
    native_size, native_digest = run.write_candidate(NATIVE_PATH, NATIVE_BYTES)
    normalized_size, normalized_digest = run.write_candidate(
        NORMALIZED_PATH, NORMALIZED_BYTES
    )
    native = declaration(
        NATIVE_PATH, NATIVE_KIND, NATIVE_MEDIA, native_size, native_digest
    )
    normalized = declaration(
        NORMALIZED_PATH,
        NORMALIZED_KIND,
        NORMALIZED_MEDIA,
        normalized_size,
        normalized_digest,
    )
    wire.artifact(native)
    wire.artifact(normalized)
    wire.final(
        run.write_manifest(run.manifest("SUCCEEDED", [native, normalized])), "SUCCEEDED"
    )
    return 0


def run_heartbeat_timeout(run: Run) -> int:
    run.wire.heartbeat()
    time.sleep(LONG_SLEEP_SECONDS)
    return 0


def run_process_timeout(run: Run) -> int:
    time.sleep(PROCESS_TIMEOUT_SLEEP_SECONDS)
    return run_success(run)


def run_cancellation(run: Run) -> int:
    while True:
        run.wire.heartbeat()
        time.sleep(HEARTBEAT_PERIOD_SECONDS)


def _exit_with_manifest(run: Run, status: str, exit_value: int) -> int:
    wire = run.wire
    wire.heartbeat()
    document = run.manifest(status, [], diagnostics=[failure_diagnostic()])
    wire.final(run.write_manifest(document), status)
    return exit_value


def run_exit_10(run: Run) -> int:
    return _exit_with_manifest(run, "FAILED", 10)


def run_exit_40(run: Run) -> int:
    return _exit_with_manifest(run, "FAILED", 40)


def run_exit_50(run: Run) -> int:
    return _exit_with_manifest(run, "CANCELLED", 50)


def run_exit_60(run: Run) -> int:
    return _exit_with_manifest(run, "TIMED_OUT", 60)


def run_exit_70(run: Run) -> int:
    return _exit_with_manifest(run, "FAILED", 70)


def run_exit_unrecognized(run: Run) -> int:
    run.wire.heartbeat()
    return UNRECOGNIZED_EXIT


def run_missing_manifest(run: Run) -> int:
    run.wire.heartbeat()
    return 0


def run_malformed_manifest(run: Run) -> int:
    wire = run.wire
    wire.heartbeat()
    wire.final(run.write_manifest_bytes(b"not json"), "SUCCEEDED")
    return 0


def run_disagreeing_manifest(run: Run) -> int:
    wire = run.wire
    wire.heartbeat()
    wire.final(run.write_manifest(run.manifest("SUCCEEDED", [])), "SUCCEEDED")
    return 40


def run_exit_0_not_applicable(run: Run) -> int:
    return _late(
        run,
        "NOT_APPLICABLE",
        adapter_diagnostic(
            "ADAPTER.UNSUPPORTED_CAPABILITY",
            "COMPATIBILITY",
            "the strategy requires a capability this engine lacks",
            retriable=False,
        ),
        0,
    )


def run_path_escape(run: Run) -> int:
    wire = run.wire
    wire.heartbeat()
    wire.artifact(
        declaration(
            "../escape.bin",
            NATIVE_KIND,
            NATIVE_MEDIA,
            len(NATIVE_BYTES),
            sha256_hex(NATIVE_BYTES),
        )
    )
    return 0


def run_manifest_path_escape(run: Run) -> int:
    wire = run.wire
    wire.heartbeat()
    wire.progress()
    native_size, native_digest = run.write_candidate(NATIVE_PATH, NATIVE_BYTES)
    native = declaration(
        NATIVE_PATH, NATIVE_KIND, NATIVE_MEDIA, native_size, native_digest
    )
    wire.artifact(native)
    escape = declaration(
        "C:/escape.bin",
        NATIVE_KIND,
        NATIVE_MEDIA,
        len(OTHER_BYTES),
        sha256_hex(OTHER_BYTES),
    )
    wire.final(
        run.write_manifest(run.manifest("SUCCEEDED", [native, escape])), "SUCCEEDED"
    )
    return 0


def run_checksum_mismatch(run: Run) -> int:
    other = sha256_hex(OTHER_BYTES)
    return run_success(run, event_native_digest=other, manifest_native_digest=other)


def run_event_manifest_mismatch(run: Run) -> int:
    return run_success(run, manifest_native_digest=sha256_hex(OTHER_BYTES))


def run_crash_before_first_event(run: Run) -> int:
    os._exit(CRASH_EXIT)


def run_crash_after_partial_events(run: Run) -> int:
    wire = run.wire
    wire.heartbeat()
    wire.heartbeat()
    wire.heartbeat()
    wire.artifact(
        declaration(
            NATIVE_PATH,
            NATIVE_KIND,
            NATIVE_MEDIA,
            len(NATIVE_BYTES),
            sha256_hex(NATIVE_BYTES),
        )
    )
    os._exit(CRASH_EXIT)


def run_token_in_warning(run: Run) -> int:
    return run_success(
        run,
        status="SUCCEEDED_WITH_WARNINGS",
        warning_document=warning(f"fills approximated for {run.request.token}"),
    )


def run_token_in_candidate(run: Run) -> int:
    return run_success(
        run,
        native_bytes=b"fake native result " + run.request.token.encode("utf-8") + b"\n",
    )


def run_core_namespace_code(run: Run) -> int:
    run.wire.diagnostic(
        adapter_diagnostic("SECURITY.SPOOF", "ENGINE_RUNTIME", "a spoofed core code")
    )
    return 0


def run_second_final_result(run: Run) -> int:
    wire = run.wire
    wire.heartbeat()
    wire.progress()
    digest = run.write_manifest(run.manifest("SUCCEEDED", []))
    wire.final(digest, "SUCCEEDED")
    wire.final(digest, "SUCCEEDED")
    return 0


def run_partial_then_failed_manifest(run: Run) -> int:
    wire = run.wire
    wire.heartbeat()
    native_size, native_digest = run.write_candidate(NATIVE_PATH, NATIVE_BYTES)
    wire.artifact(
        declaration(NATIVE_PATH, NATIVE_KIND, NATIVE_MEDIA, native_size, native_digest)
    )
    document = run.manifest("FAILED", [], diagnostics=[failure_diagnostic()])
    wire.final(run.write_manifest(document), "FAILED")
    return 40


def run_token_as_path(run: Run) -> int:
    wire = run.wire
    wire.heartbeat()
    wire.artifact(
        declaration(
            run.request.token,
            NATIVE_KIND,
            NATIVE_MEDIA,
            len(NATIVE_BYTES),
            sha256_hex(NATIVE_BYTES),
        )
    )
    return 0


def run_token_as_phase(run: Run) -> int:
    run.wire.heartbeat(phase=run.request.token)
    return 0


def run_oversized_manifest(run: Run) -> int:
    wire = run.wire
    wire.heartbeat()
    padded: list[Document] = [
        {
            "warning_code": f"ADAPTER.PAD_{index:02d}",
            "message": "x" * PAD_TEXT_CHARACTERS,
            "impact": "y" * PAD_TEXT_CHARACTERS,
            "prevented_comparison_levels": ["LEVEL_3"],
        }
        for index in range(PAD_WARNING_COUNT)
    ]
    document = run.manifest("SUCCEEDED_WITH_WARNINGS", [], warnings=padded)
    data = canonical(document)
    assert len(data) > run.request.limit("max_manifest_bytes")
    wire.final(run.write_manifest_bytes(data), "SUCCEEDED_WITH_WARNINGS")
    return 0


def run_invalid_utf8_stdout(run: Run) -> int:
    run.wire.heartbeat()
    emit(b"{\xff\xfe")
    return 0


RUN_SCENARIOS = {
    "fake.conformant": run_conformant,
    "fake.warnings": run_warnings,
    "fake.late-not-applicable": run_late_not_applicable,
    "fake.late-unavailable": run_late_unavailable,
    "fake.malformed-json": run_malformed_json,
    "fake.unknown-event": run_unknown_event,
    "fake.duplicate-sequence": run_duplicate_sequence,
    "fake.replayed-sequence": run_replayed_sequence,
    "fake.skipped-sequence": run_skipped_sequence,
    "fake.wrong-invocation": run_wrong_invocation,
    "fake.wrong-request-hash": run_wrong_request_hash,
    "fake.wrong-token": run_wrong_token,
    "fake.oversized-line": run_oversized_line,
    "fake.stdout-noise": run_stdout_noise,
    "fake.stderr-output": run_stderr_output,
    "fake.stderr-flood": run_stderr_flood,
    "fake.heartbeat-success": run_heartbeat_success,
    "fake.heartbeat-timeout": run_heartbeat_timeout,
    "fake.process-timeout": run_process_timeout,
    "fake.cancellation": run_cancellation,
    "fake.exit-10-run": run_exit_10,
    "fake.exit-40": run_exit_40,
    "fake.exit-50": run_exit_50,
    "fake.exit-60": run_exit_60,
    "fake.exit-70": run_exit_70,
    "fake.exit-unrecognized": run_exit_unrecognized,
    "fake.missing-manifest": run_missing_manifest,
    "fake.malformed-manifest": run_malformed_manifest,
    "fake.disagreeing-manifest": run_disagreeing_manifest,
    "fake.exit-0-not-applicable": run_exit_0_not_applicable,
    "fake.path-escape": run_path_escape,
    "fake.manifest-path-escape": run_manifest_path_escape,
    "fake.checksum-mismatch": run_checksum_mismatch,
    "fake.event-manifest-mismatch": run_event_manifest_mismatch,
    "fake.crash-before-first-event": run_crash_before_first_event,
    "fake.crash-after-partial-events": run_crash_after_partial_events,
    "fake.token-in-warning": run_token_in_warning,
    "fake.token-in-candidate": run_token_in_candidate,
    "fake.core-namespace-code": run_core_namespace_code,
    "fake.second-final-result": run_second_final_result,
    "fake.stale-attempt-result": run_exit_40,
    "fake.partial-then-failed-manifest": run_partial_then_failed_manifest,
    "fake.token-as-path": run_token_as_path,
    "fake.token-as-phase": run_token_as_phase,
    "fake.oversized-manifest": run_oversized_manifest,
    "fake.invalid-utf8-stdout": run_invalid_utf8_stdout,
}


#: The adapter identities this fake serves, per command; anything else is refused.
KNOWN_ADAPTER_NAMES = {
    "describe": frozenset(DESCRIBE_SCENARIOS),
    "validate": frozenset(VALIDATE_SCENARIOS),
    "run": frozenset(RUN_SCENARIOS),
}


# --- Entry point (plan 3.7 argument array) -----------------------------------------


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="fake_adapter", add_help=False)
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
        # Plan 3.6: an argument array the adapter cannot serve is a refused request.
        return REQUEST_INVALID_EXIT
    command = str(arguments.command)
    work_dir = str(arguments.work_dir) if command == "run" else None
    try:
        request = load_request(str(arguments.request), command, work_dir)
    except RequestRefused:
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
