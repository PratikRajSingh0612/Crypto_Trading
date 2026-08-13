from __future__ import annotations

import os
import socket
import subprocess
from typing import Never

import pytest
from pydantic import ValidationError

from crypto_lab.adapters.descriptors import (
    AdapterDescriptor,
    EngineDescriptor,
    OperatingSystem,
    SupportedSchemaVersion,
)


def _engine() -> EngineDescriptor:
    return EngineDescriptor(
        schema_version="1.0.0",
        engine_name="engine.alpha",
        engine_version="1.2.3",
        engine_family="engine.family",
        planned_role="Research simulation.",
        known_limitations=("No live trading.",),
    )


def _schema(name: str, version: str) -> SupportedSchemaVersion:
    return SupportedSchemaVersion(schema_name=name, schema_version=version)


def _adapter(**updates: object) -> AdapterDescriptor:
    payload = {
        "schema_version": "1.0.0",
        "adapter_name": "adapter.alpha",
        "adapter_version": "1.0.0",
        "engine": _engine(),
        "supported_protocol_versions": ("1.0.0", "1.10.0"),
        "supported_schema_versions": (
            _schema("domain.instrument-ref", "1.0.0"),
            _schema("domain.money", "1.0.0"),
        ),
        "capability_vocabulary_version": "capabilities/v1",
        "native_capabilities": ("market.unknown_but_normalized",),
        "approximated_capabilities": (),
        "unsupported_capabilities": ("orders.live",),
        "supported_operating_systems": (OperatingSystem.WINDOWS,),
        "runtime_requirements": ("CPython 3.12",),
        "network_required": True,
        "credentials_required": True,
        "known_modeling_limitations": ("No exchange connectivity.",),
        "executable_hash": "a" * 64,
    }
    payload.update(updates)
    return AdapterDescriptor.model_validate(payload)


def _forbidden(*_args: object, **_kwargs: object) -> Never:
    raise AssertionError("descriptor construction performed runtime work")


def test_structural_descriptor_accepts_unknown_normalized_capability() -> None:
    descriptor = _adapter()
    assert descriptor.native_capabilities == ("market.unknown_but_normalized",)
    assert descriptor.network_required is True
    assert descriptor.credentials_required is True


def test_supported_schema_versions_are_structured_sorted_and_unique() -> None:
    descriptor = _adapter()
    assert descriptor.supported_schema_versions[0] == _schema(
        "domain.instrument-ref",
        "1.0.0",
    )
    for invalid in (
        (
            _schema("domain.money", "1.0.0"),
            _schema("domain.instrument-ref", "1.0.0"),
        ),
        (
            _schema("domain.money", "1.0.0"),
            _schema("domain.money", "1.0.0"),
        ),
        (
            _schema("domain.money", "1.10.0"),
            _schema("domain.money", "1.9.0"),
        ),
    ):
        with pytest.raises(ValidationError):
            _adapter(supported_schema_versions=invalid)


@pytest.mark.parametrize(
    "updates",
    [
        {"supported_protocol_versions": ("1.10.0", "1.9.0")},
        {"supported_protocol_versions": ("1.0.0", "1.0.0")},
        {"native_capabilities": ("z.capability", "a.capability")},
        {
            "native_capabilities": ("market.data",),
            "approximated_capabilities": ("market.data",),
        },
        {
            "supported_operating_systems": (
                OperatingSystem.WINDOWS,
                OperatingSystem.LINUX,
            )
        },
        {"unexpected": "rejected"},
    ],
)
def test_descriptor_rejects_unsorted_duplicate_overlapping_or_unknown_values(
    updates: dict[str, object],
) -> None:
    with pytest.raises(ValidationError):
        _adapter(**updates)


def test_all_descriptor_arrays_are_explicit() -> None:
    payload = _adapter().model_dump(mode="python")
    for field in (
        "supported_protocol_versions",
        "supported_schema_versions",
        "native_capabilities",
        "approximated_capabilities",
        "unsupported_capabilities",
        "supported_operating_systems",
        "runtime_requirements",
        "known_modeling_limitations",
    ):
        missing = dict(payload)
        del missing[field]
        with pytest.raises(ValidationError, match="Field required"):
            AdapterDescriptor.model_validate(missing)


def test_engine_descriptor_rejects_unknown_and_unsorted_limitations() -> None:
    payload = _engine().model_dump(mode="python")
    payload["unexpected"] = True
    with pytest.raises(ValidationError, match="extra_forbidden"):
        EngineDescriptor.model_validate(payload)
    with pytest.raises(ValidationError, match="must be sorted"):
        EngineDescriptor(
            schema_version="1.0.0",
            engine_name="engine.alpha",
            engine_version="1.0.0",
            engine_family="engine.family",
            planned_role="Research.",
            known_limitations=("z", "a"),
        )


def test_descriptor_construction_launches_and_reads_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(subprocess, "Popen", _forbidden)
    monkeypatch.setattr(socket, "create_connection", _forbidden)
    monkeypatch.setattr(os, "getenv", _forbidden)
    _adapter()
