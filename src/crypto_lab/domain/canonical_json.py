"""Deterministic canonical JSON serialization."""

from __future__ import annotations

import json
from datetime import datetime
from decimal import Decimal
from enum import StrEnum

from pydantic import BaseModel

from crypto_lab.domain.financial import format_decimal
from crypto_lab.domain.time import format_utc, require_utc


def _normalize(value: object, active: set[int]) -> object:
    if value is None or type(value) is bool:
        return value
    if isinstance(value, StrEnum):
        return _normalize(value.value, active)
    if type(value) is str or type(value) is int:
        return value
    if isinstance(value, float):
        raise TypeError("float is forbidden in canonical JSON")
    if isinstance(value, Decimal):
        return format_decimal(value)
    if isinstance(value, datetime):
        return format_utc(require_utc(value))
    if isinstance(value, BaseModel):
        identity = id(value)
        if identity in active:
            raise ValueError("cyclic canonical value")
        active.add(identity)
        try:
            dumped = value.model_dump(
                mode="python",
                by_alias=True,
            )
            return _normalize(dumped, active)
        finally:
            active.remove(identity)
    if type(value) is dict:
        identity = id(value)
        if identity in active:
            raise ValueError("cyclic canonical value")
        active.add(identity)
        try:
            normalized: dict[str, object] = {}
            for key, nested in value.items():
                if type(key) is not str:
                    raise TypeError("canonical JSON object keys must be strings")
                normalized[key] = _normalize(nested, active)
            return normalized
        finally:
            active.remove(identity)
    if type(value) is list or type(value) is tuple:
        identity = id(value)
        if identity in active:
            raise ValueError("cyclic canonical value")
        active.add(identity)
        try:
            return [_normalize(item, active) for item in value]
        finally:
            active.remove(identity)
    raise TypeError(f"unsupported canonical JSON type: {type(value).__name__}")


def canonical_json_text(value: object) -> str:
    """Return canonical compact JSON text."""
    normalized = _normalize(value, set())
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def canonical_json_bytes(value: object) -> bytes:
    """Return canonical UTF-8 bytes without a BOM."""
    return canonical_json_text(value).encode("utf-8")
