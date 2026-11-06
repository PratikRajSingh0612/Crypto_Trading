"""Stage 9 Task 2: field-level redaction over bounded detail trees (plan Task 2
"Interfaces produced"; specification 24.3:1774, 30.1).

The Stage 6 rule re-exposed over ``JsonValue`` trees: any string value carrying
a token-shaped run (the url-safe attempt-token alphabet, 32 characters or more)
and any value under a denylisted key becomes ``"[REDACTED]"``. Keys are governed
by the reviewed domain bounds and denylist, not by the token grammar: an
ordinary snake_case key of 32 characters is not a token.
"""

from __future__ import annotations

from typing import Any

import pytest

from crypto_lab.audit.redaction import (
    REDACTED,
    TOKEN_SHAPE_PATTERN,
    contains_token_shape,
    is_denylisted_key,
    redact_details,
    validate_bounded_details,
)
from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import (
    MAX_DETAIL_BYTES,
    MAX_DETAIL_COLLECTION,
    MAX_DETAIL_DEPTH,
    MAX_DETAIL_NODES,
    MAX_DETAIL_STRING,
    _inspect_details,
)

_TOKEN = "Ab9_-" * 7  # 35 url-safe characters
_HEX_HASH = "a" * 64
_PREFIXED_ID = "art_12345678-1234-4234-8234-123456789abc"
_LONG_KEY = "sanitized_adapter_result_manifest_hash"  # 38 characters


def test_token_shaped_values_replaced() -> None:
    assert redact_details({"a": _TOKEN}) == {"a": REDACTED}
    assert redact_details({"a": "x" * 31}) == {"a": "x" * 31}
    assert redact_details({"a": "x" * 32}) == {"a": REDACTED}
    assert redact_details({"a": f"prefix {_TOKEN} suffix"}) == {"a": REDACTED}
    # Declared consequence of the grammar: hex digests and prefixed identifiers
    # are token-shaped, so they cannot be detail values (they are top-level
    # fields of the records instead).
    assert redact_details({"hash": _HEX_HASH}) == {"hash": REDACTED}
    assert redact_details({"ref": _PREFIXED_ID}) == {"ref": REDACTED}
    # A non-url-safe character breaks the run.
    assert redact_details({"a": "a" * 31 + "." + "b" * 31}) == {
        "a": "a" * 31 + "." + "b" * 31
    }
    # Recursive: lists and nested objects at every depth.
    assert redact_details({"l": [_TOKEN, ["x", _TOKEN], {"d": _TOKEN}]}) == {
        "l": [REDACTED, ["x", REDACTED], {"d": REDACTED}]
    }
    # Non-string leaves are untouched outside a denylisted key.
    assert redact_details({"n": 7, "b": True, "z": None, "e": []}) == {
        "n": 7,
        "b": True,
        "z": None,
        "e": [],
    }


def test_denylisted_keys_replaced() -> None:
    redacted = redact_details(
        {
            "api_key": "short",
            "nested": {"credentials": 1, "ok": True, "AccessToken": None},
            "items": [{"attempt_token": "x"}, {"plain": "x"}],
        }
    )
    assert redacted == {
        "api_key": REDACTED,
        "nested": {"credentials": REDACTED, "ok": True, "AccessToken": REDACTED},
        "items": [{"attempt_token": REDACTED}, {"plain": "x"}],
    }
    # The key itself is kept so the shape survives; only the value is replaced.
    assert set(redacted) == {"api_key", "nested", "items"}


def test_token_shaped_keys_are_governed_by_the_key_bounds_not_the_grammar() -> None:
    """Values only: a 38-character snake_case key is an ordinary key."""
    assert contains_token_shape(_LONG_KEY)
    assert redact_details({_LONG_KEY: "x"}) == {_LONG_KEY: "x"}
    assert validate_bounded_details({_LONG_KEY: "x"}) == {_LONG_KEY: "x"}


@pytest.mark.parametrize(
    "details",
    [
        {"a": _TOKEN},
        {"api_key": "v", "n": {"credentials": [1, 2]}},
        {"mixed": [_TOKEN, {"api_key": _TOKEN}, "plain", 3, None, False]},
        {"clean": {"deep": {"deeper": ["x", 1, None]}}},
        {},
    ],
)
def test_idempotent(details: dict[str, Any]) -> None:
    once = redact_details(details)
    assert redact_details(once) == once
    # The redacted form is a fixed point; the models accept it unless a
    # denylisted key is present, which the reused domain bounds refuse outright.
    if _has_denylisted_key(once):
        with pytest.raises(ValueError, match="secret-like"):
            validate_bounded_details(once)
    else:
        assert validate_bounded_details(once) == once


def _has_denylisted_key(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            is_denylisted_key(key) or _has_denylisted_key(nested)
            for key, nested in value.items()
        )
    if isinstance(value, list):
        return any(_has_denylisted_key(item) for item in value)
    return False


def test_bounds_preserved() -> None:
    """Redaction never changes the shape: the same keys, list lengths, depth and
    node count, and every replaced string is shorter than the ceiling."""
    deep: Any = _TOKEN
    for _ in range(MAX_DETAIL_DEPTH - 1):
        deep = [deep]
    wide: dict[str, Any] = {
        f"k{index:02d}": "v" * MAX_DETAIL_STRING for index in range(63)
    }
    wide["deep"] = deep
    assert len(wide) == MAX_DETAIL_COLLECTION
    nodes_before = _inspect_details(wide)
    assert nodes_before <= MAX_DETAIL_NODES
    assert len(canonical_json_bytes(wide)) > MAX_DETAIL_BYTES
    redacted = redact_details(wide)
    assert set(redacted) == set(wide)
    assert _inspect_details(redacted) == nodes_before
    innermost = redacted["deep"]
    depth = 0
    while isinstance(innermost, list):
        depth += 1
        (innermost,) = innermost
    assert depth == MAX_DETAIL_DEPTH - 1
    assert innermost == REDACTED
    assert len(REDACTED) < MAX_DETAIL_STRING
    # A bounded input stays bounded: the replacement is shorter than any token.
    bounded: dict[str, Any] = {
        "a": _TOKEN,
        "b": [_TOKEN] * 8,
        "c": {"inner": f"x {_TOKEN}"},
    }
    assert len(canonical_json_bytes(redact_details(bounded))) < len(
        canonical_json_bytes(bounded)
    )
    assert validate_bounded_details(redact_details(bounded)) == redact_details(bounded)
    # A denylisted key survives redaction as a key, so the bounds still refuse it.
    with pytest.raises(ValueError, match="secret-like"):
        validate_bounded_details(redact_details({"api_key": "x" * 100}))


def test_contains_token_shape_grammar() -> None:
    assert TOKEN_SHAPE_PATTERN == r"[A-Za-z0-9_-]{32,}"  # noqa: S105 - a grammar
    assert contains_token_shape("A" * 32)
    assert contains_token_shape("-" * 32)
    assert contains_token_shape("_" * 32)
    assert contains_token_shape("0" * 1025)
    assert contains_token_shape(f"before {_TOKEN} after")
    assert not contains_token_shape("A" * 31)
    assert not contains_token_shape("")
    assert not contains_token_shape("a" * 20 + " " + "b" * 20)
    assert not contains_token_shape("a" * 31 + "/" + "b" * 31)
    assert not contains_token_shape("a" * 31 + "é" + "b" * 31)
    assert not contains_token_shape(REDACTED)
    with pytest.raises(TypeError, match="built-in string"):
        contains_token_shape(b"A" * 32)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    "key",
    [
        "api_key",
        "apiKey",
        "APIKEY",
        "x-api-key",
        "password",
        "Password",
        "user_password_hash",
        "secret",
        "secrets",
        "client_secret",
        "secretary",
        "credential",
        "credentials",
        "attempt_token",
        "attemptToken",
        "access_token",
        "auth_token",
        "token",
        "tokenizer",
        "key",
        "stage",
        "observed",
        "pass",
        "passphrase",
        "sanitized_adapter_result_manifest_hash",
        "credentialed_user",
        "_secret_",
        "secret.value",
    ],
)
def test_denylist_matches_the_domain_detail_refusal(key: str) -> None:
    """The redaction denylist is the reviewed domain denylist: for every key the
    answer equals whether ``_inspect_details`` refuses it as secret-like."""
    refusal: ValueError | None = None
    try:
        _inspect_details({key: None})
    except ValueError as error:
        refusal = error
    refused = refusal is not None
    if refusal is not None:
        assert "secret-like" in str(refusal)
    assert is_denylisted_key(key) is refused, key


def test_unsupported_values_fail_closed() -> None:
    with pytest.raises(ValueError, match="unsupported"):
        redact_details({"ratio": 0.5})  # type: ignore[dict-item]
    with pytest.raises(ValueError, match="unsupported"):
        redact_details({"nested": [{"when": object()}]})  # type: ignore[dict-item]
    with pytest.raises(TypeError, match="mapping"):
        redact_details(["not", "a", "mapping"])  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="string"):
        redact_details({1: "x"})  # type: ignore[dict-item]
    with pytest.raises(TypeError, match="built-in string"):
        is_denylisted_key(b"api_key")  # type: ignore[arg-type]


def test_validate_bounded_details_applies_bounds_then_the_fixed_point() -> None:
    with pytest.raises(ValueError, match="secret-like"):
        validate_bounded_details({"api_key": REDACTED})
    with pytest.raises(ValueError, match="redaction fixed point"):
        validate_bounded_details({"a": _TOKEN})
    with pytest.raises(ValueError, match="too many nodes"):
        validate_bounded_details({f"k{index}": [0] * 4 for index in range(60)})
    with pytest.raises(ValueError, match="maximum encoded bytes"):
        validate_bounded_details({f"k{index:02d}": "v" * 2048 for index in range(9)})
    with pytest.raises(ValueError, match="too long"):
        validate_bounded_details({"a": "v" * 2049})
    clean: dict[str, Any] = {"a": "x", "b": [1, None, {"c": True}]}
    assert validate_bounded_details(clean) is clean
