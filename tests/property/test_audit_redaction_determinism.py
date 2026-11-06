"""Stage 9 plan 7.3: ``redact_details`` is idempotent and removes any value
containing a token-shaped substring; the audit details hash is stable under
key order (T28.4-03, A33.6-09)."""

from __future__ import annotations

from typing import Any

from hypothesis import given, settings
from hypothesis import strategies as st

from crypto_lab.audit.models import audit_details_hash
from crypto_lab.audit.redaction import (
    REDACTED,
    contains_token_shape,
    is_denylisted_key,
    redact_details,
)

_URL_SAFE = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_-"
_KEY_ALPHABET = "abcdefghijklmnopqrstuvwxyz_"
_PLAIN_ALPHABET = "abc xyz.,:/!é0123456789"

_tokens = st.text(alphabet=_URL_SAFE, min_size=32, max_size=80)
_plain = st.text(alphabet=_PLAIN_ALPHABET, max_size=40)
_text_strategy = st.one_of(
    _plain,
    st.builds(
        lambda before, token, after: before + token + after, _plain, _tokens, _plain
    ),
)
_leaf_strategy = st.one_of(
    st.none(),
    st.booleans(),
    st.integers(min_value=-(2**63), max_value=2**63 - 1),
    _text_strategy,
)
_keys = st.one_of(
    st.text(alphabet=_KEY_ALPHABET, min_size=1, max_size=12),
    st.sampled_from(["api_key", "credentials", "attempt_token", "stage", "count"]),
)
_values = st.recursive(
    _leaf_strategy,
    lambda children: st.one_of(
        st.lists(children, max_size=4),
        st.dictionaries(_keys, children, max_size=4),
    ),
    max_leaves=12,
)
_details = st.dictionaries(_keys, _values, max_size=6)


def _leaves(value: Any, governed: bool = False) -> list[tuple[Any, bool]]:
    """Every leaf in document order; a subtree under a denylisted key is one
    governed leaf, because redaction replaces that whole value."""
    if governed:
        return [(value, True)]
    if isinstance(value, list):
        return [pair for item in value for pair in _leaves(item)]
    if isinstance(value, dict):
        return [
            pair
            for key, nested in value.items()
            for pair in _leaves(nested, is_denylisted_key(key))
        ]
    return [(value, False)]


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [text for item in value for text in _strings(item)]
    if isinstance(value, dict):
        return [text for nested in value.values() for text in _strings(nested)]
    return []


def _shape(value: Any, governed: bool = False) -> Any:
    if governed:
        return "governed"
    if isinstance(value, list):
        return [_shape(item) for item in value]
    if isinstance(value, dict):
        return {
            key: _shape(nested, is_denylisted_key(key)) for key, nested in value.items()
        }
    return type(value).__name__


@settings(deadline=None, max_examples=150)
@given(_details)
def test_redaction_is_idempotent_and_shape_preserving(
    details: dict[str, Any],
) -> None:
    once = redact_details(details)
    assert redact_details(once) == once
    assert _shape(once) == _shape(details)
    assert list(once) == list(details)


@settings(deadline=None, max_examples=150)
@given(_details)
def test_no_token_shaped_substring_survives(details: dict[str, Any]) -> None:
    redacted = redact_details(details)
    for text in _strings(redacted):
        assert not contains_token_shape(text)
    before = _leaves(details)
    after = _leaves(redacted)
    assert len(before) == len(after)
    for (original, governed), (replaced, _) in zip(before, after, strict=True):
        if governed or (isinstance(original, str) and contains_token_shape(original)):
            assert replaced == REDACTED
        else:
            assert replaced == original


@settings(deadline=None, max_examples=100)
@given(_details, st.randoms(use_true_random=False))
def test_details_hash_is_stable_under_key_order(
    details: dict[str, Any], random_source: Any
) -> None:
    clean = redact_details(details)
    keys = list(clean)
    random_source.shuffle(keys)
    reordered = {key: clean[key] for key in keys}
    assert audit_details_hash(reordered) == audit_details_hash(clean)
    changed = {**clean, "zz_control": "changed"}
    assert audit_details_hash(changed) != audit_details_hash(clean)
