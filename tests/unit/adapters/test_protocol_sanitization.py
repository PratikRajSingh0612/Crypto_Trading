"""Stage 6 Task 4: raw-token sanitization (plan section 7.6; specification 14.7, 19.4).

`redact_attempt_token` replaces every occurrence with the placeholder and counts;
`redact_payload` walks a decoded JSON object (keys and values, nested) and exempts
exactly the top-level ``attempt_token`` key; `token_present` is the exact-byte scan
that tolerates chunk boundaries; `contamination_sample` records byte length, source
hash and an escaped redacted sample only when the line decodes as UTF-8;
`BoundedStderrCapture` is the bounded redacting fold whose ``finish()`` leaves no
byte in `StderrCapture`. Nothing here reads a clock, a file or the environment.
"""

from __future__ import annotations

import ast
import hashlib
import json
from pathlib import Path
from typing import Any, Final, Never

import pytest
from pydantic import ValidationError
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters import sanitization
from crypto_lab.adapters.limits import MAX_CONTAMINATION_SAMPLE_BYTES, MAX_STDERR_BYTES
from crypto_lab.adapters.sanitization import (
    REDACTION_PLACEHOLDER,
    BoundedStderrCapture,
    ContaminationSample,
    StderrCapture,
    contamination_sample,
    redact_attempt_token,
    redact_payload,
    token_present,
)
from crypto_lab.domain.hashing import sha256_bytes

_TOKEN: Final = "Qx7TOKENqz9TOKEN" + "token0123456789ab"
_OTHER: Final = "Zy3OTHERzz1OTHER" + "other9876543210cd"
_PURE_ROOTS: Final = frozenset(
    {"__future__", "collections", "hashlib", "json", "typing", "pydantic", "crypto_lab"}
)
_STAGE4_BARE_NAMES: Final = frozenset(
    {"buffer", "context", "note", "problem", "compose", "Loader", "get_snippet"}
)


def _missing(value: object) -> bool:
    return value is MISSING


def _forbidden(*_args: object, **_kwargs: object) -> Never:
    raise AssertionError("sanitization performed runtime work")


# --- Inventory and purity ---------------------------------------------------------


def test_the_placeholder_is_the_plan_literal_and_cannot_be_a_token() -> None:
    assert REDACTION_PLACEHOLDER == "<attempt-token-redacted>"
    # Shorter than the 32-character token minimum and outside the url-safe grammar.
    assert len(REDACTION_PLACEHOLDER) < 32
    assert "<" in REDACTION_PLACEHOLDER


@pytest.mark.parametrize(
    ("model", "expected", "optional"),
    [
        (ContaminationSample, ("byte_length", "source_hash", "sample"), ("sample",)),
        (
            StderrCapture,
            ("retained_byte_count", "truncated", "source_hash", "sanitized_text"),
            ("sanitized_text",),
        ),
    ],
    ids=["ContaminationSample", "StderrCapture"],
)
def test_each_projection_declares_exactly_the_plan_fields_in_order(
    model: type[Any], expected: tuple[str, ...], optional: tuple[str, ...]
) -> None:
    assert tuple(model.model_fields) == expected
    for name, field in model.model_fields.items():
        assert field.is_required() is (name not in optional), name
    assert "schema_version" not in model.model_fields
    assert "attempt_token" not in model.model_fields


def _scan(source: str) -> tuple[set[str], set[str], set[str]]:
    """The Stage 4 bare-name scan: import roots, first-party packages and every name
    the source mentions (bound, attribute or called); ambient calls are refused."""
    tree = ast.parse(source)
    roots: set[str] = set()
    packages: set[str] = set()
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.partition(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            roots.add(node.module.partition(".")[0])
            if node.module.startswith("crypto_lab."):
                packages.add(node.module.split(".")[1])
        elif isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        if isinstance(node, ast.Call):
            target = node.func
            called = (
                target.id
                if isinstance(target, ast.Name)
                else getattr(target, "attr", "")
            )
            assert called not in {"open", "now", "utcnow", "today"}, ast.dump(node)
    return roots, packages, names


def test_the_module_imports_only_pure_roots_and_uses_no_forbidden_name() -> None:
    source = Path(sanitization.__file__ or "").read_text(encoding="utf-8")
    roots, packages, names = _scan(source)
    assert roots <= _PURE_ROOTS, sorted(roots - _PURE_ROOTS)
    assert packages <= {"domain", "adapters"}, sorted(packages)
    assert names & _STAGE4_BARE_NAMES == set()
    assert "subprocess" not in source
    assert "AttemptToken" not in source


def test_the_bare_name_scan_finds_a_planted_name() -> None:
    """Plan Task 4 control: the scan that clears the module does see a Stage 4 bare
    name whether it is bound, read as an attribute or called."""
    planted = (
        "def f(buffer):\n    note = buffer.context\n    return get_snippet(note)\n"
    )
    assert _scan(planted)[2] & _STAGE4_BARE_NAMES == {
        "buffer",
        "context",
        "note",
        "get_snippet",
    }


def test_sanitization_launches_reads_and_connects_to_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("subprocess.Popen", _forbidden)
    monkeypatch.setattr("socket.create_connection", _forbidden)
    monkeypatch.setattr("os.getenv", _forbidden)
    redact_attempt_token(f"x{_TOKEN}y", _TOKEN)
    redact_payload({"a": [_TOKEN]}, _TOKEN)
    token_present([b"ab", b"cd"], b"bc")
    contamination_sample(b"starting engine", _TOKEN)
    fold = BoundedStderrCapture(limit=64, token=_TOKEN)
    fold.feed(b"engine says hello\n")
    fold.finish()


# --- redact_attempt_token -----------------------------------------------------------


def test_every_occurrence_is_replaced_and_counted() -> None:
    text = f"start {_TOKEN} middle {_TOKEN}{_TOKEN} end"
    redacted, count = redact_attempt_token(text, _TOKEN)
    assert count == 3
    assert _TOKEN not in redacted
    assert redacted == (
        f"start {REDACTION_PLACEHOLDER} middle "
        f"{REDACTION_PLACEHOLDER}{REDACTION_PLACEHOLDER} end"
    )


def test_a_text_without_the_token_is_returned_unchanged_with_a_zero_count() -> None:
    assert redact_attempt_token("no secret here", _TOKEN) == ("no secret here", 0)
    assert redact_attempt_token("", _TOKEN) == ("", 0)
    # Another run's token is not this run's token.
    assert redact_attempt_token(_OTHER, _TOKEN) == (_OTHER, 0)


def test_redaction_arguments_are_type_and_bound_checked() -> None:
    with pytest.raises(TypeError, match="text"):
        redact_attempt_token(b"bytes", _TOKEN)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="token"):
        redact_attempt_token("text", None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="token"):
        redact_attempt_token("text", "")


# --- redact_payload -----------------------------------------------------------------


def test_redact_payload_walks_values_keys_and_nesting_and_leaves_the_input_alone() -> (
    None
):
    document: dict[str, Any] = {
        "message": f"engine said {_TOKEN}",
        "nested": {"list": [_TOKEN, 1, True, None, {"deep": f"{_TOKEN}!"}]},
        f"key-{_TOKEN}": "value",
        "count": 3,
        "flag": False,
        "nothing": None,
    }
    snapshot = repr(document)
    result, count = redact_payload(document, _TOKEN)
    redacted: Any = result
    assert count == 4
    assert repr(document) == snapshot
    assert _TOKEN not in repr(redacted)
    assert redacted["message"] == f"engine said {REDACTION_PLACEHOLDER}"
    assert redacted["nested"]["list"][0] == REDACTION_PLACEHOLDER
    assert redacted["nested"]["list"][1:4] == [1, True, None]
    assert redacted["nested"]["list"][4]["deep"] == f"{REDACTION_PLACEHOLDER}!"
    assert redacted[f"key-{REDACTION_PLACEHOLDER}"] == "value"
    assert redacted["count"] == 3
    assert redacted["flag"] is False
    assert redacted["nothing"] is None


def test_redact_payload_exempts_only_the_top_level_attempt_token_key() -> None:
    document: dict[str, Any] = {
        "attempt_token": _TOKEN,
        "payload": {"attempt_token": _TOKEN, "phase": _TOKEN},
    }
    result, count = redact_payload(document, _TOKEN)
    redacted: Any = result
    assert count == 2
    assert redacted["attempt_token"] == _TOKEN
    assert redacted["payload"]["attempt_token"] == REDACTION_PLACEHOLDER
    assert redacted["payload"]["phase"] == REDACTION_PLACEHOLDER


def test_redact_payload_accepts_every_json_root_and_rejects_others() -> None:
    assert redact_payload([_TOKEN, "x"], _TOKEN) == ([REDACTION_PLACEHOLDER, "x"], 1)
    assert redact_payload(_TOKEN, _TOKEN) == (REDACTION_PLACEHOLDER, 1)
    assert redact_payload(7, _TOKEN) == (7, 0)
    assert redact_payload(None, _TOKEN) == (None, 0)
    # A JSON number that decoded as a float is a leaf like any other: it is left
    # for strict validation to refuse, never a reason for the walk to raise.
    assert redact_payload({"x": 1.5}, _TOKEN) == ({"x": 1.5}, 0)
    with pytest.raises(TypeError, match="JSON"):
        redact_payload({"x": b"bytes"}, _TOKEN)  # type: ignore[dict-item]
    with pytest.raises(TypeError, match="JSON"):
        redact_payload({1: "x"}, _TOKEN)  # type: ignore[dict-item]
    with pytest.raises(ValueError, match="token"):
        redact_payload({"x": "y"}, "")


# --- token_present ------------------------------------------------------------------


def test_a_token_split_across_two_chunks_is_detected() -> None:
    token = _TOKEN.encode("utf-8")
    prefix, suffix = token[:13], token[13:]
    assert token_present([b"noise " + prefix, suffix + b" more"], token)
    assert token_present([token[:1], token[1:-1], token[-1:]], token)
    assert token_present([b"", token, b""], token)
    assert not token_present([b"noise " + prefix, b"x" + suffix], token)
    assert not token_present([], token)
    assert not token_present([b"", b""], token)
    assert not token_present([_OTHER.encode("utf-8")], token)


def test_token_present_consumes_an_iterator_once_and_checks_its_arguments() -> None:
    token = _TOKEN.encode("utf-8")
    chunks = iter([b"a", token])
    assert token_present(chunks, token)
    assert list(chunks) == []
    with pytest.raises(ValueError, match="token"):
        token_present([b"x"], b"")
    with pytest.raises(TypeError, match="token"):
        token_present([b"x"], _TOKEN)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="chunk"):
        token_present(["text"], token)  # type: ignore[list-item]


# --- contamination_sample ------------------------------------------------------------


def test_a_utf8_line_yields_an_escaped_redacted_sample_with_its_facts() -> None:
    line = f"starting engine\x01 {_TOKEN} back\\slash é".encode()
    sample = contamination_sample(line, _TOKEN)
    assert sample.byte_length == len(line)
    assert sample.source_hash == hashlib.sha256(line).hexdigest()
    assert not _missing(sample.sample)
    assert _TOKEN not in sample.sample
    assert sample.sample == (
        f"starting engine\\x01 {REDACTION_PLACEHOLDER} back\\\\slash é"
    )
    assert ContaminationSample.model_validate(sample.model_dump(mode="python")) == (
        sample
    )
    with pytest.raises(ValidationError, match="frozen"):
        sample.byte_length = 0


def test_a_line_that_is_not_utf8_carries_no_sample() -> None:
    line = b"{\xff\xfe"
    sample = contamination_sample(line, _TOKEN)
    assert _missing(sample.sample)
    assert sample.byte_length == 3
    assert sample.source_hash == sha256_bytes(line)


def test_the_sample_is_bounded_after_redaction_and_escaping() -> None:
    line = ("x" * 1000).encode()
    sample = contamination_sample(line, _TOKEN)
    assert len(sample.sample) == MAX_CONTAMINATION_SAMPLE_BYTES
    escaped = ("\x00" * 200).encode()
    sample = contamination_sample(escaped, _TOKEN)
    assert len(sample.sample) <= MAX_CONTAMINATION_SAMPLE_BYTES
    assert sample.sample.startswith("\\x00\\x00")
    # A token straddling the truncation point is redacted before truncation.
    padded = ("y" * 250 + _TOKEN + "z" * 50).encode()
    sample = contamination_sample(padded, _TOKEN)
    assert _TOKEN not in sample.sample
    assert _TOKEN[:10] not in sample.sample
    assert sample.sample.startswith("y" * 250 + REDACTION_PLACEHOLDER[:6])


def test_an_empty_line_yields_an_empty_sample_and_arguments_are_checked() -> None:
    sample = contamination_sample(b"", _TOKEN)
    assert sample.byte_length == 0
    assert sample.sample == ""
    with pytest.raises(TypeError, match="line"):
        contamination_sample("text", _TOKEN)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="token"):
        contamination_sample(b"x", "")


def test_the_sample_model_bounds_its_fields() -> None:
    with pytest.raises(ValidationError, match="sample"):
        ContaminationSample(
            byte_length=1,
            source_hash="a" * 64,
            sample="x" * (MAX_CONTAMINATION_SAMPLE_BYTES + 1),
        )
    with pytest.raises(ValidationError, match="byte_length"):
        ContaminationSample(byte_length=-1, source_hash="a" * 64)
    with pytest.raises(ValidationError, match="extra"):
        ContaminationSample.model_validate(
            {"byte_length": 1, "source_hash": "a" * 64, "line": "x"}
        )


# --- BoundedStderrCapture -----------------------------------------------------------


def test_the_fold_hashes_every_byte_redacts_and_leaves_no_bytes_behind() -> None:
    fold = BoundedStderrCapture(limit=1024, token=_TOKEN)
    first = f"engine warming up {_TOKEN}\n".encode()
    second = "second line é\n".encode()
    fold.feed(first)
    fold.feed(second)
    capture = fold.finish()
    assert isinstance(capture, StderrCapture)
    assert capture.retained_byte_count == len(first) + len(second)
    assert capture.truncated is False
    assert capture.source_hash == hashlib.sha256(first + second).hexdigest()
    assert capture.sanitized_text == (
        f"engine warming up {REDACTION_PLACEHOLDER}\nsecond line é\n"
    )
    assert _TOKEN not in capture.sanitized_text
    assert set(StderrCapture.model_fields) == {
        "retained_byte_count",
        "truncated",
        "source_hash",
        "sanitized_text",
    }
    assert "bytes" not in repr(capture.model_dump(mode="json")).lower()
    with pytest.raises(RuntimeError, match="finished"):
        fold.feed(b"late")
    with pytest.raises(RuntimeError, match="finished"):
        fold.finish()


def test_the_fold_truncates_at_the_limit_while_hashing_every_byte() -> None:
    fold = BoundedStderrCapture(limit=10, token=_TOKEN)
    fold.feed(b"0123456")
    fold.feed(b"789abcdef")
    fold.feed(b"ghij")
    capture = fold.finish()
    assert capture.truncated is True
    assert capture.retained_byte_count == 10
    assert capture.source_hash == sha256_bytes(b"0123456789abcdefghij")
    assert capture.sanitized_text == "0123456789"


def test_a_token_straddling_the_cut_leaves_no_prefix_in_the_text() -> None:
    limit = 40
    fold = BoundedStderrCapture(limit=limit, token=_TOKEN)
    fold.feed(b"a" * 30 + _TOKEN.encode("utf-8") + b"tail")
    capture = fold.finish()
    assert capture.truncated is True
    assert capture.retained_byte_count == limit
    assert not _missing(capture.sanitized_text)
    for length in range(1, len(_TOKEN)):
        assert _TOKEN[:length] not in capture.sanitized_text[30:]
    assert capture.sanitized_text.startswith("a" * 30)
    # Control: an untruncated capture keeps everything after redaction.
    fold = BoundedStderrCapture(limit=1024, token=_TOKEN)
    fold.feed(b"a" * 30 + _TOKEN.encode("utf-8") + b"tail")
    assert fold.finish().sanitized_text == "a" * 30 + REDACTION_PLACEHOLDER + "tail"


def test_a_capture_that_is_not_utf8_keeps_only_count_hash_and_flag() -> None:
    fold = BoundedStderrCapture(limit=64, token=_TOKEN)
    fold.feed(b"\xff\xfe binary")
    capture = fold.finish()
    assert _missing(capture.sanitized_text)
    assert capture.retained_byte_count == 9
    assert capture.truncated is False
    assert capture.source_hash == sha256_bytes(b"\xff\xfe binary")


def test_an_empty_capture_is_an_empty_text() -> None:
    capture = BoundedStderrCapture(limit=64, token=_TOKEN).finish()
    assert capture.retained_byte_count == 0
    assert capture.truncated is False
    assert capture.sanitized_text == ""
    assert capture.source_hash == sha256_bytes(b"")


def test_the_fold_checks_its_arguments_and_the_model_bounds_its_text() -> None:
    with pytest.raises(ValueError, match="limit"):
        BoundedStderrCapture(limit=0, token=_TOKEN)
    with pytest.raises(ValueError, match="limit"):
        BoundedStderrCapture(limit=MAX_STDERR_BYTES + 1, token=_TOKEN)
    with pytest.raises(TypeError, match="limit"):
        BoundedStderrCapture(limit=True, token=_TOKEN)
    with pytest.raises(ValueError, match="token"):
        BoundedStderrCapture(limit=1, token="")
    fold = BoundedStderrCapture(limit=MAX_STDERR_BYTES, token=_TOKEN)
    with pytest.raises(TypeError, match="chunk"):
        fold.feed("text")  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="sanitized_text"):
        StderrCapture(
            retained_byte_count=0,
            truncated=False,
            source_hash="a" * 64,
            sanitized_text="x" * (MAX_STDERR_BYTES + 1),
        )
    with pytest.raises(ValidationError, match="retained_byte_count"):
        StderrCapture(retained_byte_count=-1, truncated=False, source_hash="a" * 64)


def test_redaction_refuses_to_collapse_two_keys_into_one() -> None:
    """Preventive (began green): two keys that redact to one spelling would lose a
    member silently, so the walk refuses rather than picking a survivor."""
    with pytest.raises(ValueError, match="collapse"):
        redact_payload({f"k{_TOKEN}": 1, f"k{REDACTION_PLACEHOLDER}": 2}, _TOKEN)
    # Control: distinct redacted keys are kept, each counted once.
    redacted, count = redact_payload({f"a{_TOKEN}": 1, f"b{_TOKEN}": 2}, _TOKEN)
    assert count == 2
    assert redacted == {f"a{REDACTION_PLACEHOLDER}": 1, f"b{REDACTION_PLACEHOLDER}": 2}


def test_the_sample_escapes_every_non_printable_plane() -> None:
    """Preventive (began green): control characters below U+0100, non-printable
    characters below U+10000 and non-printable astral characters each take their
    own escape; printable text of any plane is kept."""
    line = "a\x1fb\u2028c\U000e0001d\u00e9\U0001f600".encode()
    sample = contamination_sample(line, _TOKEN)
    assert sample.sample == "a\\x1fb\\u2028c\\U000e0001d\u00e9\U0001f600"


def test_a_json_line_is_sampled_from_its_redacted_decoded_object() -> None:
    """Cross-check finding: JSON escapes can spell the token without a literal
    occurrence in the wire text, so a line that decodes as JSON is sampled from the
    redacted decoded object (its top-level ``attempt_token`` replaced too), and the
    sample is emitted only when the token is provably absent from it."""
    escaped = "".join(f"\\u{ord(character):04x}" for character in _TOKEN)
    line = (
        '{"attempt_token":"' + escaped + '","phase":"' + escaped + '","n":[1,"x"]}'
    ).encode("ascii")
    assert _TOKEN not in line.decode("ascii")
    sample = contamination_sample(line, _TOKEN)
    assert not _missing(sample.sample)
    assert _TOKEN not in sample.sample
    assert "u00" not in sample.sample
    assert sample.sample.count(REDACTION_PLACEHOLDER) == 2
    assert sample.byte_length == len(line)
    assert sample.source_hash == sha256_bytes(line)
    # The caller may hand over the decoded object it already holds.
    same = contamination_sample(line, _TOKEN, decoded=json.loads(line))
    assert same == sample
    # A non-JSON line keeps the text path.
    text = contamination_sample(b"starting engine " + _TOKEN.encode(), _TOKEN)
    assert text.sample == "starting engine " + REDACTION_PLACEHOLDER


def test_a_deeply_nested_json_line_yields_no_sample_and_never_raises() -> None:
    """Cross-check finding: a document the C decoder accepts may still exceed the
    recursive walk; the sample is then omitted rather than an exception escaping."""
    depth = 1500
    line = b'{"a":' + b"[" * depth + b"]" * depth + b"}"
    sample = contamination_sample(line, _TOKEN)
    assert _missing(sample.sample)
    assert sample.byte_length == len(line)
    # Control: the walk itself does exceed the interpreter's depth on that object.
    with pytest.raises(RecursionError):
        redact_payload(json.loads(line), _TOKEN)


def test_an_all_digit_token_spelled_as_a_json_number_yields_no_sample() -> None:
    """Preventive (began green): the token grammar admits an all-digit token, and a
    JSON number leaf is not a string the redaction walks, so the re-serialized text
    could carry the token as digits. The absence proof refuses that sample; an
    accepted ``RunEvent`` cannot carry one because every bounded integer field is at
    most 19 digits and a token is at least 32."""
    digits = "1" * 32
    line = b'{"n": ' + digits.encode("ascii") + b"}"
    sample = contamination_sample(line, digits)
    assert _missing(sample.sample)
    assert sample.byte_length == len(line)
    # Control: as a JSON string the same token is redacted and the sample is kept.
    quoted = b'{"n": "' + digits.encode("ascii") + b'"}'
    kept = contamination_sample(quoted, digits)
    assert kept.sample == '{"n": "' + REDACTION_PLACEHOLDER + '"}'
    # Control: in plain text the same token is redacted as text.
    text = contamination_sample(b"x " + digits.encode("ascii") + b" y", digits)
    assert text.sample == "x " + REDACTION_PLACEHOLDER + " y"


def test_the_sample_bound_is_measured_in_utf8_bytes_not_characters() -> None:
    """Cross-check finding: ``MAX_CONTAMINATION_SAMPLE_BYTES`` names bytes while
    printable non-ASCII text is kept verbatim, so a character cut could reach four
    times the bound. The cut counts UTF-8 bytes and never splits a character."""
    two_byte = ("é" * 300).encode()
    sample = contamination_sample(two_byte, _TOKEN)
    assert sample.sample == "é" * (MAX_CONTAMINATION_SAMPLE_BYTES // 2)
    assert len(sample.sample.encode()) == MAX_CONTAMINATION_SAMPLE_BYTES
    four_byte = ("\U0001f600" * 100).encode()
    astral = contamination_sample(four_byte, _TOKEN)
    assert astral.sample == "\U0001f600" * (MAX_CONTAMINATION_SAMPLE_BYTES // 4)
    mixed = ("ab" + "\U0001f600").encode() * 100
    cut = contamination_sample(mixed, _TOKEN)
    encoded = cut.sample.encode()
    bound = MAX_CONTAMINATION_SAMPLE_BYTES
    assert bound - 4 < len(encoded) <= bound
    assert encoded == mixed[: len(encoded)]
    # Control: an ASCII line still fills the bound exactly.
    ascii_sample = contamination_sample(b"z" * 300, _TOKEN)
    assert len(ascii_sample.sample) == MAX_CONTAMINATION_SAMPLE_BYTES


def test_the_stderr_text_bound_holds_when_redaction_lengthens_the_text() -> None:
    """Preventive: the fold admits a token shorter than the placeholder, so redaction
    can lengthen the retained text past ``MAX_STDERR_BYTES`` characters; the fold cuts
    the redacted text to the bound instead of failing its own projection (an attempt
    token is at least 32 characters, longer than the placeholder, so a harness never
    reaches the cut)."""
    occurrences = MAX_STDERR_BYTES // len(REDACTION_PLACEHOLDER) + 1
    short = "q"
    assert short not in REDACTION_PLACEHOLDER
    fold = BoundedStderrCapture(limit=MAX_STDERR_BYTES, token=short)
    fold.feed(short.encode() * occurrences)
    capture = fold.finish()
    assert capture.truncated is False
    assert capture.retained_byte_count == occurrences
    assert len(capture.sanitized_text) == MAX_STDERR_BYTES
    assert short not in capture.sanitized_text
    # Control: a token no shorter than the placeholder never lengthens the text.
    same = BoundedStderrCapture(limit=64, token=_TOKEN)
    same.feed(_TOKEN.encode() + b" tail")
    assert same.finish().sanitized_text == REDACTION_PLACEHOLDER + " tail"
