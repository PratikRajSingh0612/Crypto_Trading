"""Raw-token sanitization at the adapter trust boundary (Stage 6 plan section 7.6;
specification 14.7 and 19.4).

The raw attempt token is temporary sensitive correlation material. Every function
here removes it from adapter-controlled text before that text can reach a durable
or projected record, and none of them ever receives the token from anywhere but its
caller's argument:

- ``redact_attempt_token`` replaces every occurrence in one text with
  ``REDACTION_PLACEHOLDER`` and returns the count.
- ``redact_payload`` walks a decoded JSON document -- object keys and values, list
  items, nested to any depth -- redacting every string, and exempts exactly one
  place: the value of the document's own top-level ``attempt_token`` key, which the
  W-class input retains verbatim for the hash comparison and the harness's presence
  assertion (plan 7.6). It returns a new document and the count; the input is never
  mutated. Two keys that redact to one spelling are refused, so a document can never
  lose a member silently.
- ``token_present`` is the exact-byte scan over a chunk iterable that carries the last
  ``len(token) - 1`` bytes forward, so a token straddling two chunks is still found.
- ``contamination_sample`` records ``byte_length`` and ``source_hash`` for a rejected
  line and, only when the line decodes as strict UTF-8, a redacted sample escaped
  deterministically (printable characters kept, backslash doubled, everything else as
  ``\\xNN``, ``\\uNNNN`` or ``\\UNNNNNNNN``) and cut between characters to at most
  ``MAX_CONTAMINATION_SAMPLE_BYTES`` UTF-8 bytes. A line that decodes as JSON is
  sampled from the re-serialized text of its redacted decoded object (the
  top-level ``attempt_token`` value replaced too), because a JSON escape can spell the
  token without a literal occurrence in the wire text; every other line is redacted
  as text. The sample is omitted when the line is not UTF-8, when the decoded object
  cannot be walked or re-serialized, or when the token is not provably absent from
  the text (specification 14.7).
- ``BoundedStderrCapture`` is the bounded redacting fold plan 1.4 hosts early: ``feed``
  retains at most ``limit`` bytes, marks ``truncated`` beyond them and hashes every byte
  received; ``finish`` decodes the retained bytes as strict UTF-8, redacts them and
  discards them, so only ``retained_byte_count``, ``truncated``, ``source_hash`` and
  ``sanitized_text`` leave the fold. When the capture was truncated, a tail that is a
  proper prefix of the token is dropped from the text before redaction (the longest
  such prefix), so a token cut by the limit cannot leave a fragment behind. The
  redacted text is cut to ``MAX_STDERR_BYTES`` characters after redaction, a bound
  only a token shorter than the placeholder can press.

Task-local readings, declared rather than inferred silently: the token argument is a
non-empty string of at most 1024 characters (the ``attempt_token_hash`` bound); JSON
numbers that decoded as floats are leaves the walk leaves untouched for strict
validation to refuse; the fold's ``limit`` is ``1..MAX_STDERR_BYTES`` (the parse-ceiling
precedent), the configuration floor being the snapshot's rule; a retained capture cut
inside a multi-byte character is not UTF-8 and yields no text.
"""

from __future__ import annotations

import json
from collections.abc import Iterable
from hashlib import sha256
from typing import Annotated, Final, cast

from pydantic import Field, JsonValue, StringConstraints
from pydantic.experimental.missing_sentinel import MISSING

from crypto_lab.adapters.limits import MAX_CONTAMINATION_SAMPLE_BYTES, MAX_STDERR_BYTES
from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.hashing import sha256_bytes
from crypto_lab.domain.identifiers import Sha256

#: Plan 7.6: the literal every redacted occurrence becomes. Shorter than the
#: 32-character token minimum and outside the url-safe token grammar.
REDACTION_PLACEHOLDER: Final = "<attempt-token-redacted>"
#: The ``attempt_token_hash`` bound: a token is a string of 1 through 1024 characters.
_MAX_TOKEN_CHARACTERS: Final = 1024
#: The one key whose top-level value ``redact_payload`` retains verbatim.
_EXEMPT_KEY: Final = "attempt_token"

_SanitizedText = Annotated[
    str, StringConstraints(strict=True, max_length=MAX_STDERR_BYTES)
]
_SampleText = Annotated[
    str, StringConstraints(strict=True, max_length=MAX_CONTAMINATION_SAMPLE_BYTES)
]


def _require_token(token: object) -> str:
    if type(token) is not str:
        raise TypeError("token must be a built-in string")
    if not token or len(token) > _MAX_TOKEN_CHARACTERS:
        raise ValueError(f"token length must be 1 through {_MAX_TOKEN_CHARACTERS}")
    return token


def redact_attempt_token(text: str, token: str) -> tuple[str, int]:
    """Replace every occurrence of ``token`` in ``text``; return the text and count."""
    if type(text) is not str:
        raise TypeError("text must be a built-in string")
    _require_token(token)
    count = text.count(token)
    if count == 0:
        return text, 0
    return text.replace(token, REDACTION_PLACEHOLDER), count


def _walk(value: JsonValue, token: str) -> tuple[JsonValue, int]:
    if type(value) is str:
        return redact_attempt_token(value, token)
    if (
        value is None
        or type(value) is bool
        or type(value) is int
        or type(value) is float
    ):
        return value, 0
    if type(value) is list:
        items: list[JsonValue] = []
        total = 0
        for item in value:
            redacted, count = _walk(item, token)
            items.append(redacted)
            total += count
        return items, total
    if type(value) is dict:
        return _walk_object(value, token, exempt_key=None)
    raise TypeError("the document is not a JSON value")


def _walk_object(
    document: dict[str, JsonValue], token: str, *, exempt_key: str | None
) -> tuple[dict[str, JsonValue], int]:
    redacted: dict[str, JsonValue] = {}
    total = 0
    for key, value in document.items():
        if type(key) is not str:
            raise TypeError("the document is not a JSON value: keys must be strings")
        if key == exempt_key:
            redacted[key] = value
            continue
        new_key, key_count = redact_attempt_token(key, token)
        new_value, value_count = _walk(value, token)
        if new_key in redacted:
            raise ValueError("redaction would collapse two object keys into one")
        redacted[new_key] = new_value
        total += key_count + value_count
    return redacted, total


def redact_payload(document: JsonValue, token: str) -> tuple[JsonValue, int]:
    """Redact every string in a decoded JSON document except the top-level token.

    Plan 7.6: keys and values at every depth are redacted; the value of the
    document's own top-level ``attempt_token`` key is retained verbatim. Returns a
    new document and the number of occurrences replaced; the input is not mutated.
    """
    _require_token(token)
    if type(document) is dict:
        return _walk_object(document, token, exempt_key=_EXEMPT_KEY)
    return _walk(document, token)


def token_present(chunks: Iterable[bytes], token: bytes) -> bool:
    """Whether the exact token bytes occur anywhere in the concatenated chunks.

    Carries the last ``len(token) - 1`` bytes of each chunk forward, so an
    occurrence split across a chunk boundary is found (plan 7.6). Consumes the
    iterable once and stops at the first occurrence.
    """
    if type(token) is not bytes:
        raise TypeError("token must be bytes")
    if not token:
        raise ValueError("token must not be empty")
    keep = len(token) - 1
    carry = b""
    for chunk in chunks:
        if type(chunk) is not bytes:
            raise TypeError("each chunk must be bytes")
        window = carry + chunk
        if token in window:
            return True
        carry = window[-keep:] if keep else b""
    return False


class ContaminationSample(CanonicalModel):
    """The bounded record of one rejected stdout line (plan 7.6; trust class P).

    ``sample`` is present only when the line decoded as UTF-8 and every token
    occurrence was provably removed; otherwise only the byte length and the exact
    source hash are recorded (specification 14.7).
    """

    byte_length: int = Field(ge=0)
    source_hash: Sha256
    sample: _SampleText | MISSING = MISSING  # type: ignore[valid-type]


def _escape(text: str, limit: int) -> str:
    """Deterministic ``repr``-style escaping, cut so the result fits in ``limit``
    UTF-8 bytes; the cut falls between characters, never inside one."""
    units: list[str] = []
    size = 0
    for character in text:
        if character == "\\":
            unit = "\\\\"
        elif character.isprintable():
            unit = character
        else:
            code = ord(character)
            if code < 0x100:
                unit = f"\\x{code:02x}"
            elif code < 0x10000:
                unit = f"\\u{code:04x}"
            else:
                unit = f"\\U{code:08x}"
        unit_size = len(unit.encode("utf-8"))
        if size + unit_size > limit:
            break
        units.append(unit)
        size += unit_size
    return "".join(units)


def _redacted_document_text(document: JsonValue, token: str) -> str | None:
    """The JSON text of the redacted document, or ``None`` when it cannot be
    produced (a walk or serialization that exceeds the interpreter's depth, a
    non-finite number). The top-level ``attempt_token`` value is replaced as well:
    the exemption exists for validation, never for a sample."""
    try:
        redacted, _ = redact_payload(document, token)
        if type(redacted) is dict and _EXEMPT_KEY in redacted:
            redacted = {**redacted, _EXEMPT_KEY: REDACTION_PLACEHOLDER}
        return json.dumps(redacted, ensure_ascii=False, allow_nan=False)
    except (TypeError, ValueError, RecursionError):
        return None


def contamination_sample(
    line: bytes,
    token: str,
    *,
    decoded: JsonValue | MISSING = MISSING,  # type: ignore[valid-type]
) -> ContaminationSample:
    """Plan 7.6: byte length, exact source hash and a redacted escaped sample.

    A line that decodes as JSON is sampled from its redacted decoded object, never
    from the wire text: a JSON escape can spell the token without a literal
    occurrence, so only the decoded strings are a sound redaction surface. The
    caller may hand over the object it already decoded through ``decoded``; any
    other line is redacted as text. The sample is emitted only when the token is
    provably absent from the text that will be escaped. The standalone decode is the
    plain ``json.loads`` (a repeated key keeps its last value; a non-finite leaf is
    refused at re-serialization), not the parser's header decoder: the absence proof,
    not the decoder, is what protects the sample.
    """
    if type(line) is not bytes:
        raise TypeError("line must be bytes")
    _require_token(token)
    facts: dict[str, object] = {
        "byte_length": len(line),
        "source_hash": sha256_bytes(line),
    }
    try:
        text = line.decode("utf-8")
    except UnicodeDecodeError:
        return ContaminationSample.model_validate(facts)
    document: object = decoded
    if document is MISSING:
        try:
            document = json.loads(text)
        except (ValueError, RecursionError):
            document = MISSING
    if document is MISSING:
        redacted, _ = redact_attempt_token(text, token)
    else:
        rendered = _redacted_document_text(cast("JsonValue", document), token)
        if rendered is None:
            return ContaminationSample.model_validate(facts)
        redacted = rendered
    if token in redacted:
        return ContaminationSample.model_validate(facts)
    facts["sample"] = _escape(redacted, MAX_CONTAMINATION_SAMPLE_BYTES)
    return ContaminationSample.model_validate(facts)


class StderrCapture(CanonicalModel):
    """The projection the stderr fold returns (plan 3.7; trust class P).

    ``retained_byte_count`` counts the bytes kept under the budget; the bytes
    themselves never leave the fold. ``sanitized_text`` is present when the whole
    retained capture decoded as UTF-8 and was redacted, absent otherwise.
    """

    retained_byte_count: int = Field(ge=0)
    truncated: bool
    source_hash: Sha256
    sanitized_text: _SanitizedText | MISSING = MISSING  # type: ignore[valid-type]


class BoundedStderrCapture:
    """The bounded redacting stderr fold (plan 7.6); a mutable accumulator, not a model.

    ``feed`` accumulates up to ``limit`` bytes, sets ``truncated`` beyond it and
    hashes every byte; ``finish`` decodes and redacts the retained bytes, discards
    them and returns the ``StderrCapture``. Neither method is valid after ``finish``.
    """

    __slots__ = (
        "_digest",
        "_finished",
        "_limit",
        "_retained",
        "_token",
        "_truncated",
    )

    def __init__(self, *, limit: int, token: str) -> None:
        if type(limit) is not int:
            raise TypeError("limit must be a built-in integer")
        if not 1 <= limit <= MAX_STDERR_BYTES:
            raise ValueError(f"limit must be within 1..{MAX_STDERR_BYTES}")
        self._token = _require_token(token)
        self._limit = limit
        self._retained = bytearray()
        self._digest = sha256()
        self._truncated = False
        self._finished = False

    def feed(self, chunk: bytes) -> None:
        """Hash every byte; retain up to the limit; mark truncation beyond it."""
        if self._finished:
            raise RuntimeError("the capture is finished")
        if type(chunk) is not bytes:
            raise TypeError("chunk must be bytes")
        self._digest.update(chunk)
        room = self._limit - len(self._retained)
        if len(chunk) > room:
            self._retained += chunk[:room]
            self._truncated = True
        else:
            self._retained += chunk

    def _text_bytes(self, retained: bytes) -> bytes:
        """The retained bytes minus a truncated tail that is a proper token prefix."""
        if not self._truncated:
            return retained
        token = self._token.encode("utf-8")
        longest = min(len(token) - 1, len(retained))
        for length in range(longest, 0, -1):
            if retained.endswith(token[:length]):
                return retained[:-length]
        return retained

    def finish(self) -> StderrCapture:
        """Decode, redact and discard the retained bytes; return the projection."""
        if self._finished:
            raise RuntimeError("the capture is finished")
        self._finished = True
        retained = bytes(self._retained)
        self._retained = bytearray()
        facts: dict[str, object] = {
            "retained_byte_count": len(retained),
            "truncated": self._truncated,
            "source_hash": self._digest.hexdigest(),
        }
        try:
            text = self._text_bytes(retained).decode("utf-8")
        except UnicodeDecodeError:
            return StderrCapture.model_validate(facts)
        sanitized, _ = redact_attempt_token(text, self._token)
        # A token shorter than the placeholder lengthens the text; the projection's
        # bound holds by construction (the cut follows redaction, so no token
        # fragment can be exposed by it).
        facts["sanitized_text"] = sanitized[:MAX_STDERR_BYTES]
        return StderrCapture.model_validate(facts)
