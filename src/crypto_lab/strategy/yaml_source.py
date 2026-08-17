"""Safe YAML loading and the single-pass bounded event-to-value builder.

This is the only module permitted to import ``yaml``. It never enters PyYAML's
Composer or Constructor: ``yaml.parse`` yields events, and the bounded plain
value is built directly from that one event stream. ``yaml.load``,
``yaml.safe_load``, ``yaml.compose``, and ``yaml.compose_all`` are never
called, so no node graph and no cyclic graph can exist.
"""

from __future__ import annotations

import codecs
import contextlib
import copy
import re
from collections.abc import Iterator
from datetime import datetime
from typing import Annotated, Final, cast

import yaml
from pydantic import (
    AfterValidator,
    JsonValue,
    StringConstraints,
    TypeAdapter,
    WithJsonSchema,
)

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.diagnostics import (
    MAX_DETAIL_STRING,
    Diagnostic,
    DiagnosticCategory,
    DiagnosticDetailValue,
    DiagnosticSeverity,
)
from crypto_lab.domain.hashing import HashingProfile, _uuid4_shaped, profile_hash
from crypto_lab.domain.identifiers import exact_string_schema
from crypto_lab.domain.results import Failure, Result, Success

MAX_SOURCE_BYTES: Final = 262_144
MAX_SCALAR_CHARACTERS: Final = 8_192
MAX_COLLECTION_ENTRIES: Final = 512
MAX_EVENT_DEPTH: Final = 32
MAX_EXPANDED_DEPTH: Final = 32
MAX_EVENT_COUNT: Final = 20_000
MAX_ANCHORS: Final = 64
MAX_ALIAS_REFERENCES: Final = 256
MAX_EXPANDED_NODES: Final = 50_000
MIN_INTEGER_VALUE: Final = -(2**63)
MAX_INTEGER_VALUE: Final = 2**63 - 1

_SOURCE_COMPONENT: Final = "strategy.yaml_source"
_MAX_INTEGER_DIGITS: Final = 19
_BOMS: Final = (
    codecs.BOM_UTF32_LE,
    codecs.BOM_UTF32_BE,
    codecs.BOM_UTF8,
    codecs.BOM_UTF16_LE,
    codecs.BOM_UTF16_BE,
)
_SOURCE_NAME_PATTERN: Final = r"^(?!.*\.\.)[a-z0-9][a-z0-9._-]{0,127}$"
_SOURCE_NAME_RE: Final = re.compile(_SOURCE_NAME_PATTERN)

_STR_TAG: Final = "tag:yaml.org,2002:str"
_INT_TAG: Final = "tag:yaml.org,2002:int"
_BOOL_TAG: Final = "tag:yaml.org,2002:bool"
_MAP_TAG: Final = "tag:yaml.org,2002:map"
_SEQ_TAG: Final = "tag:yaml.org,2002:seq"

_CANONICAL_INTEGER = re.compile(r"^(0|-?[1-9][0-9]*)$")
_NON_PLAIN_STYLES: Final = frozenset({"'", '"', "|", ">"})
# Deliberately at least as broad as PyYAML's own resolver regexes, so the
# contract holds even against a reader implementing YAML 1.1 more completely.
# The merge token ``<<`` is absent by design: it is rejected in key position by
# the mapping-key contract and is an ordinary string elsewhere.
_REJECTED_PLAIN_SCALARS: Final = tuple(
    re.compile(pattern)
    for pattern in (
        r"^(?:y|Y|yes|Yes|YES|n|N|no|No|NO|on|On|ON|off|Off|OFF"
        r"|True|TRUE|False|FALSE)$",
        r"^[-+]?0b[01_]+$",
        r"^[-+]?0o?[0-7_]+$",
        r"^[-+]?0x[0-9a-fA-F_]+$",
        r"^\+[0-9][0-9_]*$",
        r"^-?0[0-9_]+$",
        r"^-0$",
        r"^[-+]?[0-9][0-9_]*_[0-9_]*$",
        r"^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+$",
        r"^[-+]?(?:\.[0-9_]+|[0-9][0-9_]*\.[0-9_]*)(?:[eE][-+]?[0-9]+)?$",
        r"^[-+]?[0-9][0-9_]*[eE][-+]?[0-9]+$",
        r"^[-+]?[0-9][0-9_]*(?::[0-5]?[0-9])+\.[0-9_]*$",
        r"^[-+]?\.(?:inf|Inf|INF)$",
        r"^\.(?:nan|NaN|NAN)$",
        r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$",
        r"^[0-9]{4}-[0-9]{1,2}-[0-9]{1,2}(?:[Tt]|[ \t]+)[0-9]{1,2}:[0-9]{2}"
        r":[0-9]{2}(?:\.[0-9]*)?(?:[ \t]*(?:Z|[-+][0-9]{1,2}(?::[0-9]{2})?))?$",
        r"^(?:~|null|Null|NULL|)$",
        r"^=$",
    )
)

_SECURITY_CODES: Final = frozenset(
    {
        "STRATEGY.YAML_FORBIDDEN_TAG",
        "STRATEGY.YAML_MERGE_KEY_FORBIDDEN",
        "STRATEGY.YAML_SCALAR_TOO_LONG",
        "STRATEGY.YAML_COLLECTION_TOO_LARGE",
        "STRATEGY.YAML_DEPTH_EXCEEDED",
        "STRATEGY.YAML_EVENT_BUDGET_EXCEEDED",
        "STRATEGY.YAML_ANCHOR_BUDGET_EXCEEDED",
        "STRATEGY.YAML_ALIAS_BUDGET_EXCEEDED",
        "STRATEGY.YAML_EXPANSION_EXCEEDED",
        "STRATEGY.YAML_RECURSIVE_ALIAS",
        "STRATEGY.YAML_ANCHOR_REDEFINED",
        "STRATEGY.YAML_DIRECTIVE_FORBIDDEN",
        "STRATEGY.SOURCE_TOO_LARGE",
        "STRATEGY.SOURCE_NOT_IN_MEMORY",
        "STRATEGY.SOURCE_NAME_INVALID",
    }
)
# One fixed project-authored message per code. No message is derived from the
# document, so no document byte can reach a diagnostic through one.
_MESSAGES: Final = {
    "STRATEGY.SOURCE_TOO_LARGE": "strategy source exceeds the maximum byte size",
    "STRATEGY.SOURCE_NOT_UTF8": "strategy source is not valid UTF-8",
    "STRATEGY.SOURCE_BOM_PRESENT": "strategy source carries a byte order mark",
    "STRATEGY.SOURCE_NOT_IN_MEMORY": "strategy source must be in-memory bytes",
    "STRATEGY.SOURCE_NAME_INVALID": "strategy source name is not a bounded label",
    "STRATEGY.YAML_SYNTAX": "strategy source is not well-formed YAML",
    "STRATEGY.YAML_MULTIPLE_DOCUMENTS": "strategy source carries multiple documents",
    "STRATEGY.YAML_EMPTY_DOCUMENT": "strategy source carries no document",
    "STRATEGY.YAML_FORBIDDEN_TAG": "strategy source carries a forbidden YAML tag",
    "STRATEGY.YAML_DUPLICATE_KEY": "strategy source repeats a mapping key",
    "STRATEGY.YAML_MERGE_KEY_FORBIDDEN": "strategy source uses a YAML merge key",
    "STRATEGY.YAML_SCALAR_TOO_LONG": (
        "strategy source scalar exceeds the maximum length"
    ),
    "STRATEGY.YAML_COLLECTION_TOO_LARGE": (
        "strategy source collection exceeds the maximum entry count"
    ),
    "STRATEGY.YAML_DEPTH_EXCEEDED": "strategy source exceeds the maximum nesting depth",
    "STRATEGY.YAML_EVENT_BUDGET_EXCEEDED": (
        "strategy source exceeds the maximum event count"
    ),
    "STRATEGY.YAML_ANCHOR_BUDGET_EXCEEDED": (
        "strategy source exceeds the maximum anchor count"
    ),
    "STRATEGY.YAML_ALIAS_BUDGET_EXCEEDED": (
        "strategy source exceeds the maximum alias count"
    ),
    "STRATEGY.YAML_EXPANSION_EXCEEDED": (
        "strategy source exceeds the maximum expanded node budget"
    ),
    "STRATEGY.YAML_RECURSIVE_ALIAS": (
        "strategy source uses a recursive or unknown alias"
    ),
    "STRATEGY.YAML_NONCANONICAL_SCALAR": (
        "strategy source carries a non-canonical scalar form"
    ),
    "STRATEGY.YAML_ANCHOR_REDEFINED": "strategy source redefines an anchor name",
    "STRATEGY.YAML_MAPPING_KEY_INVALID": "strategy source mapping key is not a string",
    "STRATEGY.YAML_INTEGER_OUT_OF_RANGE": (
        "strategy source integer is outside the signed 64-bit range"
    ),
    "STRATEGY.YAML_DIRECTIVE_FORBIDDEN": "strategy source carries a YAML directive",
}


def _reject_path_shaped(value: str) -> str:
    if _SOURCE_NAME_RE.fullmatch(value) is None:
        raise ValueError("source name must be a bounded non-path label")
    return value


# The pattern is not in ``StringConstraints`` because Pydantic compiles that
# with ``rust-regex``, which has no look-around and rejects the negative
# look-ahead outright.
SourceName = Annotated[
    str,
    StringConstraints(strict=True, min_length=1, max_length=128),
    AfterValidator(_reject_path_shaped),
    WithJsonSchema(
        exact_string_schema(_SOURCE_NAME_PATTERN, min_length=1, max_length=128)
    ),
]

type YamlValue = str | int | bool | dict[str, "YamlValue"] | list["YamlValue"]

_SOURCE_NAME_ADAPTER: Final = TypeAdapter(SourceName)


class StrictStrategySafeLoader(yaml.SafeLoader):
    """A ``SafeLoader`` subclass with a deliberately empty body.

    The Constructor is never invoked, so no constructor is required. Nothing
    here may register a constructor or resolver: an unqualified
    ``StrictStrategySafeLoader.yaml_constructors[t] = f`` would mutate the
    inherited ``yaml.SafeLoader`` dict.
    """


class YamlDocument(CanonicalModel):
    """One bounded plain value decoded from a single YAML document."""

    source_name: SourceName
    value: YamlValue


HANDLED_EVENT_CLASSES: Final = frozenset(
    {
        yaml.StreamStartEvent,
        yaml.StreamEndEvent,
        yaml.DocumentStartEvent,
        yaml.DocumentEndEvent,
        yaml.AliasEvent,
        yaml.ScalarEvent,
        yaml.SequenceStartEvent,
        yaml.SequenceEndEvent,
        yaml.MappingStartEvent,
        yaml.MappingEndEvent,
    }
)


def _classify_integer_text(text: str) -> tuple[int | None, str | None]:
    """Bound an integer by value before ``int()`` sees a huge literal."""
    if len(text.lstrip("-")) > _MAX_INTEGER_DIGITS:
        return None, "STRATEGY.YAML_INTEGER_OUT_OF_RANGE"
    value = int(text)
    if not MIN_INTEGER_VALUE <= value <= MAX_INTEGER_VALUE:
        return None, "STRATEGY.YAML_INTEGER_OUT_OF_RANGE"
    return value, None


def classify_scalar_event(
    event: yaml.ScalarEvent,
) -> tuple[str | int | bool | None, str | None]:
    """Classify one scalar event without consulting PyYAML's resolver.

    A ``yaml.parse`` event carries no resolved implicit tag, so ``event.tag``
    decides only whether a tag was written, never what an untagged scalar means.
    """
    text = event.value
    if not isinstance(text, str):  # pragma: no cover - PyYAML always yields str
        return None, "STRATEGY.YAML_NONCANONICAL_SCALAR"
    if len(text) > MAX_SCALAR_CHARACTERS:
        return None, "STRATEGY.YAML_SCALAR_TOO_LONG"

    if event.tag is not None:
        if event.tag == _STR_TAG:
            return text, None
        if event.tag == _INT_TAG:
            if _CANONICAL_INTEGER.fullmatch(text) is None:
                return None, "STRATEGY.YAML_NONCANONICAL_SCALAR"
            return _classify_integer_text(text)
        if event.tag == _BOOL_TAG:
            if text not in ("true", "false"):
                return None, "STRATEGY.YAML_NONCANONICAL_SCALAR"
            return text == "true", None
        return None, "STRATEGY.YAML_FORBIDDEN_TAG"

    style = event.style
    non_plain = style in _NON_PLAIN_STYLES
    implicit = event.implicit
    if non_plain:
        if implicit != (False, True):
            return None, "STRATEGY.YAML_NONCANONICAL_SCALAR"
        return text, None
    if not implicit[0]:
        return None, "STRATEGY.YAML_NONCANONICAL_SCALAR"

    # Rules 3 and 4 are evaluated first and win, so a canonical integer is
    # never consulted against the deliberately overlapping rejection table.
    if text in ("true", "false"):
        return text == "true", None
    if _CANONICAL_INTEGER.fullmatch(text) is not None:
        return _classify_integer_text(text)
    for pattern in _REJECTED_PLAIN_SCALARS:
        if pattern.fullmatch(text) is not None:
            return None, "STRATEGY.YAML_NONCANONICAL_SCALAR"
    return text, None


def _classify_collection_tag(
    event: yaml.CollectionStartEvent,
    expected: str,
) -> str | None:
    tag = event.tag
    if tag is None or tag == expected:
        return None
    return "STRATEGY.YAML_FORBIDDEN_TAG"


def _value_depth(value: object) -> int:
    if isinstance(value, dict):
        return 1 + max((_value_depth(item) for item in value.values()), default=0)
    if isinstance(value, list):
        return 1 + max((_value_depth(item) for item in value), default=0)
    return 1


class _Frame:
    """One open anchor's transitive expansion cost."""

    __slots__ = ("cost", "name")

    def __init__(self, name: str) -> None:
        self.name = name
        self.cost = 0


class _Container:
    __slots__ = ("anchor", "entries", "is_map", "keys", "pending_key", "value")

    def __init__(self, *, is_map: bool, anchor: str | None) -> None:
        self.is_map = is_map
        self.anchor = anchor
        self.value: dict[str, YamlValue] | list[YamlValue] = {} if is_map else []
        self.keys: set[str] = set()
        self.pending_key: str | None = None
        self.entries = 0


class _Budget:
    """Every ceiling that is counted rather than structural."""

    __slots__ = (
        "alias_references",
        "anchor_definitions",
        "anchor_values",
        "defined_anchors",
        "events",
        "expanded",
        "expanded_size",
        "open_frames",
    )

    def __init__(self) -> None:
        self.events = 0
        self.expanded = 0
        self.alias_references = 0
        self.anchor_definitions = 0
        self.defined_anchors: set[str] = set()
        self.expanded_size: dict[str, int] = {}
        self.anchor_values: dict[str, object] = {}
        self.open_frames: list[_Frame] = []

    def charge(self, cost: int) -> str | None:
        self.expanded += cost
        for frame in self.open_frames:
            frame.cost += cost
        if self.expanded > MAX_EXPANDED_NODES:
            return "STRATEGY.YAML_EXPANSION_EXCEEDED"
        return None


class _Rejected(Exception):
    """Internal control flow carrying one closed error code and a mark."""

    def __init__(
        self,
        code: str,
        event: yaml.Event | None = None,
        extra: dict[str, DiagnosticDetailValue] | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.event = event
        self.extra: dict[str, DiagnosticDetailValue] = extra or {}


def _mark_details(event: yaml.Event | None) -> dict[str, DiagnosticDetailValue]:
    """Return only the integer line and column, never a snippet or buffer."""
    if event is None or event.start_mark is None:
        return {}
    return {
        "line": int(event.start_mark.line) + 1,
        "column": int(event.start_mark.column) + 1,
    }


def _diagnostic(
    code: str,
    observed_at_utc: datetime,
    details: dict[str, DiagnosticDetailValue],
) -> Diagnostic:
    category = (
        DiagnosticCategory.SECURITY
        if code in _SECURITY_CODES
        else DiagnosticCategory.SCHEMA_VALIDATION
    )
    message = _MESSAGES[code]
    payload: dict[str, JsonValue] = {
        "schema_version": "1.0.0",
        "error_code": code,
        "category": category.value,
        "severity": DiagnosticSeverity.ERROR.value,
        "source_component": _SOURCE_COMPONENT,
        "message": message,
        "retriable": False,
        "details": cast(JsonValue, details),
    }
    identity = _uuid4_shaped(
        profile_hash(HashingProfile.DIAGNOSTIC_IDENTITY_V1, payload),
    )
    return Diagnostic(
        schema_version="1.0.0",
        diagnostic_id=f"diag_{identity}",
        severity=DiagnosticSeverity.ERROR,
        error_code=code,
        category=category,
        message=message,
        source_component=_SOURCE_COMPONENT,
        retriable=False,
        timestamp_utc=observed_at_utc,
        details=details,
        causal_diagnostic_ids=(),
    )


def _failure(
    code: str,
    observed_at_utc: datetime,
    details: dict[str, DiagnosticDetailValue] | None = None,
) -> Failure:
    return Failure(
        outcome="FAILURE",
        diagnostics=(_diagnostic(code, observed_at_utc, details or {}),),
    )


def _open_anchor(budget: _Budget, anchor: str | None) -> None:
    if anchor is None:
        return
    # Definitions, not distinct names, and the membership test is the set of
    # every name seen so far rather than the completed-anchor store: a name
    # whose own node is still open has no recorded expanded size yet, so
    # ``expanded_size`` alone cannot see a nested redefinition.
    if anchor in budget.defined_anchors:
        raise _Rejected("STRATEGY.YAML_ANCHOR_REDEFINED")
    budget.defined_anchors.add(anchor)
    budget.anchor_definitions += 1
    if budget.anchor_definitions > MAX_ANCHORS:
        raise _Rejected("STRATEGY.YAML_ANCHOR_BUDGET_EXCEEDED")


def _charge(budget: _Budget, cost: int, event: yaml.Event) -> None:
    code = budget.charge(cost)
    if code is not None:
        raise _Rejected(code, event)


def _place(
    stack: list[_Container],
    value: YamlValue,
    event: yaml.Event,
) -> None:
    """Attach one completed value to its parent container."""
    container = stack[-1]
    target = container.value
    if isinstance(target, dict):
        key = container.pending_key
        if key is None:  # pragma: no cover - a key always precedes its value
            raise _Rejected("STRATEGY.YAML_MAPPING_KEY_INVALID", event)
        target[key] = value
        container.pending_key = None
        return
    container.entries += 1
    if container.entries > MAX_COLLECTION_ENTRIES:
        raise _Rejected("STRATEGY.YAML_COLLECTION_TOO_LARGE", event)
    target.append(value)


def _accept_key(container: _Container, event: yaml.ScalarEvent) -> None:
    """Apply the mapping-key contract in its exact precedence order."""
    text = event.value
    if isinstance(text, str) and len(text) > MAX_SCALAR_CHARACTERS:
        raise _Rejected("STRATEGY.YAML_SCALAR_TOO_LONG", event)
    if event.tag is not None and event.tag not in (_STR_TAG, _INT_TAG, _BOOL_TAG):
        raise _Rejected("STRATEGY.YAML_FORBIDDEN_TAG", event)
    classified, code = classify_scalar_event(event)
    if code is not None or classified is None:
        raise _Rejected(code or "STRATEGY.YAML_NONCANONICAL_SCALAR", event)
    if classified == "<<":
        raise _Rejected("STRATEGY.YAML_MERGE_KEY_FORBIDDEN", event)
    if not isinstance(classified, str):
        raise _Rejected("STRATEGY.YAML_MAPPING_KEY_INVALID", event)
    if classified in container.keys:
        # Section 5.2 item 9 authorises the key alongside the integer line and
        # column, so a duplicate is actionable without a snippet. The key is
        # clamped to ``MAX_DETAIL_STRING`` because it is the one channel by which
        # a document byte reaches a ``Diagnostic``: a scalar may be
        # ``MAX_SCALAR_CHARACTERS`` long, four times the detail-string ceiling,
        # and an unclamped value raises ``ValidationError`` out of ``Diagnostic``
        # construction — escaping the ``Result``-only contract of sections 5.2
        # and 5.3.2. Reachable only through the explicit ``?`` key indicator,
        # since PyYAML caps a simple key at 1024 characters.
        raise _Rejected(
            "STRATEGY.YAML_DUPLICATE_KEY",
            event,
            {"key": classified[:MAX_DETAIL_STRING]},
        )
    container.entries += 1
    if container.entries > MAX_COLLECTION_ENTRIES:
        raise _Rejected("STRATEGY.YAML_COLLECTION_TOO_LARGE", event)
    container.keys.add(classified)
    container.pending_key = classified


def _close_container(budget: _Budget, container: _Container) -> None:
    if container.anchor is None:
        return
    frame = budget.open_frames.pop()
    # Section 5.3.1 requires this check, and it is unreachable by construction:
    # ``charge`` adds every cost to ``expanded`` as well as to each open frame,
    # and ``expanded`` never decreases, so ``frame.cost <= expanded`` always
    # holds and ``charge`` raises first. Kept as the reviewed bound it is.
    if frame.cost > MAX_EXPANDED_NODES:  # pragma: no cover - charge raises first
        raise _Rejected("STRATEGY.YAML_EXPANSION_EXCEEDED")
    budget.expanded_size[container.anchor] = frame.cost
    budget.anchor_values[container.anchor] = container.value


def _expand_alias(
    budget: _Budget,
    stack: list[_Container],
    event: yaml.AliasEvent,
) -> YamlValue:
    name = event.anchor
    open_names = {frame.name for frame in budget.open_frames}
    if name not in budget.expanded_size or name in open_names:
        raise _Rejected("STRATEGY.YAML_RECURSIVE_ALIAS", event)
    budget.alias_references += 1
    if budget.alias_references > MAX_ALIAS_REFERENCES:
        raise _Rejected("STRATEGY.YAML_ALIAS_BUDGET_EXCEEDED", event)
    _charge(budget, budget.expanded_size[name], event)
    spliced = cast(YamlValue, copy.deepcopy(budget.anchor_values[name]))
    if len(stack) + _value_depth(spliced) > MAX_EXPANDED_DEPTH:
        raise _Rejected("STRATEGY.YAML_DEPTH_EXCEEDED", event)
    return spliced


def _build_from_events(
    events: Iterator[yaml.Event],
    budget: _Budget,
) -> YamlValue:
    stack: list[_Container] = []
    root: YamlValue | None = None
    started = False
    completed = False

    for event in events:
        if type(event) not in HANDLED_EVENT_CLASSES:
            raise _Rejected("STRATEGY.YAML_SYNTAX", event)
        budget.events += 1
        if budget.events > MAX_EVENT_COUNT:
            raise _Rejected("STRATEGY.YAML_EVENT_BUDGET_EXCEEDED", event)

        if isinstance(event, yaml.StreamStartEvent | yaml.StreamEndEvent):
            continue
        if isinstance(event, yaml.DocumentStartEvent):
            if started:
                raise _Rejected("STRATEGY.YAML_MULTIPLE_DOCUMENTS", event)
            if event.version is not None or event.tags:
                raise _Rejected("STRATEGY.YAML_DIRECTIVE_FORBIDDEN", event)
            started = True
            continue
        if isinstance(event, yaml.DocumentEndEvent):
            completed = True
            continue
        if completed:
            raise _Rejected("STRATEGY.YAML_MULTIPLE_DOCUMENTS", event)

        if isinstance(event, yaml.SequenceEndEvent | yaml.MappingEndEvent):
            container = stack.pop()
            _close_container(budget, container)
            if stack:
                _place(stack, container.value, event)
            else:
                root = container.value
            continue

        in_key_position = bool(
            stack and stack[-1].is_map and stack[-1].pending_key is None
        )

        if isinstance(event, yaml.AliasEvent):
            if in_key_position:
                raise _Rejected("STRATEGY.YAML_MAPPING_KEY_INVALID", event)
            spliced = _expand_alias(budget, stack, event)
            if stack:
                _place(stack, spliced, event)
            else:  # pragma: no cover - a root alias has no preceding anchor
                # PyYAML resets anchors per document and the root node is the
                # first node, so no document root can be an alias.
                root = spliced
            continue

        if isinstance(event, yaml.ScalarEvent):
            if in_key_position:
                _accept_key(stack[-1], event)
                _charge(budget, 1, event)
                _open_anchor(budget, event.anchor)
                if event.anchor is not None:
                    budget.expanded_size[event.anchor] = 1
                    budget.anchor_values[event.anchor] = event.value
                continue
            classified, code = classify_scalar_event(event)
            if code is not None or classified is None:
                raise _Rejected(code or "STRATEGY.YAML_NONCANONICAL_SCALAR", event)
            _charge(budget, 1, event)
            _open_anchor(budget, event.anchor)
            if event.anchor is not None:
                budget.expanded_size[event.anchor] = 1
                budget.anchor_values[event.anchor] = classified
            if stack:
                _place(stack, classified, event)
            else:
                root = classified
            continue

        # A sequence or mapping start.
        if not isinstance(event, yaml.CollectionStartEvent):  # pragma: no cover
            raise _Rejected("STRATEGY.YAML_SYNTAX", event)
        is_map = isinstance(event, yaml.MappingStartEvent)
        if in_key_position:
            raise _Rejected("STRATEGY.YAML_MAPPING_KEY_INVALID", event)
        tag_code = _classify_collection_tag(event, _MAP_TAG if is_map else _SEQ_TAG)
        if tag_code is not None:
            raise _Rejected(tag_code, event)
        _open_anchor(budget, event.anchor)
        if event.anchor is not None:
            budget.open_frames.append(_Frame(event.anchor))
        _charge(budget, 1, event)
        stack.append(_Container(is_map=is_map, anchor=event.anchor))
        if len(stack) > MAX_EVENT_DEPTH or len(stack) > MAX_EXPANDED_DEPTH:
            raise _Rejected("STRATEGY.YAML_DEPTH_EXCEEDED", event)

    if not started or root is None:
        raise _Rejected("STRATEGY.YAML_EMPTY_DOCUMENT")
    return root


def load_yaml_document(
    source: bytes,
    source_name: SourceName,
    observed_at_utc: datetime,
) -> Result[YamlDocument]:
    """Decode one YAML document into a bounded plain value.

    Bytes only. A rejected ``source_name`` is exactly the path this guards
    against, so its diagnostic echoes no part of the offending value.
    """
    try:
        _SOURCE_NAME_ADAPTER.validate_python(source_name)
    except ValueError:
        return _failure("STRATEGY.SOURCE_NAME_INVALID", observed_at_utc)

    if type(source) is not bytes:
        return _failure("STRATEGY.SOURCE_NOT_IN_MEMORY", observed_at_utc)
    if len(source) > MAX_SOURCE_BYTES:
        return _failure("STRATEGY.SOURCE_TOO_LARGE", observed_at_utc)
    for bom in _BOMS:
        if source.startswith(bom):
            return _failure("STRATEGY.SOURCE_BOM_PRESENT", observed_at_utc)
    try:
        text = source.decode("utf-8")
    except UnicodeDecodeError:
        return _failure("STRATEGY.SOURCE_NOT_UTF8", observed_at_utc)

    budget = _Budget()
    events = yaml.parse(text, Loader=StrictStrategySafeLoader)
    try:
        with contextlib.closing(events):
            value = _build_from_events(iter(events), budget)
    except _Rejected as rejected:
        details: dict[str, DiagnosticDetailValue] = dict(_mark_details(rejected.event))
        details.update(rejected.extra)
        return _failure(rejected.code, observed_at_utc, details)
    except yaml.YAMLError:
        # Never let the exception text, snippet, buffer, problem, context, or
        # note reach a diagnostic: each embeds document characters verbatim.
        return _failure("STRATEGY.YAML_SYNTAX", observed_at_utc)

    return Success[YamlDocument](
        outcome="SUCCESS",
        value=YamlDocument(source_name=source_name, value=value),
    )
