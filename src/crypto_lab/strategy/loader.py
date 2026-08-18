"""The `StrategyLoader` facade: strategy bytes into one validated version.

This module composes the committed boundaries and adds no validation of its own
beyond the strict-model stage. Its whole contribution is *ordering* and *failing
closed*.

**Stage order, and why it is exactly this.**

1. ``load_yaml_document`` — validates ``source_name`` before touching ``source``,
   accepts bytes only, and applies every section 5.2 and 5.3 safety bound. Nothing
   later can run on a document this stage rejected.
2. ``StrategySpec.model_validate_json`` over ``canonical_json_bytes`` of the decoded
   plain value — the committed Task 2 idiom. ``CanonicalModel`` is ``strict=True``,
   so python-mode validation of a plain mapping would reject a string where an enum
   belongs; JSON is also a YAML subset, so this re-encoding cannot admit a value the
   YAML stage did not already accept.
3. ``validate_feature_graph`` — a **single** call, not two. Task 4's entry point
   already invokes Task 3's ``validate_strategy_expressions`` and combines both
   diagnostic sets through ``bounded_failure``, per plan section 5.4.1. Calling Task
   3 separately as well would double-count every expression diagnostic and make the
   returned set a function of this facade rather than of the document.

Only after all three stages succeed is a ``StrategyVersion`` constructed. There is
no path on which a namespace-invalid, type-invalid, cyclic, or policy-invalid
strategy yields a successful result.

**What this module never does.** Read a clock, the filesystem, the network, the
environment, process state, machine identity, or a random source; import or execute
an extension module; resolve an adapter executable; scan a directory; accept a path
or a file object; or expose a convenience path-loading method. ``observed_at_utc``
is explicit, and ``strategy_version_id`` is derived from content identity, so two
independent loads of equal bytes produce equal records.

**Expected failures return through ``Result``.** A ``ValidationError`` from the
model stage is converted to diagnostics; it never escapes.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from datetime import datetime
from typing import Final, cast

from pydantic import JsonValue, ValidationError

from crypto_lab.domain.canonical_json import canonical_json_bytes
from crypto_lab.domain.diagnostics import (
    Diagnostic,
    DiagnosticCategory,
    DiagnosticDetailValue,
    DiagnosticSeverity,
)
from crypto_lab.domain.hashing import (
    HashingProfile,
    _uuid4_shaped,
    profile_hash,
    sha256_bytes,
)
from crypto_lab.domain.results import Failure, Result, Success
from crypto_lab.strategy.feature_graph import bounded_failure, validate_feature_graph
from crypto_lab.strategy.models import StrategySpec
from crypto_lab.strategy.versioning import (
    STRATEGY_VERSION_PROFILE_VERSION,
    StrategySourceProvenance,
    StrategyVersion,
    sorted_extension_hashes,
    strategy_version_hash,
    strategy_version_identifier,
)
from crypto_lab.strategy.yaml_source import SourceName, load_yaml_document

SOURCE_COMPONENT: Final = "strategy.loader"

_SCHEMA_INVALID: Final = "STRATEGY.SCHEMA_INVALID"
_UNKNOWN_FIELD: Final = "STRATEGY.UNKNOWN_FIELD"
_EXPRESSION_UNKNOWN_OP: Final = "STRATEGY.EXPRESSION_UNKNOWN_OP"

# The six closed codes Task 2's model validators already write at the head of their
# own ``ValueError`` messages. That prefixing is a deliberate hand-off: the model
# layer cannot return a ``Result``, so it marks the code and this boundary recovers
# it. Recovering rather than collapsing them into ``STRATEGY.SCHEMA_INVALID`` is
# what keeps section 5.9's table meaningful.
_MODEL_DECLARED_CODES: Final = frozenset(
    {
        "STRATEGY.EXPRESSION_DEPTH_EXCEEDED",
        "STRATEGY.EXTENSION_DECLARATION",
        "STRATEGY.PARAMETER_OUT_OF_BOUNDS",
        "STRATEGY.POLICY_FORBIDDEN_DIRECTION",
        "STRATEGY.POLICY_FORBIDDEN_MARKET",
        "STRATEGY.REFERENCE_NEGATIVE_OFFSET",
    }
)
# Matches ``strategy/validation.py``, so one defect carries one category wherever it
# is detected.
_SECURITY_CODES: Final = frozenset({"STRATEGY.EXPRESSION_DEPTH_EXCEEDED"})
# ``op`` is the only discriminator in the whole strategy model closure, so a failed
# tag lookup can only ever be an unknown expression operator.
_UNION_TAG_TYPES: Final = frozenset({"union_tag_invalid", "union_tag_not_found"})
_VALUE_ERROR_PREFIX: Final = "Value error, "
# Pydantic discards an item that fails validation and then reports the shrunken
# collection as well, so a rejected rule inside a ``min_length=1`` tuple yields both
# the real defect and a derived ``too_short``. Only a discard can shrink a
# collection, so a ``too_short`` reported at a location that also has a deeper error
# is always derived from it; ``too_long`` is deliberately absent, because a discard
# can never cause one.
_CASCADE_TYPES: Final = frozenset({"too_short"})

# One fixed project-authored message per code. No message is derived from the
# document, so no document byte can reach a diagnostic through one.
_MESSAGES: Final[Mapping[str, str]] = {
    _SCHEMA_INVALID: "strategy document does not satisfy the strategy schema",
    _UNKNOWN_FIELD: "strategy document carries an unknown field",
    _EXPRESSION_UNKNOWN_OP: "strategy document names an unknown expression operator",
    "STRATEGY.EXPRESSION_DEPTH_EXCEEDED": (
        "strategy expression nesting exceeds the maximum depth"
    ),
    "STRATEGY.EXTENSION_DECLARATION": (
        "engine extension declaration states inconsistent effects"
    ),
    "STRATEGY.PARAMETER_OUT_OF_BOUNDS": (
        "parameter value lies outside its declared bounds"
    ),
    "STRATEGY.POLICY_FORBIDDEN_DIRECTION": "initial policy accepts LONG only",
    "STRATEGY.POLICY_FORBIDDEN_MARKET": "initial policy accepts SPOT only",
    "STRATEGY.REFERENCE_NEGATIVE_OFFSET": "bar offsets must be non-negative",
}


def _declared_code(error: Mapping[str, object]) -> str | None:
    """Recover the closed code a Task 2 validator wrote into its own message.

    The original exception is preferred over ``msg``, which Pydantic prefixes with
    ``"Value error, "``; the prefix is stripped from either path so neither spelling
    can silently stop matching.
    """
    reported = error.get("ctx")
    text: str | None = None
    if isinstance(reported, Mapping):
        cause = reported.get("error")
        if cause is not None:
            text = str(cause)
    if text is None:
        message = error.get("msg")
        text = message if isinstance(message, str) else ""
    head = text.removeprefix(_VALUE_ERROR_PREFIX).split(": ", 1)[0]
    return head if head in _MODEL_DECLARED_CODES else None


def _classify(
    error: Mapping[str, object],
) -> tuple[str, dict[str, DiagnosticDetailValue]]:
    """Map one Pydantic error to a closed code and a leak-free detail payload.

    ``details`` carries at most Pydantic's own error ``type`` — a fixed name such as
    ``extra_forbidden`` or ``missing``. It deliberately carries **no** part of
    ``loc``: a location path includes author-chosen mapping keys such as a parameter
    name or an unknown field's name, and specification section 24.3 forbids document
    or path material reaching a diagnostic. The constraint name alone is enough to
    keep two distinct schema defects from deduplicating into one.
    """
    kind = error.get("type")
    constraint = kind if isinstance(kind, str) else ""
    declared = _declared_code(error)
    if declared is not None:
        # The code is the whole message here, so no constraint name is added and a
        # repeated policy defect deduplicates to one diagnostic.
        return declared, {}
    if constraint in _UNION_TAG_TYPES:
        return _EXPRESSION_UNKNOWN_OP, {"constraint": constraint}
    code = _UNKNOWN_FIELD if constraint == "extra_forbidden" else _SCHEMA_INVALID
    return code, {"constraint": constraint}


def _location(error: Mapping[str, object]) -> tuple[object, ...]:
    reported = error.get("loc")
    return reported if isinstance(reported, tuple) else ()


def _substantive(
    reported: Sequence[Mapping[str, object]],
) -> list[Mapping[str, object]]:
    """Drop every collection-shrink error derived from a deeper rejection.

    ``loc`` is consulted here for **filtering only** and never reaches a diagnostic,
    so no author-chosen mapping key escapes.

    This can never return an empty list. Dropping an error requires a strictly
    deeper error to exist, and the deepest error present has nothing below it, so at
    least one error always survives.
    """
    locations = [_location(error) for error in reported]
    kept: list[Mapping[str, object]] = []
    for error, where in zip(reported, locations, strict=True):
        kind = error.get("type")
        derived = kind in _CASCADE_TYPES and any(
            len(other) > len(where) and other[: len(where)] == where
            for other in locations
        )
        if not derived:
            kept.append(error)
    return kept


def _diagnostic(
    code: str,
    details: dict[str, DiagnosticDetailValue],
    observed_at_utc: datetime,
) -> Diagnostic:
    """Build one diagnostic whose identity is a function of its content alone."""
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
        "source_component": SOURCE_COMPONENT,
        "message": message,
        "retriable": False,
        "details": cast("JsonValue", details),
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
        source_component=SOURCE_COMPONENT,
        retriable=False,
        timestamp_utc=observed_at_utc,
        details=details,
        causal_diagnostic_ids=(),
    )


def _model_failure(invalid: ValidationError, observed_at_utc: datetime) -> Failure:
    """Convert strict-model rejection into deterministic bounded diagnostics.

    ``include_input=False`` means the offending value is never even materialised, and
    ``include_url=False`` keeps a documentation link out of the payload.
    ``include_context=True`` is required: the context is where the original
    ``ValueError`` carrying a closed code lives.

    ``bounded_failure`` is reused rather than reimplemented, so deduplication,
    canonical ordering, and the terminal marker behave identically at every Stage 4
    boundary.
    """
    reported: Sequence[Mapping[str, object]] = invalid.errors(
        include_url=False,
        include_context=True,
        include_input=False,
    )
    diagnostics: list[Diagnostic] = []
    for error in _substantive(reported):
        code, details = _classify(error)
        diagnostics.append(_diagnostic(code, details, observed_at_utc))
    return bounded_failure(diagnostics, observed_at_utc)


class StrategyLoader:
    """Bytes in, one validated ``StrategyVersion`` or diagnostics out.

    Stateless by construction: ``__slots__`` is empty and ``load`` is a
    ``staticmethod``, so there is no configuration, no cached clock, and no
    filesystem root an instance could carry.
    """

    __slots__ = ()

    @staticmethod
    def load(
        source: bytes,
        source_name: SourceName,
        observed_at_utc: datetime,
    ) -> Result[StrategyVersion]:
        """Decode, validate, and identify one strategy document.

        ``source_name`` is the bounded non-path label of plan section 5.2.3, which
        narrows specification section 8.2's ``str`` without changing the parameters,
        ownership, or result semantics of that operation.
        """
        decoded = load_yaml_document(source, source_name, observed_at_utc)
        if isinstance(decoded, Failure):
            return decoded

        try:
            spec = StrategySpec.model_validate_json(
                canonical_json_bytes(decoded.value.value)
            )
        except ValidationError as invalid:
            return _model_failure(invalid, observed_at_utc)

        validated = validate_feature_graph(spec, observed_at_utc)
        if isinstance(validated, Failure):
            return validated

        content_hash = strategy_version_hash(spec)
        return Success[StrategyVersion](
            outcome="SUCCESS",
            value=StrategyVersion(
                schema_version="1.0.0",
                strategy_version_id=strategy_version_identifier(content_hash),
                strategy_id=spec.strategy_id,
                content_hash=content_hash,
                strategy_spec=spec,
                extension_hashes=tuple(sorted_extension_hashes(spec.engine_extensions)),
                hashing_profile_version=STRATEGY_VERSION_PROFILE_VERSION,
                created_at_utc=observed_at_utc,
                source_provenance=StrategySourceProvenance(
                    source_name=source_name,
                    source_bytes_sha256=sha256_bytes(source),
                    source_byte_length=len(source),
                    observed_at_utc=observed_at_utc,
                ),
            ),
        )
