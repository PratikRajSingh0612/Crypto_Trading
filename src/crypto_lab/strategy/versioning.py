"""Strategy content identity: the hashed payload, provenance, and the record.

Plan section 5.5 fixes the hashed payload exactly, and this module is the only
place that builds it. Identity flows through ``HashingProfile.STRATEGY_VERSION_V1``
and ``profile_hash`` alone: there is no ad-hoc SHA-256 construction here, no
``hash()``, and no raw YAML text.

**What is material.** The canonical validated ``StrategySpec`` in full, the
strategy schema version, the expression-semantics version, the hashing-profile
version, and every declared extension-module content hash.

**What is not.** ``source_name``, the source bytes and their digest, the source
byte length, ``observed_at_utc``, ``created_at_utc``, ``strategy_version_id``, and
the whole ``StrategySourceProvenance`` record. Comments, harmless whitespace,
mapping key order, flow-versus-block style, and equivalent quoting cannot reach the
payload either, because the payload is built from the validated model rather than
from the document text.

``content_hash`` is deliberately absent from its own payload, so no self-hash field
exists.
"""

from __future__ import annotations

from typing import Annotated, Final, Literal, Self, cast

from pydantic import Field, JsonValue, model_validator

from crypto_lab.domain.base import CanonicalModel
from crypto_lab.domain.hashing import (
    HashingProfile,
    _uuid4_shaped,
    profile_hash,
)
from crypto_lab.domain.identifiers import Sha256, StrategyId, StrategyVersionId
from crypto_lab.domain.time import UtcDateTime
from crypto_lab.strategy.expressions import EXPRESSION_SEMANTICS_VERSION
from crypto_lab.strategy.models import (
    MAX_ENGINE_EXTENSIONS,
    EngineExtensionDeclaration,
    StrategySpec,
    _extension_key,
)
from crypto_lab.strategy.yaml_source import MAX_SOURCE_BYTES, SourceName

# Written as a literal rather than as ``HashingProfile.STRATEGY_VERSION_V1.value``
# so that ``Final`` gives it a literal type and it can satisfy the record's
# ``Literal["strategy-version/v1"]`` field. A ``StrEnum`` member's ``.value`` is
# typed plain ``str``, which strict mypy rejects there.
# ``test_the_declared_profile_version_matches_the_hashing_profile`` pins the two
# together, so the duplication cannot drift.
STRATEGY_VERSION_PROFILE_VERSION: Final = "strategy-version/v1"


def sorted_extension_hashes(
    declarations: tuple[EngineExtensionDeclaration, ...],
) -> list[Sha256]:
    """Return every declared extension content hash in canonical order.

    Plan section 5.5 item 5 fixes the order as ``(adapter_name, extension_id,
    version)``, with ``version`` compared numerically through Task 2's
    ``_extension_key`` rather than lexicographically. Reusing that exact key is
    required rather than tidy: ``"1.10.0" < "1.9.0"`` as text, so an independently
    written comparison here could disagree with the model's own normalization and
    the disagreement would be baked into a permanent ``content_hash``.

    A validated ``StrategySpec.engine_extensions`` is already in this order, so this
    is idempotent there. It sorts anyway, so the payload's order-independence is a
    property of this function and not an inherited assumption, and so that a caller
    holding declarations from any other source gets the same canonical sequence.

    Because the model already normalizes, the only test that can observe this sort
    at all is ``test_sorted_extension_hashes_normalizes_an_unsorted_input_sequence``,
    which calls it with a reversed tuple. The hash-level reordering test cannot: it
    goes through the model, which orders the declarations before this is reached.

    A ``list`` rather than a ``tuple``: ``profile_hash`` types its payload
    ``dict[str, JsonValue]`` and ``CanonicalHashEnvelope`` is ``strict=True``, which
    rejects a tuple outright.
    """
    return [item.content_hash for item in sorted(declarations, key=_extension_key)]


def strategy_version_payload(spec: StrategySpec) -> dict[str, JsonValue]:
    """Build exactly the five-key identity payload of plan section 5.5.

    Following the Stage 3 convention in ``datasets/hashing.py``, the specification
    enters as ``model_dump(mode="json")`` behind an explicit ``cast``. There are no
    exclusions: ``StrategySpec`` holds no self-hash field, so every one of its
    twenty-one fields is material.
    """
    return {
        "strategy_spec": cast("JsonValue", spec.model_dump(mode="json")),
        "strategy_schema_version": spec.schema_version,
        "expression_semantics_version": EXPRESSION_SEMANTICS_VERSION,
        "hashing_profile_version": STRATEGY_VERSION_PROFILE_VERSION,
        "extension_hashes": cast(
            "JsonValue",
            sorted_extension_hashes(spec.engine_extensions),
        ),
    }


def strategy_version_hash(spec: StrategySpec) -> Sha256:
    """Hash one validated specification's material content identity."""
    return profile_hash(
        HashingProfile.STRATEGY_VERSION_V1,
        strategy_version_payload(spec),
    )


def strategy_version_identifier(content_hash: Sha256) -> StrategyVersionId:
    """Derive a version ID from content identity, never from a random source.

    ``uuid.uuid4`` and every wall-clock source are forbidden, and a caller-supplied
    ID would make two independent loads of equal bytes produce unequal records. The
    digest is reshaped by the same ``_uuid4_shaped`` helper the deterministic
    diagnostic identity of plan section 5.3.3 uses.

    This is a one-way derivation and is deliberately **not** enforced as a record
    invariant: ``strategy_version_id`` is non-material, so a record carrying a
    different ID must remain constructible in order to be provably non-material.
    """
    return f"strv_{_uuid4_shaped(content_hash)}"


class StrategySourceProvenance(CanonicalModel):
    """Audit-only facts about the bytes a version was decoded from.

    Explicitly outside the identity payload, per plan section 5.5. ``source_name``
    is a bounded label and never a filesystem path, because specification section
    24.3 forbids a local path or username reaching a diagnostic or an audit record.
    """

    source_name: SourceName
    source_bytes_sha256: Sha256
    source_byte_length: Annotated[int, Field(strict=True, ge=0, le=MAX_SOURCE_BYTES)]
    observed_at_utc: UtcDateTime


class StrategyVersion(CanonicalModel):
    """Immutable content identity for one validated strategy.

    Specification section 11.3's eight minimum fields in that order, followed by the
    one documented addition ``source_provenance``, which section 5.5 requires be
    retained and kept outside the hash. Field order does not affect identity:
    ``canonical_json_text`` sorts keys, and the payload embeds the specification
    dump rather than this record.
    """

    schema_version: Literal["1.0.0"]
    strategy_version_id: StrategyVersionId
    strategy_id: StrategyId
    content_hash: Sha256
    strategy_spec: StrategySpec
    extension_hashes: tuple[Sha256, ...] = Field(max_length=MAX_ENGINE_EXTENSIONS)
    hashing_profile_version: Literal["strategy-version/v1"]
    created_at_utc: UtcDateTime
    source_provenance: StrategySourceProvenance

    @model_validator(mode="after")
    def validate_identity_is_recomputed(self) -> Self:
        """Recompute identity from canonical content, per specification line 555.

        Its row states that the hash is recomputed from canonical content and that
        extension declarations and hashes must match exactly. Enforcing that here
        rather than only in the loader means no caller — including a later stage
        rehydrating a persisted record — can assemble a version whose recorded
        identity disagrees with its own specification.
        """
        if self.strategy_id != self.strategy_spec.strategy_id:
            raise ValueError("strategy_id must equal the specification's strategy_id")
        expected = tuple(sorted_extension_hashes(self.strategy_spec.engine_extensions))
        if self.extension_hashes != expected:
            raise ValueError(
                "extension_hashes must equal the declared extension content hashes"
            )
        if self.content_hash != strategy_version_hash(self.strategy_spec):
            raise ValueError("content_hash must equal the recomputed strategy identity")
        return self
