"""Stage 9 Task 6, plan 7.3: the finalization identities are disjoint between
purposes and stable under replay (requirement rows R17.2-01, R17.2-02,
R29.6-01, T28.4-02, T28.1-05).

Hypothesis draws the purpose-specific tuples of specification 17.2 -- the
identifiers, the hashes, the correlation -- and proves that ``finalization_identity``
answers the same digest for the same inputs, a different digest for a changed
field, and never a digest a RESULT and an EVIDENCE tuple share even when every
shared-shaped value coincides; ``finalization_id_for`` is a pure function of the
identity. The replay property drives the memory unit of work through two equal
EVIDENCE finalizations and proves the second answers the stored result with
``replayed=True`` and writes nothing but its replay audit row. ``deadline=None``
per the repository convention.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from hypothesis import given, settings
from hypothesis import strategies as st

from crypto_lab.artifacts.models import FinalizationResult
from crypto_lab.domain.hashing import (
    candidate_set_hash_for,
    finalization_id_for,
    finalization_identity,
)
from crypto_lab.domain.lifecycle import CommandInvocationState, EngineRunState
from crypto_lab.domain.results import Success
from doubles.artifacts import (
    MemoryFinalizationHarness,
    sample_evidence_request,
    sample_result_request,
)
from doubles.experiments import sample_invocation, sample_run

_C = CommandInvocationState
_R = EngineRunState

_HEX = "0123456789abcdef"
_KINDS = ("INVOCATION", "DIAGNOSTIC", "AUDIT")
_PREFIXES = {"INVOCATION": "inv_", "DIAGNOSTIC": "diag_", "AUDIT": "audit_"}


def _uuid4_text(draw: st.DrawFn) -> str:
    bits = draw(st.integers(min_value=0, max_value=2**128 - 1))
    return str(uuid.UUID(int=bits, version=4))


hashes = st.text(alphabet=_HEX, min_size=64, max_size=64)


@st.composite
def result_tuples(draw: st.DrawFn) -> dict[str, str]:
    return {
        "run_id": f"run_{_uuid4_text(draw)}",
        "run_invocation_id": f"inv_{_uuid4_text(draw)}",
        "attempt_token_hash": draw(hashes),
        "source_adapter_result_manifest_hash": draw(hashes),
        "sanitized_adapter_result_manifest_hash": draw(hashes),
    }


@st.composite
def evidence_tuples(draw: st.DrawFn) -> dict[str, str]:
    kind = draw(st.sampled_from(_KINDS))
    return {
        "owner_hash": draw(hashes),
        "correlation_kind": kind,
        "correlation_id": f"{_PREFIXES[kind]}{_uuid4_text(draw)}",
        "candidate_set_hash": draw(hashes),
    }


@settings(deadline=None, max_examples=60)
@given(result=result_tuples(), evidence=evidence_tuples())
def test_identities_disjoint_and_replay_stable(
    result: dict[str, str], evidence: dict[str, str]
) -> None:
    result_identity = finalization_identity("RESULT", **result)
    evidence_identity = finalization_identity("EVIDENCE", **evidence)
    # Same inputs, same identity and the same derived ``fin_`` id.
    assert finalization_identity("RESULT", **result) == result_identity
    assert finalization_identity("EVIDENCE", **evidence) == evidence_identity
    assert finalization_id_for(result_identity) == finalization_id_for(result_identity)
    # The purposes never share an identity, even over coinciding hash values.
    assert result_identity != evidence_identity
    shared = dict(evidence)
    shared["owner_hash"] = result["attempt_token_hash"]
    shared["candidate_set_hash"] = result["source_adapter_result_manifest_hash"]
    assert finalization_identity("EVIDENCE", **shared) != result_identity
    # Any changed field changes the identity.
    for name, value in result.items():
        changed = dict(result)
        changed[name] = value[:-1] + ("0" if value[-1] != "0" else "1")
        if name.endswith("_id"):
            changed[name] = value[:-1] + ("a" if value[-1] != "a" else "b")
        assert finalization_identity("RESULT", **changed) != result_identity
    for name, value in evidence.items():
        if name == "correlation_kind":
            continue
        changed_evidence = dict(evidence)
        changed_evidence[name] = value[:-1] + ("a" if value[-1] != "a" else "b")
        moved = finalization_identity("EVIDENCE", **changed_evidence)
        assert moved != evidence_identity


def test_requests_derive_disjoint_keys_from_the_same_candidate_set() -> None:
    run = sample_run(_R.RUNNING)
    invocation = sample_invocation(_C.EXITED)
    ids = ("cand_12345678-1234-4234-8234-123456789abc",)
    result = sample_result_request(ids, run=run, invocation=invocation)
    evidence = sample_evidence_request(ids)
    assert result.candidate_set_hash == evidence.candidate_set_hash
    assert result.candidate_set_hash == candidate_set_hash_for(ids)
    assert result.idempotency_key != evidence.idempotency_key
    assert finalization_id_for(result.idempotency_key) != finalization_id_for(
        evidence.idempotency_key
    )


def test_memory_double_replay_returns_the_same_result(tmp_path: Path) -> None:
    harness = MemoryFinalizationHarness(tmp_path)
    plan = harness.plant_evidence_prestate()
    first = harness.finalize(plan.request)
    assert isinstance(first, Success)
    before = harness.durable()
    for _ in range(3):
        again = harness.finalize(plan.request)
        assert isinstance(again, Success)
        assert isinstance(again.value, FinalizationResult)
        assert again.value.replayed is True
        assert again.value.model_copy(update={"replayed": False}) == first.value
    after = harness.durable()
    assert after.journal == before.journal
    assert after.refs == before.refs
    assert after.candidates == before.candidates
    assert after.object_blobs == before.object_blobs
    assert after.audit_actions == (
        *before.audit_actions,
        *(("FINALIZATION_REPLAYED",) * 3),
    )
