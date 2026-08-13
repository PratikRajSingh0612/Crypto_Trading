from __future__ import annotations

import pytest
from pydantic import TypeAdapter, ValidationError

from crypto_lab.adapters.versioning import highest_common_stable_version
from crypto_lab.domain.versioning import SemanticVersion, parse_semantic_version


@pytest.mark.parametrize("value", ["0.0.0", "1.2.3", "10.20.300"])
def test_semantic_version_accepts_canonical_stable_values(value: str) -> None:
    assert TypeAdapter(SemanticVersion).validate_python(value) == value
    assert parse_semantic_version(value) == tuple(
        int(component) for component in value.split(".")
    )


@pytest.mark.parametrize(
    "value",
    [
        "latest",
        "v1.2.3",
        "1.2",
        "1.2.3.4",
        "1.2.3-alpha",
        "1.2.3+build",
        "01.2.3",
        "1.02.3",
        "1.2.03",
        " 1.2.3",
        "1.2.3 ",
    ],
)
def test_semantic_version_rejects_noncanonical_values(value: str) -> None:
    with pytest.raises(ValidationError):
        TypeAdapter(SemanticVersion).validate_python(value)


def test_highest_common_version_is_numeric_set_intersection() -> None:
    core: tuple[SemanticVersion, ...] = ("1.9.0", "1.10.0", "2.0.0")
    adapter: tuple[SemanticVersion, ...] = ("1.10.0", "1.9.0", "3.0.0")
    original_core = core
    original_adapter = adapter
    assert highest_common_stable_version(core, adapter) == "1.10.0"
    assert core == original_core
    assert adapter == original_adapter
    assert highest_common_stable_version(("1.0.0",), ("2.0.0",)) is None


@pytest.mark.parametrize(
    ("core", "adapter"),
    [
        (("1.0.0", "1.0.0"), ("1.0.0",)),
        (("1.0.0",), ("1.0.0", "1.0.0")),
    ],
)
def test_highest_common_version_rejects_duplicates(
    core: tuple[SemanticVersion, ...],
    adapter: tuple[SemanticVersion, ...],
) -> None:
    with pytest.raises(ValueError, match="must be unique"):
        highest_common_stable_version(core, adapter)


@pytest.mark.parametrize(
    ("core", "adapter"),
    [
        (("1.0.0", "not-a-version"), ("1.0.0",)),
        (("1.0.0",), ("1.0.0", "not-a-version")),
        (("not-a-version",), ("2.0.0",)),
    ],
)
def test_highest_common_version_validates_every_input_before_intersection(
    core: tuple[str, ...],
    adapter: tuple[str, ...],
) -> None:
    with pytest.raises(ValueError, match="stable canonical"):
        highest_common_stable_version(core, adapter)
