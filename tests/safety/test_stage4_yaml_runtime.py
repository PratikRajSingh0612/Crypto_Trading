"""Stage 4 YAML runtime guards.

This module imports ``yaml`` deliberately and is the only safety module that
may. Keeping it separate from ``tests/safety/test_stage4_boundaries.py`` means
the source-level guards there stay collectable before PyYAML is installed.
"""

from __future__ import annotations

import yaml

# Thirteen entries: the twelve ``tag:yaml.org,2002:`` tags plus the ``None``
# key that ``SafeConstructor.add_constructor(None,
# SafeConstructor.construct_undefined)`` registers. Omitting ``None`` produces
# a failure that reads like a supply-chain alarm rather than a test bug.
_EXPECTED_SAFELOADER_TAGS = frozenset(
    {
        None,
        "tag:yaml.org,2002:null",
        "tag:yaml.org,2002:bool",
        "tag:yaml.org,2002:int",
        "tag:yaml.org,2002:float",
        "tag:yaml.org,2002:binary",
        "tag:yaml.org,2002:timestamp",
        "tag:yaml.org,2002:omap",
        "tag:yaml.org,2002:pairs",
        "tag:yaml.org,2002:set",
        "tag:yaml.org,2002:str",
        "tag:yaml.org,2002:seq",
        "tag:yaml.org,2002:map",
    }
)


def test_safeloader_constructor_tags_are_exactly_expected() -> None:
    """Catch a third-party ``yaml.YAMLObject`` or constructor registration.

    The assertion is absolute rather than a before/after comparison, because a
    comparison is structurally incapable of detecting a class-body or
    import-time mutation that already ran.
    """
    assert frozenset(yaml.SafeLoader.yaml_constructors) == _EXPECTED_SAFELOADER_TAGS
