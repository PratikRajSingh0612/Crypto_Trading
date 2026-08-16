"""Stage 4 source-level security guards.

This module must never import ``yaml``. The runtime assertions that need the
real library live in ``tests/safety/test_stage4_yaml_runtime.py``; a
module-level ``import yaml`` here would make the whole file uncollectable until
synchronization installs PyYAML, and the preventive guards below are declared
to begin green.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
from test_stage3_boundaries import _import_aliases, _resolved_qualified_name

# Dangerous only as members of the ``yaml`` module. ``load`` stays
# qualified-only because ``StrategyLoader.load`` is a legitimate Stage 4
# method, and a bare ``load`` would also trip ``tomllib.loads``' neighbours.
_QUALIFIED_YAML_NAMES = frozenset(
    {
        "load",
        "full_load",
        "unsafe_load",
        "safe_load",
        "compose",
        "compose_all",
    }
)
# Cannot collide with legitimate code anywhere under ``src/crypto_lab``. The
# three ``yaml_*`` attributes matter independently of the ``add_*`` methods,
# because assigning into an inherited constructor dict mutates
# ``yaml.SafeLoader``. The final five are the section 5.2 item 14 redaction
# attributes, which must never reach a diagnostic.
_BARE_FORBIDDEN_NAMES = frozenset(
    {
        "full_load",
        "unsafe_load",
        "safe_load",
        "compose",
        "compose_all",
        "Loader",
        "FullLoader",
        "UnsafeLoader",
        "CLoader",
        "CFullLoader",
        "CUnsafeLoader",
        "CSafeLoader",
        "CBaseLoader",
        "CParser",
        "cyaml",
        "_yaml",
        "YAMLObject",
        "add_constructor",
        "add_multi_constructor",
        "add_implicit_resolver",
        "yaml_constructors",
        "yaml_multi_constructors",
        "yaml_implicit_resolvers",
        "get_snippet",
        "buffer",
        "problem",
        "context",
        "note",
    }
)
_IMPORT_FORM_NAMES = _QUALIFIED_YAML_NAMES | _BARE_FORBIDDEN_NAMES
# Matches every spelling mypy itself accepts. Its own
# ``TYPE_IGNORE_PATTERN = re.compile(r"[^#]*#\s*type:\s*ignore\s*(.*)")`` puts
# ``\s*`` after the colon, so ``# type:ignore`` and ``#type:ignore`` are
# effective suppressions and a literal-string guard misses them.
_IGNORE_PATTERN = re.compile(r"#\s*type:\s*ignore(?:\[(?P<codes>[^\]]*)\])?")
# ``import`` is the parent of the other two in mypy's own
# ``errorcodes.py`` (``sub_code_of=IMPORT``), so it silences an untyped or
# missing stub wherever it appears. Omitting it leaves the widest hole.
_IMPORT_FAMILY = frozenset({"import", "import-untyped", "import-not-found"})


def _source_files(repository_root: Path) -> tuple[Path, ...]:
    return tuple(sorted((repository_root / "src/crypto_lab").rglob("*.py")))


def _yaml_violations(tree: ast.AST, label: str) -> list[str]:
    """Return every forbidden YAML construction site in one parsed module."""
    aliases = _import_aliases(tree)
    violations: list[str] = []
    for node in ast.walk(tree):
        # Qualified matching. A dotted string can never equal an
        # ``ast.Attribute.attr``, so the base must be resolved through the
        # module's own import bindings instead.
        if isinstance(node, ast.Attribute) and node.attr in _QUALIFIED_YAML_NAMES:
            # Resolving the whole dotted name, rather than only a single
            # ``ast.Name`` base, also covers ``yaml.<submodule>.load``. A base
            # rebound through assignment (``y = yaml``) still escapes every AST
            # tripwire; the Task 2 import-closure test, which proves the
            # yaml-importing file set is exactly {"strategy/yaml_source.py"},
            # is the backstop for that class.
            resolved = _resolved_qualified_name(node, aliases)
            if resolved is not None and resolved.startswith("yaml."):
                violations.append(f"{label}:{node.lineno}: qualified {node.attr}")
        # Import-form matching. ``from yaml import safe_load`` produces no
        # attribute at the call site, so qualified matching cannot see it, and
        # the existing import-root test only inspects the root ``yaml``.
        if (
            isinstance(node, ast.ImportFrom)
            and node.module is not None
            and (node.module == "yaml" or node.module.startswith("yaml."))
        ):
            for alias in node.names:
                if alias.name in _IMPORT_FORM_NAMES:
                    violations.append(f"{label}:{node.lineno}: import {alias.name}")
        # Bare-name matching. Assignment targets are themselves ``ast.Name`` or
        # ``ast.Attribute`` nodes, so the walk already reaches them. Never
        # matches ``ast.keyword.arg``, so a required
        # ``Loader=StrictStrategySafeLoader`` keyword does not self-collide.
        if isinstance(node, ast.Name) and node.id in _BARE_FORBIDDEN_NAMES:
            violations.append(f"{label}:{node.lineno}: bare {node.id}")
        if isinstance(node, ast.Attribute) and node.attr in _BARE_FORBIDDEN_NAMES:
            violations.append(f"{label}:{node.lineno}: attribute {node.attr}")
    return violations


def test_no_source_file_constructs_yaml_unsafely(repository_root: Path) -> None:
    violations: list[str] = []
    source = repository_root / "src/crypto_lab"
    for path in _source_files(repository_root):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        violations.extend(
            _yaml_violations(tree, path.relative_to(source).as_posix()),
        )

    assert violations == []


@pytest.mark.parametrize(
    ("source", "expected_mode"),
    [
        # The four shapes the plan names.
        ("import yaml\nyaml.safe_load(x)\n", "qualified"),
        ("import yaml as y\ny.compose(x)\n", "qualified"),
        ("Loader = 1\n", "bare"),
        ("from yaml import safe_load\nsafe_load(x)\n", "import"),
        # Mode-unique shapes. Five of the six qualified names are also
        # bare-matched, so the four shapes above stay detected even if the
        # qualified or import-form branch were deleted. `load` is the only
        # qualified-only name, which makes these the shapes that actually pin
        # those two branches.
        ("import yaml\nyaml.load(x)\n", "qualified"),
        ("import yaml as y\ny.load(x)\n", "qualified"),
        ("import yaml.composer\nyaml.composer.load(x)\n", "qualified"),
        ("from yaml import load\nload(x)\n", "import"),
        ("self.yaml_constructors[t] = f\n", "attribute"),
    ],
)
def test_guard_detects_every_unsafe_form(source: str, expected_mode: str) -> None:
    violations = _yaml_violations(ast.parse(source), "fixture")

    assert violations != []
    # Asserting the matching mode, not merely non-emptiness, is what keeps a
    # deleted branch from passing on another branch's overlapping match.
    assert any(expected_mode in violation for violation in violations)


def test_guard_does_not_flag_legitimate_calls() -> None:
    source = "import tomllib\nobj.load()\ntomllib.loads(x)\n"

    assert _yaml_violations(ast.parse(source), "legitimate") == []


def _import_ignore_violation(line: str) -> str | None:
    """Return why one line silences an import-family mypy error, else None."""
    match = _IGNORE_PATTERN.search(line)
    if match is None:
        return None
    codes = match.group("codes")
    if codes is None:
        # A bare ignore silences every code, so it matters exactly where an
        # untyped-stub error would be raised: on the import itself.
        if line.lstrip().startswith(("import ", "from ")):
            return "bare ignore on an import line"
        return None
    for code in (item.strip() for item in codes.split(",")):
        if code in _IMPORT_FAMILY:
            return f"suppressed {code}"
    return None


@pytest.mark.parametrize(
    "line",
    [
        "from yaml import safe_load  # type: ignore",
        "import yaml  # type:ignore",
        "import yaml  #type:ignore",
        "from x import y  # type: ignore[import]",
        "from x import y  # type: ignore[import-untyped]",
        "from x import y  # type: ignore[import-not-found]",
        "from x import y  # type:ignore[import-untyped]",
        "value = thing()  # type: ignore[import-untyped]",
        "from x import y  # type: ignore[assignment, import]",
    ],
)
def test_typing_guard_detects_every_suppression_spelling(line: str) -> None:
    assert _import_ignore_violation(line) is not None


@pytest.mark.parametrize(
    "line",
    [
        "    x: A | MISSING = MISSING  # type: ignore[valid-type]",
        "value = thing()  # type: ignore",
        "import yaml",
        "from x import y  # type: ignore[assignment]",
        "from x import y",
    ],
)
def test_typing_guard_allows_every_legitimate_line(line: str) -> None:
    assert _import_ignore_violation(line) is None


def test_no_source_file_silences_an_untyped_import(repository_root: Path) -> None:
    violations: list[str] = []
    source = repository_root / "src/crypto_lab"
    for path in _source_files(repository_root):
        relative_path = path.relative_to(source).as_posix()
        for number, line in enumerate(
            path.read_text(encoding="utf-8").splitlines(),
            start=1,
        ):
            reason = _import_ignore_violation(line)
            if reason is not None:
                violations.append(f"{relative_path}:{number}: {reason}")

    assert violations == []
