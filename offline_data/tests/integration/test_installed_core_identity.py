"""The installed-core identity check: this checkout's core, installed here.

The sub-project consumes the core distribution ``crypto-trading-lab`` as a
non-editable path dependency built from the parent checkout into
``offline_data/.venv`` (README, "Placement"). The distribution version is
``0.1.0`` at the preserved core and at Stage 9 alike, the lock records no
content identity for the path source and the registration test pins no
migration revision, so a stale or misbound installation could pass every other
gate unnoticed (the readiness brief, section 3.2). This module is the
consumer-side identity check. Every filesystem observation happens inside a
fixture or a test; the core is imported only through the installed package, and
the checkout source is read as bytes for comparison, never imported in its
place. Three parts, all by resolved location:

1. **Binding.** ``sys.executable`` and ``sys.prefix`` resolve under the
   checkout's ``offline_data/.venv``; ``crypto_lab.__file__`` and
   ``crypto_lab.persistence.migration_runner.__file__`` resolve under that
   environment's ``site-packages``; and the distribution's ``direct_url.json``
   (read through ``importlib.metadata``, never emitted) records a ``file:`` URL
   that resolves to exactly this checkout root with ``editable`` false. Only
   the third part distinguishes a same-content wheel built from another
   checkout and installed into this environment. Every location, origin and
   identity assertion is a bare boolean with a fixed message, so no absolute
   path reaches pytest's assertion output; the inventory messages below carry
   relative paths and hex digests only, which are relative by construction.

2. **Inventory.** The sorted relative-path inventories of every ``.py`` file
   beneath the checkout's ``src/crypto_lab`` and beneath the installed
   ``crypto_lab`` package must be nonempty and identical, file by file and
   byte for byte; missing, extra or changed Python files fail, and the failure
   message names every differing relative path, with the SHA-256 of the
   checkout bytes and of the installed bytes of each changed file, so the
   identities are available for review. The ``.py``-only
   inventory deliberately excludes the three non-Python classes the wheel
   carries: ``py.typed``, ``persistence/migrations/script.py.mako`` and the
   JSON schemas force-included from the repository ``schemas/`` directory into
   ``crypto_lab/schemas`` (no source-tree counterpart under ``src/crypto_lab``;
   the core reads none of them at runtime).

3. **Migration head.** The required head follows from the checkout's exact
   versions inventory: ``__init__.py`` with ``r0001_stage8_baseline.py``
   requires ``r0001_stage8_baseline``; those two with
   ``r0002_stage9_artifacts.py`` require ``r0002_stage9_artifacts``; any other
   inventory is rejected. The installed versions inventory must equal the
   checkout's, and the installed runner's default ``expected_head()`` (no
   ``script_location`` override, no upgrade, no database) must return the
   checkout-selected head. Accepting either head independently of the
   checkout is forbidden.

When all three parts hold, one deterministic success record goes to the
retained pytest output through ``capsys.disabled()``: the repository-relative
environment and package labels, the module count, the inventory digest, the
migration file names and the observed head, and nothing else (no absolute
path, no environment value, no file content). The inventory digest is the
SHA-256 of the UTF-8 text made of one line per checkout file in sorted path
order, each line being the SHA-256 hex digest of the file's bytes, two spaces,
the POSIX relative path and a line feed.

The synthetic controls run the same checker functions over small trees under
``tmp_path`` and prove each rejection: changed bytes at the same nominal
version, a missing file, an extra file, empty inventories, a simulated Stage 9
checkout paired with a baseline installation, an incorrect observed head and
every incorrect interpreter, package and origin binding, beside a matching
positive control. Nothing mutates the real checkout, the installed package, the
interpreter or the migration directory. The check proves that this checkout's
installation is this checkout's source; it is not the combined-tree
acceptance, which the later route still owes.
"""

from __future__ import annotations

import dataclasses
import hashlib
import json
import sys
import sysconfig
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path
from types import ModuleType
from typing import Final
from urllib.parse import unquote, urlsplit

import crypto_lab
import pytest
from crypto_lab.persistence import migration_runner

CORE_DISTRIBUTION = "crypto-trading-lab"
DIRECT_URL_FILE = "direct_url.json"
ENVIRONMENT_LABEL = "offline_data/.venv"
PACKAGE_LABEL = "crypto_lab"
SOURCE_LABEL = "src/crypto_lab"
VERSIONS_DIRECTORY = "persistence/migrations/versions"
BASELINE_HEAD = "r0001_stage8_baseline"
STAGE9_HEAD = "r0002_stage9_artifacts"
BASELINE_VERSIONS = ("__init__.py", f"{BASELINE_HEAD}.py")
STAGE9_VERSIONS = (*BASELINE_VERSIONS, f"{STAGE9_HEAD}.py")
KNOWN_VERSION_INVENTORIES: Mapping[tuple[str, ...], str] = {
    BASELINE_VERSIONS: BASELINE_HEAD,
    STAGE9_VERSIONS: STAGE9_HEAD,
}
SUCCESS_RECORD_PREFIX = "INSTALLED_CORE_IDENTITY"


# --- checkers shared by the real observation and the synthetic controls ------


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _python_inventory(root: Path) -> dict[str, bytes]:
    """Every ``.py`` file beneath ``root``, keyed by its POSIX relative path.

    A missing directory, or one holding no Python file, yields an empty
    inventory, which every comparison rejects.
    """
    if not root.is_dir():
        return {}
    files = sorted(path for path in root.rglob("*.py") if path.is_file())
    return {path.relative_to(root).as_posix(): path.read_bytes() for path in files}


def _inventory_digest(inventory: Mapping[str, bytes]) -> str:
    """The documented deterministic digest of an inventory (module docstring)."""
    lines = "".join(
        f"{_sha256(inventory[path])}  {path}\n" for path in sorted(inventory)
    )
    return _sha256(lines.encode("utf-8"))


@dataclass(frozen=True, slots=True)
class InventoryComparison:
    """The checkout inventory against the installed one; relative paths only."""

    checkout_count: int
    installed_count: int
    missing: tuple[str, ...]
    extra: tuple[str, ...]
    changed: tuple[str, ...]
    #: One ``<path> checkout=<sha256> installed=<sha256>`` entry per changed file.
    changed_identities: tuple[str, ...]
    digest: str

    @property
    def accepted(self) -> bool:
        return (
            self.checkout_count > 0
            and self.installed_count > 0
            and not self.missing
            and not self.extra
            and not self.changed
        )


def _compare_inventories(
    checkout: Mapping[str, bytes], installed: Mapping[str, bytes]
) -> InventoryComparison:
    shared = checkout.keys() & installed.keys()
    changed = tuple(
        sorted(path for path in shared if checkout[path] != installed[path])
    )
    return InventoryComparison(
        checkout_count=len(checkout),
        installed_count=len(installed),
        missing=tuple(sorted(checkout.keys() - installed.keys())),
        extra=tuple(sorted(installed.keys() - checkout.keys())),
        changed=changed,
        changed_identities=tuple(
            f"{path} checkout={_sha256(checkout[path])} "
            f"installed={_sha256(installed[path])}"
            for path in changed
        ),
        digest=_inventory_digest(checkout),
    )


def _version_files(inventory: Mapping[str, bytes]) -> tuple[str, ...]:
    """The sorted ``.py`` file names directly inside the versions directory."""
    prefix = f"{VERSIONS_DIRECTORY}/"
    names = (path[len(prefix) :] for path in inventory if path.startswith(prefix))
    return tuple(sorted(name for name in names if "/" not in name))


def _required_head(version_files: tuple[str, ...]) -> str | None:
    """The head an exact known versions inventory requires; ``None`` otherwise."""
    return KNOWN_VERSION_INVENTORIES.get(version_files)


@dataclass(frozen=True, slots=True)
class HeadVerdict:
    """The checkout-selected head against the installed inventory and head."""

    checkout_versions: tuple[str, ...]
    installed_versions: tuple[str, ...]
    required: str | None
    observed: str

    @property
    def inventories_match(self) -> bool:
        return self.checkout_versions == self.installed_versions

    @property
    def accepted(self) -> bool:
        return (
            self.required is not None
            and self.inventories_match
            and self.observed == self.required
        )


def _head_verdict(
    checkout: Mapping[str, bytes], installed: Mapping[str, bytes], observed: str
) -> HeadVerdict:
    checkout_versions = _version_files(checkout)
    return HeadVerdict(
        checkout_versions=checkout_versions,
        installed_versions=_version_files(installed),
        required=_required_head(checkout_versions),
        observed=observed,
    )


def _file_url_path(url: str) -> Path | None:
    """The local path a ``file:`` URL names, or ``None`` for any other URL."""
    parts = urlsplit(url)
    if parts.scheme != "file":
        return None
    path = unquote(parts.path)
    if parts.netloc not in ("", "localhost"):
        path = f"//{parts.netloc}{path}"
    elif len(path) >= 3 and path[0] == "/" and path[1].isalpha() and path[2] == ":":
        path = path[1:]
    return Path(path)


def _direct_url_origin(payload: object) -> tuple[Path | None, bool]:
    """The origin a ``direct_url.json`` payload names and its ``editable`` flag.

    The origin is ``None`` unless the payload is an object whose ``url`` is a
    ``file:`` URL; the flag is true only for an explicit ``"editable": false``
    inside ``dir_info``, so every malformed or editable record is rejected.
    """
    if not isinstance(payload, dict):
        return None, False
    url = payload.get("url")
    dir_info = payload.get("dir_info")
    origin = _file_url_path(url) if isinstance(url, str) else None
    not_editable = isinstance(dir_info, dict) and dir_info.get("editable") is False
    return origin, not_editable


@dataclass(frozen=True, slots=True)
class Binding:
    """The eight boolean parts of the interpreter, package and origin binding."""

    interpreter_in_environment: bool
    prefix_in_environment: bool
    site_packages_in_environment: bool
    package_in_site_packages: bool
    runner_in_site_packages: bool
    origin_is_file_url: bool
    origin_matches_checkout: bool
    origin_not_editable: bool

    @property
    def accepted(self) -> bool:
        return all(dataclasses.astuple(self))


def _binding(
    *,
    executable: Path,
    prefix: Path,
    site_packages: Path,
    package_file: Path,
    runner_file: Path,
    environment_root: Path,
    checkout_root: Path,
    direct_url: object,
) -> Binding:
    """Decide every binding part by resolved location; nothing is emitted."""
    environment = environment_root.resolve()
    checkout = checkout_root.resolve()
    site = site_packages.resolve()
    origin, not_editable = _direct_url_origin(direct_url)
    return Binding(
        interpreter_in_environment=executable.resolve().is_relative_to(environment),
        prefix_in_environment=prefix.resolve().is_relative_to(environment),
        site_packages_in_environment=site.is_relative_to(environment),
        package_in_site_packages=package_file.resolve().is_relative_to(site),
        runner_in_site_packages=runner_file.resolve().is_relative_to(site),
        origin_is_file_url=origin is not None,
        origin_matches_checkout=origin is not None and origin.resolve() == checkout,
        origin_not_editable=not_editable,
    )


# --- the real interpreter, installation and checkout -------------------------


@dataclass(frozen=True, slots=True)
class IdentityFacts:
    """Everything the identity check observed about the real environment."""

    binding: Binding
    comparison: InventoryComparison
    head: HeadVerdict

    @property
    def accepted(self) -> bool:
        return self.binding.accepted and self.comparison.accepted and self.head.accepted


def _module_file(module: ModuleType) -> Path:
    file = module.__file__
    assert isinstance(file, str), "the module records no file origin"
    return Path(file)


def _direct_url_payload(distribution: str) -> object:
    """The parsed ``direct_url.json`` of the distribution, or ``None``."""
    try:
        text = metadata.distribution(distribution).read_text(DIRECT_URL_FILE)
    except metadata.PackageNotFoundError:
        return None
    if text is None:
        return None
    try:
        payload: object = json.loads(text)
    except json.JSONDecodeError:
        return None
    return payload


def _success_record(facts: IdentityFacts) -> str:
    return " ".join(
        (
            SUCCESS_RECORD_PREFIX,
            f"environment={ENVIRONMENT_LABEL}",
            f"package={PACKAGE_LABEL}",
            f"source={SOURCE_LABEL}",
            f"modules={facts.comparison.checkout_count}",
            f"inventory_sha256={facts.comparison.digest}",
            f"migrations={','.join(facts.head.checkout_versions)}",
            f"head={facts.head.observed}",
        )
    )


@pytest.fixture
def checkout_root(sub_project_root: Path) -> Path:
    """The repository checkout that holds this sub-project."""
    return sub_project_root.parent


@pytest.fixture
def environment_root(sub_project_root: Path) -> Path:
    """The sub-project environment the launcher pins."""
    return sub_project_root / ".venv"


@pytest.fixture
def identity_facts(checkout_root: Path, environment_root: Path) -> IdentityFacts:
    """Observe the running interpreter, the installed core and the checkout."""
    package_file = _module_file(crypto_lab)
    binding = _binding(
        executable=Path(sys.executable),
        prefix=Path(sys.prefix),
        site_packages=Path(sysconfig.get_path("purelib")),
        package_file=package_file,
        runner_file=_module_file(migration_runner),
        environment_root=environment_root,
        checkout_root=checkout_root,
        direct_url=_direct_url_payload(CORE_DISTRIBUTION),
    )
    checkout = _python_inventory(checkout_root / "src" / PACKAGE_LABEL)
    installed = _python_inventory(package_file.parent)
    return IdentityFacts(
        binding=binding,
        comparison=_compare_inventories(checkout, installed),
        head=_head_verdict(checkout, installed, migration_runner.expected_head()),
    )


def test_the_interpreter_and_imported_core_bind_to_the_sub_project_environment(
    identity_facts: IdentityFacts,
) -> None:
    """Every binding part holds, asserted as a bare boolean with a fixed message."""
    binding = identity_facts.binding
    interpreter_in_environment = binding.interpreter_in_environment
    prefix_in_environment = binding.prefix_in_environment
    site_packages_in_environment = binding.site_packages_in_environment
    package_in_site_packages = binding.package_in_site_packages
    runner_in_site_packages = binding.runner_in_site_packages
    origin_is_file_url = binding.origin_is_file_url
    origin_matches_checkout = binding.origin_matches_checkout
    origin_not_editable = binding.origin_not_editable

    assert interpreter_in_environment, "sys.executable is outside offline_data/.venv"
    assert prefix_in_environment, "sys.prefix is outside offline_data/.venv"
    assert site_packages_in_environment, "site-packages is outside offline_data/.venv"
    assert package_in_site_packages, "crypto_lab is not imported from site-packages"
    assert runner_in_site_packages, "migration_runner is not from site-packages"
    assert origin_is_file_url, "direct_url records no file: URL"
    assert origin_matches_checkout, "direct_url origin mismatch"
    assert origin_not_editable, "direct_url records no non-editable installation"


def test_the_installed_core_python_inventory_equals_the_checkout_source(
    identity_facts: IdentityFacts,
) -> None:
    """Nonempty, identical relative-path sets and byte-identical files.

    The messages list relative paths and hex digests in full, because pytest
    abbreviates a long tuple comparison; they hold no absolute path.
    """
    comparison = identity_facts.comparison
    missing = " ".join(comparison.missing)
    extra = " ".join(comparison.extra)
    changed = " | ".join(comparison.changed_identities)

    assert comparison.checkout_count > 0, "the checkout source inventory is empty"
    assert comparison.installed_count > 0, "the installed package inventory is empty"
    assert comparison.missing == (), f"installed package lacks: {missing}"
    assert comparison.extra == (), f"installed package holds extra modules: {extra}"
    assert comparison.changed == (), f"installed module bytes differ: {changed}"
    assert comparison.accepted


def test_the_installed_migration_head_is_the_checkout_selected_head(
    identity_facts: IdentityFacts,
) -> None:
    """The checkout's versions inventory selects the head the runner reports."""
    head = identity_facts.head

    assert head.checkout_versions == head.installed_versions
    assert head.required is not None, "unknown versions inventory"
    assert head.observed == head.required
    assert head.accepted


def test_the_identity_success_record_is_retained(
    identity_facts: IdentityFacts,
    checkout_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """One deterministic record, free of paths, written past pytest's capture."""
    accepted = identity_facts.accepted
    assert accepted, "the identity check did not pass; no record is emitted"

    record = _success_record(identity_facts)
    path_free = (
        str(checkout_root.resolve()) not in record
        and str(Path(sys.prefix).resolve()) not in record
        and "\\" not in record
    )
    assert path_free, "the success record names a path"
    assert record.startswith(f"{SUCCESS_RECORD_PREFIX} environment=")
    assert record.endswith(f" head={identity_facts.head.observed}")

    with capsys.disabled():
        print(f"\n{record}", flush=True)


# --- synthetic controls under tmp_path ---------------------------------------

SYNTHETIC_SOURCE_FILES: Mapping[str, bytes] = {
    "__init__.py": b'"""Synthetic core package."""\n',
    "py.typed": b"",
    "persistence/__init__.py": b"",
    "persistence/migration_runner.py": b"HEAD = 'r0001_stage8_baseline'\n",
    "persistence/migrations/__init__.py": b"",
    "persistence/migrations/env.py": b"# synthetic env\n",
    "persistence/migrations/script.py.mako": b"# synthetic template\n",
    f"{VERSIONS_DIRECTORY}/__init__.py": b"",
    f"{VERSIONS_DIRECTORY}/{BASELINE_HEAD}.py": b"revision = 'r0001_stage8_baseline'\n",
}
SYNTHETIC_WHEEL_ONLY_FILES: Mapping[str, bytes] = {
    "schemas/domain/synthetic-v1.schema.json": b'{"synthetic": true}\n',
}
SYNTHETIC_PYTHON_FILES: Mapping[str, bytes] = {
    path: data for path, data in SYNTHETIC_SOURCE_FILES.items() if path.endswith(".py")
}
SYNTHETIC_PYTHON_COUNT = 7
STAGE9_FILE = f"{VERSIONS_DIRECTORY}/{STAGE9_HEAD}.py"
STAGE9_BYTES = b"revision = 'r0002_stage9_artifacts'\n"
_DEFAULT: Final = object()


def _write_tree(root: Path, files: Mapping[str, bytes]) -> Path:
    for relative, data in files.items():
        path = root.joinpath(*relative.split("/"))
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
    return root


@dataclass(frozen=True, slots=True)
class SyntheticPair:
    """A synthetic ``src/crypto_lab`` beside a synthetic installed package."""

    checkout: Path
    installed: Path

    def compare(self) -> InventoryComparison:
        return _compare_inventories(
            _python_inventory(self.checkout), _python_inventory(self.installed)
        )

    def head(self, observed: str) -> HeadVerdict:
        return _head_verdict(
            _python_inventory(self.checkout),
            _python_inventory(self.installed),
            observed,
        )


@pytest.fixture
def synthetic_pair(tmp_path: Path) -> SyntheticPair:
    """Identical Python files; the installation also carries the wheel-only JSON."""
    checkout = _write_tree(
        tmp_path / "checkout" / "src" / "crypto_lab", SYNTHETIC_SOURCE_FILES
    )
    installed = _write_tree(
        tmp_path / "environment" / "site-packages" / "crypto_lab",
        {**SYNTHETIC_SOURCE_FILES, **SYNTHETIC_WHEEL_ONLY_FILES},
    )
    return SyntheticPair(checkout=checkout, installed=installed)


def test_the_matching_synthetic_pair_is_accepted(synthetic_pair: SyntheticPair) -> None:
    """The positive control: identical Python files, the baseline head observed."""
    comparison = synthetic_pair.compare()
    head = synthetic_pair.head(BASELINE_HEAD)

    assert comparison.accepted
    assert comparison.checkout_count == SYNTHETIC_PYTHON_COUNT
    assert comparison.installed_count == SYNTHETIC_PYTHON_COUNT
    assert comparison.digest == _inventory_digest(SYNTHETIC_PYTHON_FILES)
    assert head.accepted
    assert head.required == BASELINE_HEAD
    assert head.checkout_versions == BASELINE_VERSIONS


def test_the_non_python_wheel_classes_do_not_enter_the_inventory(
    synthetic_pair: SyntheticPair,
) -> None:
    """``py.typed``, the Mako template and the JSON schema are excluded."""
    installed = _python_inventory(synthetic_pair.installed)

    assert set(installed) == set(SYNTHETIC_PYTHON_FILES)
    assert not any(path.endswith((".mako", ".json", ".typed")) for path in installed)


def test_changed_bytes_at_the_same_nominal_version_are_rejected(
    synthetic_pair: SyntheticPair,
) -> None:
    """A one-byte change the version string and the head check cannot see."""
    target = synthetic_pair.installed / "persistence" / "migration_runner.py"
    original = target.read_bytes()
    mutated = original.replace(b"HEAD", b"head", 1)
    target.write_bytes(mutated)
    bytes_changed = target.read_bytes() == mutated and mutated != original
    assert bytes_changed

    comparison = synthetic_pair.compare()
    head = synthetic_pair.head(BASELINE_HEAD)

    assert comparison.changed == ("persistence/migration_runner.py",)
    assert comparison.changed_identities == (
        f"persistence/migration_runner.py checkout={_sha256(original)} "
        f"installed={_sha256(mutated)}",
    )
    assert comparison.missing == ()
    assert comparison.extra == ()
    assert not comparison.accepted
    assert head.accepted, "the head check alone admits the change; the bytes fail it"


def test_a_missing_installed_file_is_rejected(synthetic_pair: SyntheticPair) -> None:
    (synthetic_pair.installed / "persistence" / "migrations" / "env.py").unlink()

    comparison = synthetic_pair.compare()

    assert comparison.missing == ("persistence/migrations/env.py",)
    assert comparison.extra == ()
    assert comparison.changed == ()
    assert comparison.installed_count == SYNTHETIC_PYTHON_COUNT - 1
    assert not comparison.accepted


def test_an_extra_installed_file_is_rejected(synthetic_pair: SyntheticPair) -> None:
    extra = synthetic_pair.installed / "persistence" / "extra_module.py"
    extra.write_bytes(b"# not in the checkout\n")

    comparison = synthetic_pair.compare()

    assert comparison.extra == ("persistence/extra_module.py",)
    assert comparison.missing == ()
    assert comparison.changed == ()
    assert comparison.installed_count == SYNTHETIC_PYTHON_COUNT + 1
    assert not comparison.accepted


@pytest.mark.parametrize(
    ("checkout_shape", "installed_shape"),
    [
        ("empty", "empty"),
        ("empty", "full"),
        ("full", "empty"),
        ("missing", "full"),
        ("full", "non-python-only"),
    ],
)
def test_an_empty_inventory_is_rejected(
    tmp_path: Path, checkout_shape: str, installed_shape: str
) -> None:
    """An absent, empty or Python-free tree on either side is never accepted."""
    shapes: Mapping[str, Mapping[str, bytes]] = {
        "full": SYNTHETIC_SOURCE_FILES,
        "non-python-only": {
            path: data
            for path, data in {
                **SYNTHETIC_SOURCE_FILES,
                **SYNTHETIC_WHEEL_ONLY_FILES,
            }.items()
            if not path.endswith(".py")
        },
    }
    checkout = tmp_path / "checkout" / "src" / "crypto_lab"
    installed = tmp_path / "environment" / "site-packages" / "crypto_lab"
    for root, shape in ((checkout, checkout_shape), (installed, installed_shape)):
        if shape == "empty":
            root.mkdir(parents=True)
        elif shape != "missing":
            _write_tree(root, shapes[shape])

    comparison = SyntheticPair(checkout=checkout, installed=installed).compare()

    assert (comparison.checkout_count == 0) == (checkout_shape != "full")
    assert (comparison.installed_count == 0) == (installed_shape != "full")
    assert not comparison.accepted


def test_a_stage9_checkout_with_a_baseline_installation_is_rejected(
    synthetic_pair: SyntheticPair,
) -> None:
    """The checkout selects ``r0002``; the stale installation offers ``r0001``."""
    _write_tree(synthetic_pair.checkout, {STAGE9_FILE: STAGE9_BYTES})

    comparison = synthetic_pair.compare()
    head = synthetic_pair.head(BASELINE_HEAD)

    assert comparison.missing == (STAGE9_FILE,)
    assert not comparison.accepted
    assert head.checkout_versions == STAGE9_VERSIONS
    assert head.installed_versions == BASELINE_VERSIONS
    assert head.required == STAGE9_HEAD
    assert not head.inventories_match
    assert not head.accepted


def test_a_matching_stage9_pair_requires_the_stage9_head(
    synthetic_pair: SyntheticPair,
) -> None:
    """Checker behavior only: a real ``r0002`` result is owed by the later route."""
    _write_tree(synthetic_pair.checkout, {STAGE9_FILE: STAGE9_BYTES})
    _write_tree(synthetic_pair.installed, {STAGE9_FILE: STAGE9_BYTES})

    comparison = synthetic_pair.compare()
    stage9_head = synthetic_pair.head(STAGE9_HEAD)
    baseline_head = synthetic_pair.head(BASELINE_HEAD)

    assert comparison.accepted
    assert stage9_head.accepted
    assert stage9_head.required == STAGE9_HEAD
    assert not baseline_head.accepted


@pytest.mark.parametrize(
    "observed",
    [STAGE9_HEAD, "r0001_stage8_baselin", "R0001_STAGE8_BASELINE", "", "head"],
)
def test_an_incorrect_observed_head_is_rejected(
    synthetic_pair: SyntheticPair, observed: str
) -> None:
    head = synthetic_pair.head(observed)

    assert head.inventories_match
    assert head.required == BASELINE_HEAD
    assert not head.accepted


@pytest.mark.parametrize(
    "version_files",
    [
        (),
        ("__init__.py",),
        (f"{BASELINE_HEAD}.py",),
        ("__init__.py", f"{STAGE9_HEAD}.py"),
        ("__init__.py", f"{BASELINE_HEAD}.py", "r0003_future.py"),
        ("__init__.py", f"{BASELINE_HEAD}.py", f"{STAGE9_HEAD}.py", "r0003_future.py"),
        ("__init__.py", f"{BASELINE_HEAD}.pyc"),
    ],
)
def test_any_other_versions_inventory_selects_no_head(
    version_files: tuple[str, ...],
) -> None:
    assert _required_head(version_files) is None
    assert _required_head(BASELINE_VERSIONS) == BASELINE_HEAD
    assert _required_head(STAGE9_VERSIONS) == STAGE9_HEAD


@dataclass(frozen=True, slots=True)
class SyntheticEnvironment:
    """A synthetic checkout whose ``offline_data/.venv`` holds the package."""

    checkout: Path
    environment: Path
    site_packages: Path
    executable: Path
    package_file: Path
    runner_file: Path


@pytest.fixture
def synthetic_environment(tmp_path: Path) -> SyntheticEnvironment:
    """A checkout root with a space, so percent-decoding of the URL is exercised."""
    checkout = tmp_path / "check out"
    environment = checkout / "offline_data" / ".venv"
    site_packages = environment / "Lib" / "site-packages"
    executable = environment / "Scripts" / "python.exe"
    package_file = site_packages / "crypto_lab" / "__init__.py"
    runner_file = site_packages / "crypto_lab" / "persistence" / "migration_runner.py"
    for path in (executable, package_file, runner_file):
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"")
    return SyntheticEnvironment(
        checkout=checkout,
        environment=environment,
        site_packages=site_packages,
        executable=executable,
        package_file=package_file,
        runner_file=runner_file,
    )


def _direct_url(origin: Path, *, editable: bool = False) -> dict[str, object]:
    return {"url": origin.as_uri(), "dir_info": {"editable": editable}}


def _synthetic_binding(
    env: SyntheticEnvironment,
    *,
    executable: Path | None = None,
    prefix: Path | None = None,
    site_packages: Path | None = None,
    package_file: Path | None = None,
    runner_file: Path | None = None,
    direct_url: object = _DEFAULT,
) -> Binding:
    return _binding(
        executable=env.executable if executable is None else executable,
        prefix=env.environment if prefix is None else prefix,
        site_packages=env.site_packages if site_packages is None else site_packages,
        package_file=env.package_file if package_file is None else package_file,
        runner_file=env.runner_file if runner_file is None else runner_file,
        environment_root=env.environment,
        checkout_root=env.checkout,
        direct_url=_direct_url(env.checkout) if direct_url is _DEFAULT else direct_url,
    )


def test_the_matching_synthetic_binding_is_accepted(
    synthetic_environment: SyntheticEnvironment,
) -> None:
    binding = _synthetic_binding(synthetic_environment)

    assert binding.accepted
    assert all(dataclasses.astuple(binding))


LOCATION_REJECTIONS: Mapping[
    str, tuple[Callable[[SyntheticEnvironment], Binding], str]
] = {
    "interpreter from the root environment": (
        lambda env: _synthetic_binding(
            env, executable=env.checkout / ".venv" / "Scripts" / "python.exe"
        ),
        "interpreter_in_environment",
    ),
    "interpreter from a sibling environment": (
        lambda env: _synthetic_binding(
            env,
            executable=env.environment.with_name(".venv2") / "Scripts" / "python.exe",
        ),
        "interpreter_in_environment",
    ),
    "prefix of the root environment": (
        lambda env: _synthetic_binding(env, prefix=env.checkout / ".venv"),
        "prefix_in_environment",
    ),
    "prefix of the sub-project directory": (
        lambda env: _synthetic_binding(env, prefix=env.environment.parent),
        "prefix_in_environment",
    ),
    "site-packages of the root environment": (
        lambda env: _synthetic_binding(
            env,
            site_packages=env.checkout / ".venv" / "Lib" / "site-packages",
            package_file=env.checkout / ".venv" / "Lib" / "site-packages" / "x.py",
            runner_file=env.checkout / ".venv" / "Lib" / "site-packages" / "y.py",
        ),
        "site_packages_in_environment",
    ),
    "package imported from the checkout source": (
        lambda env: _synthetic_binding(
            env, package_file=env.checkout / "src" / "crypto_lab" / "__init__.py"
        ),
        "package_in_site_packages",
    ),
    "package imported from another worktree's environment": (
        lambda env: _synthetic_binding(
            env,
            package_file=env.checkout.parent
            / "other worktree"
            / "offline_data"
            / ".venv"
            / "Lib"
            / "site-packages"
            / "crypto_lab"
            / "__init__.py",
        ),
        "package_in_site_packages",
    ),
    "runner imported from the checkout source": (
        lambda env: _synthetic_binding(
            env,
            runner_file=env.checkout
            / "src"
            / "crypto_lab"
            / "persistence"
            / "migration_runner.py",
        ),
        "runner_in_site_packages",
    ),
}


@pytest.mark.parametrize("case", sorted(LOCATION_REJECTIONS))
def test_an_incorrect_location_binding_is_rejected(
    synthetic_environment: SyntheticEnvironment, case: str
) -> None:
    """Exactly the named part fails; every other part still holds."""
    build, failing_part = LOCATION_REJECTIONS[case]
    binding = build(synthetic_environment)
    parts = dataclasses.asdict(binding)

    assert parts[failing_part] is False
    assert all(value for name, value in parts.items() if name != failing_part)
    assert not binding.accepted


ORIGIN_REJECTIONS: Mapping[
    str, tuple[Callable[[SyntheticEnvironment], object], tuple[bool, bool, bool]]
] = {
    "another worktree": (
        lambda env: _direct_url(env.checkout.parent / "other worktree"),
        (True, False, True),
    ),
    "a copy beside the checkout": (
        lambda env: _direct_url(env.checkout.with_name(f"{env.checkout.name}-copy")),
        (True, False, True),
    ),
    "the sub-project directory": (
        lambda env: _direct_url(env.checkout / "offline_data"),
        (True, False, True),
    ),
    "the checkout's parent": (
        lambda env: _direct_url(env.checkout.parent),
        (True, False, True),
    ),
    "an editable installation": (
        lambda env: _direct_url(env.checkout, editable=True),
        (True, True, False),
    ),
    "no editable flag": (
        lambda env: {"url": env.checkout.as_uri(), "dir_info": {}},
        (True, True, False),
    ),
    "no dir_info": (
        lambda env: {"url": env.checkout.as_uri()},
        (True, True, False),
    ),
    "a non-file url": (
        lambda env: {
            "url": "https://example.invalid/core",
            "dir_info": {"editable": False},
        },
        (False, False, True),
    ),
    "a non-string url": (
        lambda env: {"url": 7, "dir_info": {"editable": False}},
        (False, False, True),
    ),
    "no direct_url.json": (lambda env: None, (False, False, False)),
    "a non-object payload": (
        lambda env: [env.checkout.as_uri()],
        (False, False, False),
    ),
}


@pytest.mark.parametrize("case", sorted(ORIGIN_REJECTIONS))
def test_an_incorrect_origin_record_is_rejected(
    synthetic_environment: SyntheticEnvironment, case: str
) -> None:
    """The location parts hold; the origin parts fail exactly as expected."""
    build, expected = ORIGIN_REJECTIONS[case]
    binding = _synthetic_binding(
        synthetic_environment, direct_url=build(synthetic_environment)
    )
    origin_parts = (
        binding.origin_is_file_url,
        binding.origin_matches_checkout,
        binding.origin_not_editable,
    )

    assert origin_parts == expected
    assert binding.interpreter_in_environment
    assert binding.prefix_in_environment
    assert binding.site_packages_in_environment
    assert binding.package_in_site_packages
    assert binding.runner_in_site_packages
    assert not binding.accepted


SYNTHETIC_SUCCESS_RECORD = (
    "INSTALLED_CORE_IDENTITY environment=offline_data/.venv package=crypto_lab "
    "source=src/crypto_lab modules=7 "
    "inventory_sha256=1cec625fd19bb178e7753926685e2552905aea7b07282e4a03535f334175ad1c "
    "migrations=__init__.py,r0001_stage8_baseline.py head=r0001_stage8_baseline"
)


def test_the_success_record_format_is_pinned_on_the_synthetic_pair(
    synthetic_pair: SyntheticPair, synthetic_environment: SyntheticEnvironment
) -> None:
    """The exact record shape the verifier output is read for, as one literal.

    The synthetic digest was captured once from the documented definition and
    freezes it: a change to the digest text, the field order or a label changes
    this literal.
    """
    facts = IdentityFacts(
        binding=_synthetic_binding(synthetic_environment),
        comparison=synthetic_pair.compare(),
        head=synthetic_pair.head(BASELINE_HEAD),
    )

    assert facts.accepted
    assert _success_record(facts) == SYNTHETIC_SUCCESS_RECORD


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("file:///C:/check%20out/root", Path("C:/check out/root")),
        ("file:///c:/root", Path("c:/root")),
        ("file://server/share/root", Path("//server/share/root")),
        ("file://localhost/C:/root", Path("C:/root")),
        ("https://example.invalid/root", None),
        ("", None),
        ("C:/root", None),
    ],
)
def test_file_url_paths_are_decoded_as_local_paths(
    url: str, expected: Path | None
) -> None:
    assert _file_url_path(url) == expected
