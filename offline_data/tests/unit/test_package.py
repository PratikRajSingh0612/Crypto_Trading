"""Smoke test for the ``crypto_lab_offline_data`` package scaffold."""

import crypto_lab_offline_data


def test_package_version_is_the_scaffold_version() -> None:
    """The installed package reports the pinned scaffold version."""
    assert crypto_lab_offline_data.__version__ == "0.1.0"
