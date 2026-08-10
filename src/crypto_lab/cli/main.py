"""Version and help command for the local research foundation."""

from __future__ import annotations

import argparse
import importlib.metadata
from collections.abc import Sequence

_DISTRIBUTION_NAME = "crypto-trading-lab"


def build_parser() -> argparse.ArgumentParser:
    """Build the Stage 1 command parser."""
    parser = argparse.ArgumentParser(
        prog="crypto-lab",
        description="Local engine-neutral cryptocurrency research foundation.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {importlib.metadata.version(_DISTRIBUTION_NAME)}",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the version/help-only Stage 1 command line."""
    parser = build_parser()
    parser.parse_args(argv)
    parser.print_help()
    return 0
