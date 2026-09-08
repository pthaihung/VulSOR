"""Convenient entry point for the offline PrimeVul file-context builder."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Sequence


_REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_ROOT = _REPOSITORY_ROOT / "src"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))


def main(argv: Sequence[str] | None = None) -> int:
    """Run the existing ``file-context build`` command through one script."""
    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments and arguments[0] == "build":
        arguments = arguments[1:]
    if "--progress" not in arguments:
        arguments.append("--progress")

    from agents.repo_context.cli import main as cli_main

    return cli_main(["file-context", "build", *arguments])


if __name__ == "__main__":
    raise SystemExit(main())
