from __future__ import annotations

import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINT = ROOT / "context_tool" / "context_tool.py"


def test_context_tool_has_standalone_entrypoint() -> None:
    assert ENTRYPOINT.is_file()


def test_context_tool_help_exposes_only_build_interface() -> None:
    result = subprocess.run(
        [sys.executable, str(ENTRYPOINT), "build", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert "--pairs" in result.stdout
    assert "--file-info" in result.stdout
    assert "--dataset-root" in result.stdout
    assert "--output" in result.stdout
    assert "file-context" not in result.stdout


def test_context_tool_does_not_import_legacy_context_packages() -> None:
    source = ENTRYPOINT.read_text(encoding="utf-8")

    assert "agents.input_context" not in source
    assert "agents.repo_context" not in source
    assert "scripts.context_tool" not in source
