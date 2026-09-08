"""Load the standalone context tool for unit tests without installing it."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


_ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "vulsor_standalone_context_tool",
    _ROOT / "context_tool" / "context_tool.py",
)
if _SPEC is None or _SPEC.loader is None:
    raise ImportError("could not load context_tool/context_tool.py")

context_tool = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = context_tool
_SPEC.loader.exec_module(context_tool)

for _name in dir(context_tool):
    if not _name.startswith("__"):
        globals()[_name] = getattr(context_tool, _name)
