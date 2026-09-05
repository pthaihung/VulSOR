"""Extract a sampled C/C++ function name with Clang JSON AST output."""

from __future__ import annotations

import json
import subprocess
import tempfile
from collections.abc import Callable, Iterator, Sequence
from pathlib import Path
from typing import Any, Literal


class ClangFunctionError(RuntimeError):
    """A controlled failure while deriving a function name from source."""

    def __init__(self, kind: Literal["clang_unavailable", "clang_invalid_ast", "function_not_found", "ambiguous_function"]):
        self.kind = kind
        super().__init__(kind)


ClangRunner = Callable[[Sequence[str], int], str]


def _run_clang(arguments: Sequence[str], timeout: int) -> str:
    try:
        result = subprocess.run(
            list(arguments),
            check=False,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except (FileNotFoundError, OSError, subprocess.TimeoutExpired):
        raise ClangFunctionError("clang_unavailable") from None
    return result.stdout


def _walk(node: Any) -> Iterator[dict[str, Any]]:
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from _walk(value)


def _language_for_suffix(suffix: str) -> str:
    if suffix.casefold() in {".cc", ".cp", ".cxx", ".cpp", ".c++", ".c"}:
        return "c++" if suffix.casefold() != ".c" else "c"
    raise ClangFunctionError("function_not_found")


def extract_function_name(
    code: str,
    suffix: str,
    runner: ClangRunner = _run_clang,
    *,
    clang_executable: str = "clang",
    timeout_seconds: int = 30,
) -> str:
    """Return the one named function declaration belonging to sampled source."""

    if not isinstance(code, str) or not code.strip():
        raise ClangFunctionError("function_not_found")
    language = _language_for_suffix(suffix)
    with tempfile.TemporaryDirectory() as directory:
        source = Path(directory) / f"sample{suffix}"
        source.write_text(code, encoding="utf-8")
        payload = runner(
            (
                clang_executable,
                "-x",
                language,
                "-Xclang",
                "-ast-dump=json",
                "-fsyntax-only",
                str(source),
            ),
            timeout_seconds,
        )
    try:
        ast = json.loads(payload)
    except (TypeError, json.JSONDecodeError):
        raise ClangFunctionError("clang_invalid_ast") from None

    names: set[str] = set()
    for node in _walk(ast):
        if node.get("kind") not in {"FunctionDecl", "CXXMethodDecl", "CXXConstructorDecl"}:
            continue
        name = node.get("name")
        location = node.get("loc")
        filename = location.get("file") if isinstance(location, dict) else None
        if isinstance(name, str) and name and filename == source.name:
            names.add(name)
    if not names:
        raise ClangFunctionError("function_not_found")
    if len(names) != 1:
        raise ClangFunctionError("ambiguous_function")
    return next(iter(names))


__all__ = ["ClangFunctionError", "ClangRunner", "extract_function_name"]
