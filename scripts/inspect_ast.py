"""Inspect selected nodes from a Clang JSON AST."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from typing import Any


SOURCE_FILE = Path("tests/fixtures/simple.cpp")


def run_clang(source_file: Path) -> dict[str, Any]:
    """Run Clang and return its JSON AST."""
    result = subprocess.run(
        [
            "clang",
            "-x",
            "c++",
            "-Xclang",
            "-ast-dump=json",
            "-fsyntax-only",
            str(source_file),
        ],
        capture_output=True,
        text=True,
        check=True,
    )

    return json.loads(result.stdout)


def walk(node: Any) -> list[dict[str, Any]]:
    """Return all dictionary nodes recursively contained in an AST."""
    nodes: list[dict[str, Any]] = []

    if isinstance(node, dict):
        nodes.append(node)

        for value in node.values():
            nodes.extend(walk(value))

    elif isinstance(node, list):
        for item in node:
            nodes.extend(walk(item))

    return nodes


def main() -> None:
    """Print the AST nodes relevant to the simple.cpp fixture."""
    ast = run_clang(SOURCE_FILE)

    for node in walk(ast):
        if node.get("kind") == "FunctionDecl" and node.get("name") == "foo":
            print("===== FUNCTION foo =====")
            print(json.dumps(node, indent=2))
            print()

        if node.get("kind") == "CallExpr":
            text = json.dumps(node)

            if "memcpy" in text:
                print("===== CALL containing memcpy =====")
                print(json.dumps(node, indent=2))
                print()


if __name__ == "__main__":
    main()