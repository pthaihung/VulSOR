from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from agents.repo_context.file_cpg import (
    FileContextError,
    FileCpgCache,
    validate_file_context_payload,
)
from agents.repo_context.primevul_file_source import ResolvedFileSource


def test_select_target_requires_exactly_one_method_containing_span() -> None:
    payload = {"target_status": "ambiguous", "candidates": []}

    with pytest.raises(FileContextError, match="exact target"):
        validate_file_context_payload(payload)


def test_validate_file_context_payload_allows_callee_metadata_without_body():
    payload = {
        "target_status": "exact",
        "imports": [],
        "callee_funcs": [
            {
                "name": "helper",
                "signature": "void helper(int)",
                "file": "target.c",
                "line": 20,
                "start_line": 20,
                "end_line": 24,
                "provenance": "cpg_same_file_callee",
            }
        ],
        "call_relations": [],
        "call_site_arguments": [],
        "data_flow": [],
        "control_dependencies": [],
        "declarations": [],
        "types": [],
    }

    validated = validate_file_context_payload(payload)

    assert validated["callee_funcs"][0]["name"] == "helper"


def test_file_cpg_cache_is_keyed_by_source_digest(tmp_path: Path) -> None:
    source = tmp_path / "target.c"
    content = b"int target(void) {}\n"
    source.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    resolved = ResolvedFileSource(source, None, digest)
    calls: list[tuple[Path, Path]] = []

    class FakeJoern:
        def build_cpg(self, source_root: Path, output: Path) -> None:
            calls.append((source_root, output))
            output.write_bytes(b"cpg")

    cache = FileCpgCache(tmp_path / "cache", FakeJoern())
    first = cache.get_or_build(resolved)
    second = cache.get_or_build(resolved)

    assert first.cpg_path == second.cpg_path
    assert first.cpg_path.name == digest + ".bin"
    assert len(calls) == 1
    assert first.staged_source.suffix == ".c"
