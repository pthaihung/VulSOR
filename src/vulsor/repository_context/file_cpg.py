"""File-scoped Joern CPG creation and extraction boundary validation."""

from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from .primevul_file_source import ResolvedFileSource


_CONTEXT_FAMILIES = (
    "imports",
    "callee_funcs",
    "call_relations",
    "call_site_arguments",
    "data_flow",
    "control_dependencies",
    "declarations",
    "types",
)


class FileContextError(RuntimeError):
    """A file CPG or its source-grounded context is invalid."""


class CpgBuilder(Protocol):
    def build_cpg(self, source_root: Path, output_path: Path) -> None: ...


@dataclass(frozen=True)
class FileCpgArtifact:
    cpg_path: Path
    staged_source: Path
    source_sha256: str
    cache_hit: bool


class FileCpgCache:
    """Cache a CPG by source bytes, not repository identity or revision."""

    def __init__(self, cache_root: Path, joern: CpgBuilder) -> None:
        self.cache_root = Path(cache_root)
        self.joern = joern

    def get_or_build(self, source: ResolvedFileSource) -> FileCpgArtifact:
        source_path = source.source_path.resolve()
        cache_root = self.cache_root.resolve()
        source_bytes = source_path.read_bytes()
        actual_digest = hashlib.sha256(source_bytes).hexdigest()
        if actual_digest != source.source_sha256:
            raise FileContextError("source digest changed before CPG construction")
        suffix = source_path.suffix or ".c"
        stage_dir = cache_root / "sources" / actual_digest
        staged_source = stage_dir / f"target{suffix}"
        cpg_path = cache_root / "cpg" / f"{actual_digest}.bin"
        self._write_if_missing(staged_source, source_bytes)
        if cpg_path.is_file() and cpg_path.stat().st_size > 0:
            return FileCpgArtifact(cpg_path, staged_source, actual_digest, True)
        cpg_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_dir = Path(tempfile.mkdtemp(prefix=f".{actual_digest}.", dir=cpg_path.parent))
        temporary_output = temporary_dir / "cpg.bin"
        try:
            self.joern.build_cpg(stage_dir, temporary_output)
            if not temporary_output.is_file() or temporary_output.stat().st_size <= 0:
                raise FileContextError("Joern did not create a non-empty file CPG")
            os.replace(temporary_output, cpg_path)
        finally:
            shutil.rmtree(temporary_dir, ignore_errors=True)
        return FileCpgArtifact(cpg_path, staged_source, actual_digest, False)

    @staticmethod
    def _write_if_missing(path: Path, content: bytes) -> None:
        if path.is_file():
            if path.read_bytes() != content:
                raise FileContextError("staged source does not match its digest")
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
            os.replace(temporary_name, path)
        except Exception:
            Path(temporary_name).unlink(missing_ok=True)
            raise


def validate_file_context_payload(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise FileContextError("file context payload must be an object")
    if payload.get("target_status") != "exact":
        raise FileContextError("file context requires exactly one exact target")
    validated: dict[str, Any] = {"target_status": "exact"}
    for family in _CONTEXT_FAMILIES:
        values = payload.get(family, [])
        if not isinstance(values, list):
            raise FileContextError(f"file context family {family} must be an array")
        validated[family] = values
    return validated


__all__ = [
    "FileContextError",
    "FileCpgArtifact",
    "FileCpgCache",
    "validate_file_context_payload",
]
