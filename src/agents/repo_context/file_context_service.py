"""Offline PrimeVul file-context build orchestration."""
from __future__ import annotations

import json
import os
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .file_cpg import FileContextError, FileCpgCache
from .file_context_selection import select_file_context
from ..input_context.file_prompt_context import FileContextBudgetError, validate_complete_context
from .joern import JoernError
from .primevul_file_source import FileSourceResolutionError, PrimeVulFileSourceResolver


@dataclass(frozen=True)
class FileContextResult:
    record: dict[str, Any]
    status: str
    reason: str | None = None


ProgressCallback = Callable[[int, int, FileContextResult], None]


class PrimeVulLocatorIndex:
    def __init__(self, values: Mapping[str, Any]) -> None:
        self.values = dict(values)
        self.float_values: dict[float, Mapping[str, Any] | None] = {}
        for key, value in self.values.items():
            if isinstance(key, str) and key.isdecimal() and isinstance(value, Mapping):
                try: number = float(key)
                except OverflowError: continue
                if number in self.float_values: self.float_values[number] = None
                else: self.float_values[number] = value

    @classmethod
    def load(cls, path: Path) -> "PrimeVulLocatorIndex":
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(value, Mapping): raise ValueError("file_info must be an object")
        return cls(value)

    def lookup(self, func_hash: object) -> Mapping[str, Any] | None:
        if isinstance(func_hash, bool): return None
        if isinstance(func_hash, int): value = self.values.get(str(func_hash))
        elif isinstance(func_hash, float): value = self.float_values.get(func_hash)
        else: return None
        return value if isinstance(value, Mapping) else None


class FileContextService:
    def __init__(self, resolver: PrimeVulFileSourceResolver, cpg_cache: FileCpgCache, joern: Any, *, dataset_root: Path) -> None:
        self.resolver, self.cpg_cache, self.joern = resolver, cpg_cache, joern
        self.dataset_root = Path(dataset_root)

    def process(self, raw: Mapping[str, Any], locators: PrimeVulLocatorIndex) -> FileContextResult:
        record = dict(raw)
        record["context"] = {}
        locator = locators.lookup(raw.get("func_hash"))
        if locator is None: return FileContextResult(record, "unavailable", "locator_missing")
        start, end = locator.get("start_line"), locator.get("end_line")
        if not isinstance(start, int) or isinstance(start, bool) or not isinstance(end, int) or isinstance(end, bool) or start < 1 or end < start:
            return FileContextResult(record, "unavailable", "invalid_source_range")
        try:
            source = self.resolver.resolve(locator=locator, repository_url=str(raw["project_url"]), fix_revision=str(raw["commit_id"]), dataset_root=self.dataset_root)
            artifact = self.cpg_cache.get_or_build(source)
            facts = self.joern.extract_file_context(artifact.cpg_path, source_file=artifact.staged_source, start_line=start, end_line=end)
            selected = select_file_context(facts)
            record["context"] = validate_complete_context(selected)
            return FileContextResult(record, "built")
        except FileContextBudgetError: return FileContextResult(record, "oversized", "context_over_2000_tokens")
        except (KeyError, FileSourceResolutionError, FileContextError, JoernError, OSError, ValueError):
            return FileContextResult(record, "unavailable", "context_extraction_failed")

    @staticmethod
    def _target_count(pairs: Path, limit: int | None) -> int:
        if limit is not None and limit <= 0:
            return 0
        total = 0
        with Path(pairs).open("r", encoding="utf-8-sig") as source:
            for line in source:
                if not line.strip():
                    continue
                raw = json.loads(line)
                if not isinstance(raw, Mapping) or raw.get("target") != 1:
                    continue
                total += 1
                if limit is not None and total >= limit:
                    break
        return total

    def build_jsonl(
        self,
        pairs: Path,
        file_info: Path,
        output: Path,
        *,
        limit: int | None = None,
        report: Path | None = None,
        progress: ProgressCallback | None = None,
    ) -> dict[str, int]:
        locators = PrimeVulLocatorIndex.load(file_info)
        counts = {"total": 0, "built": 0, "unavailable": 0, "failed": 0, "oversized": 0}
        total_targets = self._target_count(pairs, limit)
        output.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(dir=output.parent, prefix=f".{output.name}.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as target, Path(pairs).open("r", encoding="utf-8-sig") as source:
                for line in source:
                    if not line.strip(): continue
                    raw = json.loads(line)
                    if not isinstance(raw, Mapping) or raw.get("target") != 1: continue
                    if limit is not None and counts["total"] >= limit: break
                    counts["total"] += 1
                    result = self.process(raw, locators)
                    counts[result.status] += 1
                    target.write(json.dumps(result.record, ensure_ascii=False, separators=(",", ":")) + "\n")
                    if progress is not None:
                        progress(counts["total"], total_targets, result)
            os.replace(temp_name, output)
        except Exception:
            Path(temp_name).unlink(missing_ok=True)
            raise
        if report is not None:
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(json.dumps(counts, indent=2) + "\n", encoding="utf-8")
        return counts
