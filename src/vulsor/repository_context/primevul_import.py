"""Import paired PrimeVul records into compact query-safe files."""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .clang_function import ClangFunctionError
from .index import _atomic_write_text, write_repository_index
from .models import RepositoryIndexRecord, RepositoryRef, TargetAnchor
from .source_match import normalized_code_sha256


FunctionExtractor = Callable[[str, str], str]
ParentRevisionResolver = Callable[[RepositoryRef], str]


@dataclass(frozen=True)
class ImportSummary:
    accepted: int
    rejected: int


def _sample_id(raw: Mapping[str, Any]) -> str | None:
    value = raw.get("idx")
    if isinstance(value, bool) or not isinstance(value, int):
        return None
    return f"test_{value}"


def _reject(sample_id: str | None, reason: str) -> dict[str, str | None]:
    return {"sample_id": sample_id, "reason": reason}


def _float_locators(info: Mapping[str, Any]) -> dict[float, Mapping[str, Any] | None]:
    """Index integer file-info hashes represented as lossy JSON floats."""

    locators: dict[float, Mapping[str, Any] | None] = {}
    for key, value in info.items():
        if not isinstance(key, str) or not key.isdecimal() or not isinstance(value, Mapping):
            continue
        try:
            floating_hash = float(key)
        except OverflowError:
            continue
        existing = locators.get(floating_hash)
        if existing is None and floating_hash not in locators:
            locators[floating_hash] = value
        elif existing != value:
            locators[floating_hash] = None
    return locators


def _locator(
    info: Mapping[str, Any],
    float_locators: Mapping[float, Mapping[str, Any] | None],
    func_hash: object,
) -> Mapping[str, Any] | None:
    if isinstance(func_hash, bool):
        return None
    if isinstance(func_hash, int):
        value = info.get(str(func_hash))
    elif isinstance(func_hash, float) and math.isfinite(func_hash):
        value = float_locators.get(func_hash)
    else:
        return None
    return value if isinstance(value, Mapping) else None


def _record(
    raw: Mapping[str, Any],
    locator: Mapping[str, Any],
    extract: FunctionExtractor,
    resolve_parent_revision: ParentRevisionResolver,
) -> RepositoryIndexRecord:
    code = raw.get("func")
    path = locator.get("project_file_path")
    if not isinstance(code, str) or not code.strip():
        raise ValueError("invalid_record")
    if not isinstance(path, str) or not path.strip():
        raise ValueError("locator_invalid")
    suffix = Path(path).suffix
    name = extract(code, suffix)
    repository = RepositoryRef(
        repository_id=raw["project"],
        repository_url=raw["project_url"],
        revision=raw["commit_id"],
    )
    return RepositoryIndexRecord(
        sample_id=_sample_id(raw) or "invalid",
        repository=RepositoryRef(
            repository_id=repository.repository_id,
            repository_url=repository.repository_url,
            revision=resolve_parent_revision(repository),
        ),
        target=TargetAnchor(
            file_path=path,
            function_name=name,
            start_line=None,
            end_line=None,
            normalized_code_sha256=normalized_code_sha256(code),
        ),
    )


def _reason(exc: Exception) -> str:
    if isinstance(exc, ClangFunctionError):
        return {
            "function_not_found": "function_not_found",
            "ambiguous_function": "function_ambiguous",
            "clang_unavailable": "clang_unavailable",
        }.get(exc.kind, "invalid_record")
    if isinstance(exc, KeyError):
        return "invalid_record"
    if isinstance(exc, (TypeError, ValueError, ValidationError)):
        return "locator_invalid" if str(exc) == "locator_invalid" else "invalid_record"
    return "invalid_record"


def import_primevul_test(
    raw_path: Path,
    file_info_path: Path,
    output_root: Path,
    extract_function_name: FunctionExtractor,
    *,
    resolve_parent_revision: ParentRevisionResolver | None = None,
) -> ImportSummary:
    """Create test.jsonl, index.jsonl, and sanitized import rejects atomically."""

    raw_path, file_info_path, output_root = Path(raw_path), Path(file_info_path), Path(output_root)
    resolve_parent_revision = resolve_parent_revision or (lambda ref: ref.revision)
    info = json.loads(file_info_path.read_text(encoding="utf-8"))
    if not isinstance(info, Mapping):
        raise ValueError("file_info must be a JSON object")
    float_locators = _float_locators(info)

    accepted: dict[str, tuple[str, RepositoryIndexRecord]] = {}
    rejects: list[dict[str, str | None]] = []
    with raw_path.open("r", encoding="utf-8-sig") as handle:
        for raw_line in handle:
            if not raw_line.strip():
                continue
            try:
                raw = json.loads(raw_line)
            except json.JSONDecodeError:
                rejects.append(_reject(None, "invalid_record"))
                continue
            if not isinstance(raw, Mapping) or raw.get("target") != 1:
                continue
            sample_id = _sample_id(raw)
            if sample_id is None:
                rejects.append(_reject(None, "invalid_record"))
                continue
            if sample_id in accepted:
                rejects.append(_reject(sample_id, "duplicate_sample_id"))
                continue
            locator = _locator(info, float_locators, raw.get("func_hash"))
            if locator is None:
                rejects.append(_reject(sample_id, "locator_missing"))
                continue
            try:
                record = _record(
                    raw, locator, extract_function_name, resolve_parent_revision
                )
            except Exception as exc:
                rejects.append(_reject(sample_id, _reason(exc)))
                continue
            accepted[sample_id] = (str(raw["func"]), record)

    output_root.mkdir(parents=True, exist_ok=True)
    input_payload = "".join(
        json.dumps({"sample_id": sample_id, "code": code}, ensure_ascii=True, sort_keys=True) + "\n"
        for sample_id, (code, _) in sorted(accepted.items())
    )
    reject_payload = "".join(
        json.dumps(value, ensure_ascii=True, sort_keys=True) + "\n"
        for value in sorted(rejects, key=lambda value: (value["sample_id"] or "", value["reason"]))
    )
    _atomic_write_text(output_root / "test.jsonl", input_payload)
    write_repository_index((record for _, record in accepted.values()), output_root / "index.jsonl")
    _atomic_write_text(output_root / "import-rejects.jsonl", reject_payload)
    return ImportSummary(accepted=len(accepted), rejected=len(rejects))


__all__ = [
    "FunctionExtractor",
    "ImportSummary",
    "ParentRevisionResolver",
    "import_primevul_test",
]
