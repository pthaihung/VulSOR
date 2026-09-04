"""Normalize raw PrimeVul metadata into a leakage-safe repository index."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .index import write_repository_index
from .models import RepositoryIndexRecord, RepositoryRef, TargetAnchor


@dataclass(frozen=True)
class PrimeVulFieldMap:
    """Map normalized locator fields to keys in raw PrimeVul records."""

    sample_id: str
    repository_id: str
    repository_url: str
    revision: str
    file_path: str
    function_name: str
    code: str
    start_line: str | None = None
    end_line: str | None = None


FIELD_MAP = PrimeVulFieldMap(
    sample_id="id",
    repository_id="project_url",
    repository_url="project_url",
    revision="commit_id",
    file_path="file_path",
    function_name="func_name",
    code="func",
    start_line="start",
    end_line="end",
)


def _normalize_code(code: str) -> str:
    """Canonicalize line endings and insignificant surrounding whitespace."""
    code = code.replace("\r\n", "\n").replace("\r", "\n")
    lines = [line.rstrip() for line in code.split("\n")]
    return "\n".join(lines).strip()


def _normalized_code_sha256(code: str) -> str:
    if not isinstance(code, str):
        raise TypeError("code must be a string")
    return hashlib.sha256(_normalize_code(code).encode("utf-8")).hexdigest()


class _SourceMatch:
    """Small source-matching boundary used by index normalization."""

    normalized_code_sha256 = staticmethod(_normalized_code_sha256)


source_match = _SourceMatch()
normalized_code_sha256 = source_match.normalized_code_sha256


def normalize_primevul_record(
    raw: Mapping[str, Any],
    field_map: PrimeVulFieldMap,
) -> RepositoryIndexRecord:
    """Convert one raw record while retaining only repository locator fields."""
    start_line = (
        raw[field_map.start_line] if field_map.start_line is not None else None
    )
    end_line = raw[field_map.end_line] if field_map.end_line is not None else None

    return RepositoryIndexRecord(
        sample_id=raw[field_map.sample_id],
        repository=RepositoryRef(
            repository_id=raw[field_map.repository_id],
            repository_url=raw[field_map.repository_url],
            revision=raw[field_map.revision],
        ),
        target=TargetAnchor(
            file_path=raw[field_map.file_path],
            function_name=raw[field_map.function_name],
            start_line=start_line,
            end_line=end_line,
            normalized_code_sha256=source_match.normalized_code_sha256(
                raw[field_map.code]
            ),
        ),
    )


def _sample_id_for_reject(raw: object, field_map: PrimeVulFieldMap) -> str | None:
    if not isinstance(raw, Mapping):
        return None
    sample_id = raw.get(field_map.sample_id)
    return sample_id if isinstance(sample_id, str) else None


def _sanitized_reason(exc: Exception) -> str:
    if isinstance(exc, json.JSONDecodeError):
        return "invalid_json"

    if isinstance(exc, ValidationError):
        details = []
        for error in exc.errors():
            location = ".".join(str(part) for part in error.get("loc", ()))
            details.append(f"{location or 'record'}: {error.get('type', 'invalid')}")
        return "; ".join(details) or "validation_error"

    if isinstance(exc, KeyError):
        return f"missing_field: {exc.args[0]}"

    if isinstance(exc, TypeError):
        return "invalid_record_type"

    return "invalid_record"


def normalize_primevul_jsonl(
    input_path: Path,
    output_path: Path,
    reject_path: Path,
    field_map: PrimeVulFieldMap = FIELD_MAP,
) -> None:
    """Normalize raw JSONL, writing valid records and sanitized rejects."""
    accepted: dict[str, RepositoryIndexRecord] = {}
    rejects: list[dict[str, object]] = []

    with input_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue

            raw: object = None
            try:
                raw = json.loads(line)
                record = normalize_primevul_record(raw, field_map)
                if record.sample_id in accepted:
                    raise ValueError("duplicate sample_id")
                accepted[record.sample_id] = record
            except (KeyError, TypeError, ValueError, ValidationError) as exc:
                rejects.append(
                    {
                        "line": line_number,
                        "sample_id": _sample_id_for_reject(raw, field_map),
                        "reason": _sanitized_reason(exc),
                    }
                )

    write_repository_index(accepted, output_path)
    reject_path.write_text(
        "".join(
            f"{json.dumps(reject, ensure_ascii=False, sort_keys=True)}\n"
            for reject in rejects
        ),
        encoding="utf-8",
    )
