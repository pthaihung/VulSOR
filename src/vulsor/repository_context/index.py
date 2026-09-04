"""Load and persist normalized repository metadata indexes."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping
from pathlib import Path

from pydantic import ValidationError

from .models import RepositoryIndexRecord


class RepositoryIndex:
    """Lookup table for leakage-safe sample-to-repository metadata."""

    def __init__(self, records: dict[str, RepositoryIndexRecord]):
        self._records = records

    @classmethod
    def load(cls, path: Path) -> "RepositoryIndex":
        records: dict[str, RepositoryIndexRecord] = {}
        first_lines: dict[str, int] = {}

        with path.open("r", encoding="utf-8") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue

                try:
                    record = RepositoryIndexRecord.model_validate(json.loads(line))
                except (ValueError, ValidationError) as exc:
                    raise ValueError(
                        f"Invalid repository index record at {path}:{line_number}"
                    ) from exc

                if record.sample_id in records:
                    raise ValueError(
                        f"Duplicate sample_id {record.sample_id!r} at "
                        f"{path}:{first_lines[record.sample_id]} and "
                        f"{path}:{line_number}"
                    )

                records[record.sample_id] = record
                first_lines[record.sample_id] = line_number

        return cls(records)

    def get(self, sample_id: str) -> RepositoryIndexRecord:
        try:
            return self._records[sample_id]
        except KeyError as exc:
            raise KeyError(f"Repository metadata not found: {sample_id}") from exc

    def __len__(self) -> int:
        return len(self._records)


def write_repository_index(
    records: Iterable[RepositoryIndexRecord]
    | Mapping[str, RepositoryIndexRecord],
    path: Path,
) -> None:
    """Write records in sample order and atomically replace ``path``."""
    values = records.values() if isinstance(records, Mapping) else records
    ordered = sorted(values, key=lambda record: record.sample_id)
    payload = "".join(f"{record.model_dump_json()}\n" for record in ordered)

    temporary_path = path.with_suffix(".tmp")
    temporary_path.write_text(payload, encoding="utf-8")
    temporary_path.replace(path)
