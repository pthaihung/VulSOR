"""Load and persist normalized repository metadata indexes."""

from __future__ import annotations

import json
import os
import tempfile
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

        with path.open("rb") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                if not raw_line.strip():
                    continue

                try:
                    line = raw_line.decode("utf-8", errors="strict")
                    record = RepositoryIndexRecord.model_validate(json.loads(line))
                except (UnicodeDecodeError, ValueError, ValidationError) as exc:
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
    materialized = list(values)
    first_positions: dict[str, int] = {}
    for position, record in enumerate(materialized, start=1):
        if record.sample_id in first_positions:
            raise ValueError(
                f"Duplicate sample_id {record.sample_id!r}: first record at "
                f"position {first_positions[record.sample_id]} and duplicate "
                f"record at position {position}"
            )
        first_positions[record.sample_id] = position

    ordered = sorted(materialized, key=lambda record: record.sample_id)
    payload = "".join(f"{record.model_dump_json()}\n" for record in ordered)

    _atomic_write_text(path, payload)


def _atomic_write_text(path: Path, payload: str) -> None:
    """Write text through an exclusive sibling temporary file."""
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)

    try:
        with os.fdopen(
            descriptor,
            "w",
            encoding="utf-8",
            errors="strict",
            newline="",
        ) as handle:
            handle.write(payload)
            handle.flush()
        temporary_path.replace(path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
