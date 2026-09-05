"""Read and write strict, query-safe repository-context preparation catalogs."""

from __future__ import annotations

import json
from collections.abc import Iterable
from pathlib import Path

from pydantic import ValidationError

from .index import _atomic_write_text
from .models import PreparedRecord, UnresolvedPreparedRecord


def _safe_component(value: str, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\x00" in value
        or value in {".", ".."}
        or "/" in value
        or "\\" in value
    ):
        raise ValueError(f"{label} must be a safe path component")
    return value


def prepared_catalog_paths(
    cache_root: Path, dataset: str, split: str
) -> tuple[Path, Path]:
    """Return READY and unresolved catalog paths without creating directories."""

    root = Path(cache_root)
    if "\x00" in str(root):
        raise ValueError("cache_root must not contain NUL bytes")
    dataset = _safe_component(dataset, "dataset")
    split = _safe_component(split, "split")
    parent = root / "prepared" / dataset
    return parent / f"{split}.jsonl", parent / f"{split}.unresolved.jsonl"


class PreparedCatalog:
    """In-memory index of READY records only."""

    def __init__(self, records: dict[str, PreparedRecord]) -> None:
        self._records = records

    @classmethod
    def empty(cls) -> "PreparedCatalog":
        return cls({})

    @classmethod
    def load(cls, path: Path) -> "PreparedCatalog":
        path = Path(path)
        if "\x00" in str(path):
            raise ValueError("path must not contain NUL bytes")
        if not path.exists():
            return cls.empty()
        if not path.is_file() or path.is_symlink():
            raise ValueError("prepared catalog must be a regular file")

        records: dict[str, PreparedRecord] = {}
        first_lines: dict[str, int] = {}
        try:
            with path.open("rb") as handle:
                for line_number, raw_line in enumerate(handle, start=1):
                    if not raw_line.strip():
                        continue
                    try:
                        record = PreparedRecord.model_validate(
                            json.loads(raw_line.decode("utf-8", errors="strict"))
                        )
                    except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
                        raise ValueError(
                            f"invalid prepared catalog record at {path}:{line_number}"
                        ) from exc
                    if record.sample_id in records:
                        raise ValueError(
                            f"duplicate sample_id {record.sample_id!r} at "
                            f"{path}:{first_lines[record.sample_id]} and {path}:{line_number}"
                        )
                    records[record.sample_id] = record
                    first_lines[record.sample_id] = line_number
        except OSError as exc:
            raise ValueError(f"could not read prepared catalog: {path}") from exc
        return cls(records)

    def get_or_none(self, sample_id: str) -> PreparedRecord | None:
        return self._records.get(sample_id)

    def records(self) -> tuple[PreparedRecord, ...]:
        return tuple(self._records.values())

    def __len__(self) -> int:
        return len(self._records)


def _catalog_payload(records: Iterable[PreparedRecord | UnresolvedPreparedRecord]) -> str:
    materialized = list(records)
    first_positions: dict[str, int] = {}
    for position, record in enumerate(materialized, start=1):
        if record.sample_id in first_positions:
            raise ValueError(f"duplicate sample_id: {record.sample_id}")
        first_positions[record.sample_id] = position
    ordered = sorted(materialized, key=lambda record: record.sample_id)
    return "".join(f"{record.model_dump_json()}\n" for record in ordered)


def _write_catalog(
    records: Iterable[PreparedRecord | UnresolvedPreparedRecord], path: Path
) -> None:
    path = Path(path)
    if "\x00" in str(path):
        raise ValueError("path must not contain NUL bytes")
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(path, _catalog_payload(records))


def write_prepared_catalog(records: Iterable[PreparedRecord], path: Path) -> None:
    """Atomically publish sorted READY records."""

    _write_catalog(records, path)


def write_unresolved_catalog(
    records: Iterable[UnresolvedPreparedRecord], path: Path
) -> None:
    """Atomically publish sorted controlled unresolved outcomes."""

    _write_catalog(records, path)


def load_unresolved_catalog(path: Path) -> tuple[UnresolvedPreparedRecord, ...]:
    """Read controlled unresolved outcomes; a missing catalog means no outcomes."""

    path = Path(path)
    if not path.exists():
        return ()
    values: list[UnresolvedPreparedRecord] = []
    seen: set[str] = set()
    try:
        with path.open("rb") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                if not raw_line.strip():
                    continue
                try:
                    record = UnresolvedPreparedRecord.model_validate(
                        json.loads(raw_line.decode("utf-8", errors="strict"))
                    )
                except (UnicodeDecodeError, json.JSONDecodeError, ValidationError) as exc:
                    raise ValueError(
                        f"invalid unresolved catalog record at {path}:{line_number}"
                    ) from exc
                if record.sample_id in seen:
                    raise ValueError(f"duplicate sample_id: {record.sample_id}")
                seen.add(record.sample_id)
                values.append(record)
    except OSError as exc:
        raise ValueError(f"could not read unresolved catalog: {path}") from exc
    return tuple(values)


__all__ = [
    "PreparedCatalog",
    "load_unresolved_catalog",
    "prepared_catalog_paths",
    "write_prepared_catalog",
    "write_unresolved_catalog",
]
