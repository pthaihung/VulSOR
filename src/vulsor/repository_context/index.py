"""Load and persist normalized repository metadata indexes."""

from __future__ import annotations

import json
import os
import re
import tempfile
from collections.abc import Iterable, Mapping
from pathlib import Path

from pydantic import ValidationError

from .models import RepositoryIndexRecord


def _validate_repository_relative_file_path(file_path: object) -> str:
    if not isinstance(file_path, str):
        raise TypeError("file_path must be a string")
    if "\x00" in file_path:
        raise ValueError("file_path must not contain NUL bytes")
    if (
        not file_path.strip()
        or file_path.startswith("/")
        or "\\" in file_path
        or re.match(r"^[A-Za-z]:", file_path)
        or any(segment == ".." for segment in file_path.split("/"))
    ):
        raise ValueError("file_path must be a repository-relative POSIX path")
    return file_path


class RepositoryIndex:
    """Lookup table for leakage-safe sample-to-repository metadata."""

    def __init__(self, records: dict[str, RepositoryIndexRecord]):
        self._records = records

    @classmethod
    def load(cls, path: Path) -> "RepositoryIndex":
        path = Path(path)
        _reject_nul_path(path, "path")
        records: dict[str, RepositoryIndexRecord] = {}
        first_lines: dict[str, int] = {}

        with path.open("rb") as handle:
            for line_number, raw_line in enumerate(handle, start=1):
                if not raw_line.strip():
                    continue

                try:
                    line = raw_line.decode("utf-8", errors="strict")
                    record = RepositoryIndexRecord.model_validate(json.loads(line))
                    _validate_repository_relative_file_path(
                        record.target.file_path
                    )
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
    path = Path(path)
    _reject_nul_path(path, "path")
    _atomic_write_text(path, _repository_index_payload(records))


def _repository_index_payload(
    records: Iterable[RepositoryIndexRecord]
    | Mapping[str, RepositoryIndexRecord],
) -> str:
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
    return "".join(f"{record.model_dump_json()}\n" for record in ordered)


def _stage_text(path: Path, payload: str, suffix: str) -> Path:
    """Write text through an exclusive sibling temporary file."""
    _reject_nul_path(path, "path")
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=suffix,
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
        return temporary_path
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _backup_existing(path: Path) -> Path | None:
    descriptor, backup_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".bak",
        dir=path.parent,
    )
    os.close(descriptor)
    backup_path = Path(backup_name)

    try:
        if not path.exists():
            backup_path.unlink(missing_ok=True)
            return None
        os.replace(path, backup_path)
        return backup_path
    except BaseException:
        backup_path.unlink(missing_ok=True)
        raise


def _atomic_write_text_pair(
    first_path: Path,
    first_payload: str,
    second_path: Path,
    second_payload: str,
) -> None:
    """Publish two staged files with rollback on a publication failure."""
    first_path = Path(first_path)
    second_path = Path(second_path)
    _reject_nul_path(first_path, "first_path")
    _reject_nul_path(second_path, "second_path")

    staged_paths: list[Path] = []
    backups: list[tuple[Path, Path | None]] = []
    try:
        staged_paths.append(_stage_text(first_path, first_payload, ".tmp"))
        staged_paths.append(_stage_text(second_path, second_payload, ".tmp"))

        backups.append((first_path, _backup_existing(first_path)))
        backups.append((second_path, _backup_existing(second_path)))

        staged_paths[0].replace(first_path)
        staged_paths[1].replace(second_path)
    except BaseException:
        for destination, backup_path in reversed(backups):
            if backup_path is None:
                destination.unlink(missing_ok=True)
            else:
                os.replace(backup_path, destination)
        raise
    finally:
        for staged_path in staged_paths:
            staged_path.unlink(missing_ok=True)
        for _, backup_path in backups:
            if backup_path is not None:
                backup_path.unlink(missing_ok=True)


def _atomic_write_text(path: Path, payload: str) -> None:
    """Write text through an exclusive sibling temporary file."""
    temporary_path = _stage_text(path, payload, ".tmp")
    try:
        temporary_path.replace(path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _reject_nul_path(path: Path, label: str) -> None:
    if "\x00" in str(path):
        raise ValueError(f"{label} must not contain NUL bytes")
