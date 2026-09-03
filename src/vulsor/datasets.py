"""Dataset loading helpers for VulSOR."""

from __future__ import annotations

import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

from vulsor.config import VulSORConfig


@dataclass(frozen=True)
class DatasetSample:
    """One source-code sample selected from a configured dataset."""

    sample_id: str
    code: str
    context: dict | None = None


def iter_dataset_samples(
    config: VulSORConfig,
    dataset_name: str,
    split: str,
    *,
    sample_id: str | None = None,
    limit: int | None = None,
    offset: int = 0,
    random_count: int | None = None,
    random_seed: int | None = None,
    include_context: bool = False,
) -> Iterator[DatasetSample]:
    """Yield samples from a PrimeVul_clean-style inputs JSONL file."""
    dataset = config.datasets.get(dataset_name)

    if dataset is None:
        raise ValueError(
            f"Dataset is not configured: {dataset_name}"
        )

    input_file = dataset.root / "inputs" / f"{split}.jsonl"

    if not input_file.is_file():
        raise FileNotFoundError(
            f"Dataset input split does not exist: {input_file}"
        )

    context_by_sample_id = (
        _load_context_map(dataset.root, split)
        if include_context
        else {}
    )
    selected: list[DatasetSample] = []

    with input_file.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSONL record at {input_file}:{line_number}"
                ) from exc

            current_sample_id = record.get("sample_id")
            code = record.get("code")

            if not isinstance(current_sample_id, str):
                raise ValueError(
                    f"Missing sample_id at {input_file}:{line_number}"
                )

            if not isinstance(code, str):
                raise ValueError(
                    f"Missing code at {input_file}:{line_number}"
                )

            sample = DatasetSample(
                sample_id=current_sample_id,
                code=code,
                context=context_by_sample_id.get(current_sample_id),
            )

            if sample_id is not None:
                if current_sample_id == sample_id:
                    yield sample
                    return

                continue

            selected.append(sample)

    if sample_id is not None:
        raise ValueError(
            f"Sample not found in {dataset_name}/{split}: {sample_id}"
        )

    if random_count is not None:
        generator = random.Random(random_seed)
        selected = generator.sample(
            selected,
            k=min(random_count, len(selected)),
        )

    else:
        if offset:
            selected = selected[offset:]

        if limit is not None:
            selected = selected[:limit]

    yield from selected


def _load_context_map(
    dataset_root: Path,
    split: str,
) -> dict[str, dict]:
    """Load optional clean technical context for dataset samples."""
    context_file = dataset_root / "context" / f"{split}.jsonl"

    if not context_file.is_file():
        return {}

    context_by_sample_id: dict[str, dict] = {}

    with context_file.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()

            if not line:
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSONL record at {context_file}:{line_number}"
                ) from exc

            sample_id = record.get("sample_id")

            if not isinstance(sample_id, str):
                raise ValueError(
                    f"Missing sample_id at {context_file}:{line_number}"
                )

            context_by_sample_id[sample_id] = record

    return context_by_sample_id
