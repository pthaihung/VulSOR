"""Verify a small, explicit set of offline repository-context samples.

This script deliberately does not run batch preprocessing.  It processes only
the sample IDs supplied on the command line and writes a compact report that
contains metadata and rendered-context counts, never repository source code.
"""

from __future__ import annotations

import argparse
import json
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from typing import Any

from vulsor.config import load_config
from vulsor.datasets import iter_dataset_samples
from vulsor.repository_context.cpg_cache import CpgCache
from vulsor.repository_context.git_repository import GitRepositoryResolver
from vulsor.repository_context.index import RepositoryIndex
from vulsor.repository_context.joern import JoernAdapter
from vulsor.repository_context.prompt_context import PromptContextRecord, upsert_prompt_context
from vulsor.repository_context.service import RepositoryPreparationError, RepositoryPreprocessor


_HEADINGS = {
    "[DATA DEPENDENCIES]": "data_dependencies",
    "[CONTROL DEPENDENCIES]": "control_dependencies",
    "[DECLARATIONS, TYPES AND CONTRACTS]": "declarations_types_contracts",
    "[CALL RELATIONS]": "calls",
}


class VerificationCase:
    """One deliberately selected sample and its review category."""

    def __init__(self, sample_id: str, category: str):
        if not sample_id.strip() or not category.strip():
            raise ValueError("sample_id and category must not be blank")
        self.sample_id = sample_id
        self.category = category


def rendered_family_counts(context: str) -> dict[str, int]:
    """Count rendered evidence lines by approved prompt section."""

    counts = {family: 0 for family in _HEADINGS.values()}
    active: str | None = None
    for line in context.splitlines():
        active = _HEADINGS.get(line, active)
        if active is not None and line.startswith("- "):
            counts[active] += 1
    return counts


def _unavailable_detail(error: Exception) -> str:
    if isinstance(error, RepositoryPreparationError):
        return error.kind
    return str(error).strip() or type(error).__name__


def verify_cases(
    cases: Sequence[VerificationCase],
    *,
    identity_for: Callable[[str], Mapping[str, str]],
    build_context: Callable[[str], PromptContextRecord],
) -> list[dict[str, object]]:
    """Build explicit cases and return source-free verification records."""

    report: list[dict[str, object]] = []
    for case in cases:
        identity = identity_for(case.sample_id)
        base: dict[str, object] = {
            "sample_id": case.sample_id,
            "category": case.category,
            "repository": str(identity["repository"]),
            "revision": str(identity["revision"]),
        }
        try:
            record = build_context(case.sample_id)
        except (RepositoryPreparationError, OSError, ValueError, KeyError) as error:
            report.append(
                {
                    **base,
                    "status": "unavailable",
                    "context_characters": 0,
                    "family_counts": rendered_family_counts(""),
                    "limitations": [_unavailable_detail(error)],
                }
            )
            continue
        except Exception as error:
            report.append(
                {
                    **base,
                    "status": "failed",
                    "context_characters": 0,
                    "family_counts": rendered_family_counts(""),
                    "limitations": [_unavailable_detail(error)],
                }
            )
            continue
        report.append(
            {
                **base,
                "status": "built",
                "context_characters": len(record.context),
                "family_counts": rendered_family_counts(record.context),
                "limitations": list(record.limitations),
            }
        )
    return report


def _parse_case(value: str) -> VerificationCase:
    sample_id, separator, category = value.partition(":")
    if not separator:
        raise argparse.ArgumentTypeError("sample must be SAMPLE_ID:CATEGORY")
    try:
        return VerificationCase(sample_id, category)
    except ValueError as error:
        raise argparse.ArgumentTypeError(str(error)) from error


def _repository_index_path(config: Any, dataset: str, split: str) -> Path:
    configured = config.datasets[dataset]
    explicit = configured.repository_index_files.get(split)
    if explicit is not None:
        return explicit
    if configured.repository_index_dir is None:
        raise ValueError("dataset repository index must be configured")
    return configured.repository_index_dir / f"{split}.jsonl"


def run(args: argparse.Namespace) -> list[dict[str, object]]:
    config = load_config(args.config)
    index = RepositoryIndex.load(_repository_index_path(config, args.dataset, args.split))
    samples = {
        sample.sample_id: sample
        for sample in iter_dataset_samples(config, args.dataset, args.split)
        if sample.sample_id in {case.sample_id for case in args.sample}
    }
    service = RepositoryPreprocessor(
        index,
        GitRepositoryResolver(config.repository_context, git_executable=config.tools.git),
        CpgCache(config.repository_context),
        JoernAdapter(config),
    )

    def identity_for(sample_id: str) -> Mapping[str, str]:
        record = index.get(sample_id)
        return {
            "repository": str(record.repository.repository_url),
            "revision": record.repository.revision,
        }

    def build_context(sample_id: str) -> PromptContextRecord:
        sample = samples.get(sample_id)
        if sample is None:
            raise RepositoryPreparationError("sample_missing", "sample was not found")
        record = service.build_prompt_context(sample_id, sample.code)
        upsert_prompt_context(args.contexts_output, record)
        return record

    report = verify_cases(args.sample, identity_for=identity_for, build_context=build_context)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--dataset", required=True)
    parser.add_argument("--split", required=True, choices=("train", "valid", "test"))
    parser.add_argument("--sample", required=True, action="append", type=_parse_case)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--contexts-output", required=True, type=Path)
    args = parser.parse_args()
    report = run(args)
    print(json.dumps({"checked": len(report), "built": sum(item["status"] == "built" for item in report)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
