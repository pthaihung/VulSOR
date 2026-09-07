#!/usr/bin/env python
"""EDA for information that remains missing or unreliable after repair.

Outputs PNG charts plus CSV/JSON summaries under data/EDA.  The script assumes
data/PrimeVul_clean is the repaired clean directory and compares it to
data/PrimeVul_raw.
"""

from __future__ import annotations

import csv
import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any


SPLITS = ("train", "valid", "test")
ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = ROOT / "data"
CLEAN_DIR = DATA_DIR / "PrimeVul_clean"
RAW_DIR = DATA_DIR / "PrimeVul_raw"
EDA_DIR = DATA_DIR / "EDA"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def find_raw_archive_root(raw_dir: Path) -> Path | None:
    candidates = sorted(raw_dir.glob("file_contents-*"))
    if candidates:
        return candidates[0]
    if (raw_dir / "file_contents").exists():
        return raw_dir
    return None


def raw_local_exists(raw_archive_root: Path | None, raw_local_file_path: str | None) -> bool:
    if not raw_archive_root or not raw_local_file_path:
        return False
    return (raw_archive_root / raw_local_file_path).exists()


def collect_split(split: str, raw_archive_root: Path | None) -> dict[str, Any]:
    raw_rows = read_jsonl(RAW_DIR / f"primevul_{split}_paired.jsonl")
    input_rows = read_jsonl(CLEAN_DIR / "inputs" / f"{split}.jsonl")
    label_rows = read_jsonl(CLEAN_DIR / "labels" / f"{split}.jsonl")
    context_rows = read_jsonl(CLEAN_DIR / "context" / f"{split}.jsonl")
    paired_rows = read_jsonl(CLEAN_DIR / "paired" / f"{split}.jsonl")

    stats = Counter()
    issue_examples: dict[str, list[dict[str, Any]]] = defaultdict(list)
    projects_with_missing_raw_file = Counter()
    projects_with_whole_file_missing_func = Counter()
    projects_with_range_issues = Counter()

    for index, (raw, clean_input, label, context) in enumerate(
        zip(raw_rows, input_rows, label_rows, context_rows)
    ):
        sample_id = f"{split}_{index:06d}"
        stats["records"] += 1

        if clean_input.get("code") == raw.get("func"):
            stats["target_function_body_exact_from_raw"] += 1
        else:
            stats["target_function_body_mismatch"] += 1
            add_example(issue_examples, "target_function_body_mismatch", sample_id, raw, context)

        if label.get("target") == raw.get("target"):
            stats["label_matches_raw"] += 1
        else:
            stats["label_mismatch"] += 1
            add_example(issue_examples, "label_mismatch", sample_id, raw, context)

        target_source = context.get("target_function_source") or {}
        if target_source.get("body") == raw.get("func"):
            stats["context_embeds_raw_function_body"] += 1
        else:
            stats["context_missing_embedded_raw_function_body"] += 1
            add_example(
                issue_examples,
                "context_missing_embedded_raw_function_body",
                sample_id,
                raw,
                context,
            )

        quality = context.get("context_quality") or {}
        raw_path = context.get("raw_local_file_path")
        raw_path_exists = quality.get("raw_local_file_path_exists")
        if raw_path_exists is None:
            raw_path_exists = raw_local_exists(raw_archive_root, raw_path)
        if raw_path and not raw_path_exists:
            stats["raw_archive_file_missing"] += 1
            projects_with_missing_raw_file[raw.get("project") or "unknown"] += 1
            add_example(issue_examples, "raw_archive_file_missing", sample_id, raw, context)

        if context.get("resolved_file_available"):
            stats["usable_whole_file_context"] += 1
        else:
            stats["no_usable_whole_file_context"] += 1

        whole_contains = quality.get("whole_file_contains_raw_function")
        if whole_contains is False and quality.get("resolved_file_path_exists"):
            stats["whole_file_does_not_contain_raw_func"] += 1
            projects_with_whole_file_missing_func[raw.get("project") or "unknown"] += 1
            add_example(
                issue_examples,
                "whole_file_does_not_contain_raw_func",
                sample_id,
                raw,
                context,
            )

        if quality.get("function_range_contains_raw_function") is False and quality.get(
            "whole_file_contains_raw_function"
        ):
            stats["function_range_not_canonical"] += 1
            projects_with_range_issues[raw.get("project") or "unknown"] += 1
            add_example(issue_examples, "function_range_not_canonical", sample_id, raw, context)

        if quality.get("target_range_contains_raw_function") is False and quality.get(
            "whole_file_contains_raw_function"
        ):
            stats["target_range_not_canonical"] += 1
            projects_with_range_issues[raw.get("project") or "unknown"] += 1
            add_example(issue_examples, "target_range_not_canonical", sample_id, raw, context)

    paired_ok = 0
    paired_bad = 0
    for pair_index, pair in enumerate(paired_rows):
        raw_pair = raw_rows[pair_index * 2 : pair_index * 2 + 2]
        raw_vulnerable = next((row for row in raw_pair if row.get("target") == 1), None)
        raw_fixed = next((row for row in raw_pair if row.get("target") == 0), None)
        if (
            raw_vulnerable
            and raw_fixed
            and (pair.get("vulnerable") or {}).get("func_hash") == raw_vulnerable.get("func_hash")
            and (pair.get("fixed") or {}).get("func_hash") == raw_fixed.get("func_hash")
        ):
            paired_ok += 1
        else:
            paired_bad += 1
    stats["paired_matches_raw"] = paired_ok
    stats["paired_mismatch"] = paired_bad

    return {
        "split": split,
        "counts": {
            "raw": len(raw_rows),
            "inputs": len(input_rows),
            "labels": len(label_rows),
            "context": len(context_rows),
            "paired": len(paired_rows),
        },
        "stats": dict(stats),
        "issue_examples": issue_examples,
        "projects": {
            "missing_raw_archive_file": projects_with_missing_raw_file.most_common(20),
            "whole_file_missing_raw_function": projects_with_whole_file_missing_func.most_common(20),
            "range_not_canonical": projects_with_range_issues.most_common(20),
        },
    }


def add_example(
    issue_examples: dict[str, list[dict[str, Any]]],
    issue: str,
    sample_id: str,
    raw: dict[str, Any],
    context: dict[str, Any],
    limit: int = 10,
) -> None:
    if len(issue_examples[issue]) >= limit:
        return
    issue_examples[issue].append(
        {
            "sample_id": sample_id,
            "project": raw.get("project"),
            "target": raw.get("target"),
            "func_hash": raw.get("func_hash"),
            "file_hash": raw.get("file_hash"),
            "file_name": raw.get("file_name"),
            "cve": raw.get("cve"),
            "raw_local_file_path": context.get("raw_local_file_path"),
            "resolved_file_content_path": context.get("resolved_file_content_path"),
            "function_start_line": context.get("function_start_line"),
            "function_end_line": context.get("function_end_line"),
            "target_function": context.get("target_function"),
            "context_quality": context.get("context_quality"),
        }
    )


def write_tables(report: dict[str, Any]) -> None:
    EDA_DIR.mkdir(parents=True, exist_ok=True)
    (EDA_DIR / "raw_missing_context_summary.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    rows: list[dict[str, Any]] = []
    for split_report in report["splits"]:
        split = split_report["split"]
        stats = split_report["stats"]
        counts = split_report["counts"]
        rows.append(
            {
                "split": split,
                "records": counts["raw"],
                "target_body_exact_from_raw": stats.get("target_function_body_exact_from_raw", 0),
                "label_matches_raw": stats.get("label_matches_raw", 0),
                "context_embeds_raw_function_body": stats.get("context_embeds_raw_function_body", 0),
                "usable_whole_file_context": stats.get("usable_whole_file_context", 0),
                "no_usable_whole_file_context": stats.get("no_usable_whole_file_context", 0),
                "raw_archive_file_missing": stats.get("raw_archive_file_missing", 0),
                "whole_file_does_not_contain_raw_func": stats.get(
                    "whole_file_does_not_contain_raw_func", 0
                ),
                "function_range_not_canonical": stats.get("function_range_not_canonical", 0),
                "target_range_not_canonical": stats.get("target_range_not_canonical", 0),
                "paired_matches_raw": stats.get("paired_matches_raw", 0),
                "paired_mismatch": stats.get("paired_mismatch", 0),
            }
        )

    with (EDA_DIR / "raw_missing_context_summary.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def plot(report: dict[str, Any]) -> list[str]:
    import matplotlib.pyplot as plt

    EDA_DIR.mkdir(parents=True, exist_ok=True)
    paths: list[str] = []
    splits = [item["split"] for item in report["splits"]]
    records = [item["counts"]["raw"] for item in report["splits"]]

    target_ok = [
        item["stats"].get("target_function_body_exact_from_raw", 0)
        for item in report["splits"]
    ]
    whole_ok = [
        item["stats"].get("usable_whole_file_context", 0) for item in report["splits"]
    ]
    whole_missing = [
        item["stats"].get("no_usable_whole_file_context", 0) for item in report["splits"]
    ]

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(splits, target_ok, color="#2f6f6d", label="target function body from raw")
    ax.set_title("Canonical Target Function Coverage")
    ax.set_ylabel("records")
    ax.set_ylim(0, max(records) * 1.12)
    for x, value, total in zip(splits, target_ok, records):
        ax.text(x, value + max(records) * 0.015, f"{value}/{total}", ha="center")
    ax.legend()
    fig.tight_layout()
    path = EDA_DIR / "01_target_function_coverage.png"
    fig.savefig(path, dpi=160)
    plt.close(fig)
    paths.append(str(path))

    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(splits, whole_ok, color="#4f81bd", label="usable whole-file context")
    ax.bar(splits, whole_missing, bottom=whole_ok, color="#c0504d", label="missing/unusable")
    ax.set_title("Whole-File Context Availability")
    ax.set_ylabel("records")
    for idx, split in enumerate(splits):
        total = records[idx]
        ax.text(idx, total + max(records) * 0.015, f"{whole_ok[idx]}/{total} usable", ha="center")
    ax.legend()
    fig.tight_layout()
    path = EDA_DIR / "02_whole_file_context_availability.png"
    fig.savefig(path, dpi=160)
    plt.close(fig)
    paths.append(str(path))

    issue_names = [
        "raw_archive_file_missing",
        "whole_file_does_not_contain_raw_func",
        "function_range_not_canonical",
        "target_range_not_canonical",
    ]
    colors = ["#d9534f", "#f0ad4e", "#5bc0de", "#8064a2"]
    fig, ax = plt.subplots(figsize=(11, 5.5))
    width = 0.18
    x_positions = list(range(len(splits)))
    for offset, (issue, color) in enumerate(zip(issue_names, colors)):
        values = [item["stats"].get(issue, 0) for item in report["splits"]]
        xs = [x + (offset - 1.5) * width for x in x_positions]
        ax.bar(xs, values, width=width, label=issue, color=color)
        for x, value in zip(xs, values):
            if value:
                ax.text(x, value + 3, str(value), ha="center", fontsize=8)
    ax.set_xticks(x_positions)
    ax.set_xticklabels(splits)
    ax.set_title("Remaining Raw/Context Issues After Repair")
    ax.set_ylabel("records")
    ax.legend(fontsize=8)
    fig.tight_layout()
    path = EDA_DIR / "03_remaining_issue_counts.png"
    fig.savefig(path, dpi=160)
    plt.close(fig)
    paths.append(str(path))

    fig, ax = plt.subplots(figsize=(10, 4.5))
    metrics = [
        "target_function_body_exact_from_raw",
        "label_matches_raw",
        "context_embeds_raw_function_body",
        "usable_whole_file_context",
    ]
    data = []
    for split_report in report["splits"]:
        total = split_report["counts"]["raw"]
        data.append(
            [
                100.0 * split_report["stats"].get(metric, 0) / total
                for metric in metrics
            ]
        )
    image = ax.imshow(data, cmap="YlGnBu", vmin=0, vmax=100, aspect="auto")
    ax.set_xticks(range(len(metrics)))
    ax.set_xticklabels(
        ["target body", "labels", "context embeds body", "whole-file usable"],
        rotation=20,
        ha="right",
    )
    ax.set_yticks(range(len(splits)))
    ax.set_yticklabels(splits)
    for row_idx, row in enumerate(data):
        for col_idx, value in enumerate(row):
            ax.text(col_idx, row_idx, f"{value:.1f}%", ha="center", va="center", fontsize=9)
    ax.set_title("Clean-vs-Raw Coverage Percent")
    fig.colorbar(image, ax=ax, label="%")
    fig.tight_layout()
    path = EDA_DIR / "04_coverage_heatmap.png"
    fig.savefig(path, dpi=160)
    plt.close(fig)
    paths.append(str(path))

    return paths


def main() -> int:
    raw_archive_root = find_raw_archive_root(RAW_DIR)
    report = {
        "clean_dir": str(CLEAN_DIR),
        "raw_dir": str(RAW_DIR),
        "raw_archive_root": str(raw_archive_root) if raw_archive_root else None,
        "splits": [collect_split(split, raw_archive_root) for split in SPLITS],
    }
    write_tables(report)
    image_paths = plot(report)
    print("EDA written to:", EDA_DIR)
    for path in image_paths:
        print("image:", path)
    print("table:", EDA_DIR / "raw_missing_context_summary.csv")
    print("json:", EDA_DIR / "raw_missing_context_summary.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
