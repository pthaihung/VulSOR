#!/usr/bin/env python
"""CWE/CVE distribution EDA for PrimeVul_clean.

Reads data/PrimeVul_clean/labels/*.jsonl and writes charts plus summary tables
under data/EDA.
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
EDA_DIR = DATA_DIR / "EDA"


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def normalize_cwe_values(value: Any) -> list[str]:
    if value is None:
        return ["UNKNOWN"]
    if isinstance(value, list):
        values = [str(item) for item in value if item not in (None, "")]
        return values or ["UNKNOWN"]
    text = str(value).strip()
    return [text] if text else ["UNKNOWN"]


def normalize_cve_value(value: Any) -> str:
    text = str(value).strip() if value is not None else ""
    return text or "UNKNOWN"


def collect() -> dict[str, Any]:
    split_reports: dict[str, Any] = {}
    overall_cwe = Counter()
    overall_cve = Counter()
    overall_target = Counter()
    cwe_by_target: dict[str, Counter[str]] = defaultdict(Counter)
    cve_by_target: dict[str, Counter[str]] = defaultdict(Counter)

    for split in SPLITS:
        rows = read_jsonl(CLEAN_DIR / "labels" / f"{split}.jsonl")
        cwe_counter = Counter()
        cve_counter = Counter()
        target_counter = Counter()
        multi_cwe_count = 0

        for row in rows:
            target = str(row.get("target", "UNKNOWN"))
            target_counter[target] += 1
            overall_target[target] += 1

            cwe_values = normalize_cwe_values(row.get("cwe"))
            if len(cwe_values) > 1:
                multi_cwe_count += 1
            for cwe in cwe_values:
                cwe_counter[cwe] += 1
                overall_cwe[cwe] += 1
                cwe_by_target[target][cwe] += 1

            cve = normalize_cve_value(row.get("cve"))
            cve_counter[cve] += 1
            overall_cve[cve] += 1
            cve_by_target[target][cve] += 1

        split_reports[split] = {
            "records": len(rows),
            "target_counts": dict(target_counter),
            "unique_cwe": len(cwe_counter),
            "unique_cve": len(cve_counter),
            "multi_cwe_records": multi_cwe_count,
            "all_cwe": cwe_counter.most_common(),
            "all_cve": cve_counter.most_common(),
            "top_cwe": cwe_counter.most_common(30),
            "top_cve": cve_counter.most_common(30),
        }

    return {
        "clean_dir": str(CLEAN_DIR),
        "splits": split_reports,
        "overall": {
            "records": sum(report["records"] for report in split_reports.values()),
            "target_counts": dict(overall_target),
            "unique_cwe": len(overall_cwe),
            "unique_cve": len(overall_cve),
            "all_cwe": overall_cwe.most_common(),
            "all_cve": overall_cve.most_common(),
            "top_cwe": overall_cwe.most_common(50),
            "top_cve": overall_cve.most_common(50),
            "cwe_by_target": {
                target: counter.most_common(30)
                for target, counter in sorted(cwe_by_target.items())
            },
            "cve_by_target": {
                target: counter.most_common(30)
                for target, counter in sorted(cve_by_target.items())
            },
        },
    }


def write_tables(report: dict[str, Any]) -> None:
    EDA_DIR.mkdir(parents=True, exist_ok=True)
    (EDA_DIR / "cwe_cve_distribution_summary.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    with (EDA_DIR / "cwe_distribution_top.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=["scope", "cwe", "count"])
        writer.writeheader()
        for cwe, count in report["overall"]["top_cwe"]:
            writer.writerow({"scope": "overall", "cwe": cwe, "count": count})
        for split, split_report in report["splits"].items():
            for cwe, count in split_report["top_cwe"]:
                writer.writerow({"scope": split, "cwe": cwe, "count": count})

    with (EDA_DIR / "cve_distribution_top.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=["scope", "cve", "count"])
        writer.writeheader()
        for cve, count in report["overall"]["top_cve"]:
            writer.writerow({"scope": "overall", "cve": cve, "count": count})
        for split, split_report in report["splits"].items():
            for cve, count in split_report["top_cve"]:
                writer.writerow({"scope": split, "cve": cve, "count": count})

    with (EDA_DIR / "cwe_distribution_all.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=["scope", "cwe", "count"])
        writer.writeheader()
        for cwe, count in report["overall"]["all_cwe"]:
            writer.writerow({"scope": "overall", "cwe": cwe, "count": count})
        for split, split_report in report["splits"].items():
            for cwe, count in split_report["all_cwe"]:
                writer.writerow({"scope": split, "cwe": cwe, "count": count})

    with (EDA_DIR / "cve_distribution_all.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=["scope", "cve", "count"])
        writer.writeheader()
        for cve, count in report["overall"]["all_cve"]:
            writer.writerow({"scope": "overall", "cve": cve, "count": count})
        for split, split_report in report["splits"].items():
            for cve, count in split_report["all_cve"]:
                writer.writerow({"scope": split, "cve": cve, "count": count})

    with (EDA_DIR / "test_cwe_distribution_all.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=["cwe", "count"])
        writer.writeheader()
        for cwe, count in report["splits"]["test"]["all_cwe"]:
            writer.writerow({"cwe": cwe, "count": count})

    with (EDA_DIR / "test_cve_distribution_all.csv").open(
        "w", encoding="utf-8", newline=""
    ) as handle:
        writer = csv.DictWriter(handle, fieldnames=["cve", "count"])
        writer.writeheader()
        for cve, count in report["splits"]["test"]["all_cve"]:
            writer.writerow({"cve": cve, "count": count})


def plot_barh(
    items: list[tuple[str, int]],
    title: str,
    path: Path,
    color: str,
    row_height: float = 0.36,
    dpi: int = 160,
    label_size: int = 8,
    value_size: int = 8,
    annotate_values: bool = True,
) -> None:
    import matplotlib.pyplot as plt

    labels = [item[0] for item in items][::-1]
    values = [item[1] for item in items][::-1]
    fig_height = max(5.0, row_height * len(labels) + 1.4)
    fig, ax = plt.subplots(figsize=(12, fig_height))
    ax.barh(labels, values, color=color)
    ax.set_title(title)
    ax.set_xlabel("records")
    ax.tick_params(axis="y", labelsize=label_size)
    if annotate_values and values:
        for idx, value in enumerate(values):
            ax.text(
                value + max(values) * 0.01,
                idx,
                str(value),
                va="center",
                fontsize=value_size,
            )
    fig.tight_layout()
    fig.savefig(path, dpi=dpi)
    plt.close(fig)


def plot_grouped_top_cwe(report: dict[str, Any], path: Path) -> None:
    import matplotlib.pyplot as plt

    top_cwes = [cwe for cwe, _ in report["overall"]["top_cwe"][:12]]
    split_counters = {}
    for split in SPLITS:
        split_counters[split] = dict(report["splits"][split]["top_cwe"])

    x_positions = list(range(len(top_cwes)))
    width = 0.24
    colors = {"train": "#4f81bd", "valid": "#9bbb59", "test": "#c0504d"}
    fig, ax = plt.subplots(figsize=(13, 5.5))
    for offset, split in enumerate(SPLITS):
        values = [split_counters[split].get(cwe, 0) for cwe in top_cwes]
        xs = [x + (offset - 1) * width for x in x_positions]
        ax.bar(xs, values, width=width, label=split, color=colors[split])
    ax.set_xticks(x_positions)
    ax.set_xticklabels(top_cwes, rotation=35, ha="right")
    ax.set_title("Top CWE Distribution by Split")
    ax.set_ylabel("records")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def plot_target_distribution(report: dict[str, Any], path: Path) -> None:
    import matplotlib.pyplot as plt

    labels = list(SPLITS)
    target_0 = [report["splits"][split]["target_counts"].get("0", 0) for split in SPLITS]
    target_1 = [report["splits"][split]["target_counts"].get("1", 0) for split in SPLITS]
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar(labels, target_0, label="target=0 fixed/benign", color="#4f81bd")
    ax.bar(labels, target_1, bottom=target_0, label="target=1 vulnerable", color="#c0504d")
    ax.set_title("Label Distribution by Split")
    ax.set_ylabel("records")
    for idx, split in enumerate(labels):
        total = target_0[idx] + target_1[idx]
        ax.text(idx, total + max(target_0 + target_1) * 0.015, str(total), ha="center")
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def plot_unique_counts(report: dict[str, Any], path: Path) -> None:
    import matplotlib.pyplot as plt

    labels = list(SPLITS) + ["overall"]
    unique_cwe = [report["splits"][split]["unique_cwe"] for split in SPLITS] + [
        report["overall"]["unique_cwe"]
    ]
    unique_cve = [report["splits"][split]["unique_cve"] for split in SPLITS] + [
        report["overall"]["unique_cve"]
    ]
    x_positions = list(range(len(labels)))
    width = 0.35
    fig, ax = plt.subplots(figsize=(9, 5))
    ax.bar([x - width / 2 for x in x_positions], unique_cwe, width, label="unique CWE", color="#8064a2")
    ax.bar([x + width / 2 for x in x_positions], unique_cve, width, label="unique CVE", color="#4bacc6")
    ax.set_xticks(x_positions)
    ax.set_xticklabels(labels)
    ax.set_title("Unique CWE/CVE Counts")
    ax.set_ylabel("unique values")
    for xs, values in [
        ([x - width / 2 for x in x_positions], unique_cwe),
        ([x + width / 2 for x in x_positions], unique_cve),
    ]:
        for x, value in zip(xs, values):
            ax.text(x, value + max(unique_cve) * 0.01, str(value), ha="center", fontsize=8)
    ax.legend()
    fig.tight_layout()
    fig.savefig(path, dpi=160)
    plt.close(fig)


def plot_all_cwe(report: dict[str, Any], path: Path) -> None:
    plot_barh(
        report["overall"]["all_cwe"],
        "All CWE Distribution Overall",
        path,
        "#8064a2",
    )


def plot_all_cve(report: dict[str, Any], path: Path) -> None:
    plot_barh(
        report["overall"]["all_cve"],
        "All CVE Distribution Overall",
        path,
        "#4bacc6",
        row_height=0.10,
        dpi=140,
        label_size=3,
        value_size=3,
        annotate_values=True,
    )


def plot_test_all_cwe(report: dict[str, Any], path: Path) -> None:
    plot_barh(
        report["splits"]["test"]["all_cwe"],
        "All CWE Distribution in Test Split",
        path,
        "#8064a2",
    )


def plot_test_all_cve(report: dict[str, Any], path: Path) -> None:
    plot_barh(
        report["splits"]["test"]["all_cve"],
        "All CVE Distribution in Test Split",
        path,
        "#4bacc6",
        row_height=0.14,
        dpi=150,
        label_size=4,
        value_size=4,
        annotate_values=True,
    )


def plot(report: dict[str, Any]) -> list[str]:
    EDA_DIR.mkdir(parents=True, exist_ok=True)
    paths = [
        EDA_DIR / "05_top_cwe_overall.png",
        EDA_DIR / "06_top_cve_overall.png",
        EDA_DIR / "07_top_cwe_by_split.png",
        EDA_DIR / "08_label_distribution_by_split.png",
        EDA_DIR / "09_unique_cwe_cve_counts.png",
        EDA_DIR / "10_all_cwe_distribution.png",
        EDA_DIR / "11_all_cve_distribution.png",
        EDA_DIR / "12_test_all_cwe_distribution.png",
        EDA_DIR / "13_test_all_cve_distribution.png",
    ]
    plot_barh(
        report["overall"]["top_cwe"][:20],
        "Top CWE Overall",
        paths[0],
        "#8064a2",
    )
    plot_barh(
        report["overall"]["top_cve"][:20],
        "Top CVE Overall",
        paths[1],
        "#4bacc6",
    )
    plot_grouped_top_cwe(report, paths[2])
    plot_target_distribution(report, paths[3])
    plot_unique_counts(report, paths[4])
    plot_all_cwe(report, paths[5])
    plot_all_cve(report, paths[6])
    plot_test_all_cwe(report, paths[7])
    plot_test_all_cve(report, paths[8])
    return [str(path) for path in paths]


def main() -> int:
    report = collect()
    write_tables(report)
    image_paths = plot(report)
    print("CWE/CVE EDA written to:", EDA_DIR)
    for path in image_paths:
        print("image:", path)
    print("json:", EDA_DIR / "cwe_cve_distribution_summary.json")
    print("csv:", EDA_DIR / "cwe_distribution_top.csv")
    print("csv:", EDA_DIR / "cve_distribution_top.csv")
    print("csv:", EDA_DIR / "cwe_distribution_all.csv")
    print("csv:", EDA_DIR / "cve_distribution_all.csv")
    print("csv:", EDA_DIR / "test_cwe_distribution_all.csv")
    print("csv:", EDA_DIR / "test_cve_distribution_all.csv")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
