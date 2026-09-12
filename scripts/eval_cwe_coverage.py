from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Iterable


CWE_CATEGORY_MAP = {
    "CWE-119": "out-of-bounds",
    "CWE-120": "out-of-bounds",
    "CWE-121": "out-of-bounds",
    "CWE-122": "out-of-bounds",
    "CWE-125": "out-of-bounds",
    "CWE-126": "out-of-bounds",
    "CWE-127": "out-of-bounds",
    "CWE-787": "out-of-bounds",
    "CWE-788": "out-of-bounds",
    "CWE-416": "use-after-free",
    "CWE-476": "null-deref",
    "CWE-401": "resource-leak",
    "CWE-404": "resource-leak",
    "CWE-415": "double-free",
    "CWE-190": "integer-overflow",
    "CWE-191": "integer-overflow",
    "CWE-369": "integer-overflow",
    "CWE-252": "unchecked-api-failure",
    "CWE-362": "race-or-lock-misuse",
    "CWE-667": "race-or-lock-misuse",
    "CWE-772": "early-exit-cleanup",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Check Stage 2 obligation coverage against ground-truth CWE families.")
    parser.add_argument("--project-root", default=".", help="Repository root containing data/, config/, and stages/.")
    parser.add_argument("--stage-root", default=None, help="Artifact directory; defaults to stages/semantic-v2.")
    parser.add_argument("--split", default="test", choices=["train", "valid", "test"])
    parser.add_argument("--limit", type=int, default=None)
    args = parser.parse_args()

    root = Path(args.project_root).resolve()
    label_path = root / "data" / "PrimeVul_clean" / "labels" / f"{args.split}.jsonl"
    stage_root = Path(args.stage_root) if args.stage_root is not None else root / "stages" / "semantic-v2"
    if not stage_root.is_absolute():
        stage_root = root / stage_root
    labels = list(read_jsonl(label_path))
    if args.limit is not None:
        labels = labels[: args.limit]

    checked = 0
    missing_stage2 = []
    unsupported_cwe = []
    mismatches = []
    for label in labels:
        if label.get("target") != 1:
            continue
        sample_id = label.get("sample_id")
        expected = expected_categories(label.get("cwe") or [])
        if not expected:
            unsupported_cwe.append({"sample_id": sample_id, "cwe": label.get("cwe") or []})
            continue
        rules_path = stage_root / str(sample_id) / "stage_2_rules.json"
        if not rules_path.exists():
            missing_stage2.append(str(sample_id))
            continue
        checked += 1
        rules = load_rules(rules_path)
        actual = {
            str(rule.get("coverage_category", "")).strip()
            for rule in rules
            if isinstance(rule, dict) and rule.get("coverage_category")
        }
        if expected.isdisjoint(actual):
            mismatches.append(
                {
                    "sample_id": sample_id,
                    "cwe": label.get("cwe") or [],
                    "expected_categories": sorted(expected),
                    "actual_categories": sorted(actual),
                    "rule_count": len(rules),
                }
            )

    result = {
        "split": args.split,
        "checked_vulnerable_samples": checked,
        "missing_stage2_count": len(missing_stage2),
        "unsupported_cwe_count": len(unsupported_cwe),
        "mismatch_count": len(mismatches),
        "missing_stage2": missing_stage2,
        "unsupported_cwe": unsupported_cwe,
        "mismatches": mismatches,
    }
    print(json.dumps(result, ensure_ascii=False, indent=2))
    if mismatches:
        raise SystemExit(1)


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def expected_categories(cwes: list[str]) -> set[str]:
    return {CWE_CATEGORY_MAP[cwe] for cwe in cwes if cwe in CWE_CATEGORY_MAP}


def load_rules(path: Path) -> list[dict[str, Any]]:
    record = json.loads(path.read_text(encoding="utf-8"))
    output = record.get("output", {})
    rules = output.get("rules", output.get("obligations", []))
    return rules if isinstance(rules, list) else []


if __name__ == "__main__":
    main()
