from __future__ import annotations

import argparse
import json
from pathlib import Path

from src.agents.Pipeline import read_jsonl
from src.agents.SimpleYaml import load_yaml
from src.agents.tools.LineLocatorTool import LineLocatorTool


def main() -> None:
    parser = argparse.ArgumentParser(description="Locate source lines for a name/expression inside a dataset sample.")
    parser.add_argument("query", help="Function, variable, expression, or evidence text to locate.")
    parser.add_argument("--sample-id", default="test_000000")
    parser.add_argument("--split", default="test", choices=["train", "valid", "test"])
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent
    sample = load_sample(project_root, args.split, args.sample_id)
    locator = LineLocatorTool(sample["code"])
    print(json.dumps({"sample_id": args.sample_id, "query": args.query, "matches": locator.locate(args.query)}, ensure_ascii=False, indent=2))


def load_sample(project_root: Path, split: str, sample_id: str) -> dict[str, object]:
    datasets = load_yaml(project_root / "config" / "datasets.yml")
    active_dataset = datasets["defaults"]["active_dataset"]
    input_file = datasets["datasets"][active_dataset]["splits"][split]["input_file"]
    for sample in read_jsonl(project_root / input_file):
        if sample.get("sample_id") == sample_id:
            return sample
    raise ValueError(f"Sample not found: {sample_id}")


if __name__ == "__main__":
    main()
