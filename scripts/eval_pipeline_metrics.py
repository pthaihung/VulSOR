from __future__ import annotations

import argparse
import json
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable


STAGE_FILES = {
    1: "stage_1_semantic_model.json",
    2: "stage_2_rules.json",
    3: "stage_3_obligation_adjudicator.json",
}
COLLECTIONS = {
    "operation_agent": "operations",
    "state_agent": "states",
    "value_agent": "values",
    "execution_agent": "executions",
}


def main() -> None:
    parser = argparse.ArgumentParser(description="Evaluate VulSOR predictions, coverage, structure, and token use.")
    parser.add_argument("--project-root", default=".")
    parser.add_argument("--stage-root", default=None, help="Defaults to stages under project root.")
    parser.add_argument("--split", default="test", choices=["train", "valid", "test"])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output", type=Path, default=None)
    parser.add_argument("--summary-dir", type=Path, default=None, help="Defaults to stages/summary.")
    parser.add_argument("--baseline", action="append", default=[], help="Baseline row as Name=metrics.json. Metrics may be this script's JSON output or a flat metric dict.")
    args = parser.parse_args()

    project_root = Path(args.project_root).resolve()
    stage_root = Path(args.stage_root) if args.stage_root is not None else project_root / "stages"
    if not stage_root.is_absolute():
        stage_root = project_root / stage_root
    labels_path = project_root / "data" / "PrimeVul_clean" / "labels" / f"{args.split}.jsonl"
    context_path = project_root / "data" / "build_context" / "context_clean" / f"{args.split}.jsonl"
    result = evaluate_pipeline(labels_path, stage_root, limit=args.limit, context_path=context_path, project_root=project_root)
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output is not None:
        output_path = args.output if args.output.is_absolute() else project_root / args.output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
    summary_dir = args.summary_dir if args.summary_dir is not None else project_root / "stages" / "summary"
    if not summary_dir.is_absolute():
        summary_dir = project_root / summary_dir
    written, result = write_summary_artifacts(summary_dir, args.split, result, load_baselines(args.baseline), project_root)
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output is not None:
        output_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


def evaluate_pipeline(
    labels_path: Path,
    stage_root: Path,
    limit: int | None = None,
    context_path: Path | None = None,
    project_root: Path | None = None,
    sample_ids: set[str] | None = None,
) -> dict[str, Any]:
    labels = list(read_jsonl(labels_path))
    if limit is not None:
        labels = labels[:limit]
    if sample_ids is not None:
        labels = [label for label in labels if str(label.get("sample_id")) in sample_ids]

    selective_pairs: list[tuple[int, int]] = []
    confirmed_vulnerable_pairs: list[tuple[int, int]] = []
    potential_vulnerable_pairs: list[tuple[int, int]] = []
    missing_stage3: list[str] = []
    abstained_ids: list[str] = []
    claim_counts = Counter({agent: 0 for agent in COLLECTIONS})
    normalized_claim_counts: Counter[str] = Counter()
    operation_count = 0
    obligation_count = 0
    operations_without_obligations = 0
    evidence_ref_count = 0
    assessment_counts = Counter({name: 0 for name in ("satisfied", "violated", "potentially_violated", "legacy_or_invalid")})
    analysis_failure_count = 0
    tri_state_artifact_count = 0
    token_by_stage = {str(stage): {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0} for stage in STAGE_FILES}
    decided_predictions: dict[str, int] = {}

    for label in labels:
        sample_id = str(label.get("sample_id"))
        target = int(label.get("target", 0))
        sample_dir = stage_root / sample_id
        records = {stage: read_json(sample_dir / filename) for stage, filename in STAGE_FILES.items()}
        stage3 = records[3]
        if stage3 is None:
            missing_stage3.append(sample_id)
        else:
            output = stage3.get("output", {})
            artifact_uses_tri_state = True
            prediction = output.get("binary_prediction")
            decision_basis = output.get("decision_basis")
            if is_decided_binary_output(output):
                prediction_int = int(prediction)
                decided_predictions[sample_id] = prediction_int
                selective_pairs.append((target, prediction_int))
                if decision_basis in {"confirmed_violation", "violated_obligation"}:
                    confirmed_vulnerable_pairs.append((target, prediction_int))
                elif decision_basis == "potential_violation":
                    potential_vulnerable_pairs.append((target, prediction_int))
            else:
                abstained_ids.append(sample_id)
            if output.get("decision_basis") == "analysis_failure" or output.get("analysis_failure"):
                analysis_failure_count += 1
            for assessment in iter_stage3_assessments(output):
                if assessment in assessment_counts:
                    assessment_counts[assessment] += 1
                else:
                    assessment_counts["legacy_or_invalid"] += 1
                    artifact_uses_tri_state = False
            if artifact_uses_tri_state:
                tri_state_artifact_count += 1

        stage1 = records[1]
        operations_for_sample: set[str] = set()
        if stage1 is not None:
            model = stage1.get("output", {}).get("semantic_model", {})
            for agent, collection in COLLECTIONS.items():
                claims = semantic_claims(model, agent, collection)
                if not isinstance(claims, list):
                    continue
                claim_counts[agent] += len(claims)
                for index, claim in enumerate(claims):
                    if not isinstance(claim, dict):
                        continue
                    normalized = normalize_claim(claim.get("claim"))
                    if normalized:
                        normalized_claim_counts[f"{sample_id}:{normalized}"] += 1
                    if agent == "operation_agent":
                        operations_for_sample.add(str(claim.get("id") or f"operation_index_{index}"))
            operation_count += len(operations_for_sample)

        stage2 = records[2]
        covered_operations: set[str] = set()
        if stage2 is not None:
            rules_output = stage2.get("output", {})
            rules = rules_output.get("rules", rules_output.get("obligations", []))
            if isinstance(rules, list):
                obligation_count += len(rules)
                for rule in rules:
                    if not isinstance(rule, dict):
                        continue
                    if rule.get("operation_id"):
                        covered_operations.add(str(rule["operation_id"]))
                    elif rule.get("expression") or rule.get("locations"):
                        covered_operations.add(f"operation_index_{len(covered_operations)}")
                    refs = rule.get("evidence_refs", [])
                    evidence_ref_count += len(refs) if isinstance(refs, list) else 0
                    requirements = rule.get("requirements", [])
                    evidence_ref_count += len(requirements) if isinstance(requirements, list) else 0
        operations_without_obligations += len(operations_for_sample - covered_operations)

        for stage, record in records.items():
            if record is None:
                continue
            usage = record.get("token_usage", {})
            for key in ("input_tokens", "output_tokens", "total_tokens"):
                token_by_stage[str(stage)][key] += int(usage.get(key, 0) or 0)

    expected = len(labels)
    evaluated = len(selective_pairs)
    total_claims = sum(claim_counts.values())
    duplicate_claim_count = sum(count - 1 for count in normalized_claim_counts.values() if count > 1)
    total_assessments = sum(assessment_counts.values())
    total_tokens = {
        key: sum(stage_usage[key] for stage_usage in token_by_stage.values())
        for key in ("input_tokens", "output_tokens", "total_tokens")
    }
    return {
        "evaluation": {
            "expected_samples": expected,
            "missing_stage3_count": len(missing_stage3),
            "missing_stage3_ids": missing_stage3,
            "coverage": safe_div(evaluated, expected),
            "abstention_count": expected - evaluated,
            "abstention_rate": safe_div(expected - evaluated, expected),
            "abstained_ids": abstained_ids,
            "selective": classification_metrics(selective_pairs),
            "confirmed_vulnerable": classification_metrics(confirmed_vulnerable_pairs),
            "potential_vulnerable": classification_metrics(potential_vulnerable_pairs),
            "pairwise": pairwise_metrics(labels, decided_predictions),
        },
        "pipeline": {
            "sample_count": expected,
            "operation_count": operation_count,
            "operations_per_sample": safe_div(operation_count, expected),
            "claim_count_by_agent": dict(claim_counts),
            "claims_per_sample_by_agent": {agent: safe_div(count, expected) for agent, count in claim_counts.items()},
            "support_claims_per_operation": safe_div(total_claims - operation_count, operation_count),
            "duplicate_claim_count": duplicate_claim_count,
            "duplicate_claim_rate": safe_div(duplicate_claim_count, total_claims),
            "obligation_count": obligation_count,
            "obligations_per_operation": safe_div(obligation_count, operation_count),
            "operations_without_obligations": operations_without_obligations,
            "operations_without_obligations_rate": safe_div(operations_without_obligations, operation_count),
            "assessment_count_by_state": dict(assessment_counts),
            "tri_state_stage3_artifact_count": tri_state_artifact_count,
            "legacy_or_invalid_stage3_artifact_count": expected - len(missing_stage3) - tri_state_artifact_count,
            "satisfied_obligation_rate": safe_div(assessment_counts["satisfied"], total_assessments),
            "violated_obligation_rate": safe_div(assessment_counts["violated"], total_assessments),
            "potentially_violated_obligation_rate": safe_div(assessment_counts["potentially_violated"], total_assessments),
            "analysis_failure_count": analysis_failure_count,
            "analysis_failure_rate": safe_div(analysis_failure_count, expected),
            "evidence_refs_per_obligation": safe_div(evidence_ref_count, obligation_count),
        },
        "tokens": {
            "by_stage": token_by_stage,
            **total_tokens,
            "average_input_tokens_per_sample": safe_div(total_tokens["input_tokens"], expected),
            "average_output_tokens_per_sample": safe_div(total_tokens["output_tokens"], expected),
            "average_total_tokens_per_sample": safe_div(total_tokens["total_tokens"], expected),
        },
        "retrieval": retrieval_metrics(context_path, labels, project_root=project_root),
    }


def classification_metrics(pairs: list[tuple[int, int]]) -> dict[str, Any]:
    tp = sum(target == 1 and prediction == 1 for target, prediction in pairs)
    fp = sum(target == 0 and prediction == 1 for target, prediction in pairs)
    tn = sum(target == 0 and prediction == 0 for target, prediction in pairs)
    fn = sum(target == 1 and prediction == 0 for target, prediction in pairs)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    specificity = safe_div(tn, tn + fp)
    return {
        "evaluated_samples": len(pairs),
        "tp": tp,
        "fp": fp,
        "tn": tn,
        "fn": fn,
        "accuracy": safe_div(tp + tn, len(pairs)),
        "precision": precision,
        "recall": recall,
        "fpr": safe_div(fp, fp + tn),
        "f1": safe_div(2 * precision * recall, precision + recall),
        "specificity": specificity,
        "balanced_accuracy": (recall + specificity) / 2 if (tp + fn) and (tn + fp) else None,
    }


def pairwise_metrics(labels: list[dict[str, Any]], predictions_by_sample_id: dict[str, int]) -> dict[str, Any]:
    pairs: dict[str, dict[int, tuple[str, int]]] = {}
    for label in labels:
        pair_id = label.get("pair_id")
        sample_id = label.get("sample_id")
        if pair_id is None or sample_id is None:
            continue
        target = int(label.get("target", 0) or 0)
        prediction = predictions_by_sample_id.get(str(sample_id))
        if prediction is None:
            continue
        pairs.setdefault(str(pair_id), {})[target] = (str(sample_id), int(prediction))

    evaluated = 0
    correct = 0
    reversed_count = 0
    for pair in pairs.values():
        if 0 not in pair or 1 not in pair:
            continue
        evaluated += 1
        vulnerable_prediction = pair[1][1]
        fixed_prediction = pair[0][1]
        if vulnerable_prediction == 1 and fixed_prediction == 0:
            correct += 1
        elif vulnerable_prediction == 0 and fixed_prediction == 1:
            reversed_count += 1

    pairwise_correct = safe_div(correct, evaluated)
    pairwise_reversed = safe_div(reversed_count, evaluated)
    return {
        "evaluated_pairs": evaluated,
        "pairwise_correct_count": correct,
        "pairwise_reversed_count": reversed_count,
        "pairwise_correct": pairwise_correct,
        "pairwise_reversed": pairwise_reversed,
        "vulnerability_pairwise_score": pairwise_correct - pairwise_reversed,
    }


def retrieval_metrics(
    context_path: Path | None,
    labels: list[dict[str, Any]],
    project_root: Path | None = None,
) -> dict[str, Any]:
    expected_samples = len(labels)
    context_file = repo_relative_path(context_path, project_root) if context_path is not None else None
    if context_path is None or not context_path.exists():
        return {
            "context_file": context_file,
            "samples_with_context": 0,
            "retrieval_trigger_rate": 0.0,
            "context_item_count": 0,
            "average_context_items_per_sample": 0.0,
            "context_json_bytes": 0,
            "average_context_json_bytes_per_sample": 0.0,
            "repository_query_count": None,
            "joern_overhead_seconds": None,
        }

    context_by_sample = {str(item.get("sample_id")): item for item in read_jsonl(context_path)}
    samples_with_context = 0
    context_item_count = 0
    context_json_bytes = 0
    repository_query_count = 0
    has_query_count = False
    for label in labels:
        sample_id = str(label.get("sample_id"))
        record = context_by_sample.get(sample_id)
        if not record:
            continue
        context = record.get("context")
        if not context:
            continue
        samples_with_context += 1
        context_item_count += count_context_items(context)
        context_json = json.dumps(context, ensure_ascii=False, separators=(",", ":"))
        context_json_bytes += len(context_json.encode("utf-8"))
        query_count = extract_query_count(record)
        if query_count is not None:
            repository_query_count += query_count
            has_query_count = True

    return {
        "context_file": context_file,
        "samples_with_context": samples_with_context,
        "retrieval_trigger_rate": safe_div(samples_with_context, expected_samples),
        "context_item_count": context_item_count,
        "average_context_items_per_sample": safe_div(context_item_count, expected_samples),
        "context_json_bytes": context_json_bytes,
        "average_context_json_bytes_per_sample": safe_div(context_json_bytes, expected_samples),
        "repository_query_count": repository_query_count if has_query_count else None,
        "joern_overhead_seconds": None,
    }


def count_context_items(value: Any) -> int:
    if isinstance(value, dict):
        total = 0
        for child in value.values():
            if isinstance(child, list):
                total += len(child)
            elif isinstance(child, dict):
                total += count_context_items(child)
        return total
    if isinstance(value, list):
        return len(value)
    return 0


def extract_query_count(record: dict[str, Any]) -> int | None:
    for key in ("repository_query_count", "repo_query_count", "query_count"):
        if key in record:
            return int(record.get(key) or 0)
    metadata = record.get("metadata")
    if isinstance(metadata, dict):
        for key in ("repository_query_count", "repo_query_count", "query_count"):
            if key in metadata:
                return int(metadata.get(key) or 0)
    return None


def load_baselines(values: list[str]) -> list[dict[str, Any]]:
    baselines = []
    for value in values:
        name, sep, path_text = value.partition("=")
        if not sep or not name.strip() or not path_text.strip():
            raise SystemExit(f"Invalid --baseline value {value!r}; expected Name=metrics.json")
        path = Path(path_text)
        data = json.loads(path.read_text(encoding="utf-8"))
        baselines.append({"name": name.strip(), "metrics": data})
    return baselines


def write_summary_artifacts(
    summary_dir: Path,
    split: str,
    result: dict[str, Any],
    baselines: list[dict[str, Any]],
    project_root: Path,
) -> tuple[list[Path], dict[str, Any]]:
    summary_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    prefix = summary_dir / f"{timestamp}_{split}_metrics"
    json_path = prefix.with_suffix(".json")
    markdown_path = prefix.with_suffix(".md")
    written = [json_path, markdown_path]
    output_result = dict(result)
    output_result["summary_artifacts"] = [repo_relative_path(path, project_root) for path in written]
    rows = build_comparison_rows(output_result, baselines)
    markdown = render_markdown_report(output_result, rows)
    json_path.write_text(json.dumps(output_result, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    markdown_path.write_text(markdown + "\n", encoding="utf-8")
    return written, output_result


def build_comparison_rows(result: dict[str, Any], baselines: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rows = [paper_row("VulSOR", result)]
    rows.extend(paper_row(item["name"], item["metrics"]) for item in baselines)
    return rows


def paper_row(name: str, result: dict[str, Any]) -> dict[str, Any]:
    metrics = result.get("evaluation", {}).get("selective", result.get("selective", result))
    pairwise = result.get("evaluation", {}).get("pairwise", result.get("pairwise", {}))
    retrieval = result.get("retrieval", {})
    tokens = result.get("tokens", {})
    return {
        "method": name,
        "samples": metrics.get("evaluated_samples", result.get("evaluated_samples")),
        "acc": metrics.get("accuracy", result.get("accuracy")),
        "precision": metrics.get("precision", result.get("precision")),
        "recall": metrics.get("recall", result.get("recall")),
        "f1": metrics.get("f1", result.get("f1")),
        "fpr": metrics.get("fpr", result.get("fpr")),
        "pc": pairwise.get("pairwise_correct", result.get("pairwise_correct")),
        "pr": pairwise.get("pairwise_reversed", result.get("pairwise_reversed")),
        "vps": pairwise.get("vulnerability_pairwise_score", result.get("vulnerability_pairwise_score")),
        "retrieval_rate": retrieval.get("retrieval_trigger_rate", result.get("retrieval_trigger_rate")),
        "context_items": retrieval.get("context_item_count", result.get("context_item_count")),
        "repo_queries": retrieval.get("repository_query_count", result.get("repository_query_count")),
        "input_tokens_per_sample": tokens.get("average_input_tokens_per_sample", result.get("average_input_tokens_per_sample")),
        "output_tokens_per_sample": tokens.get("average_output_tokens_per_sample", result.get("average_output_tokens_per_sample")),
        "tokens_per_sample": tokens.get("average_total_tokens_per_sample", result.get("average_total_tokens_per_sample")),
        "joern_seconds": retrieval.get("joern_overhead_seconds", result.get("joern_overhead_seconds")),
    }


def render_markdown_report(result: dict[str, Any], rows: list[dict[str, Any]]) -> str:
    sections = [
        "# VulSOR Evaluation Summary",
        "",
        "## Table 1. Classification Performance",
        markdown_table(rows, ["method", "samples", "acc", "precision", "recall", "f1", "fpr"]),
        "",
        "## Table 2. Vulnerable-Fixed Pair Performance",
        markdown_table(rows, ["method", "pc", "pr", "vps"]),
        "",
        "## Table 3. Retrieval And Cost",
        markdown_table(rows, ["method", "retrieval_rate", "context_items", "repo_queries", "input_tokens_per_sample", "output_tokens_per_sample", "tokens_per_sample", "joern_seconds"]),
        "",
        "## Notes",
        "- ACC = (TP + TN) / (TP + TN + FP + FN).",
        "- F1 = 2 * Precision * Recall / (Precision + Recall).",
        "- FPR = FP / (FP + TN).",
        "- P-C is pair-wise correct prediction, P-R is pair-wise reversed prediction, VPS = P-C - P-R.",
        "- Token columns are per-sample averages split into input, output, and total tokens.",
        "- Repository query count and Joern overhead are reported as N/A when the artifacts do not contain those measurements.",
        "",
        "## Raw Counts",
        "```json",
        json.dumps(result, ensure_ascii=False, indent=2),
        "```",
    ]
    return "\n".join(sections)


def markdown_table(rows: list[dict[str, Any]], keys: list[str]) -> str:
    headers = [display_name(key) for key in keys]
    lines = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(format_cell(row.get(key)) for key in keys) + " |")
    return "\n".join(lines)


def display_name(key: str) -> str:
    return {
        "method": "Method",
        "samples": "N",
        "acc": "ACC",
        "precision": "Precision",
        "recall": "Recall",
        "f1": "F1",
        "fpr": "FPR",
        "pc": "P-C",
        "pr": "P-R",
        "vps": "VPS",
        "retrieval_rate": "Retrieval",
        "context_items": "Ctx.",
        "repo_queries": "Queries",
        "input_tokens_per_sample": "Input tok/sample",
        "output_tokens_per_sample": "Output tok/sample",
        "tokens_per_sample": "Total tok/sample",
        "joern_seconds": "Joern s",
    }.get(key, key)


def format_cell(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def repo_relative_path(path: Path, project_root: Path | None) -> str:
    if project_root is None:
        return str(path)
    try:
        return str(path.resolve().relative_to(project_root.resolve()))
    except ValueError:
        return str(path)


def is_decided_binary_output(output: dict[str, Any]) -> bool:
    expected_decisions = {
        "confirmed_violation": ("Vulnerable", 1),
        "potential_violation": ("Vulnerable", 1),
        "established_safety": ("Benign", 0),
        "violated_obligation": ("Vulnerable", 1),
        "all_obligations_satisfied": ("Benign", 0),
        "no_security_relevant_obligations": ("Benign", 0),
        "no_nontrivial_reasoning_operations": ("Benign", 0),
    }
    expected = expected_decisions.get(output.get("decision_basis"))
    return expected is not None and (output.get("decision"), output.get("binary_prediction")) == expected


def semantic_claims(model: Any, agent: str, collection: str) -> list[Any]:
    if not isinstance(model, dict):
        return []
    nested = model.get(agent)
    if isinstance(nested, dict) and isinstance(nested.get(collection), list):
        return nested[collection]
    top_level = model.get(collection)
    return top_level if isinstance(top_level, list) else []


def iter_stage3_assessments(output: dict[str, Any]) -> list[Any]:
    assessments = output.get("assessments")
    if isinstance(assessments, list):
        return assessments
    result: list[Any] = []
    for adjudication in output.get("adjudications", []):
        if not isinstance(adjudication, dict):
            continue
        result.append(adjudication.get("output", adjudication).get("assessment"))
    return result


def safe_div(numerator: int | float, denominator: int | float) -> float:
    return float(numerator) / float(denominator) if denominator else 0.0


def normalize_claim(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def read_json(path: Path) -> dict[str, Any] | None:
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            if line.strip():
                yield json.loads(line)


if __name__ == "__main__":
    main()
