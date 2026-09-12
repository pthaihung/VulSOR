from __future__ import annotations

import argparse
import json
import re
from collections import Counter
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
    parser.add_argument("--stage-root", default=None, help="Defaults to stages/semantic-v2 under project root.")
    parser.add_argument("--split", default="test", choices=["train", "valid", "test"])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()

    project_root = Path(args.project_root).resolve()
    stage_root = Path(args.stage_root) if args.stage_root is not None else project_root / "stages" / "semantic-v2"
    if not stage_root.is_absolute():
        stage_root = project_root / stage_root
    labels_path = project_root / "data" / "PrimeVul_clean" / "labels" / f"{args.split}.jsonl"
    result = evaluate_pipeline(labels_path, stage_root, limit=args.limit)
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    if args.output is not None:
        output_path = args.output if args.output.is_absolute() else project_root / args.output
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


def evaluate_pipeline(labels_path: Path, stage_root: Path, limit: int | None = None) -> dict[str, Any]:
    labels = list(read_jsonl(labels_path))
    if limit is not None:
        labels = labels[:limit]

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
                selective_pairs.append((target, int(prediction)))
                if decision_basis == "confirmed_violation":
                    confirmed_vulnerable_pairs.append((target, int(prediction)))
                elif decision_basis == "potential_violation":
                    potential_vulnerable_pairs.append((target, int(prediction)))
            else:
                abstained_ids.append(sample_id)
            if output.get("decision_basis") == "analysis_failure" or output.get("analysis_failure"):
                analysis_failure_count += 1
            for adjudication in output.get("adjudications", []):
                if not isinstance(adjudication, dict):
                    continue
                assessment = adjudication.get("output", adjudication).get("assessment")
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
                claims = model.get(agent, {}).get(collection, [])
                if not isinstance(claims, list):
                    continue
                claim_counts[agent] += len(claims)
                for claim in claims:
                    if not isinstance(claim, dict):
                        continue
                    normalized = normalize_claim(claim.get("claim"))
                    if normalized:
                        normalized_claim_counts[f"{sample_id}:{normalized}"] += 1
                    if agent == "operation_agent" and claim.get("id"):
                        operations_for_sample.add(str(claim["id"]))
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
                    refs = rule.get("evidence_refs", [])
                    evidence_ref_count += len(refs) if isinstance(refs, list) else 0
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
            "average_total_tokens_per_sample": safe_div(total_tokens["total_tokens"], expected),
        },
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
        "f1": safe_div(2 * precision * recall, precision + recall),
        "specificity": specificity,
        "balanced_accuracy": (recall + specificity) / 2 if (tp + fn) and (tn + fp) else None,
    }


def is_decided_binary_output(output: dict[str, Any]) -> bool:
    expected_decisions = {
        "confirmed_violation": ("Vulnerable", 1),
        "potential_violation": ("Vulnerable", 1),
        "established_safety": ("Benign", 0),
    }
    expected = expected_decisions.get(output.get("decision_basis"))
    return expected is not None and (output.get("decision"), output.get("binary_prediction")) == expected


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
