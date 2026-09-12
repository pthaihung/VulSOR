from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scripts.eval_pipeline_metrics import evaluate_pipeline


class PipelineMetricsTests(unittest.TestCase):
    def test_reports_selective_binary_and_pipeline_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            labels = root / "labels.jsonl"
            labels.write_text(
                "\n".join(
                    [
                        json.dumps({"sample_id": "s1", "target": 1}),
                        json.dumps({"sample_id": "s2", "target": 0}),
                        json.dumps({"sample_id": "s3", "target": 1}),
                    ]
                ),
                encoding="utf-8",
            )
            self._write_sample(root, "s1", target=1, prediction=1, assessment="violated", decision_basis="confirmed_violation", decision="Vulnerable")
            self._write_sample(root, "s2", target=0, prediction=0, assessment="satisfied", decision_basis="established_safety", decision="Benign")
            self._write_sample(root, "s3", target=1, prediction=1, assessment="potentially_violated", decision_basis="potential_violation", decision="Vulnerable")

            result = evaluate_pipeline(labels, root)

            self.assertEqual(3, result["evaluation"]["expected_samples"])
            self.assertEqual(3, result["evaluation"]["selective"]["evaluated_samples"])
            self.assertEqual(1.0, result["evaluation"]["selective"]["accuracy"])
            self.assertEqual(1.0, result["evaluation"]["coverage"])
            self.assertEqual(0, result["evaluation"]["abstention_count"])
            self.assertEqual(3, result["pipeline"]["operation_count"])
            self.assertEqual(3, result["pipeline"]["obligation_count"])
            self.assertAlmostEqual(1 / 3, result["pipeline"]["potentially_violated_obligation_rate"])
            self.assertEqual(0.0, result["pipeline"]["analysis_failure_rate"])
            self.assertEqual(1.0, result["evaluation"]["confirmed_vulnerable"]["precision"])
            self.assertEqual(1.0, result["evaluation"]["potential_vulnerable"]["precision"])
            self.assertEqual(3, result["pipeline"]["tri_state_stage3_artifact_count"])
            self.assertEqual(0, result["pipeline"]["legacy_or_invalid_stage3_artifact_count"])
            self.assertEqual(30, result["tokens"]["total_tokens"])

    def test_excludes_missing_or_mismatched_decision_contracts_from_binary_metrics(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            labels = root / "labels.jsonl"
            labels.write_text("\n".join(json.dumps({"sample_id": sample_id, "target": target}) for sample_id, target in (("valid", 1), ("mismatch", 0), ("missing", 0))), encoding="utf-8")
            self._write_sample(root, "valid", target=1, prediction=1, assessment="violated", decision_basis="confirmed_violation", decision="Vulnerable")
            self._write_sample(root, "mismatch", target=0, prediction=0, assessment="satisfied", decision_basis="confirmed_violation", decision="Benign")
            self._write_sample(root, "missing", target=0, prediction=0, assessment="satisfied", decision_basis=None, decision="Benign")

            result = evaluate_pipeline(labels, root)

            self.assertEqual(1, result["evaluation"]["selective"]["evaluated_samples"])
            self.assertEqual(2, result["evaluation"]["abstention_count"])
            self.assertEqual(["mismatch", "missing"], result["evaluation"]["abstained_ids"])

    @staticmethod
    def _write_sample(
        root: Path,
        sample_id: str,
        *,
        target: int,
        prediction: int | None,
        assessment: str,
        decision_basis: str | None,
        decision: str,
    ) -> None:
        sample_dir = root / sample_id
        sample_dir.mkdir()
        stage1 = {
            "output": {
                "semantic_model": {
                    "operation_agent": {"operations": [{"id": "o1", "claim": "read p"}]},
                    "state_agent": {"states": [{"id": "s1", "claim": "p is input"}]},
                    "value_agent": {"values": []},
                    "execution_agent": {"executions": []},
                }
            },
            "token_usage": {"total_tokens": 5},
        }
        stage2 = {
            "output": {
                "rules": [
                    {
                        "id": "obligation_1",
                        "operation_id": "o1",
                        "evidence_refs": ["operation_agent.operations[0]"],
                    }
                ]
            },
            "token_usage": {"total_tokens": 3},
        }
        stage3 = {
            "output": {
                "binary_prediction": prediction,
                "decision_basis": decision_basis,
                "decision": decision,
                "adjudications": [
                    {"output": {"obligation_id": "obligation_1", "assessment": assessment, "refs": []}}
                ],
            },
            "token_usage": {"total_tokens": 2},
        }
        for number, name, value in (
            (1, "semantic_model", stage1),
            (2, "rules", stage2),
            (3, "obligation_adjudicator", stage3),
        ):
            (sample_dir / f"stage_{number}_{name}.json").write_text(json.dumps(value), encoding="utf-8")


if __name__ == "__main__":
    unittest.main()
