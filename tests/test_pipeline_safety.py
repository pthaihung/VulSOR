from __future__ import annotations

import unittest

from src.agents.BaseAgent import _retry_token_multiplier
from src.agents.LLMClient import is_cacheable_response
from src.agents.Pipeline import aggregate_final_verdict
from src.agents.QualityGate import validate_nonempty_semantic_output


class PipelineSafetyTests(unittest.TestCase):
    def test_insufficient_evidence_abstains(self) -> None:
        verdict = aggregate_final_verdict([], {"status": "insufficient"})

        self.assertEqual("InsufficientEvidence", verdict["label"])
        self.assertIsNone(verdict["binary_prediction"])
        self.assertEqual(0, verdict["best_effort_binary_prediction"])

    def test_adequate_evidence_without_violation_is_benign(self) -> None:
        verdict = aggregate_final_verdict([], {"status": "adequate"})

        self.assertEqual("Benign", verdict["label"])
        self.assertEqual(0, verdict["binary_prediction"])

    def test_any_established_violation_is_vulnerable(self) -> None:
        adjudications = [
            {
                "rule": {"id": "obligation_1"},
                "output": {"obligation_id": "obligation_1", "violation": 1},
            }
        ]

        verdict = aggregate_final_verdict(adjudications, {"status": "adequate"})

        self.assertEqual("Vulnerable", verdict["label"])
        self.assertEqual(1, verdict["binary_prediction"])

    def test_empty_operation_output_is_rejected_when_source_has_signals(self) -> None:
        code = "int read_at(char *buffer, int index) { return buffer[index]; }"

        errors = validate_nonempty_semantic_output({"operations": []}, "operation_agent", code)

        self.assertTrue(errors)

    def test_empty_operation_output_is_allowed_without_operation_signals(self) -> None:
        code = "int constant(void) { return 1; }"

        errors = validate_nonempty_semantic_output({"operations": []}, "operation_agent", code)

        self.assertEqual([], errors)

    def test_length_response_is_not_cacheable(self) -> None:
        response = {
            "choices": [
                {
                    "finish_reason": "length",
                    "message": {"content": '{"operations":[]}'},
                }
            ]
        }

        self.assertFalse(is_cacheable_response(response))

    def test_complete_response_is_cacheable(self) -> None:
        response = {
            "choices": [
                {
                    "finish_reason": "stop",
                    "message": {"content": '{"operations":[]}'},
                }
            ]
        }

        self.assertTrue(is_cacheable_response(response))

    def test_length_retry_doubles_output_budget(self) -> None:
        self.assertEqual(2, _retry_token_multiplier(["LLM response is empty (finish_reason=length)"]))


if __name__ == "__main__":
    unittest.main()
