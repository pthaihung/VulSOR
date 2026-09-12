from __future__ import annotations

import unittest

from src.agents.BaseAgent import _retry_token_multiplier
from src.agents.LLMClient import is_cacheable_response
from src.agents.Pipeline import VulSORPipeline, aggregate_final_verdict, assess_evidence_status
from src.agents.QualityGate import validate_semantic_claim_output


class PipelineSafetyTests(unittest.TestCase):
    def test_potential_violation_is_a_vulnerable_decision(self) -> None:
        adjudications = [
            {
                "rule": {"id": "obligation_1"},
                "output": {"obligation_id": "obligation_1", "assessment": "potentially_violated", "possibility": "may be unsafe", "supporting_evidence_refs": ["operation_agent.operations[0]"], "contradicting_evidence_refs": [], "confirmation_gap": "path is unresolved"},
            }
        ]
        verdict = aggregate_final_verdict(adjudications, {"status": "adequate"})

        self.assertEqual("Vulnerable", verdict["label"])
        self.assertEqual(1, verdict["binary_prediction"])
        self.assertEqual("potential_violation", verdict["decision_basis"])
        self.assertEqual(["obligation_1"], verdict["triggering_obligations"])

    def test_all_satisfied_obligations_are_benign(self) -> None:
        adjudications = [
            {
                "rule": {"id": "obligation_1"},
                "output": {"obligation_id": "obligation_1", "assessment": "satisfied", "possibility": "safe", "supporting_evidence_refs": ["operation_agent.operations[0]"], "contradicting_evidence_refs": [], "confirmation_gap": ""},
            }
        ]
        verdict = aggregate_final_verdict(adjudications, {"status": "adequate"})

        self.assertEqual("Benign", verdict["label"])
        self.assertEqual(0, verdict["binary_prediction"])
        self.assertEqual("established_safety", verdict["decision_basis"])
        self.assertEqual([], verdict["triggering_obligations"])

    def test_any_established_violation_is_vulnerable(self) -> None:
        adjudications = [
            {
                "rule": {"id": "obligation_1"},
                "output": {"obligation_id": "obligation_1", "assessment": "violated", "possibility": "unsafe", "supporting_evidence_refs": ["operation_agent.operations[0]"], "contradicting_evidence_refs": [], "confirmation_gap": ""},
            }
        ]

        verdict = aggregate_final_verdict(adjudications, {"status": "adequate"})

        self.assertEqual("Vulnerable", verdict["label"])
        self.assertEqual(1, verdict["binary_prediction"])
        self.assertEqual("confirmed_violation", verdict["decision_basis"])
        self.assertEqual(["obligation_1"], verdict["triggering_obligations"])

    def test_no_adjudications_is_an_analysis_failure(self) -> None:
        verdict = aggregate_final_verdict([], {"status": "adequate"})

        self.assertEqual("AnalysisFailure", verdict["label"])
        self.assertIsNone(verdict["binary_prediction"])
        self.assertEqual("analysis_failure", verdict["decision_basis"])

    def test_any_confirmed_violation_takes_precedence_over_potential_violation(self) -> None:
        adjudications = [
            {
                "rule": {"id": "obligation_1"},
                "output": {"obligation_id": "obligation_1", "assessment": "potentially_violated", "possibility": "may be unsafe", "supporting_evidence_refs": ["operation_agent.operations[0]"], "contradicting_evidence_refs": [], "confirmation_gap": "path is unresolved"},
            }
        ]
        adjudications.append(
            {
                "rule": {"id": "obligation_2"},
                "output": {"obligation_id": "obligation_2", "assessment": "violated", "possibility": "the indexed read executes with a negative index", "supporting_evidence_refs": ["operation_agent.operations[0]"], "contradicting_evidence_refs": [], "confirmation_gap": ""},
            }
        )
        verdict = aggregate_final_verdict(adjudications, {"status": "adequate"})
        self.assertEqual("confirmed_violation", verdict["decision_basis"])
        self.assertEqual(["obligation_2"], verdict["triggering_obligations"])

    def test_duplicate_or_invalid_adjudications_are_analysis_failures(self) -> None:
        adjudications = [
            {"rule": {"id": "obligation_1"}, "output": {"obligation_id": "obligation_1", "assessment": "satisfied"}},
            {"rule": {"id": "obligation_1"}, "output": {"obligation_id": "obligation_1", "assessment": "unknown"}},
        ]
        verdict = aggregate_final_verdict(adjudications, {"status": "adequate"})
        self.assertEqual("AnalysisFailure", verdict["label"])
        self.assertIsNone(verdict["binary_prediction"])
        self.assertEqual("analysis_failure", verdict["decision_basis"])

    def test_missing_required_adjudication_is_an_analysis_failure(self) -> None:
        adjudications = [
            {"rule": {"id": "obligation_1"}, "output": {"obligation_id": "obligation_1", "assessment": "satisfied"}},
        ]
        verdict = aggregate_final_verdict(
            adjudications,
            {"status": "adequate"},
            expected_obligation_ids=["obligation_1", "obligation_2"],
        )
        self.assertEqual("AnalysisFailure", verdict["label"])
        self.assertIsNone(verdict["binary_prediction"])

    def test_incomplete_satisfied_adjudication_is_an_analysis_failure(self) -> None:
        verdict = aggregate_final_verdict(
            [{"rule": {"id": "obligation_1"}, "output": {"obligation_id": "obligation_1", "assessment": "satisfied"}}],
            {"status": "adequate"},
        )
        self.assertEqual("AnalysisFailure", verdict["label"])
        self.assertIsNone(verdict["binary_prediction"])

    def test_analysis_failure_is_explicit_and_never_fabricates_an_assessment(self) -> None:
        status = assess_evidence_status(
            {"status": "adequate", "reasons": []},
            {"output": {"rules": [{"id": "obligation_1"}]}},
            [],
            [{"stage": "Stage 3", "agent_key": "obligation_adjudicator", "error": "invalid batch"}],
        )

        self.assertEqual("insufficient", status["status"])
        self.assertTrue(any("adjudicator failed" in reason for reason in status["reasons"]))

    def test_stage3_validation_failure_writes_an_explicit_failure_record(self) -> None:
        class InvalidAdjudicator:
            def run(self, *args, **kwargs):
                raise ValueError("ObligationAdjudicator output failed validation: invalid batch")

        operation = {
            "id": "o1",
            "location": "L1",
            "entities": ["i"],
            "claim": "reads i",
            "evidence": "1: read(i);",
        }
        semantic_record = {
            "output": {
                "semantic_model": {"operation_agent": {"operations": [operation]}},
                "operation_contexts": [{"operation_id": "o1", "operation": operation, "state_facts": [], "value_facts": [], "execution_facts": []}],
            },
            "quality_gate": {"status": "passed"},
        }
        rules_record = {
            "output": {"rules": [{"id": "r1", "operation_id": "o1", "safety_requirement": "i must be non-negative", "applicable_condition": "when o1 executes", "evidence_refs": ["operation_agent.operations[0]"]}]},
            "quality_gate": {"status": "passed"},
        }
        pipeline = object.__new__(VulSORPipeline)
        pipeline.agents = {"obligation_adjudicator": InvalidAdjudicator()}
        pipeline._read_required_stage = lambda sample, stage: semantic_record if stage == 1 else rules_record
        pipeline.ground_truth_for_sample = lambda sample_id: None
        pipeline._artifact_metadata_for = lambda *args, **kwargs: {}
        pipeline._write_stage_json = lambda *args, **kwargs: None

        record = pipeline.run_stage_3({"sample_id": "x", "code": "read(i);"})

        self.assertTrue(record["output"]["analysis_failure"])
        self.assertEqual("failed", record["quality_gate"]["status"])
        self.assertEqual([], record["output"]["adjudications"])
        self.assertIsNone(record["output"]["binary_prediction"])
        self.assertEqual("analysis_failure", record["output"]["decision_basis"])

    def test_empty_operation_output_is_structurally_valid_even_when_source_has_signals(self) -> None:
        self.assertEqual([], validate_semantic_claim_output({"operations": []}, "operation_agent", 1))

    def test_pipeline_does_not_reject_empty_semantic_output_from_source_regexes(self) -> None:
        captured_errors: list[str] = []

        class EmptyOperationAgent:
            def run(self, variables, extra_validators, **kwargs):
                parsed = {"operations": []}
                for validator in extra_validators:
                    captured_errors.extend(validator(parsed))
                return {"parsed": parsed, "quality_gate": {}}

        pipeline = object.__new__(VulSORPipeline)
        pipeline.agents = {"operation_agent": EmptyOperationAgent()}

        pipeline._run_agent(
            "operation_agent",
            {},
            source_code="int read_at(char *buffer, int index) { return buffer[index]; }",
            max_line=1,
        )

        self.assertEqual([], captured_errors)

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
