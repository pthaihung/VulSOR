from __future__ import annotations

import json
import unittest
from pathlib import Path
import shutil

from src.agents.Pipeline import VulSORPipeline
from src.agents.SemanticContract import SCHEMA_VERSION


class SemanticPipelineV2Tests(unittest.TestCase):
    def test_dry_run_writes_versioned_three_stage_artifacts(self) -> None:
        project_root = Path(__file__).resolve().parents[1]
        pipeline = VulSORPipeline(project_root, split="test", dry_run=True)
        temporary = project_root / "stages" / ".semantic-v2-test"
        shutil.rmtree(temporary, ignore_errors=True)
        try:
            pipeline.stage_root = temporary
            pipeline._ensure_stage_dirs()
            sample = pipeline.find_sample("test_000000")

            record = pipeline.run_sample(sample, up_to_stage=3)

            self.assertEqual(SCHEMA_VERSION, record["schema_version"])
            self.assertEqual("AnalysisFailure", record["output"]["label"])
            self.assertEqual("analysis_failure", record["output"]["decision_basis"])
            stage_files = list((pipeline.stage_root / "test_000000").glob("*.json"))
            self.assertEqual(3, len(stage_files))
            self.assertEqual(
                {
                    "stage_1_semantic_model.json",
                    "stage_2_rules.json",
                    "stage_3_obligation_adjudicator.json",
                },
                {path.name for path in stage_files},
            )

            semantic_record = pipeline._read_required_stage(sample, 1)
            self.assertIn("operation_contexts", semantic_record["output"])
            self.assertEqual([], semantic_record["output"]["operation_contexts"])

            rules_record = pipeline._read_required_stage(sample, 2)
            upstream = rules_record["artifact_metadata"]["upstream_hashes"]
            self.assertIn("semantic_model", upstream)
            self.assertIn("operation_contexts", upstream)
            self.assertEqual({"semantic_model", "operation_contexts"}, set(upstream))

            events: list[dict[str, object]] = []
            pipeline.run_sample(sample, up_to_stage=3, progress_callback=events.append)
            done = [event for event in events if event.get("event") == "stage_done"]
            self.assertEqual(["cached", "cached", "cached"], [event.get("status") for event in done])
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    def test_scripted_pipeline_carries_operation_contexts_to_all_final_decision_bases(self) -> None:
        expected_bases = {
            "violated": "confirmed_violation",
            "potentially_violated": "potential_violation",
            "satisfied": "established_safety",
        }
        for assessment, expected_basis in expected_bases.items():
            with self.subTest(assessment=assessment):
                pipeline, client, temporary = self._scripted_pipeline(assessment)
                try:
                    record = pipeline.run_sample(self._sample(), up_to_stage=3)

                    semantic_record = pipeline._read_required_stage(self._sample(), 1)
                    context = semantic_record["output"]["operation_contexts"]
                    rules_record = pipeline._read_required_stage(self._sample(), 2)
                    rule = rules_record["output"]["rules"][0]

                    self.assertEqual(["o1"], [item["operation_id"] for item in context])
                    self.assertEqual(["v1"], [item["id"] for item in context[0]["value_facts"]])
                    self.assertEqual("o1", rule["operation_id"])
                    self.assertEqual(expected_basis, record["output"]["decision_basis"])
                    self.assertFalse(record["output"]["analysis_failure"])
                    self.assertEqual(6, len(record["output"]["adjudications"][0]["output"]))
                    self.assertEqual(6, len(client.calls))
                    self.assertIn("operation_contexts", client.calls[4][-1].content)
                    self.assertIn("obligations", client.calls[5][-1].content)
                finally:
                    shutil.rmtree(temporary, ignore_errors=True)

    def test_invalid_adjudication_after_one_retry_is_analysis_failure_without_decision(self) -> None:
        invalid = {"adjudications": [{"obligation_id": "obligation_1"}]}
        pipeline, client, temporary = self._scripted_pipeline("satisfied", adjudicator_outputs=[invalid, invalid])
        try:
            record = pipeline.run_sample(self._sample(), up_to_stage=3)

            self.assertTrue(record["output"]["analysis_failure"])
            self.assertEqual("analysis_failure", record["output"]["decision_basis"])
            self.assertIsNone(record["output"]["decision"])
            self.assertIsNone(record["output"]["binary_prediction"])
            self.assertEqual([], record["output"]["adjudications"])
            self.assertEqual(7, len(client.calls))
            self.assertIn("The previous answer failed validation.", client.calls[-1][-1].content)
        finally:
            shutil.rmtree(temporary, ignore_errors=True)

    def _scripted_pipeline(
        self,
        assessment: str,
        adjudicator_outputs: list[dict[str, object]] | None = None,
    ) -> tuple[VulSORPipeline, "ScriptedClient", Path]:
        project_root = Path(__file__).resolve().parents[1]
        temporary = project_root / "stages" / ".semantic-v2-scripted-test"
        shutil.rmtree(temporary, ignore_errors=True)
        pipeline = VulSORPipeline(project_root, split="test", dry_run=True, output_root=temporary)
        client = ScriptedClient(self._scripted_outputs(assessment, adjudicator_outputs))
        for agent in pipeline.agents.values():
            agent.llm_client = client
        return pipeline, client, temporary

    @staticmethod
    def _sample() -> dict[str, object]:
        return {
            "sample_id": "scripted_sample",
            "code": "int read_at(int *p, int i) {\n    return p[i];\n}",
        }

    @staticmethod
    def _scripted_outputs(
        assessment: str,
        adjudicator_outputs: list[dict[str, object]] | None,
    ) -> list[dict[str, object]]:
        adjudication = {
            "obligation_id": "obligation_1",
            "assessment": assessment,
            "possibility": "when o1 executes, index i may be invalid for the indexed read",
            "supporting_evidence_refs": ["operation_agent.operations[0]", "value_agent.values[0]"],
            "contradicting_evidence_refs": [],
            "confirmation_gap": "the caller constraint that bounds i is not supplied" if assessment == "potentially_violated" else "",
        }
        return [
            {"operations": [{"id": "o1", "location": "L2", "entities": ["p", "i"], "claim": "read p[i]", "evidence": "L2: return p[i];"}]},
            {"states": []},
            {"values": [{"id": "v1", "location": "L1", "entities": ["i"], "claim": "i is a function input", "evidence": "L1: int read_at(int *p, int i) {", "operation_ids": ["o1"]}]},
            {"executions": []},
            {"obligations": [{"id": "obligation_1", "operation_id": "o1", "safety_requirement": "index i must be within the readable range of p", "applicable_condition": "when o1 executes", "evidence_refs": ["operation_agent.operations[0]", "value_agent.values[0]"]}]},
            *([{ "adjudications": [adjudication] }] if adjudicator_outputs is None else adjudicator_outputs),
        ]


class ScriptedClient:
    def __init__(self, outputs: list[dict[str, object]]) -> None:
        self.outputs = list(outputs)
        self.calls: list[list[object]] = []

    def chat_completion(self, messages: list[object], **_: object) -> dict[str, object]:
        self.calls.append(messages)
        if not self.outputs:
            raise AssertionError("scripted client received more requests than expected")
        return {"choices": [{"message": {"content": json.dumps(self.outputs.pop(0))}}]}


if __name__ == "__main__":
    unittest.main()
