from __future__ import annotations

import unittest
from pathlib import Path

from src.agents.SimpleYaml import load_yaml


class PromptContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        root = Path(__file__).resolve().parents[1]
        prompt_root = root / "src" / "agents" / "prompts"
        cls.operation = load_yaml(prompt_root / "SemanticAgent" / "Operation_Agent.yml")
        cls.state = load_yaml(prompt_root / "SemanticAgent" / "State_Agent.yml")
        cls.value = load_yaml(prompt_root / "SemanticAgent" / "Value_Agent.yml")
        cls.execution = load_yaml(prompt_root / "SemanticAgent" / "Execution_Agent.yml")
        cls.reasoner = load_yaml(prompt_root / "Obligation_Reasoner.yml")
        cls.adjudicator = load_yaml(prompt_root / "Obligation_Adjudicator.yml")

    def test_semantic_prompts_have_no_fixed_claim_caps(self) -> None:
        for prompt in (self.operation, self.state, self.value, self.execution):
            text = prompt["system_prompt"].lower()
            self.assertNotIn("keep at most", text)
            self.assertIn("do not silently", text)

    def test_operation_defines_one_distinct_action_per_record(self) -> None:
        text = self.operation["system_prompt"].lower()
        self.assertIn("safety-check point", text)
        self.assertNotIn("prefer one useful derived claim", text)

    def test_semantic_fact_prompts_require_explicit_operation_ids(self) -> None:
        for prompt, collection in (
            (self.state, "states"),
            (self.value, "values"),
            (self.execution, "executions"),
        ):
            item_schema = prompt["output_schema"][collection][0]
            self.assertEqual(
                {"id", "location", "entities", "claim", "evidence", "operation_ids"},
                set(item_schema),
            )
            self.assertIn("operation_ids", prompt["system_prompt"])

    def test_reasoner_consumes_operation_contexts_directly(self) -> None:
        self.assertEqual({"operation_contexts_json"}, set(self.reasoner["inputs"]))
        self.assertIn("{operation_contexts_json}", self.reasoner["user_prompt_template"])

    def test_state_value_execution_boundaries_are_explicit(self) -> None:
        self.assertIn("do not derive state from control flow", self.state["system_prompt"].lower())
        self.assertIn("execution owns all control-flow-derived constraints", self.value["system_prompt"].lower())
        self.assertIn("may be modified between the guard and the operation", self.execution["system_prompt"].lower())
        self.assertNotIn("combine guards", self.value["system_prompt"].lower())

    def test_operation_anchors_define_relevance_not_truth(self) -> None:
        for prompt in (self.state, self.value, self.execution):
            self.assertIn("operation anchor only defines the analysis target", prompt["system_prompt"].lower())

    def test_reasoner_derives_obligations_without_evidence_bias_or_note(self) -> None:
        text = self.reasoner["system_prompt"].lower()
        self.assertIn("lack of supporting evidence must not", text)
        self.assertIn("strongest supported abstract requirement", text)
        self.assertNotIn("hard budget", text)
        self.assertNotIn("missing guard", text)
        item_schema = self.reasoner["output_schema"]["obligations"][0]
        self.assertNotIn("note", item_schema)
        self.assertEqual("o1", self.reasoner["user_prompt_template"].split("operation_id:", 1)[1].splitlines()[0].strip())

    def test_reasoner_contract_is_atomic_and_operation_centered(self) -> None:
        text = self.reasoner["system_prompt"].lower()
        item_schema = self.reasoner["output_schema"]["obligations"][0]

        self.assertIn("every operation context must produce at least one obligation", text)
        self.assertIn("atomic", text)
        self.assertIn("do not invent concrete sizes", text)
        self.assertEqual(
            {"id", "operation_id", "safety_requirement", "applicable_condition", "evidence_refs"},
            set(item_schema),
        )

    def test_adjudicator_uses_five_gate_tri_state_assessment(self) -> None:
        text = self.adjudicator["system_prompt"].lower()
        self.assertIn("five gates", text)
        self.assertIn("positive supplied semantic evidence", text)
        item_schema = self.adjudicator["output_schema"]["adjudications"][0]
        self.assertEqual({"obligation_id", "assessment", "possibility", "supporting_evidence_refs", "contradicting_evidence_refs", "confirmation_gap"}, set(item_schema))
        self.assertEqual("satisfied | violated | potentially_violated", item_schema["assessment"])


if __name__ == "__main__":
    unittest.main()
