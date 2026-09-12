from __future__ import annotations

import unittest

from src.agents.Pipeline import (
    add_anchor_line_windows,
    compact_fact_for_adjudicator,
    filter_evidence_for_obligation,
    supplied_evidence_refs,
    validate_batch_adjudications,
    validate_obligation_evidence_refs,
)


class ClaimConsumerTests(unittest.TestCase):
    def setUp(self) -> None:
        self.model = {
            "operation_agent": {"operations": [{"id": "o1", "location": "L4", "entities": ["p", "i"], "claim": "read p[i]", "evidence": "L4: return p[i];"}]},
            "state_agent": {"states": [{"id": "s1", "location": "L2", "entities": ["p"], "claim": "p is the input pointer", "evidence": "L2: int *p"}]},
            "value_agent": {"values": []},
            "execution_agent": {"executions": []},
        }

    def test_stage3_payload_keeps_all_claim_fields(self) -> None:
        evidence = filter_evidence_for_obligation(
            self.model,
            {"operation_id": "o1", "evidence_refs": ["state_agent.states[0]"]},
        )

        self.assertEqual("p is the input pointer", evidence["semantic_evidence"]["state_agent"][0]["claim"])
        self.assertEqual("L2", evidence["semantic_evidence"]["state_agent"][0]["location"])
        self.assertNotIn("role", evidence["semantic_evidence"]["state_agent"][0])

    def test_stage3_uses_explicit_operation_context_facts_without_linker(self) -> None:
        operation = self.model["operation_agent"]["operations"][0]
        state = self.model["state_agent"]["states"][0]
        operation_contexts = [{
            "operation_id": "o1",
            "operation": operation,
            "state_facts": [state],
            "value_facts": [],
            "execution_facts": [],
        }, {
            "operation_id": "o2",
            "operation": self.model["operation_agent"]["operations"][0],
            "state_facts": [],
            "value_facts": [],
            "execution_facts": [],
        }]

        evidence = filter_evidence_for_obligation(
            self.model,
            {"operation_id": "o1", "evidence_refs": ["operation_agent.operations[0]"]},
            operation_contexts,
        )

        self.assertEqual(
            ["operation_agent", "state_agent"],
            list(evidence["semantic_evidence"]),
        )

    def test_invalid_stage2_ref_is_rejected(self) -> None:
        errors = validate_obligation_evidence_refs(
            {"obligations": [{"evidence_refs": ["state_agent.records[0]"]}]},
            self.model,
        )

        self.assertTrue(any("must reference an existing semantic_model path" in error for error in errors))

    def test_stage2_requires_atomic_context_scoped_obligations(self) -> None:
        operation_contexts = [{
            "operation_id": "o1",
            "operation": self.model["operation_agent"]["operations"][0],
            "state_facts": [self.model["state_agent"]["states"][0]],
            "value_facts": [],
            "execution_facts": [],
        }, {
            "operation_id": "o2",
            "operation": self.model["operation_agent"]["operations"][0],
            "state_facts": [],
            "value_facts": [],
            "execution_facts": [],
        }]
        errors = validate_obligation_evidence_refs(
            {
                "obligations": [
                    {
                        "id": "obligation_1",
                        "operation_id": "o1",
                        "safety_requirement": "the pointer must be non-null and must be within bounds",
                        "applicable_condition": "before the read",
                        "evidence_refs": ["operation_agent.operations[0]"],
                    },
                    {
                        "id": "obligation_1",
                        "operation_id": "o3",
                        "safety_requirement": "",
                        "applicable_condition": "always",
                        "evidence_refs": ["execution_agent.executions[0]"],
                        "unexpected_field": "rejected",
                    },
                ]
            },
            self.model,
            operation_contexts,
        )

        self.assertTrue(any("exactly id, operation_id" in error for error in errors))
        self.assertTrue(any("duplicate id" in error for error in errors))
        self.assertTrue(any("unknown operation_id" in error for error in errors))
        self.assertTrue(any("safety_requirement must be a non-empty string" in error for error in errors))
        self.assertTrue(any("atomic" in error for error in errors))
        self.assertTrue(any("must contain at least one obligation" in error for error in errors))

    def test_stage2_rejects_duplicate_requirements_and_refs_outside_context(self) -> None:
        operation_contexts = [{
            "operation_id": "o1",
            "operation": self.model["operation_agent"]["operations"][0],
            "state_facts": [],
            "value_facts": [],
            "execution_facts": [],
        }]
        obligation = {
            "id": "obligation_1",
            "operation_id": "o1",
            "safety_requirement": "the indexed read must stay within the allocated object",
            "applicable_condition": "always",
            "evidence_refs": ["state_agent.states[0]"],
        }
        errors = validate_obligation_evidence_refs(
            {"obligations": [obligation, {**obligation, "id": "obligation_2"}]},
            self.model,
            operation_contexts,
        )

        self.assertTrue(any("duplicate safety_requirement" in error for error in errors))
        self.assertTrue(any("outside operation context o1" in error for error in errors))

    def test_stage2_requires_matching_operation_anchor_reference(self) -> None:
        operation_contexts = [{
            "operation_id": "o1",
            "operation": self.model["operation_agent"]["operations"][0],
            "state_facts": [self.model["state_agent"]["states"][0]],
            "value_facts": [],
            "execution_facts": [],
        }]
        errors = validate_obligation_evidence_refs(
            {"obligations": [{
                "id": "obligation_1",
                "operation_id": "o1",
                "safety_requirement": "the indexed read must stay within the allocated object",
                "applicable_condition": "always",
                "evidence_refs": ["state_agent.states[0]"],
            }]},
            self.model,
            operation_contexts,
        )

        self.assertTrue(any("must include matching operation anchor" in error for error in errors))

    def test_stage2_rejects_obvious_single_must_compound_requirement(self) -> None:
        operation_contexts = [{
            "operation_id": "o1",
            "operation": self.model["operation_agent"]["operations"][0],
            "state_facts": [],
            "value_facts": [],
            "execution_facts": [],
        }]
        errors = validate_obligation_evidence_refs(
            {"obligations": [{
                "id": "obligation_1",
                "operation_id": "o1",
                "safety_requirement": "the pointer must be non-null and within bounds",
                "applicable_condition": "before the read",
                "evidence_refs": ["operation_agent.operations[0]"],
            }]},
            self.model,
            operation_contexts,
        )

        self.assertTrue(any("must be atomic" in error for error in errors))

    def test_stage2_accepts_simple_single_property_requirements(self) -> None:
        operation_contexts = [{
            "operation_id": "o1",
            "operation": self.model["operation_agent"]["operations"][0],
            "state_facts": [],
            "value_facts": [],
            "execution_facts": [],
        }]
        errors = validate_obligation_evidence_refs(
            {"obligations": [
                {
                    "id": "obligation_1",
                    "operation_id": "o1",
                    "safety_requirement": "i must be non-negative",
                    "applicable_condition": "before the read",
                    "evidence_refs": ["operation_agent.operations[0]"],
                },
                {
                    "id": "obligation_2",
                    "operation_id": "o1",
                    "safety_requirement": "length must equal capacity",
                    "applicable_condition": "before the read",
                    "evidence_refs": ["operation_agent.operations[0]"],
                },
            ]},
            self.model,
            operation_contexts,
        )

        self.assertEqual([], errors)

    def test_adjudicator_compact_record_has_v2_fields(self) -> None:
        compact = compact_fact_for_adjudicator({"ref": "operation_agent.operations[0]", **self.model["operation_agent"]["operations"][0]})

        self.assertEqual({"ref", "id", "location", "entities", "claim", "evidence"}, set(compact))

    def test_stage3_compact_obligation_keeps_only_contract_fields(self) -> None:
        from src.agents.Pipeline import compact_obligation_for_adjudicator

        compact = compact_obligation_for_adjudicator({
            "id": "obligation_1",
            "operation_id": "o1",
            "safety_requirement": "the read must stay in bounds",
            "applicable_condition": "always",
            "evidence_refs": ["operation_agent.operations[0]"],
            "unexpected_field": "rejected",
        })

        self.assertEqual(
            {"id", "operation_id", "safety_requirement", "applicable_condition", "evidence_refs"},
            set(compact),
        )

    def test_anchor_window_uses_v2_location(self) -> None:
        code = "\n".join(f"line {index}" for index in range(1, 80))

        window = add_anchor_line_windows(code, [{"location": "L40"}], radius=1)

        self.assertEqual("39: line 39\n40: line 40\n41: line 41", window)

    def test_adjudication_requires_tri_state_assessment(self) -> None:
        errors = validate_batch_adjudications(
            {"adjudications": [{"obligation_id": "obligation_1", "violation": 0, "refs": []}]},
            ["obligation_1"],
        )

        self.assertTrue(any("assessment" in error for error in errors))

    def test_adjudication_accepts_curated_satisfied_violated_and_potential_cases(self) -> None:
        allowed = {"r1": {"operation_agent.operations[0]", "value_agent.values[0]"}}
        cases = (
            {"obligation_id": "r1", "assessment": "satisfied", "possibility": "i is proven non-negative at o1", "supporting_evidence_refs": ["value_agent.values[0]"], "contradicting_evidence_refs": [], "confirmation_gap": ""},
            {"obligation_id": "r1", "assessment": "violated", "possibility": "i is negative when o1 executes", "supporting_evidence_refs": ["value_agent.values[0]"], "contradicting_evidence_refs": [], "confirmation_gap": ""},
            {"obligation_id": "r1", "assessment": "potentially_violated", "possibility": "i may be negative when o1 executes", "supporting_evidence_refs": ["value_agent.values[0]"], "contradicting_evidence_refs": [], "confirmation_gap": "no supplied caller/path establishes a negative value"},
        )

        for item in cases:
            with self.subTest(assessment=item["assessment"]):
                self.assertEqual([], validate_batch_adjudications({"adjudications": [item]}, ["r1"], allowed))

    def test_potential_adjudication_requires_the_confirmation_gap(self) -> None:
        errors = validate_batch_adjudications(
            {
                "adjudications": [
                    {"obligation_id": "obligation_1", "assessment": "potentially_violated", "possibility": "i may be negative", "supporting_evidence_refs": ["operation_agent.operations[0]"], "contradicting_evidence_refs": [], "confirmation_gap": ""}
                ]
            },
            ["obligation_1"],
            {"obligation_1": {"operation_agent.operations[0]"}},
        )

        self.assertTrue(any("confirmation_gap" in error for error in errors))

    def test_potential_adjudication_rejects_contradicting_evidence(self) -> None:
        errors = validate_batch_adjudications(
            {"adjudications": [{
                "obligation_id": "r1",
                "assessment": "potentially_violated",
                "possibility": "i may be negative when o1 executes",
                "supporting_evidence_refs": ["value_agent.values[0]"],
                "contradicting_evidence_refs": ["value_agent.values[1]"],
                "confirmation_gap": "no supplied caller/path establishes a negative value",
            }]},
            ["r1"],
            {"r1": {"value_agent.values[0]", "value_agent.values[1]"}},
        )

        self.assertTrue(any("contradicting_evidence_refs must be empty" in error for error in errors))

    def test_potential_adjudication_rejects_a_vague_possibility(self) -> None:
        errors = validate_batch_adjudications(
            {"adjudications": [{
                "obligation_id": "r1",
                "assessment": "potentially_violated",
                "possibility": "maybe",
                "supporting_evidence_refs": ["value_agent.values[0]"],
                "contradicting_evidence_refs": [],
                "confirmation_gap": "no supplied caller/path establishes a negative value",
            }]},
            ["r1"],
            {"r1": {"value_agent.values[0]"}},
        )

        self.assertTrue(any("possibility must describe a concrete" in error for error in errors))

    def test_potential_adjudication_rejects_a_generic_confirmation_gap(self) -> None:
        allowed = {"r1": {"value_agent.values[0]"}}
        base = {
            "obligation_id": "r1",
            "assessment": "potentially_violated",
            "possibility": "i may be negative when o1 executes",
            "supporting_evidence_refs": ["value_agent.values[0]"],
            "contradicting_evidence_refs": [],
        }
        for confirmation_gap in ("x", "more evidence needed"):
            with self.subTest(confirmation_gap=confirmation_gap):
                errors = validate_batch_adjudications(
                    {"adjudications": [{**base, "confirmation_gap": confirmation_gap}]},
                    ["r1"],
                    allowed,
                )
                self.assertTrue(any("confirmation_gap must identify" in error for error in errors))

    def test_adjudication_refs_must_come_from_supplied_evidence(self) -> None:
        errors = validate_batch_adjudications(
            {
                "adjudications": [
                    {
                        "obligation_id": "obligation_1",
                        "assessment": "satisfied",
                        "possibility": "i is non-negative",
                        "supporting_evidence_refs": ["state_agent.states[99]"],
                        "contradicting_evidence_refs": [],
                        "confirmation_gap": "",
                    }
                ]
            },
            ["obligation_1"],
            {"obligation_1": {"operation_agent.operations[0]"}},
        )

        self.assertTrue(any("not supplied" in error for error in errors))

    def test_batch_rejects_missing_duplicate_and_legacy_refs_without_forming_an_assessment(self) -> None:
        errors = validate_batch_adjudications(
            {"adjudications": [
                {"obligation_id": "r1", "assessment": "satisfied", "refs": []},
                {"obligation_id": "r1", "assessment": "violated", "refs": []},
            ]},
            ["r1", "r2"],
            {"r1": {"operation_agent.operations[0]"}, "r2": set()},
        )

        self.assertTrue(any("missing obligation_id" in error for error in errors))
        self.assertTrue(any("duplicate" in error for error in errors))
        self.assertTrue(any("exactly obligation_id, assessment, possibility" in error for error in errors))

    def test_supplied_evidence_refs_are_collected_per_obligation(self) -> None:
        payload = {
            "obligation_specific_evidence": {
                "semantic_evidence": {
                    "operation_agent": [{"ref": "operation_agent.operations[0]"}],
                    "state_agent": [{"ref": "state_agent.states[0]"}],
                }
            }
        }

        self.assertEqual(
            {"operation_agent.operations[0]", "state_agent.states[0]"},
            supplied_evidence_refs(payload),
        )


if __name__ == "__main__":
    unittest.main()
