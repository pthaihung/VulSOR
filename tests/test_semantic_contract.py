from __future__ import annotations

import unittest

from src.agents.SemanticContract import (
    OPERATION_FIELDS,
    SEMANTIC_FACT_FIELDS,
    evidence_fragments,
    parse_location,
    resolve_claim_ref,
    validate_claim_output,
    validate_operation_references,
)


class SemanticContractTests(unittest.TestCase):
    def test_contract_fields_distinguish_operations_from_semantic_facts(self) -> None:
        self.assertEqual(("id", "location", "entities", "claim", "evidence"), OPERATION_FIELDS)
        self.assertEqual(OPERATION_FIELDS + ("operation_ids",), SEMANTIC_FACT_FIELDS)

    def test_valid_claim_uses_v2_five_field_contract(self) -> None:
        output = {
            "operations": [
                {
                    "id": "o1",
                    "location": "L4",
                    "entities": ["p", "i"],
                    "claim": "read element p[i]",
                    "evidence": "L4: return p[i];",
                }
            ]
        }

        self.assertEqual([], validate_claim_output(output, "operation_agent", 4))

    def test_legacy_fields_are_rejected(self) -> None:
        output = {
            "states": [
                {
                    "id": "s1",
                    "location": "L2",
                    "entities": ["p"],
                    "claim": "p is non-null",
                    "evidence": "L2: if (p)",
                    "role": "guard",
                }
            ]
        }

        errors = validate_claim_output(output, "state_agent", 3)

        self.assertTrue(any("unsupported field" in error for error in errors))

    def test_non_operation_fact_requires_nonempty_unique_operation_ids(self) -> None:
        base_fact = {
            "id": "s1",
            "location": "L2",
            "entities": ["p"],
            "claim": "p is non-null",
            "evidence": "L2: if (p)",
        }

        missing_errors = validate_claim_output({"states": [base_fact]}, "state_agent", 3)
        empty_errors = validate_claim_output(
            {"states": [{**base_fact, "operation_ids": []}]}, "state_agent", 3
        )
        duplicate_errors = validate_claim_output(
            {"states": [{**base_fact, "operation_ids": ["o1", "o1"]}]}, "state_agent", 3
        )

        self.assertTrue(any("missing field" in error and "operation_ids" in error for error in missing_errors))
        self.assertTrue(any("non-empty" in error and "operation_ids" in error for error in empty_errors))
        self.assertTrue(any("duplicates" in error and "operation_ids" in error for error in duplicate_errors))

    def test_operation_rejects_operation_ids_as_an_unsupported_field(self) -> None:
        output = {
            "operations": [
                {
                    "id": "o1",
                    "location": "L1",
                    "entities": ["p"],
                    "claim": "dereference p",
                    "evidence": "L1: *p = 1;",
                    "operation_ids": ["o1"],
                }
            ]
        }

        errors = validate_claim_output(output, "operation_agent", 1)

        self.assertTrue(any("unsupported field" in error and "operation_ids" in error for error in errors))

    def test_operation_references_reject_unknown_ids_or_orphan_facts(self) -> None:
        model = {
            "operation_agent": {"operations": [self._operation("o1", 1, "p")]},
            "state_agent": {
                "states": [
                    self._fact("s1", 2, "p", ["o999"]),
                    self._fact("s2", 3, "q", []),
                ]
            },
            "value_agent": {"values": []},
            "execution_agent": {"executions": []},
        }

        errors = validate_operation_references(model)

        self.assertTrue(any("unknown operation id" in error and "o999" in error for error in errors))
        self.assertTrue(any("orphan" in error and "s2" in error for error in errors))

    def test_operation_references_reject_duplicate_operation_ids(self) -> None:
        model = {
            "operation_agent": {
                "operations": [self._operation("o1", 1, "p"), self._operation("o1", 2, "q")]
            },
            "state_agent": {"states": []},
            "value_agent": {"values": []},
            "execution_agent": {"executions": []},
        }

        errors = validate_operation_references(model)

        self.assertTrue(any("duplicated" in error and "o1" in error for error in errors))

    def test_operation_references_reject_malformed_fact_collection(self) -> None:
        model = {
            "operation_agent": {"operations": [self._operation("o1", 1, "p")]},
            "state_agent": {"states": "not-an-array"},
            "value_agent": {"values": []},
            "execution_agent": {"executions": []},
        }

        self.assertIn(
            "$.state_agent.states must be an array",
            validate_operation_references(model),
        )

    def test_invalid_location_and_evidence_remain_rejected_for_linked_facts(self) -> None:
        fact = self._fact("v1", 2, "size", ["o1"])
        fact["location"] = "line 2"
        fact["evidence"] = "size = count * 4;"

        errors = validate_claim_output({"values": [fact]}, "value_agent", 2)

        self.assertTrue(any("location" in error for error in errors))
        self.assertTrue(any("evidence" in error and "L<number>" in error for error in errors))

    @staticmethod
    def _operation(operation_id: str, line: int, entity: str) -> dict[str, object]:
        return {
            "id": operation_id,
            "location": f"L{line}",
            "entities": [entity],
            "claim": f"operate on {entity}",
            "evidence": f"L{line}: use({entity});",
        }

    @staticmethod
    def _fact(fact_id: str, line: int, entity: str, operation_ids: list[str]) -> dict[str, object]:
        return {
            "id": fact_id,
            "location": f"L{line}",
            "entities": [entity],
            "claim": f"fact about {entity}",
            "evidence": f"L{line}: check({entity});",
            "operation_ids": operation_ids,
        }

    def test_multiline_evidence_preserves_each_line(self) -> None:
        self.assertEqual(
            [(2, "if (i >= n) return;"), (3, "if (i < 0) return;")],
            evidence_fragments("L2: if (i >= n) return;\nL3: if (i < 0) return;"),
        )

    def test_every_evidence_line_requires_a_source_line_prefix(self) -> None:
        output = {
            "values": [
                {
                    "id": "v1",
                    "location": "L2",
                    "entities": ["size", "count"],
                    "claim": "size equals count times four",
                    "evidence": "L2: size = count * 4;\ncount is trusted",
                }
            ]
        }

        errors = validate_claim_output(output, "value_agent", 2)

        self.assertTrue(any("evidence" in error and "L<number>" in error for error in errors))

    def test_claim_id_must_use_exact_agent_prefix_and_number(self) -> None:
        output = {
            "operations": [
                {
                    "id": "operation-one",
                    "location": "L1",
                    "entities": ["p"],
                    "claim": "dereference p",
                    "evidence": "L1: *p = 1;",
                }
            ]
        }

        self.assertTrue(validate_claim_output(output, "operation_agent", 1))

    def test_reference_is_strict_and_zero_based(self) -> None:
        model = {
            "operation_agent": {"operations": []},
            "execution_agent": {
                "executions": [
                    {
                        "id": "e1",
                        "location": "L4",
                        "entities": [],
                        "claim": "L4 is reachable",
                        "evidence": "L4: return 0;",
                    }
                ]
            },
        }

        self.assertEqual("execution_agent.executions[0]", resolve_claim_ref(model, "execution_agent.executions[0]"))
        self.assertIsNone(resolve_claim_ref(model, "execution_agent.executions[1]"))
        self.assertIsNone(resolve_claim_ref(model, "execution_agent.records[0]"))
        self.assertEqual(4, parse_location("L4", 4))
        self.assertIsNone(parse_location("line 4", 4))


if __name__ == "__main__":
    unittest.main()
