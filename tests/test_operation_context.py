from __future__ import annotations

import unittest

from src.agents.OperationContext import OperationContextError, build_operation_contexts


class OperationContextTests(unittest.TestCase):
    def test_builds_one_deterministic_context_per_operation_in_source_order(self) -> None:
        operation_one = self._operation("o1", 8, "buffer")
        operation_two = self._operation("o2", 3, "cursor")
        state_one = self._fact("s1", 7, "buffer", ["o2", "o1"])
        state_two = self._fact("s2", 2, "cursor", ["o2"])
        value = self._fact("v1", 4, "length", ["o1"])
        execution = self._fact("e1", 5, "branch", ["o2"])
        model = {
            "operation_agent": {"operations": [operation_one, operation_two]},
            "state_agent": {"states": [state_one, state_two]},
            "value_agent": {"values": [value]},
            "execution_agent": {"executions": [execution]},
        }

        contexts = build_operation_contexts(model)

        self.assertEqual(["o1", "o2"], [context["operation_id"] for context in contexts])
        self.assertEqual(
            {"operation_id", "operation", "state_facts", "value_facts", "execution_facts"},
            set(contexts[0]),
        )
        self.assertIs(operation_one, contexts[0]["operation"])
        self.assertEqual([state_one], contexts[0]["state_facts"])
        self.assertEqual([value], contexts[0]["value_facts"])
        self.assertEqual([], contexts[0]["execution_facts"])
        self.assertEqual([state_one, state_two], contexts[1]["state_facts"])
        self.assertEqual([execution], contexts[1]["execution_facts"])

    def test_does_not_infer_relevance_from_entity_overlap_or_line_distance(self) -> None:
        operation_one = self._operation("o1", 10, "buffer")
        operation_two = self._operation("o2", 100, "cursor")
        explicitly_linked = self._fact("s1", 11, "buffer", ["o2"])
        model = {
            "operation_agent": {"operations": [operation_one, operation_two]},
            "state_agent": {"states": [explicitly_linked]},
            "value_agent": {"values": []},
            "execution_agent": {"executions": []},
        }

        contexts = build_operation_contexts(model)

        self.assertEqual([], contexts[0]["state_facts"])
        self.assertEqual([explicitly_linked], contexts[1]["state_facts"])

    def test_rejects_orphan_references_before_building_contexts(self) -> None:
        model = {
            "operation_agent": {"operations": [self._operation("o1", 1, "p")]},
            "state_agent": {"states": [self._fact("s1", 2, "p", ["missing"])]},
            "value_agent": {"values": []},
            "execution_agent": {"executions": []},
        }

        with self.assertRaisesRegex(OperationContextError, "unknown operation id.*missing"):
            build_operation_contexts(model)

    def test_rejects_malformed_semantic_fact_collection(self) -> None:
        model = {
            "operation_agent": {"operations": [self._operation("o1", 1, "p")]},
            "state_agent": {"states": {}},
            "value_agent": {"values": []},
            "execution_agent": {"executions": []},
        }

        with self.assertRaisesRegex(OperationContextError, r"\$\.state_agent\.states must be an array"):
            build_operation_contexts(model)

    def test_rejects_duplicate_fact_references(self) -> None:
        model = {
            "operation_agent": {"operations": [self._operation("o1", 1, "p")]},
            "state_agent": {"states": [self._fact("s1", 2, "p", ["o1", "o1"])]},
            "value_agent": {"values": []},
            "execution_agent": {"executions": []},
        }

        with self.assertRaisesRegex(OperationContextError, "duplicated id 'o1'"):
            build_operation_contexts(model)

    def test_rejects_duplicate_operation_ids(self) -> None:
        model = {
            "operation_agent": {
                "operations": [self._operation("o1", 1, "p"), self._operation("o1", 2, "q")]
            },
            "state_agent": {"states": []},
            "value_agent": {"values": []},
            "execution_agent": {"executions": []},
        }

        with self.assertRaisesRegex(OperationContextError, r"operations\[1\].*duplicated"):
            build_operation_contexts(model)

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


if __name__ == "__main__":
    unittest.main()
