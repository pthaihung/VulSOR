from __future__ import annotations

import unittest

from src.agents.QualityGate import validate_semantic_claim_grounding


class SemanticGroundingTests(unittest.TestCase):
    def test_line_prefixed_fragments_ground_independently(self) -> None:
        output = {
            "executions": [
                {
                    "id": "e1",
                    "location": "L4",
                    "entities": ["i", "n"],
                    "claim": "reaching L4 requires 0 <= i < n",
                    "evidence": "L2: if (i >= n) return;\nL3: if (i < 0) return;",
                }
            ]
        }

        errors, metadata = validate_semantic_claim_grounding(
            output,
            "execution_agent",
            "int f(int i, int n) {\n  if (i >= n) return;\n  if (i < 0) return;\n  return i;\n}",
        )

        self.assertEqual([], errors)
        self.assertEqual("pass", metadata["execution_agent.executions[0]"]["status"])

    def test_wrong_prefixed_line_fails_even_when_text_exists_elsewhere(self) -> None:
        output = {
            "operations": [
                {
                    "id": "o1",
                    "location": "L2",
                    "entities": ["p"],
                    "claim": "read p",
                    "evidence": "L2: return *p;",
                }
            ]
        }

        errors, metadata = validate_semantic_claim_grounding(
            output,
            "operation_agent",
            "int f(int *p) {\n  return 0;\n  return *p;\n}",
        )

        self.assertTrue(errors)
        self.assertEqual("retry", metadata["operation_agent.operations[0]"]["status"])


if __name__ == "__main__":
    unittest.main()
