"""B2 Value Agent."""

from __future__ import annotations

from typing import Any

from vulsor.agents.BaseAgent import BaseAgent
from vulsor.agents.SemanticViews import build_value_view


class ValueAgent(BaseAgent):
    """Reconstruct local value provenance and relations from B1 facts."""

    agent_name = "value"

    def build_local_view(self, artifact: dict[str, Any]) -> dict[str, Any]:
        """Build symbols, constants, constraints, bounds, and nullability."""
        return build_value_view(artifact)
