"""B2 Operation Agent."""

from __future__ import annotations

from typing import Any

from vulsor.agents.BaseAgent import BaseAgent
from vulsor.agents.SemanticViews import build_operation_view


class OperationAgent(BaseAgent):
    """Enumerate operation sites and conservative semantic roles."""

    agent_name = "operation"

    def build_local_view(self, artifact: dict[str, Any]) -> dict[str, Any]:
        """Build operation records, call roles, and operation inventory."""
        return build_operation_view(artifact)
