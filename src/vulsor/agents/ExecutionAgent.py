"""B2 Execution Agent."""

from __future__ import annotations

from typing import Any

from vulsor.agents.BaseAgent import BaseAgent
from vulsor.agents.SemanticViews import build_execution_view


class ExecutionAgent(BaseAgent):
    """Reconstruct control-flow conditions and operation ordering."""

    agent_name = "execution"

    def build_local_view(self, artifact: dict[str, Any]) -> dict[str, Any]:
        """Build control regions, branches, operation order, and guards."""
        return build_execution_view(artifact)
