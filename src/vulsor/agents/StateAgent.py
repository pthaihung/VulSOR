"""Compatibility wrapper for the B2 State Agent."""

from __future__ import annotations

from pathlib import Path

from typing import Any

from vulsor.agents.BaseAgent import (
    AgentRunResult,
    BaseAgent,
)
from vulsor.agents.SemanticViews import build_state_view


class StateAgent(BaseAgent):
    """Build a conservative state view from B1 artifacts."""

    agent_name = "state"

    def build_local_view(self, artifact: dict[str, Any]) -> dict[str, Any]:
        """Build variables, objects, buffers, resources, and missing state."""
        return build_state_view(artifact)



def run_state_agent_for_manifest(
    manifest_path: Path,
    *,
    brain_context_dir: Path = Path("brain_context"),
    sample_id: str | None = None,
    limit: int | None = None,
    force: bool = False,
) -> list[AgentRunResult]:
    """Run the State Agent for samples listed in a B1 manifest."""
    from vulsor.agents.BaseAgent import run_semantic_agent_for_manifest

    return run_semantic_agent_for_manifest(
        manifest_path,
        agent_name="state",
        brain_context_dir=brain_context_dir,
        sample_id=sample_id,
        limit=limit,
        force=force,
    )
