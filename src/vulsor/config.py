"""Typed configuration for VulSOR.

Configuration is intentionally kept separate from implementation logic.
Model names, tool executables, and dataset roots belong here or in a
YAML file under `configs/`, not hard-coded inside `cli.py` / `pipeline.py`
(see VulSOR.md, Section "Dependencies" / project instructions on
PROMPT AND CONFIGURATION MANAGEMENT).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictInt

from vulsor.repository_context.models import EvidenceBudget


class ToolsConfig(BaseModel):
    """External tool executables, resolved via PATH by default.

    Do NOT hard-code machine-specific paths here. If a machine needs a specific path, that
    belongs in that machine's own config YAML, not in this schema's
    defaults (VulSOR.md, "Environment state on Windows").
    """

    model_config = ConfigDict(populate_by_name=True)

    clang: str = "clang"
    clang_cpp: str = Field(default="clang++", alias="clang++")
    git: str = "git"
    joern: str = "joern"
    joern_parse: str = Field(default="joern-parse", alias="joern-parse")


class DatasetConfig(BaseModel):
    """Location of one named dataset (e.g. 'primevul').

    `root` is expected to point at a PrimeVul_clean-style directory
    with inputs/, labels/, paired/ subfolders (VulSOR.md, Section 19).
    """

    root: Path
    repository_index_dir: Path | None = None


class RepositoryContextConfig(BaseModel):
    enabled: bool = False
    cache_root: Path = Path("workspace/repository_context")
    clone_timeout_seconds: StrictInt = Field(default=600, ge=1)
    build_timeout_seconds: StrictInt = Field(default=1800, ge=1)
    query_timeout_seconds: StrictInt = Field(default=120, ge=1)
    lock_timeout_seconds: StrictInt = Field(default=60, ge=1)
    default_budget: EvidenceBudget = Field(default_factory=EvidenceBudget)


class VulSORConfig(BaseModel):
    """Top-level VulSOR configuration.

    Loaded from a YAML file such as configs/default.yaml or
    configs/primevul.yaml. All fields have safe defaults so that
    `load_config(None)` returns a usable config for local/dev use.
    """

    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    datasets: dict[str, DatasetConfig] = Field(default_factory=dict)
    repository_context: RepositoryContextConfig = Field(
        default_factory=RepositoryContextConfig
    )


class AgentLLMOverride(BaseModel):
    """Optional LLM settings that override the shared agent defaults."""

    provider: str | None = None
    base_url: str | None = None
    model: str | None = None
    api_key_env: str | None = None
    temperature: float | None = None
    timeout_seconds: int | None = None
    max_output_tokens: int | None = None
    max_tool_rounds: int | None = None
    allowed_tools: tuple[str, ...] | None = None
    extra_headers: dict[str, str] | None = None


class AgentLLMConfig(BaseModel):
    """LLM API settings loaded from a dedicated semantic-agent YAML file."""

    provider: str = "openai_compatible"
    base_url: str = "https://api.openai.com/v1/chat/completions"
    model: str = "gpt-4.1-mini"
    api_key_env: str = "OPENAI_API_KEY"
    temperature: float = 0.0
    timeout_seconds: int = 60
    max_output_tokens: int = 1200
    max_tool_rounds: int = 1
    allowed_tools: tuple[str, ...] = (
        "get_program_facts",
        "get_fact_links",
        "get_completeness",
        "get_limitations",
    )
    extra_headers: dict[str, str] = Field(default_factory=dict)
    agents: dict[str, AgentLLMOverride] = Field(default_factory=dict)

    def for_agent(self, agent_name: str) -> AgentLLMConfig:
        """Return shared settings merged with an agent-specific override."""
        override = self.agents.get(agent_name)

        if override is None:
            return self

        return self.model_copy(
            update=override.model_dump(exclude_unset=True, exclude_none=True)
        ).model_copy(update={"agents": {}})


def load_config(path: Path | None) -> VulSORConfig:
    """Load a VulSORConfig from a YAML file, or return defaults.

    Args:
        path: Path to a YAML config file, or None to use built-in defaults.

    Returns:
        A validated VulSORConfig.

    Raises:
        FileNotFoundError: if `path` is given but does not exist.
        pydantic.ValidationError: if the YAML content does not match
            the expected schema.
    """
    if path is None:
        return VulSORConfig()

    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return VulSORConfig(**raw)


def load_llm_config(path: Path | None) -> AgentLLMConfig:
    """Load semantic-agent LLM settings from a standalone YAML file."""
    if path is None:
        return AgentLLMConfig()

    if not path.exists():
        raise FileNotFoundError(f"LLM config file not found: {path}")

    raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return AgentLLMConfig(**raw)
