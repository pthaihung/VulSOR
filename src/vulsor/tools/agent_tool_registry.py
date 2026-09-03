"""Tool registry for semantic-agent LLM calls.

These tools only expose data already present in the current B1 artifact. They
do not inspect the repository, call external analyzers, or produce verdicts.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


FORBIDDEN_METADATA = {
    "target",
    "cwe",
    "cve",
    "cve_desc",
    "nvd_url",
    "pair_id",
    "commit_id",
    "commit_url",
    "commit_message",
    "side",
}


@dataclass(frozen=True)
class AgentToolResult:
    """Result of one semantic-agent tool call."""

    tool: str
    status: str
    output: Any
    error: str | None = None


TOOL_DESCRIPTIONS = {
    "get_program_facts": (
        "Return a selected program_facts list or dict from the current B1 "
        "artifact. Arguments: fact_type optional, limit optional."
    ),
    "get_context_facts": (
        "Return context_facts from the current B1 artifact. Context facts are "
        "hints, not proof."
    ),
    "get_cpg_facts": (
        "Return cpg_facts from the current B1 artifact when Joern/CPG was "
        "enabled."
    ),
    "get_fact_links": "Return analysis.links from the current B1 artifact.",
    "get_completeness": (
        "Return analysis.completeness and build_diagnosis from the current B1 "
        "artifact."
    ),
    "get_limitations": (
        "Return inherited limitations and rules from the current B1 artifact."
    ),
    "get_fact_by_id": "Return one exact B1 fact by its id.",
    "get_facts_by_location": "Return B1 facts at one source line and optional column.",
    "get_related_facts": "Return B1 facts containing an exact related fact id.",
}

TOOL_SCHEMAS = {
    "get_program_facts": {
        "input": {"fact_type": "string|null", "limit": "integer|null"},
        "output": "selected program_facts list or object",
    },
    "get_context_facts": {
        "input": {},
        "output": "analysis.context_facts object; hints, not proof",
    },
    "get_cpg_facts": {
        "input": {},
        "output": "analysis.cpg_facts object or empty object",
    },
    "get_fact_links": {
        "input": {},
        "output": "analysis.links object",
    },
    "get_completeness": {
        "input": {},
        "output": "completeness and build_diagnosis objects",
    },
    "get_limitations": {
        "input": {},
        "output": "limitations and rules lists",
    },
    "get_fact_by_id": {
        "input": {"fact_id": "string"},
        "output": "one matching fact or null",
    },
    "get_facts_by_location": {
        "input": {"line": "integer", "column": "integer|null", "limit": "integer|null"},
        "output": "at most 20 matching facts",
    },
    "get_related_facts": {
        "input": {"fact_id": "string", "limit": "integer|null"},
        "output": "facts and links containing the requested id",
    },
}


def tool_manifest(allowed_tools: tuple[str, ...]) -> list[dict[str, Any]]:
    """Return tool name, purpose, input, and output contracts for the prompt."""
    return [
        {
            "name": name,
            "description": TOOL_DESCRIPTIONS[name],
            "input": TOOL_SCHEMAS[name]["input"],
            "output": TOOL_SCHEMAS[name]["output"],
        }
        for name in allowed_tools
        if name in TOOL_DESCRIPTIONS
    ]


def run_agent_tool(
    *,
    name: str,
    arguments: dict[str, Any] | None,
    artifact: dict[str, Any],
    allowed_tools: tuple[str, ...],
) -> AgentToolResult:
    """Run one allowlisted tool.

    Args:
        name: Tool name from ``allowed_tools``.
        arguments: Tool-specific input object, or ``None``.
        artifact: Current B1 artifact used as the only data source.
        allowed_tools: Tool names enabled for this agent.

    Returns:
        An ``AgentToolResult`` containing status, output data, or an error.
    """
    if name not in allowed_tools:
        return AgentToolResult(
            tool=name,
            status="rejected",
            output=None,
            error="tool is not allowed by agent_llm.yaml",
        )

    if name == "get_program_facts":
        return _get_program_facts(artifact, arguments or {})

    if name == "get_context_facts":
        return _get_analysis_field(artifact, name, "context_facts")

    if name == "get_cpg_facts":
        return _get_analysis_field(artifact, name, "cpg_facts")

    if name == "get_fact_links":
        return _get_analysis_field(artifact, name, "links")

    if name == "get_completeness":
        analysis = _analysis(artifact)
        return AgentToolResult(
            tool=name,
            status="ok",
            output=_strip_forbidden(
                {
                    "completeness": analysis.get("completeness", {}),
                    "build_diagnosis": analysis.get("build_diagnosis", {}),
                }
            ),
        )

    if name == "get_limitations":
        analysis = _analysis(artifact)
        return AgentToolResult(
            tool=name,
            status="ok",
            output={
                "limitations": analysis.get("limitations", []),
                "rules": analysis.get("rules", []),
            },
        )

    if name == "get_fact_by_id":
        return _get_fact_by_id(artifact, arguments or {})

    if name == "get_facts_by_location":
        return _get_facts_by_location(artifact, arguments or {})

    if name == "get_related_facts":
        return _get_related_facts(artifact, arguments or {})

    return AgentToolResult(
        tool=name,
        status="error",
        output=None,
        error="unknown tool",
    )


def _get_program_facts(
    artifact: dict[str, Any],
    arguments: dict[str, Any],
) -> AgentToolResult:
    """Return selected B1 program facts.

    Input is ``fact_type`` and optional non-negative ``limit``. Output is the
    selected list/object with forbidden dataset metadata removed.
    """
    facts = (
        artifact.get("sample", {})
        .get("result", {})
        .get("program_facts", {})
    )
    fact_type = arguments.get("fact_type")
    output: Any = facts

    if isinstance(fact_type, str) and fact_type:
        output = facts.get(fact_type, [])

    limit = arguments.get("limit")
    if limit is not None and (
        not isinstance(limit, int) or not 0 <= limit <= 20
    ):
        return _invalid_input(
            "get_program_facts",
            "limit must be an integer between 0 and 20",
        )

    if isinstance(output, list) and isinstance(limit, int):
        output = output[:limit]

    return AgentToolResult(
        tool="get_program_facts",
        status="ok",
        output=_strip_forbidden(output),
    )


def _get_analysis_field(
    artifact: dict[str, Any],
    tool_name: str,
    field: str,
) -> AgentToolResult:
    """Return one analysis field from the current artifact.

    Input is the tool name and artifact field. Output is the sanitized field
    value wrapped in an ``AgentToolResult``.
    """
    return AgentToolResult(
        tool=tool_name,
        status="ok",
        output=_strip_forbidden(_analysis(artifact).get(field, {})),
    )


def _get_fact_by_id(
    artifact: dict[str, Any],
    arguments: dict[str, Any],
) -> AgentToolResult:
    fact_id = arguments.get("fact_id")
    if not isinstance(fact_id, str) or not fact_id:
        return _invalid_input("get_fact_by_id", "fact_id must be a non-empty string")

    for record in _fact_records(artifact):
        if record.get("id") == fact_id:
            return AgentToolResult(
                tool="get_fact_by_id",
                status="ok",
                output=_strip_forbidden(record),
            )

    return AgentToolResult(tool="get_fact_by_id", status="ok", output=None)


def _get_facts_by_location(
    artifact: dict[str, Any],
    arguments: dict[str, Any],
) -> AgentToolResult:
    line = arguments.get("line")
    column = arguments.get("column")
    if not isinstance(line, int) or line < 1:
        return _invalid_input("get_facts_by_location", "line must be a positive integer")
    if column is not None and (not isinstance(column, int) or column < 1):
        return _invalid_input("get_facts_by_location", "column must be a positive integer or null")

    limit = _validated_limit(arguments.get("limit"))
    if limit == -1:
        return _invalid_input(
            "get_facts_by_location",
            "limit must be an integer between 0 and 20",
        )
    if limit is None:
        limit = 20
    matches = []
    for record in _fact_records(artifact):
        if record.get("line") != line:
            continue
        if column is not None and record.get("column") != column:
            continue
        matches.append(record)
        if len(matches) >= min(limit, 20):
            break

    return AgentToolResult(
        tool="get_facts_by_location",
        status="ok",
        output=_strip_forbidden(matches),
    )


def _get_related_facts(
    artifact: dict[str, Any],
    arguments: dict[str, Any],
) -> AgentToolResult:
    fact_id = arguments.get("fact_id")
    if not isinstance(fact_id, str) or not fact_id:
        return _invalid_input("get_related_facts", "fact_id must be a non-empty string")
    limit = _validated_limit(arguments.get("limit"))
    if limit == -1:
        return _invalid_input(
            "get_related_facts",
            "limit must be an integer between 0 and 20",
        )
    if limit is None:
        limit = 20
    matches = []
    for record in _fact_records(artifact):
        if record.get("id") == fact_id or fact_id in _string_values(record):
            matches.append(record)
        if len(matches) >= min(limit, 20):
            break
    return AgentToolResult(
        tool="get_related_facts",
        status="ok",
        output=_strip_forbidden(matches),
    )


def _fact_records(artifact: dict[str, Any]) -> list[dict[str, Any]]:
    facts = artifact.get("sample", {}).get("result", {}).get("program_facts", {})
    records = []
    for value in facts.values() if isinstance(facts, dict) else []:
        if isinstance(value, list):
            records.extend(item for item in value if isinstance(item, dict))
    return records


def _string_values(value: Any) -> set[str]:
    if isinstance(value, dict):
        return {item for item in value.values() if isinstance(item, str)}
    if isinstance(value, list):
        return {item for item in value if isinstance(item, str)}
    return set()


def _validated_limit(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, int) and 0 <= value <= 20:
        return value
    return -1


def _invalid_input(tool: str, error: str) -> AgentToolResult:
    return AgentToolResult(tool=tool, status="error", output=None, error=error)


def _analysis(artifact: dict[str, Any]) -> dict[str, Any]:
    analysis = artifact.get("sample", {}).get("analysis", {})

    return analysis if isinstance(analysis, dict) else {}


def _strip_forbidden(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: _strip_forbidden(item)
            for key, item in value.items()
            if key not in FORBIDDEN_METADATA
        }

    if isinstance(value, list):
        return [_strip_forbidden(item) for item in value]

    return value
