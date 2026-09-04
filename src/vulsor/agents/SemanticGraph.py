"""Build a queryable semantic CPG overlay from merged B2 views."""

from __future__ import annotations

from typing import Any

from vulsor.agents.SemanticViews import list_of_dicts


GRAPH_SCHEMA_VERSION = 1


def build_semantic_cpg_overlay(
    semantic_payload: dict[str, Any],
) -> dict[str, Any]:
    """Convert agent_semantics.json payload into nodes and edges.

    This graph is an overlay for B2 semantics. It preserves evidence links and
    query structure, but it is not a replacement for a full Joern CPG.
    """
    semantics = semantic_payload.get("agent_semantics")
    if not isinstance(semantics, dict):
        semantics = semantic_payload

    builder = _GraphBuilder()
    sample_id = str(
        semantics.get("sample_id")
        or semantic_payload.get("sample_id")
        or "unknown"
    )
    source_artifact = semantics.get("source_artifact")

    _add_recovery_assumptions(builder, semantics)
    function_ranges = _add_functions(builder, semantics)
    variable_ids = _add_variables(builder, semantics)
    operation_ids = _add_operations(builder, semantics, function_ranges)
    _add_execution(builder, semantics, operation_ids)
    _add_value_semantics(builder, semantics, variable_ids, operation_ids)
    _add_cross_view_links(builder, semantics, operation_ids, variable_ids)
    _add_llm_semantics(builder, semantics, operation_ids, variable_ids)

    nodes = builder.nodes()
    edges = builder.edges()

    return {
        "schema_version": GRAPH_SCHEMA_VERSION,
        "artifact_kind": "semantic_cpg_overlay",
        "sample_id": sample_id,
        "source_semantics": semantic_payload.get(
            "_meta",
            {},
        ).get("source_semantics")
        or "agent_semantics.json",
        "source_artifact": source_artifact,
        "graph": {
            "nodes": nodes,
            "edges": edges,
            "summary": {
                "node_count": len(nodes),
                "edge_count": len(edges),
                "node_types": _count_by_key(nodes, "type"),
                "edge_types": _count_by_key(edges, "type"),
            },
        },
        "_meta": {
            "provenance": "vulsor/b2/semantic_graph",
            "meaning": (
                "Semantic CPG overlay built from B2 semantic agent views; "
                "not a full Joern CPG."
            ),
            "boundary": {
                "verdict": "not_allowed",
                "cwe": "not_allowed",
                "invented_facts": "not_allowed",
            },
        },
    }


def _add_recovery_assumptions(
    builder: "_GraphBuilder",
    semantics: dict[str, Any],
) -> None:
    for index, assumption in enumerate(
        list_of_dicts(semantics.get("recovery_assumptions"))
    ):
        symbol = _string_or_none(assumption.get("symbol")) or "unknown"
        node_id = f"recovery_assumption:{index}:{symbol}"
        builder.add_node(
            node_id,
            "RecoveryAssumption",
            {
                "kind": assumption.get("kind"),
                "symbol": assumption.get("symbol"),
                "declaration": assumption.get("declaration"),
                "reason": assumption.get("reason"),
                "provenance": assumption.get("provenance"),
                "trust": assumption.get("trust"),
                "used_for": assumption.get("used_for"),
                "not_evidence_for_verdict": assumption.get(
                    "not_evidence_for_verdict"
                ),
            },
        )


def _add_functions(
    builder: "_GraphBuilder",
    semantics: dict[str, Any],
) -> list[dict[str, Any]]:
    state_view = semantics.get("state_view") or {}
    functions = []

    for function in list_of_dicts(state_view.get("functions")):
        function_id = _string_or_none(function.get("id"))
        if function_id is None:
            continue

        start_line = _int_or_none(function.get("start_line"))
        end_line = _int_or_none(function.get("end_line"))
        builder.add_node(
            function_id,
            "Function",
            {
                "name": function.get("name"),
                "start_line": start_line,
                "end_line": end_line,
            },
        )
        functions.append(
            {
                "id": function_id,
                "start_line": start_line,
                "end_line": end_line,
            }
        )

    return functions


def _add_variables(
    builder: "_GraphBuilder",
    semantics: dict[str, Any],
) -> dict[str, str]:
    state_view = semantics.get("state_view") or {}
    variable_ids = {}

    for variable in list_of_dicts(state_view.get("variables")):
        name = _string_or_none(variable.get("name"))
        if name is None:
            continue

        variable_id = f"variable:{name}"
        variable_ids[name] = variable_id
        builder.add_node(
            variable_id,
            "Variable",
            {
                "name": name,
                "kind": variable.get("kind"),
                "data_flow_count": variable.get("data_flow_count"),
                "confidence": variable.get("confidence"),
                "uncertainty": variable.get("uncertainty"),
                "definition_locations": variable.get("definition_locations", []),
                "use_locations": variable.get("use_locations", []),
            },
        )
        builder.supported_by(variable_id, variable.get("supporting_fact_ids"))

        for fact_id in _strings(variable.get("definition_ids")):
            fact_node_id = builder.add_fact(fact_id)
            builder.add_edge(variable_id, fact_node_id, "DEFINED_BY")

        for fact_id in _strings(variable.get("use_ids")):
            fact_node_id = builder.add_fact(fact_id)
            builder.add_edge(variable_id, fact_node_id, "USED_BY_FACT")

    _add_named_candidates(
        builder,
        "BufferCandidate",
        "buffer",
        state_view.get("buffers"),
        variable_ids,
        "HAS_BUFFER_CANDIDATE",
    )
    _add_named_candidates(
        builder,
        "ResourceCandidate",
        "resource",
        state_view.get("resources"),
        variable_ids,
        "HAS_RESOURCE_CANDIDATE",
    )
    _add_named_candidates(
        builder,
        "ObjectCandidate",
        "object",
        state_view.get("objects"),
        variable_ids,
        "HAS_OBJECT_CANDIDATE",
    )

    return variable_ids


def _add_named_candidates(
    builder: "_GraphBuilder",
    node_type: str,
    prefix: str,
    items: Any,
    variable_ids: dict[str, str],
    edge_type: str,
) -> None:
    for item in list_of_dicts(items):
        name = _string_or_none(item.get("name"))
        if name is None:
            continue

        node_id = f"{prefix}:{name}"
        builder.add_node(
            node_id,
            node_type,
            {
                "name": name,
                "kind": item.get("kind"),
                "confidence": item.get("confidence"),
                "uncertainty": item.get("uncertainty"),
                "reasons": item.get("reasons", []),
            },
        )
        builder.supported_by(node_id, item.get("supporting_fact_ids"))

        variable_id = variable_ids.get(name)
        if variable_id is not None:
            builder.add_edge(variable_id, node_id, edge_type)


def _add_operations(
    builder: "_GraphBuilder",
    semantics: dict[str, Any],
    function_ranges: list[dict[str, Any]],
) -> dict[str, str]:
    operation_view = semantics.get("operation_view") or {}
    operation_ids = {}

    for operation in list_of_dicts(operation_view.get("operations")):
        operation_id = _string_or_none(operation.get("operation_id"))
        inventory_id = _string_or_none(operation.get("operation_inventory_id"))
        node_id = operation_id or inventory_id
        if node_id is None:
            continue

        operation_ids[node_id] = node_id
        if inventory_id is not None:
            operation_ids[inventory_id] = node_id
        if operation_id is not None:
            operation_ids[operation_id] = node_id

        source_location = _dict_or_empty(operation.get("source_location"))
        line = _int_or_none(source_location.get("line"))
        builder.add_node(
            node_id,
            "Operation",
            {
                "operation_inventory_id": inventory_id,
                "operation_id": operation_id,
                "name": operation.get("name"),
                "kind": operation.get("kind"),
                "semantic_role": operation.get("semantic_role"),
                "resolved": operation.get("resolved"),
                "arguments": operation.get("arguments", []),
                "source_location": source_location,
                "confidence": operation.get("confidence"),
                "uncertainty": operation.get("uncertainty"),
            },
        )
        builder.supported_by(node_id, operation.get("supporting_fact_ids"))

        function_id = _function_for_line(function_ranges, line)
        if function_id is not None:
            builder.add_edge(function_id, node_id, "CONTAINS")

        role = _string_or_none(operation.get("semantic_role"))
        if role is not None:
            role_id = f"semantic_role:{role}"
            builder.add_node(role_id, "SemanticRole", {"name": role})
            builder.add_edge(node_id, role_id, "HAS_ROLE")

    for candidate in list_of_dicts(operation_view.get("source_sink_candidates")):
        node_id = _operation_node_id(candidate, operation_ids)
        if node_id is None:
            continue
        builder.add_edge(
            node_id,
            "semantic_role:source_sink_candidate",
            "MARKED_AS",
        )
        builder.add_node(
            "semantic_role:source_sink_candidate",
            "SemanticRole",
            {"name": "source_sink_candidate"},
        )

    return operation_ids


def _add_execution(
    builder: "_GraphBuilder",
    semantics: dict[str, Any],
    operation_ids: dict[str, str],
) -> None:
    execution_view = semantics.get("execution_view") or {}
    ordered_operations = sorted(
        list_of_dicts(execution_view.get("ordered_operations")),
        key=lambda item: item.get("order_index", 0),
    )

    previous_id = None
    for item in ordered_operations:
        node_id = _operation_node_id(item, operation_ids)
        if node_id is None:
            continue

        builder.add_node(
            node_id,
            "Operation",
            {
                "name": item.get("name"),
                "source_location": item.get("source_location", {}),
            },
        )
        builder.supported_by(node_id, item.get("supporting_fact_ids"))

        if previous_id is not None:
            builder.add_edge(
                previous_id,
                node_id,
                "ORDERED_BEFORE",
                {"order_source": "execution_view.ordered_operations"},
            )
        previous_id = node_id

    for index, region in enumerate(
        list_of_dicts(execution_view.get("control_regions"))
    ):
        region_id = _string_or_none(region.get("id")) or f"control_region:{index}"
        builder.add_node(
            region_id,
            "ControlRegion",
            {
                "statements": region.get("statements", []),
                "confidence": region.get("confidence"),
                "uncertainty": region.get("uncertainty"),
            },
        )
        builder.supported_by(region_id, region.get("supporting_fact_ids"))

    for index, guard in enumerate(
        list_of_dicts(execution_view.get("guard_candidates"))
    ):
        guard_id = _guard_id(guard, index)
        builder.add_node(
            guard_id,
            "Guard",
            {
                "condition": guard.get("condition"),
                "name": guard.get("name"),
                "source_block": guard.get("source_block"),
                "target_block": guard.get("target_block"),
                "source_location": guard.get("source_location", {}),
                "confidence": guard.get("confidence"),
                "uncertainty": guard.get("uncertainty"),
            },
        )
        builder.supported_by(guard_id, guard.get("supporting_fact_ids"))

        operation_id = _operation_node_id(guard, operation_ids)
        if operation_id is not None:
            builder.add_edge(operation_id, guard_id, "ACTS_AS_GUARD")


def _add_value_semantics(
    builder: "_GraphBuilder",
    semantics: dict[str, Any],
    variable_ids: dict[str, str],
    operation_ids: dict[str, str],
) -> None:
    value_view = semantics.get("value_view") or {}

    for item in list_of_dicts(value_view.get("symbols")):
        name = _string_or_none(item.get("name"))
        if name is None:
            continue

        variable_id = variable_ids.setdefault(name, f"variable:{name}")
        builder.add_node(
            variable_id,
            "Variable",
            {
                "name": name,
                "value_provenance": item.get("provenance"),
                "confidence": item.get("confidence"),
                "uncertainty": item.get("uncertainty"),
            },
        )
        builder.supported_by(variable_id, item.get("supporting_fact_ids"))

    for index, item in enumerate(list_of_dicts(value_view.get("constants"))):
        node_id = f"constant:{index}:{item.get('value')}"
        builder.add_node(
            node_id,
            "Constant",
            {
                "value": item.get("value"),
                "source_location": item.get("source_location", {}),
                "confidence": item.get("confidence"),
                "uncertainty": item.get("uncertainty"),
            },
        )
        builder.supported_by(node_id, item.get("supporting_fact_ids"))

    for index, item in enumerate(
        list_of_dicts(value_view.get("constraints"))
    ):
        _add_constraint(builder, item, index, "branch_constraint", operation_ids)

    for index, item in enumerate(
        list_of_dicts(value_view.get("bounds_relations"))
    ):
        _add_constraint(builder, item, index, "bounds_relation", operation_ids)

    for index, item in enumerate(
        list_of_dicts(value_view.get("nullability_notes"))
    ):
        name = _string_or_none(item.get("name"))
        note_id = f"nullability:{index}:{name or 'unknown'}"
        builder.add_node(
            note_id,
            "NullabilityNote",
            {
                "name": name,
                "relation": item.get("relation"),
                "confidence": item.get("confidence"),
                "uncertainty": item.get("uncertainty"),
            },
        )
        builder.supported_by(note_id, item.get("supporting_fact_ids"))

        variable_id = variable_ids.get(name or "")
        if variable_id is not None:
            builder.add_edge(variable_id, note_id, "HAS_NULLABILITY_NOTE")


def _add_constraint(
    builder: "_GraphBuilder",
    item: dict[str, Any],
    index: int,
    prefix: str,
    operation_ids: dict[str, str],
) -> None:
    node_id = f"{prefix}:{index}"
    builder.add_node(
        node_id,
        "ValueConstraint",
        {
            "kind": prefix,
            "condition": item.get("condition"),
            "operation": item.get("operation"),
            "relation": item.get("relation"),
            "arguments": item.get("arguments", []),
            "source_location": item.get("source_location", {}),
            "confidence": item.get("confidence"),
            "uncertainty": item.get("uncertainty"),
        },
    )
    builder.supported_by(node_id, item.get("supporting_fact_ids"))

    for fact_id in _strings(item.get("supporting_fact_ids")):
        operation_id = operation_ids.get(fact_id)
        if operation_id is not None:
            builder.add_edge(operation_id, node_id, "HAS_VALUE_CONSTRAINT")


def _add_cross_view_links(
    builder: "_GraphBuilder",
    semantics: dict[str, Any],
    operation_ids: dict[str, str],
    variable_ids: dict[str, str],
) -> None:
    operation_view = semantics.get("operation_view") or {}

    for operation in list_of_dicts(operation_view.get("operations")):
        operation_id = _operation_node_id(operation, operation_ids)
        if operation_id is None:
            continue

        for argument in _strings(operation.get("arguments")):
            for name in _argument_identifiers(argument):
                variable_id = variable_ids.get(name)
                if variable_id is not None:
                    builder.add_edge(operation_id, variable_id, "USES_SYMBOL")

    for link in list_of_dicts(semantics.get("cross_view_links")):
        operation_id = _operation_node_id(link, operation_ids)
        if operation_id is None:
            continue

        for name in _strings(link.get("buffer_names")):
            buffer_id = f"buffer:{name}"
            if builder.has_node(buffer_id):
                builder.add_edge(
                    operation_id,
                    buffer_id,
                    "OPERATES_ON_BUFFER_CANDIDATE",
                    {
                        "confidence": link.get("confidence"),
                        "uncertainty": link.get("uncertainty"),
                    },
                )


def _add_llm_semantics(
    builder: "_GraphBuilder",
    semantics: dict[str, Any],
    operation_ids: dict[str, str],
    variable_ids: dict[str, str],
) -> None:
    llm_semantics = semantics.get("llm_semantics")
    if not isinstance(llm_semantics, dict):
        return

    for agent_name, payload in llm_semantics.items():
        if not isinstance(agent_name, str) or not isinstance(payload, dict):
            continue

        agent_id = f"llm_agent:{agent_name}"
        builder.add_node(
            agent_id,
            "LLMSemanticAgent",
            {
                "agent": agent_name,
                "source": payload.get("source"),
                "provider": payload.get("provider"),
                "model": payload.get("model"),
                "summary": payload.get("summary"),
            },
        )

        for index, observation in enumerate(
            list_of_dicts(payload.get("observations"))
        ):
            observation_id = f"llm_observation:{agent_name}:{index}"
            builder.add_node(
                observation_id,
                "SemanticObservation",
                {
                    "agent": agent_name,
                    "claim": observation.get("claim"),
                    "confidence": observation.get("confidence"),
                    "uncertainty": observation.get("uncertainty"),
                },
            )
            builder.add_edge(agent_id, observation_id, "EMITS_OBSERVATION")
            _link_reasoning_evidence(
                builder,
                observation_id,
                observation.get("supporting_fact_ids"),
                operation_ids,
                variable_ids,
            )

        for group_index, group in enumerate(
            list_of_dicts(payload.get("reasoning_groups"))
        ):
            group_id = f"reasoning_group:{agent_name}:{group_index}"
            builder.add_node(
                group_id,
                "ReasoningGroup",
                {
                    "agent": agent_name,
                    "description": group.get("description"),
                },
            )
            builder.add_edge(agent_id, group_id, "EMITS_REASONING_GROUP")

            for step_index, step in enumerate(
                list_of_dicts(group.get("steps"))
            ):
                step_id = (
                    f"reasoning_step:{agent_name}:{group_index}:{step_index}"
                )
                builder.add_node(
                    step_id,
                    "ReasoningStep",
                    {
                        "agent": agent_name,
                        "claim": step.get("claim"),
                        "derived_from": step.get("derived_from"),
                        "confidence": step.get("confidence"),
                        "uncertainty": step.get("uncertainty"),
                    },
                )
                builder.add_edge(group_id, step_id, "HAS_STEP")
                _link_reasoning_evidence(
                    builder,
                    step_id,
                    _step_fact_ids(step),
                    operation_ids,
                    variable_ids,
                )


def _link_reasoning_evidence(
    builder: "_GraphBuilder",
    source_id: str,
    fact_ids: Any,
    operation_ids: dict[str, str],
    variable_ids: dict[str, str],
) -> None:
    for fact_id in _strings(fact_ids):
        fact_node_id = builder.add_fact(fact_id)
        builder.add_edge(source_id, fact_node_id, "SUPPORTED_BY")

        referred_node = _node_for_fact_reference(
            fact_id,
            operation_ids,
            variable_ids,
        )
        if referred_node is not None:
            builder.add_edge(source_id, referred_node, "REFERS_TO")


def _step_fact_ids(step: dict[str, Any]) -> list[str]:
    fact_ids = []
    fact_ids.extend(_fact_ids_from_derived_from(step.get("derived_from")))

    for evidence in list_of_dicts(step.get("evidence")):
        fact_id = _string_or_none(evidence.get("fact_id"))
        if fact_id is not None:
            fact_ids.append(fact_id)

    return list(dict.fromkeys(fact_ids))


def _fact_ids_from_derived_from(value: Any) -> list[str]:
    if isinstance(value, str):
        return [value] if value else []
    if isinstance(value, list):
        return [
            item
            for item in value
            if isinstance(item, str) and item
        ]
    return []


def _node_for_fact_reference(
    fact_id: str,
    operation_ids: dict[str, str],
    variable_ids: dict[str, str],
) -> str | None:
    operation_id = operation_ids.get(fact_id)
    if operation_id is not None:
        return operation_id

    parts = fact_id.split(":")
    if len(parts) >= 2 and parts[0] in {"definition", "use"}:
        return variable_ids.get(parts[1])

    return None


def _operation_node_id(
    item: dict[str, Any],
    operation_ids: dict[str, str],
) -> str | None:
    for key in ("operation_id", "operation_inventory_id"):
        value = _string_or_none(item.get(key))
        if value is not None and value in operation_ids:
            return operation_ids[value]
    return None


def _function_for_line(
    function_ranges: list[dict[str, Any]],
    line: int | None,
) -> str | None:
    if line is None:
        return None

    for function in function_ranges:
        start_line = function.get("start_line")
        end_line = function.get("end_line")
        if (
            isinstance(start_line, int)
            and isinstance(end_line, int)
            and start_line <= line <= end_line
        ):
            return str(function["id"])

    return None


def _guard_id(guard: dict[str, Any], index: int) -> str:
    source = guard.get("source_block")
    target = guard.get("target_block")
    if isinstance(source, str) and isinstance(target, str):
        return f"guard:{source}:{target}:{index}"

    operation_id = _string_or_none(guard.get("operation_id"))
    if operation_id is not None:
        return f"guard:{operation_id}"

    return f"guard:{index}"


def _argument_identifiers(argument: str) -> set[str]:
    return {
        token
        for token in argument.replace("->", " ").replace(".", " ").split()
        if token.isidentifier()
    }


def _count_by_key(items: list[dict[str, Any]], key: str) -> dict[str, int]:
    counts: dict[str, int] = {}
    for item in items:
        value = str(item.get(key, "unknown"))
        counts[value] = counts.get(value, 0) + 1
    return counts


def _dict_or_empty(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _int_or_none(value: Any) -> int | None:
    return value if isinstance(value, int) else None


def _string_or_none(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _strings(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [
        item
        for item in value
        if isinstance(item, str) and item
    ]


class _GraphBuilder:
    def __init__(self) -> None:
        self._nodes: dict[str, dict[str, Any]] = {}
        self._edges: dict[tuple[str, str, str], dict[str, Any]] = {}

    def add_node(
        self,
        node_id: str,
        node_type: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        node = self._nodes.setdefault(
            node_id,
            {
                "id": node_id,
                "type": node_type,
                "properties": {},
            },
        )
        node["type"] = node_type
        if properties:
            node["properties"].update(
                {
                    key: value
                    for key, value in properties.items()
                    if value is not None
                }
            )

    def has_node(self, node_id: str) -> bool:
        return node_id in self._nodes

    def add_fact(self, fact_id: str) -> str:
        node_id = f"fact:{fact_id}"
        self.add_node(
            node_id,
            "Fact",
            {
                "fact_id": fact_id,
                "fact_kind": fact_id.split(":", 1)[0],
            },
        )
        return node_id

    def supported_by(self, node_id: str, fact_ids: Any) -> None:
        for fact_id in _strings(fact_ids):
            fact_node_id = self.add_fact(fact_id)
            self.add_edge(node_id, fact_node_id, "SUPPORTED_BY")

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: str,
        properties: dict[str, Any] | None = None,
    ) -> None:
        key = (source, edge_type, target)
        edge = self._edges.setdefault(
            key,
            {
                "source": source,
                "target": target,
                "type": edge_type,
                "properties": {},
            },
        )
        if properties:
            edge["properties"].update(
                {
                    key: value
                    for key, value in properties.items()
                    if value is not None
                }
            )

    def nodes(self) -> list[dict[str, Any]]:
        return list(self._nodes.values())

    def edges(self) -> list[dict[str, Any]]:
        return list(self._edges.values())
