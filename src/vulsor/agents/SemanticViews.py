"""Deterministic semantic-view builders for B2 agents."""

from __future__ import annotations

from typing import Any


FORBIDDEN_VIEW_KEYS = {
    "verdict",
    "cwe",
    "cve",
    "cve_desc",
    "nvd_url",
    "exploitability",
}

VIEW_REQUIRED_KEYS = {
    "state": ("target", "functions", "variables", "buffers"),
    "value": ("symbols", "constants", "constraints", "bounds_relations"),
    "execution": ("control_regions", "branch_conditions", "ordered_operations"),
    "operation": ("operations", "call_roles", "source_sink_candidates"),
}


def build_state_view(artifact: dict[str, Any]) -> dict[str, Any]:
    facts, analysis = facts_and_analysis(artifact)
    definitions = list_of_dicts(facts.get("definitions"))
    uses = list_of_dicts(facts.get("uses"))
    data_flow = list_of_dicts(facts.get("data_flow"))
    operations = list_of_dicts(facts.get("operations"))
    variable_items = variable_records(definitions, uses, data_flow)
    buffers = buffer_candidates(variable_items, operations)
    functions = function_summaries(list_of_dicts(facts.get("functions")))

    return {
        "target": target_summary(functions),
        "functions": functions,
        "variables": variable_items,
        "objects": object_candidates(variable_items),
        "buffers": buffers,
        "resources": resource_candidates(variable_items, operations),
        "missing_state_facts_summary": missing_context_summary(
            analysis,
            component="state",
            extra=[
                {
                    "kind": "buffer_capacity",
                    "reason": "capacity is not present in B1 facts",
                }
            ]
            if buffers
            else [],
        ),
    }


def build_value_view(artifact: dict[str, Any]) -> dict[str, Any]:
    facts, analysis = facts_and_analysis(artifact)
    definitions = list_of_dicts(facts.get("definitions"))
    uses = list_of_dicts(facts.get("uses"))
    data_flow = list_of_dicts(facts.get("data_flow"))
    operations = list_of_dicts(facts.get("operations"))
    symbols = variable_records(definitions, uses, data_flow)

    return {
        "symbols": [
            {
                "name": item["name"],
                "definition_ids": item["definition_ids"],
                "use_ids": item["use_ids"],
                "provenance": "syntactic_reaching_definition"
                if item["data_flow_count"]
                else "definition_or_use_only",
                "supporting_fact_ids": item["supporting_fact_ids"],
                "confidence": item["confidence"],
                "uncertainty": (
                    "syntactic local data-flow only; no alias/path proof"
                ),
            }
            for item in symbols
        ],
        "constants": constant_candidates(operations),
        "constraints": branch_constraints(facts),
        "bounds_relations": bounds_relation_candidates(operations),
        "nullability_notes": nullability_notes(symbols, operations),
        "missing_value_facts_summary": missing_context_summary(
            analysis,
            component="value",
        ),
    }


def build_execution_view(artifact: dict[str, Any]) -> dict[str, Any]:
    facts, analysis = facts_and_analysis(artifact)
    operations = sorted(
        list_of_dicts(facts.get("operations")),
        key=lambda item: (item.get("line") or 0, item.get("column") or 0),
    )
    control_flow = list_of_dicts(facts.get("control_flow"))

    return {
        "control_regions": [
            {
                "id": block.get("id"),
                "statements": block.get("statements", []),
                "supporting_fact_ids": [block.get("id")]
                if isinstance(block.get("id"), str)
                else [],
                "confidence": "medium",
                "uncertainty": "CFG block source mapping may be unavailable",
            }
            for block in list_of_dicts(facts.get("cfg_blocks"))
        ],
        "branch_conditions": branch_constraints(facts),
        "ordered_operations": [
            {
                "operation_id": op.get("id"),
                "name": op.get("name"),
                "source_location": location(op.get("line"), op.get("column")),
                "order_index": index,
                "supporting_fact_ids": [op.get("id")]
                if isinstance(op.get("id"), str)
                else [],
                "confidence": "high",
                "uncertainty": None,
            }
            for index, op in enumerate(operations)
        ],
        "guard_candidates": guard_candidates(control_flow, operations),
        "missing_execution_facts_summary": missing_context_summary(
            analysis,
            component="execution",
            extra=missing_for_completeness(analysis, "cfg"),
        ),
    }


def build_operation_view(artifact: dict[str, Any]) -> dict[str, Any]:
    facts, analysis = facts_and_analysis(artifact)
    records = []

    for index, operation in enumerate(list_of_dicts(facts.get("operations"))):
        role = operation_role(str(operation.get("name", "")))
        fact_id = operation.get("id")
        records.append(
            {
                "operation_inventory_id": f"opinv:{index}",
                "operation_id": fact_id,
                "name": operation.get("name"),
                "kind": operation.get("kind"),
                "semantic_role": role["role"],
                "resolved": role["resolved"],
                "arguments": operation.get("arguments", []),
                "source_location": location(
                    operation.get("line"),
                    operation.get("column"),
                ),
                "supporting_fact_ids": [fact_id]
                if isinstance(fact_id, str)
                else [],
                "confidence": role["confidence"],
                "uncertainty": role["uncertainty"],
            }
        )

    source_sink_roles = {
        "copy",
        "input",
        "allocation",
        "free",
        "parse",
        "bounds_check",
        "tree_lookup",
        "string_format",
    }

    return {
        "operations": records,
        "call_roles": [
            {
                "operation_inventory_id": item["operation_inventory_id"],
                "name": item["name"],
                "semantic_role": item["semantic_role"],
                "resolved": item["resolved"],
            }
            for item in records
        ],
        "source_sink_candidates": [
            item
            for item in records
            if item["semantic_role"] in source_sink_roles
        ],
        "missing_operation_facts_summary": missing_context_summary(
            analysis,
            component="operation",
        ),
    }


def facts_and_analysis(
    artifact: dict[str, Any],
) -> tuple[dict[str, Any], dict[str, Any]]:
    sample = artifact.get("sample", {})
    result = sample.get("result", {})
    analysis = sample.get("analysis", {})

    return result.get("program_facts") or {}, analysis


def variable_records(
    definitions: list[dict[str, Any]],
    uses: list[dict[str, Any]],
    data_flow: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    items: dict[str, dict[str, Any]] = {}

    for definition in definitions:
        name = definition.get("variable")

        if not isinstance(name, str) or not name:
            continue

        item = items.setdefault(name, variable_template(name))
        item["definition_ids"].append(definition.get("id"))
        item["definition_locations"].append(
            location(definition.get("line"), definition.get("column"))
        )

    for use in uses:
        name = use.get("variable")

        if not isinstance(name, str) or not name:
            continue

        item = items.setdefault(name, variable_template(name))
        item["use_ids"].append(use.get("id"))
        item["use_locations"].append(location(use.get("line"), use.get("column")))

    flow_count_by_variable: dict[str, int] = {}

    for flow in data_flow:
        name = flow.get("variable")

        if isinstance(name, str):
            flow_count_by_variable[name] = flow_count_by_variable.get(name, 0) + 1

    for name, item in items.items():
        item["data_flow_count"] = flow_count_by_variable.get(name, 0)
        item["supporting_fact_ids"] = [
            fact_id
            for fact_id in item["definition_ids"] + item["use_ids"]
            if isinstance(fact_id, str)
        ]
        item["confidence"] = "high" if item["definition_ids"] else "medium"

    return list(items.values())


def variable_template(name: str) -> dict[str, Any]:
    return {
        "name": name,
        "kind": "variable",
        "definition_ids": [],
        "use_ids": [],
        "definition_locations": [],
        "use_locations": [],
        "data_flow_count": 0,
        "supporting_fact_ids": [],
        "confidence": "medium",
        "uncertainty": None,
    }


def object_candidates(variables_: list[dict[str, Any]]) -> list[dict[str, Any]]:
    candidates = []

    for variable in variables_:
        name = str(variable.get("name", ""))

        if not looks_object_like(name):
            continue

        candidates.append(
            {
                "name": name,
                "kind": "object_candidate",
                "supporting_fact_ids": variable["supporting_fact_ids"],
                "confidence": "low",
                "uncertainty": (
                    "object role is inferred from identifier naming only"
                ),
            }
        )

    return candidates


def resource_candidates(
    variables_: list[dict[str, Any]],
    operations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    resource_names = set()

    for operation in operations:
        role = operation_role(str(operation.get("name", "")))["role"]
        if role not in {"allocation", "free", "tree_create", "tree_destroy"}:
            continue

        for argument in operation.get("arguments", []):
            if isinstance(argument, str) and argument:
                resource_names.add(argument)

    candidates = []
    for variable in variables_:
        name = str(variable.get("name", ""))
        if name not in resource_names and not looks_resource_like(name):
            continue

        candidates.append(
            {
                "name": name,
                "kind": "resource_candidate",
                "supporting_fact_ids": variable["supporting_fact_ids"],
                "confidence": "low",
                "uncertainty": (
                    "resource role is inferred from operation/name heuristics; "
                    "ownership and lifetime are not proven"
                ),
            }
        )

    return candidates


def buffer_candidates(
    variables_: list[dict[str, Any]],
    operations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    names_from_operations: set[str] = set()

    for operation in operations:
        role = operation_role(str(operation.get("name", "")))["role"]
        if role not in {"copy", "input", "string_format", "length"}:
            continue

        for argument in operation.get("arguments", []):
            if isinstance(argument, str):
                names_from_operations.update(argument_identifiers(argument))

    candidates = []

    for variable in variables_:
        name = variable["name"]

        reasons = []
        if name in names_from_operations:
            reasons.append("used by buffer-sensitive operation")
        if looks_buffer_like(name):
            reasons.append("identifier looks buffer-like")
        if has_array_like_definition(variable):
            reasons.append("definition text/fact suggests array storage")

        if not reasons:
            continue

        candidates.append(
            {
                "name": name,
                "kind": "buffer_candidate",
                "reasons": reasons,
                "supporting_fact_ids": variable["supporting_fact_ids"],
                "source_locations": (
                    variable["definition_locations"] + variable["use_locations"]
                ),
                "confidence": "medium" if len(reasons) > 1 else "low",
                "uncertainty": (
                    "buffer role is inferred from naming or call arguments; "
                    "capacity is unknown"
                ),
            }
        )

    return candidates


def constant_candidates(operations: list[dict[str, Any]]) -> list[dict[str, Any]]:
    constants = []

    for operation in operations:
        for argument in operation.get("arguments", []):
            if not isinstance(argument, str):
                continue

            if argument.isdigit() or argument.startswith(("0x", "'")):
                constants.append(
                    {
                        "value": argument,
                        "source_location": location(
                            operation.get("line"),
                            operation.get("column"),
                        ),
                        "supporting_fact_ids": [operation.get("id")]
                        if isinstance(operation.get("id"), str)
                        else [],
                        "confidence": "medium",
                        "uncertainty": "constant parsed from operation argument text",
                    }
                )

    return constants


def branch_constraints(facts: dict[str, Any]) -> list[dict[str, Any]]:
    constraints = []

    for edge in list_of_dicts(facts.get("control_flow")):
        condition = edge.get("branch_condition")

        if condition is None:
            continue

        fact_id = edge.get("id")
        constraints.append(
            {
                "condition": condition,
                "source_block": edge.get("source"),
                "target_block": edge.get("target"),
                "supporting_fact_ids": [fact_id]
                if isinstance(fact_id, str)
                else [],
                "confidence": "medium",
                "uncertainty": "CFG condition text may lack precise source mapping",
            }
        )

    return constraints


def bounds_relation_candidates(
    operations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    candidates = []

    for operation in operations:
        name = str(operation.get("name", "")).lower()
        role = operation_role(name)["role"]

        if role not in {"copy", "input", "bounds_check", "length"}:
            continue

        fact_id = operation.get("id")
        candidates.append(
            {
                "operation": operation.get("name"),
                "arguments": operation.get("arguments", []),
                "relation": bounds_relation_for_operation(name, role),
                "source_location": location(
                    operation.get("line"),
                    operation.get("column"),
                ),
                "supporting_fact_ids": [fact_id]
                if isinstance(fact_id, str)
                else [],
                "confidence": "low",
                "uncertainty": "capacity/range is not proven by current B1 facts",
            }
        )

    return candidates


def nullability_notes(
    symbols: list[dict[str, Any]],
    operations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    notes = []
    checked_names = null_check_names(operations)

    for symbol in symbols:
        name = str(symbol.get("name", ""))

        if not looks_pointer_like(name):
            continue

        relation = (
            "null_checked_candidate"
            if name in checked_names
            else "nullability_unknown"
        )

        notes.append(
            {
                "name": name,
                "relation": relation,
                "supporting_fact_ids": symbol.get("supporting_fact_ids", []),
                "confidence": "medium" if name in checked_names else "low",
                "uncertainty": (
                    "null check is inferred from operation argument text; path "
                    "feasibility is not proven"
                    if name in checked_names
                    else "B1 facts do not encode nullability proof"
                ),
            }
        )

    return notes


def guard_candidates(
    control_flow: list[dict[str, Any]],
    operations: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    guards = branch_constraints({"control_flow": control_flow})

    for operation in operations:
        name = str(operation.get("name", "")).lower()

        if not any(token in name for token in ("check", "assert", "valid")):
            continue

        guards.append(
            {
                "operation_id": operation.get("id"),
                "name": operation.get("name"),
                "source_location": location(
                    operation.get("line"),
                    operation.get("column"),
                ),
                "supporting_fact_ids": [operation.get("id")]
                if isinstance(operation.get("id"), str)
                else [],
                "confidence": "low",
                "uncertainty": "guard role is name-based only",
            }
        )

    return guards


def operation_role(name: str) -> dict[str, Any]:
    lowered = name.lower()
    exact_roles = {
        "memcpy": ("copy", True),
        "memmove": ("copy", True),
        "memset": ("write", True),
        "strcpy": ("copy", True),
        "strncpy": ("copy", True),
        "strlcpy": ("copy", True),
        "strcat": ("append", True),
        "strncat": ("append", True),
        "snprintf": ("string_format", True),
        "sprintf": ("string_format", True),
        "formatlocalestring": ("string_format", False),
        "malloc": ("allocation", True),
        "calloc": ("allocation", True),
        "realloc": ("allocation", True),
        "acquirequantummemory": ("allocation", False),
        "acquirestring": ("allocation", False),
        "free": ("free", True),
        "destroystring": ("free", False),
        "read": ("input", True),
        "fread": ("input", True),
        "recv": ("input", True),
        "strlen": ("length", True),
        "strnlen": ("length", True),
        "sizeof": ("size", True),
        "memcmp": ("compare", True),
        "strcmp": ("compare", True),
        "strncmp": ("compare", True),
        "localecompare": ("compare", False),
        "isspace": ("character_check", True),
        "isprint": ("character_check", True),
        "newSplayTree".lower(): ("tree_create", False),
        "destroySplayTree".lower(): ("tree_destroy", False),
        "getvaluefromsplaytree": ("tree_lookup", False),
        "addvaluetosplaytree": ("tree_insert", False),
    }

    if lowered in exact_roles:
        role, standard = exact_roles[lowered]
        return {
            "role": role,
            "resolved": True,
            "confidence": "medium" if standard else "low",
            "uncertainty": (
                "role is based on standard/library operation name"
                if standard
                else "role is inferred from project/library naming convention"
            ),
        }

    pattern_roles = (
        (("check", "valid", "assert", "verify"), "guard_candidate"),
        (("parse", "decode", "readproperty"), "parse"),
        (("length", "size", "count"), "length"),
        (("alloc", "create", "new"), "allocation"),
        (("destroy", "delete", "release"), "free"),
        (("copy", "clone", "dup"), "copy"),
        (("format", "print"), "string_format"),
    )

    for tokens, role in pattern_roles:
        if any(token in lowered for token in tokens):
            return {
                "role": role,
                "resolved": False,
                "confidence": "low",
                "uncertainty": (
                    "project-specific operation role is inferred from name only"
                ),
            }

    if any(token in lowered for token in ("bound", "range", "limit")):
        return {
            "role": "bounds_check",
            "resolved": False,
            "confidence": "low",
            "uncertainty": "bounds role is inferred from name only",
        }

    return {
        "role": "unresolved_call",
        "resolved": False,
        "confidence": "low",
        "uncertainty": "callee contract is not defined in current B1 facts",
    }


def bounds_relation_for_operation(name: str, role: str) -> str:
    if role in {"copy", "input", "string_format"}:
        return "size_or_count_argument_present"
    if role == "bounds_check":
        return "explicit_bounds_check_candidate"
    if role == "length":
        return "length_value_candidate"
    return f"{name}_value_relation_candidate"


def null_check_names(operations: list[dict[str, Any]]) -> set[str]:
    checked = set()
    for operation in operations:
        name = str(operation.get("name", "")).lower()
        args = [
            argument
            for argument in operation.get("arguments", [])
            if isinstance(argument, str)
        ]
        if name in {"assert", "nonnull"} or any(
            token in name
            for token in ("null", "valid", "check")
        ):
            for argument in args:
                checked.update(argument_identifiers(argument))
        for argument in args:
            if "null" in argument.lower():
                checked.update(argument_identifiers(argument))
    return checked


def argument_identifiers(argument: str) -> set[str]:
    return {
        token
        for token in argument.replace("->", " ").replace(".", " ").split()
        if token.isidentifier()
    }


def has_array_like_definition(variable: dict[str, Any]) -> bool:
    name = str(variable.get("name", ""))
    return name.endswith("s") or name.endswith("_stack") or name.endswith("_bytes")


def missing_context(
    analysis: dict[str, Any],
    *,
    extra: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    missing = list(extra or [])

    for item in list_of_dicts(analysis.get("missing_context")):
        missing.append(
            {
                "kind": item.get("kind", "missing_context"),
                "symbol": item.get("symbol"),
                "reason": item.get("diagnostic"),
            }
        )

    return missing


def missing_context_summary(
    analysis: dict[str, Any],
    *,
    component: str,
    extra: list[dict[str, Any]] | None = None,
    sample_limit: int = 5,
) -> dict[str, Any]:
    missing = missing_context(analysis, extra=extra)
    by_kind: dict[str, int] = {}
    for item in missing:
        kind = str(item.get("kind", "missing_context"))
        by_kind[kind] = by_kind.get(kind, 0) + 1

    source_summary = analysis.get("missing_context_summary")
    if not isinstance(source_summary, dict):
        source_summary = {}

    return {
        "component": component,
        "total_items": len(missing),
        "unique_symbols": source_summary.get("unique_symbols"),
        "total_occurrences": source_summary.get("total_occurrences"),
        "by_kind": by_kind,
        "sample": missing[:sample_limit],
        "truncated": len(missing) > sample_limit,
        "detail_source": "input_artifact.analysis.missing_context",
    }


def missing_for_completeness(
    analysis: dict[str, Any],
    component: str,
) -> list[dict[str, Any]]:
    status = (
        (analysis.get("completeness") or {})
        .get(component, {})
        .get("status")
    )

    if status not in {"missing", "limited", "recovered"}:
        return []

    reason = (
        (analysis.get("completeness") or {})
        .get(component, {})
        .get("reason")
    )

    return [
        {
            "kind": f"{component}_facts_{status}",
            "reason": reason,
        }
    ]


def cross_view_links(views: dict[str, Any]) -> list[dict[str, Any]]:
    operation_view = views.get("operation_view") or {}
    state_view = views.get("state_view") or {}
    buffer_names = {
        item.get("name")
        for item in list_of_dicts(state_view.get("buffers"))
        if isinstance(item.get("name"), str)
    }
    links = []

    for operation in list_of_dicts(operation_view.get("operations")):
        args = operation.get("arguments", [])

        if not isinstance(args, list):
            continue

        matched = [arg for arg in args if arg in buffer_names]

        if matched:
            links.append(
                {
                    "kind": "operation_to_buffer_candidate",
                    "operation_inventory_id": operation.get(
                        "operation_inventory_id"
                    ),
                    "buffer_names": matched,
                    "supporting_fact_ids": operation.get(
                        "supporting_fact_ids",
                        [],
                    ),
                    "confidence": "low",
                    "uncertainty": (
                        "link is based on argument text and buffer candidate "
                        "heuristics only"
                    ),
                }
            )

    return links


def validate_semantic_view(
    agent_name: str,
    view: dict[str, Any],
) -> dict[str, Any]:
    """Validate the agent-specific B2 view shape."""
    issues: list[dict[str, Any]] = []

    if agent_name not in VIEW_REQUIRED_KEYS:
        return {
            "status": "error",
            "issues": [
                {
                    "path": "agent",
                    "reason": f"unsupported agent: {agent_name}",
                }
            ],
        }

    if not isinstance(view, dict):
        return {
            "status": "error",
            "issues": [
                {
                    "path": f"{agent_name}_view",
                    "reason": "view must be an object",
                }
            ],
        }

    _validate_no_forbidden_keys(view, f"{agent_name}_view", issues)

    for key in VIEW_REQUIRED_KEYS[agent_name]:
        if key not in view:
            issues.append(
                {
                    "path": f"{agent_name}_view.{key}",
                    "reason": "required key is missing",
                }
            )

    if agent_name == "state":
        _validate_list(view, "variables", issues)
        _validate_list(view, "buffers", issues)
        _validate_list(view, "objects", issues)
        _validate_list(view, "resources", issues)
        _validate_summary(view, "missing_state_facts_summary", issues)

    elif agent_name == "value":
        _validate_list(view, "symbols", issues)
        _validate_list(view, "constants", issues)
        _validate_list(view, "constraints", issues)
        _validate_list(view, "bounds_relations", issues)
        _validate_list(view, "nullability_notes", issues)
        _validate_summary(view, "missing_value_facts_summary", issues)

    elif agent_name == "execution":
        _validate_list(view, "control_regions", issues)
        _validate_list(view, "branch_conditions", issues)
        _validate_list(view, "ordered_operations", issues)
        _validate_list(view, "guard_candidates", issues)
        _validate_summary(view, "missing_execution_facts_summary", issues)

    elif agent_name == "operation":
        _validate_list(view, "operations", issues)
        _validate_list(view, "call_roles", issues)
        _validate_list(view, "source_sink_candidates", issues)
        _validate_summary(view, "missing_operation_facts_summary", issues)

    _validate_observation_lists(view, f"{agent_name}_view", issues)

    return {
        "status": "ok" if not issues else "error",
        "issues": issues,
    }


def _validate_list(
    view: dict[str, Any],
    key: str,
    issues: list[dict[str, Any]],
) -> None:
    if key in view and not isinstance(view[key], list):
        issues.append(
            {
                "path": key,
                "reason": "must be a list",
            }
        )


def _validate_summary(
    view: dict[str, Any],
    key: str,
    issues: list[dict[str, Any]],
) -> None:
    summary = view.get(key)
    if summary is None:
        return

    if not isinstance(summary, dict):
        issues.append({"path": key, "reason": "must be an object"})
        return

    for required in ("component", "total_items", "by_kind", "sample"):
        if required not in summary:
            issues.append(
                {
                    "path": f"{key}.{required}",
                    "reason": "required key is missing",
                }
            )

    if "sample" in summary and not isinstance(summary["sample"], list):
        issues.append({"path": f"{key}.sample", "reason": "must be a list"})


def _validate_observation_lists(
    value: Any,
    path: str,
    issues: list[dict[str, Any]],
) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            _validate_observation_lists(item, f"{path}.{key}", issues)
        return

    if not isinstance(value, list):
        return

    for index, item in enumerate(value):
        item_path = f"{path}[{index}]"
        if not isinstance(item, dict):
            continue

        _validate_no_forbidden_keys(item, item_path, issues)

        fact_ids = item.get("supporting_fact_ids")
        if fact_ids is not None and not (
            isinstance(fact_ids, list)
            and all(isinstance(fact_id, str) for fact_id in fact_ids)
        ):
            issues.append(
                {
                    "path": f"{item_path}.supporting_fact_ids",
                    "reason": "must be a list of strings",
                }
            )

        source_location = item.get("source_location")
        if source_location is not None:
            _validate_location(source_location, f"{item_path}.source_location", issues)

        source_locations = item.get("source_locations")
        if isinstance(source_locations, list):
            for loc_index, loc in enumerate(source_locations):
                _validate_location(
                    loc,
                    f"{item_path}.source_locations[{loc_index}]",
                    issues,
                )


def _validate_location(
    value: Any,
    path: str,
    issues: list[dict[str, Any]],
) -> None:
    if not isinstance(value, dict):
        issues.append({"path": path, "reason": "must be an object"})
        return

    for key in ("line", "column"):
        if key in value and value[key] is not None and not isinstance(value[key], int):
            issues.append(
                {
                    "path": f"{path}.{key}",
                    "reason": "must be an integer or null",
                }
            )


def _validate_no_forbidden_keys(
    value: Any,
    path: str,
    issues: list[dict[str, Any]],
) -> None:
    if isinstance(value, dict):
        for key, item in value.items():
            if key.lower() in FORBIDDEN_VIEW_KEYS:
                issues.append(
                    {
                        "path": f"{path}.{key}",
                        "reason": "forbidden metadata/verdict field in B2 view",
                    }
                )
            _validate_no_forbidden_keys(item, f"{path}.{key}", issues)
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _validate_no_forbidden_keys(item, f"{path}[{index}]", issues)


def function_summaries(
    functions: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            "id": function.get("id"),
            "name": function.get("name"),
            "start_line": function.get("start_line"),
            "end_line": function.get("end_line"),
        }
        for function in functions
    ]


def target_summary(functions: list[dict[str, Any]]) -> dict[str, Any]:
    """Return the target summary from the local function facts."""
    if len(functions) != 1:
        return {
            "available": False,
            "function_count": len(functions),
        }

    function = functions[0]
    return {
        "available": True,
        "name": function.get("name"),
        "start_line": function.get("start_line"),
        "end_line": function.get("end_line"),
        "body_available": True,
    }


def looks_buffer_like(name: str) -> bool:
    return any(
        token in name.lower()
        for token in ("buf", "buffer", "dst", "src", "data", "bytes")
    )


def looks_object_like(name: str) -> bool:
    return name.lower() in {
        "image",
        "profile",
        "property",
        "directory",
        "exif",
    } or any(
        token in name.lower()
        for token in ("object", "ctx", "context", "node", "tree", "image")
    )


def looks_resource_like(name: str) -> bool:
    return any(
        token in name.lower()
        for token in ("resource", "handle", "tree", "profile", "string")
    )


def looks_pointer_like(name: str) -> bool:
    return looks_buffer_like(name) or name.lower() in {
        "ptr",
        "p",
        "image",
        "profile",
        "property",
    }


def location(line: Any, column: Any) -> dict[str, int | None]:
    return {
        "line": line if isinstance(line, int) else None,
        "column": column if isinstance(column, int) else None,
    }


def list_of_dicts(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list):
        return []

    return [
        item
        for item in value
        if isinstance(item, dict)
    ]
