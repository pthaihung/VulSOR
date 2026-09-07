"""Deterministic relation-aware reduction of raw file-level Joern facts."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from .prompt_context import estimate_context_tokens

MAX_CONTEXT_TOKENS = 2000
SAFE_CONTEXT_TOKENS = 1850
MAX_CONTROLLED_LINES = 8
MAX_CALLEE_BODY_CHARS = 480

FAMILY_LIMITS = {
    "imports": 2,
    "callee_funcs": 4,
    "call_relations": 8,
    "call_site_arguments": 12,
    "data_flow": 8,
    "control_dependencies": 6,
    "declarations": 8,
    "types": 4,
}

_PACK_ORDER = (
    "data_flow",
    "control_dependencies",
    "declarations",
    "types",
    "call_relations",
    "call_site_arguments",
    "callee_funcs",
    "imports",
)
_SEED_WORDS = re.compile(
    r"memcpy|memmove|strcpy|strncpy|sprintf|snprintf|malloc|calloc|realloc|read|recv|parse|decode|convert|index",
    re.I,
)
_SIZE_WORDS = re.compile(r"size|len|length|count|offset|index|bytes|capacity", re.I)
_NON_SEMANTIC_CALL = re.compile(r"^(log|debug|trace|printf|fprintf|puts|assert)", re.I)
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_KEYWORDS = {
    "if", "else", "for", "while", "switch", "case", "return", "sizeof",
    "const", "struct", "unsigned", "signed", "void", "char", "int", "long",
    "short", "static", "true", "false",
}


def _identifier_names(value: object) -> set[str]:
    if not isinstance(value, str):
        return set()
    return {
        name
        for name in _IDENTIFIER.findall(value)
        if name not in _KEYWORDS and len(name) > 1
    }


def _names(item: Mapping[str, Any], *, include_code: bool = True) -> set[str]:
    result: set[str] = set()
    for key in ("defines", "uses"):
        values = item.get(key, [])
        if isinstance(values, list):
            result.update(
                str(value)
                for value in values
                if isinstance(value, str) and value.strip()
            )
    for key in ("name", "callee", "caller", "call"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            result.update(_identifier_names(value))
    for key in ("condition", "type"):
        result.update(_identifier_names(item.get(key)))
    if include_code:
        result.update(_identifier_names(item.get("code")))
    return result


def _semantic_call(item: Mapping[str, Any]) -> bool:
    callee = str(item.get("callee", ""))
    code = str(item.get("code", ""))
    return bool(
        _SEED_WORDS.search(callee)
        or _SEED_WORDS.search(code)
        or _SIZE_WORDS.search(code)
        or "[" in code
        or "*" in code
    )


def _relevant(item: Mapping[str, Any], names: set[str], family: str) -> bool:
    if family in {"call_relations", "call_site_arguments"} and _NON_SEMANTIC_CALL.search(
        str(item.get("callee", item.get("call", "")))
    ):
        return False
    if family == "data_flow":
        explicit = _names(item, include_code=False)
        return bool(names.intersection(explicit or _names(item)))
    if family == "declarations":
        name = item.get("name")
        return isinstance(name, str) and name in names
    if family == "types":
        return bool(names.intersection(_names(item)))
    return bool(names.intersection(_names(item)))


def _rank(family: str, item: Mapping[str, Any]) -> tuple[int, int, int, str]:
    code = str(item.get("code", ""))
    provenance = str(item.get("provenance", ""))
    provenance_rank = {
        "joern_reaching_def": 0,
        "joern_control_dependence": 0,
        "cpg_control": 1,
        "cpg_call": 1,
        "syntactic_assignment": 2,
    }.get(provenance, 1)
    priority = 0
    if family in {"call_relations", "call_site_arguments"} and _semantic_call(item):
        priority += 100
    if _SIZE_WORDS.search(code) or _SIZE_WORDS.search(str(item.get("condition", ""))):
        priority += 50
    line = item.get("line")
    line_no = line if isinstance(line, int) and line > 0 else 2**31 - 1
    return (
        provenance_rank,
        -priority,
        line_no,
        json.dumps(item, sort_keys=True, ensure_ascii=True),
    )


def _compact_item(family: str, value: Mapping[str, Any]) -> dict[str, Any]:
    item = dict(value)
    if family == "call_relations" and item.get("caller") and item.get("callee"):
        # caller/callee/location are the relation; the call expression is
        # duplicated by call_site_arguments when arguments are available.
        item.pop("code", None)
    elif family == "control_dependencies" and item.get("condition"):
        # The condition and controlled line carry the contract; the complete
        # branch body is duplicate source and is often hundreds of tokens.
        item.pop("code", None)
    elif family == "declarations" and item.get("name"):
        # name/type/location is the declaration contract. Keep no duplicate
        # source spelling when the CPG already supplied those fields.
        item.pop("code", None)
    elif family == "data_flow" and item.get("provenance") == "syntactic_assignment":
        code = item.get("code")
        if isinstance(code, str) and len(code) > 240:
            # Do not emit a misleading partial initializer. The explicit
            # defines/uses/location fields are the safe source-level summary.
            item.pop("code", None)
    elif family == "callee_funcs":
        code = item.get("code")
        if isinstance(code, str) and len(code) > MAX_CALLEE_BODY_CHARS:
            # Keep the resolved callee contract and location.  A large body
            # would consume the budget and duplicate the call relation.
            item.pop("code", None)
    return item


def _semantic_key(family: str, item: Mapping[str, Any]) -> str:
    if family == "call_relations":
        value = {key: item.get(key) for key in ("caller", "callee", "code")}
    elif family == "call_site_arguments":
        value = {key: item.get(key) for key in ("call", "argument_index", "code")}
    elif family == "data_flow":
        value = {
            key: item.get(key)
            for key in ("file", "provenance", "defines", "uses", "code")
        }
    elif family == "control_dependencies":
        value = {key: item.get(key) for key in ("file", "condition", "uses", "line", "provenance")}
    else:
        value = dict(item)
    return json.dumps(value, sort_keys=True, ensure_ascii=True)


def _dedupe_cap(family: str, values: object) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        return []
    unique: dict[str, dict[str, Any]] = {}
    for value in values:
        if not isinstance(value, Mapping):
            continue
        item = _compact_item(family, value)
        if family not in {"types"}:
            code = item.get("code", item.get("name", item.get("condition", "")))
            if not isinstance(code, str) or not code.strip():
                # A compact relation may intentionally have no code, but it
                # must still carry a source-level name/condition/contract.
                if not any(item.get(key) for key in ("name", "condition", "defines", "uses", "caller", "callee", "call")):
                    continue
        key = _semantic_key(family, item)
        if key not in unique:
            unique[key] = item
            continue
        previous = unique[key]
        if family == "data_flow":
            from_lines = {
                value
                for value in previous.get("from_lines", [previous.get("from_line")])
                if isinstance(value, int) and value > 0
            }
            if isinstance(item.get("from_line"), int) and item["from_line"] > 0:
                from_lines.add(item["from_line"])
            if len(from_lines) > 1:
                previous["from_lines"] = sorted(from_lines)
                previous.pop("from_line", None)
        elif family == "control_dependencies":
            controlled_lines = {
                value
                for value in previous.get("controlled_lines", [previous.get("controlled_line")])
                if isinstance(value, int) and value > 0
            }
            if isinstance(item.get("controlled_line"), int) and item["controlled_line"] > 0:
                controlled_lines.add(item["controlled_line"])
            if len(controlled_lines) > 1:
                previous["controlled_lines"] = sorted(controlled_lines)[:MAX_CONTROLLED_LINES]
                previous.pop("controlled_line", None)
    return sorted(unique.values(), key=lambda item: _rank(family, item))[: FAMILY_LIMITS[family]]


def _pack_under_budget(
    families: Mapping[str, list[dict[str, Any]]],
    *,
    max_tokens: int,
) -> dict[str, list[dict[str, Any]]]:
    def encoded_tokens(value: Mapping[str, list[dict[str, Any]]]) -> int:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return estimate_context_tokens(encoded)

    def has_call_relation(value: Mapping[str, Any], callee: str) -> bool:
        return str(value.get("callee", "")) == callee

    def remove_one_low_priority(
        candidate: dict[str, list[dict[str, Any]]],
        family: str,
        *,
        required_callee: str,
    ) -> bool:
        values = candidate.get(family, [])
        if not values:
            return False
        if family == "call_relations":
            removable = [
                index
                for index, item in enumerate(values)
                if not has_call_relation(item, required_callee)
            ]
            if not removable:
                return False
            values.pop(removable[-1])
            retained_callees = {
                str(item.get("callee"))
                for item in values
                if item.get("callee")
            }
            candidate["call_site_arguments"] = [
                item
                for item in candidate.get("call_site_arguments", [])
                if str(item.get("call")) in retained_callees
            ]
            return True
        values.pop()
        return True

    def reserve_call_argument(
        current: dict[str, list[dict[str, Any]]],
    ) -> dict[str, list[dict[str, Any]]]:
        retained_calls = {
            str(item.get("callee"))
            for item in current.get("call_relations", [])
            if item.get("callee")
        }
        if not retained_calls:
            return current
        if current.get("call_site_arguments"):
            # The greedy pass already kept at least one valid call-site
            # argument.  Do not append the reservation candidate twice.
            return current

        reserved_argument: dict[str, Any] | None = None
        required_callee = ""
        for item in families.get("call_site_arguments", []):
            call = str(item.get("call", ""))
            if call in retained_calls:
                reserved_argument = item
                required_callee = call
                break
        if reserved_argument is None:
            return current

        candidate = {key: list(value) for key, value in current.items()}
        candidate.setdefault("call_site_arguments", []).append(reserved_argument)
        if encoded_tokens(candidate) <= max_tokens:
            return candidate

        # Preserve the relation and one argument, evicting the least important
        # families first.  The lists are already rank-sorted, so removing the
        # tail also removes the least useful item within each family.
        eviction_order = (
            "imports",
            "types",
            "declarations",
            "control_dependencies",
            "data_flow",
            "callee_funcs",
        )
        while encoded_tokens(candidate) > max_tokens:
            removed = False
            for family in eviction_order:
                if remove_one_low_priority(
                    candidate,
                    family,
                    required_callee=required_callee,
                ):
                    removed = True
                    break
            if not removed:
                # Never evict the relation needed to explain the argument.  If
                # the minimal pair itself does not fit, normal packing remains
                # the truthful fallback and emits no partial pair.
                return current
        return candidate

    selected: dict[str, list[dict[str, Any]]] = {}
    for family in _PACK_ORDER:
        for item in families.get(family, []):
            if family == "call_site_arguments":
                retained_calls = {
                    str(call.get("callee"))
                    for call in selected.get("call_relations", [])
                    if call.get("callee")
                }
                if str(item.get("call")) not in retained_calls:
                    continue
            candidate = {key: list(value) for key, value in selected.items()}
            candidate.setdefault(family, []).append(item)
            if encoded_tokens(candidate) <= max_tokens:
                selected = candidate
    selected = reserve_call_argument(selected)
    return {family: selected[family] for family in FAMILY_LIMITS if family in selected}


def _target_range(raw_facts: Mapping[str, object]) -> tuple[int, int] | None:
    start = raw_facts.get("target_start_line")
    end = raw_facts.get("target_end_line")
    if (
        isinstance(start, int)
        and not isinstance(start, bool)
        and isinstance(end, int)
        and not isinstance(end, bool)
        and start >= 1
        and end >= start
    ):
        return start, end
    return None


def _flow_in_target_scope(item: Mapping[str, Any], raw_facts: Mapping[str, object]) -> bool:
    target = _target_range(raw_facts)
    if target is None:
        return True
    start, end = target
    target_method = raw_facts.get("target_function")
    methods = {
        str(item.get(key))
        for key in ("from_method", "to_method")
        if isinstance(item.get(key), str) and item.get(key)
    }
    if isinstance(target_method, str) and target_method in methods:
        return True
    lines = [
        item.get("line"),
        item.get("from_line"),
    ]
    return any(isinstance(value, int) and start <= value <= end for value in lines)


def select_file_context(
    raw_facts: Mapping[str, object], *, max_tokens: int = SAFE_CONTEXT_TOKENS
) -> dict[str, list[dict[str, Any]]]:
    """Select a relation-aware, complete sparse context under a token budget."""
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens < 1:
        raise ValueError("max_tokens must be a positive integer")

    calls = [item for item in raw_facts.get("call_relations", []) if isinstance(item, Mapping)]
    args = [item for item in raw_facts.get("call_site_arguments", []) if isinstance(item, Mapping)]
    names: set[str] = set()
    semantic_calls = [item for item in calls if _semantic_call(item)]
    seed_calls = semantic_calls or calls
    for item in args:
        if not seed_calls or any(item.get("call") == call.get("callee") for call in seed_calls):
            names.update(_names(item))
    for item in seed_calls:
        names.update(_names(item))
    if not names:
        for item in args:
            names.update(_names(item))

    selected: dict[str, list[dict[str, Any]]] = {}
    for _ in range(3):
        previous = set(names)
        selected["data_flow"] = [
            dict(item)
            for item in raw_facts.get("data_flow", [])
            if isinstance(item, Mapping)
            and _flow_in_target_scope(item, raw_facts)
            and (not names or _relevant(item, names, "data_flow"))
        ]
        for item in selected["data_flow"]:
            names.update(_names(item, include_code=False))
        if names == previous:
            break

    selected["call_relations"] = [
        dict(item)
        for item in calls
        if not _NON_SEMANTIC_CALL.search(str(item.get("callee", "")))
        and (not names or _relevant(item, names, "call_relations") or _semantic_call(item))
    ]
    selected_call_names = {str(item.get("callee")) for item in selected["call_relations"]}
    selected["call_site_arguments"] = [
        dict(item)
        for item in args
        if str(item.get("call", "")) in selected_call_names
        or (not names or _relevant(item, names, "call_site_arguments"))
    ]
    selected["control_dependencies"] = [
        dict(item)
        for item in raw_facts.get("control_dependencies", [])
        if isinstance(item, Mapping) and (not names or _relevant(item, names, "control_dependencies"))
    ]
    selected["declarations"] = [
        dict(item)
        for item in raw_facts.get("declarations", [])
        if isinstance(item, Mapping) and (not names or _relevant(item, names, "declarations"))
    ]
    declaration_types = {
        str(item.get("type"))
        for item in selected["declarations"]
        if isinstance(item.get("type"), str) and item.get("type")
    }
    selected["types"] = [
        dict(item)
        for item in raw_facts.get("types", [])
        if isinstance(item, Mapping)
        and (not declaration_types or str(item.get("name")) in declaration_types)
    ]
    selected_call_names = {str(item.get("callee")) for item in selected["call_relations"]}
    selected["callee_funcs"] = [
        dict(item)
        for item in raw_facts.get("callee_funcs", [])
        if isinstance(item, Mapping)
        and (not selected_call_names or str(item.get("name")) in selected_call_names)
    ]
    selected["imports"] = [
        dict(item) for item in raw_facts.get("imports", []) if isinstance(item, Mapping)
    ]

    capped: dict[str, list[dict[str, Any]]] = {}
    for family, values in selected.items():
        capped_values = _dedupe_cap(family, values)
        if capped_values:
            capped[family] = capped_values
    retained_call_names = {
        str(item.get("callee"))
        for item in capped.get("call_relations", [])
        if item.get("callee")
    }
    if "callee_funcs" in capped:
        capped["callee_funcs"] = [
            item
            for item in capped["callee_funcs"]
            if str(item.get("name")) in retained_call_names
        ]
        if not capped["callee_funcs"]:
            capped.pop("callee_funcs")
    return _pack_under_budget(capped, max_tokens=max_tokens)


__all__ = [
    "FAMILY_LIMITS",
    "MAX_CONTEXT_TOKENS",
    "SAFE_CONTEXT_TOKENS",
    "select_file_context",
]
