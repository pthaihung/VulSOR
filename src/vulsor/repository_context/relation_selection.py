"""Deterministically select prompt-ready relations from Joern candidates."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


MAX_SEEDS = 2
MAX_DATA_DEPTH = 6
MAX_DATA_FACTS = 16
MAX_CONTROL_FACTS = 20
MAX_DECLARATION_FACTS = 12
MAX_CONTRACT_FACTS = 2
MAX_CALL_FACTS = 12

_CONTROL_PRIORITY = {
    "null_check": 0,
    "bounds_check": 1,
    "overflow_check": 2,
    "type_or_format_dispatch": 3,
    "loop_bound": 4,
    "other_guard": 5,
}


class RelationSelectionError(ValueError):
    """Joern candidate output cannot be selected safely."""


def _items(raw: Mapping[str, object], field: str) -> list[dict[str, Any]]:
    value = raw.get(field, ())
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise RelationSelectionError(f"{field} must be an array")
    result: list[dict[str, Any]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise RelationSelectionError(f"{field} must contain objects")
        code, file_path, line = item.get("code"), item.get("file"), item.get("line")
        if (
            not isinstance(code, str)
            or not code.strip()
            or not isinstance(file_path, str)
            or not file_path.strip()
            or isinstance(line, bool)
            or not isinstance(line, int)
            or line < 1
        ):
            raise RelationSelectionError(f"{field} requires source-grounded items")
        result.append(dict(item))
    return result


def _names(item: Mapping[str, object], field: str) -> set[str]:
    value = item.get(field, ())
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise RelationSelectionError(f"candidate {field} must be an array")
    if any(not isinstance(name, str) or not name.strip() for name in value):
        raise RelationSelectionError(f"candidate {field} must contain names")
    return {name.strip() for name in value}


def _source_key(item: Mapping[str, object]) -> tuple[str, int, str]:
    return (
        str(item["file"]).replace("\\", "/").casefold(),
        int(item["line"]),
        str(item["code"]).casefold(),
    )


def _deduplicate(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    retained: dict[tuple[object, ...], dict[str, Any]] = {}
    for item in items:
        key = (
            str(item["file"]).replace("\\", "/").casefold(),
            item["line"],
            item["code"],
            item.get("role"),
            item.get("provenance"),
        )
        retained.setdefault(key, item)
    return sorted(retained.values(), key=_source_key)


def _seed_entities(seed: Mapping[str, object]) -> set[str]:
    explicit = seed.get("entities")
    if isinstance(explicit, Sequence) and not isinstance(explicit, (str, bytes)):
        return {name.strip() for name in explicit if isinstance(name, str) and name.strip()}
    return _names(seed, "uses") | _names(seed, "defines")


def _fallback_seeds(
    data: list[dict[str, Any]], calls: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    preferred = sorted(
        (item for item in data if item.get("kind") == "parameter"), key=_source_key
    )
    preferred.extend(
        sorted((item for item in data if item.get("kind") == "return"), key=_source_key)
    )
    preferred.extend(
        sorted((item for item in calls if item.get("sensitive") is True), key=_source_key)
    )
    seeds: list[dict[str, Any]] = []
    for item in preferred:
        entities = sorted(_names(item, "defines") | _names(item, "uses"))
        if not entities:
            continue
        seed = dict(item)
        seed["entities"] = entities
        seeds.append(seed)
        if len(seeds) == MAX_SEEDS:
            break
    return seeds


def _limit(
    items: list[dict[str, Any]], limit: int, family: str, limitations: list[str]
) -> list[dict[str, Any]]:
    unique = _deduplicate(items)
    if len(unique) > limit:
        limitations.append(f"{family}: bounded to {limit} items")
    return unique[:limit]


def select_repository_relations(raw: Mapping[str, object]) -> dict[str, object]:
    """Select relation families using explicit Joern entity metadata."""

    if raw.get("target_status") != "exact":
        raise RelationSelectionError("an exact target function is required")
    seeds = _items(raw, "seeds")
    data = _items(raw, "data_candidates")
    controls = _items(raw, "control_candidates")
    declarations = _items(raw, "declaration_candidates")
    contracts = _items(raw, "contract_candidates")
    calls = _items(raw, "call_candidates")
    limitations_value = raw.get("limitations", ())
    if not isinstance(limitations_value, Sequence) or isinstance(
        limitations_value, (str, bytes)
    ):
        raise RelationSelectionError("limitations must be an array")
    limitations = [
        item for item in limitations_value if isinstance(item, str) and item.strip()
    ]

    seeds = sorted(seeds, key=lambda item: (-int(item.get("priority", 0)), *_source_key(item)))[:MAX_SEEDS]
    if not seeds:
        seeds = _fallback_seeds(data, calls)
        limitations.append("seed_fallback_used")

    entities: set[str] = set()
    for seed in seeds:
        seed_entities = _seed_entities(seed)
        seed["entities"] = sorted(seed_entities)
        entities.update(seed_entities)

    selected_data: list[dict[str, Any]] = []
    for _ in range(MAX_DATA_DEPTH):
        found = [item for item in data if _names(item, "defines") & entities]
        new = [item for item in found if item not in selected_data]
        if not new:
            break
        selected_data.extend(new)
        for item in new:
            entities.update(_names(item, "uses"))

    if any(
        item.get("provenance") == "syntactic_assignment_fallback"
        for item in selected_data
    ):
        limitations.append(
            "data_dependencies: syntactic assignment fallback does not prove reaching definitions or aliases"
        )

    retained_lines = {int(item["line"]) for item in (*seeds, *selected_data)}
    selected_controls = [
        item
        for item in controls
        if _names(item, "uses") & entities
        or bool(set(item.get("governs_lines", ())) & retained_lines)
    ]
    selected_controls.sort(
        key=lambda item: (_CONTROL_PRIORITY.get(str(item.get("role")), 99), *_source_key(item))
    )
    selected_declarations = [
        item for item in declarations if _names(item, "defines") & entities
    ]
    selected_contracts = [
        item
        for item in contracts
        if (_names(item, "defines") | _names(item, "uses")) & entities
    ]
    macro_names = {
        str(item["name"])
        for item in selected_contracts
        if isinstance(item.get("name"), str) and str(item["name"]).strip()
    }
    selected_calls = [
        item
        for item in calls
        if str(item.get("callee", "")) not in macro_names
        and (_names(item, "defines") | _names(item, "uses")) & entities
    ]

    selected_data = _limit(selected_data, MAX_DATA_FACTS, "data_dependencies", limitations)
    selected_controls = _limit(
        selected_controls, MAX_CONTROL_FACTS, "control_dependencies", limitations
    )
    selected_declarations = _limit(
        selected_declarations,
        MAX_DECLARATION_FACTS,
        "declarations_types",
        limitations,
    )
    selected_contracts = _limit(
        selected_contracts, MAX_CONTRACT_FACTS, "local_contracts", limitations
    )
    selected_calls = _limit(selected_calls, MAX_CALL_FACTS, "calls", limitations)

    return {
        "anchor_status": "exact",
        "anchors": seeds,
        "data_dependencies": selected_data,
        "control_dependencies": selected_controls,
        "declarations_types": selected_declarations,
        "local_contracts": selected_contracts,
        "calls": selected_calls,
        "limitations": list(dict.fromkeys(limitations)),
        "truncated": bool(raw.get("truncated"))
        or any("bounded to" in item for item in limitations),
    }


__all__ = ["RelationSelectionError", "select_repository_relations"]
