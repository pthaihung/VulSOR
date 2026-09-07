"""Deterministically select prompt-ready relations from Joern candidates."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


MAX_SEEDS = 2
MAX_DATA_DEPTH = 6
MAX_DEFINITIONS_PER_ENTITY = 2
MAX_DATA_FACTS = 16
MAX_CONTROL_FACTS = 20
MAX_DECLARATION_FACTS = 12
MAX_CONTRACT_FACTS = 2
MAX_CALL_FACTS = 12

_CONTROL_PRIORITY = {
    "overflow_check": 0,
    "bounds_check": 1,
    "null_check": 2,
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
    return {
        name.strip()
        for name in value
        if name.strip().casefold() not in {"null", "true", "false"}
    }


def _source_key(item: Mapping[str, object]) -> tuple[str, int, str]:
    return (
        str(item["file"]).replace("\\", "/").casefold(),
        int(item["line"]),
        str(item["code"]).casefold(),
    )


def _governed_lines(item: Mapping[str, object]) -> set[int]:
    value = item.get("governs_lines", ())
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        return set()
    return {
        line for line in value
        if isinstance(line, int) and not isinstance(line, bool) and line >= 1
    }


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


def _deduplicate_in_order(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
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
    return list(retained.values())


def _deduplicate_controls_in_order(
    items: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    retained: dict[tuple[str, str, str], dict[str, Any]] = {}
    for item in items:
        key = (
            str(item["file"]).replace("\\", "/").casefold(),
            str(item["code"]).strip().casefold(),
            str(item.get("role", "")),
        )
        retained.setdefault(key, item)
    return list(retained.values())


def _seed_entities(seed: Mapping[str, object]) -> set[str]:
    explicit = seed.get("entities")
    if isinstance(explicit, Sequence) and not isinstance(explicit, (str, bytes)):
        return {name.strip() for name in explicit if isinstance(name, str) and name.strip()}
    return _names(seed, "uses") | _names(seed, "defines")


def _is_size_or_offset_entity(name: str) -> bool:
    lowered = name.casefold()
    return any(
        marker in lowered
        for marker in ("size", "length", "count", "offset", "index", "bytes", "components", "format")
    )


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
    items: list[dict[str, Any]], limit: int, family: str, limitations: list[str],
    *, priority_ordered: bool = False,
) -> list[dict[str, Any]]:
    unique = _deduplicate_in_order(items) if priority_ordered else _deduplicate(items)
    if len(unique) > limit:
        limitations.append(f"{family}: bounded to {limit} items")
    return sorted(unique[:limit], key=_source_key)


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
    required_before: dict[str, int] = {}
    for seed in seeds:
        seed_entities = _seed_entities(seed)
        seed["entities"] = sorted(seed_entities)
        entities.update(seed_entities)
        for entity in seed_entities:
            required_before[entity] = max(required_before.get(entity, 0), int(seed["line"]))

    selected_data: list[dict[str, Any]] = []
    data_depth: dict[tuple[str, int, str], int] = {}

    def expand_data(rounds: int, *, starting_depth: int = 1) -> None:
        for round_index in range(rounds):
            found: list[dict[str, Any]] = []
            for entity, cutoff in tuple(required_before.items()):
                definitions = [
                    item
                    for item in data
                    if entity in _names(item, "defines") and int(item["line"]) <= cutoff
                ]
                definitions.sort(key=_source_key, reverse=True)
                found.extend(definitions[:MAX_DEFINITIONS_PER_ENTITY])
            new = [item for item in found if item not in selected_data]
            if not new:
                break
            selected_data.extend(new)
            for item in new:
                data_depth[_source_key(item)] = min(
                    data_depth.get(_source_key(item), MAX_DATA_DEPTH + 1),
                    starting_depth + round_index,
                )
                for entity in _names(item, "uses"):
                    entities.add(entity)
                    required_before[entity] = max(
                        required_before.get(entity, 0), int(item["line"])
                    )

    expand_data(MAX_DATA_DEPTH)

    retained_lines = {int(item["line"]) for item in (*seeds, *selected_data)}
    selected_controls = [
        item
        for item in controls
        if _names(item, "uses") & entities
        or bool(_governed_lines(item) & retained_lines)
    ]
    for control in selected_controls:
        if control.get("role") == "other_guard":
            continue
        for entity in _names(control, "uses"):
            entities.add(entity)
            required_before[entity] = max(
                required_before.get(entity, 0), int(control["line"])
            )
    expand_data(3)
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
        or bool(_governed_lines(item) & retained_lines)
    ]

    seed_entity_names = {name for seed in seeds for name in _seed_entities(seed)}
    selected_data.sort(
        key=lambda item: (
            0
            if _names(item, "defines") & seed_entity_names
            else 1
            if data_depth.get(_source_key(item), MAX_DATA_DEPTH + 1) <= 3
            else 2
            if any(_is_size_or_offset_entity(name) for name in _names(item, "defines"))
            else 3,
            -int(item["line"]),
        )
    )
    prioritized_data = _deduplicate_in_order(selected_data)[:MAX_DATA_FACTS]
    selected_data = _limit(
        selected_data, MAX_DATA_FACTS, "data_dependencies", limitations,
        priority_ordered=True,
    )
    entities = set(seed_entity_names)
    for item in selected_data:
        entities.update(_names(item, "defines"))
        entities.update(_names(item, "uses"))
    retained_lines = {int(item["line"]) for item in (*seeds, *selected_data)}
    selected_controls = [
        item
        for item in controls
        if _names(item, "uses") & entities
        or bool(_governed_lines(item) & retained_lines)
    ]
    selected_controls.sort(
        key=lambda item: (
            _CONTROL_PRIORITY.get(str(item.get("role")), 99),
            0 if _governed_lines(item) & retained_lines else 1,
            -len(_names(item, "uses") & entities),
            min(
                (abs(int(item["line"]) - line) for line in retained_lines),
                default=2**31 - 1,
            ),
            *_source_key(item),
        )
    )
    selected_controls = _deduplicate_controls_in_order(selected_controls)
    selected_declarations = [
        item for item in declarations if _names(item, "defines") & entities
    ]
    selected_contracts = [
        item
        for item in contracts
        if (_names(item, "defines") | _names(item, "uses")) & entities
        and (
            not isinstance(item.get("invocation_lines"), Sequence)
            or isinstance(item.get("invocation_lines"), (str, bytes))
            or bool(set(item["invocation_lines"]) & retained_lines)
        )
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
    seed_lines = {int(item["line"]) for item in seeds}
    selected_calls.sort(
        key=lambda item: (
            0 if int(item["line"]) in seed_lines else 1,
            0 if int(item["line"]) in retained_lines else 1,
            0 if item.get("sensitive") is True else 1,
            *_source_key(item),
        )
    )
    entity_order: list[str] = sorted(seed_entity_names)
    for item in prioritized_data:
        for entity in (*sorted(_names(item, "defines")), *sorted(_names(item, "uses"))):
            if entity not in entity_order:
                entity_order.append(entity)
    entity_rank = {entity: index for index, entity in enumerate(entity_order)}
    selected_declarations.sort(
        key=lambda item: (
            min(
                (entity_rank.get(name, len(entity_rank)) for name in _names(item, "defines")),
                default=len(entity_rank),
            ),
            *_source_key(item),
        )
    )
    selected_controls = _limit(
        selected_controls, MAX_CONTROL_FACTS, "control_dependencies", limitations,
        priority_ordered=True,
    )
    selected_declarations = _limit(
        selected_declarations,
        MAX_DECLARATION_FACTS,
        "declarations_types",
        limitations,
        priority_ordered=True,
    )
    selected_contracts = _limit(
        selected_contracts, MAX_CONTRACT_FACTS, "local_contracts", limitations
    )
    selected_calls = _limit(
        selected_calls, MAX_CALL_FACTS, "calls", limitations, priority_ordered=True
    )

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
