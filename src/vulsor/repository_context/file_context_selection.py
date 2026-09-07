"""Deterministic relation-aware reduction of raw file-level Joern facts."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

FAMILY_LIMITS = {
    "imports": 12, "callee_funcs": 6, "call_relations": 16,
    "call_site_arguments": 24, "data_flow": 32, "control_dependencies": 16,
    "declarations": 24, "types": 24,
}
_SEED_WORDS = re.compile(r"memcpy|memmove|strcpy|strncpy|sprintf|snprintf|malloc|calloc|realloc|read|recv|parse|decode|convert|index|\*|\[", re.I)
_SIZE_WORDS = re.compile(r"size|len|length|count|offset|index|bytes|capacity", re.I)
_NON_SEMANTIC_CALL = re.compile(r"^(log|debug|trace|printf|fprintf|puts|assert)", re.I)
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_KEYWORDS = {"if", "else", "for", "while", "switch", "case", "return", "sizeof", "const", "struct", "unsigned", "signed", "void", "char", "int", "long", "short", "static"}


def _names(item: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    for key in ("defines", "uses"):
        values = item.get(key, [])
        if isinstance(values, list):
            result.update(str(value) for value in values if isinstance(value, str) and value.strip())
    for key in ("name",):
        if isinstance(item.get(key), str):
            result.add(str(item[key]))
    code = item.get("code")
    if isinstance(code, str):
        result.update(_SIZE_WORDS.findall(code))
        result.update(name for name in _IDENTIFIER.findall(code) if name not in _KEYWORDS)
    callee = item.get("callee")
    if isinstance(callee, str):
        result.discard(callee)
    return result


def _relevant(item: Mapping[str, Any], names: set[str]) -> bool:
    if _NON_SEMANTIC_CALL.search(str(item.get("callee", ""))):
        return False
    return bool(names.intersection(_names(item)))


def _rank(family: str, item: Mapping[str, Any]) -> tuple[int, int, str]:
    code = str(item.get("code", ""))
    priority = 0
    if family in {"call_relations", "call_site_arguments"} and _SEED_WORDS.search(code): priority += 100
    if _SIZE_WORDS.search(code): priority += 50
    line = item.get("line")
    line_no = line if isinstance(line, int) and line > 0 else 2**31 - 1
    return (-priority, line_no, json.dumps(item, sort_keys=True, ensure_ascii=True))


def _dedupe_cap(family: str, values: object) -> list[dict[str, Any]]:
    if not isinstance(values, list): return []
    unique: dict[str, dict[str, Any]] = {}
    for value in values:
        if not isinstance(value, Mapping): continue
        item = dict(value)
        code = item.get("code", item.get("name", ""))
        if not isinstance(code, str) or not code.strip(): continue
        key = json.dumps(item, sort_keys=True, ensure_ascii=True)
        unique.setdefault(key, item)
    return sorted(unique.values(), key=lambda item: _rank(family, item))[:FAMILY_LIMITS[family]]


def select_file_context(raw_facts: Mapping[str, object]) -> dict[str, list[dict[str, Any]]]:
    calls = [item for item in raw_facts.get("call_relations", []) if isinstance(item, Mapping)]
    args = [item for item in raw_facts.get("call_site_arguments", []) if isinstance(item, Mapping)]
    names: set[str] = set()
    for item in calls:
        if _SEED_WORDS.search(str(item.get("code", ""))): names.update(_names(item))
    if not names:
        for item in args: names.update(_names(item))
    selected: dict[str, list[dict[str, Any]]] = {}
    for _ in range(3):
        for family in ("data_flow", "control_dependencies", "declarations", "types", "call_relations", "call_site_arguments", "callee_funcs"):
            selected[family] = [dict(item) for item in raw_facts.get(family, []) if isinstance(item, Mapping) and (not names or _relevant(item, names))]
        previous = set(names)
        for item in selected.get("data_flow", []): names.update(_names(item))
        if names == previous: break
    for family in FAMILY_LIMITS:
        values = selected.get(family, []) if family != "imports" else [dict(item) for item in raw_facts.get("imports", []) if isinstance(item, Mapping)]
        capped = _dedupe_cap(family, values)
        if capped: selected[family] = capped
        else: selected.pop(family, None)
    return {family: selected[family] for family in FAMILY_LIMITS if family in selected}
