from __future__ import annotations

"""Compact Stage-1 semantic contracts for VulSOR v4."""

import re
from collections.abc import Iterable, Mapping
from typing import Any


SCHEMA_VERSION = "semantic-claims-v4.12"
COLLECTIONS = {
    "operation_agent": "operations",
    "state_agent": "states",
    "value_agent": "values",
    "execution_agent": "executions",
}
OPERATION_FIELDS = ("locations", "expression", "claim")
SEMANTIC_FACT_FIELDS = ("entities", "claim", "evidence")
LOCATION_RE = re.compile(r"^L([1-9][0-9]*)$")
EVIDENCE_LINE_RE = re.compile(r"(?m)^\s*L([1-9][0-9]*)\s*:\s*(.+?)\s*$")


class SemanticContractError(ValueError):
    pass


def collection_for_agent(agent_key: str) -> str:
    try:
        return COLLECTIONS[agent_key]
    except KeyError as exc:
        raise SemanticContractError(f"unknown semantic agent: {agent_key}") from exc


def parse_location(value: object, max_line: int | None = None) -> int | None:
    if not isinstance(value, str):
        return None
    match = LOCATION_RE.fullmatch(value.strip())
    if match is None:
        return None
    line = int(match.group(1))
    if max_line is not None and not 1 <= line <= max_line:
        return None
    return line


def format_location(line: int) -> str:
    if isinstance(line, bool) or not isinstance(line, int) or line < 1:
        raise SemanticContractError(f"invalid source line: {line!r}")
    return f"L{line}"


def evidence_fragments(value: object) -> list[tuple[int | None, str]]:
    """Parse canonical semantic evidence into (line, source fragment) pairs.

    Model-provider normalization happens before this function, so the persisted
    contract remains one compact newline-delimited string.
    """
    if not isinstance(value, str):
        return []
    fragments: list[tuple[int | None, str]] = []
    for raw_line in value.splitlines():
        raw_line = raw_line.strip()
        if not raw_line:
            continue
        match = re.fullmatch(r"L([1-9][0-9]*)\s*:\s*(.*)", raw_line)
        if match:
            fragments.append((int(match.group(1)), match.group(2).strip()))
        else:
            fragments.append((None, raw_line))
    return fragments


def validate_claim_output(output: object, agent_key: str, max_line: int) -> list[str]:
    errors: list[str] = []
    if not isinstance(output, dict):
        return ["semantic output must be an object"]

    collection_name = collection_for_agent(agent_key)
    collection = output.get(collection_name)
    if not isinstance(collection, list):
        return [f"$.{collection_name} must be an array"]

    expected_fields = (
        set(OPERATION_FIELDS)
        if agent_key == "operation_agent"
        else set(SEMANTIC_FACT_FIELDS)
    )

    for index, item in enumerate(collection):
        path = f"$.{collection_name}[{index}]"
        if not isinstance(item, dict):
            errors.append(f"{path} must be an object")
            continue

        if set(item) != expected_fields:
            missing = sorted(expected_fields - set(item))
            extra = sorted(set(item) - expected_fields)
            if missing:
                errors.append(f"{path} missing field(s): {', '.join(missing)}")
            if extra:
                errors.append(f"{path} has unsupported field(s): {', '.join(extra)}")

        if agent_key == "operation_agent":
            locations = item.get("locations")
            if not isinstance(locations, list) or not locations:
                errors.append(f"{path}.locations must be a non-empty array")
            else:
                parsed_locations: list[int] = []
                for location_index, location in enumerate(locations):
                    line = parse_location(location, max_line)
                    if line is None:
                        errors.append(
                            f"{path}.locations[{location_index}] must be L1..L{max_line}"
                        )
                    else:
                        parsed_locations.append(line)
                hashable_locations = [
                    location for location in locations if isinstance(location, str)
                ]
                if len(hashable_locations) != len(set(hashable_locations)):
                    errors.append(f"{path}.locations must not contain duplicates")
                if parsed_locations != sorted(parsed_locations):
                    errors.append(f"{path}.locations must be in source order")

            for field in ("expression", "claim"):
                value = item.get(field)
                if not isinstance(value, str) or not value.strip():
                    errors.append(f"{path}.{field} must be a non-empty string")
        else:
            entities = item.get("entities")
            if not isinstance(entities, list) or any(
                not isinstance(value, str) or not value.strip() for value in entities
            ):
                errors.append(f"{path}.entities must be an array of non-empty strings")
            elif len(entities) != len(set(entities)):
                errors.append(f"{path}.entities must not contain duplicates")

            claim = item.get("claim")
            if not isinstance(claim, str) or not claim.strip():
                errors.append(f"{path}.claim must be a non-empty string")

            evidence = item.get("evidence")
            if not isinstance(evidence, str) or not evidence.strip():
                errors.append(f"{path}.evidence must be a non-empty string")
            else:
                for evidence_index, evidence_line in enumerate(
                    evidence.splitlines(), start=1
                ):
                    match = re.fullmatch(
                        r"\s*L([1-9][0-9]*)\s*:\s*\S.*", evidence_line
                    )
                    if match is None:
                        errors.append(
                            f"{path}.evidence line {evidence_index} must use 'L<number>: exact source text'"
                        )
                        continue
                    if int(match.group(1)) > max_line:
                        errors.append(
                            f"{path}.evidence line {evidence_index} must reference L1..L{max_line}"
                        )

    return errors


def validate_operation_references(semantic_model: Mapping[str, Any]) -> list[str]:
    """Compatibility no-op: v4 semantic facts intentionally carry no operation links."""
    return []


def iter_claims(semantic_model: Mapping[str, Any]) -> Iterable[dict[str, Any]]:
    """Iterate the compact flattened Stage-1 model."""
    # v4 flattened form
    if any(name in semantic_model for name in ("operations", "states", "values", "executions")):
        for collection_name in ("operations", "states", "values", "executions"):
            collection = semantic_model.get(collection_name, [])
            if not isinstance(collection, list):
                continue
            agent_key = {
                "operations": "operation_agent",
                "states": "state_agent",
                "values": "value_agent",
                "executions": "execution_agent",
            }[collection_name]
            for index, fact in enumerate(collection):
                if not isinstance(fact, Mapping):
                    continue
                first_location = None
                if collection_name == "operations":
                    locations = fact.get("locations", [])
                    if isinstance(locations, list) and locations:
                        first_location = parse_location(locations[0])
                yield {
                    "ref": f"{collection_name}[{index}]",
                    "agent_key": agent_key,
                    "collection": collection_name,
                    "index": index,
                    "line": first_location,
                    "entities": tuple(
                        str(value)
                        for value in fact.get("entities", [])
                        if isinstance(value, str)
                    ),
                    "fact": dict(fact),
                }
        return

    # Legacy nested form retained for old cached artifacts/helpers.
    for agent_key, collection_name in COLLECTIONS.items():
        output = semantic_model.get(agent_key, {})
        collection = output.get(collection_name, []) if isinstance(output, Mapping) else []
        if not isinstance(collection, list):
            continue
        for index, fact in enumerate(collection):
            if not isinstance(fact, Mapping):
                continue
            yield {
                "ref": f"{agent_key}.{collection_name}[{index}]",
                "agent_key": agent_key,
                "collection": collection_name,
                "index": index,
                "line": None,
                "entities": tuple(
                    str(value)
                    for value in fact.get("entities", [])
                    if isinstance(value, str)
                ),
                "fact": dict(fact),
            }


def resolve_claim_ref(semantic_model: Mapping[str, Any], ref: str) -> str | None:
    return None


def resolve_claim_id(semantic_model: Mapping[str, Any], ref: str) -> str | None:
    return None
