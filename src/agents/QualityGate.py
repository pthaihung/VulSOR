from __future__ import annotations

import json
import re
from typing import Any

from .tools.LineLocatorTool import LineLocatorTool


class QualityGateError(ValueError):
    pass


def validate_output_schema(output: Any, schema: Any, path: str = "$") -> list[str]:
    errors: list[str] = []
    if isinstance(schema, dict):
        if not isinstance(output, dict):
            return [f"{path} must be an object"]
        for key, child_schema in schema.items():
            if key not in output:
                errors.append(f"{path}.{key} is missing")
                continue
            errors.extend(validate_output_schema(output[key], child_schema, f"{path}.{key}"))
        return errors

    if isinstance(schema, list):
        if not isinstance(output, list):
            return [f"{path} must be an array"]
        if schema:
            for index, item in enumerate(output):
                errors.extend(validate_output_schema(item, schema[0], f"{path}[{index}]"))
        return errors

    if isinstance(schema, str):
        if not _matches_schema_scalar(output, schema):
            errors.append(f"{path} must match: {schema}")
    return errors


def validate_line_numbers(output: dict[str, Any], max_line: int) -> list[str]:
    errors: list[str] = []
    for owner_path, owner in _semantic_outputs(output):
        for collection_name in ("operations", "records"):
            for index, item in enumerate(owner.get(collection_name, [])):
                item_path = f"{owner_path}.{collection_name}[{index}]"
                line = item.get("line")
                if line is None:
                    continue
                if not isinstance(line, int):
                    errors.append(f"{item_path}.line must be an integer")
                    continue
                if line < 1 or line > max_line:
                    errors.append(f"{item_path}.line={line} is outside 1..{max_line}")
    return errors


def validate_semantic_fact_contract(output: dict[str, Any], agent_key: str) -> list[str]:
    expected_prefix = {
        "operation_agent": "op_",
        "state_agent": "state_",
        "value_agent": "value_",
        "execution_agent": "exec_",
    }.get(agent_key)
    if expected_prefix is None:
        return []

    errors: list[str] = []
    seen_ids: set[str] = set()
    for owner_path, owner in _semantic_outputs(output):
        for collection_name in ("operations", "records"):
            for index, item in enumerate(owner.get(collection_name, [])):
                item_path = f"{owner_path}.{collection_name}[{index}]"
                item_id = item.get("id")
                if not isinstance(item_id, str) or not item_id.startswith(expected_prefix):
                    errors.append(f"{item_path}.id must start with {expected_prefix!r}")
                elif item_id in seen_ids:
                    errors.append(f"{item_path}.id={item_id!r} is duplicated")
                else:
                    seen_ids.add(item_id)
                if agent_key != "operation_agent":
                    for key in ("entity", "base_entity"):
                        value = item.get(key)
                        if not isinstance(value, str) or not value.strip():
                            errors.append(f"{item_path}.{key} must be a non-empty string")
                for key in _required_string_fact_fields(agent_key):
                    value = item.get(key)
                    if not isinstance(value, str):
                        errors.append(f"{item_path}.{key} must be a string")
                if agent_key == "execution_agent":
                    target_line = item.get("target_line")
                    if not isinstance(target_line, (int, float)) or isinstance(target_line, bool):
                        errors.append(f"{item_path}.target_line must be a number")
    return errors


def validate_nonempty_semantic_output(output: dict[str, Any], agent_key: str, source_code: str) -> list[str]:
    collection_name = "operations" if agent_key == "operation_agent" else "records"
    collection = output.get(collection_name)
    if isinstance(collection, list) and collection:
        return []

    signal_lines = _semantic_signal_lines(source_code, agent_key)
    if not signal_lines:
        return []

    preview = ", ".join(str(line) for line in signal_lines[:8])
    return [
        f"$.{collection_name} must not be empty: source contains "
        f"{len(signal_lines)} high-confidence {agent_key} signal line(s), including line(s) {preview}"
    ]


def _semantic_signal_lines(source_code: str, agent_key: str) -> list[int]:
    patterns = {
        "operation_agent": (
            r"->",
            r"\b[A-Za-z_]\w*\s*\[[^\]]+\]",
            r"\b(?:memcpy|memmove|memset|malloc|calloc|realloc|free|strlen|strcpy|strncpy|read|write)\s*\(",
            r"\(\s*(?:const\s+)?(?:unsigned\s+|signed\s+)?[A-Za-z_]\w*(?:\s+[A-Za-z_]\w*)*\s*\*+\s*\)",
            r"\b[A-Za-z_]\w*\s*(?:\+\+|--|\+=|-=)",
        ),
        "state_agent": (
            r"\bNULL\b",
            r"\b(?:malloc|calloc|realloc|free|open|close|lock|unlock|init|destroy|acquire|release)\w*\s*\(",
            r"\b[A-Za-z_]\w*\s*=\s*(?:NULL|[A-Za-z_]\w*)\s*;",
        ),
        "value_agent": (
            r"\b(?:size|length|count|index|offset|bytes?|rows?|columns?)\w*\b",
            r"\bsizeof\s*\(",
            r"(?:<=|>=|==|!=|<<|>>|\+|\-|\*|/|%)",
            r"\(\s*(?:unsigned|signed|size_t|ssize_t|int|long|short|char|float|double)\b[^)]*\)",
        ),
        "execution_agent": (
            r"\b(?:if|for|while|switch)\s*\(",
            r"\b(?:return|break|continue|goto)\b",
            r"\?[^:;]+:",
        ),
    }.get(agent_key, ())
    if not patterns:
        return []

    cleaned = _strip_comments_and_literals(source_code)
    return [
        line_number
        for line_number, line in enumerate(cleaned.splitlines(), start=1)
        if any(re.search(pattern, line) for pattern in patterns)
    ]


def _strip_comments_and_literals(source_code: str) -> str:
    def preserve_newlines(match: re.Match[str]) -> str:
        return "\n" * match.group(0).count("\n")

    cleaned = re.sub(r"/\*.*?\*/", preserve_newlines, source_code, flags=re.DOTALL)
    cleaned = re.sub(r"//[^\n]*", "", cleaned)
    cleaned = re.sub(r'"(?:\\.|[^"\\])*"', '""', cleaned)
    cleaned = re.sub(r"'(?:\\.|[^'\\])*'", "''", cleaned)
    return cleaned


def _required_string_fact_fields(agent_key: str) -> tuple[str, ...]:
    fields = {
        "operation_agent": (),
        "state_agent": ("access_path", "role", "effect", "target_entity"),
        "value_agent": ("access_path", "role", "effect", "target_entity", "value_entity"),
        "execution_agent": ("role", "effect", "target_entity"),
    }
    return fields.get(agent_key, ())


def _semantic_outputs(output: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    if any(key in output for key in ("operations", "records")):
        return [("$", output)]
    nested = []
    for key in ("operation_agent", "state_agent", "value_agent", "execution_agent"):
        value = output.get(key)
        if isinstance(value, dict):
            nested.append((f"$.{key}", value))
    return nested


def validate_source_grounding(output: dict[str, Any], locator: LineLocatorTool) -> list[str]:
    errors: list[str] = []
    for owner_path, owner in _semantic_outputs(output):
        for collection_name in ("operations", "records"):
            for index, item in enumerate(owner.get(collection_name, [])):
                candidates = _grounding_candidates(item)
                if not candidates:
                    continue
                grounding = resolve_soft_grounding(item, candidates, locator)
                if grounding:
                    item["grounding"] = grounding
                if grounding and grounding.get("status") in {"pass", "warning"}:
                    continue
                if grounding and grounding.get("status") == "retry":
                    errors.append(
                        f"{owner_path}.{collection_name}[{index}] grounding is too weak: "
                        f"claimed_line={grounding.get('claimed_line')}, "
                        f"resolved_line={grounding.get('resolved_line')}, "
                        f"match_type={grounding.get('match_type')}, reason={grounding.get('reason')}"
                    )
                    continue
                errors.append(
                    f"{owner_path}.{collection_name}[{index}] has no source match for any grounding text: "
                    + ", ".join(candidates[:3])
                )
    return errors


def resolve_soft_grounding(
    item: dict[str, Any],
    candidates: list[str],
    locator: LineLocatorTool,
    near_window: int = 2,
) -> dict[str, Any] | None:
    claimed_line = item.get("line")
    matches = []
    for candidate in candidates:
        for match in locator.locate(candidate):
            matches.append(
                {
                    **match,
                    "candidate": candidate,
                    "rank": _match_rank(str(match.get("match_type", "")), float(match.get("score", 0.0) or 0.0)),
                }
            )
    if not matches:
        return None

    best = _best_grounding_match(matches, claimed_line)
    resolved_line = int(best["line"])
    line_delta = _line_delta(claimed_line, resolved_line)
    match_type = str(best.get("match_type", "unknown"))
    score = float(best.get("score", 0.0) or 0.0)

    if line_delta is None:
        status = "warning"
        confidence = "medium" if score >= 0.75 else "low"
        reason = "source evidence was found, but the LLM did not provide a usable line anchor"
    elif line_delta == 0 and match_type in {"exact", "normalized_exact"}:
        status = "pass"
        confidence = "high"
        reason = "evidence matches the claimed line"
    elif line_delta <= near_window and score >= 0.5:
        status = "pass"
        confidence = "high" if match_type in {"exact", "normalized_exact"} else "medium"
        reason = f"evidence resolves within +/-{near_window} lines of the claimed line"
    elif match_type in {"exact", "normalized_exact"}:
        status = "warning"
        confidence = "medium"
        reason = "evidence exists in source, but far from the claimed line"
    elif score >= 0.75:
        status = "warning"
        confidence = "low"
        reason = "weak evidence match exists, but far from the claimed line"
    else:
        status = "retry"
        confidence = "low"
        reason = "evidence only has a weak match far from the claimed line"

    return {
        "claimed_line": claimed_line if isinstance(claimed_line, int) else None,
        "resolved_line": resolved_line,
        "line_delta": line_delta,
        "match_type": match_type,
        "confidence": confidence,
        "status": status,
        "reason": reason,
        "evidence": best.get("candidate", ""),
        "source_line": best.get("text", ""),
    }


def _best_grounding_match(matches: list[dict[str, Any]], claimed_line: Any) -> dict[str, Any]:
    if isinstance(claimed_line, int):
        return sorted(
            matches,
            key=lambda match: (
                abs(int(match["line"]) - claimed_line),
                -float(match.get("rank", 0.0) or 0.0),
                int(match["line"]),
            ),
        )[0]
    return sorted(
        matches,
        key=lambda match: (
            -float(match.get("rank", 0.0) or 0.0),
            int(match["line"]),
        ),
    )[0]


def _line_delta(claimed_line: Any, resolved_line: int) -> int | None:
    if not isinstance(claimed_line, int):
        return None
    return abs(resolved_line - claimed_line)


def _match_rank(match_type: str, score: float) -> float:
    base = {
        "exact": 3.0,
        "normalized_exact": 2.8,
        "identifier": 2.0,
        "token": 1.0,
    }.get(match_type, 0.5)
    return base + score


def _grounding_candidates(item: dict[str, Any]) -> list[str]:
    candidates = []
    for key in ("expression", "evidence"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            candidates.extend(_source_like_fragments(value))
    return candidates


def _source_like_fragments(value: str) -> list[str]:
    value = value.strip()
    fragments = [value]
    quoted = []
    for match in re.finditer(r"`([^`]+)`|\"([^\"]+)\"", value):
        fragment = match.group(1) or match.group(2)
        if fragment:
            quoted.append(fragment.strip())
    fragments.extend(fragment for fragment in quoted if fragment)

    shows_match = re.search(r"\bshows?\s+(.+)$", value, flags=re.IGNORECASE)
    if shows_match:
        fragments.extend(_split_prose_joined_code(shows_match.group(1).strip()))

    line_prefix_match = re.search(r"^line\s+\d+\s*:?\s*(.+)$", value, flags=re.IGNORECASE)
    if line_prefix_match:
        fragments.extend(_split_prose_joined_code(line_prefix_match.group(1).strip()))

    return _dedupe_fragments(fragments)


def _split_prose_joined_code(value: str) -> list[str]:
    fragments = [value]
    for separator in (r";", r"\bfollowed by\b", r"\bthen\b", r"\bon line\s+\d+\b"):
        next_fragments = []
        for fragment in fragments:
            next_fragments.extend(re.split(separator, fragment, flags=re.IGNORECASE))
        fragments = next_fragments
    return [fragment.strip(" ,.;") for fragment in fragments if fragment.strip(" ,.;")]


def _dedupe_fragments(fragments: list[str]) -> list[str]:
    deduped = []
    seen = set()
    for fragment in fragments:
        normalized = fragment.strip("`\"' ")
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        deduped.append(normalized)
    return deduped


def build_retry_user_prompt(
    original_user_prompt: str,
    invalid_output: Any,
    errors: list[str],
    schema: Any,
) -> str:
    previous_output = _compact_retry_value(invalid_output)
    return "\n".join(
        [
            "The previous answer failed validation.",
            "Fix the answer and return exactly one valid JSON object.",
            "Do not add Markdown, code fences, or prose outside JSON.",
            "",
            "validation_errors:",
            json.dumps(errors, ensure_ascii=False, indent=2),
            "",
            "required_schema:",
            json.dumps(schema, ensure_ascii=False, separators=(",", ":")),
            "",
            "previous_output:",
            previous_output,
            "",
            "original_task:",
            original_user_prompt,
        ]
    )


def _compact_retry_value(value: Any, limit: int = 12000) -> str:
    if isinstance(value, dict) and isinstance(value.get("unparseable_output"), str):
        summary = dict(value)
        summary["unparseable_output"] = _truncate_text(value["unparseable_output"], limit)
        value = summary
    text = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    return _truncate_text(text, limit)


def _truncate_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[truncated]"


def _matches_schema_scalar(output: Any, schema: str) -> bool:
    variants = [part.strip() for part in schema.split("|")]
    for variant in variants:
        if variant == "string" and isinstance(output, str):
            return True
        if variant == "number" and isinstance(output, (int, float)) and not isinstance(output, bool):
            return True
        if variant == "boolean" and isinstance(output, bool):
            return True
        if output == _parse_literal(variant):
            return True
    return False


def _parse_literal(value: str) -> Any:
    if value == "null":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    try:
        return int(value)
    except ValueError:
        return value
