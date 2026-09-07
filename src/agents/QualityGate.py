from __future__ import annotations

import json
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
    for collection_name in ("operations", "records"):
        for index, item in enumerate(output.get(collection_name, [])):
            line = item.get("line")
            if line is None:
                continue
            if not isinstance(line, int):
                errors.append(f"{collection_name}[{index}].line must be an integer")
                continue
            if line < 1 or line > max_line:
                errors.append(f"{collection_name}[{index}].line={line} is outside 1..{max_line}")
    return errors


def validate_source_grounding(output: dict[str, Any], locator: LineLocatorTool) -> list[str]:
    errors: list[str] = []
    for collection_name in ("operations", "records"):
        for index, item in enumerate(output.get(collection_name, [])):
            candidates = _grounding_candidates(item)
            if not candidates:
                continue
            if any(locator.has_match(candidate) for candidate in candidates):
                continue
            errors.append(
                f"{collection_name}[{index}] has no source match for any grounding text: "
                + ", ".join(candidates[:3])
            )
    return errors


def _grounding_candidates(item: dict[str, Any]) -> list[str]:
    candidates = []
    for key in ("expression", "operation", "entity", "evidence"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            candidates.append(value.strip())
    return candidates


def build_retry_user_prompt(
    original_user_prompt: str,
    invalid_output: Any,
    errors: list[str],
    schema: Any,
) -> str:
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
            json.dumps(schema, ensure_ascii=False, indent=2),
            "",
            "previous_output:",
            json.dumps(invalid_output, ensure_ascii=False, indent=2),
            "",
            "original_task:",
            original_user_prompt,
        ]
    )


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
