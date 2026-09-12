from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from .LLMClient import LLMMessage
from .QualityGate import build_retry_user_prompt, validate_output_schema
from .SimpleYaml import load_yaml


class AgentRunError(ValueError):
    """Validated agent failure carrying usage so sample-level failure keeps accounting."""

    def __init__(
        self,
        message: str,
        *,
        agent_key: str,
        errors: list[str],
        attempts: list[dict[str, Any]],
        token_usage: dict[str, int],
    ) -> None:
        super().__init__(message)
        self.agent_key = agent_key
        self.errors = list(errors)
        self.attempts = list(attempts)
        self.token_usage = dict(token_usage)


class PromptAgent:
    def __init__(self, agent_key: str, config: dict[str, Any], project_root: Path, llm_client: Any) -> None:
        self.agent_key = agent_key
        self.config = config
        self.project_root = project_root
        self.llm_client = llm_client
        self.prompt = load_yaml(project_root / config["prompt_file"])
        self.name = config.get("name", self.prompt.get("agent", agent_key))
        self.llm = config.get("llm", {})

    def render_user_prompt(self, variables: dict[str, Any]) -> str:
        template = self.prompt.get("user_prompt_template") or self.prompt.get("prompt_template")
        if not template:
            raise ValueError(f"{self.name} prompt file does not define a prompt template.")
        safe_variables = {
            key: json.dumps(value, ensure_ascii=False, separators=(",", ":")) if isinstance(value, (dict, list)) else str(value)
            for key, value in variables.items()
        }
        return _render_template(template, safe_variables)

    def run(
        self,
        variables: dict[str, Any],
        extra_validators: list[Callable[[Any], list[str]]] | None = None,
        progress_callback: Callable[[dict[str, Any]], None] | None = None,
        progress_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        user_prompt = self.render_user_prompt(variables)
        messages = []
        system_prompt = self.prompt.get("system_prompt")
        if system_prompt:
            messages.append(LLMMessage(role="system", content=system_prompt))
        messages.append(LLMMessage(role="user", content=user_prompt))

        attempts = []
        token_usage = empty_token_usage()
        max_retries = int(self.config.get("quality_gates", {}).get("max_retries", 2))
        # Operation extraction is foundational. Give it at least one correction attempt
        # even when an older agents.yml configured max_retries=0.
        if self.agent_key == "operation_agent":
            max_retries = max(max_retries, 1)
        progress_context = progress_context or {}
        previous_errors: list[str] = []
        for attempt_index in range(max_retries + 1):
            retry_without_reasoning = _should_retry_without_reasoning(previous_errors)
            token_multiplier = _retry_token_multiplier(previous_errors)
            max_tokens = self._effective_max_tokens(
                retry_without_reasoning=retry_without_reasoning,
                token_multiplier=token_multiplier,
            )
            if progress_callback is not None:
                progress_callback(
                    {
                        **progress_context,
                        "event": "llm_attempt_start",
                        "agent_key": self.agent_key,
                        "attempt": attempt_index + 1,
                        "total": max_retries + 1,
                        "retry_without_reasoning": retry_without_reasoning,
                        "token_multiplier": token_multiplier,
                        "max_tokens": max_tokens,
                        "timeout_seconds": int(self.llm.get("timeout_seconds", 120)),
                    }
                )
            raw = self._complete(
                messages,
                retry_without_reasoning=retry_without_reasoning,
                token_multiplier=token_multiplier,
            )
            attempt_usage = token_usage_from_response(raw)
            token_usage = add_token_usage(token_usage, attempt_usage)
            content: str | None = None
            try:
                content = _extract_message_content(raw)
                parsed = _parse_json_content(content)
                parsed = _normalize_common_model_shapes(parsed)
                errors = [] if _is_dry_run(parsed) else validate_output_schema(parsed, self.prompt.get("output_schema", {}))
                for validator in extra_validators or []:
                    errors.extend([] if _is_dry_run(parsed) else validator(parsed))
            except (json.JSONDecodeError, TypeError, ValueError) as exc:
                parsed = {
                    "unparseable_output": content,
                    "raw_response_summary": _summarize_raw_response(raw),
                }
                errors = [str(exc)]

            attempts.append(
                {
                    "attempt": attempt_index + 1,
                    "errors": errors,
                    "token_usage": attempt_usage,
                    "max_tokens": max_tokens,
                }
            )
            if progress_callback is not None:
                progress_callback(
                    {
                        **progress_context,
                        "event": "llm_attempt_done",
                        "agent_key": self.agent_key,
                        "attempt": attempt_index + 1,
                        "total": max_retries + 1,
                        "errors": errors,
                        "token_usage": attempt_usage,
                        "max_tokens": max_tokens,
                    }
                )
            if not errors:
                break

            if attempt_index == max_retries:
                raise AgentRunError(
                    f"{self.name} output failed validation: {'; '.join(errors)}",
                    agent_key=self.agent_key,
                    errors=errors,
                    attempts=attempts,
                    token_usage=token_usage,
                )

            previous_errors = errors
            messages = []
            if system_prompt:
                messages.append(LLMMessage(role="system", content=system_prompt))
            retry_prompt = (
                build_length_retry_user_prompt(user_prompt, self.prompt.get("output_schema", {}))
                if _is_empty_length_error(errors)
                else build_retry_user_prompt(
                    original_user_prompt=user_prompt,
                    invalid_output=parsed,
                    errors=errors,
                    schema=self.prompt.get("output_schema", {}),
                )
            )
            messages.append(
                LLMMessage(
                    role="user",
                    content=retry_prompt,
                )
            )

        return {
            "agent": self.name,
            "parsed": parsed,
            "raw_response": raw,
            "quality_gate": {
                "status": "passed",
                "attempts": attempts,
                "token_usage": token_usage,
            },
        }

    def _complete(
        self,
        messages: list[LLMMessage],
        retry_without_reasoning: bool = False,
        token_multiplier: int = 1,
    ) -> dict[str, Any]:
        max_tokens = int(self.llm.get("max_tokens", 1024))
        reasoning = self.llm.get("reasoning")
        max_tokens = self._effective_max_tokens(
            retry_without_reasoning=retry_without_reasoning,
            token_multiplier=token_multiplier,
        )
        if retry_without_reasoning:
            reasoning = {"enabled": False}
        return self.llm_client.chat_completion(
            messages=messages,
            model=self.llm.get("model"),
            temperature=float(self.llm.get("temperature", 0.0)),
            max_tokens=max_tokens,
            timeout_seconds=int(self.llm.get("timeout_seconds", 120)),
            response_format=self._response_format(),
            reasoning=reasoning,
        )

    def _effective_max_tokens(self, retry_without_reasoning: bool = False, token_multiplier: int = 1) -> int:
        max_tokens = int(self.llm.get("max_tokens", 1024))
        max_tokens *= max(token_multiplier, 1)
        if retry_without_reasoning:
            max_tokens = max(max_tokens * 2, 8192)
        return max_tokens

    def _response_format(self) -> Any:
        configured = self.llm.get("response_format")
        schema = self.prompt.get("output_schema")
        if configured == "json" and schema:
            return {
                "type": "json_schema",
                "json_schema": {
                    "name": _json_schema_name(self.agent_key),
                    "strict": True,
                    "schema": _to_json_schema(schema),
                },
            }
        return configured



def _normalize_common_model_shapes(value: Any) -> Any:
    """Repair only narrow, schema-preserving JSON-shape slips.

    The persisted VulSOR contract stays strict and compact.  This normalizer only
    removes provider formatting wrappers that carry no semantic information:

    * Operation.locations: [{"line":"L12"}] -> ["L12"]
    * semantic evidence: ["L12: x", "L13: y"] -> "L12: x\\nL13: y"
    * evidence items shaped as {"line":"L12","text":"x"} are converted to the
      same canonical string form.

    Anything more ambiguous is left untouched so the normal validators reject it.
    """
    # Stage 3 occasionally wraps the requested raw array in a single `assessments`
    # property. Unwrap only that exact one-field shape; this is representation-only.
    if isinstance(value, dict) and set(value) == {"assessments"} and isinstance(value.get("assessments"), list):
        value = value["assessments"]
    if isinstance(value, list):
        if all(isinstance(item, str) for item in value):
            return [item.strip().lower() for item in value]
        return value
    if not isinstance(value, dict):
        return value

    operations = value.get("operations")
    if isinstance(operations, list):
        for operation in operations:
            if not isinstance(operation, dict):
                continue
            locations = operation.get("locations")
            if not isinstance(locations, list):
                continue
            normalized: list[Any] = []
            changed = False
            for location in locations:
                replacement = None
                if isinstance(location, int) and not isinstance(location, bool) and location > 0:
                    replacement = f"L{location}"
                elif isinstance(location, dict) and len(location) == 1:
                    key, wrapped = next(iter(location.items()))
                    if key in {"line", "location", "value"}:
                        if isinstance(wrapped, int) and not isinstance(wrapped, bool) and wrapped > 0:
                            replacement = f"L{wrapped}"
                        elif isinstance(wrapped, str):
                            candidate = wrapped.strip()
                            if re.fullmatch(r"L[1-9][0-9]*", candidate):
                                replacement = candidate
                normalized.append(replacement if replacement is not None else location)
                changed = changed or replacement is not None
            # Duplicate locations are a presentation-only defect. Preserve the first
            # occurrence and source order rather than spending a retry.
            deduped: list[Any] = []
            seen: set[str] = set()
            for location in normalized:
                key = repr(location)
                if key in seen:
                    changed = True
                    continue
                seen.add(key)
                deduped.append(location)
            if changed:
                operation["locations"] = deduped

    # Duplicate semantic entities do not change the meaning of a fact. Deduplicate
    # them deterministically instead of rejecting the whole agent output.
    for collection_name in ("states", "values", "executions"):
        records = value.get(collection_name)
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            entities = record.get("entities")
            if isinstance(entities, list):
                deduped_entities: list[Any] = []
                seen_entities: set[str] = set()
                for entity in entities:
                    key = entity if isinstance(entity, str) else repr(entity)
                    if key in seen_entities:
                        continue
                    seen_entities.add(key)
                    deduped_entities.append(entity)
                record["entities"] = deduped_entities

    # Some JSON-capable providers still return evidence as an array even though
    # the requested schema is a string.  Joining source citations is lossless and
    # avoids an expensive LLM retry for a purely representational mistake.
    for collection_name in ("states", "values", "executions"):
        records = value.get(collection_name)
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            evidence = record.get("evidence")
            if isinstance(evidence, dict):
                evidence = [evidence]
            if not isinstance(evidence, list):
                continue
            normalized_lines: list[str] = []
            convertible = True
            for item in evidence:
                if isinstance(item, str) and item.strip():
                    normalized_lines.extend(
                        line.strip() for line in item.splitlines() if line.strip()
                    )
                    continue
                if isinstance(item, dict):
                    line_value = item.get("line", item.get("location"))
                    text_value = item.get("text", item.get("source", item.get("evidence")))
                    normalized_line = None
                    if isinstance(line_value, int) and not isinstance(line_value, bool) and line_value > 0:
                        normalized_line = f"L{line_value}"
                    elif isinstance(line_value, str) and re.fullmatch(
                        r"L[1-9][0-9]*", line_value.strip()
                    ):
                        normalized_line = line_value.strip()
                    if normalized_line is not None and isinstance(text_value, str) and text_value.strip():
                        normalized_lines.append(
                            f"{normalized_line}: {text_value.strip()}"
                        )
                        continue
                convertible = False
                break
            if convertible and normalized_lines:
                record["evidence"] = "\n".join(normalized_lines)
    return value

def _parse_json_content(content: str) -> Any:
    try:
        return json.loads(content)
    except json.JSONDecodeError as original_error:
        # A provider can append a second JSON value or short prose despite JSON mode.
        # If the prefix is a complete valid JSON value, keep that value rather than
        # retrying the LLM for a non-semantic trailing-format defect.
        stripped = content.lstrip()
        try:
            parsed, end = json.JSONDecoder().raw_decode(stripped)
            if end > 0:
                return parsed
        except json.JSONDecodeError:
            pass
        candidates = []
        object_start, object_end = content.find("{"), content.rfind("}")
        array_start, array_end = content.find("["), content.rfind("]")
        if object_start != -1 and object_end > object_start:
            candidates.append((object_start, object_end + 1))
        if array_start != -1 and array_end > array_start:
            candidates.append((array_start, array_end + 1))
        for start, end in sorted(candidates, key=lambda item: item[0]):
            try:
                return json.loads(content[start:end])
            except json.JSONDecodeError:
                pass
        raise original_error


def _json_schema_name(agent_key: str) -> str:
    return re.sub(r"[^A-Za-z0-9_]", "_", agent_key).strip("_") or "agent_output"


def _to_json_schema(schema: Any) -> dict[str, Any]:
    if isinstance(schema, dict):
        properties = {key: _to_json_schema(value) for key, value in schema.items()}
        return {
            "type": "object",
            "properties": properties,
            "required": list(properties.keys()),
            "additionalProperties": False,
        }
    if isinstance(schema, list):
        item_schema = _to_json_schema(schema[0]) if schema else {}
        return {
            "type": "array",
            "items": item_schema,
        }
    if isinstance(schema, str):
        return _scalar_to_json_schema(schema)
    return {}


def _scalar_to_json_schema(schema: str) -> dict[str, Any]:
    variants = [part.strip() for part in schema.split("|")]
    if len(variants) == 1:
        variant = variants[0]
        primitive = _primitive_json_schema(variant)
        if primitive is not None:
            return primitive
        if ":" in variant:
            return {"type": "string", "description": variant}
        return {"const": _parse_schema_literal(variant)}

    primitive_types = []
    enum_values = []
    for variant in variants:
        primitive = _primitive_json_schema(variant)
        if primitive is not None and "type" in primitive:
            primitive_types.append(primitive["type"])
        else:
            enum_values.append(_parse_schema_literal(variant))
    if enum_values and not primitive_types:
        return {"enum": enum_values}
    if primitive_types and not enum_values:
        return {"type": primitive_types}
    return {"anyOf": [{"type": value} for value in primitive_types] + [{"enum": enum_values}]}


def _primitive_json_schema(variant: str) -> dict[str, Any] | None:
    if variant == "string":
        return {"type": "string"}
    if variant == "number":
        return {"type": "number"}
    if variant == "boolean":
        return {"type": "boolean"}
    if variant == "null":
        return {"type": "null"}
    return None


def _parse_schema_literal(value: str) -> Any:
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


def _extract_message_content(raw: dict[str, Any]) -> str:
    choices = raw.get("choices")
    if not isinstance(choices, list) or not choices:
        raise ValueError("LLM response did not include any choices.")

    first_choice = choices[0]
    if not isinstance(first_choice, dict):
        raise ValueError("LLM response choice is not an object.")

    message = first_choice.get("message")
    if not isinstance(message, dict):
        raise ValueError("LLM response choice did not include a message object.")

    content = message.get("content")
    if isinstance(content, str):
        if content.strip():
            return content
        raise ValueError(_empty_content_error(first_choice, message))

    if isinstance(content, list):
        text_parts = []
        for part in content:
            if isinstance(part, dict) and isinstance(part.get("text"), str):
                text_parts.append(part["text"])
        joined = "\n".join(text_parts).strip()
        if joined:
            return joined

    raise ValueError(_empty_content_error(first_choice, message))


def _empty_content_error(choice: dict[str, Any], message: dict[str, Any]) -> str:
    details = []
    finish_reason = choice.get("finish_reason")
    if finish_reason:
        details.append(f"finish_reason={finish_reason}")
    refusal = message.get("refusal")
    if refusal:
        details.append(f"refusal={refusal}")
    reasoning = message.get("reasoning")
    if reasoning:
        details.append("reasoning was returned without final JSON content")
    suffix = f" ({'; '.join(details)})" if details else ""
    return f"LLM response message content is empty{suffix}."


def _should_retry_without_reasoning(errors: list[str]) -> bool:
    return any(
        "LLM response message content is empty" in error
        and "finish_reason=length" in error
        and "reasoning was returned without final JSON content" in error
        for error in errors
    )


def _retry_token_multiplier(errors: list[str]) -> int:
    return 2 if _is_empty_length_error(errors) else 1


def _is_empty_length_error(errors: list[str]) -> bool:
    return any(
        ("LLM response message content is empty" in error or "LLM response is empty" in error)
        and "finish_reason=length" in error
        for error in errors
    )


def build_length_retry_user_prompt(original_user_prompt: str, schema: Any, limit: int = 8000) -> str:
    return "\n".join(
        [
            "The previous answer exceeded the output limit and returned no final JSON.",
            "Retry with a much smaller valid JSON object.",
            "Return only the most important records. If uncertain, return an empty array for the top-level collection.",
            "Do not include Markdown, prose, explanations, or extra fields.",
            "",
            "required_schema:",
            json.dumps(schema, ensure_ascii=False, separators=(",", ":")),
            "",
            "original_task_compact:",
            _truncate_text(original_user_prompt, limit),
        ]
    )


def _truncate_text(value: str, limit: int) -> str:
    if len(value) <= limit:
        return value
    return value[:limit] + "\n...[truncated]"


def _looks_like_truncated_json(error: str) -> bool:
    markers = (
        "Unterminated string",
        "Expecting ',' delimiter",
        "Expecting property name enclosed in double quotes",
        "Expecting value",
    )
    return any(marker in error for marker in markers)


def _summarize_raw_response(raw: dict[str, Any]) -> dict[str, Any]:
    choices = raw.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return {"choice_count": 0}

    first_choice = choices[0]
    message = first_choice.get("message") if isinstance(first_choice.get("message"), dict) else {}
    return {
        "choice_count": len(choices),
        "finish_reason": first_choice.get("finish_reason"),
        "message_keys": sorted(message.keys()) if isinstance(message, dict) else [],
    }


def empty_token_usage() -> dict[str, int]:
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
    }


def add_token_usage(left: dict[str, int], right: dict[str, int]) -> dict[str, int]:
    return {
        "input_tokens": left.get("input_tokens", 0) + right.get("input_tokens", 0),
        "output_tokens": left.get("output_tokens", 0) + right.get("output_tokens", 0),
        "total_tokens": left.get("total_tokens", 0) + right.get("total_tokens", 0),
    }


def token_usage_from_response(raw: dict[str, Any]) -> dict[str, int]:
    usage = raw.get("usage")
    if not isinstance(usage, dict):
        return empty_token_usage()

    input_tokens = _int_usage_value(usage, "prompt_tokens", "input_tokens")
    output_tokens = _int_usage_value(usage, "completion_tokens", "output_tokens")
    total_tokens = _int_usage_value(usage, "total_tokens")
    if total_tokens == 0:
        total_tokens = input_tokens + output_tokens
    return {
        "input_tokens": input_tokens,
        "output_tokens": output_tokens,
        "total_tokens": total_tokens,
    }


def _int_usage_value(usage: dict[str, Any], *keys: str) -> int:
    for key in keys:
        value = usage.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, float):
            return int(value)
    return 0


def _is_dry_run(parsed: Any) -> bool:
    return isinstance(parsed, dict) and parsed.get("dry_run") is True


def _render_template(template: str, variables: dict[str, str]) -> str:
    pattern = re.compile(r"(?m)^(?P<prefix>[ \t]*).*?\{(?P<name>[A-Za-z_][A-Za-z0-9_]*)\}")

    def replacement(match: re.Match[str]) -> str:
        name = match.group("name")
        if name not in variables:
            raise KeyError(f"Missing prompt variable: {name}")
        value = variables[name]
        prefix = match.group("prefix")
        indented_value = value.replace("\n", "\n" + prefix)
        return match.group(0).replace("{" + name + "}", indented_value)

    return pattern.sub(replacement, template)
