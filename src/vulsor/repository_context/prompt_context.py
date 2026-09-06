"""Compact, prompt-ready repository context produced during offline work."""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from .index import _atomic_write_text


_SECTIONS = (
    ("data_dependencies", "[DATA DEPENDENCIES]"),
    ("control_dependencies", "[CONTROL DEPENDENCIES]"),
    ("declarations_types", "[DECLARATIONS, TYPES AND CONTRACTS]"),
    ("calls", "[CALL RELATIONS]"),
)
MAX_RENDERED_DATA_FACTS = 16
MAX_RENDERED_CONTROL_FACTS = 20
MAX_DECLARATION_FACTS = 12
MAX_CALL_FACTS = 12
MAX_LOCAL_CONTRACT_LINES = 15
DEFAULT_MAX_CONTEXT_CHARACTERS = 8_000
DEFAULT_MAX_CONTEXT_TOKENS = 2_000


class PromptContextError(RuntimeError):
    """The offline extractor did not return renderable target context."""


class PromptContextRecord(BaseModel):
    """The only repository-context artifact consumed by the runtime."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    sample_id: str = Field(min_length=1)
    context: str = Field(min_length=1)
    limitations: tuple[str, ...] = ()


def _as_items(raw: Mapping[str, object], family: str) -> list[Mapping[str, object]]:
    value = raw.get(family, ())
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise PromptContextError(f"{family} must be an array")
    items: list[Mapping[str, object]] = []
    for item in value:
        if not isinstance(item, Mapping):
            raise PromptContextError(f"{family} must contain objects")
        items.append(item)
    return items


def _location(item: Mapping[str, object]) -> str:
    file_path = item.get("file")
    line = item.get("line")
    if isinstance(file_path, str) and isinstance(line, int) and line >= 1:
        return f"{file_path}:{line}"
    if isinstance(file_path, str):
        return file_path
    return "source location unavailable"


def _item_text(family: str, item: Mapping[str, object]) -> str:
    code = item.get("code")
    if not isinstance(code, str) or not code.strip():
        code = item.get("name")
    if not isinstance(code, str) or not code.strip():
        code = "source expression unavailable"
    if family == "calls":
        callee = item.get("callee")
        arguments = item.get("arguments")
        details: list[str] = []
        if isinstance(callee, str) and callee.strip():
            details.append(f"callee: {callee}")
        if isinstance(arguments, Sequence) and not isinstance(arguments, (str, bytes)):
            args = ", ".join(str(argument) for argument in arguments)
            details.append(f"arguments: {args}")
        suffix = f"; {'; '.join(details)}" if details else ""
        return f"- {code} ({_location(item)}){suffix}"
    if family == "declarations_types":
        name, type_name = item.get("name"), item.get("type")
        details = (
            f"; {name}: {type_name}"
            if isinstance(name, str)
            and name.strip()
            and isinstance(type_name, str)
            and type_name.strip()
            else ""
        )
        return f"- {code} ({_location(item)}){details}"
    condition = item.get("condition")
    suffix = f"; condition: {condition}" if isinstance(condition, str) and condition.strip() else ""
    return f"- {code}{suffix} ({_location(item)})"


def _unique_sorted(family: str, items: list[Mapping[str, object]]) -> list[str]:
    rendered = {_item_text(family, item): item for item in items}

    def sort_key(value: str) -> tuple[str, int, str]:
        item = rendered[value]
        file_path = item.get("file")
        line = item.get("line")
        return (
            file_path.replace("\\", "/").casefold()
            if isinstance(file_path, str)
            else "~",
            line if isinstance(line, int) and line >= 1 else 2**31 - 1,
            value.casefold(),
        )

    return sorted(rendered, key=sort_key)


def estimate_context_tokens(text: str) -> int:
    """Conservatively estimate prompt tokens without a model-specific tokenizer."""

    return (len(text.encode("utf-8")) + 2) // 3


def _render_with_budget(
    sections: list[tuple[str, list[str]]], max_characters: int, max_tokens: int
) -> tuple[str, bool]:
    if max_characters < 1:
        raise PromptContextError("max_characters must be positive")
    if max_tokens < 1:
        raise PromptContextError("max_tokens must be positive")
    selected = [[] for _ in sections]
    candidates = [
        (section_index, line)
        for section_index, (_, lines) in enumerate(sections)
        for line in lines
    ]

    def compose() -> str:
        return "\n\n".join(
            "\n".join((heading, *(selected[index] or ["- No mapped evidence found."])))
            for index, (heading, _) in enumerate(sections)
        )

    text = compose()
    if len(text) > max_characters or estimate_context_tokens(text) > max_tokens:
        raise PromptContextError("context budget is too small for the section headers")
    truncated = False
    for section_index, line in candidates:
        selected[section_index].append(line)
        candidate = compose()
        if (
            len(candidate) > max_characters
            or estimate_context_tokens(candidate) > max_tokens
        ):
            selected[section_index].pop()
            truncated = True
            continue
        text = candidate
    if any(len(lines) > 1 for _, lines in sections) and any(
        line not in selected[index]
        for index, (_, lines) in enumerate(sections)
        for line in lines[1:]
    ):
        truncated = True
    return text, truncated


def _limited(lines: list[str], limit: int) -> tuple[list[str], bool]:
    return lines[:limit], len(lines) > limit


def _contract_lines(items: list[Mapping[str, object]]) -> tuple[list[str], bool]:
    lines: list[str] = []
    for item in sorted(
        items,
        key=lambda value: (
            str(value.get("file", "~")).replace("\\", "/").casefold(),
            value.get("line") if isinstance(value.get("line"), int) else 2**31 - 1,
        ),
    ):
        code = item.get("code")
        if not isinstance(code, str) or not code.strip():
            continue
        location = _location(item)
        for source_line in code.splitlines():
            if source_line.strip():
                lines.append(f"- {source_line.strip()} ({location})")
    return _limited(lines, MAX_LOCAL_CONTRACT_LINES)


def render_prompt_context(
    sample_id: str,
    raw: Mapping[str, object],
    *,
    max_characters: int = DEFAULT_MAX_CONTEXT_CHARACTERS,
    max_tokens: int = DEFAULT_MAX_CONTEXT_TOKENS,
) -> PromptContextRecord:
    """Render source-grounded Joern evidence into fixed prompt sections."""

    if not sample_id.strip():
        raise PromptContextError("sample_id must not be blank")
    if (
        isinstance(max_tokens, bool)
        or not isinstance(max_tokens, int)
        or not 1 <= max_tokens <= DEFAULT_MAX_CONTEXT_TOKENS
    ):
        raise PromptContextError(
            f"max_tokens must be between 1 and {DEFAULT_MAX_CONTEXT_TOKENS}"
        )
    if raw.get("anchor_status") != "exact":
        raise PromptContextError("an exact target-function anchor is required")
    limitations_value = raw.get("limitations", ())
    if not isinstance(limitations_value, Sequence) or isinstance(
        limitations_value, (str, bytes)
    ):
        raise PromptContextError("limitations must be an array")
    limitations = tuple(
        str(item) for item in limitations_value if isinstance(item, str) and item.strip()
    )
    sections: list[tuple[str, list[str]]] = []
    for family, heading in _SECTIONS:
        lines = _unique_sorted(family, _as_items(raw, family))
        if family == "declarations_types":
            contracts, _ = _contract_lines(_as_items(raw, "local_contracts"))
            lines.extend(contracts)
        limit = {
            "data_dependencies": MAX_RENDERED_DATA_FACTS,
            "control_dependencies": MAX_RENDERED_CONTROL_FACTS,
            "declarations_types": MAX_DECLARATION_FACTS + MAX_LOCAL_CONTRACT_LINES,
            "calls": MAX_CALL_FACTS,
        }[family]
        lines, family_truncated = _limited(lines, limit)
        if family_truncated:
            limitations = tuple(dict.fromkeys((*limitations, "context_truncated")))
        sections.append((heading, lines or ["- No mapped evidence found."]))
    context, truncated = _render_with_budget(sections, max_characters, max_tokens)
    if bool(raw.get("truncated")) or truncated:
        limitations = tuple(dict.fromkeys((*limitations, "context_truncated")))
    return PromptContextRecord(
        sample_id=sample_id,
        context=context,
        limitations=limitations,
    )


def load_prompt_context(path: Path, sample_id: str) -> PromptContextRecord | None:
    """Read one context record without creating files or invoking tools."""

    if not path.is_file():
        return None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        record = PromptContextRecord.model_validate_json(line)
        if record.sample_id == sample_id:
            return record
    return None


def upsert_prompt_context(path: Path, record: PromptContextRecord) -> None:
    """Atomically replace one sample record while preserving other records."""

    records: dict[str, PromptContextRecord] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                item = PromptContextRecord.model_validate_json(line)
                records[item.sample_id] = item
    records[record.sample_id] = record
    payload = "".join(
        item.model_dump_json() + "\n" for _, item in sorted(records.items())
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    _atomic_write_text(path, payload)


__all__ = [
    "PromptContextError",
    "PromptContextRecord",
    "DEFAULT_MAX_CONTEXT_TOKENS",
    "estimate_context_tokens",
    "load_prompt_context",
    "render_prompt_context",
    "upsert_prompt_context",
]
