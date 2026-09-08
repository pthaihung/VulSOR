"""Serialize complete sparse file context under one strict token budget."""

from __future__ import annotations

import json
from typing import Any, Mapping

MAX_FILE_CONTEXT_TOKENS = 2000

def estimate_context_tokens(text: str) -> int:
    """Conservatively estimate context tokens without a model tokenizer."""
    return (len(text.encode("utf-8")) + 2) // 3


class FileContextBudgetError(ValueError):
    """The entire sparse context cannot fit the fixed input allowance."""


def _clean(value: object) -> object | None:
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return value if value > 0 else None
    if isinstance(value, Mapping):
        cleaned = {str(key): item for key, raw in value.items() if (item := _clean(raw)) is not None}
        return cleaned or None
    if isinstance(value, list):
        cleaned = [item for raw in value if (item := _clean(raw)) is not None]
        return cleaned or None
    return None


def make_sparse_context(payload: Mapping[str, object]) -> dict[str, object]:
    """Drop unmapped/blank content without fabricating context."""
    sparse: dict[str, object] = {}
    for family in sorted(payload):
        cleaned = _clean(payload[family])
        if cleaned is not None:
            sparse[family] = cleaned
    return sparse


def validate_complete_context(context: Mapping[str, object]) -> dict[str, object]:
    sparse = make_sparse_context(context)
    encoded = json.dumps(sparse, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    tokens = estimate_context_tokens(encoded)
    if tokens > MAX_FILE_CONTEXT_TOKENS:
        raise FileContextBudgetError(
            f"complete file context exceeds {MAX_FILE_CONTEXT_TOKENS} tokens ({tokens})"
        )
    return sparse


__all__ = [
    "FileContextBudgetError",
    "MAX_FILE_CONTEXT_TOKENS",
    "estimate_context_tokens",
    "make_sparse_context",
    "validate_complete_context",
]
