"""Read-only index for context produced by the offline file-context phase."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .file_cpg import _CONTEXT_FAMILIES


class PrebuiltContextError(ValueError):
    """The enriched JSONL is malformed or contains an unsafe context."""


class PrebuiltContextStore:
    def __init__(self, contexts: dict[str, dict[str, Any]]) -> None:
        self._contexts = contexts

    @classmethod
    def load(cls, path: Path) -> "PrebuiltContextStore":
        contexts: dict[str, dict[str, Any]] = {}
        with Path(path).open("r", encoding="utf-8-sig") as handle:
            for line_number, line in enumerate(handle, start=1):
                if not line.strip():
                    continue
                try:
                    record = json.loads(line)
                except json.JSONDecodeError as exc:
                    raise PrebuiltContextError(f"invalid context JSONL at line {line_number}") from exc
                if not isinstance(record, dict) or isinstance(record.get("idx"), bool) or not isinstance(record.get("idx"), int):
                    raise PrebuiltContextError(f"context record at line {line_number} has no integer idx")
                sample_id = f"test_{record['idx']}"
                if sample_id in contexts:
                    raise PrebuiltContextError(f"duplicate context sample {sample_id}")
                context = record.get("context")
                if not isinstance(context, dict):
                    raise PrebuiltContextError(f"context for {sample_id} must be an object")
                if set(context) - set(_CONTEXT_FAMILIES):
                    raise PrebuiltContextError(f"context for {sample_id} has unsupported fields")
                contexts[sample_id] = context
        return cls(contexts)

    def get(self, sample_id: str) -> dict[str, Any]:
        context = self._contexts.get(sample_id)
        return dict(context) if context is not None else {}


__all__ = ["PrebuiltContextError", "PrebuiltContextStore"]
