from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulsor.repository_context.prebuilt_context import PrebuiltContextError, PrebuiltContextStore


def test_store_loads_context_by_primevul_idx(tmp_path: Path) -> None:
    path = tmp_path / "enriched.jsonl"
    path.write_text(json.dumps({"idx": 7, "func": "ignored", "context": {"types": [{"name": "size_t"}]}}) + "\n", encoding="utf-8")
    store = PrebuiltContextStore.load(path)
    assert store.get("test_7") == {"types": [{"name": "size_t"}]}
    assert store.get("test_8") == {}


def test_store_rejects_context_fields_outside_contract(tmp_path: Path) -> None:
    path = tmp_path / "enriched.jsonl"
    path.write_text(json.dumps({"idx": 7, "context": {"verdict": "bad"}}) + "\n", encoding="utf-8")
    with pytest.raises(PrebuiltContextError, match="unsupported"):
        PrebuiltContextStore.load(path)
