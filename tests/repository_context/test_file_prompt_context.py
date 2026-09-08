from __future__ import annotations

import pytest

from tests.context_tool_module import (
    FileContextBudgetError,
    make_sparse_context,
    validate_complete_context,
)


def test_sparse_context_omits_empty_families() -> None:
    assert make_sparse_context({"imports": [], "types": [{"name": "size_t"}]}) == {
        "types": [{"name": "size_t"}]
    }


def test_oversized_context_is_rejected_without_truncation() -> None:
    with pytest.raises(FileContextBudgetError, match="2000"):
        validate_complete_context({"data_flow": [{"code": "x" * 7000}]})
