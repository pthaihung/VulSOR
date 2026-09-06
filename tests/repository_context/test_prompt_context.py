import json

import pytest

from vulsor.repository_context.prompt_context import (
    PromptContextError,
    PromptContextRecord,
    load_prompt_context,
    render_prompt_context,
    upsert_prompt_context,
)


def raw_context(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "anchor_status": "exact",
        "calls": [
            {
                "code": 'GetImageProfile(image, "exif")',
                "callee": "GetImageProfile",
                "arguments": ["image", '"exif"'],
                "file": "magick/property.c",
                "line": 101,
            }
        ],
        "data_dependencies": [],
        "control_dependencies": [],
        "declarations_types": [
            {
                "code": "const Image *image",
                "name": "image",
                "type": "const Image *",
                "file": "magick/property.c",
                "line": 1,
            }
        ],
        "limitations": ["data_dependencies: no mapped evidence was found"],
        "truncated": False,
    }
    payload.update(overrides)
    return payload


def test_renderer_emits_all_paper_sections_and_preserves_limitations() -> None:
    record = render_prompt_context("test_194963", raw_context(), max_characters=4000)

    assert isinstance(record, PromptContextRecord)
    assert record.sample_id == "test_194963"
    assert record.limitations == ("data_dependencies: no mapped evidence was found",)
    assert record.context.count("[CALL RELATIONS]") == 1
    assert record.context.count("[DATA DEPENDENCIES]") == 1
    assert record.context.count("[CONTROL DEPENDENCIES]") == 1
    assert record.context.count("[DECLARATIONS AND TYPES]") == 1
    assert record.context.index("[CALL RELATIONS]") < record.context.index(
        "[DATA DEPENDENCIES]"
    ) < record.context.index("[CONTROL DEPENDENCIES]") < record.context.index(
        "[DECLARATIONS AND TYPES]"
    )
    assert 'GetImageProfile(image, "exif") (magick/property.c:101)' in record.context
    assert "const Image *image (magick/property.c:1)" in record.context
    assert "[DATA DEPENDENCIES]\n- No mapped evidence found." in record.context


def test_renderer_deduplicates_and_truncates_at_item_boundaries() -> None:
    call = raw_context()["calls"]
    distinct_calls = [
        {**call[0], "code": f"helper_{index}(image)", "callee": f"helper_{index}", "line": 100 + index}
        for index in range(8)
    ]
    record = render_prompt_context(
        "test_194963",
        raw_context(calls=[distinct_calls[0], distinct_calls[0], *distinct_calls[1:]], limitations=[]),
        max_characters=420,
    )

    assert record.context.count("helper_0(image)") == 1
    assert "context_truncated" in record.limitations
    assert len(record.context) <= 420


def test_renderer_rejects_non_exact_anchor() -> None:
    with pytest.raises(PromptContextError, match="exact"):
        render_prompt_context("test_194963", raw_context(anchor_status="not_found"))


def test_jsonl_upsert_replaces_selected_record_and_preserves_others(tmp_path) -> None:
    path = tmp_path / "context.jsonl"
    other = PromptContextRecord(sample_id="other", context="other context")
    selected = render_prompt_context("test_194963", raw_context())
    replacement = PromptContextRecord(
        sample_id="test_194963", context="replacement context", limitations=("limited",)
    )

    upsert_prompt_context(path, other)
    upsert_prompt_context(path, selected)
    upsert_prompt_context(path, replacement)

    records = [PromptContextRecord.model_validate(json.loads(line)) for line in path.read_text(encoding="utf-8").splitlines()]
    assert {record.sample_id for record in records} == {"other", "test_194963"}
    assert load_prompt_context(path, "test_194963") == replacement
    assert load_prompt_context(path, "missing") is None
