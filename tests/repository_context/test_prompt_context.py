import json

import pytest

from vulsor.repository_context.prompt_context import (
    DEFAULT_MAX_CONTEXT_TOKENS,
    PromptContextError,
    PromptContextRecord,
    load_prompt_context,
    estimate_context_tokens,
    render_prompt_context,
    upsert_prompt_context,
)


def test_context_token_budget_defaults_to_two_thousand_tokens() -> None:
    assert DEFAULT_MAX_CONTEXT_TOKENS == 2_000


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
    assert record.context.count("[DECLARATIONS, TYPES AND CONTRACTS]") == 1
    assert record.context.index("[DATA DEPENDENCIES]") < record.context.index(
        "[CONTROL DEPENDENCIES]"
    ) < record.context.index("[DECLARATIONS, TYPES AND CONTRACTS]") < record.context.index(
        "[CALL RELATIONS]"
    )
    assert 'GetImageProfile(image, "exif") (magick/property.c:101)' in record.context
    assert "const Image *image (magick/property.c:1)" in record.context
    assert "[DATA DEPENDENCIES]\n- No mapped evidence found." in record.context


def test_renderer_rejects_context_that_exceeds_the_character_safety_cap() -> None:
    call = raw_context()["calls"]
    distinct_calls = [
        {**call[0], "code": f"helper_{index}(image)", "callee": f"helper_{index}", "line": 100 + index}
        for index in range(8)
    ]
    with pytest.raises(PromptContextError, match="context exceeds"):
        render_prompt_context(
            "test_194963",
            raw_context(calls=[distinct_calls[0], distinct_calls[0], *distinct_calls[1:]], limitations=[]),
            max_characters=420,
        )


def test_renderer_rejects_non_exact_anchor() -> None:
    with pytest.raises(PromptContextError, match="exact"):
        render_prompt_context("test_194963", raw_context(anchor_status="not_found"))


def test_renderer_uses_anchors_internally_but_emits_only_relation_sections() -> None:
    anchors = [
        {"code": f"*(double *)p{index}", "file": "demo.c", "line": 40 + index}
        for index in range(3)
    ]
    calls = [
        {"code": f"read_{index}(p)", "callee": f"read_{index}", "file": "demo.c", "line": 80 + index}
        for index in range(13)
    ]
    record = render_prompt_context(
        "s1",
        raw_context(
            anchors=anchors,
            data_dependencies=[
                {"anchor_line": 40, "code": "p0 = buffer", "file": "demo.c", "line": 20}
            ],
            control_dependencies=[
                {"anchor_line": 40, "code": "size >= 8", "file": "demo.c", "line": 30}
            ],
            local_contracts=[
                {"code": "p0 = buffer;\n" * 16, "file": "macro.h", "line": 5}
            ],
            calls=calls,
            limitations=[],
        ),
        max_characters=8_000,
    )

    headings = [line for line in record.context.splitlines() if line.startswith("[")]
    assert headings == [
        "[DATA DEPENDENCIES]",
        "[CONTROL DEPENDENCIES]",
        "[DECLARATIONS, TYPES AND CONTRACTS]",
        "[CALL RELATIONS]",
    ]
    assert "[RISK ANCHORS]" not in record.context
    assert "read_11(p)" in record.context
    assert "read_12(p)" not in record.context
    assert record.context.count("p0 = buffer;") == 15
    assert "context_truncated" in record.limitations


def test_renderer_does_not_reduce_selected_unanchored_data_to_eight_items() -> None:
    data = [
        {"code": f"x{index} = source{index}", "file": "demo.c", "line": index + 1}
        for index in range(16)
    ]

    record = render_prompt_context(
        "s1", raw_context(data_dependencies=data, anchors=[], local_contracts=[])
    )

    assert "x15 = source15" in record.context


def test_renderer_rejects_context_that_exceeds_two_thousand_estimated_tokens() -> None:
    long_fact = " ".join("dependency" for _ in range(200))
    data = [
        {"code": f"x{index} = {long_fact}", "file": "demo.c", "line": index + 1}
        for index in range(16)
    ]

    with pytest.raises(PromptContextError, match="context exceeds"):
        render_prompt_context(
            "s1",
            raw_context(data_dependencies=data),
            max_characters=100_000,
        )


def test_renderer_rejects_a_token_limit_above_the_hard_cap() -> None:
    with pytest.raises(PromptContextError, match="max_tokens"):
        render_prompt_context("s1", raw_context(), max_tokens=2_001)


def test_renderer_orders_items_by_source_location_before_text() -> None:
    record = render_prompt_context(
        "s1",
        raw_context(
            calls=[
                {"code": "zeta()", "file": "demo.c", "line": 3},
                {"code": "alpha()", "file": "demo.c", "line": 8},
            ]
        ),
    )

    assert record.context.index("zeta()") < record.context.index("alpha()")


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
