import json

from src.agents.Pipeline import (
    STAGE_FILES,
    STAGE_LABELS,
    build_input_context_record,
    stage_summary,
)


def test_stage_2_is_a_neutral_input_context_boundary() -> None:
    record = build_input_context_record("test_000001")

    assert STAGE_FILES[2] == ("input_context", "input_context")
    assert STAGE_LABELS[2] == "Stage 2 - input context"
    assert record == {
        "sample_id": "test_000001",
        "stage": "input_context",
        "output": {"status": "not_provided", "context": {}},
        "quality_gate": {"status": "passed"},
        "token_usage": {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
    }
    assert stage_summary(2, record) == "status=not_provided"

    serialized_record = json.dumps(record)
    assert "cpg" not in serialized_record.lower()
    assert "repository_evidence" not in serialized_record.lower()
