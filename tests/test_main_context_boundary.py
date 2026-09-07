import json

from src.agents.Pipeline import (
    STAGE_FILES,
    STAGE_LABELS,
    build_input_context_record,
    build_pipeline_diagnostics,
    filter_evidence_for_obligation,
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


def test_filtered_evidence_uses_optional_input_context() -> None:
    semantic_model = {
        "operation_agent": {
            "operations": [{"id": "op_1", "kind": "memory_access"}],
        },
    }
    obligation = {"operation_id": "op_1", "evidence_refs": []}
    input_context = {"status": "not_provided", "context": {}}

    result = filter_evidence_for_obligation(semantic_model, obligation, input_context)

    assert result["input_context"] == input_context
    assert "cpg_evidence" not in result


def test_unfiltered_evidence_uses_empty_optional_input_context() -> None:
    semantic_model = {
        "operation_agent": {
            "operations": [{"id": "op_1", "kind": "memory_access"}],
        },
    }

    result = filter_evidence_for_obligation(semantic_model, {})

    assert result["semantic_evidence"] == semantic_model
    assert result["input_context"] == {}
    assert "cpg_evidence" not in result


def test_diagnostics_accept_neutral_stage_2_without_missing_repo_warning() -> None:
    semantic = {
        "quality_gate": {"status": "passed"},
        "output": {"semantic_model": {}, "agent_quality_gates": {}},
    }
    input_context = {
        "quality_gate": {"status": "passed"},
        "output": {"status": "not_provided", "context": {}},
    }
    rules = {
        "quality_gate": {"status": "passed"},
        "output": {"rules": []},
    }

    diagnostics = build_pipeline_diagnostics(semantic, input_context, rules, [], [])

    assert diagnostics["stage_status"]["Stage 2"] == "passed"
    assert diagnostics["missing_information"] == []
    assert diagnostics["warnings"] == []
