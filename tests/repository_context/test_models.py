import pytest
from pydantic import ValidationError

from vulsor.config import RepositoryContextConfig
from vulsor.repository_context.models import (
    EvidenceBudget,
    EvidenceItem,
    EvidencePhase,
    EvidenceProvenance,
    EvidenceRequest,
    QueryFamily,
    RelationFamily,
    RepositoryRef,
    RepositoryEvidence,
    SourceAnchor,
    SourceLocation,
)


def repository_ref() -> RepositoryRef:
    return RepositoryRef(
        repository_id="demo",
        repository_url="https://example.test/demo.git",
        revision="a" * 40,
    )


def test_evidence_request_requires_positive_finite_budget() -> None:
    with pytest.raises(ValidationError):
        EvidenceBudget(max_nodes=0)


def test_evidence_request_is_operation_anchored() -> None:
    request = EvidenceRequest(
        request_id="req-1",
        phase=EvidencePhase.INSTANTIATE,
        obligation_ref="draft-1",
        repository_ref=repository_ref(),
        anchor=SourceAnchor(
            file_path="src/demo.c",
            function_name="target",
            operation_kind="call",
            operation_name="consume",
            line=9,
            entity="value",
        ),
        questions=("callee_definition",),
        allowed_relations=(RelationFamily.CALL,),
    )
    assert request.anchor.operation_name == "consume"
    assert request.budget.max_call_depth == 2


def test_repository_ref_requires_full_commit_sha() -> None:
    with pytest.raises(ValidationError):
        RepositoryRef(
            repository_id="demo",
            repository_url="https://example.test/demo.git",
            revision="abc123",
        )


def test_evidence_provenance_accepts_call_argument_query_family() -> None:
    provenance = EvidenceProvenance(query_family="call_argument")

    assert provenance.query_family is QueryFamily.CALL_ARGUMENT


@pytest.mark.parametrize(
    "evidence_id",
    ("repo_ev_001", "repo_ev_0123456789abcdef"),
)
def test_evidence_item_accepts_documented_evidence_ids(evidence_id: str) -> None:
    item = EvidenceItem(
        evidence_id=evidence_id,
        kind="call",
        subject="target",
        relation="calls",
        source=SourceLocation(file_path="src/demo.c", start_line=9),
        provenance=EvidenceProvenance(query_family="call_argument"),
    )

    assert item.evidence_id == evidence_id


def test_evidence_budget_rejects_bool_for_max_nodes() -> None:
    with pytest.raises(ValidationError):
        EvidenceBudget(max_nodes=True)


def test_source_anchor_rejects_string_for_line() -> None:
    with pytest.raises(ValidationError):
        SourceAnchor(
            file_path="src/demo.c",
            function_name="target",
            operation_kind="call",
            operation_name="consume",
            line="3",
        )


def request_payload() -> dict[str, object]:
    return {
        "request_id": "req-1",
        "phase": "instantiate",
        "obligation_ref": "draft-1",
        "repository_ref": {
            "repository_id": "demo",
            "repository_url": "https://example.test/demo.git",
            "revision": "a" * 40,
        },
        "anchor": {
            "file_path": "src/demo.c",
            "function_name": "target",
            "operation_kind": "call",
            "operation_name": "consume",
            "line": 9,
        },
        "questions": ["callee_definition"],
        "allowed_relations": ["call"],
    }


def test_evidence_request_accepts_json_lists() -> None:
    request = EvidenceRequest.model_validate(request_payload())

    assert request.questions == ("callee_definition",)
    assert request.allowed_relations == (RelationFamily.CALL,)


def test_evidence_request_rejects_invalid_relation_from_json_list() -> None:
    with pytest.raises(ValidationError):
        EvidenceRequest.model_validate(
            request_payload() | {"allowed_relations": ["unknown"]}
        )


def test_evidence_request_rejects_blank_question_from_json_list() -> None:
    with pytest.raises(ValidationError):
        EvidenceRequest.model_validate(request_payload() | {"questions": [" "]})


def test_repository_evidence_accepts_json_lists_for_tuple_arrays() -> None:
    result = RepositoryEvidence.model_validate(
        {
            "request_id": "req-1",
            "status": "complete",
            "anchor_resolution": {"status": "exact", "candidate_count": 1},
            "evidence": [
                {
                    "evidence_id": "repo_ev_001",
                    "kind": "call",
                    "subject": "target",
                    "relation": "calls",
                    "conditions": ["guarded"],
                    "source": {"file_path": "src/demo.c", "start_line": 9},
                    "provenance": {
                        "query_family": "call_argument",
                        "cpg_node_types": ["Call"],
                        "cpg_node_ids": [42],
                    },
                    "path": [{"file_path": "src/demo.c", "start_line": 9}],
                }
            ],
            "limitations": [{"kind": "partial", "detail": "unresolved"}],
        }
    )

    assert isinstance(result.evidence, tuple)
    assert result.evidence[0].conditions == ("guarded",)
    assert result.evidence[0].provenance.cpg_node_types == ("Call",)
    assert result.evidence[0].provenance.cpg_node_ids == (42,)
    assert len(result.evidence[0].path) == 1
    assert result.limitations[0].detail == "unresolved"


@pytest.mark.parametrize(
    "field_name",
    (
        "clone_timeout_seconds",
        "build_timeout_seconds",
        "query_timeout_seconds",
        "lock_timeout_seconds",
    ),
)
@pytest.mark.parametrize("value", (True, 1.5, "60"))
def test_repository_context_timeouts_require_strict_int(
    field_name: str,
    value: object,
) -> None:
    with pytest.raises(ValidationError):
        RepositoryContextConfig(**{field_name: value})
