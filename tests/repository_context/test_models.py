import pytest
from pydantic import ValidationError

from vulsor.repository_context.models import (
    EvidenceBudget,
    EvidenceItem,
    EvidencePhase,
    EvidenceProvenance,
    EvidenceRequest,
    QueryFamily,
    RelationFamily,
    RepositoryRef,
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
