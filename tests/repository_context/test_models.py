import pytest
from pydantic import ValidationError

from vulsor.repository_context.models import (
    EvidenceBudget,
    EvidencePhase,
    EvidenceRequest,
    RelationFamily,
    RepositoryRef,
    SourceAnchor,
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
