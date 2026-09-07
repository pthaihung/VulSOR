import json

import pytest
from pydantic import ValidationError

from vulsor.config import RepositoryContextConfig
from vulsor.repository_context.models import (
    AnchorResolution,
    EvidenceBudget,
    EvidenceItem,
    EvidencePhase,
    EvidenceProvenance,
    EvidenceRequest,
    Limitation,
    QueryFamily,
    RelationFamily,
    RepositoryIndexRecord,
    RepositoryRef,
    RepositoryEvidence,
    SourceAnchor,
    SourceLocation,
    TargetAnchor,
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
        json.loads(json.dumps(repository_evidence_payload()))
    )

    assert isinstance(result.evidence, tuple)
    assert result.evidence[0].conditions == ("guarded",)
    assert result.evidence[0].provenance.cpg_node_types == ("Call",)
    assert result.evidence[0].provenance.cpg_node_ids == (42,)
    assert len(result.evidence[0].path) == 1
    assert result.limitations[0].detail == "unresolved"


def repository_evidence_payload() -> dict[str, object]:
    return {
        "request_id": "req-1",
        "status": "complete",
        "resolved_revision": None,
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


def test_evidence_request_accepts_json_lists_after_json_decode() -> None:
    request = EvidenceRequest.model_validate(
        json.loads(json.dumps(request_payload()))
    )

    assert request.questions == ("callee_definition",)
    assert request.allowed_relations == (RelationFamily.CALL,)


@pytest.mark.parametrize(
    "resolved_revision",
    ("abc123", "a" * 39, True),
)
def test_repository_evidence_requires_strict_full_revision(
    resolved_revision: object,
) -> None:
    with pytest.raises(ValidationError):
        RepositoryEvidence.model_validate(
            repository_evidence_payload()
            | {"resolved_revision": resolved_revision}
        )


def test_repository_evidence_accepts_full_revision() -> None:
    result = RepositoryEvidence.model_validate(
        repository_evidence_payload() | {"resolved_revision": "a" * 40}
    )

    assert result.resolved_revision == "a" * 40


def test_repository_evidence_requires_resolved_revision_key() -> None:
    payload = repository_evidence_payload()
    payload.pop("resolved_revision")

    with pytest.raises(ValidationError):
        RepositoryEvidence.model_validate(payload)


def test_unavailable_repository_evidence_accepts_null_revision() -> None:
    result = RepositoryEvidence.model_validate(
        json.loads(json.dumps(repository_evidence_payload() | {"status": "unavailable"}))
    )

    assert result.resolved_revision is None


@pytest.mark.parametrize(
    ("model", "payload"),
    (
        pytest.param(
            TargetAnchor,
            {
                "file_path": "src/demo.c",
                "function_name": "target",
                "start_line": 10,
                "end_line": 9,
                "normalized_code_sha256": "a" * 64,
            },
            id="target-anchor",
        ),
        pytest.param(
            SourceLocation,
            {"file_path": "src/demo.c", "start_line": 10, "end_line": 9},
            id="source-location",
        ),
    ),
)
def test_source_ranges_require_ordered_lines(model: type, payload: dict) -> None:
    with pytest.raises(ValidationError):
        model.model_validate(payload)


@pytest.mark.parametrize(
    ("status", "candidate_count"),
    (
        ("exact", 0),
        ("exact", 2),
        ("not_found", 1),
        ("ambiguous", 0),
        ("ambiguous", 1),
    ),
)
def test_anchor_resolution_requires_status_consistency(
    status: str,
    candidate_count: int,
) -> None:
    with pytest.raises(ValidationError):
        AnchorResolution.model_validate(
            {"status": status, "candidate_count": candidate_count}
        )


@pytest.mark.parametrize(
    ("status", "candidate_count"),
    (("exact", 1), ("not_found", 0), ("ambiguous", 2)),
)
def test_anchor_resolution_accepts_consistent_status(
    status: str,
    candidate_count: int,
) -> None:
    resolution = AnchorResolution.model_validate(
        {"status": status, "candidate_count": candidate_count}
    )

    assert resolution.candidate_count == candidate_count


@pytest.mark.parametrize(
    "build_model",
    (
        pytest.param(
            lambda: RepositoryRef(
                repository_id=" \t",
                repository_url="https://example.test/demo.git",
                revision="a" * 40,
            ),
            id="repository-id",
        ),
        pytest.param(
            lambda: RepositoryIndexRecord(
                sample_id=" ",
                repository=repository_ref(),
                target=TargetAnchor(
                    file_path="src/demo.c",
                    function_name="target",
                    normalized_code_sha256="a" * 64,
                ),
            ),
            id="sample-id",
        ),
        pytest.param(
            lambda: TargetAnchor(
                file_path="\t",
                function_name="target",
                normalized_code_sha256="a" * 64,
            ),
            id="target-file-path",
        ),
        pytest.param(
            lambda: TargetAnchor(
                file_path="src/demo.c",
                function_name=" ",
                normalized_code_sha256="a" * 64,
            ),
            id="target-function-name",
        ),
        pytest.param(
            lambda: SourceAnchor(
                file_path=" ",
                function_name="target",
                operation_kind="call",
                operation_name="consume",
                line=9,
            ),
            id="source-file-path",
        ),
        pytest.param(
            lambda: SourceAnchor(
                file_path="src/demo.c",
                function_name="\t",
                operation_kind="call",
                operation_name="consume",
                line=9,
            ),
            id="source-function-name",
        ),
        pytest.param(
            lambda: SourceAnchor(
                file_path="src/demo.c",
                function_name="target",
                function_signature=" ",
                operation_kind="call",
                operation_name="consume",
                line=9,
            ),
            id="function-signature",
        ),
        pytest.param(
            lambda: SourceAnchor(
                file_path="src/demo.c",
                function_name="target",
                operation_kind=" ",
                operation_name="consume",
                line=9,
            ),
            id="operation-kind",
        ),
        pytest.param(
            lambda: SourceAnchor(
                file_path="src/demo.c",
                function_name="target",
                operation_kind="call",
                operation_name="\t",
                line=9,
            ),
            id="operation-name",
        ),
        pytest.param(
            lambda: SourceAnchor(
                file_path="src/demo.c",
                function_name="target",
                operation_kind="call",
                operation_name="consume",
                line=9,
                entity=" ",
            ),
            id="entity",
        ),
        pytest.param(
            lambda: EvidenceRequest.model_validate(
                request_payload() | {"request_id": " "}
            ),
            id="request-id",
        ),
        pytest.param(
            lambda: EvidenceRequest.model_validate(
                request_payload() | {"obligation_ref": "\t"}
            ),
            id="obligation-ref",
        ),
        pytest.param(
            lambda: EvidenceRequest.model_validate(
                request_payload() | {"questions": [" "]}
            ),
            id="question",
        ),
        pytest.param(
            lambda: SourceLocation(file_path=" ", start_line=1),
            id="location-file-path",
        ),
        pytest.param(
            lambda: SourceLocation(file_path="src/demo.c", start_line=1, code=" "),
            id="location-code",
        ),
        pytest.param(
            lambda: EvidenceProvenance(
                query_family="call_argument", cpg_node_types=[" "]
            ),
            id="cpg-node-type",
        ),
        pytest.param(
            lambda: EvidenceItem(
                evidence_id=" ",
                kind="call",
                subject="target",
                relation="calls",
                source=SourceLocation(file_path="src/demo.c", start_line=1),
                provenance=EvidenceProvenance(query_family="call_argument"),
            ),
            id="evidence-id",
        ),
        pytest.param(
            lambda: EvidenceItem(
                evidence_id="repo_ev_001",
                kind=" ",
                subject="target",
                relation="calls",
                source=SourceLocation(file_path="src/demo.c", start_line=1),
                provenance=EvidenceProvenance(query_family="call_argument"),
            ),
            id="evidence-kind",
        ),
        pytest.param(
            lambda: EvidenceItem(
                evidence_id="repo_ev_001",
                kind="call",
                subject="\t",
                relation="calls",
                source=SourceLocation(file_path="src/demo.c", start_line=1),
                provenance=EvidenceProvenance(query_family="call_argument"),
            ),
            id="evidence-subject",
        ),
        pytest.param(
            lambda: EvidenceItem(
                evidence_id="repo_ev_001",
                kind="call",
                subject="target",
                relation=" ",
                source=SourceLocation(file_path="src/demo.c", start_line=1),
                provenance=EvidenceProvenance(query_family="call_argument"),
            ),
            id="evidence-relation",
        ),
        pytest.param(
            lambda: EvidenceItem(
                evidence_id="repo_ev_001",
                kind="call",
                subject="target",
                relation="calls",
                object=" ",
                source=SourceLocation(file_path="src/demo.c", start_line=1),
                provenance=EvidenceProvenance(query_family="call_argument"),
            ),
            id="evidence-object",
        ),
        pytest.param(
            lambda: EvidenceItem(
                evidence_id="repo_ev_001",
                kind="call",
                subject="target",
                relation="calls",
                conditions=[" "],
                source=SourceLocation(file_path="src/demo.c", start_line=1),
                provenance=EvidenceProvenance(query_family="call_argument"),
            ),
            id="evidence-condition",
        ),
        pytest.param(
            lambda: Limitation(kind=" ", detail="unresolved"),
            id="limitation-kind",
        ),
        pytest.param(
            lambda: Limitation(kind="partial", detail="\t"),
            id="limitation-detail",
        ),
        pytest.param(
            lambda: RepositoryEvidence.model_validate(
                repository_evidence_payload() | {"request_id": " "}
            ),
            id="result-request-id",
        ),
    ),
)
def test_contracts_reject_whitespace_only_important_strings(build_model) -> None:
    with pytest.raises(ValidationError):
        build_model()


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
