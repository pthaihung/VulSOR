"""Contract tests for validating and grounding repository evidence."""

from copy import deepcopy
from pathlib import Path

import pytest

from vulsor.repository_context.evidence import (
    normalize_repository_evidence,
    validate_raw_result,
)
from vulsor.repository_context.models import EvidenceRequest


def request(**budget: int) -> EvidenceRequest:
    return EvidenceRequest.model_validate(
        {
            "request_id": "req-8",
            "phase": "evaluate",
            "obligation_ref": "ob-1",
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
                "line": 1,
            },
            "questions": ["callee_definition"],
            "allowed_relations": [
                "call",
                "argument",
                "data_flow",
                "control_dependence",
                "declaration",
                "type",
            ],
            "budget": budget,
        }
    )


def node(node_id: int = 1, line: int = 1, **changes) -> dict:
    return {
        "id": node_id,
        "nodeType": "CALL",
        "name": "consume",
        "code": "untrusted fabricated code\nand extra lines",
        "file": "src/demo.c",
        "line": line,
        "column": None,
        "method": "target",
        "typeFullName": "void",
        "argumentIndex": None,
    } | changes


def record(kind: str = "anchor", node_id: int = 1, line: int = 1, **changes) -> dict:
    return {
        "kind": kind,
        "relation": "calls",
        "subject": "target",
        "object": None,
        "conditions": [],
        "node": node(node_id, line),
        "path": [],
    } | changes


def payload(**families: list) -> dict:
    return {
        "schema_version": 1,
        "request_id": "req-8",
        "resolved_revision": "a" * 40,
        "anchor_resolution": {"status": "exact", "candidate_count": 1},
        "families": dict.fromkeys(
            [family.value for family in request().allowed_relations], []
        )
        | families,
        "limitations": [],
        "truncated": False,
    }


@pytest.fixture
def repository(tmp_path: Path) -> Path:
    source = tmp_path / "src/demo.c"
    source.parent.mkdir()
    source.write_text(
        "".join(f"  actual_source_{i}();\n" for i in range(1, 21)), encoding="utf-8"
    )
    return tmp_path


def test_validator_returns_json_without_filesystem_reads(monkeypatch) -> None:
    def forbid_read(*args, **kwargs):
        pytest.fail("raw validation must not access the filesystem")

    for name in ("open", "read_text", "resolve", "stat", "lstat"):
        monkeypatch.setattr(Path, name, forbid_read)
    raw = payload(call=[record()])
    before = deepcopy(raw)
    result = validate_raw_result(raw, request())
    assert result == raw == before
    assert result is not raw


@pytest.mark.parametrize(
    "field,value",
    [
        ("schema_version", True),
        ("schema_version", 2),
        ("schema_version", "1"),
        ("request_id", "other"),
        ("resolved_revision", "b" * 40),
        ("resolved_revision", None),
        ("resolved_revision", "abc"),
        ("families", []),
        ("limitations", {}),
        ("truncated", 1),
        ("extra", "/private/secret"),
    ],
)
def test_rejects_bad_envelope(field: str, value) -> None:
    with pytest.raises(ValueError):
        validate_raw_result(payload() | {field: value}, request())


@pytest.mark.parametrize("field", list(payload()))
def test_requires_every_envelope_field(field: str) -> None:
    raw = payload()
    del raw[field]
    with pytest.raises(ValueError):
        validate_raw_result(raw, request())


@pytest.mark.parametrize(
    "status,count",
    [
        ("exact", 0),
        ("exact", 2),
        ("not_found", 1),
        ("ambiguous", 1),
        ("unknown", 1),
        ("exact", True),
        ("exact", "1"),
    ],
)
def test_rejects_inconsistent_anchor(status, count) -> None:
    with pytest.raises(ValueError):
        validate_raw_result(
            payload()
            | {
                "anchor_resolution": {"status": status, "candidate_count": count},
            },
            request(),
        )


@pytest.mark.parametrize(
    "families", [{"unknown": []}, {"call": {}}, {"call": None}, {"call": [None]}]
)
def test_rejects_invalid_families(families) -> None:
    with pytest.raises(ValueError):
        validate_raw_result(payload() | {"families": families}, request())


def test_rejects_unrequested_family_even_when_empty() -> None:
    only_call = request().model_copy(
        update={"allowed_relations": request().allowed_relations[:1]}
    )
    with pytest.raises(ValueError):
        validate_raw_result(payload(), only_call)


@pytest.mark.parametrize(
    "change",
    [
        {"kind": "unknown"},
        {"subject": " "},
        {"relation": 3},
        {"object": []},
        {"conditions": "guard"},
        {"conditions": [True]},
        {"conditions": [""]},
        {"path": {}},
        {"node": None},
        {"unexpected": "field"},
        {"node": node(id=True)},
        {"node": node(line="1")},
        {"node": node(line=0)},
        {"node": node(column=0)},
        {"node": node(argumentIndex=True)},
        {"node": node(nodeType="")},
        {"node": node(extra="field")},
        {"kind": "data_flow_path", "path": []},
        {"path": [node()]},
    ],
)
def test_rejects_invalid_record_shapes(change) -> None:
    with pytest.raises(ValueError):
        validate_raw_result(payload(call=[record(**change)]), request())


def test_schema_errors_do_not_echo_untrusted_values() -> None:
    secret = "C:\\Users\\secret\\checkout"
    with pytest.raises(ValueError) as error:
        validate_raw_result(
            payload(call=[record(subject={"secret": secret})]), request()
        )
    assert secret not in str(error.value)
    assert "secret" not in str(error.value)


def test_grounding_uses_real_single_source_line(repository) -> None:
    result = normalize_repository_evidence(
        payload(call=[record()]), request(), repository
    )
    assert result.status == "complete"
    item = result.evidence[0]
    assert item.source.code == "  actual_source_1();"
    assert item.source.file_path == "src/demo.c"
    assert item.source.start_line == 1
    assert item.source.start_column is None
    assert item.provenance.cpg_node_ids == (1,)
    assert result.budget_usage.model_dump() == {
        "nodes": 1,
        "flow_paths": 0,
        "source_lines": 1,
        "evidence_items": 1,
        "truncated": False,
    }


def test_stable_ids_dedup_graph_ids_and_input_order(repository) -> None:
    original = record()
    duplicate = record(node_id=99, node=node(99, code="different graph text"))
    raw = payload(call=[duplicate, original, deepcopy(original)])
    result = normalize_repository_evidence(raw, request(), repository)
    single = normalize_repository_evidence(
        payload(call=[original]), request(), repository
    )
    reversed_result = normalize_repository_evidence(
        payload(call=list(reversed(raw["families"]["call"]))), request(), repository
    )
    assert len(result.evidence) == 1
    assert result.evidence[0].evidence_id == single.evidence[0].evidence_id
    assert result == reversed_result
    assert result.evidence[0].provenance.cpg_node_ids == (1, 99)
    assert result.budget_usage.nodes == 2
    assert len(result.evidence[0].evidence_id) == len("repo_ev_") + 16


def test_ranks_before_selecting_and_sorts_shorter_flows(repository) -> None:
    raw = payload(
        call=[
            record("call_neighbor", 9, 1),
            record("callee_definition", 3, 3),
            record(),
        ],
        argument=[record("direct_entity", 2, 2)],
        data_flow=[
            record("data_flow_path", 4, 4, path=[node(4, 4), node(5, 5), node(6, 6)]),
            record("data_flow_path", 7, 7, path=[node(7, 7), node(8, 8)]),
        ],
        control_dependence=[record("dominance", 10, 10)],
    )
    result = normalize_repository_evidence(
        raw, request(max_evidence_items=6), repository
    )
    assert [item.kind for item in result.evidence] == [
        "anchor",
        "direct_entity",
        "callee_definition",
        "data_flow_path",
        "data_flow_path",
        "dominance",
    ]
    assert [len(item.path) for item in result.evidence[3:5]] == [2, 3]
    assert result.status == "partial"
    assert result.budget_usage.truncated


@pytest.mark.parametrize("budget", [{"max_nodes": 2}, {"max_source_lines": 2}])
def test_flow_is_omitted_whole_and_does_not_consume_budget(repository, budget) -> None:
    raw = payload(
        call=[record(), record("call_neighbor", 4, 4)],
        data_flow=[
            record("data_flow_path", 1, 1, path=[node(1, 1), node(2, 2), node(3, 3)])
        ],
    )
    result = normalize_repository_evidence(raw, request(**budget), repository)
    assert [item.kind for item in result.evidence] == ["anchor", "call_neighbor"]
    assert result.budget_usage.nodes == result.budget_usage.source_lines == 2
    assert result.budget_usage.flow_paths == 0
    assert result.status == "partial"
    assert any(limit.kind == "context_budget_exceeded" for limit in result.limitations)


def test_counters_use_unique_nodes_and_union_lines_across_items_and_paths(
    repository,
) -> None:
    raw = payload(
        call=[record()],
        argument=[record("argument", 2, 1)],
        data_flow=[
            record("data_flow_path", 1, 1, path=[node(1, 1), node(3, 2), node(1, 1)])
        ],
    )
    result = normalize_repository_evidence(
        raw, request(max_nodes=3, max_source_lines=2), repository
    )
    assert result.status == "complete"
    assert result.budget_usage.model_dump() == {
        "nodes": 3,
        "flow_paths": 1,
        "source_lines": 2,
        "evidence_items": 3,
        "truncated": False,
    }
    assert len(result.evidence[-1].path) == 3


def test_flow_path_budget(repository) -> None:
    raw = payload(
        data_flow=[
            record("data_flow_path", 1, 1, path=[node(1, 1), node(2, 2)]),
            record("data_flow_path", 3, 3, path=[node(3, 3), node(4, 4)]),
        ]
    )
    result = normalize_repository_evidence(raw, request(max_flow_paths=1), repository)
    assert len(result.evidence) == result.budget_usage.flow_paths == 1
    assert len(result.evidence[0].path) == 2
    assert result.budget_usage.truncated


@pytest.mark.parametrize(
    "file",
    [
        "../outside.c",
        "src/../src/demo.c",
        "src\\..\\demo.c",
        "C:\\secret.c",
        "C:secret.c",
        "\\\\server\\secret.c",
        "/etc/passwd",
        "src/demo.c:stream",
    ],
)
def test_rejects_unsafe_source_paths(repository, file) -> None:
    with pytest.raises(ValueError) as error:
        normalize_repository_evidence(
            payload(call=[record(node=node(file=file))]), request(), repository
        )
    assert file not in str(error.value)


def test_normalizes_windows_separators_in_relative_paths(repository) -> None:
    result = normalize_repository_evidence(
        payload(call=[record(node=node(file="src\\demo.c"))]), request(), repository
    )
    assert result.evidence[0].source.file_path == "src/demo.c"


def test_rejects_symlink_even_when_target_is_inside_repository(repository) -> None:
    link = repository / "linked.c"
    try:
        link.symlink_to(repository / "src/demo.c")
    except OSError:
        pytest.skip("symlink creation is unavailable")
    with pytest.raises(ValueError):
        normalize_repository_evidence(
            payload(call=[record(node=node(file="linked.c"))]), request(), repository
        )


@pytest.mark.parametrize(
    "change",
    [{"line": None}, {"file": None}, {"file": ""}, {"line": 99}, {"file": "missing.c"}],
)
def test_missing_source_omits_record_with_limitation(repository, change) -> None:
    result = normalize_repository_evidence(
        payload(call=[record(node=node(**change))]), request(), repository
    )
    assert not result.evidence
    assert result.status == "partial"
    assert result.limitations
    assert result.budget_usage.nodes == 0
    assert not result.budget_usage.truncated


def test_missing_flow_position_omits_entire_flow(repository) -> None:
    raw = payload(
        data_flow=[record("data_flow_path", path=[node(), node(2, line=None)])]
    )
    result = normalize_repository_evidence(raw, request(), repository)
    assert not result.evidence
    assert result.status == "partial"
    assert result.budget_usage.flow_paths == result.budget_usage.nodes == 0


def test_failed_or_missing_family_preserves_success_and_sanitizes_paths(
    repository,
) -> None:
    raw = payload(call=[record()])
    del raw["families"]["data_flow"]
    raw["limitations"] = [
        {
            "kind": "query_family_failed",
            "detail": 'data_flow: cannot read "C:\\Users\\Secret User\\repo.c" or /private/host/repo.c',
        }
    ]
    result = normalize_repository_evidence(raw, request(), repository)
    assert result.status == "partial"
    assert len(result.evidence) == 1
    assert "data_flow" in " ".join(limit.detail for limit in result.limitations)
    assert "Secret" not in result.model_dump_json()
    assert "/private/host" not in result.model_dump_json()
    assert not result.budget_usage.truncated


def test_missing_requested_family_is_partial(repository) -> None:
    raw = payload(call=[record()])
    del raw["families"]["type"]
    result = normalize_repository_evidence(raw, request(), repository)
    assert result.status == "partial"
    assert any("type" in limit.detail for limit in result.limitations)


def test_raw_truncation_reports_budget_limitation(repository) -> None:
    result = normalize_repository_evidence(
        payload(call=[record()]) | {"truncated": True}, request(), repository
    )
    assert result.status == "partial"
    assert result.budget_usage.truncated
    assert any(limit.kind == "context_budget_exceeded" for limit in result.limitations)


@pytest.mark.parametrize("status,count", [("not_found", 0), ("ambiguous", 2)])
def test_nonexact_returns_empty_without_reading_repository(
    status, count, tmp_path
) -> None:
    raw = payload() | {
        "anchor_resolution": {"status": status, "candidate_count": count},
        "families": {},
    }
    result = normalize_repository_evidence(raw, request(), tmp_path / "absent")
    assert result.status == status
    assert not result.evidence
    assert result.budget_usage.nodes == result.budget_usage.evidence_items == 0


def test_nonexact_rejects_even_empty_family_arrays() -> None:
    with pytest.raises(ValueError):
        validate_raw_result(
            payload()
            | {
                "anchor_resolution": {"status": "not_found", "candidate_count": 0},
            },
            request(),
        )
