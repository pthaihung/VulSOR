from pathlib import Path
from types import SimpleNamespace

import pytest

from vulsor.repository_context.cpg_cache import CpgCache, CpgIdentity
from vulsor.repository_context.index import RepositoryIndex
from vulsor.repository_context.models import EvidenceRequest, RepositoryIndexRecord
from vulsor.repository_context.prepared import PreparedCatalog
from vulsor.repository_context.service import (
    RepositoryContextQueryService,
    RepositoryPreprocessor,
)
from vulsor.repository_context.source_match import normalized_code_sha256


CODE = "int target(int x) {\n    return consume(x);\n}"


def request() -> EvidenceRequest:
    return EvidenceRequest.model_validate(
        {"request_id": "query-1", "phase": "evaluate", "obligation_ref": "ob-1",
         "repository_ref": {"repository_id": "repo", "repository_url": "https://example.test/repo.git", "revision": "a" * 40},
         "anchor": {"file_path": "demo.c", "function_name": "target", "operation_kind": "call", "operation_name": "consume", "line": 2},
         "questions": ["What value is passed?"], "allowed_relations": ["call"]}
    )


def index() -> RepositoryIndex:
    record = RepositoryIndexRecord.model_validate(
        {"sample_id": "s1", "repository": request().repository_ref.model_dump(mode="json"),
         "target": {"file_path": "demo.c", "function_name": "target", "normalized_code_sha256": normalized_code_sha256(CODE)}}
    )
    return RepositoryIndex({"s1": record})


def raw_result(current_request: EvidenceRequest) -> dict:
    return {"schema_version": 1, "request_id": current_request.request_id, "resolved_revision": "a" * 40,
            "anchor_resolution": {"status": "exact", "candidate_count": 1},
            "families": {"call": [{"kind": "anchor", "relation": "anchored_call", "subject": "target", "object": "consume", "conditions": [], "path": [],
                                    "node": {"id": 1, "nodeType": "CALL", "name": "consume", "code": "ignore raw source", "file": "demo.c", "line": 2, "column": None, "method": "target", "typeFullName": "int", "argumentIndex": None}}]},
            "limitations": [], "truncated": False}


def test_query_without_ready_record_returns_empty_without_git_or_build(tmp_path: Path) -> None:
    class ForbiddenJoern:
        def query(self, *_):
            pytest.fail("query must not run without a READY record")

    service = RepositoryContextQueryService(index(), PreparedCatalog.empty(), tmp_path / "cache", ForbiddenJoern())
    result = service.retrieve(request(), CODE, sample_id="s1")

    assert result.status == "not_found"
    assert result.evidence == ()
    assert result.limitations[0].kind == "repository_context_unavailable"


def test_query_with_ready_record_calls_only_joern_query(tmp_path: Path) -> None:
    from vulsor.repository_context.git_repository import revision_snapshot_path

    root = revision_snapshot_path(tmp_path / "cache", request().repository_ref.repository_url, "a" * 40)
    root.mkdir(parents=True)
    (root / "demo.c").write_text(CODE, encoding="utf-8")
    cache = CpgCache(cache_root=tmp_path / "cache")
    identity = CpgIdentity(repository_url=str(request().repository_ref.repository_url), revision="a" * 40, joern_version="test-version")
    artifact = cache.get_or_build(identity, lambda directory: (directory / "cpg.bin").write_bytes(b"cpg"))

    class Joern:
        calls: list[str] = []

        def query(self, cpg_path, current_request):
            assert cpg_path == artifact.cpg_path
            self.calls.append("query")
            return raw_result(current_request)

    preprocessor = RepositoryPreprocessor(index(), SimpleNamespace(resolve=lambda _: SimpleNamespace(repository_root=root, resolved_revision="a" * 40)), cache,
        SimpleNamespace(version=lambda: "test-version", build_cpg=lambda *_: None, smoke=lambda *_: None))
    record = preprocessor.preprocess_sample("s1", CODE)
    joern = Joern()
    service = RepositoryContextQueryService(index(), PreparedCatalog({"s1": record}), tmp_path / "cache", joern)

    result = service.retrieve(request(), CODE, sample_id="s1")

    assert result.status == "complete"
    assert joern.calls == ["query"]


def test_preprocessor_builds_smokes_and_returns_ready(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "demo.c").write_text(CODE, encoding="utf-8")
    calls: list[str] = []

    class Joern:
        def version(self):
            calls.append("version")
            return "test-version"

        def build_cpg(self, source, output):
            assert source == root
            calls.append("build")
            output.write_bytes(b"cpg")

        def smoke(self, path):
            assert path.name == "cpg.bin"
            calls.append("smoke")

    service = RepositoryPreprocessor(index(), SimpleNamespace(resolve=lambda _: SimpleNamespace(repository_root=root, resolved_revision="a" * 40)), CpgCache(cache_root=tmp_path / "cache"), Joern())
    record = service.preprocess_sample("s1", CODE)

    assert record.status == "ready"
    assert calls == ["version", "build", "smoke"]


def test_preprocessor_builds_prompt_context_from_ready_cpg(tmp_path: Path) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    (root / "demo.c").write_text(CODE, encoding="utf-8")

    class Joern:
        def version(self):
            return "test-version"

        def build_cpg(self, _, output):
            output.write_bytes(b"cpg")

        def smoke(self, _):
            return None

        def extract_function_context(self, path, *, file_path, function_name, max_items):
            assert path.name == "cpg.bin"
            assert (file_path, function_name, max_items) == ("demo.c", "target", 120)
            return {
                "anchor_status": "exact",
                "calls": [],
                "data_dependencies": [],
                "control_dependencies": [],
                "declarations_types": [],
                "limitations": ["calls: no mapped evidence was found"],
                "truncated": False,
            }

    service = RepositoryPreprocessor(
        index(),
        SimpleNamespace(resolve=lambda _: SimpleNamespace(repository_root=root, resolved_revision="a" * 40)),
        CpgCache(cache_root=tmp_path / "cache"),
        Joern(),
    )

    record = service.build_prompt_context("s1", CODE)

    assert record.sample_id == "s1"
    assert "[CALL RELATIONS]" in record.context
    assert record.limitations == ("calls: no mapped evidence was found",)
