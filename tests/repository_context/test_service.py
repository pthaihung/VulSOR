from types import SimpleNamespace

import pytest

from vulsor.repository_context.cpg_cache import CpgCache
from vulsor.repository_context.git_repository import (
    ResolvedRepository,
    RepositoryResolutionError,
)
from vulsor.repository_context.index import RepositoryIndex
from vulsor.repository_context.joern import JoernError
from vulsor.repository_context.models import EvidenceRequest, RepositoryIndexRecord
from vulsor.repository_context.service import RepositoryContextService
from vulsor.repository_context.source_match import normalized_code_sha256


CODE = "int target(int x) {\n    return consume(x);\n}"


def test_service_types_are_available_from_public_package_api():
    from vulsor.repository_context import PreparedRepository, RepositoryContextService

    assert PreparedRepository.__module__.endswith(".service")
    assert RepositoryContextService.__module__.endswith(".service")


def make_request():
    return EvidenceRequest.model_validate(
        {
            "request_id": "query-1",
            "phase": "evaluate",
            "obligation_ref": "ob-1",
            "repository_ref": {
                "repository_id": "repo",
                "repository_url": "https://example.test/repo.git",
                "revision": "a" * 40,
            },
            "anchor": {
                "file_path": "demo.c",
                "function_name": "target",
                "operation_kind": "call",
                "operation_name": "consume",
                "line": 2,
            },
            "questions": ["What value is passed?"],
            "allowed_relations": ["call"],
        }
    )


@pytest.fixture
def setup(tmp_path):
    root = tmp_path / "repository"
    root.mkdir()
    (root / "demo.c").write_text(CODE, encoding="utf-8")
    record = RepositoryIndexRecord.model_validate(
        {
            "sample_id": "sample-1",
            "repository": make_request().repository_ref.model_dump(mode="json"),
            "target": {
                "file_path": "demo.c",
                "function_name": "target",
                "normalized_code_sha256": normalized_code_sha256(CODE),
            },
        }
    )
    counts = SimpleNamespace(build=0, query=0, smoke=0)

    class Joern:
        def version(self):
            return "test-version"

        def build_cpg(self, source, output):
            assert source == root
            counts.build += 1
            output.write_bytes(b"fake graph")

        def smoke(self, path):
            counts.smoke += 1

        def query(self, path, request):
            counts.query += 1
            return {
                "schema_version": 1,
                "request_id": request.request_id,
                "resolved_revision": "a" * 40,
                "anchor_resolution": {"status": "exact", "candidate_count": 1},
                "families": {
                    "call": [
                        {
                            "kind": "anchor",
                            "relation": "anchored_call",
                            "subject": "target",
                            "object": "consume",
                            "conditions": [],
                            "path": [],
                            "node": {
                                "id": 1,
                                "nodeType": "CALL",
                                "name": "consume",
                                "code": "ignore raw source",
                                "file": "demo.c",
                                "line": 2,
                                "column": None,
                                "method": "target",
                                "typeFullName": "int",
                                "argumentIndex": None,
                            },
                        }
                    ]
                },
                "limitations": [],
                "truncated": False,
            }

    repositories = SimpleNamespace(
        resolve=lambda ref: ResolvedRepository(root, ref.revision, root)
    )
    service = RepositoryContextService(
        RepositoryIndex({"sample-1": record}),
        repositories,
        CpgCache(cache_root=tmp_path / "cache"),
        Joern(),
    )
    return service, counts, root


def test_same_revision_reuses_one_smoke_validated_cpg(setup):
    service, counts, _ = setup
    first = service.retrieve(make_request(), CODE, sample_id="sample-1")
    second = service.retrieve(make_request(), CODE, sample_id="sample-1")
    assert first == second
    assert first.status == "complete"
    assert first.evidence[0].source.code == "    return consume(x);"
    assert counts.build == 1 and counts.query == 2 and counts.smoke == 2


@pytest.mark.parametrize("failure", ["missing", "hash", "source", "repo", "anchor"])
def test_failed_identity_or_source_never_queries(setup, failure):
    service, counts, root = setup
    request, code, sample_id = make_request(), CODE, "sample-1"
    if failure == "missing":
        sample_id = "absent"
    if failure == "hash":
        code += "changed"
    if failure == "source":
        (root / "demo.c").write_text("other", encoding="utf-8")
    if failure == "repo":
        request = request.model_copy(
            update={
                "repository_ref": request.repository_ref.model_copy(
                    update={"revision": "b" * 40}
                )
            }
        )
    if failure == "anchor":
        request = request.model_copy(
            update={"anchor": request.anchor.model_copy(update={"file_path": "else.c"})}
        )
    result = service.retrieve(request, code, sample_id=sample_id)
    assert not result.evidence and result.limitations
    assert counts.build == counts.query == 0


def test_smoke_failure_never_publishes_ready_cache(setup):
    service, counts, _ = setup

    def fail(path):
        raise JoernError("secret host path")

    service.joern.smoke = fail
    result = service.retrieve(make_request(), CODE, sample_id="sample-1")
    assert result.status == "unavailable" and "secret" not in result.model_dump_json()
    assert not list(service.cache.cache_dir.glob("*/manifest.json"))
    assert counts.query == 0


def test_git_failure_is_sanitized(setup):
    service, counts, _ = setup

    def fail(ref):
        raise RepositoryResolutionError("https://token@example.test")

    service.repositories.resolve = fail
    result = service.retrieve(make_request(), CODE, sample_id="sample-1")
    assert result.status == "unavailable" and "token" not in result.model_dump_json()
    assert counts.query == counts.build == 0


@pytest.mark.parametrize("failure", ["schema", "unsafe_path"])
def test_invalid_external_evidence_returns_sanitized_unavailable(setup, failure):
    service, _, _ = setup
    original = service.joern.query

    def malformed(path, request):
        raw = original(path, request)
        if failure == "schema":
            raw["schema_version"] = 999
        else:
            raw["families"]["call"][0]["node"]["file"] = "../secret.c"
        return raw

    service.joern.query = malformed
    result = service.retrieve(make_request(), CODE, sample_id="sample-1")
    assert result.status == "unavailable" and not result.evidence
    assert result.limitations[0].kind == "invalid_repository_evidence"
    assert "secret" not in result.model_dump_json()


def test_nonexact_and_failed_family_results(setup):
    service, counts, _ = setup
    original = service.joern.query

    def ambiguous(path, request):
        raw = original(path, request)
        raw.update(
            anchor_resolution={"status": "ambiguous", "candidate_count": 2}, families={}
        )
        return raw

    service.joern.query = ambiguous
    result = service.retrieve(make_request(), CODE, sample_id="sample-1")
    assert result.status == "ambiguous" and not result.evidence

    def partial(path, request):
        raw = original(path, request)
        raw["limitations"] = [{"kind": "query_family_failed", "detail": "call: failed"}]
        return raw

    service.joern.query = partial
    result = service.retrieve(make_request(), CODE, sample_id="sample-1")
    assert result.status == "partial" and result.evidence
