import json

import pytest
from pydantic import ValidationError

from vulsor.repository_context.models import (
    PreparedRecord,
    UnresolvedPreparedRecord,
)
from vulsor.repository_context.prepared import (
    PreparedCatalog,
    prepared_catalog_paths,
    write_prepared_catalog,
    write_unresolved_catalog,
)


def repository_ref() -> dict[str, str]:
    return {
        "repository_id": "demo",
        "repository_url": "https://example.test/demo.git",
        "revision": "a" * 40,
    }


def target_anchor() -> dict[str, object]:
    return {
        "file_path": "src/demo.c",
        "function_name": "target",
        "start_line": 3,
        "end_line": 5,
        "normalized_code_sha256": "b" * 64,
    }


def ready_record(sample_id: str = "s1") -> PreparedRecord:
    return PreparedRecord.model_validate(
        {
            "sample_id": sample_id,
            "repository": repository_ref(),
            "target": target_anchor(),
            "source_match": {
                "status": "exact",
                "start_line": 3,
                "end_line": 5,
            },
            "cpg": {
                "cache_key": "c" * 64,
                "joern_version": "4.0.592",
                "frontend": "C",
                "frontend_args": [],
            },
            "status": "ready",
        }
    )


def test_ready_catalog_round_trip_only_persists_whitelisted_fields(tmp_path) -> None:
    record = ready_record()
    path = tmp_path / "test.jsonl"

    write_prepared_catalog([record], path)

    payload = json.loads(path.read_text(encoding="utf-8"))
    assert set(payload) == {
        "sample_id",
        "repository",
        "target",
        "source_match",
        "cpg",
        "status",
    }
    assert PreparedCatalog.load(path).get_or_none("s1") == record


def test_missing_ready_catalog_is_empty_and_unresolved_is_separate(tmp_path) -> None:
    unresolved_path = tmp_path / "test.unresolved.jsonl"
    write_unresolved_catalog(
        [UnresolvedPreparedRecord(sample_id="s1", kind="source_mismatch")],
        unresolved_path,
    )

    assert PreparedCatalog.load(tmp_path / "missing.jsonl").get_or_none("s1") is None
    assert json.loads(unresolved_path.read_text(encoding="utf-8")) == {
        "sample_id": "s1",
        "kind": "source_mismatch",
        "status": "unresolved",
    }


def test_catalog_writers_sort_records_and_reject_duplicate_sample_ids(tmp_path) -> None:
    path = tmp_path / "test.jsonl"

    write_prepared_catalog([ready_record("s2"), ready_record("s1")], path)

    assert [json.loads(line)["sample_id"] for line in path.read_text(encoding="utf-8").splitlines()] == [
        "s1",
        "s2",
    ]
    with pytest.raises(ValueError, match="duplicate sample_id: s1"):
        write_prepared_catalog([ready_record("s1"), ready_record("s1")], path)


def test_catalog_paths_are_safe_and_under_prepared_directory(tmp_path) -> None:
    ready_path, unresolved_path = prepared_catalog_paths(tmp_path, "primevul", "test")

    assert ready_path == tmp_path / "prepared" / "primevul" / "test.jsonl"
    assert unresolved_path == tmp_path / "prepared" / "primevul" / "test.unresolved.jsonl"
    with pytest.raises(ValueError, match="safe path component"):
        prepared_catalog_paths(tmp_path, "../outside", "test")


@pytest.mark.parametrize("kind", ("exception: details", "unknown", ""))
def test_unresolved_records_allow_only_controlled_kinds(kind: str) -> None:
    with pytest.raises(ValidationError):
        UnresolvedPreparedRecord(sample_id="s1", kind=kind)
