import json
from pathlib import Path

import pytest

from vulsor.repository_context.index import RepositoryIndex, write_repository_index
from vulsor.repository_context.primevul_index import (
    FIELD_MAP,
    PrimeVulFieldMap,
    normalize_primevul_jsonl,
    normalize_primevul_record,
)


def raw_record(
    *, sample_id: str = "s1", code: str = "int target(void) { return 0; }"
) -> dict:
    return {
        "id": sample_id,
        "project_url": "https://github.com/acme/demo.git",
        "commit_id": "a" * 40,
        "file_path": "src/demo.c",
        "func_name": "target",
        "start": 4,
        "end": 8,
        "func": code,
        "target": 1,
        "cve": "CVE-X",
        "commit_message": "fix issue",
        "pair_id": "pair-1",
    }


def test_normalizer_whitelists_locator_fields() -> None:
    record = normalize_primevul_record(raw_record(), FIELD_MAP)

    assert set(record.model_dump()) == {"sample_id", "repository", "target"}
    assert "CVE-X" not in record.model_dump_json()
    assert "fix issue" not in record.model_dump_json()
    assert "pair-1" not in record.model_dump_json()


def test_normalizer_uses_explicit_field_map() -> None:
    field_map = PrimeVulFieldMap(
        sample_id="sample",
        repository_id="repo",
        repository_url="url",
        revision="sha",
        file_path="path",
        function_name="name",
        code="source",
        start_line="first",
        end_line="last",
    )
    raw = {
        "sample": "s1",
        "repo": "demo",
        "url": "https://github.com/acme/demo.git",
        "sha": "b" * 40,
        "path": "src/demo.c",
        "name": "target",
        "source": "int target(void) { return 0; }",
        "first": 4,
        "last": 8,
        "unmapped": "must not be copied",
    }

    record = normalize_primevul_record(raw, field_map)

    assert record.sample_id == "s1"
    assert record.repository.repository_id == "demo"
    assert record.repository.revision == "b" * 40
    assert record.target.file_path == "src/demo.c"
    assert record.target.function_name == "target"
    assert record.target.start_line == 4
    assert record.target.end_line == 8
    assert "unmapped" not in record.model_dump_json()


def test_repository_index_rejects_duplicate_sample_ids_with_both_lines(
    tmp_path: Path,
) -> None:
    index_path = tmp_path / "test.jsonl"
    record = normalize_primevul_record(raw_record(), FIELD_MAP)
    index_path.write_text(
        f"\n{record.model_dump_json()}\n\n{record.model_dump_json()}\n",
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"test\.jsonl:2 and .*test\.jsonl:4"):
        RepositoryIndex.load(index_path)


def test_repository_index_loads_nonblank_jsonl_and_reports_missing_sample(
    tmp_path: Path,
) -> None:
    index_path = tmp_path / "test.jsonl"
    first = normalize_primevul_record(raw_record(sample_id="s1"), FIELD_MAP)
    second = normalize_primevul_record(raw_record(sample_id="s2"), FIELD_MAP)
    index_path.write_text(
        f"{first.model_dump_json()}\n\n{second.model_dump_json()}\n",
        encoding="utf-8",
    )

    index = RepositoryIndex.load(index_path)

    assert len(index) == 2
    assert index.get("s1") == first
    with pytest.raises(KeyError, match="Repository metadata not found: missing"):
        index.get("missing")


def test_repository_index_reports_malformed_record_location(tmp_path: Path) -> None:
    index_path = tmp_path / "test.jsonl"
    index_path.write_text("\nnot-json\n", encoding="utf-8")

    with pytest.raises(ValueError, match=r"Invalid repository index record at .*test\.jsonl:2"):
        RepositoryIndex.load(index_path)


def test_write_repository_index_sorts_records_and_replaces_target(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "nested" / "index.jsonl"
    output_path.parent.mkdir()
    records = [
        normalize_primevul_record(raw_record(sample_id="s2"), FIELD_MAP),
        normalize_primevul_record(raw_record(sample_id="s1"), FIELD_MAP),
    ]

    write_repository_index(records, output_path)

    written = [
        json.loads(line)
        for line in output_path.read_text(encoding="utf-8").splitlines()
    ]
    assert [record["sample_id"] for record in written] == ["s1", "s2"]
    assert not output_path.with_suffix(".tmp").exists()


def test_normalize_primevul_jsonl_writes_rejects_without_raw_metadata(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "raw.jsonl"
    output_path = tmp_path / "index.jsonl"
    reject_path = tmp_path / "rejects.jsonl"
    input_path.write_text(
        json.dumps(raw_record()) + "\n" + json.dumps(raw_record(sample_id="bad"))
        + "\n",
        encoding="utf-8",
    )
    raw = json.loads(input_path.read_text(encoding="utf-8").splitlines()[1])
    raw.pop("commit_id")
    input_path.write_text(
        json.dumps(raw_record()) + "\n" + json.dumps(raw) + "\n",
        encoding="utf-8",
    )

    normalize_primevul_jsonl(input_path, output_path, reject_path, FIELD_MAP)

    assert len(output_path.read_text(encoding="utf-8").splitlines()) == 1
    rejects = [
        json.loads(line)
        for line in reject_path.read_text(encoding="utf-8").splitlines()
    ]
    assert rejects[0]["line"] == 2
    assert rejects[0]["sample_id"] == "bad"
    assert "commit_id" in rejects[0]["reason"]
    assert "CVE-X" not in reject_path.read_text(encoding="utf-8")
    assert "fix issue" not in reject_path.read_text(encoding="utf-8")
