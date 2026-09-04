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
    *,
    sample_id: str = "s1",
    code: str = "int target(void) { return 0; }",
    file_path: str = "src/demo.c",
) -> dict:
    return {
        "id": sample_id,
        "project_url": "https://github.com/acme/demo.git",
        "commit_id": "a" * 40,
        "file_path": file_path,
        "func_name": "target",
        "start": 4,
        "end": 8,
        "func": code,
        "target": 1,
        "cve": "CVE-X",
        "commit_message": "fix issue",
        "pair_id": "pair-1",
    }


def field_map_kwargs(**overrides: str | None) -> dict[str, str | None]:
    values: dict[str, str | None] = {
        "sample_id": "id",
        "repository_id": "project",
        "repository_url": "project_url",
        "revision": "commit_id",
        "file_path": "file_path",
        "function_name": "func_name",
        "code": "func",
        "start_line": "start",
        "end_line": "end",
    }
    values.update(overrides)
    return values


def test_field_map_rejects_protected_cve_mapping_before_normalization() -> None:
    with pytest.raises(ValueError, match=r"protected.*cve"):
        PrimeVulFieldMap(**field_map_kwargs(code="cve"))


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


@pytest.mark.parametrize(
    "file_path",
    (
        "/src/demo.c",
        "C:/src/demo.c",
        "../demo.c",
        "src/../demo.c",
        "src/demo\x00.c",
    ),
)
def test_repository_index_rejects_unsafe_target_file_paths(
    tmp_path: Path,
    file_path: str,
) -> None:
    index_path = tmp_path / "index.jsonl"
    payload = json.loads(
        normalize_primevul_record(raw_record(), FIELD_MAP).model_dump_json()
    )
    payload["target"]["file_path"] = file_path
    index_path.write_text(json.dumps(payload) + "\n", encoding="utf-8")

    with pytest.raises(ValueError, match=r"Invalid repository index record at .*:1"):
        RepositoryIndex.load(index_path)


def test_write_repository_index_rejects_duplicates_before_writing(
    tmp_path: Path,
) -> None:
    output_path = tmp_path / "index.jsonl"
    output_path.write_text("existing\n", encoding="utf-8")
    record = normalize_primevul_record(raw_record(), FIELD_MAP)

    with pytest.raises(ValueError, match=r"Duplicate sample_id 's1'.*1.*2"):
        write_repository_index([record, record], output_path)

    assert output_path.read_text(encoding="utf-8") == "existing\n"


@pytest.mark.parametrize("collision", ("input_output", "input_reject", "output_reject"))
def test_normalizer_rejects_resolved_path_collisions_without_overwriting(
    tmp_path: Path,
    collision: str,
) -> None:
    input_path = tmp_path / "input.jsonl"
    output_path = tmp_path / "output.jsonl"
    reject_path = tmp_path / "rejects.jsonl"
    input_path.write_text(json.dumps(raw_record()) + "\n", encoding="utf-8")
    output_path.write_text("output sentinel\n", encoding="utf-8")
    reject_path.write_text("reject sentinel\n", encoding="utf-8")

    if collision == "input_output":
        output_path = tmp_path / "." / input_path.name
    elif collision == "input_reject":
        reject_path = tmp_path / "." / input_path.name
    else:
        reject_path = tmp_path / "." / output_path.name

    with pytest.raises(ValueError, match="distinct"):
        normalize_primevul_jsonl(input_path, output_path, reject_path, FIELD_MAP)

    assert input_path.read_text(encoding="utf-8") == json.dumps(raw_record()) + "\n"
    assert (tmp_path / "output.jsonl").read_text(encoding="utf-8") == (
        "output sentinel\n"
    )
    assert (tmp_path / "rejects.jsonl").read_text(encoding="utf-8") == (
        "reject sentinel\n"
    )


@pytest.mark.parametrize("code", ("", " \t\r\n"))
def test_normalizer_rejects_blank_source_code_before_hashing(code: str) -> None:
    with pytest.raises(ValueError, match="source code.*blank"):
        normalize_primevul_record(raw_record(code=code), FIELD_MAP)


@pytest.mark.parametrize(
    "file_path",
    (
        "/src/demo.c",
        "C:/src/demo.c",
        "../demo.c",
        "src/../demo.c",
        r"src\demo.c",
    ),
)
def test_normalizer_rejects_non_repository_relative_file_paths(
    file_path: str,
) -> None:
    with pytest.raises(ValueError, match="repository-relative POSIX"):
        normalize_primevul_record(raw_record(file_path=file_path), FIELD_MAP)


def test_normalizer_rejects_nul_target_file_path() -> None:
    with pytest.raises(ValueError, match="NUL"):
        normalize_primevul_record(raw_record(file_path="src/demo\x00.c"), FIELD_MAP)


@pytest.mark.parametrize("path_name", ("input", "output", "reject"))
def test_normalizer_rejects_nul_in_filesystem_paths_before_resolution(
    tmp_path: Path,
    path_name: str,
) -> None:
    input_path = tmp_path / "raw.jsonl"
    output_path = tmp_path / "index.jsonl"
    reject_path = tmp_path / "rejects.jsonl"
    input_path.write_text(json.dumps(raw_record()) + "\n", encoding="utf-8")
    paths = {
        "input": Path(str(input_path) + "\x00"),
        "output": Path(str(output_path) + "\x00"),
        "reject": Path(str(reject_path) + "\x00"),
    }
    selected_path = paths[path_name]
    if path_name == "input":
        input_path = selected_path
    elif path_name == "output":
        output_path = selected_path
    else:
        reject_path = selected_path

    with pytest.raises(ValueError, match="NUL"):
        normalize_primevul_jsonl(input_path, output_path, reject_path, FIELD_MAP)


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
    assert not list(output_path.parent.glob(f".{output_path.name}.*.tmp"))


def test_atomic_writes_leave_unrelated_temp_files_untouched(tmp_path: Path) -> None:
    input_path = tmp_path / "raw.jsonl"
    output_path = tmp_path / "index.jsonl"
    reject_path = tmp_path / "rejects.jsonl"
    output_temp = output_path.with_suffix(".tmp")
    reject_temp = reject_path.with_suffix(".tmp")
    input_path.write_text(json.dumps(raw_record()) + "\n", encoding="utf-8")
    output_temp.write_text("unrelated output temp\n", encoding="utf-8")
    reject_temp.write_text("unrelated reject temp\n", encoding="utf-8")

    normalize_primevul_jsonl(input_path, output_path, reject_path, FIELD_MAP)

    assert output_temp.read_text(encoding="utf-8") == "unrelated output temp\n"
    assert reject_temp.read_text(encoding="utf-8") == "unrelated reject temp\n"
    assert output_path.exists()
    assert reject_path.exists()
    assert not list(tmp_path.glob(f".{output_path.name}.*.tmp"))
    assert not list(tmp_path.glob(f".{reject_path.name}.*.tmp"))


def test_atomic_replace_failure_preserves_outputs_and_cleans_temps(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    input_path = tmp_path / "raw.jsonl"
    output_path = tmp_path / "index.jsonl"
    reject_path = tmp_path / "rejects.jsonl"
    input_path.write_text(json.dumps(raw_record()) + "\n", encoding="utf-8")
    output_path.write_text("previous accepted\n", encoding="utf-8")
    reject_path.write_text("previous rejected\n", encoding="utf-8")

    def fail_replace(source: Path, target: Path) -> Path:
        raise OSError("simulated replace failure")

    monkeypatch.setattr(Path, "replace", fail_replace)

    with pytest.raises(OSError, match="simulated replace failure"):
        normalize_primevul_jsonl(input_path, output_path, reject_path, FIELD_MAP)

    assert output_path.read_text(encoding="utf-8") == "previous accepted\n"
    assert reject_path.read_text(encoding="utf-8") == "previous rejected\n"
    assert not list(tmp_path.glob(f".{output_path.name}.*.tmp"))
    assert not list(tmp_path.glob(f".{reject_path.name}.*.tmp"))


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


def test_normalize_primevul_jsonl_escapes_surrogate_reject_sample_id(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "raw.jsonl"
    output_path = tmp_path / "index.jsonl"
    reject_path = tmp_path / "rejects.jsonl"
    invalid = raw_record(sample_id="\ud800")
    invalid.pop("commit_id")
    input_path.write_text(
        json.dumps(raw_record()) + "\n" + json.dumps(invalid) + "\n",
        encoding="utf-8",
    )

    normalize_primevul_jsonl(input_path, output_path, reject_path, FIELD_MAP)

    assert len(output_path.read_text(encoding="utf-8").splitlines()) == 1
    reject_bytes = reject_path.read_bytes()
    assert b"\\ud800" in reject_bytes
    reject = json.loads(reject_bytes.decode("utf-8").splitlines()[0])
    assert reject["sample_id"] == "\ud800"


def test_normalize_primevul_jsonl_reports_duplicate_line_and_sample_id(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "raw.jsonl"
    output_path = tmp_path / "index.jsonl"
    reject_path = tmp_path / "rejects.jsonl"
    input_path.write_text(
        json.dumps(raw_record()) + "\n" + json.dumps(raw_record()) + "\n",
        encoding="utf-8",
    )

    normalize_primevul_jsonl(input_path, output_path, reject_path, FIELD_MAP)

    reject = json.loads(reject_path.read_text(encoding="utf-8").splitlines()[0])
    assert reject["line"] == 2
    assert reject["sample_id"] == "s1"
    assert "duplicate" in reject["reason"]
    assert "1" in reject["reason"]


def test_normalize_primevul_jsonl_rejects_invalid_utf8_per_line(
    tmp_path: Path,
) -> None:
    input_path = tmp_path / "raw.jsonl"
    output_path = tmp_path / "index.jsonl"
    reject_path = tmp_path / "rejects.jsonl"
    input_path.write_bytes(
        json.dumps(raw_record()).encode("utf-8") + b"\n" + b"{\xff}\n"
    )

    normalize_primevul_jsonl(input_path, output_path, reject_path, FIELD_MAP)

    assert len(output_path.read_text(encoding="utf-8").splitlines()) == 1
    reject = json.loads(reject_path.read_text(encoding="utf-8").splitlines()[0])
    assert reject == {"line": 2, "reason": "invalid_utf8", "sample_id": None}
