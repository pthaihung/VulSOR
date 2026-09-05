import json
from pathlib import Path

from vulsor.repository_context.primevul_import import (
    ImportSummary,
    import_primevul_test,
)


def _write_json(path: Path, value: object) -> None:
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value) + "\n")


def test_import_selects_target_one_and_writes_only_safe_fields(tmp_path: Path) -> None:
    raw = tmp_path / "pairs.jsonl"
    _write_json(
        raw,
        {
            "idx": 10,
            "target": 1,
            "project": "demo",
            "project_url": "https://example.test/demo.git",
            "commit_id": "a" * 40,
            "func_hash": 123,
            "func": "int target(void) {}",
            "cve": "must-not-leak",
        },
    )
    _write_json(
        raw,
        {
            "idx": 11,
            "target": 0,
            "project": "demo",
            "project_url": "https://example.test/demo.git",
            "commit_id": "a" * 40,
            "func_hash": 456,
            "func": "int paired(void) {}",
        },
    )
    info = tmp_path / "file_info.json"
    info.write_text(
        json.dumps(
            {
                "123": {
                    "project_file_path": "src/demo.c",
                    "start_line": 4,
                    "end_line": 4,
                }
            }
        ),
        encoding="utf-8",
    )
    output = tmp_path / "out"

    result = import_primevul_test(raw, info, output, lambda code, suffix: "target")

    assert result == ImportSummary(accepted=1, rejected=0)
    assert json.loads((output / "test.jsonl").read_text(encoding="utf-8")) == {
        "sample_id": "test_10",
        "code": "int target(void) {}",
    }
    index = json.loads((output / "index.jsonl").read_text(encoding="utf-8"))
    assert index["sample_id"] == "test_10"
    assert index["target"]["file_path"] == "src/demo.c"
    assert "cve" not in (output / "index.jsonl").read_text(encoding="utf-8")


def test_import_rejects_missing_file_info_without_guessing_path(tmp_path: Path) -> None:
    raw = tmp_path / "pairs.jsonl"
    _write_json(
        raw,
        {
            "idx": 11,
            "target": 1,
            "project": "demo",
            "project_url": "https://example.test/demo.git",
            "commit_id": "a" * 40,
            "func_hash": 456,
            "func": "int target(void) {}",
        },
    )
    info = tmp_path / "file_info.json"
    info.write_text("{}", encoding="utf-8")
    output = tmp_path / "out"

    result = import_primevul_test(raw, info, output, lambda code, suffix: "target")

    assert result == ImportSummary(accepted=0, rejected=1)
    assert json.loads((output / "import-rejects.jsonl").read_text(encoding="utf-8")) == {
        "sample_id": "test_11",
        "reason": "locator_missing",
    }


def test_import_uses_parent_revision_and_defers_source_span_validation(
    tmp_path: Path,
) -> None:
    raw = tmp_path / "pairs.jsonl"
    _write_json(
        raw,
        {
            "idx": 12,
            "target": 1,
            "project": "demo",
            "project_url": "https://example.test/demo.git",
            "commit_id": "a" * 40,
            "func_hash": 789,
            "func": "int vulnerable(void) {}",
        },
    )
    info = tmp_path / "file_info.json"
    info.write_text(
        json.dumps(
            {
                "789": {
                    "project_file_path": "src/demo.c",
                    "start_line": 40,
                    "end_line": 50,
                }
            }
        ),
        encoding="utf-8",
    )

    def resolve_parent(record) -> str:
        assert record.revision == "a" * 40
        return "b" * 40

    output = tmp_path / "out"
    result = import_primevul_test(
        raw,
        info,
        output,
        lambda code, suffix: "vulnerable",
        resolve_parent_revision=resolve_parent,
    )

    assert result == ImportSummary(accepted=1, rejected=0)
    index = json.loads((output / "index.jsonl").read_text(encoding="utf-8"))
    assert index["repository"]["revision"] == "b" * 40
    assert index["target"]["start_line"] is None
    assert index["target"]["end_line"] is None
