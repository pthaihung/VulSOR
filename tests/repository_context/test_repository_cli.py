import json
from dataclasses import fields

import pytest
from vulsor.cli import build_parser, main
from vulsor.datasets import DatasetSample
from vulsor.repository_context.models import RepositoryIndexRecord
from vulsor.repository_context.primevul_import import ImportSummary
from vulsor.repository_context.index import write_repository_index
from vulsor.repository_context.source_match import normalized_code_sha256


def test_repository_commands_are_separate_from_inspect_and_agent():
    parser = build_parser()
    for action in ("preprocess", "status", "query"):
        args = [
            "repo-context",
            action,
            "--dataset",
            "primevul",
            "--split",
            "test",
            "--sample",
            "sample",
        ]
        if action == "preprocess":
            args = [
                "repo-context",
                action,
                "--dataset",
                "primevul",
                "--split",
                "test",
                "--all",
            ]
        if action == "query":
            args += ["--request", "request.json", "--output", "result.json"]
        parsed = parser.parse_args(args)
        assert parsed.repo_action == action
    for command in ("inspect", "agent"):
        args = (
            [command, "--file", "example.c"]
            if command == "inspect"
            else [command, "--dataset", "primevul", "--split", "test", "--agent", "all"]
        )
        assert not hasattr(parser.parse_args(args), "repo_action")


def test_dataset_sample_boundary_contains_only_id_and_code():
    assert {field.name for field in fields(DatasetSample)} == {"sample_id", "code"}


def test_doctor_adds_optional_tools_only_on_request(monkeypatch, capsys):
    monkeypatch.setattr(
        "vulsor.cli.shutil.which", lambda exe: exe if exe.startswith("clang") else None
    )
    assert main(["doctor"]) == 0
    assert "joern" not in capsys.readouterr().out
    assert main(["doctor", "--repository-context"]) == 1
    assert "joern-parse" in capsys.readouterr().out


def test_status_has_no_tool_calls_or_cache_side_effects(tmp_path, monkeypatch, capsys):
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    record = RepositoryIndexRecord.model_validate(
        {
            "sample_id": "s1",
            "repository": {
                "repository_id": "demo",
                "repository_url": "https://example.test/repo.git",
                "revision": "a" * 40,
            },
            "target": {
                "file_path": "demo.c",
                "function_name": "target",
                "normalized_code_sha256": normalized_code_sha256("int target() {}"),
            },
        }
    )
    write_repository_index([record], index_dir / "test.jsonl")
    cache_dir = tmp_path / "never-created"
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "repository_context": {"cache_root": str(cache_dir)},
                "datasets": {
                    "primevul": {
                        "root": str(tmp_path),
                        "repository_index_dir": str(index_dir),
                    }
                },
            }
        )
    )

    def forbidden(*args, **kwargs):
        raise AssertionError("status invoked tool")

    monkeypatch.setattr("subprocess.run", forbidden)
    assert (
        main(
            [
                "repo-context",
                "status",
                "--config",
                str(config),
                "--dataset",
                "primevul",
                "--split",
                "test",
                "--sample",
                "s1",
            ]
        )
        == 0
    )
    assert not cache_dir.exists()
    assert json.loads(capsys.readouterr().out)["cpg_ready"] is False


def test_index_command_uses_field_map_and_counts_rejects(tmp_path, capsys):
    mapping = {
        name: name
        for name in (
            "sample_id",
            "repository_id",
            "repository_url",
            "revision",
            "file_path",
            "function_name",
            "code",
        )
    }
    field_map = tmp_path / "map.json"
    field_map.write_text(json.dumps(mapping))
    raw = tmp_path / "raw.jsonl"
    raw.write_text(
        json.dumps(
            {
                "sample_id": "s1",
                "repository_id": "r1",
                "repository_url": "https://example.test/repo.git",
                "revision": "a" * 40,
                "file_path": "demo.c",
                "function_name": "target",
                "code": "int target() {}",
                "target": 1,
                "cve": "must not leak",
            }
        )
        + "\n{}\n"
    )
    output, rejects = tmp_path / "index.jsonl", tmp_path / "rejects.jsonl"
    assert (
        main(
            [
                "repo-context",
                "index",
                "--source",
                str(raw),
                "--field-map",
                str(field_map),
                "--output",
                str(output),
                "--rejects",
                str(rejects),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out) == {"accepted": 1, "rejected": 1}
    assert "must not leak" not in output.read_text() + rejects.read_text()


def test_preprocess_requires_exactly_one_of_sample_or_all() -> None:
    parser = build_parser()
    with pytest.raises(SystemExit):
        parser.parse_args(
            ["repo-context", "preprocess", "--dataset", "primevul", "--split", "test"]
        )


def test_query_missing_ready_context_does_not_construct_git_or_cache(
    monkeypatch, tmp_path, capsys
) -> None:
    dataset_root = tmp_path / "dataset"
    (dataset_root / "inputs").mkdir(parents=True)
    (dataset_root / "inputs" / "test.jsonl").write_text(
        json.dumps({"sample_id": "s1", "code": "int target() {}"}) + "\n",
        encoding="utf-8",
    )
    index_dir = tmp_path / "index"
    index_dir.mkdir()
    write_repository_index(
        [
            RepositoryIndexRecord.model_validate(
                {
                    "sample_id": "s1",
                    "repository": {"repository_id": "r", "repository_url": "https://example.test/r.git", "revision": "a" * 40},
                    "target": {"file_path": "demo.c", "function_name": "target", "normalized_code_sha256": normalized_code_sha256("int target() {}")},
                }
            )
        ],
        index_dir / "test.jsonl",
    )
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"repository_context": {"cache_root": str(tmp_path / "cache")}, "datasets": {"primevul": {"root": str(dataset_root), "repository_index_dir": str(index_dir)}}}), encoding="utf-8")
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps({"request_id": "q1", "phase": "evaluate", "obligation_ref": "o1", "repository_ref": {"repository_id": "r", "repository_url": "https://example.test/r.git", "revision": "a" * 40}, "anchor": {"file_path": "demo.c", "function_name": "target", "operation_kind": "call", "operation_name": "target", "line": 1}, "questions": ["q"], "allowed_relations": ["call"]}), encoding="utf-8")
    output_path = tmp_path / "evidence.json"

    def forbidden(*args, **kwargs):
        raise AssertionError("query constructed a mutable dependency")

    monkeypatch.setattr("vulsor.repository_context.cli.GitRepositoryResolver", forbidden, raising=False)
    monkeypatch.setattr("vulsor.repository_context.cli.CpgCache", forbidden, raising=False)
    assert main(["repo-context", "query", "--config", str(config_path), "--dataset", "primevul", "--split", "test", "--sample", "s1", "--request", str(request_path), "--output", str(output_path)]) == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))["evidence"] == []
    assert json.loads(capsys.readouterr().out)["status"] == "not_found"


def test_status_uses_configured_repository_index_file(tmp_path, capsys) -> None:
    index_path = tmp_path / "index.jsonl"
    write_repository_index(
        [
            RepositoryIndexRecord.model_validate(
                {
                    "sample_id": "s1",
                    "repository": {
                        "repository_id": "demo",
                        "repository_url": "https://example.test/demo.git",
                        "revision": "a" * 40,
                    },
                    "target": {
                        "file_path": "demo.c",
                        "function_name": "target",
                        "normalized_code_sha256": normalized_code_sha256(
                            "int target(void) {}"
                        ),
                    },
                }
            )
        ],
        index_path,
    )
    config_path = tmp_path / "config.json"
    config_path.write_text(
        json.dumps(
            {
                "repository_context": {"cache_root": str(tmp_path / "cache")},
                "datasets": {
                    "primevul": {
                        "root": str(tmp_path),
                        "repository_index_files": {"test": str(index_path)},
                    }
                },
            }
        ),
        encoding="utf-8",
    )

    assert (
        main(
            [
                "repo-context",
                "status",
                "--config",
                str(config_path),
                "--dataset",
                "primevul",
                "--split",
                "test",
                "--sample",
                "s1",
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["sample_id"] == "s1"


def test_import_primevul_command_writes_compact_output(tmp_path, monkeypatch, capsys) -> None:
    captured = {}

    def fake_import(raw, info, output, extract, *, resolve_parent_revision):
        captured.update(raw=raw, info=info, output=output)
        assert extract("int target(void) {}", ".c") == "target"
        assert callable(resolve_parent_revision)
        return ImportSummary(accepted=1, rejected=0)

    monkeypatch.setattr("vulsor.repository_context.cli.import_primevul_test", fake_import)
    monkeypatch.setattr(
        "vulsor.repository_context.cli.extract_function_name",
        lambda code, suffix, **kwargs: "target",
    )
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"tools": {"clang": "clang-test"}}), encoding="utf-8")
    raw, info, output = tmp_path / "raw.jsonl", tmp_path / "info.json", tmp_path / "out"

    assert main([
        "repo-context", "import-primevul", "--config", str(config),
        "--source", str(raw), "--file-info", str(info), "--output-root", str(output),
    ]) == 0
    assert captured == {"raw": raw, "info": info, "output": output}
    assert json.loads(capsys.readouterr().out) == {"accepted": 1, "rejected": 0}
