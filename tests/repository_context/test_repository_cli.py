import json
from dataclasses import fields

from vulsor.cli import build_parser, main
from vulsor.datasets import DatasetSample
from vulsor.repository_context.models import RepositoryIndexRecord
from vulsor.repository_context.index import write_repository_index
from vulsor.repository_context.source_match import normalized_code_sha256


def test_repository_commands_are_separate_from_inspect_and_agent():
    parser = build_parser()
    for action in ("prepare", "status", "query"):
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
    assert json.loads(capsys.readouterr().out)["cpg_cache_keys"] == []


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
