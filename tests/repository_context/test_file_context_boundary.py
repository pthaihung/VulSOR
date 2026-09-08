import argparse
import json
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_ROOT = PROJECT_ROOT / "src"

from tests.context_tool_module import context_tool as cli

build_parser = cli.build_parser


def test_context_cli_exposes_only_file_context_build() -> None:
    parser = build_parser()
    command_action = next(action for action in parser._actions if action.dest == "command")
    assert set(command_action.choices) == {"build"}


def test_context_cli_has_no_repository_query_symbols() -> None:
    source = Path("context_tool/context_tool.py").read_text(encoding="utf-8")
    for legacy_name in (
        "RepositoryPreprocessor",
        "RepositoryContextQueryService",
        "repo-context",
        "import-primevul",
        "build-context",
        "show-context",
    ):
        assert legacy_name not in source


def test_file_context_budget_has_no_legacy_prompt_context_dependency() -> None:
    file_prompt_context_source = Path("context_tool/context_tool.py").read_text(encoding="utf-8")
    from tests.context_tool_module import (
        MAX_FILE_CONTEXT_TOKENS,
        estimate_context_tokens,
        validate_complete_context,
    )

    assert "prompt_context" not in file_prompt_context_source
    assert MAX_FILE_CONTEXT_TOKENS == 2000
    assert estimate_context_tokens("abcd") == 2
    assert validate_complete_context({"data_flow": [{"code": "x = y"}]})


def test_joern_adapter_exposes_only_file_context_operations() -> None:
    from tests.context_tool_module import JoernAdapter

    assert hasattr(JoernAdapter, "build_cpg")
    assert hasattr(JoernAdapter, "extract_file_context")
    assert not hasattr(JoernAdapter, "query")
    assert not hasattr(JoernAdapter, "extract_function_context")
    assert not hasattr(JoernAdapter, "smoke")


def test_legacy_repository_context_surface_is_absent() -> None:
    roots = (
        PROJECT_ROOT / "src",
        PROJECT_ROOT / "context_tool",
        PROJECT_ROOT / "README.md",
        PROJECT_ROOT / "AGENT.md",
    )
    forbidden = (
        "RepositoryPreprocessor",
        "RepositoryContextQueryService",
        "GitRepositoryResolver",
        "PreparedCatalog",
        "repo-context",
        "repository_evidence.sc",
        "import-primevul",
    )
    for root in roots:
        files = [root] if root.is_file() else root.rglob("*")
        for path in files:
            if path.is_file() and path.suffix in {".py", ".yml", ".yaml", ".md", ".sc"}:
                source = path.read_text(encoding="utf-8")
                assert not any(name in source for name in forbidden), path


def test_main_loads_config_and_dispatches(monkeypatch) -> None:
    loaded_paths: list[Path | None] = []
    dispatched: list[tuple[argparse.Namespace, object]] = []
    config = object()

    def fake_load_config(path: Path | None) -> object:
        loaded_paths.append(path)
        return config

    def fake_handle_file_context(args: argparse.Namespace, received_config: object) -> int:
        dispatched.append((args, received_config))
        return 17

    monkeypatch.setattr(cli, "load_config", fake_load_config)
    monkeypatch.setattr(cli, "handle_file_context", fake_handle_file_context)

    result = cli.main(
        [
            "build",
            "--config",
            "config.yml",
            "--pairs",
            "pairs.jsonl",
            "--file-info",
            "file-info.json",
            "--dataset-root",
            "dataset",
            "--output",
            "context.jsonl",
        ]
    )

    assert result == 17
    assert loaded_paths == [Path("config.yml")]
    assert len(dispatched) == 1
    assert dispatched[0][1] is config


def test_handle_file_context_rejects_non_positive_limit(monkeypatch, tmp_path, capsys) -> None:
    def fail_joern(*args, **kwargs):
        raise AssertionError("JoernAdapter should not be called")

    monkeypatch.setattr(cli, "JoernAdapter", fail_joern)
    args = argparse.Namespace(
        limit=0,
        pairs=tmp_path / "pairs.jsonl",
        file_info=tmp_path / "file-info.json",
        dataset_root=tmp_path / "dataset",
        output=tmp_path / "context.jsonl",
        report=tmp_path / "report.json",
        progress=False,
    )

    result = cli.handle_file_context(args, object())

    assert result == 1
    assert json.loads(capsys.readouterr().out)["status"] == "unavailable"


def test_handle_file_context_rejects_same_input_output(monkeypatch, tmp_path, capsys) -> None:
    def fail_joern(*args, **kwargs):
        raise AssertionError("JoernAdapter should not be called")

    monkeypatch.setattr(cli, "JoernAdapter", fail_joern)
    pairs = tmp_path / "pairs.jsonl"
    args = argparse.Namespace(
        limit=None,
        pairs=pairs,
        file_info=tmp_path / "file-info.json",
        dataset_root=tmp_path / "dataset",
        output=tmp_path / "nested" / ".." / pairs.name,
        report=tmp_path / "report.json",
        progress=False,
    )

    result = cli.handle_file_context(args, object())

    assert result == 1
    assert json.loads(capsys.readouterr().out)["status"] == "unavailable"
