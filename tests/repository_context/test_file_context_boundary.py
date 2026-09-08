import argparse
import json
import sys
from pathlib import Path


SOURCE_ROOT = Path(__file__).resolve().parents[2] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from agents.repo_context import cli
from agents.repo_context.cli import build_parser


def test_context_cli_exposes_only_file_context_build() -> None:
    parser = build_parser()
    command_action = next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    assert set(command_action.choices) == {"file-context"}

    file_parser = command_action.choices["file-context"]
    file_action = next(
        action
        for action in file_parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    assert set(file_action.choices) == {"build"}


def test_context_cli_has_no_repository_query_symbols() -> None:
    source = Path("src/agents/repo_context/cli.py").read_text(encoding="utf-8")
    for legacy_name in (
        "RepositoryPreprocessor",
        "RepositoryContextQueryService",
        "repo-context",
        "import-primevul",
        "build-context",
        "show-context",
    ):
        assert legacy_name not in source


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
            "file-context",
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
