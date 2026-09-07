from pathlib import Path

from scripts import context_tool


def test_context_tool_delegates_to_file_context_build(monkeypatch) -> None:
    captured: list[list[str]] = []

    def fake_cli_main(argv):
        captured.append(list(argv))
        return 7

    monkeypatch.setattr("vulsor.cli.main", fake_cli_main)

    result = context_tool.main(
        [
            "build",
            "--pairs",
            "pairs.jsonl",
            "--file-info",
            "file_info.json",
            "--dataset-root",
            "dataset",
            "--output",
            "context.jsonl",
        ]
    )

    assert result == 7
    assert captured == [
        [
            "file-context",
            "build",
            "--pairs",
            "pairs.jsonl",
            "--file-info",
            "file_info.json",
            "--dataset-root",
            "dataset",
            "--output",
            "context.jsonl",
            "--progress",
        ]
    ]
    assert str(Path(__file__).parents[1] / "src") in context_tool.sys.path


def test_context_tool_accepts_build_without_requiring_pythonpath(monkeypatch) -> None:
    captured: list[list[str]] = []

    def fake_cli_main(argv):
        captured.append(list(argv))
        return 0

    monkeypatch.setattr("vulsor.cli.main", fake_cli_main)

    assert context_tool.main(["build", "--help"]) == 0
    assert captured == [["file-context", "build", "--help", "--progress"]]
