from tests.context_tool_module import context_tool


def test_context_tool_dispatches_build_to_file_context_service(monkeypatch, tmp_path) -> None:
    dispatched: list[tuple[object, object]] = []

    def fake_load_config(path):
        return "config"

    def fake_handle(args, config):
        dispatched.append((args, config))
        return 7

    monkeypatch.setattr(context_tool, "load_config", fake_load_config)
    monkeypatch.setattr(context_tool, "handle_file_context", fake_handle)

    result = context_tool.main(
        [
            "build",
            "--pairs",
            str(tmp_path / "pairs.jsonl"),
            "--file-info",
            str(tmp_path / "file_info.json"),
            "--dataset-root",
            str(tmp_path / "dataset"),
            "--output",
            str(tmp_path / "context.jsonl"),
        ]
    )

    assert result == 7
    assert len(dispatched) == 1
    assert dispatched[0][1] == "config"
