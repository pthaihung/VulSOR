import json

from agents.repo_context.file_context_service import (
    FileContextResult,
    FileContextService,
)


def test_build_jsonl_reports_progress_for_each_target_record(tmp_path) -> None:
    pairs = tmp_path / "pairs.jsonl"
    pairs.write_text(
        "\n".join(
            [
                json.dumps({"idx": 1, "target": 1, "func_hash": 101}),
                json.dumps({"idx": 2, "target": 0, "func_hash": 102}),
                json.dumps({"idx": 3, "target": 1, "func_hash": 103}),
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    file_info = tmp_path / "file_info.json"
    file_info.write_text("{}", encoding="utf-8")
    output = tmp_path / "context.jsonl"
    events = []
    service = FileContextService(object(), object(), object(), dataset_root=tmp_path)

    def fake_process(raw, locators):
        return FileContextResult({**raw, "context": {}}, "built")

    service.process = fake_process

    counts = service.build_jsonl(
        pairs,
        file_info,
        output,
        progress=lambda current, total, result: events.append(
            (current, total, result.status, result.record["idx"])
        ),
    )

    assert counts == {"total": 2, "built": 2, "unavailable": 0, "failed": 0, "oversized": 0}
    assert events == [(1, 2, "built", 1), (2, 2, "built", 3)]
