from __future__ import annotations

import json

from data.build_primevul_context import build_context_files


def test_build_primevul_context_excludes_label_metadata(tmp_path):
    clean_root = tmp_path / "PrimeVul_clean"
    raw_root = tmp_path / "PrimeVul_raw"
    paired_dir = clean_root / "paired"
    file_dir = raw_root / "file_contents-bundle" / "file_contents" / "proj"

    paired_dir.mkdir(parents=True)
    file_dir.mkdir(parents=True)

    file_hash = 456
    func_hash = 123
    file_path = file_dir / f"{file_hash}.txt"
    file_path.write_text(
        "\n".join(
            [
                "static int helper(void) { return 1; }",
                "int caller(void) { return f(); }",
                "int f(void) { return helper(); }",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (raw_root / "file_info.json").write_text(
        json.dumps(
            {
                str(func_hash): {
                    "file_name": "f.c",
                    "file_hash": file_hash,
                    "project_file_path": "src/f.c",
                    "local_file_path": f"file_contents/proj/{file_hash}.txt",
                    "start_line": 10,
                    "end_line": 12,
                }
            }
        ),
        encoding="utf-8",
    )

    (paired_dir / "test.jsonl").write_text(
        json.dumps(
            {
                "pair_id": "pair_0",
                "cve": "CVE-0000-0000",
                "cwe": ["CWE-000"],
                "commit_message": "fix vulnerability",
                "vulnerable": {
                    "func": "int f(void) { return 0; }",
                    "func_hash": func_hash,
                    "target": 1,
                },
                "fixed": {
                    "func": "int f(void) { return 1; }",
                    "func_hash": 999,
                    "target": 0,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    stats = build_context_files(
        clean_root=clean_root,
        raw_root=raw_root,
        splits=["test"],
    )

    records = [
        json.loads(line)
        for line in (clean_root / "context" / "test.jsonl").read_text(
            encoding="utf-8",
        ).splitlines()
    ]
    keys = set().union(*(record.keys() for record in records))

    assert stats[0].total == 2
    assert stats[0].with_resolved_file == 1
    assert records[0]["sample_id"] == "test_000000"
    assert records[0]["resolved_file_available"] is True
    assert records[0]["function_start_line"] == 10
    assert records[0]["target_function"]["name"] == "f"
    assert records[0]["target_function"]["body_available"] is True
    assert records[0]["file_function_index"]["function_count"] == 3
    assert records[0]["call_context"]["scope"] == "same_file"
    assert records[0]["call_context"]["direct_callees"][0]["name"] == (
        "helper"
    )
    assert records[0]["call_context"]["direct_callees"][0][
        "body_available"
    ] is True
    assert records[0]["call_context"]["direct_callers"][0]["name"] == (
        "caller"
    )
    assert records[1]["sample_id"] == "test_000001"
    assert records[1]["file_context_available"] is False
    assert not keys.intersection(
        {
            "target",
            "cwe",
            "cve",
            "cve_desc",
            "nvd_url",
            "pair_id",
            "commit_id",
            "commit_url",
            "commit_message",
            "side",
        }
    )


def test_build_primevul_context_indexes_cpp_methods_in_namespace(tmp_path):
    clean_root = tmp_path / "PrimeVul_clean"
    raw_root = tmp_path / "PrimeVul_raw"
    paired_dir = clean_root / "paired"
    file_dir = raw_root / "file_contents-bundle" / "file_contents" / "proj"

    paired_dir.mkdir(parents=True)
    file_dir.mkdir(parents=True)

    file_hash = 456
    func_hash = 123
    file_path = file_dir / f"{file_hash}.txt"
    file_path.write_text(
        "\n".join(
            [
                "namespace demo {",
                "Status Worker::Initialize(const Graph& graph) {",
                "  TF_RETURN_IF_ERROR(view_.Initialize(&graph));",
                "  return Status::OK();",
                "}",
                "}",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    (raw_root / "file_info.json").write_text(
        json.dumps(
            {
                str(func_hash): {
                    "file_name": "worker.cc",
                    "file_hash": file_hash,
                    "project_file_path": "src/worker.cc",
                    "local_file_path": f"file_contents/proj/{file_hash}.txt",
                    "start_line": 2,
                    "end_line": 5,
                }
            }
        ),
        encoding="utf-8",
    )

    (paired_dir / "test.jsonl").write_text(
        json.dumps(
            {
                "vulnerable": {
                    "func": (
                        "Status Worker::Initialize(const Graph& graph) {\n"
                        "  return Status::OK();\n"
                        "}"
                    ),
                    "func_hash": func_hash,
                    "target": 1,
                },
                "fixed": {
                    "func": "int unrelated(void) { return 0; }",
                    "func_hash": 999,
                    "target": 0,
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    build_context_files(
        clean_root=clean_root,
        raw_root=raw_root,
        splits=["test"],
    )

    records = [
        json.loads(line)
        for line in (clean_root / "context" / "test.jsonl").read_text(
            encoding="utf-8",
        ).splitlines()
    ]

    assert records[0]["target_function"]["name"] == "Initialize"
    assert records[0]["target_function"]["start_line"] == 2
    assert records[0]["target_function"]["indexed"] is True
    assert records[0]["file_function_index"]["function_count"] == 1
    assert records[0]["call_context"]["available"] is True
