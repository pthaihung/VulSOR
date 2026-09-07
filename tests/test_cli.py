from __future__ import annotations

import json

import pytest

from vulsor.cli import build_parser
from vulsor.cli import main
from vulsor.cli import _build_diagnosis
from vulsor.cli import _dataset_stage_summary_rows
from vulsor.cli import _format_dataset_inspection_text
from vulsor.cli import _resolve_sample_selection
from vulsor.cli import _interactive_source_file_options
from vulsor.cli import _stage_coverage
from vulsor.agents.BaseAgent import (
    _line_numbers,
    _normalize_llm_payload,
    _source_windows,
    _validate_llm_reasoning,
    _validate_llm_view_payload,
)
from vulsor.agents.SemanticViews import build_operation_view
from vulsor.agents.SemanticViews import build_state_view
from vulsor.config import load_llm_config
from vulsor.tools.agent_tool_registry import run_agent_tool
from vulsor.analysis.program import analyze_source_code_tolerant
from vulsor.ui.console import MenuAction
from vulsor.ui.console import show_main_menu


# ---------------------------------------------------------------------------
# Interactive CLI
# ---------------------------------------------------------------------------


def test_main_without_arguments_opens_interactive(monkeypatch):
    called = False

    def fake_interactive():
        nonlocal called
        called = True
        return 0

    monkeypatch.setattr(
        "vulsor.cli._run_interactive",
        fake_interactive,
    )

    result = main([])

    assert result == 0
    assert called is True


def test_interactive_exit(monkeypatch):
    monkeypatch.setattr(
        "vulsor.cli.show_main_menu",
        lambda: MenuAction.EXIT,
    )

    assert main([]) == 0


def test_show_main_menu_selects_evaluate(monkeypatch):
    keys = iter(
        [
            "down",
            "down",
            "enter",
        ]
    )

    monkeypatch.setattr(
        "vulsor.ui.console._read_key",
        lambda: next(keys),
    )

    assert show_main_menu() is MenuAction.EVALUATE


def test_show_main_menu_selects_exit(monkeypatch):
    keys = iter(
        [
            "down",
            "down",
            "down",
            "down",
            "down",
            "down",
            "down",
            "enter",
        ]
    )

    monkeypatch.setattr(
        "vulsor.ui.console._read_key",
        lambda: next(keys),
    )

    assert show_main_menu() is MenuAction.EXIT


def test_show_main_menu_selects_agent(monkeypatch):
    keys = iter(
        [
            "down",
            "down",
            "down",
            "down",
            "enter",
        ]
    )

    monkeypatch.setattr(
        "vulsor.ui.console._read_key",
        lambda: next(keys),
    )

    assert show_main_menu() is MenuAction.AGENT


def test_show_main_menu_quit_key(monkeypatch):
    monkeypatch.setattr(
        "vulsor.ui.console._read_key",
        lambda: "q",
    )

    assert show_main_menu() is MenuAction.EXIT


# ---------------------------------------------------------------------------
# Parser
# ---------------------------------------------------------------------------


def test_inspect_accepts_file() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "inspect",
            "--file",
            "sample.c",
        ]
    )

    assert args.command == "inspect"
    assert args.file.name == "sample.c"
    assert args.config is None


def test_config_is_command_local() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "evaluate",
            "--config",
            "configs/primevul.yaml",
            "--dataset",
            "primevul",
            "--split",
            "test",
            "--limit",
            "10",
        ]
    )

    assert args.command == "evaluate"
    assert args.config.name == "primevul.yaml"
    assert args.dataset == "primevul"
    assert args.split == "test"
    assert args.limit == 10


def test_run_accepts_until_stage() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "run",
            "--file",
            "sample.c",
            "--until-stage",
            "program_analysis",
        ]
    )

    assert args.command == "run"
    assert args.until_stage == "program_analysis"


def test_run_program_analysis_file_outputs_json(capsys) -> None:
    fixture = "tests/fixtures/simple.cpp"

    result = main(
        [
            "run",
            "--file",
            fixture,
            "--until-stage",
            "program_analysis",
            "--format",
            "json",
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert result == 0
    assert output["stage_reached"] == "program_analysis"
    assert output["program_facts"]["functions"]
    assert output["program_facts"]["control_flow"]
    assert output["program_facts"]["data_flow"]


def test_inspect_file_outputs_program_analysis_summary(capsys) -> None:
    result = main(
        [
            "inspect",
            "--file",
            "tests/fixtures/simple.cpp",
        ]
    )

    output = capsys.readouterr().out

    assert result == 0
    assert "stage_reached: program_analysis" in output
    assert "functions: 1" in output
    assert "control_flow_edges: 4" in output
    assert "Functions:" in output
    assert "- foo (function:foo:3) lines 3-6" in output
    assert "Operations:" in output
    assert "- call memcpy(dst, src, len) at 5:9" in output
    assert "Control Flow:" in output
    assert "- B2 -> B1 [if [B2.4]]" in output
    assert "Data Flow:" in output
    assert "- len: 3:36 -> 5:26" in output
    assert "Call Graph:" in output
    assert "- foo -> memcpy at 5:9" in output


def test_inspect_dataset_outputs_json_for_multiple_samples(
    tmp_path,
    capsys,
) -> None:
    dataset_root = tmp_path / "dataset"
    input_dir = dataset_root / "inputs"
    input_dir.mkdir(parents=True)

    records = [
        {
            "sample_id": "sample_000000",
            "code": "int add_one(int value) { return value + 1; }\n",
        },
        {
            "sample_id": "sample_000001",
            "code": (
                "int choose(int value) {\n"
                "    if (value > 0) return value;\n"
                "    return 0;\n"
                "}\n"
            ),
        },
    ]

    input_file = input_dir / "test.jsonl"
    input_file.write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "\n".join(
            [
                "datasets:",
                "  local:",
                f"    root: {dataset_root.as_posix()}",
            ]
        ),
        encoding="utf-8",
    )

    result = main(
        [
            "inspect",
            "--config",
            str(config_file),
            "--dataset",
            "local",
            "--split",
            "test",
            "--limit",
            "2",
            "--format",
            "json",
            "--brain-context-dir",
            str(tmp_path / "brain_context"),
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert result == 0
    assert output["dataset"] == "local"
    assert output["split"] == "test"
    assert output["count"] == 2
    assert [
        sample["sample_id"]
        for sample in output["samples"]
    ] == ["sample_000000", "sample_000001"]
    assert all(
        sample["status"] == "ok"
        for sample in output["samples"]
    )
    assert output["samples"][0]["result"]["program_facts"]["functions"]
    assert output["samples"][0]["analysis"]["links"]["function_links"]
    manifest_path = tmp_path / "brain_context" / "local" / "test" / "manifest.json"
    artifact_path = (
        tmp_path
        / "brain_context"
        / "local"
        / "test"
        / "sample_000000.json"
    )
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    artifact = json.loads(artifact_path.read_text(encoding="utf-8"))

    assert output["brain_context"]["count"] == 2
    assert manifest["count"] == 2
    assert artifact["artifact_kind"] == "program_analysis"
    assert artifact["sample_id"] == "sample_000000"
    analysis = artifact["sample"]["analysis"]
    assert analysis["scope"] == "function"
    assert "source_context" not in analysis
    assert "context_facts" not in analysis
    assert "cpg_facts" not in analysis


def test_b2_views_use_local_program_facts_without_repository_context() -> None:
    artifact = {
        "sample": {
            "result": {
                "program_facts": {
                    "functions": [
                        {
                            "id": "function:example:1",
                            "name": "example",
                            "start_line": 1,
                            "end_line": 3,
                        }
                    ],
                    "operations": [],
                    "definitions": [],
                    "uses": [],
                    "data_flow": [],
                    "control_flow": [],
                    "cfg_blocks": [],
                }
            },
            "analysis": {
                "missing_context": [],
                "completeness": {},
            },
        }
    }

    state_view = build_state_view(artifact)
    operation_view = build_operation_view(artifact)

    assert state_view["target"] == {
        "available": True,
        "name": "example",
        "start_line": 1,
        "end_line": 3,
        "body_available": True,
    }
    assert "helper_call_context" not in operation_view


def test_state_agent_reads_brain_context_and_uses_cache(
    tmp_path,
    capsys,
) -> None:
    dataset_root = tmp_path / "dataset"
    input_dir = dataset_root / "inputs"
    brain_context_dir = tmp_path / "brain_context"
    input_dir.mkdir(parents=True)
    brain_context_dir.mkdir()
    (brain_context_dir / "AGENT_GUIDE.md").write_text(
        "# Agent Guide\n",
        encoding="utf-8",
    )

    (input_dir / "test.jsonl").write_text(
        json.dumps(
            {
                "sample_id": "sample_000000",
                "code": (
                    "void copy(char *dst, char *src, int len) {\n"
                    "    memcpy(dst, src, len);\n"
                    "}\n"
                ),
            }
        )
        + "\n",
        encoding="utf-8",
    )

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "\n".join(
            [
                "datasets:",
                "  local:",
                f"    root: {dataset_root.as_posix()}",
            ]
        ),
        encoding="utf-8",
    )

    assert main(
        [
            "inspect",
            "--config",
            str(config_file),
            "--dataset",
            "local",
            "--split",
            "test",
            "--limit",
            "1",
            "--format",
            "json",
            "--brain-context-dir",
            str(brain_context_dir),
        ]
    ) == 0
    capsys.readouterr()

    assert main(
        [
            "agent",
            "--agent",
            "state",
            "--brain-context-dir",
            str(brain_context_dir),
            "--dataset",
            "local",
            "--split",
            "test",
            "--sample",
            "sample_000000",
            "--format",
            "json",
        ]
    ) == 0
    first_output = json.loads(capsys.readouterr().out)
    state_path = (
        brain_context_dir
        / "local"
        / "test"
        / "agents"
        / "sample_000000"
        / "state.json"
    )
    state = json.loads(state_path.read_text(encoding="utf-8"))

    assert first_output["count"] == 1
    assert first_output["results"][0]["cache_hit"] is False
    assert state["agent"] == "state"
    assert any(
        variable["name"] == "dst"
        for variable in state["state_view"]["variables"]
    )
    assert state["state_view"]["buffers"]

    assert main(
        [
            "agent",
            "--agent",
            "state",
            "--brain-context-dir",
            str(brain_context_dir),
            "--dataset",
            "local",
            "--split",
            "test",
            "--sample",
            "sample_000000",
            "--format",
            "json",
        ]
    ) == 0
    second_output = json.loads(capsys.readouterr().out)

    assert second_output["results"][0]["cache_hit"] is True


def test_all_semantic_agents_write_views_and_merge(
    tmp_path,
    capsys,
) -> None:
    dataset_root = tmp_path / "dataset"
    input_dir = dataset_root / "inputs"
    brain_context_dir = tmp_path / "brain_context"
    input_dir.mkdir(parents=True)
    brain_context_dir.mkdir()
    (brain_context_dir / "AGENT_GUIDE.md").write_text(
        "# Agent Guide\n",
        encoding="utf-8",
    )

    (input_dir / "test.jsonl").write_text(
        json.dumps(
            {
                "sample_id": "sample_000000",
                "code": (
                    "void copy(char *dst, char *src, int len) {\n"
                    "    if (len > 0) memcpy(dst, src, len);\n"
                    "}\n"
                ),
            }
        )
        + "\n",
        encoding="utf-8",
    )

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "\n".join(
            [
                "datasets:",
                "  local:",
                f"    root: {dataset_root.as_posix()}",
            ]
        ),
        encoding="utf-8",
    )

    assert main(
        [
            "inspect",
            "--config",
            str(config_file),
            "--dataset",
            "local",
            "--split",
            "test",
            "--limit",
            "1",
            "--format",
            "json",
            "--brain-context-dir",
            str(brain_context_dir),
        ]
    ) == 0
    capsys.readouterr()

    assert main(
        [
            "agent",
            "--agent",
            "all",
            "--config",
            str(config_file),
            "--brain-context-dir",
            str(brain_context_dir),
            "--dataset",
            "local",
            "--split",
            "test",
            "--sample",
            "sample_000000",
            "--format",
            "json",
        ]
    ) == 0
    output = json.loads(capsys.readouterr().out)
    agent_dir = (
        brain_context_dir
        / "local"
        / "test"
        / "agents"
        / "sample_000000"
    )

    assert output["count"] == 5

    for name in ("state", "value", "execution", "operation"):
        payload = json.loads(
            (agent_dir / f"{name}.json").read_text(encoding="utf-8")
        )
        assert payload["agent"] == name
        assert f"{name}_view" in payload
        assert payload["_meta"]["prompt"]["path"].endswith(f"{name}.json")
        assert payload["_meta"]["prompt"]["id"] == f"vulsor.b2.{name}"
        assert payload["llm"]["enabled"] is False
        assert payload["_meta"]["boundary"]["verdict"] == "not_allowed"
        assert payload["_meta"]["view_validation"]["status"] == "ok"

    merged = json.loads(
        (agent_dir / "agent_semantics.json").read_text(encoding="utf-8")
    )
    semantic_graph = json.loads(
        (agent_dir / "semantic_graph.json").read_text(encoding="utf-8")
    )
    assert not (agent_dir / "semantic_cpg.json").exists()
    assert merged["status"] == "ok"
    assert merged["agent_semantics"]["state_view"]
    assert merged["agent_semantics"]["value_view"]
    assert merged["agent_semantics"]["execution_view"]
    assert merged["agent_semantics"]["operation_view"]
    assert semantic_graph["artifact_kind"] == "semantic_graph_overlay"
    assert semantic_graph["sample_id"] == "sample_000000"
    assert semantic_graph["graph"]["summary"]["node_count"] > 0
    assert semantic_graph["graph"]["summary"]["edge_count"] > 0
    assert any(
        node["type"] == "Operation"
        and node["properties"].get("name") == "memcpy"
        for node in semantic_graph["graph"]["nodes"]
    )
    assert any(
        edge["type"] == "SUPPORTED_BY"
        and edge["target"] == "fact:operation:memcpy:2:18"
        for edge in semantic_graph["graph"]["edges"]
    )

    state = json.loads(
        (agent_dir / "state.json").read_text(encoding="utf-8")
    )
    operation = json.loads(
        (agent_dir / "operation.json").read_text(encoding="utf-8")
    )

    buffer_names = {
        item["name"]
        for item in state["state_view"]["buffers"]
    }
    roles = {
        item["name"]: item["semantic_role"]
        for item in operation["operation_view"]["operations"]
    }

    assert {"dst", "src"} <= buffer_names
    assert roles["memcpy"] == "copy"
    assert "operation_inventory" not in operation["operation_view"]

    experiment_dir = (
        tmp_path
        / "experiments"
        / "local"
        / "test"
        / "execution"
    )
    experiment_dir.mkdir(parents=True)
    (experiment_dir / "sample_000000.json").write_text(
        json.dumps(
            {
                "llm": {
                    "enabled": True,
                    "provider": "test-provider",
                    "model": "test-model",
                    "result": {
                        "status": "ok",
                        "output": {
                            "execution_view": {
                                "observations": [
                                    {
                                        "claim": "memcpy executes under the observed function body",
                                        "supporting_fact_ids": [
                                            "operation:memcpy:2:18"
                                        ],
                                        "confidence": "high",
                                        "uncertainty": None,
                                    }
                                ],
                                "summary": "memcpy is present in execution order.",
                            },
                            "reasoning_groups": [
                                {
                                    "description": "copy operation reasoning",
                                    "steps": [
                                        {
                                            "claim": "memcpy is evidence for a copy operation",
                                            "derived_from": "operation:memcpy:2:18",
                                            "evidence": [
                                                {
                                                    "fact_id": "operation:memcpy:2:18",
                                                    "source_location": {
                                                        "line": 2,
                                                        "column": 18,
                                                    },
                                                    "source_excerpt": "unavailable",
                                                }
                                            ],
                                            "confidence": "high",
                                            "uncertainty": None,
                                        }
                                    ],
                                }
                            ],
                        },
                        "usage": {},
                        "view_validation": {"status": "ok", "issues": []},
                        "reasoning_validation": {
                            "status": "ok",
                            "issues": [],
                        },
                    },
                }
            }
        ),
        encoding="utf-8",
    )
    original_experiment = (
        experiment_dir / "sample_000000.json"
    ).read_text(encoding="utf-8")

    assert main(
        [
            "agent",
            "--agent",
            "execution",
            "--config",
            str(config_file),
            "--brain-context-dir",
            str(brain_context_dir),
            "--dataset",
            "local",
            "--split",
            "test",
            "--sample",
            "sample_000000",
            "--experiments-dir",
            str(tmp_path / "experiments"),
            "--force",
            "--format",
            "json",
        ]
    ) == 0
    capsys.readouterr()
    assert (
        experiment_dir / "sample_000000.json"
    ).read_text(encoding="utf-8") == original_experiment

    assert main(
        [
            "agent",
            "--agent",
            "merge",
            "--config",
            str(config_file),
            "--brain-context-dir",
            str(brain_context_dir),
            "--dataset",
            "local",
            "--split",
            "test",
            "--sample",
            "sample_000000",
            "--experiments-dir",
            str(tmp_path / "experiments"),
            "--force",
            "--format",
            "json",
        ]
    ) == 0
    capsys.readouterr()

    merged = json.loads(
        (agent_dir / "agent_semantics.json").read_text(encoding="utf-8")
    )
    semantic_graph = json.loads(
        (agent_dir / "semantic_graph.json").read_text(encoding="utf-8")
    )
    assert merged["agent_semantics"]["llm_semantics"]["execution"][
        "observations"
    ]
    assert any(
        node["type"] == "SemanticObservation"
        and "memcpy executes" in node["properties"].get("claim", "")
        for node in semantic_graph["graph"]["nodes"]
    )
    assert any(
        edge["type"] == "REFERS_TO"
        and edge["target"] == "operation:memcpy:2:18"
        for edge in semantic_graph["graph"]["edges"]
    )


def test_agent_llm_config_and_tools_are_allowlisted(tmp_path) -> None:
    config_path = tmp_path / "agent_llm.yaml"
    config_path.write_text(
        "\n".join(
            [
                "model: test-model",
                "max_tool_rounds: 2",
                "allowed_tools:",
                "  - get_program_facts",
            ]
        ),
        encoding="utf-8",
    )
    config = load_llm_config(config_path)
    artifact = {
        "sample_id": "sample_000000",
        "target": 1,
        "sample": {
            "result": {
                "program_facts": {
                    "operations": [
                        {
                            "id": "operation:memcpy:1:1",
                            "name": "memcpy",
                            "cwe": "forbidden",
                        }
                    ]
                }
            },
            "analysis": {},
        },
    }

    accepted = run_agent_tool(
        name="get_program_facts",
        arguments={"fact_type": "operations", "limit": 1},
        artifact=artifact,
        allowed_tools=config.allowed_tools,
    )
    rejected = run_agent_tool(
        name="get_limitations",
        arguments={},
        artifact=artifact,
        allowed_tools=config.allowed_tools,
    )

    assert config.model == "test-model"
    assert config.max_tool_rounds == 2
    assert accepted.status == "ok"
    assert accepted.output[0]["name"] == "memcpy"
    assert "cwe" not in accepted.output[0]
    assert rejected.status == "rejected"


def test_agent_llm_config_supports_per_agent_overrides(tmp_path) -> None:
    config_path = tmp_path / "agent_llm.yaml"
    config_path.write_text(
        "\n".join(
            [
                "model: shared-model",
                "max_tool_rounds: 1",
                "agents:",
                "  state:",
                "    model: state-model",
                "    max_tool_rounds: 2",
                "    allowed_tools:",
                "      - get_program_facts",
                "  value:",
                "    model: value-model",
            ]
        ),
        encoding="utf-8",
    )

    config = load_llm_config(config_path)

    assert config.for_agent("state").model == "state-model"
    assert config.for_agent("state").max_tool_rounds == 2
    assert config.for_agent("state").allowed_tools == ("get_program_facts",)
    assert config.for_agent("value").model == "value-model"
    assert config.for_agent("value").max_tool_rounds == 1
    assert config.for_agent("execution").model == "shared-model"


def test_llm_view_validation_rejects_string_view() -> None:
    validation = _validate_llm_view_payload(
        {
            "state_view": "agent-specific observations",
            "reasoning_groups": [],
        },
        "state",
    )

    assert validation["status"] == "unsupported"
    assert validation["issues"][0]["path"] == "state_view"


def test_llm_payload_normalization_keeps_only_lean_view_columns() -> None:
    payload = {
        "operation_view": {
            "operations": [{"name": "memcpy"}],
            "metadata": {"extra": True},
            "observations": [
                {
                    "claim": "memcpy copies bytes",
                    "supporting_fact_ids": ["operation:memcpy:10:3"],
                    "confidence": "high",
                    "uncertainty": None,
                    "extra_column": "drop me",
                }
            ],
            "summary": "copy operation observed",
        },
        "reasoning_groups": [],
        "extra_top_level": "drop me too",
    }

    normalized = _normalize_llm_payload(payload, "operation")

    assert set(normalized) == {"operation_view", "reasoning_groups"}
    assert set(normalized["operation_view"]) == {"observations", "summary"}
    assert set(normalized["operation_view"]["observations"][0]) == {
        "claim",
        "supporting_fact_ids",
        "confidence",
        "uncertainty",
    }


def test_llm_reasoning_accepts_whitespace_folded_excerpt() -> None:
    brain_view = {
        "variables": [
            {
                "name": "profile",
                "supporting_fact_ids": [
                    "definition:profile:435:6",
                    "use:profile:456:3",
                ],
            }
        ]
    }
    payload = {
        "reasoning_groups": [
            {
                "description": "profile is defined as a pointer",
                "steps": [
                    {
                        "claim": "profile is a StringInfo pointer",
                        "derived_from": "definition:profile:435:6",
                        "evidence": [
                            {
                                "fact_id": "definition:profile:435:6",
                                "source_location": {"line": 2, "column": 6},
                                "source_excerpt": "const StringInfo *profile",
                            }
                        ],
                        "confidence": "high",
                        "uncertainty": None,
                    }
                ],
            }
        ]
    }
    source = {
        "available": True,
        "code": "void f(void) {\n  const StringInfo\n    *profile;\n}\n",
    }

    validation = _validate_llm_reasoning(payload, brain_view, source)

    assert validation["status"] == "ok"


def test_llm_reasoning_accepts_missing_line_when_excerpt_exists() -> None:
    brain_view = {
        "ordered_operations": [
            {
                "operation_id": "operation:SyncAuthenticPixels:None:10",
                "supporting_fact_ids": [
                    "operation:SyncAuthenticPixels:None:10",
                ],
            }
        ]
    }
    payload = {
        "reasoning_groups": [
            {
                "description": "return path",
                "steps": [
                    {
                        "claim": "function returns SyncAuthenticPixels",
                        "evidence": [
                            {
                                "fact_id": "operation:SyncAuthenticPixels:None:10",
                                "source_location": {"line": None, "column": 10},
                                "source_excerpt": "return(SyncAuthenticPixels(image,exception));",
                            }
                        ],
                    }
                ],
            }
        ]
    }
    source = {
        "available": True,
        "code": "int f(void) {\n  return(SyncAuthenticPixels(image,exception));\n}\n",
    }

    validation = _validate_llm_reasoning(payload, brain_view, source)

    assert validation["status"] == "ok"
    assert validation["warnings"]


def test_llm_reasoning_accepts_nonexact_excerpt_when_fact_symbol_is_on_line() -> None:
    brain_view = {
        "variables": [
            {
                "name": "exif",
                "supporting_fact_ids": [
                    "definition:exif:4:6",
                ],
            }
        ]
    }
    payload = {
        "reasoning_groups": [
            {
                "description": "split declaration",
                "steps": [
                    {
                        "claim": "exif is declared",
                        "evidence": [
                            {
                                "fact_id": "definition:exif:4:6",
                                "source_location": {"line": 4, "column": 6},
                                "source_excerpt": "const unsigned char *exif",
                            }
                        ],
                    }
                ],
            }
        ]
    }
    source = {
        "available": True,
        "code": "void f(void) {\n  const unsigned char\n    *directory,\n    *exif;\n}\n",
    }

    validation = _validate_llm_reasoning(payload, brain_view, source)

    assert validation["status"] == "ok"
    assert validation["warnings"]


def test_interactive_sample_selection_accepts_comma_indices() -> None:
    samples = [
        {"sample_id": "test_000000"},
        {"sample_id": "test_000001"},
        {"sample_id": "test_000002"},
    ]

    assert _resolve_sample_selection("1,3", samples) == [
        "test_000000",
        "test_000002",
    ]


def test_source_windows_use_fact_id_lines_without_full_source() -> None:
    brain = {
        "symbols": [
            {
                "supporting_fact_ids": [
                    "definition:value:45:7",
                    "use:value:90:13",
                ]
            }
        ]
    }
    code = "\n".join(f"line {index}" for index in range(1, 121))

    windows = _source_windows(
        {"available": True, "sample_id": "sample", "code": code},
        brain,
    )

    assert _line_numbers(brain) == {45, 90}
    assert windows["context_complete"] is False
    assert windows["requested_source_lines"] == [45, 90]
    assert len(windows["windows"]) == 2
    assert all("line 120" not in item["code"] for item in windows["windows"])


def test_interactive_agent_runs_from_menu(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    dataset_root = tmp_path / "dataset"
    input_dir = dataset_root / "inputs"
    brain_context_dir = tmp_path / "brain_context"
    input_dir.mkdir(parents=True)
    brain_context_dir.mkdir()
    (brain_context_dir / "AGENT_GUIDE.md").write_text(
        "# Agent Guide\n",
        encoding="utf-8",
    )

    (input_dir / "test.jsonl").write_text(
        json.dumps(
            {
                "sample_id": "sample_000000",
                "code": "int id(int value) { return value; }\n",
            }
        )
        + "\n",
        encoding="utf-8",
    )

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "\n".join(
            [
                "datasets:",
                "  local:",
                f"    root: {dataset_root.as_posix()}",
            ]
        ),
        encoding="utf-8",
    )

    assert main(
        [
            "inspect",
            "--config",
            str(config_file),
            "--dataset",
            "local",
            "--split",
            "test",
            "--limit",
            "1",
            "--format",
            "json",
            "--brain-context-dir",
            str(brain_context_dir),
        ]
    ) == 0
    capsys.readouterr()

    inputs = iter(
        [
            str(config_file),
            str(brain_context_dir),
            "local",
            "test",
            "3",
            "sample_000000",
            "n",
            "y",
            "",
            "n",
            "json",
            "",
            "n",
        ]
    )

    monkeypatch.setattr(
        "vulsor.cli.console.input",
        lambda *_args, **_kwargs: next(inputs),
    )

    from vulsor.cli import _interactive_agent

    assert _interactive_agent() == 0
    captured = capsys.readouterr().out
    output = json.loads(captured[captured.index("{"):])

    assert output["agent"] == "value"
    assert output["count"] == 1
    assert output["results"][0]["sample_id"] == "sample_000000"


def test_interactive_agent_runs_all_comma_selected_samples(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    brain_context_dir = tmp_path / "brain_context"
    manifest_dir = brain_context_dir / "local" / "test"
    manifest_dir.mkdir(parents=True)
    (brain_context_dir / "AGENT_GUIDE.md").write_text(
        "# Agent Guide\n",
        encoding="utf-8",
    )
    (manifest_dir / "manifest.json").write_text(
        json.dumps(
            {
                "samples": [
                    {"sample_id": "test_000000", "status": "ok"},
                    {"sample_id": "test_000001", "status": "ok"},
                    {"sample_id": "test_000002", "status": "ok"},
                ]
            }
        ),
        encoding="utf-8",
    )

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "\n".join(
            [
                "datasets:",
                "  local:",
                f"    root: {(tmp_path / 'dataset').as_posix()}",
            ]
        ),
        encoding="utf-8",
    )

    seen_samples = []

    def fake_handle_agent(args, _config):
        seen_samples.append(args.sample)
        return 0

    preview_calls = []

    monkeypatch.setattr("vulsor.cli._handle_agent", fake_handle_agent)
    monkeypatch.setattr(
        "vulsor.cli._interactive_view_agent_outputs",
        lambda **kwargs: preview_calls.append(kwargs),
    )
    inputs = iter(
        [
            str(config_file),
            str(brain_context_dir),
            "local",
            "test",
            "",
            "1,2,3",
            "n",
            "y",
            "",
            "n",
            "text",
            "",
            "y",
        ]
    )
    monkeypatch.setattr(
        "vulsor.cli.console.input",
        lambda *_args, **_kwargs: next(inputs),
    )

    from vulsor.cli import _interactive_agent

    assert _interactive_agent() == 0
    assert seen_samples == ["test_000000", "test_000001", "test_000002"]
    assert preview_calls == []
    captured = capsys.readouterr().out
    assert "Sample:" in captured
    assert "test_000002" in captured


def test_interactive_inspect_file_rejects_non_source_file(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    config_file = tmp_path / "primevul.yaml"
    config_file.write_text("datasets: {}\n", encoding="utf-8")
    inputs = iter([str(config_file)])

    monkeypatch.setattr(
        "vulsor.cli.console.input",
        lambda *_args, **_kwargs: next(inputs),
    )

    from vulsor.cli import _interactive_inspect_file

    assert _interactive_inspect_file() == 0
    captured = capsys.readouterr().out

    assert "expects a C/C++ file" in captured
    assert ".yaml" in captured


def test_interactive_source_file_suggestions_only_include_source_files(
    tmp_path,
) -> None:
    (tmp_path / "configs").mkdir()
    (tmp_path / "configs" / "primevul.yaml").write_text(
        "datasets: {}\n",
        encoding="utf-8",
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "sample.c").write_text(
        "int main(void) { return 0; }\n",
        encoding="utf-8",
    )
    (tmp_path / "experiments").mkdir()
    (tmp_path / "experiments" / "old.c").write_text(
        "int old(void) { return 0; }\n",
        encoding="utf-8",
    )

    suggestions = _interactive_source_file_options(tmp_path)

    assert "src\\sample.c" in suggestions or "src/sample.c" in suggestions
    assert all("primevul.yaml" not in item for item in suggestions)
    assert all("experiments" not in item for item in suggestions)


def test_interactive_inspect_dataset_outputs_json(
    tmp_path,
    monkeypatch,
    capsys,
) -> None:
    dataset_root = tmp_path / "dataset"
    input_dir = dataset_root / "inputs"
    input_dir.mkdir(parents=True)

    records = [
        {
            "sample_id": "sample_000000",
            "code": "int first(int value) { return value; }\n",
        },
        {
            "sample_id": "sample_000001",
            "code": "int second(int value) { return value + 1; }\n",
        },
    ]

    (input_dir / "test.jsonl").write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "\n".join(
            [
                "datasets:",
                "  local:",
                f"    root: {dataset_root.as_posix()}",
            ]
        ),
        encoding="utf-8",
    )

    inputs = iter(
        [
            "2",
            str(config_file),
            "",
            "local",
            "test",
            "2",
            "2",
            "json",
            "",
            "1",
        ]
    )

    monkeypatch.setattr(
        "vulsor.cli.console.input",
        lambda *_args, **_kwargs: next(inputs),
    )
    monkeypatch.chdir(tmp_path)

    from vulsor.cli import _interactive_inspect

    result = _interactive_inspect()
    captured = capsys.readouterr().out

    assert result == 0
    assert "JSON Output" in captured
    assert '"dataset": "local"' in captured
    assert '"split": "test"' in captured
    assert "sample_000000" in captured
    assert "sample_000001" in captured
    assert "Summary" in captured


def test_inspect_dataset_outputs_json_for_random_samples(
    tmp_path,
    capsys,
) -> None:
    dataset_root = tmp_path / "dataset"
    input_dir = dataset_root / "inputs"
    input_dir.mkdir(parents=True)

    records = [
        {
            "sample_id": f"sample_{index:06d}",
            "code": f"int f{index}(int value) {{ return value; }}\n",
        }
        for index in range(5)
    ]

    (input_dir / "test.jsonl").write_text(
        "\n".join(json.dumps(record) for record in records) + "\n",
        encoding="utf-8",
    )

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "\n".join(
            [
                "datasets:",
                "  local:",
                f"    root: {dataset_root.as_posix()}",
            ]
        ),
        encoding="utf-8",
    )

    result = main(
        [
            "inspect",
            "--config",
            str(config_file),
            "--dataset",
            "local",
            "--split",
            "test",
            "--random",
            "2",
            "--seed",
            "7",
            "--format",
            "json",
            "--brain-context-dir",
            str(tmp_path / "brain_context"),
        ]
    )

    output = json.loads(capsys.readouterr().out)

    assert result == 0
    assert output["count"] == 2
    assert all(
        sample["status"] == "ok"
        for sample in output["samples"]
    )


def test_inspect_dataset_recovers_partial_facts_from_bad_snippet(
    tmp_path,
    capsys,
) -> None:
    dataset_root = tmp_path / "dataset"
    input_dir = dataset_root / "inputs"
    input_dir.mkdir(parents=True)

    (input_dir / "test.jsonl").write_text(
        json.dumps(
            {
                "sample_id": "sample_000000",
                "code": (
                    "static ProjectType example(ProjectObject *object) {\n"
                    "    return ProjectFalse;\n"
                    "}\n"
                ),
            }
        )
        + "\n",
        encoding="utf-8",
    )

    config_file = tmp_path / "config.yaml"
    config_file.write_text(
        "\n".join(
            [
                "datasets:",
                "  local:",
                f"    root: {dataset_root.as_posix()}",
            ]
        ),
        encoding="utf-8",
    )

    result = main(
        [
            "inspect",
            "--config",
            str(config_file),
            "--dataset",
            "local",
            "--split",
            "test",
            "--limit",
            "1",
            "--format",
            "json",
            "--brain-context-dir",
            str(tmp_path / "brain_context"),
        ]
    )

    output = json.loads(capsys.readouterr().out)
    sample = output["samples"][0]

    assert result == 0
    assert sample["status"] == "partial"
    assert sample["result"]["program_facts"]["functions"][0]["name"] == (
        "example"
    )
    assert sample["analysis"]["scope"] == "function"
    assert sample["analysis"]["context_mode"] == (
        "synthetic_recovered_function"
    )
    assert sample["analysis"]["complete"] is False
    assert sample["analysis"]["completeness"]["ast"]["status"] == (
        "recovered"
    )
    assert sample["analysis"]["completeness"]["cfg"]["status"] == (
        "recovered"
    )
    assert sample["analysis"]["completeness"]["cfg"]["reason"] == (
        "Clang CFG was recovered using explicit synthetic compile context"
    )
    assert sample["analysis"]["missing_context"][0]["kind"] == (
        "unknown_type"
    )
    assert sample["analysis"]["missing_context"][0]["symbol"] == (
        "ProjectType"
    )
    assert sample["analysis"]["missing_context_summary"] == {
        "unique_symbols": 3,
        "total_occurrences": 6,
        "by_kind": {
            "unknown_type": 2,
            "undeclared_identifier": 1,
        },
    }
    assert (
        "project headers, typedefs, macros, and build flags may be unavailable"
        in sample["analysis"]["limitations"]
    )
    assert (
        "CFG facts were recovered with explicit synthetic compile context; recovery assumptions are not vulnerability evidence"
        in sample["analysis"]["limitations"]
    )
    assert sample["analysis"]["recovery_assumptions"] == [
        {
            "kind": "synthetic_typedef",
            "symbol": "ProjectType",
            "declaration": "typedef int ProjectType;",
            "reason": (
                "Clang reported missing type 'ProjectType'; declaration is "
                "used only to recover AST/CFG shape."
            ),
            "provenance": "synthetic_context",
            "trust": "compile_recovery_only",
            "used_for": "clang_ast_cfg_recovery",
            "not_evidence_for_verdict": True,
        },
        {
            "kind": "synthetic_typedef",
            "symbol": "ProjectObject",
            "declaration": "typedef int ProjectObject;",
            "reason": (
                "Clang reported missing type 'ProjectObject'; declaration is "
                "used only to recover AST/CFG shape."
            ),
            "provenance": "synthetic_context",
            "trust": "compile_recovery_only",
            "used_for": "clang_ast_cfg_recovery",
            "not_evidence_for_verdict": True,
        },
        {
            "kind": "synthetic_macro_constant",
            "symbol": "ProjectFalse",
            "declaration": "#define ProjectFalse 0",
            "reason": (
                "Clang reported undeclared identifier 'ProjectFalse'; macro "
                "is used only to recover AST/CFG shape."
            ),
            "provenance": "synthetic_context",
            "trust": "compile_recovery_only",
            "used_for": "clang_ast_cfg_recovery",
            "not_evidence_for_verdict": True,
        },
    ]
    assert (
        "program analysis emits facts only; it does not infer vulnerability verdicts"
        in sample["analysis"]["limitations"]
    )
    assert (
        "program analysis does not infer VULNERABLE/BENIGN verdicts"
        in sample["analysis"]["rules"]
    )
    assert "AST recovered from Clang errors" in sample["diagnostics"]


def test_dataset_stage_summary_groups_one_row_per_sample() -> None:
    payload = {
        "samples": [
            {
                "sample_id": "sample_000000",
                "status": "partial",
                "diagnostics": [
                    "AST recovered from Clang errors",
                    "CFG unavailable: missing project headers",
                ],
                "analysis": {
                    "missing_context": [
                        {
                            "kind": "unknown_type",
                            "symbol": "ProjectType",
                        }
                    ],
                    "limitations": [
                        "project headers, typedefs, macros, and build flags may be unavailable",
                    ],
                },
            }
        ]
    }

    rows = _dataset_stage_summary_rows(payload)

    assert len(rows) == 1
    assert rows[0]["sample_id"] == "sample_000000"
    assert rows[0]["source"] == "available"
    assert rows[0]["ast"] == "missing"
    assert rows[0]["cfg"] == "missing"
    assert rows[0]["data_flow"] == "missing"


def test_stage_coverage_is_dynamic_from_sample_statuses() -> None:
    payload = {
        "samples": [
            {
                "status": "partial",
                "analysis": {
                    "completeness": {
                        "ast": {"status": "recovered"},
                        "cfg": {"status": "missing"},
                        "data_flow": {"status": "limited"},
                    },
                },
            },
            {
                "status": "error",
            },
        ]
    }

    coverage = dict(_stage_coverage(payload))

    assert coverage == {
        "source": 1,
        "ast": 1,
        "cfg": 0,
        "data_flow": 1,
    }


def test_dataset_inspection_text_format_is_plain_sections() -> None:
    payload = {
        "dataset": "local",
        "split": "test",
        "count": 1,
        "brain_context": {
            "artifact_dir": "brain_context/local/test",
            "count": 1,
        },
        "samples": [
            {
                "sample_id": "sample_000000",
                "status": "partial",
                "result": {
                    "program_facts": {
                        "functions": [{"name": "f"}],
                        "operations": [{"name": "memcpy"}],
                        "cfg_blocks": [],
                        "data_flow": [],
                        "call_graph": [],
                    }
                },
                "analysis": {
                    "completeness": {
                        "ast": {
                            "status": "recovered",
                            "reason": "Clang emitted recoverable AST JSON despite diagnostics",
                        },
                        "cfg": {
                            "status": "missing",
                            "reason": "Clang CFG dump failed or produced no CFG text",
                        },
                        "data_flow": {
                            "status": "limited",
                            "reason": "syntactic data-flow was built from recovered AST facts",
                        },
                    },
                    "build_diagnosis": {
                        "issues": [
                            {
                                "component": "cfg",
                                "classification": "function_analysis_cfg_missing",
                                "fixable": True,
                                "message": "headers are unavailable",
                            }
                        ]
                    },
                    "missing_context_summary": {
                        "unique_symbols": 2,
                        "total_occurrences": 5,
                        "by_kind": {"unknown_type": 2},
                    },
                },
                "diagnostics": ["AST recovered from Clang errors"],
            }
        ],
    }

    output = _format_dataset_inspection_text(payload)

    assert "Summary:" in output
    assert "Stage coverage:" in output
    assert "sample_000000 [partial]" in output
    assert "artifact:" in output
    assert "sample_000000.json" in output
    assert "table_row: source=available" in output
    assert "stage_details:" in output
    assert "facts:" in output
    assert "operations=1" in output
    assert "missing_symbols: unique=2" in output
    assert "root_causes:" in output
    assert "function_analysis_cfg_missing" in output
    assert "diagnostics:" in output
    assert "Stage Summary" not in output
    assert "┏" not in output


def test_dataset_inspection_text_separates_sample_blocks() -> None:
    payload = {
        "dataset": "local",
        "split": "test",
        "count": 2,
        "samples": [
            {
                "sample_id": "sample_000000",
                "status": "error",
                "error": "failed",
            },
            {
                "sample_id": "sample_000001",
                "status": "error",
                "error": "failed",
            },
        ],
    }

    output = _format_dataset_inspection_text(payload)

    assert "\n\n- sample_000001 [error]" in output


# ---------------------------------------------------------------------------
# Input-source validation
# ---------------------------------------------------------------------------


def test_inspect_rejects_file_with_sample() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "inspect",
            "--file",
            "sample.c",
            "--sample",
            "test_000123",
        ]
    )

    with pytest.raises(
        SystemExit,
        match="--sample cannot be used with --file",
    ):
        from vulsor.cli import _validate_input_source_args

        _validate_input_source_args(args)


def test_inspect_rejects_file_with_split() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "inspect",
            "--file",
            "sample.c",
            "--split",
            "test",
        ]
    )

    with pytest.raises(
        SystemExit,
        match="--split cannot be used with --file",
    ):
        from vulsor.cli import _validate_input_source_args

        _validate_input_source_args(args)


# ---------------------------------------------------------------------------
# Evaluate validation
# ---------------------------------------------------------------------------


def test_evaluate_rejects_invalid_limit() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "evaluate",
            "--dataset",
            "primevul",
            "--split",
            "test",
            "--limit",
            "0",
        ]
    )

    with pytest.raises(
        SystemExit,
        match="--limit must be >= 1",
    ):
        from vulsor.cli import _validate_evaluate_args

        _validate_evaluate_args(args)


def test_evaluate_rejects_negative_offset() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "evaluate",
            "--dataset",
            "primevul",
            "--split",
            "test",
            "--offset",
            "-1",
        ]
    )

    with pytest.raises(
        SystemExit,
        match="--offset must be >= 0",
    ):
        from vulsor.cli import _validate_evaluate_args

        _validate_evaluate_args(args)


def test_evaluate_rejects_sample_with_offset() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "evaluate",
            "--dataset",
            "primevul",
            "--split",
            "test",
            "--sample",
            "test_000123",
            "--offset",
            "10",
        ]
    )

    with pytest.raises(
        SystemExit,
        match="--offset cannot be used with --sample",
    ):
        from vulsor.cli import _validate_evaluate_args

        _validate_evaluate_args(args)


def test_evaluate_rejects_resume_without_cache_dir() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "evaluate",
            "--dataset",
            "primevul",
            "--split",
            "test",
            "--resume",
        ]
    )

    with pytest.raises(
        SystemExit,
        match="--resume requires --cache-dir",
    ):
        from vulsor.cli import _validate_evaluate_args

        _validate_evaluate_args(args)


def test_evaluate_rejects_resume_with_no_cache() -> None:
    parser = build_parser()

    args = parser.parse_args(
        [
            "evaluate",
            "--dataset",
            "primevul",
            "--split",
            "test",
            "--resume",
            "--cache-dir",
            ".cache",
            "--no-cache",
        ]
    )

    with pytest.raises(
        SystemExit,
        match="--resume cannot be used with --no-cache",
    ):
        from vulsor.cli import _validate_evaluate_args

        _validate_evaluate_args(args)
