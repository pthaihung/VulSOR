"""Command-line interface for VulSOR.

Responsibilities:
- parse command-line arguments;
- perform basic CLI validation;
- load configuration;
- dispatch to the pipeline layer.

This module must not contain security reasoning, program-analysis logic,
LLM calls, dataset interpretation, or verification logic.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import sys

from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from pathlib import Path
from typing import Sequence
from pydantic import ValidationError
from rich.json import JSON
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from vulsor.config import VulSORConfig, load_config, load_llm_config
from vulsor.datasets import iter_dataset_samples
from vulsor.pipeline import PipelineResult, STAGE_ORDER, Stage, run_pipeline
from vulsor.analysis.program import (
    ProgramAnalysisResult,
    analyze_source_code_tolerant,
)
from vulsor.agents.BaseAgent import (
    SEMANTIC_AGENTS,
    run_all_semantic_agents_for_manifest,
    run_semantic_agent_for_manifest,
    run_semantic_merge_for_manifest,
)
from vulsor.ui.console import (
    MenuAction,
    clear_screen,
    console,
    print_error,
    print_info,
    show_main_menu,
)

PROGRAM_ANALYSIS_RULES = (
    "tools produce program facts only",
    "program analysis does not infer VULNERABLE/BENIGN verdicts",
    "missing project context is reported as a limitation, not fabricated",
    "dataset labels, CWE, CVE, and pair metadata are not used as analysis input",
)

SOURCE_FILE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
}

SOURCE_SUGGESTION_EXCLUDE_DIRS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "brain_context",
    "experiments",
    "node_modules",
}

# ---------------------------------------------------------------------------
# Parser construction
# ---------------------------------------------------------------------------


def _stage_choices() -> list[str]:
    """Return valid pipeline stage names for argparse."""
    return [stage.value for stage in STAGE_ORDER]


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level VulSOR CLI parser."""
    parser = argparse.ArgumentParser(
        prog="vulsor",
        description=(
            "VulSOR: semantic-obligation-based "
            "C/C++ vulnerability detection."
        ),
    )

    subparsers = parser.add_subparsers(
        dest="command",
        required=False,
    )

    _add_inspect_parser(subparsers)
    _add_detect_parser(subparsers)
    _add_evaluate_parser(subparsers)
    _add_run_parser(subparsers)
    _add_agent_parser(subparsers)
    _add_doctor_parser(subparsers)
    _add_version_parser(subparsers)

    from vulsor.repository_context.cli import add_parser
    add_parser(subparsers)

    return parser


def _add_config_arg(sp: argparse.ArgumentParser) -> None:
    """Add the command-local --config option."""
    sp.add_argument(
        "--config",
        type=Path,
        default=None,
        help=(
            "Path to a YAML config file. "
            "If omitted, built-in defaults are used."
        ),
    )


def _add_input_source_args(sp: argparse.ArgumentParser) -> None:
    """Add mutually exclusive file/dataset source arguments.

    Valid forms are:

        --file PATH

    or:

        --dataset NAME --split SPLIT [--sample ID]
    """
    source = sp.add_mutually_exclusive_group(required=True)

    source.add_argument(
        "--file",
        type=Path,
        help="Path to a single C/C++ source file.",
    )

    source.add_argument(
        "--dataset",
        type=str,
        help="Dataset name defined under 'datasets:' in the config.",
    )

    sp.add_argument(
        "--split",
        choices=["train", "valid", "test"],
        help="Dataset split. Required when --dataset is used.",
    )

    sp.add_argument(
        "--sample",
        type=str,
        help="Single sample_id to select from the dataset split.",
    )


def _add_output_args(sp: argparse.ArgumentParser) -> None:
    """Add common output options."""
    sp.add_argument(
        "--format",
        choices=["text", "json"],
        default="text",
        help="Output format (default: text).",
    )

    sp.add_argument(
        "--output",
        type=Path,
        default=None,
        help="Write result to this path instead of stdout.",
    )


def _add_inspect_parser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Add the inspect command."""
    sp = subparsers.add_parser(
        "inspect",
        help="Inspect program-analysis/semantic results without a verdict.",
    )

    _add_config_arg(sp)
    _add_input_source_args(sp)

    sp.add_argument(
        "--limit",
        type=int,
        help="Inspect at most N dataset samples.",
    )

    sp.add_argument(
        "--all",
        action="store_true",
        help="Inspect every sample in the selected dataset split.",
    )

    sp.add_argument(
        "--random",
        type=int,
        default=None,
        help="Inspect N random dataset samples.",
    )

    sp.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Seed for random dataset sample selection.",
    )

    sp.add_argument(
        "--jobs",
        type=int,
        default=1,
        help=(
            "Number of dataset samples to inspect concurrently "
            "(default: 1)."
        ),
    )

    sp.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Skip the first N dataset samples before inspection.",
    )

    sp.add_argument(
        "--brain-context-dir",
        type=Path,
        default=Path("brain_context"),
        help=(
            "Directory for per-sample Program Analysis artifacts "
            "(default: brain_context)."
        ),
    )

    _add_output_args(sp)

    sp.set_defaults(handler=_handle_inspect)


def _add_detect_parser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Add the detect command."""
    sp = subparsers.add_parser(
        "detect",
        help="Run vulnerability detection for one function.",
    )

    _add_config_arg(sp)
    _add_input_source_args(sp)
    _add_output_args(sp)

    sp.set_defaults(handler=_handle_detect)


def _add_evaluate_parser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Add the evaluate command."""
    sp = subparsers.add_parser(
        "evaluate",
        help="Run evaluation over a dataset split and compare predictions with labels.",
    )

    _add_config_arg(sp)

    sp.add_argument(
        "--dataset",
        type=str,
        required=True,
        help="Dataset name defined under 'datasets:' in the config.",
    )

    sp.add_argument(
        "--split",
        choices=["train", "valid", "test"],
        required=True,
        help="Dataset split to evaluate.",
    )

    selection = sp.add_mutually_exclusive_group()

    selection.add_argument(
        "--sample",
        type=str,
        help="Evaluate a single sample_id.",
    )

    selection.add_argument(
        "--limit",
        type=int,
        help="Evaluate at most N samples.",
    )

    sp.add_argument(
        "--offset",
        type=int,
        default=0,
        help="Skip the first N samples before evaluation.",
    )

    sp.add_argument(
        "--pair-metric",
        action="store_true",
        help=(
            "Also compute pair-level accuracy, where both sides of "
            "a pair must be correct."
        ),
    )

    sp.add_argument(
        "--resume",
        action="store_true",
        help="Skip samples already present in the cache directory.",
    )

    sp.add_argument(
        "--cache-dir",
        type=Path,
        default=None,
        help="Directory used for per-sample result caching.",
    )

    sp.add_argument(
        "--no-cache",
        action="store_true",
        help="Disable result caching.",
    )

    sp.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Seed for stochastic components.",
    )

    _add_output_args(sp)

    sp.set_defaults(handler=_handle_evaluate)


def _add_run_parser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Add the generic pipeline execution command."""
    sp = subparsers.add_parser(
        "run",
        help="Run the pipeline up to a selected stage.",
    )

    _add_config_arg(sp)
    _add_input_source_args(sp)

    sp.add_argument(
        "--until-stage",
        choices=_stage_choices(),
        default=Stage.ADJUDICATION.value,
        help=(
            "Run the pipeline up to and including this stage "
            "(default: full pipeline)."
        ),
    )

    _add_output_args(sp)

    sp.set_defaults(handler=_handle_run)


def _add_agent_parser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Add the local semantic agent command."""
    sp = subparsers.add_parser(
        "agent",
        help="Run local semantic agents over brain_context artifacts.",
    )

    _add_config_arg(sp)

    sp.add_argument(
        "--agent",
        choices=[*SEMANTIC_AGENTS, "all", "merge"],
        default="state",
        help="Agent to run (default: state).",
    )

    sp.add_argument(
        "--brain-context-dir",
        type=Path,
        default=Path("brain_context"),
        help="Root brain_context directory.",
    )

    sp.add_argument(
        "--dataset",
        type=str,
        required=True,
        help="Dataset name under brain_context.",
    )

    sp.add_argument(
        "--split",
        type=str,
        required=True,
        help="Dataset split under brain_context.",
    )

    sp.add_argument(
        "--sample",
        type=str,
        help="Run one sample id only.",
    )

    sp.add_argument(
        "--limit",
        type=int,
        help="Run at most N samples from the manifest.",
    )

    sp.add_argument(
        "--force",
        action="store_true",
        help="Ignore cached agent output and rerun.",
    )

    sp.add_argument(
        "--parallel",
        action="store_true",
        help="Run all four semantic agents concurrently with progress.",
    )

    sp.add_argument(
        "--llm",
        action="store_true",
        help=(
            "Call the configured LLM API for interpretation output. "
            "Without this flag, agents use local deterministic fallback."
        ),
    )

    sp.add_argument(
        "--llm-config",
        type=Path,
        default=Path("configs") / "agent_llm.yaml",
        help="YAML config for semantic-agent LLM API settings.",
    )

    sp.add_argument(
        "--experiments-dir",
        type=Path,
        default=Path("experiments"),
        help="Directory for per-sample agent outputs.",
    )

    _add_output_args(sp)

    sp.set_defaults(handler=_handle_agent)


def _add_doctor_parser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Add the environment diagnostic command."""
    sp = subparsers.add_parser(
        "doctor",
        help="Check external tool availability.",
    )

    _add_config_arg(sp)

    sp.set_defaults(handler=_handle_doctor)
    sp.add_argument("--repository-context", action="store_true",
                    help="Also check Git and Joern executables")


def _add_version_parser(
    subparsers: argparse._SubParsersAction,
) -> None:
    """Add the version command."""
    sp = subparsers.add_parser(
        "version",
        help="Print the VulSOR version.",
    )

    sp.set_defaults(handler=_handle_version)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------


def _validate_input_source_args(args: argparse.Namespace) -> None:
    """Validate file-vs-dataset argument combinations.

    Rules:
    - --file cannot be combined with --split or --sample;
    - --dataset requires --split;
    - --dataset may optionally specify --sample.
    """
    if args.file is not None:
        if args.split is not None:
            raise SystemExit(
                "error: --split cannot be used with --file"
            )

        if args.sample is not None:
            raise SystemExit(
                "error: --sample cannot be used with --file"
            )

        if getattr(args, "limit", None) is not None:
            raise SystemExit(
                "error: --limit cannot be used with --file"
            )

        if getattr(args, "offset", 0) != 0:
            raise SystemExit(
                "error: --offset cannot be used with --file"
            )

        if getattr(args, "all", False):
            raise SystemExit(
                "error: --all cannot be used with --file"
            )

        if getattr(args, "random", None) is not None:
            raise SystemExit(
                "error: --random cannot be used with --file"
            )

        if getattr(args, "seed", None) is not None:
            raise SystemExit(
                "error: --seed cannot be used with --file"
            )

        return

    # The mutually exclusive group guarantees that dataset is present
    # when file is absent, but keep the validation explicit.
    if args.dataset is None:
        raise SystemExit(
            "error: either --file or --dataset is required"
        )

    if args.split is None:
        raise SystemExit(
            "error: --split is required when --dataset is used"
        )


def _validate_inspect_args(args: argparse.Namespace) -> None:
    """Validate inspect-specific dataset selection arguments."""
    _validate_input_source_args(args)

    if args.limit is not None and args.limit < 1:
        raise SystemExit(
            "error: --limit must be >= 1"
        )

    if args.random is not None and args.random < 1:
        raise SystemExit(
            "error: --random must be >= 1"
        )

    if args.jobs < 1:
        raise SystemExit(
            "error: --jobs must be >= 1"
        )

    if args.offset < 0:
        raise SystemExit(
            "error: --offset must be >= 0"
        )

    selected_modes = [
        args.sample is not None,
        args.limit is not None,
        args.all,
        args.random is not None,
    ]

    if sum(selected_modes) > 1:
        raise SystemExit(
            "error: choose only one of --sample, --limit, --all, --random"
        )

    if args.offset != 0 and (
        args.sample is not None
        or args.all
        or args.random is not None
    ):
        raise SystemExit(
            "error: --offset can only be used with --limit"
        )

    if args.seed is not None and args.random is None:
        raise SystemExit(
            "error: --seed requires --random"
        )


def _validate_evaluate_args(args: argparse.Namespace) -> None:
    """Validate evaluation-specific selection arguments."""
    if args.limit is not None and args.limit < 1:
        raise SystemExit(
            "error: --limit must be >= 1"
        )

    if args.offset < 0:
        raise SystemExit(
            "error: --offset must be >= 0"
        )

    if args.sample is not None and args.offset != 0:
        raise SystemExit(
            "error: --offset cannot be used with --sample"
        )

    if args.resume and args.no_cache:
        raise SystemExit(
            "error: --resume cannot be used with --no-cache"
        )

    if args.resume and args.cache_dir is None:
        raise SystemExit(
            "error: --resume requires --cache-dir"
        )


# ---------------------------------------------------------------------------
# Dispatch helpers
# ---------------------------------------------------------------------------


def _not_implemented(command: str) -> int:
    """Return the current expected status for an unimplemented workflow."""
    print(
        f"{command}: not implemented yet. "
        "Program analysis is available; later stages are pending.",
        file=sys.stderr,
    )
    return 1


def _to_jsonable(value):
    """Convert pipeline dataclasses into JSON-serializable values."""
    if is_dataclass(value):
        return {
            key: _to_jsonable(item)
            for key, item in asdict(value).items()
        }

    if isinstance(value, dict):
        return {
            key: _to_jsonable(item)
            for key, item in value.items()
        }

    if isinstance(value, tuple):
        return [
            _to_jsonable(item)
            for item in value
        ]

    if isinstance(value, list):
        return [
            _to_jsonable(item)
            for item in value
        ]

    if isinstance(value, Stage):
        return value.value

    return value


def _emit_pipeline_result(
    result: PipelineResult,
    args: argparse.Namespace,
    *,
    detailed: bool = False,
    pretty: bool = False,
) -> int:
    """Emit a pipeline result as text or JSON."""
    if args.format == "json":
        output = json.dumps(
            _to_jsonable(result),
            indent=2,
        )
    else:
        facts = result.program_facts

        if facts is None:
            output = f"stage_reached: {result.stage_reached.value}"
        elif detailed:
            output = _format_program_facts_detail(result)
        else:
            output = _format_program_facts_summary(result)

    if args.output is not None:
        args.output.write_text(
            output + "\n",
            encoding="utf-8",
        )
    else:
        if args.format == "json" and (pretty or console.is_terminal):
            _render_json_output(output)
        elif detailed and (pretty or console.is_terminal):
            _render_program_facts_detail(result)
        else:
            print(output)

    return 0


def _emit_dataset_inspection(
    payload: dict,
    args: argparse.Namespace,
    *,
    pretty: bool = False,
) -> int:
    """Emit dataset inspection results."""
    if args.format == "json":
        output = json.dumps(
            _to_jsonable(payload),
            indent=2,
        )
    else:
        output = _format_dataset_inspection_text(payload)

    if args.output is not None:
        args.output.write_text(
            output + "\n",
            encoding="utf-8",
        )
    else:
        if args.format == "json" and (pretty or console.is_terminal):
            screen_output = json.dumps(
                _dataset_screen_state(payload),
                indent=2,
            )
            _render_json_output(screen_output)
            _render_dataset_issue_summary(payload)
        elif args.format == "text" and (pretty or console.is_terminal):
            print(output)
            console.print()
            _render_dataset_issue_summary(payload)
        else:
            print(output)

    return 0


def _format_dataset_inspection_text(payload: dict) -> str:
    """Return plain text dataset inspection output without Rich tables."""
    total = int(payload.get("count", len(payload.get("samples", ()))) or 0)
    counts = _sample_status_counts(payload)
    brain_context = payload.get("brain_context", {})
    lines = [
        f"dataset: {payload['dataset']}",
        f"split: {payload['split']}",
        f"samples: {total}",
    ]

    if brain_context:
        lines.append(
            "brain_context: "
            f"{brain_context.get('artifact_dir')} "
            f"({brain_context.get('count', 0)} samples)"
        )

    lines.extend(
        [
            "",
            "Summary:",
            f"- {_count_with_percent('complete', counts.get('ok', 0), total)}",
            f"- {_count_with_percent('partial', counts.get('partial', 0), total)}",
            f"- {_count_with_percent('stopped', counts.get('error', 0), total)}",
        ]
    )

    lines.extend(["", "Stage coverage:"])
    lines.extend(
        f"- {_count_with_percent(label, count, total)}"
        for label, count in _stage_coverage(payload)
    )
    lines.extend(["", "Samples:"])

    artifact_by_sample = _brain_context_artifact_map(payload)

    for index, sample in enumerate(payload.get("samples", ())):
        if index:
            lines.append("")

        sample_id = str(sample.get("sample_id", "-"))
        lines.extend(
            _format_dataset_sample_text(
                sample,
                artifact_path=artifact_by_sample.get(sample_id),
            )
        )

    return "\n".join(lines)


def _format_dataset_sample_text(
    sample: dict,
    *,
    artifact_path: str | None = None,
) -> list[str]:
    """Return detailed plain text for one dataset inspection sample."""
    row = {
        "sample_id": str(sample.get("sample_id", "-")),
        "status": str(sample.get("status", "unknown")),
        **_sample_stage_statuses(sample),
    }
    facts = _sample_program_facts(sample)
    analysis = sample.get("analysis", {})

    if not isinstance(analysis, dict):
        analysis = {}

    completeness = analysis.get("completeness", {})
    build_diagnosis = analysis.get("build_diagnosis", {})
    missing_summary = analysis.get("missing_context_summary", {})
    diagnostics = list(sample.get("diagnostics", ()))
    lines = [
        f"- {row['sample_id']} [{row['status']}]",
        "  table_row: "
        f"source={row['source']}, "
        f"ast={row['ast']}, "
        f"cfg={row['cfg']}, "
        f"data_flow={row['data_flow']}",
        "  stage_details:",
        f"  - source: {row['source']} (function snippet)",
        f"  - ast: {row['ast']}{_stage_reason_text(completeness, 'ast')}",
        f"  - cfg: {row['cfg']}{_stage_reason_text(completeness, 'cfg')}",
        (
            f"  - data_flow: {row['data_flow']}"
            f"{_stage_reason_text(completeness, 'data_flow')}"
        ),
        "  facts:",
        (
            "  - "
            f"functions={len(facts.get('functions', ()))}, "
            f"operations={len(facts.get('operations', ()))}, "
            f"cfg_blocks={len(facts.get('cfg_blocks', ()))}, "
            f"data_flow={len(facts.get('data_flow', ()))}, "
            f"call_graph={len(facts.get('call_graph', ()))}"
        ),
    ]

    if artifact_path:
        lines.insert(1, f"  artifact: {artifact_path}")

    if isinstance(missing_summary, dict) and missing_summary:
        lines.append(
            "  - missing_symbols: "
            f"unique={missing_summary.get('unique_symbols', 0)}, "
            f"occurrences={missing_summary.get('total_occurrences', 0)}, "
            f"by_kind={missing_summary.get('by_kind', {})}"
        )

    lines.extend(_format_build_diagnosis_text(build_diagnosis))

    if diagnostics:
        lines.append("  diagnostics:")
        lines.extend(
            f"  - {_short_error(str(diagnostic))}"
            for diagnostic in diagnostics[:5]
        )

        if len(diagnostics) > 5:
            lines.append(f"  - +{len(diagnostics) - 5} more")

    return lines


def _render_json_output(output: str) -> None:
    """Render JSON with syntax highlighting on the terminal."""
    console.print(
        Panel(
            JSON(output),
            title="JSON Output",
            border_style="#C084FC",
        )
    )


def _stage_reason_text(completeness: dict, key: str) -> str:
    """Return a readable reason for an analysis pass status."""
    reason = _pass_reason(completeness, key)

    if not reason:
        return ""

    return f" ({reason})"


def _pass_reason(completeness: dict, key: str) -> str:
    """Read an analysis-pass reason from dict or dataclass metadata."""
    if not isinstance(completeness, dict):
        return ""

    value = completeness.get(key)

    if isinstance(value, dict):
        return str(value.get("reason") or "")

    return str(getattr(value, "reason", "") or "")


def _format_build_diagnosis_text(build_diagnosis: dict) -> list[str]:
    """Return detailed build/root-cause diagnosis lines."""
    if not isinstance(build_diagnosis, dict):
        return []

    issues = build_diagnosis.get("issues", ())

    if not issues:
        return ["  root_causes: none"]

    lines = ["  root_causes:"]

    for issue in issues:
        if not isinstance(issue, dict):
            continue

        fixable = "yes" if issue.get("fixable") else "no"
        lines.append(
            "  - "
            f"{issue.get('component', 'unknown')}: "
            f"{issue.get('classification', 'unknown')} "
            f"(fixable={fixable}) - "
            f"{issue.get('message', '')}"
        )

    return lines


def _dataset_screen_state(payload: dict) -> dict:
    """Return compact per-sample state for interactive JSON output."""
    counts: dict[str, int] = {}

    for sample in payload["samples"]:
        status = str(sample.get("status", "unknown"))
        counts[status] = counts.get(status, 0) + 1

    artifact_by_sample = _brain_context_artifact_map(payload)
    samples = []

    for sample in payload["samples"]:
        sample_id = str(sample.get("sample_id", "-"))
        samples.append(
            {
                "sample_id": sample_id,
                "status": sample.get("status", "unknown"),
                "stages": _sample_stage_statuses(sample),
                "message": _analysis_message(sample),
                "issues": _sample_issue_objects(sample),
                "artifact_path": artifact_by_sample.get(sample_id),
            }
        )

    brain_context = payload.get("brain_context", {})

    return {
        "kind": "program_analysis_screen_state",
        "dataset": payload.get("dataset"),
        "split": payload.get("split"),
        "count": payload.get("count", len(samples)),
        "summary": {
            "ok": counts.get("ok", 0),
            "partial": counts.get("partial", 0),
            "error": counts.get("error", 0),
            "artifact_dir": brain_context.get("artifact_dir"),
            "manifest_path": brain_context.get("manifest_path"),
        },
        "samples": samples,
    }


def _brain_context_artifact_map(payload: dict) -> dict[str, str]:
    """Map sample ids to per-sample artifact paths from brain_context."""
    brain_context = payload.get("brain_context", {})
    artifact_dir = brain_context.get("artifact_dir")

    if not artifact_dir:
        return {}

    return {
        str(sample.get("sample_id", "-")): str(
            Path(artifact_dir) / f"{_safe_artifact_name(str(sample.get('sample_id', '-')))}.json"
        )
        for sample in payload.get("samples", ())
    }


def _render_dataset_inspection(
    payload: dict,
    json_output: str | None,
) -> None:
    """Render compact dataset inspection progress with Rich tables."""
    table = Table(
        title=(
            f"Program Analysis: "
            f"{payload['dataset']} / {payload['split']}"
        ),
        show_lines=True,
    )
    table.add_column("Sample", style="bold")
    table.add_column("Status")
    table.add_column("Source")
    table.add_column("AST")
    table.add_column("CFG")
    table.add_column("Data Flow")
    table.add_column("Message")

    for sample in payload["samples"]:
        stages = _sample_stage_statuses(sample)
        table.add_row(
            sample["sample_id"],
            _status_markup(sample["status"]),
            _status_markup(stages["source"]),
            _status_markup(stages["ast"]),
            _status_markup(stages["cfg"]),
            _status_markup(stages["data_flow"]),
            _analysis_message(sample),
        )

    console.print(table)
    _render_dataset_issue_summary(payload)

    if json_output is not None:
        _render_json_output(json_output)


def _sample_stage_statuses(sample: dict) -> dict[str, str]:
    """Return per-stage status labels for one inspected sample."""
    if sample.get("status") == "error":
        return {
            "source": "error",
            "ast": "skip",
            "cfg": "skip",
            "data_flow": "skip",
        }

    analysis = sample.get("analysis", {})
    completeness = analysis.get("completeness", {})

    return {
        "source": "available",
        "ast": _pass_status(completeness, "ast"),
        "cfg": _pass_status(completeness, "cfg"),
        "data_flow": _pass_status(completeness, "data_flow"),
    }


def _pass_status(completeness: dict, key: str) -> str:
    """Read an analysis-pass status from dict or dataclass metadata."""
    if not isinstance(completeness, dict):
        return "missing"

    value = completeness.get(key)

    if isinstance(value, dict):
        return str(value.get("status") or "missing")

    return str(getattr(value, "status", "missing") or "missing")


def _status_markup(status: str) -> str:
    """Color a compact status label for Rich tables."""
    if status in {"ok", "available"}:
        return f"[green]{status}[/green]"

    if status in {"partial", "limited", "recovered", "empty"}:
        return f"[yellow]{status}[/yellow]"

    if status in {"error", "failed", "missing"}:
        return f"[red]{status}[/red]"

    if status in {"skip", "disabled", "not_requested"}:
        return f"[dim]{status}[/dim]"

    return status


def _summary_ratio_text(label: str, count: int, total: int) -> str:
    """Return a readable ratio for the interactive summary panel."""
    if total <= 0:
        percent = "0.0%"
    else:
        percent = f"{count / total * 100:.1f}%"

    return f"{label}: {count}/{total} ({percent})"


def _summary_metric_lines(
    title: str,
    metrics: Sequence[tuple[str, int]],
    total: int,
) -> list[str]:
    """Return a headed metric block for the interactive summary panel."""
    lines = [title]
    lines.extend(
        f"  - {_summary_ratio_text(label, count, total)}"
        for label, count in metrics
    )
    return lines


def _render_dataset_issue_summary(payload: dict) -> None:
    """Render compact aggregate status and issue details below the table."""
    counts = _sample_status_counts(payload)
    brain_context = payload.get("brain_context", {})
    total = int(payload.get("count", len(payload.get("samples", ()))) or 0)
    summary_lines = [
        f"Analyzed: {total} samples",
        "",
        "Result status",
        f"  - {_summary_ratio_text('complete', counts.get('ok', 0), total)}",
        f"  - {_summary_ratio_text('partial', counts.get('partial', 0), total)}",
        f"  - {_summary_ratio_text('stopped', counts.get('error', 0), total)}",
    ]
    stage_coverage = _stage_coverage(payload)

    if stage_coverage:
        summary_lines.extend(
            [
                "",
                *_summary_metric_lines(
                    "Stage coverage - selected samples",
                    stage_coverage,
                    total,
                ),
            ]
        )

    if brain_context:
        summary_lines.extend(
            [
                "",
                f"Brain context: {brain_context.get('artifact_dir')}",
            ]
        )

    console.print(
        Panel(
            "\n".join(summary_lines),
            title="Summary",
            border_style="#C084FC",
        )
    )

    stage_summaries = _dataset_stage_summary_rows(payload)

    if not stage_summaries:
        return

    issue_table = Table(title="Stage Summary", show_lines=True)
    issue_table.add_column("Sample", style="bold", no_wrap=True)
    issue_table.add_column("Source")
    issue_table.add_column("AST")
    issue_table.add_column("CFG")
    issue_table.add_column("Data Flow")

    for row in stage_summaries:
        issue_table.add_row(
            row["sample_id"],
            _status_markup(row["source"]),
            _status_markup(row["ast"]),
            _status_markup(row["cfg"]),
            _status_markup(row["data_flow"]),
        )

    console.print(issue_table)


def _dataset_stage_summary_rows(payload: dict) -> list[dict[str, str]]:
    """Collect one readable stage summary row per sample."""
    rows: list[dict[str, str]] = []

    for sample in payload["samples"]:
        row = {
            "sample_id": str(sample.get("sample_id", "-")),
            "status": str(sample.get("status", "unknown")),
            **_sample_stage_statuses(sample),
        }
        rows.append(row)

    return rows


def _sample_status_counts(payload: dict) -> dict[str, int]:
    """Return counts by sample status."""
    counts: dict[str, int] = {}

    for sample in payload.get("samples", ()):
        status = str(sample.get("status", "unknown"))
        counts[status] = counts.get(status, 0) + 1

    return counts


def _count_with_percent(label: str, count: int, total: int) -> str:
    """Return a compact count plus percentage label."""
    percent = 0.0

    if total:
        percent = count * 100 / total

    return f"{label} {count} ({percent:.1f}%)"


def _stage_coverage(payload: dict) -> list[tuple[str, int]]:
    """Return aggregate stage coverage for inspected samples."""
    counts = {
        "source": 0,
        "ast": 0,
        "cfg": 0,
        "data_flow": 0,
    }

    for sample in payload.get("samples", ()):
        statuses = _sample_stage_statuses(sample)

        for stage, status in statuses.items():
            if _stage_counts_as_available(status):
                counts[stage] += 1

    return list(counts.items())


def _stage_counts_as_available(status: str) -> bool:
    """Return true when a stage produced usable facts."""
    return status in {"available", "limited", "recovered", "partial", "empty"}


def _sample_program_facts(sample: dict) -> dict:
    """Return the program_facts dict from a sample payload."""
    result = sample.get("result", {})

    if isinstance(result, dict):
        facts = result.get("program_facts", {})
    else:
        facts = getattr(result, "program_facts", None)

    if facts is None:
        return {}

    if not isinstance(facts, dict):
        return {
            "functions": getattr(facts, "functions", ()),
            "operations": getattr(facts, "operations", ()),
            "cfg_blocks": getattr(facts, "cfg_blocks", ()),
            "data_flow": getattr(facts, "data_flow", ()),
            "call_graph": getattr(facts, "call_graph", ()),
        }

    return facts


def _dataset_issue_rows(payload: dict) -> list[tuple[str, str, str]]:
    """Collect concise per-sample issue rows for terminal display."""
    rows: list[tuple[str, str, str]] = []

    for sample in payload["samples"]:
        sample_id = str(sample.get("sample_id", "-"))

        if sample.get("status") == "error":
            rows.append(
                (
                    sample_id,
                    "error",
                    _short_error(str(sample.get("error", ""))),
                )
            )
            continue

        analysis = sample.get("analysis", {})
        diagnostics = list(sample.get("diagnostics", ()))

        for diagnostic in diagnostics[:2]:
            rows.append(
                (
                    sample_id,
                    "diagnostic",
                    _short_error(str(diagnostic)),
                )
            )

        missing_context = list(analysis.get("missing_context", ()))

        if missing_context:
            rows.append(
                (
                    sample_id,
                    "missing_context",
                    _missing_context_issue_text(missing_context),
                )
            )

        limitations = list(analysis.get("limitations", ()))

        if limitations:
            rows.append(
                (
                    sample_id,
                    "limitation",
                    _short_error("; ".join(str(item) for item in limitations[:2])),
                )
            )

    return rows


def _sample_issue_objects(sample: dict) -> list[dict[str, str]]:
    """Collect concise issue objects for interactive JSON output."""
    issues: list[dict[str, str]] = []

    if sample.get("status") == "error":
        return [
            {
                "type": "error",
                "detail": _short_error(str(sample.get("error", ""))),
            }
        ]

    analysis = sample.get("analysis", {})

    for diagnostic in list(sample.get("diagnostics", ()))[:2]:
        issues.append(
            {
                "type": "diagnostic",
                "detail": _short_error(str(diagnostic)),
            }
        )

    missing_context = list(analysis.get("missing_context", ()))

    if missing_context:
        issues.append(
            {
                "type": "missing_context",
                "detail": _missing_context_issue_text(missing_context),
            }
        )

    limitations = list(analysis.get("limitations", ()))

    if limitations:
        issues.append(
            {
                "type": "limitation",
                "detail": _short_error(
                    "; ".join(str(item) for item in limitations[:2])
                ),
            }
        )

    return issues


def _missing_context_issue_text(items: list) -> str:
    """Summarize missing-context entries without dumping the full payload."""
    details = []

    for item in items[:5]:
        if isinstance(item, dict):
            kind = item.get("kind", "missing_context")
            symbol = item.get("symbol", "unknown")
        else:
            kind = getattr(item, "kind", "missing_context")
            symbol = getattr(item, "symbol", "unknown")

        details.append(f"{kind}: {symbol}")

    suffix = ""

    if len(items) > len(details):
        suffix = f"; +{len(items) - len(details)} more"

    return _short_error("; ".join(details) + suffix)


def _render_program_facts_detail(result: PipelineResult) -> None:
    """Render detailed program facts with Rich tables."""
    facts = result.program_facts

    if facts is None:
        console.print(f"stage_reached: {result.stage_reached.value}")
        return

    console.print(
        Panel(
            _format_program_facts_summary(result),
            title="Program Analysis",
            border_style="#C084FC",
        )
    )

    functions = Table(title="Functions")
    functions.add_column("Name", style="bold")
    functions.add_column("ID")
    functions.add_column("Lines")

    for function in facts.functions:
        functions.add_row(
            function.name,
            function.id,
            f"{function.start_line}-{function.end_line}",
        )

    console.print(functions)

    operations = Table(title="Operations")
    operations.add_column("Kind")
    operations.add_column("Name", style="bold")
    operations.add_column("Location")
    operations.add_column("Arguments")

    for operation in facts.operations:
        operations.add_row(
            operation.kind,
            operation.name,
            f"{operation.line}:{operation.column}",
            ", ".join(operation.arguments),
        )

    console.print(operations)

    control_flow = Table(title="Control Flow")
    control_flow.add_column("Source")
    control_flow.add_column("Target")
    control_flow.add_column("Condition")

    for edge in facts.control_flow:
        control_flow.add_row(
            edge.source,
            edge.target,
            edge.condition or "unconditional",
        )

    console.print(control_flow)

    data_flow = Table(title="Data Flow")
    data_flow.add_column("Variable", style="bold")
    data_flow.add_column("Definition")
    data_flow.add_column("Use")
    data_flow.add_column("Relation")

    for flow in facts.data_flow:
        data_flow.add_row(
            flow.variable,
            f"{flow.definition_line}:{flow.definition_column}",
            f"{flow.use_line}:{flow.use_column}",
            flow.relation,
        )

    console.print(data_flow)

    call_graph = Table(title="Call Graph")
    call_graph.add_column("Caller")
    call_graph.add_column("Callee")
    call_graph.add_column("Location")

    for edge in facts.call_graph:
        call_graph.add_row(
            edge.caller,
            edge.callee,
            f"{edge.line}:{edge.column}",
        )

    console.print(call_graph)


def _short_error(error: str, limit: int = 180) -> str:
    """Return a compact one-line error for table display."""
    first_line = error.splitlines()[0] if error else ""

    if len(first_line) <= limit:
        return first_line

    return first_line[: limit - 3] + "..."


def _diagnostic_summary(diagnostic: str) -> str:
    """Summarize Clang diagnostics for dataset JSON/table output."""
    error_count = diagnostic.count(" error:")
    warning_count = diagnostic.count(" warning:")

    parts = []

    if error_count:
        parts.append(f"{error_count} clang errors")

    if warning_count:
        parts.append(f"{warning_count} clang warnings")

    if parts:
        return ", ".join(parts)

    return _short_error(diagnostic)


def _analysis_metadata(
    analysis: ProgramAnalysisResult,
) -> dict:
    """Return explicit scope, completeness, and methodology metadata."""
    return {
        "scope": analysis.scope,
        "context_mode": analysis.context_mode,
        "complete": analysis.complete,
        "completeness": analysis.completeness or {},
        "build_diagnosis": _build_diagnosis(analysis),
        "missing_context_summary": _missing_context_summary(analysis),
        "missing_context": analysis.missing_context,
        "recovery_assumptions": analysis.recovery_assumptions,
        "links": analysis.links,
        "limitations": analysis.limitations,
        "rules": PROGRAM_ANALYSIS_RULES,
}


def _build_diagnosis(
    analysis: ProgramAnalysisResult,
) -> dict:
    """Classify fixable analysis failures without guessing facts."""
    issues: list[dict] = []

    if not analysis.cfg_available:
        issues.append(
            {
                "component": "cfg",
                "classification": "function_analysis_cfg_missing",
                "fixable": True,
                "message": (
                    "CFG is missing for the function snippet; inspect Clang "
                    "diagnostics, source syntax, or local toolchain handling"
                ),
            }
        )

    data_flow_status = (
        analysis.completeness.get("data_flow")
        if analysis.completeness
        else None
    )

    if data_flow_status and data_flow_status.status == "limited":
        issues.append(
            {
                "component": "data_flow",
                "classification": "recovered_ast_limited",
                "fixable": False,
                "message": (
                    "data-flow was built only from recovered AST facts; "
                    "better compile context may expose additional "
                    "definitions and uses"
                ),
            }
        )

    if analysis.recovered_ast:
        issues.append(
            {
                "component": "ast_and_calls",
                "classification": "recovered_partial",
                "fixable": True,
                "message": (
                    "AST/call facts were recovered despite diagnostics; "
                    "supplying missing headers, typedefs, macros, and "
                    "build flags can make them more complete"
                ),
            }
        )

    if not issues:
        return {
            "status": "complete",
            "issues": [],
        }

    return {
        "status": "partial",
        "issues": issues,
    }


def _analyze_dataset_sample(
    *,
    sample,
    clang_executable: str,
) -> ProgramAnalysisResult:
    """Analyze one dataset sample using only its target function snippet."""
    return analyze_source_code_tolerant(
        source_code=sample.code,
        clang_executable=clang_executable,
        scope="function",
    )


def _write_brain_context_artifacts(
    payload: dict,
    output_root: Path,
) -> dict:
    """Write per-sample Program Analysis artifacts for later stages."""
    dataset = str(payload["dataset"])
    split = str(payload["split"])
    artifact_dir = output_root / dataset / split
    artifact_dir.mkdir(parents=True, exist_ok=True)

    manifest_samples = []

    for sample in payload["samples"]:
        sample_id = str(sample["sample_id"])
        artifact_file = artifact_dir / f"{_safe_artifact_name(sample_id)}.json"
        artifact = {
            "schema_version": 1,
            "artifact_kind": "program_analysis",
            "dataset": dataset,
            "split": split,
            "sample_id": sample_id,
            "sample": sample,
        }
        artifact_file.write_text(
            json.dumps(
                _to_jsonable(artifact),
                indent=2,
            )
            + "\n",
            encoding="utf-8",
        )
        manifest_samples.append(
            {
                "sample_id": sample_id,
                "status": sample.get("status"),
                "path": str(artifact_file),
            }
        )

    manifest = {
        "schema_version": 1,
        "artifact_kind": "program_analysis_manifest",
        "dataset": dataset,
        "split": split,
        "count": len(manifest_samples),
        "artifact_dir": str(artifact_dir),
        "samples": manifest_samples,
    }
    manifest_file = artifact_dir / "manifest.json"
    manifest_file.write_text(
        json.dumps(
            manifest,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )

    return {
        "artifact_dir": str(artifact_dir),
        "manifest_path": str(manifest_file),
        "count": len(manifest_samples),
    }


def _safe_artifact_name(value: str) -> str:
    """Return a filesystem-safe artifact filename stem."""
    safe = [
        character
        if character.isalnum() or character in {"-", "_", "."}
        else "_"
        for character in value
    ]
    name = "".join(safe).strip("._")

    return name or "sample"


def _missing_context_summary(
    analysis: ProgramAnalysisResult,
) -> dict:
    """Summarize missing context without hiding the detailed facts."""
    by_kind: dict[str, int] = {}
    total_occurrences = 0

    for item in analysis.missing_context:
        by_kind[item.kind] = by_kind.get(item.kind, 0) + 1
        total_occurrences += item.occurrences

    return {
        "unique_symbols": len(analysis.missing_context),
        "total_occurrences": total_occurrences,
        "by_kind": by_kind,
    }


def _analysis_message(sample: dict) -> str:
    """Create a compact table message from limitations and diagnostics."""
    if sample.get("status") == "error":
        return _short_error(str(sample.get("error", "")))

    analysis = sample.get("analysis", {})
    diagnostics = list(sample.get("diagnostics", ()))
    missing_context = list(analysis.get("missing_context", ()))
    limitations = list(analysis.get("limitations", ()))

    if missing_context:
        messages = [
            (
                f"{item.get('kind', 'missing_context')}: "
                f"{item.get('symbol', 'unknown')}"
            )
            if isinstance(item, dict)
            else f"{item.kind}: {item.symbol}"
            for item in missing_context[:3]
        ]
    else:
        messages = diagnostics or limitations

    if not messages:
        return "ok"

    return _short_error("; ".join(messages))


def _analysis_diagnostics(
    analysis: ProgramAnalysisResult,
) -> tuple[str, ...]:
    """Create compact user-facing diagnostics for a recovered analysis."""
    diagnostics: list[str] = []

    if analysis.recovered_ast:
        diagnostics.append("AST recovered from Clang errors")

    if not analysis.cfg_available:
        diagnostics.append("CFG unavailable")

    error_count = max(
        (
            diagnostic.count(" error:")
            for diagnostic in analysis.diagnostics
        ),
        default=0,
    )

    if error_count:
        diagnostics.append(f"{error_count} clang errors")

    return tuple(diagnostics)


def _format_program_facts_summary(result: PipelineResult) -> str:
    """Return a compact text summary for pipeline output."""
    facts = result.program_facts

    if facts is None:
        return f"stage_reached: {result.stage_reached.value}"

    return "\n".join(
        [
            f"stage_reached: {result.stage_reached.value}",
            f"functions: {len(facts.functions)}",
            f"operations: {len(facts.operations)}",
            f"cfg_blocks: {len(facts.cfg_blocks)}",
            f"control_flow_edges: {len(facts.control_flow)}",
            f"definitions: {len(facts.definitions)}",
            f"uses: {len(facts.uses)}",
            f"data_flow: {len(facts.data_flow)}",
            f"call_graph: {len(facts.call_graph)}",
        ]
    )


def _format_program_facts_detail(result: PipelineResult) -> str:
    """Return readable program facts for inspect output."""
    facts = result.program_facts

    if facts is None:
        return f"stage_reached: {result.stage_reached.value}"

    lines = [
        _format_program_facts_summary(result),
        "",
        "Functions:",
    ]

    for function in facts.functions:
        lines.append(
            f"- {function.name} "
            f"({function.id}) "
            f"lines {function.start_line}-{function.end_line}"
        )

    lines.append("")
    lines.append("Operations:")

    for operation in facts.operations:
        arguments = ", ".join(operation.arguments)
        lines.append(
            f"- {operation.kind} {operation.name}({arguments}) "
            f"at {operation.line}:{operation.column} "
            f"[{operation.id}]"
        )

    lines.append("")
    lines.append("CFG Blocks:")

    for block in facts.cfg_blocks:
        statement_count = len(block.statements)
        lines.append(
            f"- {block.id}: {statement_count} statements"
        )

        for statement in block.statements:
            lines.append(f"  {statement}")

    lines.append("")
    lines.append("Control Flow:")

    for edge in facts.control_flow:
        condition = edge.condition or "unconditional"
        lines.append(
            f"- {edge.source} -> {edge.target} [{condition}]"
        )

    lines.append("")
    lines.append("Definitions:")

    for definition in facts.definitions:
        lines.append(
            f"- {definition.variable} "
            f"at {definition.line}:{definition.column} "
            f"[{definition.ast_node_id}]"
        )

    lines.append("")
    lines.append("Uses:")

    for use in facts.uses:
        lines.append(
            f"- {use.variable} "
            f"at {use.line}:{use.column} "
            f"[{use.ast_node_id}]"
        )

    lines.append("")
    lines.append("Data Flow:")

    for flow in facts.data_flow:
        lines.append(
            f"- {flow.variable}: "
            f"{flow.definition_line}:{flow.definition_column} -> "
            f"{flow.use_line}:{flow.use_column} "
            f"({flow.relation})"
        )

    lines.append("")
    lines.append("Call Graph:")

    for edge in facts.call_graph:
        lines.append(
            f"- {edge.caller} -> {edge.callee} "
            f"at {edge.line}:{edge.column} "
            f"[{edge.operation_id}]"
        )

    return "\n".join(lines)


@contextmanager
def _dataset_progress(total: int, *, enabled: bool):
    """Create a terminal-only progress bar for dataset inspection."""
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=False,
        disable=not enabled,
    )

    with progress:
        task_id = progress.add_task(
            "Inspect dataset samples",
            total=total,
        )
        yield {
            "progress": progress,
            "task_id": task_id,
        }


def _update_dataset_progress(
    progress: Progress,
    task_id,
    sample_id: str,
    index: int,
    total: int,
    stage: str,
) -> None:
    """Update the dataset inspection progress label."""
    progress.update(
        task_id,
        description=(
            f"[{index}/{total}] {sample_id} - {stage}"
        ),
    )


def _inspect_dataset_sample(
    *,
    sample,
    config: VulSORConfig,
) -> dict:
    """Inspect one dataset sample and return its payload entry."""
    try:
        analysis = _analyze_dataset_sample(
            sample=sample,
            clang_executable=config.tools.clang,
        )
    except Exception as exc:
        return {
            "sample_id": sample.sample_id,
            "status": "error",
            "error": str(exc),
        }

    return {
        "sample_id": sample.sample_id,
        "status": "ok" if analysis.complete else "partial",
        "result": PipelineResult(
            stage_reached=Stage.PROGRAM_ANALYSIS,
            program_facts=analysis.facts,
        ),
        "analysis": _analysis_metadata(analysis),
        "diagnostics": _analysis_diagnostics(analysis),
    }


def _inspect_dataset_samples(
    *,
    samples: list,
    config: VulSORConfig,
    jobs: int,
) -> list[dict]:
    """Inspect dataset samples sequentially or concurrently."""
    if not samples:
        return []

    if jobs == 1:
        return _inspect_dataset_samples_sequential(
            samples=samples,
            config=config,
        )

    return _inspect_dataset_samples_parallel(
        samples=samples,
        config=config,
        jobs=jobs,
    )


def _inspect_dataset_samples_sequential(
    *,
    samples: list,
    config: VulSORConfig,
) -> list[dict]:
    """Inspect samples one by one with stage-level progress labels."""
    inspected = []

    with _dataset_progress(
        total=len(samples),
        enabled=console.is_terminal,
    ) as progress_state:
        progress = progress_state["progress"]
        task_id = progress_state["task_id"]

        for index, sample in enumerate(samples, start=1):
            _update_dataset_progress(
                progress,
                task_id,
                sample.sample_id,
                index,
                len(samples),
                "program analysis",
            )

            inspected.append(
                _inspect_dataset_sample(
                    sample=sample,
                    config=config,
                )
            )
            progress.advance(task_id)

        _update_dataset_progress(
            progress,
            task_id,
            "-",
            len(samples),
            len(samples),
            "write brain_context",
        )

    return inspected


def _inspect_dataset_samples_parallel(
    *,
    samples: list,
    config: VulSORConfig,
    jobs: int,
) -> list[dict]:
    """Inspect samples concurrently while preserving output order."""
    results: list[dict | None] = [None] * len(samples)
    max_workers = min(jobs, len(samples))

    with _dataset_progress(
        total=len(samples),
        enabled=console.is_terminal,
    ) as progress_state:
        progress = progress_state["progress"]
        task_id = progress_state["task_id"]

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_index = {
                executor.submit(
                    _inspect_dataset_sample,
                    sample=sample,
                    config=config,
                ): index
                for index, sample in enumerate(samples)
            }

            for completed, future in enumerate(
                as_completed(future_to_index),
                start=1,
            ):
                index = future_to_index[future]
                sample = samples[index]
                _update_dataset_progress(
                    progress,
                    task_id,
                    sample.sample_id,
                    completed,
                    len(samples),
                    "complete",
                )
                results[index] = future.result()
                progress.advance(task_id)

        _update_dataset_progress(
            progress,
            task_id,
            "-",
            len(samples),
            len(samples),
            "write brain_context",
        )

    return [
        result
        for result in results
        if result is not None
    ]


def _handle_inspect(
    args: argparse.Namespace,
    config: VulSORConfig,
) -> int:
    """Dispatch inspect after CLI validation."""
    _validate_inspect_args(args)

    if args.file is None:
        samples = []
        limit = args.limit

        if (
            args.sample is None
            and not args.all
            and args.random is None
            and limit is None
        ):
            limit = 1

        selected_samples = list(
            iter_dataset_samples(
                config,
                args.dataset,
                args.split,
                sample_id=args.sample,
                limit=limit,
                offset=args.offset,
                random_count=args.random,
                random_seed=args.seed,
            )
        )

        samples = _inspect_dataset_samples(
            samples=selected_samples,
            config=config,
            jobs=args.jobs,
        )

        payload = {
            "dataset": args.dataset,
            "split": args.split,
            "count": len(samples),
            "samples": samples,
        }
        payload["brain_context"] = _write_brain_context_artifacts(
            payload,
            args.brain_context_dir,
        )

        return _emit_dataset_inspection(
            payload,
            args,
            pretty=getattr(args, "pretty", False),
        )

    source_code = args.file.read_text(encoding="utf-8")

    result = run_pipeline(
        source_code=source_code,
        config=config,
        until_stage=Stage.PROGRAM_ANALYSIS,
    )

    return _emit_pipeline_result(
        result,
        args,
        detailed=True,
        pretty=getattr(args, "pretty", False),
    )


def _handle_detect(
    args: argparse.Namespace,
    config: VulSORConfig,
) -> int:
    """Dispatch detect after CLI validation."""
    _validate_input_source_args(args)

    # B0 only establishes the CLI contract.
    return _not_implemented("detect")


def _handle_evaluate(
    args: argparse.Namespace,
    config: VulSORConfig,
) -> int:
    """Dispatch evaluation after CLI validation."""
    _validate_evaluate_args(args)

    # Dataset loading/evaluation is intentionally not implemented here.
    return _not_implemented("evaluate")


def _handle_run(
    args: argparse.Namespace,
    config: VulSORConfig,
) -> int:
    """Dispatch generic pipeline execution."""
    _validate_input_source_args(args)

    stage = Stage(args.until_stage)

    if args.file is None:
        return _not_implemented("run dataset input")

    source_code = args.file.read_text(encoding="utf-8")

    result = run_pipeline(
        source_code=source_code,
        config=config,
        until_stage=stage,
    )

    return _emit_pipeline_result(
        result,
        args,
        pretty=getattr(args, "pretty", False),
    )


def _handle_agent(
    args: argparse.Namespace,
    config: VulSORConfig,
) -> int:
    """Run a local semantic agent over B1 brain_context artifacts."""
    if args.limit is not None and args.limit < 1:
        raise SystemExit("error: --limit must be >= 1")

    manifest_path = (
        args.brain_context_dir
        / args.dataset
        / args.split
        / "manifest.json"
    )

    if not manifest_path.is_file():
        raise SystemExit(
            f"error: manifest not found: {manifest_path}"
        )

    llm_config = load_llm_config(args.llm_config) if args.llm else None

    if args.agent == "all":
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        selected_samples = [
            item
            for item in manifest.get("samples", [])
            if isinstance(item, dict)
        ]
        if args.sample is not None:
            selected_samples = [
                item
                for item in selected_samples
                if item.get("sample_id") == args.sample
            ]
        if args.limit is not None:
            selected_samples = selected_samples[:args.limit]

        progress = None
        progress_task = None
        progress_callback = None
        if args.parallel:
            progress = Progress(
                SpinnerColumn(),
                TextColumn("{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=console,
                disable=not console.is_terminal,
            )
            progress_task = progress.add_task(
                "Running semantic agents",
                total=len(selected_samples) * len(SEMANTIC_AGENTS),
            )
            progress_callback = lambda _: progress.advance(progress_task)

        if progress is None:
            results = run_all_semantic_agents_for_manifest(
                manifest_path,
                brain_context_dir=args.brain_context_dir,
                sample_id=args.sample,
                limit=args.limit,
                force=args.force,
                use_llm=args.llm,
                llm_config=llm_config,
                experiments_dir=args.experiments_dir,
            )
        else:
            with progress:
                results = run_all_semantic_agents_for_manifest(
                    manifest_path,
                    brain_context_dir=args.brain_context_dir,
                    sample_id=args.sample,
                    limit=args.limit,
                    force=args.force,
                    use_llm=args.llm,
                    llm_config=llm_config,
                    experiments_dir=args.experiments_dir,
                    parallel=True,
                    progress_callback=progress_callback,
                )
        llm_errors = [
            result
            for result in results
            if result.status == "error"
        ]
        if args.llm and llm_errors:
            if not console.is_terminal:
                for result in llm_errors:
                    detail = f": {result.error}" if result.error else ""
                    print(
                        f"LLM agent failed for {result.sample_id}/"
                        f"{result.agent}{detail}",
                        file=sys.stderr,
                    )
        else:
            results.extend(
                run_semantic_merge_for_manifest(
                    manifest_path,
                    brain_context_dir=args.brain_context_dir,
                    sample_id=args.sample,
                    limit=args.limit,
                    force=args.force,
                    experiments_dir=args.experiments_dir,
                )
            )
    elif args.agent == "merge":
        results = run_semantic_merge_for_manifest(
            manifest_path,
            brain_context_dir=args.brain_context_dir,
            sample_id=args.sample,
            limit=args.limit,
            force=args.force,
            experiments_dir=args.experiments_dir,
        )
    else:
        results = run_semantic_agent_for_manifest(
            manifest_path,
            agent_name=args.agent,
            brain_context_dir=args.brain_context_dir,
            sample_id=args.sample,
            limit=args.limit,
            force=args.force,
            use_llm=args.llm,
            llm_config=llm_config,
            experiments_dir=args.experiments_dir,
        )

    payload = {
        "agent": args.agent,
        "llm_enabled": args.llm,
        "llm_error_policy": (
            "fail_explicitly_without_fallback"
            if args.llm
            else "not_applicable"
        ),
        "brain_context_dir": str(args.brain_context_dir),
        "dataset": args.dataset,
        "split": args.split,
        "count": len(results),
        "results": results,
    }
    exit_status = 1 if any(result.status == "error" for result in results) else 0

    if args.format == "json":
        output = json.dumps(
            _to_jsonable(payload),
            indent=2,
        )
    else:
        lines = [
            f"agent: {args.agent}",
            f"dataset: {args.dataset}",
            f"split: {args.split}",
            f"samples: {len(results)}",
        ]
        if args.llm:
            lines.append("llm_error_policy: fail explicitly, no local fallback")

        if args.agent == "all":
            results_by_sample = {}
            for result in results:
                results_by_sample.setdefault(result.sample_id, {})[
                    result.agent or "unknown"
                ] = result

            for sample in selected_samples:
                sample_id = str(sample.get("sample_id"))
                sample_results = results_by_sample.get(sample_id, {})
                agent_states = []

                for agent_name in SEMANTIC_AGENTS:
                    result = sample_results.get(agent_name)
                    if result is None:
                        agent_states.append("MISSING")
                        lines.append(f"  [ ] {agent_name}: MISSING")
                        continue

                    if result.status == "error":
                        detail = f" - {result.error}" if result.error else ""
                        lines.append(
                            f"  [!] {agent_name}: ERROR{detail}"
                        )
                        agent_states.append("ERROR")
                        continue

                    cache = "cache" if result.cache_hit else "run"
                    lines.append(
                        f"  [OK] {agent_name}: {cache} -> "
                        f"{result.experiment_path or result.output_path} "
                        f"(in={result.input_tokens}, "
                        f"out={result.output_tokens}, "
                        f"time={result.elapsed_seconds:.2f}s)"
                    )
                    agent_states.append("OK")

                overall = "OK" if all(state == "OK" for state in agent_states) else "ERROR"
                completed_results = [
                    sample_results[name]
                    for name in SEMANTIC_AGENTS
                    if name in sample_results
                ]
                input_tokens = sum(item.input_tokens for item in completed_results)
                output_tokens = sum(item.output_tokens for item in completed_results)
                elapsed_seconds = max(
                    (item.elapsed_seconds for item in completed_results),
                    default=0.0,
                )
                lines.insert(
                    len(lines) - len(agent_states),
                    f"{sample_id}: {overall} | "
                    f"input_tokens={input_tokens} "
                    f"output_tokens={output_tokens} "
                    f"elapsed={elapsed_seconds:.2f}s",
                )

            merge_results = [
                result
                for result in results
                if result.agent == "merge"
            ]
            for result in merge_results:
                lines.append(
                    f"  [OK] merge: {result.status} -> {result.output_path}"
                )
        else:
            for result in results:
                cache = "cache" if result.cache_hit else "run"
                detail = f" | {result.error}" if result.error else ""
                lines.append(
                    f"- {result.sample_id}: {result.status} "
                    f"({cache}) -> {result.experiment_path or result.output_path}"
                    f"{detail}"
                )

        output = "\n".join(lines)

    if args.output is not None:
        args.output.write_text(output + "\n", encoding="utf-8")
    else:
        print(output)

    return exit_status


def _handle_doctor(
    args: argparse.Namespace,
    config: VulSORConfig,
) -> int:
    """Check configured external executables on PATH."""
    checks = {
        "clang": config.tools.clang,
        "clang++": config.tools.clang_cpp,
    }

    all_ok = True

    if getattr(args, "repository_context", False) or config.repository_context.enabled:
        checks.update({"git": config.tools.git, "joern": config.tools.joern,
                       "joern-parse": config.tools.joern_parse})

    for label, executable in checks.items():
        resolved = shutil.which(executable)

        if resolved:
            print(f"[OK]   {label:<8} -> {resolved}")
        else:
            print(
                f"[FAIL] {label:<8} -> "
                f"not found on PATH ({executable!r})"
            )
            all_ok = False

    return 0 if all_ok else 1


def _handle_version(
    args: argparse.Namespace,
    config: VulSORConfig,
) -> int:
    """Print the installed VulSOR version."""
    del args, config

    from vulsor import __version__

    print(__version__)
    return 0


def _interactive_file_analysis(command: str) -> int:
    """Prompt for a file path and run analysis from the interactive menu."""
    file_text = _interactive_source_file_choice()

    if not file_text:
        print_info("No file selected.")
        return 0

    path_error = _validate_interactive_source_file_path(file_text)
    if path_error:
        print_error(path_error)
        return 0

    parser = build_parser()

    if command == "run":
        args = parser.parse_args(
            [
                command,
                "--file",
                file_text,
                "--until-stage",
                Stage.PROGRAM_ANALYSIS.value,
            ]
        )
    else:
        args = parser.parse_args(
            [
                command,
                "--file",
                file_text,
            ]
        )

    config = load_config(
        getattr(args, "config", None)
    )

    args.pretty = True

    return args.handler(args, config)


def _interactive_inspect() -> int:
    """Prompt for inspect options and run analysis from the menu."""
    choice = _interactive_choice(
        "Inspect input",
        ("source-file", "dataset-samples"),
        default="source-file",
        allow_custom=False,
    )

    if choice == "dataset-samples":
        return _interactive_inspect_dataset()

    return _interactive_inspect_file()


def _interactive_inspect_file() -> int:
    """Prompt for a source file and inspect it."""
    file_text = _interactive_source_file_choice()

    if not file_text:
        print_info("No file selected.")
        return 0

    path_error = _validate_interactive_source_file_path(file_text)
    if path_error:
        print_error(path_error)
        return 0

    output_format = _interactive_output_format(default="text")
    output_path = _interactive_optional_output_path()

    argv = [
        "inspect",
        "--file",
        file_text,
        "--format",
        output_format,
    ]

    if output_path is not None:
        argv.extend(["--output", output_path])

    parser = build_parser()
    args = parser.parse_args(argv)
    args.pretty = True
    config = load_config(args.config)

    return args.handler(args, config)


def _interactive_source_file_choice() -> str:
    """Choose a C/C++ source file from suggestions or a custom path."""
    options = _interactive_source_file_options(Path.cwd())

    if options:
        return _interactive_choice(
            "C/C++ source file",
            options,
            default=options[0],
            allow_custom=True,
        )

    console.print("[bold]C/C++ source file[/bold]")
    console.print("[dim]No nearby C/C++ file suggestions found. Type a path.[/dim]")
    return console.input("[bold]Path[/bold] ").strip()


def _interactive_source_file_options(
    root: Path,
    *,
    limit: int = 12,
) -> tuple[str, ...]:
    """Return nearby C/C++ source files for interactive suggestions."""
    suggestions = []
    stack = [root]
    seen = 0

    while stack and len(suggestions) < limit and seen < 3000:
        current = stack.pop()
        seen += 1

        try:
            children = sorted(current.iterdir(), key=lambda item: item.name.lower())
        except OSError:
            continue

        for child in children:
            if len(suggestions) >= limit or seen >= 3000:
                break

            if child.is_dir():
                if child.name not in SOURCE_SUGGESTION_EXCLUDE_DIRS:
                    stack.append(child)
                continue

            seen += 1
            if child.suffix.lower() in SOURCE_FILE_EXTENSIONS:
                suggestions.append(_display_path(child, root))

    return tuple(suggestions)


def _display_path(path: Path, root: Path) -> str:
    try:
        return str(path.relative_to(root))
    except ValueError:
        return str(path)


def _validate_interactive_source_file_path(value: str) -> str | None:
    """Return a clear error for invalid interactive source-file paths."""
    path = Path(value)

    if not path.exists():
        return f"Source file not found: {value}"

    if path.is_dir():
        return f"Source path is a directory, not a C/C++ file: {value}"

    if path.suffix.lower() not in SOURCE_FILE_EXTENSIONS:
        extensions = ", ".join(sorted(SOURCE_FILE_EXTENSIONS))
        suffix = path.suffix or "no extension"
        return (
            "Inspect source-file expects a C/C++ file "
            f"({extensions}); got {suffix}."
        )

    return None


def _interactive_inspect_dataset() -> int:
    """Prompt for dataset selection and inspect selected samples."""
    config_path = _interactive_path_choice(
        "Config path",
        ("configs/primevul.yaml",),
        default="configs/primevul.yaml",
    )
    brain_context_dir = _interactive_path_choice(
        "Brain context dir",
        ("brain_context",),
        default="brain_context",
    )

    dataset_options = _interactive_directory_options(
        Path(brain_context_dir),
        default="primevul",
    )
    dataset = _interactive_choice(
        "Dataset",
        dataset_options,
        default="primevul",
    )

    split_options = _interactive_directory_options(
        Path(brain_context_dir) / dataset,
        fallback=("train", "valid", "test"),
    )
    split = _interactive_choice("Split", split_options, default="test")

    selection = _interactive_choice(
        "Sample selection",
        ("one", "first-n", "all", "random-n"),
        default="first-n",
        allow_custom=False,
    )

    sample = None
    limit = None
    inspect_all = False
    random_count = None
    random_seed = None

    if selection == "one":
        sample = console.input(
            "[bold]Sample id:[/bold] "
        ).strip()

        if not sample:
            raise ValueError("Sample id is required.")

    elif selection == "all":
        confirm = console.input(
            "[bold]Run all samples? Type ALL to confirm:[/bold] "
        ).strip()

        if confirm != "ALL":
            print_info("Cancelled.")
            return 0

        inspect_all = True

    elif selection == "random-n":
        random_text = console.input(
            "[bold]Random count [10]:[/bold] "
        ).strip() or "10"
        random_count = _parse_positive_int(random_text, "random count")

        seed_text = console.input(
            "[bold]Random seed (empty for none):[/bold] "
        ).strip()

        if seed_text:
            random_seed = _parse_int(seed_text, "random seed")

    else:
        limit_text = console.input(
            "[bold]Limit [10]:[/bold] "
        ).strip() or "10"
        limit = _parse_positive_int(limit_text, "limit")

    output_format = _interactive_output_format(default="json")
    output_path = _interactive_optional_output_path()
    jobs_text = console.input(
        "[bold]Parallel jobs [1]:[/bold] "
    ).strip() or "1"
    jobs = _parse_positive_int(jobs_text, "parallel jobs")

    argv = [
        "inspect",
        "--config",
        config_path,
        "--dataset",
        dataset,
        "--split",
        split,
        "--jobs",
        str(jobs),
        "--format",
        output_format,
    ]

    if sample:
        argv.extend(["--sample", sample])
    elif limit is not None:
        argv.extend(["--limit", str(limit)])
    elif inspect_all:
        argv.append("--all")
    elif random_count is not None:
        argv.extend(["--random", str(random_count)])

        if random_seed is not None:
            argv.extend(["--seed", str(random_seed)])

    if output_path is not None:
        argv.extend(["--output", output_path])

    parser = build_parser()
    args = parser.parse_args(argv)
    args.pretty = True
    config = load_config(args.config)

    return args.handler(args, config)


def _interactive_agent() -> int:
    """Prompt for B2 semantic-agent options and run them."""
    console.print("[bold]Semantic agent input[/bold]")

    config_path = _interactive_path_choice(
        "Project config",
        ("configs/primevul.yaml", "configs/agent_llm.yaml"),
        default="",
        allow_empty=True,
    )
    brain_context_dir = _interactive_path_choice(
        "Brain context dir",
        ("brain_context",),
        default="brain_context",
    )
    dataset = _interactive_choice(
        "Dataset",
        _interactive_directory_options(
            Path(brain_context_dir),
            default="primevul",
        ),
        default="primevul",
    )
    split = _interactive_choice(
        "Split",
        _interactive_directory_options(
            Path(brain_context_dir) / dataset,
            fallback=("train", "valid", "test"),
        ),
        default="test",
    )

    manifest_path = (
        Path(brain_context_dir)
        / dataset
        / split
        / "manifest.json"
    )
    manifest_samples = _interactive_manifest_samples(manifest_path)

    agent = _interactive_choice(
        "Agent",
        ("all", "state", "value", "execution", "operation", "merge"),
        default="all",
    )

    samples = _interactive_select_agent_samples(manifest_samples)
    limit = None

    if not samples:
        limit_text = console.input(
            "[bold]Limit (empty for all manifest samples):[/bold] "
        ).strip()

        if limit_text:
            limit = _parse_positive_int(limit_text, "limit")

    use_llm = _interactive_yes_no(
        "Use LLM API",
        default=False,
    )
    parallel = _interactive_yes_no(
        "Run four agents in parallel",
        default=True,
    )
    llm_config = None

    if use_llm:
        llm_config = _interactive_path_choice(
            "LLM config",
            ("configs/agent_llm.yaml",),
            default="configs/agent_llm.yaml",
        )
        llm_settings = load_llm_config(Path(llm_config))
        key_agent = agent if agent in SEMANTIC_AGENTS else "state"
        api_key_env = llm_settings.for_agent(key_agent).api_key_env
        _interactive_api_key(api_key_env)

    experiments_dir = _interactive_path_choice(
        "Experiments dir",
        ("experiments",),
        default="experiments",
    )

    force = _interactive_yes_no(
        "Force rerun",
        default=False,
    )
    output_format = _interactive_output_format(default="text")
    output_path = _interactive_optional_output_path()
    view_output = _interactive_yes_no(
        "View agent output after run",
        default=True,
    )

    base_argv = [
        "agent",
        "--agent",
        agent,
        "--brain-context-dir",
        brain_context_dir,
        "--dataset",
        dataset,
        "--split",
        split,
        "--format",
        output_format,
        "--experiments-dir",
        experiments_dir,
    ]

    if config_path:
        base_argv.extend(["--config", config_path])

    if limit is not None:
        base_argv.extend(["--limit", str(limit)])

    if use_llm:
        base_argv.append("--llm")
        base_argv.extend(["--llm-config", llm_config])

    if parallel and agent == "all":
        base_argv.append("--parallel")

    if force:
        base_argv.append("--force")

    if output_path is not None:
        base_argv.extend(["--output", output_path])

    parser = build_parser()
    selected_samples = samples or [None]
    preview_enabled = (
        view_output
        and output_path is None
        and len(selected_samples) == 1
        and selected_samples[0] is not None
    )
    final_result = 0

    for sample_index, sample in enumerate(selected_samples, start=1):
        if sample is not None:
            console.print()
            console.print(
                f"[bold #C084FC]Sample:[/bold #C084FC] "
                f"[bold cyan]{sample}[/bold cyan] "
                f"[dim]({sample_index}/{len(selected_samples)})[/dim]"
            )
            console.print()

        argv = list(base_argv)
        if sample:
            argv.extend(["--sample", sample])

        args = parser.parse_args(argv)
        config = load_config(args.config)
        result = args.handler(args, config)
        final_result = final_result or result

        console.print()

        if result == 0 and preview_enabled:
            _interactive_view_agent_outputs(
                brain_context_dir=Path(brain_context_dir),
                dataset=dataset,
                split=split,
                sample_id=sample or "",
                agent=agent,
                experiments_dir=Path(experiments_dir),
                use_llm=use_llm,
            )

    if view_output and output_path is None and len(selected_samples) > 1:
        print_info(
            "Skipped automatic output preview for multiple samples; "
            "open the per-sample files under the selected experiments dir."
        )

    return final_result


def _interactive_manifest_samples(
    manifest_path: Path,
) -> list[dict]:
    """Read and display available analyzed samples from a manifest."""
    if not manifest_path.is_file():
        print_info(f"No manifest found yet: {manifest_path}")
        return []

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    samples = [
        sample
        for sample in manifest.get("samples", [])
        if isinstance(sample, dict)
    ]

    if not samples:
        print_info(f"Manifest has no samples: {manifest_path}")
        return []

    console.print("[bold]Analyzed samples[/bold]")

    for index, sample in enumerate(samples, start=1):
        sample_id = sample.get("sample_id", "-")
        status = sample.get("status", "-")
        console.print(f"  {index}. {sample_id} [{status}]")

    return samples


def _interactive_select_agent_samples(
    samples: list[dict],
) -> list[str]:
    """Select analyzed samples by index, id, comma list, or all."""
    if not samples:
        value = console.input(
            "[bold]Sample id (empty for manifest selection):[/bold] "
        ).strip()
        return _split_sample_selection(value)

    if len(samples) > 20:
        print_info(
            f"Showing first 20 sample suggestions from {len(samples)} analyzed samples."
        )
    console.print("[bold]Sample[/bold]")
    console.print(
        "[dim]Suggestions. Type sample number/id, comma list like 1,3, "
        "all, or press Enter for default.[/dim]"
    )
    default = str(samples[0].get("sample_id", "")) if samples else "all"
    console.print("  [cyan]all[/cyan]. [dim]all samples[/dim] [cyan](suggestion)[/cyan]")
    for index, sample in enumerate(samples[:20], start=1):
        sample_id = str(sample.get("sample_id", ""))
        marker = "default" if sample_id == default else "suggestion"
        marker_style = "bold green" if sample_id == default else "cyan"
        option_style = "white" if sample_id == default else "dim"
        console.print(
            f"  [cyan]{index}[/cyan]. [{option_style}]{sample_id}[/{option_style}] "
            f"[{marker_style}]({marker})[/{marker_style}]"
        )
    value = console.input(
        f"[bold]Choose sample[/bold] [dim]default: {default}[/dim] "
    ).strip()

    if not value:
        return [default] if default else []

    if value.lower() == "all":
        return []

    selected = _resolve_sample_selection(value, samples)
    if selected:
        return selected

    if value.isdigit():
        index = int(value)

        if 1 <= index <= len(samples):
            return [str(samples[index - 1].get("sample_id", ""))]

    return [value]


def _split_sample_selection(value: str) -> list[str]:
    """Split a comma-separated sample-id selection."""
    return [
        item.strip()
        for item in value.split(",")
        if item.strip()
    ]


def _resolve_sample_selection(
    value: str,
    samples: list[dict],
) -> list[str]:
    """Resolve comma-separated sample indices or ids."""
    selected = []

    for item in _split_sample_selection(value):
        if item.lower() == "all":
            return []

        if item.isdigit():
            index = int(item)
            if 1 <= index <= len(samples):
                sample_id = samples[index - 1].get("sample_id")
                if sample_id:
                    selected.append(str(sample_id))
                continue

        selected.append(item)

    return selected


def _interactive_view_agent_outputs(
    *,
    brain_context_dir: Path,
    dataset: str,
    split: str,
    sample_id: str,
    agent: str,
    experiments_dir: Path = Path("experiments"),
    use_llm: bool = False,
) -> None:
    """Render selected per-agent output artifacts."""
    if not sample_id:
        print_info("Output preview is available for one selected sample.")
        return

    agent_dir = brain_context_dir / dataset / split / "agents" / sample_id
    experiment_dir = experiments_dir / dataset / split
    names = ["state", "value", "execution", "operation"]

    if agent in names:
        names = [agent]
    elif agent == "merge":
        names = ["agent_semantics"]
    elif agent == "all":
        names = [*names, "agent_semantics"]

    available = [
        (
            name,
            experiment_dir / name / f"{sample_id}.json"
            if use_llm and name != "agent_semantics"
            else agent_dir / f"{name}.json",
        )
        for name in names
        if (agent_dir / f"{name}.json").is_file()
    ]

    if not available:
        print_info(f"No agent output files found under {agent_dir}")
        return

    output_options = ("all",) + tuple(name for name, _ in available)
    choice = _interactive_choice(
        "Agent outputs",
        output_options,
        default="all",
        allow_custom=False,
    )

    selected = available

    if choice.lower() != "all":
        selected = [
            (name, path)
            for name, path in available
            if name == choice
        ]

    for name, path in selected:
        console.print()
        console.print(f"[bold]{name}[/bold]")
        _render_json_output(path.read_text(encoding="utf-8"))


def _interactive_yes_no(
    label: str,
    *,
    default: bool,
) -> bool:
    """Prompt for a yes/no option."""
    default_text = "1" if default else "2"
    yes_marker = "default" if default else "suggestion"
    no_marker = "default" if not default else "suggestion"
    yes_marker_style = "bold green" if default else "cyan"
    no_marker_style = "bold green" if not default else "cyan"
    yes_style = "white" if default else "dim"
    no_style = "white" if not default else "dim"
    console.print(f"[bold]{label}[/bold]")
    console.print("[dim]Suggestions. Type 1/2 or press Enter for default.[/dim]")
    console.print(
        f"  [cyan]1[/cyan]. [{yes_style}]yes[/{yes_style}] "
        f"[{yes_marker_style}]({yes_marker})[/{yes_marker_style}]"
    )
    console.print(
        f"  [cyan]2[/cyan]. [{no_style}]no[/{no_style}] "
        f"[{no_marker_style}]({no_marker})[/{no_marker_style}]"
    )
    value = console.input(
        f"[bold]Choose {label.lower()}[/bold] "
        f"[dim]default: {default_text}[/dim] "
    ).strip().lower()

    if not value:
        return default

    if value in {"1", "y", "yes"}:
        return True

    if value in {"2", "n", "no"}:
        return False

    raise ValueError(f"{label} must be y or n.")


def _interactive_choice(
    label: str,
    options: tuple[str, ...],
    *,
    default: str,
    allow_custom: bool = True,
) -> str:
    """Choose a value from displayed options, allowing a custom value."""
    console.print(f"[bold]{label}[/bold]")
    if options:
        custom_hint = ", or type a custom value" if allow_custom else ""
        console.print(
            "[dim]Suggestions. Type a number, press Enter for default"
            f"{custom_hint}.[/dim]"
        )
    for index, option in enumerate(options, start=1):
        marker = "default" if option == default else "suggestion"
        marker_style = "bold green" if option == default else "cyan"
        option_style = "white" if option == default else "dim"
        console.print(
            f"  [cyan]{index}[/cyan]. [{option_style}]{option}[/{option_style}] "
            f"[{marker_style}]({marker})[/{marker_style}]"
        )

    value = console.input(
        f"[bold]Choose {label.lower()}[/bold] "
        f"[dim]default: {default}[/dim] "
    ).strip()

    if not value:
        return default

    if value.isdigit() and 1 <= int(value) <= len(options):
        return options[int(value) - 1]

    if value in options:
        return value

    if not allow_custom:
        raise ValueError(f"{label} must be one of: {', '.join(options)}.")

    return value


def _interactive_directory_options(
    path: Path,
    *,
    default: str | None = None,
    fallback: tuple[str, ...] = (),
) -> tuple[str, ...]:
    """Return directory names as suggestions for an interactive choice."""
    options = []
    if path.is_dir():
        options.extend(
            child.name
            for child in path.iterdir()
            if child.is_dir()
        )

    for option in fallback:
        if option not in options:
            options.append(option)

    if default and default not in options:
        options.insert(0, default)

    return tuple(sorted(options))


def _interactive_path_choice(
    label: str,
    options: tuple[str, ...],
    *,
    default: str,
    allow_empty: bool = False,
) -> str:
    """Show path suggestions and allow a custom path."""
    display_options = list(options)
    if allow_empty:
        display_options.insert(0, "<default>")

    choice = _interactive_choice(
        label,
        tuple(display_options),
        default="<default>" if allow_empty and not default else default,
    )

    if choice == "<default>":
        return default

    return choice


def _interactive_api_key(api_key_env: str) -> None:
    """Prompt for an API key and report whether a usable value is present."""
    has_existing = bool(os.environ.get(api_key_env))
    state = "existing key found" if has_existing else "no key loaded"
    console.print(
        f"[bold]API key[/bold] [dim]{api_key_env}: {state}[/dim]"
    )
    api_key = getpass.getpass(
        f"Paste API key for {api_key_env} "
        "(hidden; Enter keeps existing): "
    ).strip()

    if api_key:
        os.environ[api_key_env] = api_key
        console.print(
            f"[green]API key received for {api_key_env}; it will be used for this run.[/green]"
        )
        return

    if os.environ.get(api_key_env):
        console.print(
            f"[yellow]No new key pasted; using existing {api_key_env} value.[/yellow]"
        )
        return

    console.print(
        f"[red]No API key is loaded for {api_key_env}; LLM mode will fail explicitly.[/red]"
    )


def _interactive_output_format(default: str) -> str:
    """Prompt for an output format."""
    return _interactive_choice(
        "Output format",
        ("text", "json"),
        default=default,
        allow_custom=False,
    )


def _interactive_optional_output_path() -> str | None:
    """Prompt for an optional output path."""
    console.print("[bold]Output file[/bold]")
    console.print("[dim]Optional. Leave empty to print to screen.[/dim]")
    value = console.input(
        "[bold]Path[/bold] [dim]optional[/dim] "
    ).strip()

    return value or None


def _parse_positive_int(value: str, label: str) -> int:
    """Parse a positive integer from interactive input."""
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be an integer.") from exc

    if parsed < 1:
        raise ValueError(f"{label} must be >= 1.")

    return parsed


def _parse_int(value: str, label: str) -> int:
    """Parse an integer from interactive input."""
    try:
        return int(value)
    except ValueError as exc:
        raise ValueError(f"{label} must be an integer.") from exc


def _run_interactive() -> int:
    """Run the interactive VulSOR menu."""

    while True:
        try:
            action = show_main_menu()
        except (EOFError, KeyboardInterrupt):
            console.print()
            print_info("Goodbye.")
            return 0

        if action is MenuAction.EXIT:
            print_info("Goodbye.")
            return 0

        command = action.value

        clear_screen()
        console.print()
        console.print(
            f"[bold #C084FC]Selected:[/bold #C084FC] "
            f"[bold]{command}[/bold]"
        )
        console.print()

        parser = build_parser()

        try:
            if action is MenuAction.INSPECT:
                result = _interactive_inspect()

                if result != 0:
                    print_info(
                        f"Command exited with status {result}."
                    )

            elif action is MenuAction.RUN:
                result = _interactive_file_analysis(command)

                if result != 0:
                    print_info(
                        f"Command exited with status {result}."
                    )

            elif action is MenuAction.AGENT:
                result = _interactive_agent()

                if result != 0:
                    print_info(
                        f"Command exited with status {result}."
                    )

            elif command in {"version", "doctor"}:
                args = parser.parse_args([command])

                config = load_config(
                    getattr(args, "config", None)
                )
                result = args.handler(args, config)

                if result != 0:
                    print_info(
                        f"Command exited with status {result}."
                    )

            else:
                # Các command cần thêm argument:
                # hiện tại chỉ hiển thị help.
                parser.parse_args(
                    [command, "--help"]
                )

        except SystemExit:
            # argparse dùng SystemExit cho --help.
            # Không để nó thoát interactive shell.
            pass

        except FileNotFoundError as exc:
            print_error(str(exc))

        except Exception as exc:
            print_error(str(exc))

        console.print()
        console.input(
            "[dim]Press Enter to return to the menu...[/dim]"
        )
# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main(argv: Sequence[str] | None = None) -> int:
    if argv is None:
        argv = sys.argv[1:]

    if not argv:
        return _run_interactive()

    parser = build_parser()
    args = parser.parse_args(argv)

    config = load_config(args.config)
    return args.handler(args, config)


if __name__ == "__main__":
    raise SystemExit(main())
