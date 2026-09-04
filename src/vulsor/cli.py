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
    focus_analysis_on_line_range,
)
from vulsor.agents.BaseAgent import (
    SEMANTIC_AGENTS,
    run_all_semantic_agents_for_manifest,
    run_semantic_agent_for_manifest,
    run_semantic_merge_for_manifest,
)
from vulsor.tools.joern import JoernAdapter
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
        "--analysis-scope",
        choices=["auto", "function", "file"],
        default="auto",
        help=(
            "Dataset analysis scope. 'auto' uses whole-file context "
            "when available and falls back to the clean function snippet."
        ),
    )

    sp.add_argument(
        "--cpg",
        action="store_true",
        help="Also run Joern/c2cpg and include real CPG method/call facts.",
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
            "",
            "Dataset context selected:",
        ]
    )
    lines.extend(
        f"- {_count_with_percent(label, count, total)}"
        for label, count in _dataset_context_coverage(payload)
    )
    split_coverage = _payload_split_context_coverage(payload)

    if split_coverage:
        split_total = int(
            payload.get("dataset_context_split", {}).get("count", 0)
            or 0
        )
        lines.extend(["", f"Dataset context split ({split_total} samples):"])
        lines.extend(
            f"- {_count_with_percent(label, count, split_total)}"
            for label, count in split_coverage
        )

    lines.extend(["", "Stage coverage:"])
    lines.extend(
        f"- {_count_with_percent(label, count, total)}"
        for label, count in _stage_coverage(payload)
    )
    lines.extend(["", "Stage vs dataset:"])
    stage_vs_dataset = _stage_vs_dataset_coverage(payload)

    if stage_vs_dataset:
        lines.extend(
            f"- {_count_with_percent(label, count, dataset_total)}"
            for label, count, dataset_total in stage_vs_dataset
        )
    else:
        lines.append("- none")

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
        "dataset": _dataset_context_gap_text(sample),
    }
    facts = _sample_program_facts(sample)
    analysis = sample.get("analysis", {})

    if not isinstance(analysis, dict):
        analysis = {}

    source_context = analysis.get("source_context", {})
    context_facts = analysis.get("context_facts", {})
    cpg_facts = analysis.get("cpg_facts", {})
    completeness = analysis.get("completeness", {})
    build_diagnosis = analysis.get("build_diagnosis", {})
    missing_summary = analysis.get("missing_context_summary", {})
    diagnostics = list(sample.get("diagnostics", ()))
    missing, _total = _dataset_context_gaps(sample)
    lines = [
        f"- {row['sample_id']} [{row['status']}]",
        "  table_row: "
        f"source={row['source']}, "
        f"context={row['context']}, "
        f"ast={row['ast']}, "
        f"cfg={row['cfg']}, "
        f"data_flow={row['data_flow']}, "
        f"cpg={row['cpg']}, "
        f"dataset={row['dataset']}",
        "  stage_details:",
        f"  - source: {row['source']} ({_source_detail(source_context)})",
        f"  - context: {row['context']} ({_context_detail(context_facts)})",
        f"  - ast: {row['ast']}{_stage_reason_text(completeness, 'ast')}",
        f"  - cfg: {row['cfg']}{_stage_reason_text(completeness, 'cfg')}",
        (
            f"  - data_flow: {row['data_flow']}"
            f"{_stage_reason_text(completeness, 'data_flow')}"
        ),
        f"  - cpg: {row['cpg']} ({_cpg_detail(cpg_facts)})",
        "  facts:",
        (
            "  - "
            f"functions={len(facts.get('functions', ()))}, "
            f"operations={len(facts.get('operations', ()))}, "
            f"cfg_blocks={len(facts.get('cfg_blocks', ()))}, "
            f"data_flow={len(facts.get('data_flow', ()))}, "
            f"call_graph={len(facts.get('call_graph', ()))}"
        ),
        "  dataset_context:",
    ]

    if artifact_path:
        lines.insert(1, f"  artifact: {artifact_path}")

    lines.extend(
        f"  - {label}: {'available' if available else 'missing'}"
        for label, available in _dataset_context_checks(sample)
    )

    if missing:
        lines.append(f"  - missing_factors: {', '.join(missing)}")

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


def _source_detail(source_context: dict) -> str:
    """Return detailed text for the source stage."""
    if not isinstance(source_context, dict) or not source_context:
        return "no source context metadata"

    selected = source_context.get("selected_source") or "not selected"
    requested = source_context.get("requested_scope") or "unknown"
    fallback = source_context.get("fallback_reason")

    parts = [
        f"requested_scope={requested}",
        f"selected_source={selected}",
    ]

    if fallback:
        parts.append(f"fallback_reason={fallback}")

    return "; ".join(parts)


def _context_detail(context_facts: dict) -> str:
    """Return detailed text for the context stage."""
    if not isinstance(context_facts, dict) or not context_facts.get("available"):
        return "no usable context facts"

    target = context_facts.get("target", {})
    file_index = context_facts.get("same_file_index", {})
    call_context = context_facts.get("same_file_call_context", {})

    if not isinstance(target, dict):
        target = {}

    if not isinstance(file_index, dict):
        file_index = {}

    if not isinstance(call_context, dict):
        call_context = {}

    return (
        f"target={target.get('name') or 'unknown'}; "
        f"same_file_functions={file_index.get('function_count', 0)}; "
        f"callees={call_context.get('direct_callee_count', 0)}; "
        f"callee_bodies={call_context.get('direct_callee_body_count', 0)}; "
        f"callers={call_context.get('direct_caller_count', 0)}"
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


def _cpg_detail(cpg_facts: dict) -> str:
    """Return detailed text for the CPG stage."""
    if not isinstance(cpg_facts, dict) or not cpg_facts:
        return "no CPG metadata"

    status = cpg_facts.get("status") or "missing"
    methods = cpg_facts.get("method_count", 0)
    calls = cpg_facts.get("call_count", 0)
    diagnostics = cpg_facts.get("diagnostics", ())

    return (
        f"status={status}; methods={methods}; calls={calls}; "
        f"diagnostics={len(diagnostics) if isinstance(diagnostics, (list, tuple)) else 0}"
    )


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
    table.add_column("Context")
    table.add_column("AST")
    table.add_column("CFG")
    table.add_column("Data Flow")
    table.add_column("CPG")
    table.add_column("Message")

    for sample in payload["samples"]:
        stages = _sample_stage_statuses(sample)
        table.add_row(
            sample["sample_id"],
            _status_markup(sample["status"]),
            _status_markup(stages["source"]),
            _status_markup(stages["context"]),
            _status_markup(stages["ast"]),
            _status_markup(stages["cfg"]),
            _status_markup(stages["data_flow"]),
            _status_markup(stages["cpg"]),
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
            "context": "skip",
            "ast": "skip",
            "cfg": "skip",
            "data_flow": "skip",
            "cpg": "skip",
        }

    analysis = sample.get("analysis", {})
    completeness = analysis.get("completeness", {})
    source_context = analysis.get("source_context", {})
    context_facts = analysis.get("context_facts", {})
    cpg_facts = analysis.get("cpg_facts", {})

    source_status = "available"
    if isinstance(source_context, dict):
        if source_context.get("fallback_reason"):
            source_status = "limited"
        elif not source_context.get("selected_source"):
            source_status = "missing"

    context_status = "missing"
    if isinstance(context_facts, dict):
        if context_facts.get("available"):
            context_status = "available"
        elif source_status == "available":
            context_status = "empty"

    return {
        "source": source_status,
        "context": context_status,
        "ast": _pass_status(completeness, "ast"),
        "cfg": _pass_status(completeness, "cfg"),
        "data_flow": _pass_status(completeness, "data_flow"),
        "cpg": _cpg_stage_status(cpg_facts),
    }


def _pass_status(completeness: dict, key: str) -> str:
    """Read an analysis-pass status from dict or dataclass metadata."""
    if not isinstance(completeness, dict):
        return "missing"

    value = completeness.get(key)

    if isinstance(value, dict):
        return str(value.get("status") or "missing")

    return str(getattr(value, "status", "missing") or "missing")


def _cpg_stage_status(cpg_facts: dict) -> str:
    """Return the compact Joern/CPG stage status."""
    if not isinstance(cpg_facts, dict):
        return "missing"

    status = str(cpg_facts.get("status") or "missing")

    if status == "not_requested":
        return "skip"

    return status


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
    dataset_coverage = _dataset_context_coverage(payload)

    if dataset_coverage:
        summary_lines.extend(
            [
                "",
                *_summary_metric_lines(
                    "Dataset context - selected samples",
                    dataset_coverage,
                    total,
                ),
            ]
        )
    split_coverage = _payload_split_context_coverage(payload)

    if split_coverage:
        split_total = int(
            payload.get("dataset_context_split", {}).get("count", 0)
            or 0
        )
        summary_lines.extend(
            [
                "",
                *_summary_metric_lines(
                    f"Dataset context - full split ({split_total} samples)",
                    split_coverage,
                    split_total,
                ),
            ]
        )

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

    stage_vs_dataset = _stage_vs_dataset_coverage(payload)

    if stage_vs_dataset:
        summary_lines.extend(
            [
                "",
                "Stage facts vs available dataset context",
                *[
                    f"  - {_summary_ratio_text(label, count, dataset_total)}"
                    for label, count, dataset_total in stage_vs_dataset
                ],
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
    issue_table.add_column("Context")
    issue_table.add_column("AST")
    issue_table.add_column("CFG")
    issue_table.add_column("Data Flow")
    issue_table.add_column("CPG")
    issue_table.add_column("Dataset")

    for row in stage_summaries:
        issue_table.add_row(
            row["sample_id"],
            _status_markup(row["source"]),
            _status_markup(row["context"]),
            _status_markup(row["ast"]),
            _status_markup(row["cfg"]),
            _status_markup(row["data_flow"]),
            _status_markup(row["cpg"]),
            row["dataset"],
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
            "dataset": _dataset_context_gap_text(sample),
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


def _dataset_context_coverage(payload: dict) -> list[tuple[str, int]]:
    """Return aggregate dataset-context coverage for inspected samples."""
    counts = {
        label: 0
        for label, _available in _dataset_context_checks({})
    }

    for sample in payload.get("samples", ()):
        for label, available in _dataset_context_checks(sample):
            if available:
                counts[label] += 1

    return list(counts.items())


def _dataset_context_split_coverage(
    config: VulSORConfig,
    dataset_name: str,
    split: str,
) -> dict:
    """Return dataset-context coverage across the full configured split."""
    dataset = config.datasets.get(dataset_name)

    if dataset is None:
        return {
            "available": False,
            "reason": "dataset is not configured",
        }

    context_file = dataset.root / "context" / f"{split}.jsonl"

    if not context_file.is_file():
        return {
            "available": False,
            "reason": f"context sidecar not found: {context_file}",
        }

    counts = {
        label: 0
        for label, _available in _dataset_context_checks({})
    }
    total = 0

    with context_file.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip():
                continue

            try:
                record = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(
                    f"Invalid JSONL record at {context_file}:{line_number}"
                ) from exc

            sample = {
                "analysis": {
                    "source_context": record,
                    "context_facts": _context_facts(record),
                }
            }
            total += 1

            for label, available in _dataset_context_checks(sample):
                if available:
                    counts[label] += 1

    return {
        "available": True,
        "path": str(context_file),
        "count": total,
        "coverage": list(counts.items()),
    }


def _payload_split_context_coverage(payload: dict) -> list[tuple[str, int]]:
    """Return full-split dataset coverage embedded in a payload."""
    split_context = payload.get("dataset_context_split", {})

    if not isinstance(split_context, dict) or not split_context.get("available"):
        return []

    coverage = split_context.get("coverage", ())

    return [
        (str(label), int(count))
        for label, count in coverage
    ]


def _stage_coverage(payload: dict) -> list[tuple[str, int]]:
    """Return aggregate stage coverage for inspected samples."""
    counts = {
        "source": 0,
        "context": 0,
        "ast": 0,
        "cfg": 0,
        "data_flow": 0,
        "cpg": 0,
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


def _stage_vs_dataset_coverage(payload: dict) -> list[tuple[str, int, int]]:
    """Return B1 fact coverage over samples where dataset context exists."""
    counters = {
        "ast/target_body": [0, 0],
        "cfg/target_index": [0, 0],
        "data_flow/target_index": [0, 0],
        "call_graph/call_context": [0, 0],
        "cpg/call_context": [0, 0],
    }

    for sample in payload.get("samples", ()):
        checks = dict(_dataset_context_checks(sample))
        facts = _sample_program_facts(sample)
        statuses = _sample_stage_statuses(sample)

        if checks.get("target_body"):
            counters["ast/target_body"][1] += 1

            if facts and facts.get("functions"):
                counters["ast/target_body"][0] += 1

        if checks.get("target_index"):
            counters["cfg/target_index"][1] += 1
            counters["data_flow/target_index"][1] += 1

            if facts and facts.get("cfg_blocks"):
                counters["cfg/target_index"][0] += 1

            if facts and facts.get("data_flow"):
                counters["data_flow/target_index"][0] += 1

        if checks.get("call_context"):
            counters["call_graph/call_context"][1] += 1
            counters["cpg/call_context"][1] += 1

            if facts and facts.get("call_graph"):
                counters["call_graph/call_context"][0] += 1

            if _stage_counts_as_available(statuses.get("cpg", "missing")):
                counters["cpg/call_context"][0] += 1

    return [
        (label, values[0], values[1])
        for label, values in counters.items()
        if values[1] > 0
    ]


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


def _dataset_context_gap_text(sample: dict) -> str:
    """Return dataset-context missing percentage and missing factors."""
    missing, total = _dataset_context_gaps(sample)
    missing_percent = 0.0

    if total:
        missing_percent = len(missing) * 100 / total

    if not missing:
        return "0.0% missing: none"

    return (
        f"{missing_percent:.1f}% missing: "
        f"{', '.join(missing)}"
    )


def _dataset_context_gaps(sample: dict) -> tuple[list[str], int]:
    """Classify which dataset-provided context factors are unavailable."""
    checks = _dataset_context_checks(sample)
    missing = [
        name
        for name, available in checks
        if not available
    ]

    return missing, len(checks)


def _dataset_context_checks(sample: dict) -> tuple[tuple[str, bool], ...]:
    """Return dataset-context factor availability for one sample."""
    analysis = sample.get("analysis", {})

    if not isinstance(analysis, dict):
        analysis = {}

    source_context = analysis.get("source_context", {})
    context_facts = analysis.get("context_facts", {})

    if not isinstance(source_context, dict):
        source_context = {}

    if not isinstance(context_facts, dict):
        context_facts = {}

    compile_context = source_context.get("compile_context", {})
    target = source_context.get("target_function", {})
    file_index = source_context.get("file_function_index", {})
    call_context = source_context.get("call_context", {})

    if not isinstance(compile_context, dict):
        compile_context = {}

    if not isinstance(target, dict):
        target = {}

    if not isinstance(file_index, dict):
        file_index = {}

    if not isinstance(call_context, dict):
        call_context = {}

    return (
        ("file_info", source_context.get("file_context_available") is True),
        (
            "whole_file",
            source_context.get("resolved_file_available") is True
            or compile_context.get("whole_file_available") is True,
        ),
        ("target_body", target.get("body_available") is True),
        ("target_index", target.get("indexed") is True),
        ("file_index", file_index.get("available") is True),
        ("call_context", call_context.get("available") is True),
        (
            "headers",
            compile_context.get("project_headers_available") is True,
        ),
        (
            "compile_commands",
            compile_context.get("compile_commands_available") is True,
        ),
        (
            "include_paths",
            compile_context.get("include_paths_available") is True,
        ),
        ("macros", compile_context.get("macros_available") is True),
    )


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


def _context_summary_line(context_facts: dict) -> str:
    """Return a compact one-line summary for enriched context facts."""
    if not isinstance(context_facts, dict):
        return ""

    if not context_facts.get("available"):
        return ""

    target = context_facts.get("target", {})
    call_context = context_facts.get("same_file_call_context", {})
    file_index = context_facts.get("same_file_index", {})

    if not isinstance(target, dict):
        target = {}

    if not isinstance(call_context, dict):
        call_context = {}

    if not isinstance(file_index, dict):
        file_index = {}

    name = target.get("name") or "unknown"
    callee_count = call_context.get("direct_callee_count", 0)
    callee_body_count = call_context.get("direct_callee_body_count", 0)
    caller_count = call_context.get("direct_caller_count", 0)
    function_count = file_index.get("function_count", 0)

    return (
        f"target={name}, same_file_functions={function_count}, "
        f"callees={callee_count}, callee_bodies={callee_body_count}, "
        f"callers={caller_count}"
    )


def _cpg_summary_line(cpg_facts: dict) -> str:
    """Return a compact one-line summary for Joern CPG facts."""
    if not isinstance(cpg_facts, dict):
        return ""

    status = cpg_facts.get("status")

    if status == "not_requested":
        return ""

    return (
        f"status={status}, methods={cpg_facts.get('method_count', 0)}, "
        f"calls={cpg_facts.get('call_count', 0)}"
    )


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
    *,
    requested_scope: str | None = None,
    source_context: dict | None = None,
    tool_status: dict | None = None,
    cpg_facts: dict | None = None,
) -> dict:
    """Return explicit scope, completeness, and methodology metadata."""
    source_context = source_context or {}

    return {
        "scope": analysis.scope,
        "requested_scope": requested_scope,
        "context_mode": analysis.context_mode,
        "complete": analysis.complete,
        "source_context": source_context,
        "context_facts": _context_facts(source_context),
        "tool_status": tool_status or {},
        "cpg_facts": cpg_facts or _cpg_not_requested(),
        "completeness": analysis.completeness or {},
        "build_diagnosis": _build_diagnosis(
            analysis,
            source_context,
        ),
        "missing_context_summary": _missing_context_summary(analysis),
        "missing_context": analysis.missing_context,
        "recovery_assumptions": analysis.recovery_assumptions,
        "links": analysis.links,
        "limitations": analysis.limitations,
        "rules": PROGRAM_ANALYSIS_RULES,
    }


def _context_facts(source_context: dict) -> dict:
    """Summarize dataset context without treating it as tool evidence."""
    target_function = source_context.get("target_function", {})
    file_function_index = source_context.get("file_function_index", {})
    call_context = source_context.get("call_context", {})

    if not isinstance(target_function, dict):
        target_function = {}

    if not isinstance(file_function_index, dict):
        file_function_index = {}

    if not isinstance(call_context, dict):
        call_context = {}

    direct_callees = _dict_items(call_context.get("direct_callees"))
    direct_callers = _dict_items(call_context.get("direct_callers"))
    indexed_functions = _dict_items(file_function_index.get("functions"))
    same_file_callees = [
        callee
        for callee in direct_callees
        if callee.get("body_available") is True
    ]
    available = bool(
        target_function
        or file_function_index.get("available")
        or call_context.get("available")
    )

    return {
        "available": available,
        "target": {
            "available": bool(target_function),
            "name": target_function.get("name"),
            "start_line": target_function.get("start_line"),
            "end_line": target_function.get("end_line"),
            "indexed": target_function.get("indexed"),
            "body_available": target_function.get("body_available"),
        },
        "same_file_index": {
            "available": bool(file_function_index.get("available")),
            "function_count": file_function_index.get(
                "function_count",
                len(indexed_functions),
            ),
        },
        "same_file_call_context": {
            "available": bool(call_context.get("available")),
            "scope": call_context.get("scope"),
            "direct_callee_count": len(direct_callees),
            "direct_callee_body_count": len(same_file_callees),
            "direct_caller_count": len(direct_callers),
            "limitations": call_context.get("limitations", ()),
        },
        "provenance": (
            "PrimeVul clean context sidecar built from raw file_info "
            "and resolved whole-file source when available"
        ),
        "trust_boundary": (
            "technical context only; not a vulnerability label, verdict, "
            "or verification evidence"
        ),
    }


def _dict_items(value) -> list[dict]:
    """Return only dictionary entries from a JSON-like list value."""
    if not isinstance(value, list):
        return []

    return [
        item
        for item in value
        if isinstance(item, dict)
    ]


def _cpg_not_requested() -> dict:
    """Return explicit metadata when Joern/CPG was not requested."""
    return {
        "status": "not_requested",
        "available": False,
        "complete": False,
        "method_count": 0,
        "call_count": 0,
        "methods": (),
        "calls": (),
        "diagnostics": (),
        "provenance": "joern/c2cpg",
    }


def _cpg_metadata(cpg_result) -> dict:
    """Convert a Joern CPG result into JSON-friendly B1 metadata."""
    status = "available" if cpg_result.complete else "partial"

    if not cpg_result.available:
        status = "unavailable"

    return {
        "status": status,
        "available": cpg_result.available,
        "complete": cpg_result.complete,
        "cpg_integrated": cpg_result.cpg_integrated,
        "method_count": len(cpg_result.methods),
        "call_count": len(cpg_result.calls),
        "methods": cpg_result.methods,
        "calls": cpg_result.calls,
        "diagnostics": cpg_result.diagnostics,
        "provenance": "joern/c2cpg",
        "trust_boundary": (
            "real CPG facts from Joern; still not vulnerability verdict "
            "or verification evidence"
        ),
    }


def _build_diagnosis(
    analysis: ProgramAnalysisResult,
    source_context: dict,
) -> dict:
    """Classify fixable analysis failures without guessing facts."""
    compile_context = source_context.get("compile_context", {})

    if not isinstance(compile_context, dict):
        compile_context = {}

    issues: list[dict] = []

    if not analysis.cfg_available:
        issues.append(
            _cfg_issue(
                analysis,
                source_context,
                compile_context,
            )
        )
    elif analysis.recovery_assumptions and _has_compile_context(
        compile_context
    ) and not source_context.get("clang_args_applied"):
        issues.append(
            {
                "component": "synthetic_context",
                "classification": "pipeline_context_not_applied",
                "fixable": True,
                "message": (
                    "dataset context advertises compile information, but "
                    "B1 still needed explicit synthetic recovery assumptions; "
                    "wire concrete include paths, macros, or Clang args into "
                    "the Clang invocation"
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


def _cfg_issue(
    analysis: ProgramAnalysisResult,
    source_context: dict,
    compile_context: dict,
) -> dict:
    """Classify why CFG is missing and whether it is fixable."""
    cfg_status = (
        analysis.completeness.get("cfg")
        if analysis.completeness
        else None
    )

    if cfg_status and cfg_status.status == "omitted":
        return {
            "component": "cfg",
            "classification": "function_range_cfg_omitted",
            "fixable": True,
            "message": (
                "whole-file CFG was produced but is not yet mapped back "
                "to the selected function line range"
            ),
        }

    has_compile_context = _has_compile_context(compile_context)

    if has_compile_context:
        if source_context.get("clang_args_applied"):
            return {
                "component": "cfg",
                "classification": "dataset_compile_context_incomplete",
                "fixable": True,
                "message": (
                    "compile context was passed to Clang, but CFG is still "
                    "missing; the sample likely needs additional headers, "
                    "typedefs, macros, or build flags"
                ),
            }

        return {
            "component": "cfg",
            "classification": "pipeline_context_not_applied",
            "fixable": True,
            "message": (
                "dataset context advertises compile information, but no "
                "concrete include paths, macros, or Clang args were available "
                "to pass into Clang"
            ),
        }

    if not source_context.get("resolved_file_available"):
        return {
            "component": "cfg",
            "classification": "dataset_file_context_missing",
            "fixable": False,
            "message": (
                "whole-file source context is unavailable for this sample"
            ),
        }

    if analysis.missing_context:
        return {
            "component": "cfg",
            "classification": "dataset_compile_context_missing",
            "fixable": True,
            "message": (
                "Clang diagnostics name missing project symbols; "
                "adding headers, typedefs, macros, or build flags can "
                "recover CFG"
            ),
        }

    if analysis.diagnostics:
        return {
            "component": "cfg",
            "classification": "clang_diagnostics_unclassified",
            "fixable": True,
            "message": (
                "Clang emitted diagnostics but they did not match the "
                "known missing-context patterns; inspect diagnostics or "
                "extend diagnostic parsing"
            ),
        }

    return {
        "component": "cfg",
        "classification": "tool_or_parser_issue",
        "fixable": True,
        "message": (
            "CFG is missing without useful diagnostics; this points to "
            "Clang invocation, CFG parser, language suffix, or local "
            "toolchain handling"
        ),
    }


def _has_compile_context(compile_context: dict) -> bool:
    return any(
        bool(compile_context.get(key))
        for key in (
            "compile_commands_available",
            "include_paths_available",
        )
    ) or compile_context.get("macros_available") is True


def _analyze_dataset_sample(
    *,
    sample,
    clang_executable: str,
    requested_scope: str,
) -> tuple[ProgramAnalysisResult, dict]:
    """Analyze one dataset sample using clean context when available."""
    context = sample.context or {}
    source_context = _source_context_metadata(
        context,
        requested_scope=requested_scope,
    )
    clang_args = _clang_args_from_compile_context(
        source_context.get("compile_context", {})
    )
    source_context["clang_args_applied"] = list(clang_args)
    resolved_file = _resolved_context_file(context)
    use_file_context = (
        requested_scope == "file"
        or (
            requested_scope == "auto"
            and resolved_file is not None
        )
    )

    if use_file_context and resolved_file is None:
        source_context["selected_source"] = "function_snippet"
        source_context["fallback_reason"] = (
            "whole-file context is unavailable for this sample"
        )
        analysis = analyze_source_code_tolerant(
            source_code=sample.code,
            clang_executable=clang_executable,
            scope="function",
            clang_args=clang_args,
        )
        return analysis, source_context

    if not use_file_context:
        source_context["selected_source"] = "function_snippet"
        analysis = analyze_source_code_tolerant(
            source_code=sample.code,
            clang_executable=clang_executable,
            scope="function",
            clang_args=clang_args,
        )
        return analysis, source_context

    source_context["selected_source"] = "whole_file"
    source_context["attempted_source"] = "whole_file"
    source_code = resolved_file.read_text(encoding="utf-8")
    suffix = _source_suffix(context)
    effective_scope = (
        "file"
        if requested_scope == "file"
        else "function"
    )
    analysis = analyze_source_code_tolerant(
        source_code=source_code,
        clang_executable=clang_executable,
        suffix=suffix,
        scope=effective_scope,
        clang_args=clang_args,
    )

    if effective_scope == "function":
        target_function = context.get("target_function", {})

        if not isinstance(target_function, dict):
            target_function = {}

        start_line = (
            target_function.get("start_line")
            if isinstance(target_function.get("start_line"), int)
            else context.get("function_start_line")
        )
        end_line = (
            target_function.get("end_line")
            if isinstance(target_function.get("end_line"), int)
            else context.get("function_end_line")
        )

        if isinstance(start_line, int) and isinstance(end_line, int):
            analysis = focus_analysis_on_line_range(
                analysis,
                start_line=start_line,
                end_line=end_line,
            )
            source_context["target_line_range"] = {
                "start": start_line,
                "end": end_line,
            }

    if (
        requested_scope == "auto"
        and not analysis.facts.functions
    ):
        source_context["selected_source"] = "function_snippet"
        source_context["fallback_reason"] = (
            "target function was not recoverable from whole-file analysis"
        )
        snippet_analysis = analyze_source_code_tolerant(
            source_code=sample.code,
            clang_executable=clang_executable,
            scope="function",
            clang_args=clang_args,
        )
        return snippet_analysis, source_context

    return analysis, source_context


def _analyze_cpg_for_sample(
    *,
    sample,
    source_context: dict,
    joern_executable: str,
) -> dict:
    """Run Joern CPG extraction for the same source selected by B1."""
    context = sample.context or {}
    selected_source = source_context.get("selected_source")
    resolved_file = _resolved_context_file(context)

    if selected_source == "whole_file" and resolved_file is not None:
        source_code = resolved_file.read_text(encoding="utf-8")
        suffix = _source_suffix(context)
    else:
        source_code = sample.code
        suffix = ".c"

    include_paths, defines = _cpg_compile_inputs(
        source_context.get("compile_context", {})
    )
    cpg_result = JoernAdapter(joern_executable).analyze_source_code(
        source_code,
        suffix=suffix,
        include_paths=include_paths,
        defines=defines,
    )

    return _cpg_metadata(cpg_result)


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


def _program_analysis_tool_status(config: VulSORConfig) -> dict:
    """Return tool capability status relevant to Program Analysis."""
    joern_status = JoernAdapter(config.tools.joern).status()

    return {
        "clang": {
            "executable": config.tools.clang,
            "available": shutil.which(config.tools.clang) is not None,
            "uses": [
                "ast_json",
                "cfg_dump",
            ],
        },
        "joern": {
            "executable": joern_status.executable,
            "available": joern_status.available,
            "resolved_path": joern_status.resolved_path,
            "cpg_integrated": joern_status.cpg_integrated,
            "message": joern_status.message,
        },
    }


def _cpg_compile_inputs(
    compile_context: dict,
) -> tuple[tuple[str, ...], tuple[str, ...]]:
    """Return include paths and defines supported by c2cpg."""
    if not isinstance(compile_context, dict):
        return (), ()

    include_paths = tuple(
        dict.fromkeys(
            _string_items(
                compile_context.get("include_paths")
                or compile_context.get("include_dirs")
                or compile_context.get("includes")
            )
            + _string_items(
                compile_context.get("system_include_paths")
                or compile_context.get("system_includes")
            )
        )
    )
    defines = tuple(
        dict.fromkeys(
            _macro_args(compile_context.get("macros"))
            + _macro_args(compile_context.get("defines"))
        )
    )

    return include_paths, defines


def _clang_args_from_compile_context(compile_context: dict) -> tuple[str, ...]:
    """Translate sidecar compile context into conservative Clang args."""
    if not isinstance(compile_context, dict):
        return ()

    args: list[str] = []

    for include_path in _string_items(
        compile_context.get("include_paths")
        or compile_context.get("include_dirs")
        or compile_context.get("includes")
    ):
        args.append(f"-I{include_path}")

    for system_include_path in _string_items(
        compile_context.get("system_include_paths")
        or compile_context.get("system_includes")
    ):
        args.append(f"-isystem{system_include_path}")

    for macro in _macro_args(compile_context.get("macros")):
        args.append(f"-D{macro}")

    for macro in _macro_args(compile_context.get("defines")):
        args.append(f"-D{macro}")

    for macro in _string_items(
        compile_context.get("undefines")
        or compile_context.get("undefined_macros")
    ):
        args.append(f"-U{macro}")

    args.extend(
        _string_items(
            compile_context.get("extra_clang_args")
            or compile_context.get("clang_args")
            or compile_context.get("compiler_args")
        )
    )

    return tuple(dict.fromkeys(args))


def _string_items(value) -> list[str]:
    """Return non-empty string entries from a JSON-like value."""
    if isinstance(value, str) and value:
        return [value]

    if not isinstance(value, list):
        return []

    return [
        item
        for item in value
        if isinstance(item, str) and item
    ]


def _macro_args(value) -> list[str]:
    """Return macro definitions in NAME or NAME=VALUE form."""
    if isinstance(value, dict):
        return [
            key if macro_value is True else f"{key}={macro_value}"
            for key, macro_value in value.items()
            if isinstance(key, str) and key
        ]

    return _string_items(value)


def _source_context_metadata(
    context: dict,
    *,
    requested_scope: str,
) -> dict:
    """Expose technical context without label or vulnerability metadata."""
    return {
        "requested_scope": requested_scope,
        "file_context_available": bool(
            context.get("file_context_available")
        ),
        "resolved_file_available": bool(
            context.get("resolved_file_available")
        ),
        "source_kind": context.get("source_kind", "function_snippet"),
        "file_name": context.get("file_name"),
        "original_file_path": context.get("original_file_path"),
        "resolved_file_content_path": context.get(
            "resolved_file_content_path"
        ),
        "compile_context": context.get("compile_context", {}),
        "target_function": context.get("target_function", {}),
        "file_function_index": context.get("file_function_index", {}),
        "call_context": context.get("call_context", {}),
    }


def _resolved_context_file(context: dict) -> Path | None:
    """Return the resolved whole-file source path when it exists."""
    path_text = context.get("resolved_file_content_path")

    if not isinstance(path_text, str) or not path_text:
        return None

    path = Path(path_text)

    if path.is_file():
        return path

    return None


def _source_suffix(context: dict) -> str:
    """Choose a C/C++ suffix for temporary whole-file analysis."""
    file_name = context.get("file_name")

    if isinstance(file_name, str):
        suffix = Path(file_name).suffix.lower()

        if suffix in {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp"}:
            return suffix

    return ".c"


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


def _selected_source(analysis: dict) -> str:
    """Return the compact source label used for a rendered row."""
    source_context = analysis.get("source_context", {})

    if not isinstance(source_context, dict):
        return "-"

    return source_context.get("selected_source") or "-"


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
    requested_scope: str,
    tool_status: dict,
    enable_cpg: bool,
) -> dict:
    """Inspect one dataset sample and return its payload entry."""
    try:
        analysis, source_context = _analyze_dataset_sample(
            sample=sample,
            clang_executable=config.tools.clang,
            requested_scope=requested_scope,
        )

        cpg_facts = (
            _analyze_cpg_for_sample(
                sample=sample,
                source_context=source_context,
                joern_executable=config.tools.joern,
            )
            if enable_cpg
            else _cpg_not_requested()
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
        "analysis": _analysis_metadata(
            analysis,
            requested_scope=requested_scope,
            source_context=source_context,
            tool_status=tool_status,
            cpg_facts=cpg_facts,
        ),
        "diagnostics": _analysis_diagnostics(analysis),
    }


def _inspect_dataset_samples(
    *,
    samples: list,
    config: VulSORConfig,
    requested_scope: str,
    tool_status: dict,
    enable_cpg: bool,
    jobs: int,
) -> list[dict]:
    """Inspect dataset samples sequentially or concurrently."""
    if not samples:
        return []

    if jobs == 1:
        return _inspect_dataset_samples_sequential(
            samples=samples,
            config=config,
            requested_scope=requested_scope,
            tool_status=tool_status,
            enable_cpg=enable_cpg,
        )

    return _inspect_dataset_samples_parallel(
        samples=samples,
        config=config,
        requested_scope=requested_scope,
        tool_status=tool_status,
        enable_cpg=enable_cpg,
        jobs=jobs,
    )


def _inspect_dataset_samples_sequential(
    *,
    samples: list,
    config: VulSORConfig,
    requested_scope: str,
    tool_status: dict,
    enable_cpg: bool,
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

            if enable_cpg:
                _update_dataset_progress(
                    progress,
                    task_id,
                    sample.sample_id,
                    index,
                    len(samples),
                    "program analysis + Joern/CPG",
                )

            inspected.append(
                _inspect_dataset_sample(
                    sample=sample,
                    config=config,
                    requested_scope=requested_scope,
                    tool_status=tool_status,
                    enable_cpg=enable_cpg,
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
    requested_scope: str,
    tool_status: dict,
    enable_cpg: bool,
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
                    requested_scope=requested_scope,
                    tool_status=tool_status,
                    enable_cpg=enable_cpg,
                ): index
                for index, sample in enumerate(samples)
            }

            for completed, future in enumerate(
                as_completed(future_to_index),
                start=1,
            ):
                index = future_to_index[future]
                sample = samples[index]
                stage = "complete"

                if enable_cpg:
                    stage = "complete after Joern/CPG"

                _update_dataset_progress(
                    progress,
                    task_id,
                    sample.sample_id,
                    completed,
                    len(samples),
                    stage,
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
        tool_status = _program_analysis_tool_status(config)

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
                include_context=True,
            )
        )

        samples = _inspect_dataset_samples(
            samples=selected_samples,
            config=config,
            requested_scope=args.analysis_scope,
            tool_status=tool_status,
            enable_cpg=args.cpg,
            jobs=args.jobs,
        )

        payload = {
            "dataset": args.dataset,
            "split": args.split,
            "count": len(samples),
            "samples": samples,
            "dataset_context_split": _dataset_context_split_coverage(
                config,
                args.dataset,
                args.split,
            ),
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
        "java": config.tools.java,
        "joern": config.tools.joern,
    }

    all_ok = True

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

    analysis_scope = _interactive_analysis_scope()
    output_format = _interactive_output_format(default="json")
    output_path = _interactive_optional_output_path()
    enable_cpg = _interactive_yes_no(
        "Run Joern/CPG facts",
        default=False,
    )
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
        "--analysis-scope",
        analysis_scope,
        "--jobs",
        str(jobs),
        "--format",
        output_format,
    ]

    if enable_cpg:
        argv.append("--cpg")

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


def _interactive_analysis_scope() -> str:
    """Prompt for dataset analysis scope."""
    return _interactive_choice(
        "Analysis scope",
        ("auto", "function", "file"),
        default="auto",
        allow_custom=False,
    )


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
