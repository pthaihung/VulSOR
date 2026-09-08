"""Offline file-context builder command."""

import argparse
import json
from pathlib import Path

from .config import VulSORConfig, load_config
from .file_context_service import FileContextResult, FileContextService
from .file_cpg import FileCpgCache
from .joern import JoernAdapter, JoernError
from .primevul_file_source import PrimeVulFileSourceResolver


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="context_tool")
    commands = parser.add_subparsers(dest="command", required=True)
    file_context = commands.add_parser(
        "file-context", help="Build offline file-level PrimeVul context"
    )
    actions = file_context.add_subparsers(dest="file_action", required=True)
    build = actions.add_parser("build")
    build.add_argument("--config", type=Path)
    build.add_argument("--pairs", required=True, type=Path)
    build.add_argument("--file-info", required=True, type=Path)
    build.add_argument("--dataset-root", required=True, type=Path)
    build.add_argument("--output", required=True, type=Path)
    build.add_argument("--report", type=Path)
    build.add_argument("--limit", type=int)
    build.add_argument("--progress", action="store_true")
    build.set_defaults(handler=handle_file_context)
    return parser


def _file_context_progress(current: int, total: int, result: FileContextResult) -> None:
    sample = result.record.get("idx", result.record.get("func_hash", "?"))
    detail = f" reason={result.reason}" if result.reason else ""
    ratio = current / total if total > 0 else 1.0
    percent = min(100, max(0, int(ratio * 100)))
    width = 24
    filled = int(width * percent / 100)
    bar = "#" * filled + "." * (width - filled)
    line = (
        f"[{bar}] {percent}% {current}/{total} "
        f"{result.status} sample={sample}{detail}"
    )
    print(
        "\r" + line.ljust(120),
        end="\n" if current >= total else "",
        flush=True,
    )


def handle_file_context(args: argparse.Namespace, config: VulSORConfig) -> int:
    try:
        if args.limit is not None and args.limit < 1:
            raise ValueError("limit must be >= 1")
        if args.pairs.resolve() == args.output.resolve():
            raise ValueError("pairs and output paths must differ")
        report = (
            args.report
            or args.dataset_root / "context" / "file-context-report.json"
        )
        joern = JoernAdapter(config)
        service = FileContextService(
            PrimeVulFileSourceResolver(args.dataset_root / "context" / "files"),
            FileCpgCache(args.dataset_root / "context" / "file-cpg", joern),
            joern,
            dataset_root=args.dataset_root,
        )
        progress = _file_context_progress if args.progress else None
        print(
            json.dumps(
                service.build_jsonl(
                    args.pairs,
                    args.file_info,
                    args.output,
                    limit=args.limit,
                    report=report,
                    progress=progress,
                )
            )
        )
        return 0
    except (OSError, ValueError, TypeError, KeyError, JoernError):
        print(
            json.dumps(
                {
                    "status": "unavailable",
                    "error": (
                        "Repository context command failed; verify inputs, metadata "
                        "and tool availability"
                    ),
                }
            )
        )
        return 1


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config(args.config)
    return args.handler(args, config)
