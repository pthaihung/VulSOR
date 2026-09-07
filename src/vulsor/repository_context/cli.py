"""Offline repository-context preprocessing and query-only runtime commands."""

import argparse
import json
from pathlib import Path

import yaml

from vulsor.config import DatasetConfig, VulSORConfig
from vulsor.datasets import iter_dataset_samples
from .cpg_cache import CpgCache, CpgCacheError, read_ready_cpg
from .clang_function import extract_function_name
from .git_repository import GitRepositoryResolver, RepositoryResolutionError
from .index import RepositoryIndex, _atomic_write_text
from .joern import JoernAdapter, JoernError
from .models import EvidenceRequest, UnresolvedPreparedRecord
from .prepared import PreparedCatalog, configured_catalog_paths, load_unresolved_catalog, write_prepared_catalog, write_unresolved_catalog
from .primevul_index import PrimeVulFieldMap, normalize_primevul_jsonl
from .primevul_import import import_primevul_test
from .prebuilt_context import PrebuiltContextStore
from .file_context_service import FileContextResult, FileContextService
from .file_cpg import FileCpgCache
from .primevul_file_source import PrimeVulFileSourceResolver
from .prompt_context import DEFAULT_MAX_CONTEXT_CHARACTERS, load_prompt_context, upsert_prompt_context
from .service import RepositoryContextQueryService, RepositoryPreparationError, RepositoryPreprocessor


def _context_character_limit(value: str) -> int:
    try:
        limit = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= limit <= DEFAULT_MAX_CONTEXT_CHARACTERS:
        raise argparse.ArgumentTypeError(
            f"must be between 1 and {DEFAULT_MAX_CONTEXT_CHARACTERS}"
        )
    return limit


def add_parser(subparsers):
    file_context = subparsers.add_parser("file-context", help="Build offline file-level PrimeVul context")
    file_actions = file_context.add_subparsers(dest="file_action", required=True)
    build = file_actions.add_parser("build")
    build.add_argument("--config", type=Path)
    build.add_argument("--pairs", required=True, type=Path)
    build.add_argument("--file-info", required=True, type=Path)
    build.add_argument("--dataset-root", required=True, type=Path)
    build.add_argument("--output", required=True, type=Path)
    build.add_argument("--report", type=Path)
    build.add_argument("--limit", type=int)
    build.add_argument("--progress", action="store_true")
    build.set_defaults(handler=handle)
    parser = subparsers.add_parser("repo-context", help="Preprocess and query repository context")
    actions = parser.add_subparsers(dest="repo_action", required=True)
    index = actions.add_parser("index")
    index.add_argument("--config", type=Path)
    for flag in ("source", "field-map", "output", "rejects"):
        index.add_argument("--" + flag, required=True, type=Path)
    index.set_defaults(handler=handle)
    importer = actions.add_parser("import-primevul")
    importer.add_argument("--config", type=Path)
    importer.add_argument("--source", required=True, type=Path)
    importer.add_argument("--file-info", required=True, type=Path)
    importer.add_argument("--output-root", required=True, type=Path)
    importer.set_defaults(handler=handle)
    preprocess = actions.add_parser("preprocess")
    preprocess.add_argument("--config", type=Path)
    preprocess.add_argument("--dataset", required=True)
    preprocess.add_argument("--split", required=True, choices=("train", "valid", "test"))
    selection = preprocess.add_mutually_exclusive_group(required=True)
    selection.add_argument("--sample")
    selection.add_argument("--all", action="store_true")
    preprocess.set_defaults(handler=handle)
    build_context = actions.add_parser("build-context")
    build_context.add_argument("--config", type=Path)
    build_context.add_argument("--dataset", required=True)
    build_context.add_argument("--split", required=True, choices=("train", "valid", "test"))
    build_context.add_argument("--sample", required=True)
    build_context.add_argument("--output", required=True, type=Path)
    build_context.add_argument(
        "--max-characters",
        type=_context_character_limit,
        default=DEFAULT_MAX_CONTEXT_CHARACTERS,
    )
    build_context.set_defaults(handler=handle)
    show_context = actions.add_parser("show-context")
    show_context.add_argument("--sample", required=True)
    show_context.add_argument("--input", required=True, type=Path)
    show_context.set_defaults(handler=handle)
    for action in ("query", "status"):
        command = actions.add_parser(action)
        command.add_argument("--config", type=Path)
        command.add_argument("--dataset", required=True)
        command.add_argument("--split", required=True, choices=("train", "valid", "test"))
        command.add_argument("--sample", required=True)
        if action == "query":
            command.add_argument("--request", type=Path, required=True)
            command.add_argument("--output", type=Path, required=True)
        command.set_defaults(handler=handle)


def _repository_index_path(dataset: DatasetConfig, split: str) -> Path:
    explicit = dataset.repository_index_files.get(split)
    if explicit is not None:
        return explicit
    if dataset.repository_index_dir is None:
        raise ValueError("Dataset repository index must be configured")
    return dataset.repository_index_dir / f"{split}.jsonl"


def _index(config: VulSORConfig, args: argparse.Namespace) -> RepositoryIndex:
    dataset = config.datasets.get(args.dataset)
    if dataset is None:
        raise ValueError("Dataset is not configured")
    return RepositoryIndex.load(_repository_index_path(dataset, args.split))


def _status(config: VulSORConfig, index: RepositoryIndex, args: argparse.Namespace) -> dict:
    ready_path, unresolved_path = configured_catalog_paths(config.repository_context, args.dataset, args.split)
    prepared = PreparedCatalog.load(ready_path).get_or_none(args.sample)
    unresolved = {item.sample_id: item for item in load_unresolved_catalog(unresolved_path)}
    return {"sample_id": args.sample, "revision": index.get(args.sample).repository.revision, "prepared": prepared is not None, "unresolved_kind": unresolved.get(args.sample).kind if args.sample in unresolved else None, "cpg_ready": bool(prepared and read_ready_cpg(config.repository_context.cache_root, prepared))}


def _preprocess(config: VulSORConfig, index: RepositoryIndex, args: argparse.Namespace) -> int:
    ready_path, unresolved_path = configured_catalog_paths(config.repository_context, args.dataset, args.split)
    existing_ready = {item.sample_id: item for item in PreparedCatalog.load(ready_path).records()}
    existing_unresolved = {item.sample_id: item for item in load_unresolved_catalog(unresolved_path)}
    samples = iter_dataset_samples(config, args.dataset, args.split, sample_id=None if args.all else args.sample)
    service = RepositoryPreprocessor(index, GitRepositoryResolver(config.repository_context, git_executable=config.tools.git), CpgCache(config.repository_context), JoernAdapter(config))
    processed = ready_count = unresolved_count = 0
    for sample in samples:
        processed += 1
        try:
            record = service.preprocess_sample(sample.sample_id, sample.code)
        except RepositoryPreparationError as exc:
            existing_ready.pop(sample.sample_id, None)
            existing_unresolved[sample.sample_id] = UnresolvedPreparedRecord(sample_id=sample.sample_id, kind=exc.kind)
            unresolved_count += 1
        else:
            existing_ready[sample.sample_id] = record
            existing_unresolved.pop(sample.sample_id, None)
            ready_count += 1
    write_prepared_catalog(existing_ready.values(), ready_path)
    write_unresolved_catalog(existing_unresolved.values(), unresolved_path)
    print(json.dumps({"processed": processed, "ready": ready_count, "unresolved": unresolved_count}))
    return 0


def _build_context(config: VulSORConfig, index: RepositoryIndex, args: argparse.Namespace) -> int:
    sample = next(
        iter_dataset_samples(config, args.dataset, args.split, sample_id=args.sample)
    )
    service = RepositoryPreprocessor(
        index,
        GitRepositoryResolver(config.repository_context, git_executable=config.tools.git),
        CpgCache(config.repository_context),
        JoernAdapter(config),
    )
    record = service.build_prompt_context(
        sample.sample_id,
        sample.code,
        max_characters=args.max_characters,
    )
    upsert_prompt_context(args.output, record)
    print(json.dumps({"sample_id": record.sample_id, "status": "built", "limitations": len(record.limitations)}))
    return 0


def _file_context_progress(current: int, total: int, result: FileContextResult) -> None:
    sample = result.record.get("idx", result.record.get("func_hash", "?"))
    detail = f" reason={result.reason}" if result.reason else ""
    ratio = current / total if total > 0 else 1.0
    percent = min(100, max(0, int(ratio * 100)))
    width = 24
    filled = int(width * percent / 100)
    bar = "#" * filled + "." * (width - filled)
    line = f"[{bar}] {percent}% {current}/{total} {result.status} sample={sample}{detail}"
    print(
        "\r" + line.ljust(120),
        end="\n" if current >= total else "",
        flush=True,
    )


def handle(args: argparse.Namespace, config: VulSORConfig) -> int:
    try:
        if getattr(args, "command", None) == "file-context":
            if args.limit is not None and args.limit < 1:
                raise ValueError("limit must be >= 1")
            if args.pairs.resolve() == args.output.resolve():
                raise ValueError("pairs and output paths must differ")
            report = args.report or args.dataset_root / "context" / "file-context-report.json"
            joern = JoernAdapter(config)
            service = FileContextService(
                PrimeVulFileSourceResolver(args.dataset_root / "context" / "files"),
                FileCpgCache(args.dataset_root / "context" / "file-cpg", joern),
                joern,
                dataset_root=args.dataset_root,
            )
            progress = _file_context_progress if args.progress else None
            print(json.dumps(service.build_jsonl(args.pairs, args.file_info, args.output, limit=args.limit, report=report, progress=progress)))
            return 0
        if args.repo_action == "show-context":
            record = load_prompt_context(args.input, args.sample)
            if record is None:
                print(json.dumps({"sample_id": args.sample, "context": "", "limitations": ["repository_context_unavailable"]}))
            else:
                print(record.model_dump_json())
            return 0
        if args.repo_action == "import-primevul":
            repositories = GitRepositoryResolver(
                config.repository_context, git_executable=config.tools.git
            )
            summary = import_primevul_test(
                args.source,
                args.file_info,
                args.output_root,
                lambda code, suffix: extract_function_name(
                    code, suffix, clang_executable=config.tools.clang
                ),
                resolve_parent_revision=repositories.resolve_parent_revision,
            )
            print(json.dumps({"accepted": summary.accepted, "rejected": summary.rejected}))
            return 0
        if args.repo_action == "query" and args.output.resolve() == args.request.resolve():
            raise ValueError("Request and evidence output paths must differ")
        if args.repo_action == "index":
            mapping = yaml.safe_load(args.field_map.read_text(encoding="utf-8"))
            field_map = PrimeVulFieldMap(**mapping)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.rejects.parent.mkdir(parents=True, exist_ok=True)
            normalize_primevul_jsonl(args.source, args.output, args.rejects, field_map)
            print(json.dumps({"accepted": len(RepositoryIndex.load(args.output)), "rejected": len(args.rejects.read_text(encoding="utf-8").splitlines())}))
            return 0
        index = _index(config, args)
        if args.repo_action == "status":
            print(json.dumps(_status(config, index, args)))
            return 0
        if args.repo_action == "preprocess":
            return _preprocess(config, index, args)
        if args.repo_action == "build-context":
            return _build_context(config, index, args)
        sample = next(iter_dataset_samples(config, args.dataset, args.split, sample_id=args.sample))
        ready_path, _ = configured_catalog_paths(config.repository_context, args.dataset, args.split)
        request = EvidenceRequest.model_validate_json(args.request.read_text(encoding="utf-8"))
        result = RepositoryContextQueryService(index, PreparedCatalog.load(ready_path), config.repository_context.cache_root, JoernAdapter(config)).retrieve(request, sample.code, sample_id=sample.sample_id)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(args.output, result.model_dump_json(indent=2) + "\n")
        print(json.dumps({"status": result.status.value, "evidence_items": len(result.evidence)}))
        return 1 if result.status == "unavailable" else 0
    except (OSError, ValueError, TypeError, KeyError, RepositoryResolutionError, CpgCacheError, JoernError):
        print(json.dumps({"status": "unavailable", "error": "Repository context command failed; verify inputs, metadata and tool availability"}))
        return 1
