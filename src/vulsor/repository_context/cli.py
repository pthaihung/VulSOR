"""Offline repository-context preprocessing and query-only runtime commands."""

import argparse
import json
from pathlib import Path

import yaml

from vulsor.config import DatasetConfig, VulSORConfig
from vulsor.datasets import iter_dataset_samples
from .cpg_cache import CpgCache, CpgCacheError, read_ready_cpg
from .git_repository import GitRepositoryResolver, RepositoryResolutionError
from .index import RepositoryIndex, _atomic_write_text
from .joern import JoernAdapter, JoernError
from .models import EvidenceRequest, UnresolvedPreparedRecord
from .prepared import PreparedCatalog, load_unresolved_catalog, prepared_catalog_paths, write_prepared_catalog, write_unresolved_catalog
from .primevul_index import PrimeVulFieldMap, normalize_primevul_jsonl
from .service import RepositoryContextQueryService, RepositoryPreparationError, RepositoryPreprocessor


def add_parser(subparsers):
    parser = subparsers.add_parser("repo-context", help="Preprocess and query repository context")
    actions = parser.add_subparsers(dest="repo_action", required=True)
    index = actions.add_parser("index")
    index.add_argument("--config", type=Path)
    for flag in ("source", "field-map", "output", "rejects"):
        index.add_argument("--" + flag, required=True, type=Path)
    index.set_defaults(handler=handle)
    preprocess = actions.add_parser("preprocess")
    preprocess.add_argument("--config", type=Path)
    preprocess.add_argument("--dataset", required=True)
    preprocess.add_argument("--split", required=True, choices=("train", "valid", "test"))
    selection = preprocess.add_mutually_exclusive_group(required=True)
    selection.add_argument("--sample")
    selection.add_argument("--all", action="store_true")
    preprocess.set_defaults(handler=handle)
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
    ready_path, unresolved_path = prepared_catalog_paths(config.repository_context.cache_root, args.dataset, args.split)
    prepared = PreparedCatalog.load(ready_path).get_or_none(args.sample)
    unresolved = {item.sample_id: item for item in load_unresolved_catalog(unresolved_path)}
    return {"sample_id": args.sample, "revision": index.get(args.sample).repository.revision, "prepared": prepared is not None, "unresolved_kind": unresolved.get(args.sample).kind if args.sample in unresolved else None, "cpg_ready": bool(prepared and read_ready_cpg(config.repository_context.cache_root, prepared))}


def _preprocess(config: VulSORConfig, index: RepositoryIndex, args: argparse.Namespace) -> int:
    ready_path, unresolved_path = prepared_catalog_paths(config.repository_context.cache_root, args.dataset, args.split)
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


def handle(args: argparse.Namespace, config: VulSORConfig) -> int:
    try:
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
        sample = next(iter_dataset_samples(config, args.dataset, args.split, sample_id=args.sample))
        ready_path, _ = prepared_catalog_paths(config.repository_context.cache_root, args.dataset, args.split)
        request = EvidenceRequest.model_validate_json(args.request.read_text(encoding="utf-8"))
        result = RepositoryContextQueryService(index, PreparedCatalog.load(ready_path), config.repository_context.cache_root, JoernAdapter(config)).retrieve(request, sample.code, sample_id=sample.sample_id)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(args.output, result.model_dump_json(indent=2) + "\n")
        print(json.dumps({"status": result.status.value, "evidence_items": len(result.evidence)}))
        return 1 if result.status == "unavailable" else 0
    except (OSError, ValueError, TypeError, KeyError, RepositoryResolutionError, CpgCacheError, JoernError):
        print(json.dumps({"status": "unavailable", "error": "Repository context command failed; verify inputs, metadata and tool availability"}))
        return 1
