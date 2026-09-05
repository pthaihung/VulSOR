"""Standalone repository context commands, independent of B1/B2."""

import argparse
import json
from pathlib import Path

import yaml

from vulsor.config import VulSORConfig
from vulsor.datasets import iter_dataset_samples
from .cpg_cache import CpgCache, CpgCacheError, CpgManifest
from .git_repository import GitRepositoryResolver, RepositoryResolutionError
from .index import RepositoryIndex, _atomic_write_text
from .joern import JoernAdapter, JoernError
from .models import EvidenceRequest
from .primevul_index import PrimeVulFieldMap, normalize_primevul_jsonl
from .service import RepositoryContextService, RepositoryPreparationError


def add_parser(subparsers):
    parser = subparsers.add_parser(
        "repo-context", help="Prepare and query repository context"
    )
    actions = parser.add_subparsers(dest="repo_action", required=True)
    index = actions.add_parser("index")
    index.add_argument("--config", type=Path)
    for flag in ("source", "field-map", "output", "rejects"):
        index.add_argument("--" + flag, required=True, type=Path)
    index.set_defaults(handler=handle)
    for action in ("prepare", "query", "status"):
        command = actions.add_parser(action)
        command.add_argument("--config", type=Path)
        command.add_argument("--dataset", required=True)
        command.add_argument(
            "--split", required=True, choices=("train", "valid", "test")
        )
        command.add_argument("--sample", required=True)
        if action == "query":
            command.add_argument("--request", type=Path, required=True)
            command.add_argument("--output", type=Path, required=True)
        command.set_defaults(handler=handle)


def _index(config, args):
    dataset = config.datasets.get(args.dataset)
    if dataset is None or dataset.repository_index_dir is None:
        raise ValueError("Dataset repository_index_dir must be configured")
    return RepositoryIndex.load(dataset.repository_index_dir / f"{args.split}.jsonl")


def _status(config, index, sample_id):
    """Read existing artifacts only; no cache/resolver constructors or tools."""
    record = index.get(sample_id)
    matches = []
    cache_dir = config.repository_context.cache_root / "cpg"
    if (
        cache_dir.is_dir()
        and not cache_dir.is_symlink()
        and not getattr(cache_dir, "is_junction", lambda: False)()
    ):
        for manifest_path in cache_dir.glob("*/manifest.json"):
            if any(
                path.is_symlink() or getattr(path, "is_junction", lambda: False)()
                for path in (manifest_path, manifest_path.parent)
            ):
                continue
            try:
                manifest = CpgManifest.model_validate_json(
                    manifest_path.read_text(encoding="utf-8")
                )
                artifact = manifest_path.parent / "cpg.bin"
                if (
                    manifest.schema_version == 1
                    and manifest.identity.revision == record.repository.revision.lower()
                    and manifest.identity.repository_url
                    == _canonical_url(record.repository.repository_url)
                    and manifest.cache_key == CpgCache.cache_key_for(manifest.identity)
                    and manifest_path.parent.name == manifest.cache_key
                    and not artifact.is_symlink()
                    and artifact.is_file()
                    and artifact.stat().st_size == manifest.cpg_size_bytes
                ):
                    matches.append(manifest.cache_key)
            except (OSError, ValueError):
                continue
    return {
        "sample_id": sample_id,
        "revision": record.repository.revision,
        "cpg_cache_keys": sorted(matches),
        "smoke_validated": False,
    }


def _canonical_url(url):
    from .git_repository import canonicalize_repository_url

    return canonicalize_repository_url(url)


def handle(args: argparse.Namespace, config: VulSORConfig) -> int:
    try:
        if (
            args.repo_action == "query"
            and args.output.resolve() == args.request.resolve()
        ):
            raise ValueError("Request and evidence output paths must differ")
        if args.repo_action == "index":
            mapping = yaml.safe_load(args.field_map.read_text(encoding="utf-8"))
            field_map = PrimeVulFieldMap(**mapping)
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.rejects.parent.mkdir(parents=True, exist_ok=True)
            normalize_primevul_jsonl(args.source, args.output, args.rejects, field_map)
            counts = {
                "accepted": len(RepositoryIndex.load(args.output)),
                "rejected": len(args.rejects.read_text(encoding="utf-8").splitlines()),
            }
            print(json.dumps(counts))
            return 0
        index = _index(config, args)
        if args.repo_action == "status":
            print(json.dumps(_status(config, index, args.sample)))
            return 0
        sample = next(
            iter_dataset_samples(
                config, args.dataset, args.split, sample_id=args.sample
            )
        )
        service = RepositoryContextService(
            index,
            GitRepositoryResolver(
                config.repository_context, git_executable=config.tools.git
            ),
            CpgCache(config.repository_context),
            JoernAdapter(config),
        )
        if args.repo_action == "prepare":
            prepared = service.prepare_sample(sample.sample_id, sample.code)
            print(
                json.dumps(
                    {
                        "sample_id": sample.sample_id,
                        "revision": prepared.resolved_revision,
                        "source_match": prepared.source_match.status.value,
                        "cache_key": prepared.cpg.cache_key,
                        "cache_hit": prepared.cpg.cache_hit,
                    }
                )
            )
            return 0
        request = EvidenceRequest.model_validate_json(
            args.request.read_text(encoding="utf-8")
        )
        result = service.retrieve(request, sample.code, sample_id=sample.sample_id)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        _atomic_write_text(args.output, result.model_dump_json(indent=2) + "\n")
        print(
            json.dumps(
                {"status": result.status.value, "evidence_items": len(result.evidence)}
            )
        )
        return 1 if result.status == "unavailable" else 0
    except (
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RepositoryPreparationError,
        RepositoryResolutionError,
        CpgCacheError,
        JoernError,
    ):
        # CLI failures must not serialize dataset records, credentials or host paths.
        print(
            json.dumps(
                {
                    "status": "unavailable",
                    "error": "Repository context command failed; verify inputs, metadata and tool availability",
                }
            )
        )
        return 1
