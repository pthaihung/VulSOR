import hashlib
import json
import os
import time
from pathlib import Path
from typing import Literal, cast

import pytest
from pydantic import ValidationError

from vulsor.config import RepositoryContextConfig
from vulsor.repository_context.cpg_cache import (
    CpgArtifact,
    CpgCache,
    CpgCacheLockTimeoutError,
    CpgIdentity,
    CpgManifest,
)


def identity(**overrides: object) -> CpgIdentity:
    values: dict[str, object] = {
        "repository_url": "https://example.test/acme/demo.git",
        "revision": "a" * 40,
        "joern_version": "2.0.0",
        "frontend": "C",
        "frontend_args": ("--language", "c", "--define", "FEATURE=1"),
    }
    values.update(overrides)
    return CpgIdentity(
        repository_url=cast(str, values["repository_url"]),
        revision=cast(str, values["revision"]),
        joern_version=cast(str, values["joern_version"]),
        frontend=cast(str, values["frontend"]),
        frontend_args=cast(tuple[str, ...], values["frontend_args"]),
    )


def test_identity_requires_nonblank_fields_and_full_revision() -> None:
    with pytest.raises(ValidationError):
        CpgIdentity(
            repository_url=" ",
            revision="abc123",
            joern_version="2.0.0",
        )


@pytest.mark.parametrize(
    "changed",
    (
        {"repository_url": "https://example.test/acme/other.git"},
        {"revision": "b" * 40},
        {"joern_version": "2.1.0"},
        {"frontend": "cpp"},
        {"frontend_args": ("--language", "cpp")},
    ),
)
def test_each_cpg_identity_change_changes_cache_key(
    tmp_path: Path,
    changed: dict[str, object],
) -> None:
    cache = CpgCache(cache_root=tmp_path)

    assert cache.cache_key_for(identity()) != cache.cache_key_for(identity(**changed))


def test_cache_key_is_sha256_of_sorted_json_identity(tmp_path: Path) -> None:
    cache = CpgCache(cache_root=tmp_path)
    current = identity()
    serialized = json.dumps(
        current.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")

    assert cache.cache_key_for(current) == hashlib.sha256(serialized).hexdigest()


def test_incomplete_manifest_or_empty_cpg_is_a_cache_miss(tmp_path: Path) -> None:
    cache = CpgCache(cache_root=tmp_path)
    current = identity()
    key = cache.cache_key_for(current)
    entry = cache.entry_path_for(current)
    entry.mkdir(parents=True)
    (entry / "cpg.bin").write_bytes(b"")
    (entry / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "cache_key": key,
                "identity": current.model_dump(mode="json"),
                "status": "ready",
                "cpg_size_bytes": 0,
            }
        ),
        encoding="utf-8",
    )

    assert cache.read(current) is None

    (entry / "cpg.bin").write_bytes(b"valid cpg")
    (entry / "manifest.json").write_text(
        json.dumps(
            {
                "cache_key": key,
                "identity": current.model_dump(mode="json"),
                "status": "ready",
                "cpg_size_bytes": 9,
            }
        ),
        encoding="utf-8",
    )

    assert cache.read(current) is None

    (entry / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "cache_key": key,
                "identity": current.model_dump(mode="json"),
                "status": "ready",
                "cpg_size_bytes": 999,
            }
        ),
        encoding="utf-8",
    )

    assert cache.read(current) is None


def test_two_calls_reuse_one_completed_entry(tmp_path: Path) -> None:
    cache = CpgCache(
        RepositoryContextConfig(cache_root=tmp_path, lock_timeout_seconds=1)
    )
    calls = 0

    def build(building_dir: Path) -> None:
        nonlocal calls
        calls += 1
        (building_dir / "cpg.bin").write_bytes(b"cpg bytes")

    first = cache.get_or_build(identity(), build)
    second = cache.get_or_build(identity(), build)

    assert isinstance(first, CpgArtifact)
    assert first.cache_hit is False
    assert second.cache_hit is True
    assert first.cache_key == second.cache_key
    assert first.root == second.root
    assert first.cpg_path == second.cpg_path
    assert calls == 1
    assert second.cpg_path.read_bytes() == b"cpg bytes"


def test_builder_exception_cleans_temporary_and_leaves_no_ready_entry(
    tmp_path: Path,
) -> None:
    cache = CpgCache(cache_root=tmp_path)
    current = identity()

    def build(building_dir: Path) -> None:
        (building_dir / "cpg.bin").write_bytes(b"partial")
        raise RuntimeError("Joern failed")

    with pytest.raises(RuntimeError, match="Joern failed"):
        cache.get_or_build(current, build)

    assert cache.read(current) is None
    assert not cache.entry_path_for(current).exists()
    assert not list(tmp_path.glob("*.building-*"))
    assert not list(tmp_path.glob("cpg/*.building-*"))


def test_build_output_must_be_nonempty_regular_cpg_file(tmp_path: Path) -> None:
    cache = CpgCache(cache_root=tmp_path)

    with pytest.raises(ValueError, match="cpg.bin"):
        cache.get_or_build(identity(), lambda _: None)

    assert cache.read(identity()) is None


def test_lock_timeout_reports_age_and_recorded_pid(tmp_path: Path) -> None:
    cache = CpgCache(
        RepositoryContextConfig(cache_root=tmp_path, lock_timeout_seconds=1)
    )
    current = identity()
    lock_path = cache.lock_path_for(current)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    created_at = time.time() - 10
    lock_path.write_text(
        f"pid={os.getpid()}\ncreated_at={created_at}\n",
        encoding="utf-8",
    )

    with pytest.raises(CpgCacheLockTimeoutError) as caught:
        cache.get_or_build(current, lambda _: None)

    assert caught.value.recorded_pid == os.getpid()
    assert caught.value.lock_age_seconds >= 9
    assert lock_path.exists()


def test_manifest_model_rejects_nonready_or_invalid_size() -> None:
    current = identity()

    with pytest.raises(ValidationError):
        CpgManifest(
            cache_key="a" * 64,
            identity=current,
            status=cast(Literal["ready"], "building"),
            cpg_size_bytes=1,
        )
    with pytest.raises(ValidationError):
        CpgManifest(cache_key="a" * 64, identity=current, cpg_size_bytes=0)
