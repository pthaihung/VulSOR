import hashlib
import json
import os
import stat
import subprocess
import time
from pathlib import Path
from typing import Literal, cast

import pytest
from pydantic import ValidationError

from vulsor.config import RepositoryContextConfig
from vulsor.repository_context.cpg_cache import (
    CpgArtifact,
    CpgCache,
    CpgCacheCleanupError,
    CpgCacheError,
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


def write_ready_cpg(directory: Path) -> None:
    (directory / "cpg.bin").write_bytes(b"ready")


def test_identity_requires_nonblank_fields_and_full_revision() -> None:
    with pytest.raises(ValidationError):
        CpgIdentity(
            repository_url=" ",
            revision="abc123",
            joern_version="2.0.0",
        )


def test_identity_canonicalizes_repository_url_and_revision(tmp_path: Path) -> None:
    first = identity(
        repository_url="HTTPS://EXAMPLE.test:443/acme/demo.git/",
        revision="A" * 40,
    )
    second = identity(
        repository_url="https://example.test/acme/demo.git",
        revision="a" * 40,
    )

    assert first.repository_url == "https://example.test/acme/demo.git"
    assert first.revision == "a" * 40
    assert first == second
    cache = CpgCache(cache_root=tmp_path)
    assert cache.cache_key_for(first) == cache.cache_key_for(second)


@pytest.mark.parametrize(
    "repository_url",
    (
        "https:///acme/demo.git",
        "https://example.test:not-a-port/acme/demo.git",
    ),
)
def test_identity_rejects_malformed_repository_urls(repository_url: str) -> None:
    with pytest.raises(ValidationError):
        identity(repository_url=repository_url)


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


def test_cache_key_is_sha256_of_sorted_ascii_json_identity(tmp_path: Path) -> None:
    cache = CpgCache(cache_root=tmp_path)
    current = identity(joern_version="joern-β", frontend_args=("--define", "π=1"))
    serialized = json.dumps(
        current.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
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


def test_read_waits_for_per_key_lock_even_when_entry_is_ready(tmp_path: Path) -> None:
    cache = CpgCache(
        RepositoryContextConfig(cache_root=tmp_path, lock_timeout_seconds=1)
    )
    current = identity()
    cache.get_or_build(current, write_ready_cpg)
    lock_path = cache.lock_path_for(current)
    lock_path.write_text(
        f"pid={os.getpid()}\ncreated_at={time.time()}\n",
        encoding="utf-8",
    )

    with pytest.raises(CpgCacheLockTimeoutError):
        cache.read(current)

    assert lock_path.exists()


def test_get_or_build_waits_for_per_key_lock_before_ready_fast_path(
    tmp_path: Path,
) -> None:
    cache = CpgCache(
        RepositoryContextConfig(cache_root=tmp_path, lock_timeout_seconds=1)
    )
    current = identity()
    cache.get_or_build(current, write_ready_cpg)
    lock_path = cache.lock_path_for(current)
    lock_path.write_text(
        f"pid={os.getpid()}\ncreated_at={time.time()}\n",
        encoding="utf-8",
    )

    with pytest.raises(CpgCacheLockTimeoutError):
        cache.get_or_build(current, lambda _: pytest.fail("builder must not run"))

    assert lock_path.exists()


def _symlink_or_skip(link: Path, target: Path) -> None:
    try:
        link.symlink_to(target)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable in this environment")


def _junction_or_skip(link: Path, target: Path) -> None:
    if os.name != "nt":
        pytest.skip("Windows junctions are unavailable on this platform")
    try:
        result = subprocess.run(
            ["cmd.exe", "/d", "/c", "mklink", "/J", str(link), str(target)],
            capture_output=True,
            check=False,
            encoding="utf-8",
            errors="replace",
            shell=False,
        )
    except OSError:
        pytest.skip("Windows junction creation is unavailable in this environment")
    if result.returncode != 0:
        pytest.skip("Windows junction creation is unavailable in this environment")


def _remove_junction(path: Path) -> None:
    if os.name == "nt" and os.path.lexists(path):
        os.rmdir(path)


def test_cache_initialization_rejects_preexisting_junction_ancestor(
    tmp_path: Path,
) -> None:
    outside = tmp_path / "outside"
    outside.mkdir()
    redirected_parent = tmp_path / "cache-parent"
    _junction_or_skip(redirected_parent, outside)
    cache_root = redirected_parent / "cache-root"

    try:
        with pytest.raises(CpgCacheError, match="cache path|junction|reparse"):
            CpgCache(cache_root=cache_root)
        assert not (outside / "cache-root").exists()
        assert not (outside / "cache-root" / "cpg").exists()
    finally:
        _remove_junction(redirected_parent)


def test_ready_entry_with_symlink_descendant_is_rejected(tmp_path: Path) -> None:
    cache = CpgCache(cache_root=tmp_path)
    current = identity()
    cache.get_or_build(current, write_ready_cpg)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")
    _symlink_or_skip(cache.entry_path_for(current) / "escape", outside)

    with pytest.raises(CpgCacheError, match="symlink"):
        cache.read(current)


def test_builder_symlink_descendant_is_rejected_and_not_promoted(
    tmp_path: Path,
) -> None:
    cache = CpgCache(cache_root=tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("outside", encoding="utf-8")

    def build(directory: Path) -> None:
        (directory / "cpg.bin").write_bytes(b"ready")
        _symlink_or_skip(directory / "escape", outside)

    with pytest.raises(CpgCacheError, match="symlink"):
        cache.get_or_build(identity(), build)

    assert cache.read(identity()) is None
    assert not list((tmp_path / "cpg").glob("*.building-*"))


def test_builder_junction_descendant_is_rejected_without_touching_target(
    tmp_path: Path,
) -> None:
    cache = CpgCache(cache_root=tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    outside_file = outside / "read-only.txt"
    outside_file.write_text("outside", encoding="utf-8")
    os.chmod(outside_file, stat.S_IREAD)
    target_mode = stat.S_IMODE(os.stat(outside_file).st_mode)

    def build(directory: Path) -> None:
        (directory / "cpg.bin").write_bytes(b"ready")
        _junction_or_skip(directory / "outside", outside)

    with pytest.raises(CpgCacheError, match="symlink|junction|reparse"):
        cache.get_or_build(identity(), build)

    assert stat.S_IMODE(os.stat(outside_file).st_mode) == target_mode
    assert not list((tmp_path / "cpg").glob("*.building-*"))


def test_replaced_cache_directory_junction_is_rejected_before_lock_creation(
    tmp_path: Path,
) -> None:
    cache = CpgCache(cache_root=tmp_path)
    outside = tmp_path / "outside"
    outside.mkdir()
    cache.cache_dir.rmdir()
    _junction_or_skip(cache.cache_dir, outside)

    try:
        with pytest.raises(CpgCacheError, match="cache directory|junction|reparse"):
            cache.read(identity())
        assert not list(outside.glob(".*.lock"))
    finally:
        _remove_junction(cache.cache_dir)


def test_replaced_cache_root_junction_is_rejected_before_lock_or_build(
    tmp_path: Path,
) -> None:
    cache_root = tmp_path / "cache-root"
    cache = CpgCache(cache_root=cache_root)
    outside = tmp_path / "outside"
    outside_cpg = outside / "cpg"
    outside_cpg.mkdir(parents=True)
    cache.cache_dir.rmdir()
    cache.cache_root.rmdir()
    _junction_or_skip(cache.cache_root, outside)
    calls = 0

    def build(directory: Path) -> None:
        nonlocal calls
        calls += 1
        (directory / "cpg.bin").write_bytes(b"outside")

    try:
        with pytest.raises(CpgCacheError, match="cache directory|junction|reparse"):
            cache.get_or_build(identity(), build)
        assert calls == 0
        assert not list(outside_cpg.glob(".*.lock"))
        assert not list(outside_cpg.glob("*.building-*"))
    finally:
        _remove_junction(cache.cache_root)


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


def test_builder_failure_cleans_read_only_temporary_files(tmp_path: Path) -> None:
    cache = CpgCache(cache_root=tmp_path)
    current = identity()

    def build(building_dir: Path) -> None:
        read_only = building_dir / "read-only.txt"
        read_only.write_text("cleanup me", encoding="utf-8")
        os.chmod(read_only, stat.S_IREAD)
        raise RuntimeError("Joern failed")

    with pytest.raises(RuntimeError, match="Joern failed"):
        cache.get_or_build(current, build)

    assert cache.read(current) is None
    assert not list((tmp_path / "cpg").glob("*.building-*"))


def test_invalid_read_only_cache_entry_is_replaced(tmp_path: Path) -> None:
    cache = CpgCache(cache_root=tmp_path)
    current = identity()
    entry = cache.entry_path_for(current)
    entry.mkdir(parents=True)
    stale_cpg = entry / "cpg.bin"
    stale_cpg.write_bytes(b"stale")
    os.chmod(stale_cpg, stat.S_IREAD)

    result = cache.get_or_build(current, write_ready_cpg)

    assert result.cache_hit is False
    assert result.cpg_path.read_bytes() == b"ready"
    assert cache.read(current) is not None


def test_cleanup_failures_are_typed(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cache = CpgCache(cache_root=tmp_path)

    def fail_rmtree(*_: object, **__: object) -> None:
        raise PermissionError("read-only cache")

    monkeypatch.setattr("vulsor.repository_context.cpg_cache.shutil.rmtree", fail_rmtree)

    def build(building_dir: Path) -> None:
        (building_dir / "cpg.bin").write_bytes(b"partial")
        raise RuntimeError("builder failed")

    with pytest.raises(CpgCacheCleanupError, match="temporary CPG"):
        cache.get_or_build(identity(), build)

    assert not cache.entry_path_for(identity()).exists()


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
