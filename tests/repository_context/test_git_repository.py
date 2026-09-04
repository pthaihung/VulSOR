from __future__ import annotations

import hashlib
import os
import shutil
import stat
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Sequence

import pytest

from vulsor.config import RepositoryContextConfig
from vulsor.repository_context import git_repository as git_repository_module
from vulsor.repository_context.git_repository import (
    CommandResult,
    GitRepositoryResolver,
    RepositoryCleanupError,
    RepositoryCommandError,
    RepositoryCommandTimeoutError,
    RepositoryResolutionError,
    RepositoryRevisionNotFoundError,
    SubprocessCommandRunner,
    canonicalize_repository_url,
)
from vulsor.repository_context.models import RepositoryRef


pytestmark = pytest.mark.skipif(
    shutil.which("git") is None,
    reason="git is required for local repository tests",
)


def run_git(
    *arguments: str,
    cwd: Path | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", *arguments],
        cwd=cwd,
        check=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        shell=False,
        text=True,
    )


@pytest.fixture
def two_commit_repository(tmp_path: Path) -> tuple[Path, str, str]:
    repository = tmp_path / "source"
    repository.mkdir()
    run_git("init", "--initial-branch", "main", cwd=repository)
    run_git("config", "user.email", "tests@example.test", cwd=repository)
    run_git("config", "user.name", "VulSOR tests", cwd=repository)

    (repository / "old.txt").write_text("old revision\n", encoding="utf-8")
    run_git("add", "old.txt", cwd=repository)
    run_git("commit", "-m", "old revision", cwd=repository)
    old_revision = run_git("rev-parse", "HEAD", cwd=repository).stdout.strip()

    (repository / "new.txt").write_text("new revision\n", encoding="utf-8")
    run_git("add", "new.txt", cwd=repository)
    run_git("commit", "-m", "new revision", cwd=repository)
    new_revision = run_git("rev-parse", "HEAD", cwd=repository).stdout.strip()

    assert len(old_revision) == 40
    assert len(new_revision) == 40
    return repository, old_revision, new_revision


def repository_ref(repository: Path, revision: str) -> RepositoryRef:
    return RepositoryRef(
        repository_id="local",
        repository_url=repository.as_uri(),
        revision=revision,
    )


@pytest.fixture
def short_cache_root(
    tmp_path: Path,
    request: pytest.FixtureRequest,
) -> Path:
    """Keep Git's internal object paths below Windows' legacy path limit."""

    suffix = hashlib.sha256(str(tmp_path).encode("utf-8")).hexdigest()[:10]
    cache_root = Path(tmp_path.anchor) / f"vulsor-test-cache-{suffix}"

    def cleanup() -> None:
        if cache_root.exists():
            git_repository_module._remove_tree(cache_root)

    request.addfinalizer(cleanup)
    return cache_root


def test_resolve_materializes_requested_immutable_revisions(
    tmp_path: Path,
    two_commit_repository: tuple[Path, str, str],
) -> None:
    repository, old_revision, new_revision = two_commit_repository
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=tmp_path / "cache",
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        )
    )

    old = resolver.resolve(repository_ref(repository, old_revision))
    new = resolver.resolve(repository_ref(repository, new_revision))

    assert old.resolved_revision == old_revision
    assert new.resolved_revision == new_revision
    assert (old.repository_root / "old.txt").read_text(encoding="utf-8") == (
        "old revision\n"
    )
    assert not (old.repository_root / "new.txt").exists()
    assert (new.repository_root / "old.txt").exists()
    assert (new.repository_root / "new.txt").read_text(encoding="utf-8") == (
        "new revision\n"
    )
    assert old.mirror_root == new.mirror_root
    assert old.repository_root != new.repository_root
    assert run_git("-C", str(old.repository_root), "rev-parse", "HEAD").stdout.strip() == (
        old_revision
    )
    assert run_git("-C", str(new.repository_root), "rev-parse", "HEAD").stdout.strip() == (
        new_revision
    )

    mirrors = list((tmp_path / "cache" / "mirrors").glob("*.git"))
    assert mirrors == [old.mirror_root]


def test_materialized_checkout_is_read_only_and_reusable(
    two_commit_repository: tuple[Path, str, str],
    short_cache_root: Path,
) -> None:
    repository, revision, _ = two_commit_repository
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=short_cache_root,
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        )
    )

    resolved = resolver.resolve(repository_ref(repository, revision))
    tracked_file = resolved.repository_root / "old.txt"

    assert tracked_file.stat().st_mode & stat.S_IWRITE == 0
    assert (resolved.repository_root / ".git" / "HEAD").stat().st_mode & stat.S_IWRITE == 0
    cached = resolver.resolve(repository_ref(repository, revision))

    assert cached.repository_root == resolved.repository_root
    assert tracked_file.read_text(encoding="utf-8") == "old revision\n"
    git_repository_module._remove_tree(resolved.repository_root)
    assert not resolved.repository_root.exists()


def test_valid_checkout_restores_an_evicted_mirror(
    two_commit_repository: tuple[Path, str, str],
    short_cache_root: Path,
) -> None:
    repository, revision, _ = two_commit_repository
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=short_cache_root,
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        )
    )

    resolved = resolver.resolve(repository_ref(repository, revision))
    git_repository_module._remove_tree(resolved.mirror_root)
    assert not resolved.mirror_root.exists()

    restored = resolver.resolve(repository_ref(repository, revision))

    assert restored.mirror_root.is_dir()
    assert restored.repository_root == resolved.repository_root


def test_valid_checkout_without_mirror_fails_when_origin_is_offline(
    tmp_path: Path,
    two_commit_repository: tuple[Path, str, str],
    short_cache_root: Path,
) -> None:
    repository, revision, _ = two_commit_repository
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=short_cache_root,
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        )
    )

    resolved = resolver.resolve(repository_ref(repository, revision))
    git_repository_module._remove_tree(resolved.mirror_root)
    repository.rename(tmp_path / "offline-source")

    with pytest.raises(RepositoryResolutionError, match="mirror"):
        resolver.resolve(repository_ref(repository, revision))


def test_cached_revision_resolves_when_origin_is_unavailable(
    tmp_path: Path,
    two_commit_repository: tuple[Path, str, str],
) -> None:
    repository, revision, _ = two_commit_repository
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=tmp_path / "cache",
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        )
    )
    resolver.resolve(repository_ref(repository, revision))
    repository.rename(tmp_path / "offline-source")

    resolved = resolver.resolve(repository_ref(repository, revision))

    assert resolved.resolved_revision == revision
    assert (resolved.repository_root / "old.txt").read_text(encoding="utf-8") == (
        "old revision\n"
    )


def test_existing_mirror_materializes_revision_offline(
    tmp_path: Path,
    two_commit_repository: tuple[Path, str, str],
) -> None:
    repository, first_revision, second_revision = two_commit_repository
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=tmp_path / "cache",
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        )
    )
    resolver.resolve(repository_ref(repository, first_revision))
    repository.rename(tmp_path / "offline-source")

    resolved = resolver.resolve(repository_ref(repository, second_revision))

    assert resolved.resolved_revision == second_revision
    assert (resolved.repository_root / "new.txt").read_text(encoding="utf-8") == (
        "new revision\n"
    )


def test_existing_mirror_is_fetched_before_resolving_new_commit(
    tmp_path: Path,
    two_commit_repository: tuple[Path, str, str],
) -> None:
    repository, first_revision, _ = two_commit_repository
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=tmp_path / "cache",
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        )
    )

    resolver.resolve(repository_ref(repository, first_revision))
    (repository / "latest.txt").write_text("fetched revision\n", encoding="utf-8")
    run_git("add", "latest.txt", cwd=repository)
    run_git("commit", "-m", "fetched revision", cwd=repository)
    latest_revision = run_git("rev-parse", "HEAD", cwd=repository).stdout.strip()

    resolved = resolver.resolve(repository_ref(repository, latest_revision))

    assert (resolved.repository_root / "latest.txt").read_text(encoding="utf-8") == (
        "fetched revision\n"
    )


def test_dangling_mirror_object_is_not_revision_available(
    two_commit_repository: tuple[Path, str, str],
    short_cache_root: Path,
) -> None:
    repository, first_revision, second_revision = two_commit_repository
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=short_cache_root,
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        )
    )
    resolved = resolver.resolve(repository_ref(repository, first_revision))
    tree = run_git(
        "rev-parse",
        f"{second_revision}^{{tree}}",
        cwd=resolved.mirror_root,
    ).stdout.strip()
    environment = os.environ.copy()
    environment.update(
        {
            "GIT_AUTHOR_EMAIL": "tests@example.test",
            "GIT_AUTHOR_NAME": "VulSOR tests",
            "GIT_COMMITTER_EMAIL": "tests@example.test",
            "GIT_COMMITTER_NAME": "VulSOR tests",
        }
    )
    dangling = subprocess.run(
        [
            "git",
            "-C",
            str(resolved.mirror_root),
            "commit-tree",
            tree,
            "-p",
            second_revision,
            "-m",
            "dangling commit",
        ],
        check=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        env=environment,
        shell=False,
        text=True,
    ).stdout.strip()

    with pytest.raises(RepositoryRevisionNotFoundError):
        resolver.resolve(repository_ref(repository, dangling))


def test_mirror_refresh_and_revision_clone_are_serialized(
    tmp_path: Path,
    two_commit_repository: tuple[Path, str, str],
) -> None:
    repository, first_revision, second_revision = two_commit_repository
    base_resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=tmp_path / "cache",
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        )
    )
    base_resolver.resolve(repository_ref(repository, first_revision))
    (repository / "latest.txt").write_text("fetched revision\n", encoding="utf-8")
    run_git("add", "latest.txt", cwd=repository)
    run_git("commit", "-m", "fetched revision", cwd=repository)
    latest_revision = run_git("rev-parse", "HEAD", cwd=repository).stdout.strip()

    class SerializedRunner:
        def __init__(self) -> None:
            self.delegate = SubprocessCommandRunner()
            self.state_lock = threading.Lock()
            self.fetch_started = threading.Event()
            self.active_fetch = False
            self.active_clone = False
            self.violations: list[str] = []

        def run(
            self,
            arguments: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout: int | float | None = None,
        ) -> CommandResult:
            is_fetch = "fetch" in arguments
            is_revision_clone = "clone" in arguments and "--no-checkout" in arguments
            if is_fetch:
                with self.state_lock:
                    if self.active_clone:
                        self.violations.append("fetch overlapped clone")
                    self.active_fetch = True
                    self.fetch_started.set()
                time.sleep(0.1)
            if is_revision_clone:
                with self.state_lock:
                    if self.active_fetch:
                        self.violations.append("clone overlapped fetch")
                    self.active_clone = True
                time.sleep(0.2)
            try:
                return self.delegate.run(arguments, cwd=cwd, timeout=timeout)
            finally:
                with self.state_lock:
                    if is_fetch:
                        self.active_fetch = False
                    if is_revision_clone:
                        self.active_clone = False

    runner = SerializedRunner()
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=tmp_path / "cache",
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        ),
        runner=runner,
    )
    with ThreadPoolExecutor(max_workers=2) as executor:
        latest_future = executor.submit(
            resolver.resolve,
            repository_ref(repository, latest_revision),
        )
        assert runner.fetch_started.wait(timeout=5)
        second_future = executor.submit(
            resolver.resolve,
            repository_ref(repository, second_revision),
        )
        latest = latest_future.result()
        second = second_future.result()

    assert latest.resolved_revision == latest_revision
    assert second.resolved_revision == second_revision
    assert runner.violations == []


def test_dirty_cached_checkout_is_rebuilt(
    tmp_path: Path,
    two_commit_repository: tuple[Path, str, str],
    short_cache_root: Path,
) -> None:
    repository, revision, _ = two_commit_repository
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=short_cache_root,
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        )
    )

    resolved = resolver.resolve(repository_ref(repository, revision))
    git_repository_module._make_tree_writable(resolved.repository_root)
    (resolved.repository_root / "old.txt").write_text("tampered\n", encoding="utf-8")
    run_git("add", "old.txt", cwd=resolved.repository_root)
    (resolved.repository_root / "untracked.txt").write_text(
        "must be removed\n",
        encoding="utf-8",
    )

    rebuilt = resolver.resolve(repository_ref(repository, revision))

    assert rebuilt.repository_root == resolved.repository_root
    assert (rebuilt.repository_root / "old.txt").read_text(encoding="utf-8") == (
        "old revision\n"
    )
    assert not (rebuilt.repository_root / "untracked.txt").exists()
    assert run_git(
        "-C",
        str(rebuilt.repository_root),
        "--no-optional-locks",
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    ).stdout == ""


def test_non_detached_cached_checkout_is_rebuilt(
    tmp_path: Path,
    two_commit_repository: tuple[Path, str, str],
    short_cache_root: Path,
) -> None:
    repository, revision, _ = two_commit_repository
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=short_cache_root,
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        )
    )

    resolved = resolver.resolve(repository_ref(repository, revision))
    git_repository_module._make_tree_writable(resolved.repository_root)
    run_git("-C", str(resolved.repository_root), "switch", "-c", "tampered-branch")

    rebuilt = resolver.resolve(repository_ref(repository, revision))

    assert run_git(
        "-C",
        str(rebuilt.repository_root),
        "rev-parse",
        "--abbrev-ref",
        "HEAD",
    ).stdout.strip() == "HEAD"


def test_existing_mirror_must_have_requested_origin_url(
    tmp_path: Path,
    two_commit_repository: tuple[Path, str, str],
    short_cache_root: Path,
) -> None:
    repository, revision, _ = two_commit_repository
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=short_cache_root,
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        )
    )
    resolved = resolver.resolve(repository_ref(repository, revision))
    wrong_source = (tmp_path / "wrong-source").as_uri()
    run_git(
        "-C",
        str(resolved.mirror_root),
        "remote",
        "set-url",
        "origin",
        wrong_source,
    )

    with pytest.raises(RepositoryResolutionError, match="remote origin"):
        resolver.resolve(repository_ref(repository, revision))


def test_unknown_revision_does_not_leave_ready_revision_entry(
    tmp_path: Path,
    two_commit_repository: tuple[Path, str, str],
) -> None:
    repository, _, _ = two_commit_repository
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=tmp_path / "cache",
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        )
    )

    with pytest.raises(RepositoryRevisionNotFoundError, match="revision"):
        resolver.resolve(repository_ref(repository, "0" * 40))

    revisions_root = tmp_path / "cache" / "revisions"
    assert not list(revisions_root.rglob("0" * 40))


def test_subprocess_timeout_is_mapped_to_project_error(
    tmp_path: Path,
    two_commit_repository: tuple[Path, str, str],
) -> None:
    repository, _, revision = two_commit_repository

    class TimeoutRunner:
        def run(
            self,
            arguments: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout: int | float | None = None,
        ) -> CommandResult:
            raise subprocess.TimeoutExpired(list(arguments), float(timeout or 0))

    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=tmp_path / "cache",
            clone_timeout_seconds=7,
            lock_timeout_seconds=5,
        ),
        runner=TimeoutRunner(),
    )

    with pytest.raises(RepositoryCommandTimeoutError, match="timed out"):
        resolver.resolve(repository_ref(repository, revision))


def test_oserror_redacts_repository_credentials(
    tmp_path: Path,
) -> None:
    secret_url = (
        "https://user:secret@example.test/acme/demo.git"
        "?api_key=query-secret&client_secret=client-secret"
    )

    class OSErrorRunner:
        def run(
            self,
            arguments: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout: int | float | None = None,
        ) -> CommandResult:
            raise OSError(f"could not execute {secret_url}")

    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=tmp_path / "cache",
            clone_timeout_seconds=7,
            lock_timeout_seconds=5,
        ),
        runner=OSErrorRunner(),
    )

    with pytest.raises(RepositoryResolutionError) as caught:
        resolver.resolve(
            RepositoryRef(
                repository_id="local",
                repository_url=secret_url,
                revision="a" * 40,
            )
        )

    message = str(caught.value)
    assert secret_url not in message
    assert "user:secret@" not in message
    assert "query-secret" not in message
    assert "client-secret" not in message


def test_read_only_conversion_fails_closed_on_walk_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    two_commit_repository: tuple[Path, str, str],
) -> None:
    repository, revision, _ = two_commit_repository
    real_walk = os.walk
    walk_calls = 0

    def failing_walk(path, *args, **kwargs):
        nonlocal walk_calls
        walk_calls += 1
        if walk_calls == 1:
            kwargs["onerror"](OSError("simulated traversal failure"))
            return iter(())
        return real_walk(path, *args, **kwargs)

    monkeypatch.setattr(os, "walk", failing_walk)
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=tmp_path / "cache",
            clone_timeout_seconds=30,
            lock_timeout_seconds=5,
        )
    )

    with pytest.raises(RepositoryResolutionError, match="travers"):
        resolver.resolve(repository_ref(repository, revision))

    assert not resolver.revision_path_for(repository_ref(repository, revision)).exists()


def test_command_errors_redact_repository_credentials(
    tmp_path: Path,
) -> None:
    secret_url = (
        "https://deploy-token:supersecret@example.test/acme/demo.git"
        "?api_key=api-secret&client_secret=client-secret"
    )
    actual_arguments: list[str] = []

    class FailingRunner:
        def run(
            self,
            arguments: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout: int | float | None = None,
        ) -> CommandResult:
            actual_arguments.extend(arguments)
            return CommandResult(tuple(arguments), 128, "", f"cannot access {secret_url}")

    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=tmp_path / "cache",
            clone_timeout_seconds=7,
            lock_timeout_seconds=5,
        ),
        runner=FailingRunner(),
    )
    ref = RepositoryRef(
        repository_id="local",
        repository_url=secret_url,
        revision="a" * 40,
    )

    with pytest.raises(RepositoryCommandError) as caught:
        resolver.resolve(ref)

    error = caught.value
    assert any(secret_url in argument for argument in actual_arguments)
    assert all("supersecret" not in argument for argument in error.arguments)
    assert all("api-secret" not in argument for argument in error.arguments)
    assert all("client-secret" not in argument for argument in error.arguments)
    assert "supersecret" not in error.stderr
    assert "api-secret" not in error.stderr
    assert "client-secret" not in error.stderr
    assert "deploy-token" not in str(error)
    assert "supersecret" not in str(error)
    assert "api-secret" not in str(error)
    assert "client-secret" not in str(error)


def test_timeout_errors_redact_repository_credentials(
    tmp_path: Path,
) -> None:
    secret_url = (
        "ssh://deploy-token:supersecret@example.test/acme/demo.git"
        "?api_key=api-secret&client_secret=client-secret"
    )
    actual_arguments: list[str] = []

    class TimeoutRunner:
        def run(
            self,
            arguments: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout: int | float | None = None,
        ) -> CommandResult:
            actual_arguments.extend(arguments)
            raise subprocess.TimeoutExpired(list(arguments), float(timeout or 0))

    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=tmp_path / "cache",
            clone_timeout_seconds=7,
            lock_timeout_seconds=5,
        ),
        runner=TimeoutRunner(),
    )
    ref = RepositoryRef(
        repository_id="local",
        repository_url=secret_url,
        revision="a" * 40,
    )

    with pytest.raises(RepositoryCommandTimeoutError) as caught:
        resolver.resolve(ref)

    assert any(secret_url in argument for argument in actual_arguments)
    assert all("supersecret" not in argument for argument in caught.value.arguments)
    assert all("api-secret" not in argument for argument in caught.value.arguments)
    assert all("client-secret" not in argument for argument in caught.value.arguments)
    assert "deploy-token" not in str(caught.value)
    assert "supersecret" not in str(caught.value)
    assert "api-secret" not in str(caught.value)
    assert "client-secret" not in str(caught.value)


def test_read_only_failed_temp_cleanup_is_portable(
    tmp_path: Path,
) -> None:
    temporary_root = tmp_path / "temporary-checkout"
    temporary_root.mkdir()
    read_only_file = temporary_root / "read-only.txt"
    read_only_file.write_text("cleanup me\n", encoding="utf-8")
    os.chmod(read_only_file, stat.S_IREAD)

    git_repository_module._remove_tree(temporary_root)

    assert not temporary_root.exists()


def test_failed_temp_cleanup_errors_are_propagated(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    class FailingRunner:
        def run(
            self,
            arguments: Sequence[str],
            *,
            cwd: Path | None = None,
            timeout: int | float | None = None,
        ) -> CommandResult:
            return CommandResult(tuple(arguments), 128, "", "clone failed")

    def fail_cleanup(path: Path) -> None:
        raise OSError("cleanup blocked")

    monkeypatch.setattr(git_repository_module, "_remove_tree", fail_cleanup)
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(
            cache_root=tmp_path / "cache",
            clone_timeout_seconds=7,
            lock_timeout_seconds=5,
        ),
        runner=FailingRunner(),
    )
    ref = RepositoryRef(
        repository_id="local",
        repository_url="https://example.test/acme/demo.git",
        revision="a" * 40,
    )

    with pytest.raises(RepositoryCleanupError, match="cleanup"):
        resolver.resolve(ref)


def test_equivalent_repository_urls_share_sha256_cache_identity(
    tmp_path: Path,
) -> None:
    resolver = GitRepositoryResolver(
        RepositoryContextConfig(cache_root=tmp_path / "cache")
    )
    first = "https://EXAMPLE.test/acme/demo.git/"
    second = "https://example.test/acme/demo.git"

    assert canonicalize_repository_url(first) == second
    assert resolver.mirror_path_for_url(first) == resolver.mirror_path_for_url(second)
    assert resolver.mirror_path_for_url(first).name == (
        hashlib.sha256(second.encode("utf-8")).hexdigest() + ".git"
    )


def test_subprocess_runner_captures_replacement_text_and_uses_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(arguments, **kwargs):
        captured["arguments"] = arguments
        captured.update(kwargs)
        return subprocess.CompletedProcess(arguments, 0, "ok\ufffd", "err\ufffd")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = SubprocessCommandRunner().run(["git", "status"], timeout=13)

    assert result.stdout == "ok\ufffd"
    assert result.stderr == "err\ufffd"
    assert captured["shell"] is False
    assert captured["timeout"] == 13
    assert captured["encoding"] == "utf-8"
    assert captured["errors"] == "replace"
