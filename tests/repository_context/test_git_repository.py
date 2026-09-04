from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Sequence

import pytest

from vulsor.config import RepositoryContextConfig
from vulsor.repository_context.git_repository import (
    CommandResult,
    GitRepositoryResolver,
    RepositoryCommandTimeoutError,
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
            raise subprocess.TimeoutExpired(list(arguments), timeout)

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
