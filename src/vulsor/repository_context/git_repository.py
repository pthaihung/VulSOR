"""Resolve Git repository references into immutable local revisions."""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Protocol, Sequence
from urllib.parse import urlsplit, urlunsplit

from vulsor.config import RepositoryContextConfig

from .models import RepositoryRef


_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_SUPPORTED_URL_SCHEMES = frozenset({"https", "http", "ssh", "file"})


class RepositoryResolutionError(RuntimeError):
    """Base class for errors raised while resolving repository references."""


class RepositoryCommandError(RepositoryResolutionError):
    """A Git command completed unsuccessfully."""

    def __init__(
        self,
        arguments: Sequence[str],
        returncode: int,
        stderr: str,
    ) -> None:
        self.arguments = tuple(arguments)
        self.returncode = returncode
        self.stderr = stderr
        detail = stderr.strip() or "no error output"
        super().__init__(
            f"Git command failed with exit code {returncode}: "
            f"{_format_arguments(self.arguments)}: {detail}"
        )


class RepositoryCommandTimeoutError(RepositoryResolutionError):
    """A Git command exceeded its configured timeout."""

    def __init__(self, arguments: Sequence[str], timeout: float | None) -> None:
        self.arguments = tuple(arguments)
        self.timeout = timeout
        super().__init__(
            f"Git command timed out after {timeout} seconds: "
            f"{_format_arguments(self.arguments)}"
        )


class RepositoryRevisionNotFoundError(RepositoryResolutionError):
    """The requested full revision is not present in the repository."""


class RepositoryLockTimeoutError(RepositoryResolutionError):
    """A cache lock could not be acquired before its configured timeout."""


# Descriptive aliases for callers that prefer Git-specific exception names.
GitRepositoryError = RepositoryResolutionError
GitCommandError = RepositoryCommandError
GitCommandTimeoutError = RepositoryCommandTimeoutError


@dataclass(frozen=True)
class CommandResult:
    """The text output of one completed external command."""

    arguments: tuple[str, ...]
    returncode: int
    stdout: str
    stderr: str


class CommandRunner(Protocol):
    """Run an argument-vector command without invoking a shell."""

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
    ) -> CommandResult:
        """Run a command and return captured UTF-8 text output."""


class SubprocessCommandRunner:
    """Default command runner used by :class:`GitRepositoryResolver`."""

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
    ) -> CommandResult:
        normalized_arguments = tuple(arguments)
        try:
            completed = subprocess.run(
                list(normalized_arguments),
                cwd=cwd,
                check=False,
                encoding="utf-8",
                errors="replace",
                shell=False,
                stderr=subprocess.PIPE,
                stdout=subprocess.PIPE,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            raise
        return CommandResult(
            arguments=normalized_arguments,
            returncode=completed.returncode,
            stdout=completed.stdout or "",
            stderr=completed.stderr or "",
        )


@dataclass(frozen=True)
class ResolvedRepository:
    """An immutable checkout and the mirror from which it was materialized."""

    repository_root: Path
    resolved_revision: str
    mirror_root: Path


def canonicalize_repository_url(repository_url: object) -> str:
    """Return a stable cache identity for a supported Git repository URL.

    Host names and schemes are case-insensitive, and a trailing repository
    slash does not change the Git source. Fragments are client-side URL
    metadata and therefore do not identify a different repository.
    """

    raw_url = str(repository_url)
    try:
        parsed = urlsplit(raw_url)
    except ValueError as exc:
        raise RepositoryResolutionError(
            f"invalid repository URL: {raw_url!r}"
        ) from exc
    scheme = parsed.scheme.lower()
    if scheme not in _SUPPORTED_URL_SCHEMES:
        raise RepositoryResolutionError(
            f"unsupported repository URL scheme: {parsed.scheme or '<missing>'}"
        )

    if scheme == "file":
        netloc = parsed.netloc
    else:
        try:
            netloc = _canonicalize_network_location(
                parsed.netloc,
                parsed.hostname,
                scheme,
            )
        except ValueError as exc:
            raise RepositoryResolutionError(
                f"invalid repository URL: {raw_url!r}"
            ) from exc

    path = parsed.path
    if scheme != "file" and path in {"", "/"}:
        path = ""
    elif path != "/":
        path = path.rstrip("/")

    return urlunsplit((scheme, netloc, path, parsed.query, ""))


def repository_url_digest(repository_url: object) -> str:
    """Return the SHA-256 digest used for repository cache paths."""

    canonical_url = canonicalize_repository_url(repository_url)
    return hashlib.sha256(canonical_url.encode("utf-8")).hexdigest()


class GitRepositoryResolver:
    """Cache Git mirrors and materialize verified detached revisions."""

    def __init__(
        self,
        config: RepositoryContextConfig | None = None,
        *,
        runner: CommandRunner | None = None,
        cache_root: Path | None = None,
        git_executable: str = "git",
    ) -> None:
        if config is None:
            config = RepositoryContextConfig(
                cache_root=cache_root
                if cache_root is not None
                else Path("workspace/repository_context")
            )
        elif cache_root is not None and Path(config.cache_root) != cache_root:
            raise ValueError("cache_root conflicts with config.cache_root")

        if not git_executable or "\x00" in git_executable:
            raise ValueError("git_executable must be a non-empty path without NUL")

        self.config = config
        self.cache_root = Path(config.cache_root).expanduser().resolve()
        self.cache_root.mkdir(parents=True, exist_ok=True)
        self._runner = runner or SubprocessCommandRunner()
        self._git_executable = git_executable

    def mirror_path_for_url(self, repository_url: object) -> Path:
        """Return the SHA-256-addressed mirror path for a repository URL."""

        return self.cache_root / "mirrors" / f"{repository_url_digest(repository_url)}.git"

    def revision_path_for(self, ref: RepositoryRef) -> Path:
        """Return the SHA-addressed checkout path for a repository reference."""

        revision = _normalized_revision(ref)
        digest = repository_url_digest(ref.repository_url)
        return self.cache_root / "revisions" / digest / revision

    def resolve(self, ref: RepositoryRef) -> ResolvedRepository:
        """Resolve ``ref`` to a checkout whose detached HEAD is the requested SHA."""

        revision = _normalized_revision(ref)
        canonical_url = canonicalize_repository_url(ref.repository_url)
        mirror_root = self.mirror_path_for_url(canonical_url)
        self._ensure_mirror(canonical_url, mirror_root)

        revision_root = self.cache_root / "revisions" / mirror_root.stem / revision
        revision_parent = revision_root.parent
        revision_parent.mkdir(parents=True, exist_ok=True)

        with _directory_lock(
            revision_root.parent / f".{revision}.lock",
            timeout=self.config.lock_timeout_seconds,
        ):
            if revision_root.exists():
                if not revision_root.is_dir():
                    raise RepositoryResolutionError(
                        f"repository revision cache entry is not a directory: {revision_root}"
                    )
                self._verify_checkout(revision_root, revision)
                return ResolvedRepository(
                    repository_root=revision_root,
                    resolved_revision=revision,
                    mirror_root=mirror_root,
                )

            temporary_root = Path(
                tempfile.mkdtemp(prefix=f".{revision}.", dir=str(self.cache_root))
            )
            try:
                self._run_git(
                    "clone",
                    "--no-checkout",
                    str(mirror_root),
                    str(temporary_root),
                )
                try:
                    self._run_git(
                        "-C",
                        str(temporary_root),
                        "checkout",
                        "--detach",
                        revision,
                    )
                except RepositoryCommandError as exc:
                    if _looks_like_missing_revision(exc.stderr):
                        raise RepositoryRevisionNotFoundError(
                            f"requested Git revision is not present: {revision}"
                        ) from exc
                    raise

                self._verify_checkout(temporary_root, revision)
                temporary_root.replace(revision_root)
            except Exception:
                shutil.rmtree(temporary_root, ignore_errors=True)
                raise

        return ResolvedRepository(
            repository_root=revision_root,
            resolved_revision=revision,
            mirror_root=mirror_root,
        )

    def _ensure_mirror(self, canonical_url: str, mirror_root: Path) -> None:
        mirror_parent = mirror_root.parent
        mirror_parent.mkdir(parents=True, exist_ok=True)

        with _directory_lock(
            mirror_parent / f".{mirror_root.name}.lock",
            timeout=self.config.lock_timeout_seconds,
        ):
            if mirror_root.exists():
                if not mirror_root.is_dir():
                    raise RepositoryResolutionError(
                        f"repository mirror cache entry is not a directory: {mirror_root}"
                    )
                self._verify_mirror(mirror_root)
                return

            temporary_root = Path(
                tempfile.mkdtemp(prefix=f".{mirror_root.stem}.", dir=str(self.cache_root))
            )
            try:
                self._run_git(
                    "clone",
                    "--mirror",
                    canonical_url,
                    str(temporary_root),
                )
                temporary_root.replace(mirror_root)
            except Exception:
                shutil.rmtree(temporary_root, ignore_errors=True)
                raise

    def _verify_mirror(self, mirror_root: Path) -> None:
        result = self._run_git(
            "-C",
            str(mirror_root),
            "rev-parse",
            "--is-bare-repository",
        )
        if result.stdout.strip().lower() != "true":
            raise RepositoryResolutionError(
                f"repository mirror is not a bare Git mirror: {mirror_root}"
            )

    def _verify_checkout(self, repository_root: Path, requested_revision: str) -> None:
        result = self._run_git(
            "-C",
            str(repository_root),
            "rev-parse",
            "HEAD",
        )
        actual_revision = result.stdout.strip().lower()
        if not _FULL_SHA.fullmatch(actual_revision):
            raise RepositoryResolutionError(
                f"Git checkout returned an invalid HEAD revision at {repository_root}"
            )
        if actual_revision != requested_revision:
            raise RepositoryResolutionError(
                f"Git checkout HEAD {actual_revision} does not match requested "
                f"revision {requested_revision}"
            )

    def _run_git(self, *arguments: str) -> CommandResult:
        command = (self._git_executable, *arguments)
        try:
            result = self._runner.run(
                command,
                timeout=self.config.clone_timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            raise RepositoryCommandTimeoutError(
                command,
                self.config.clone_timeout_seconds,
            ) from exc
        except FileNotFoundError as exc:
            raise RepositoryResolutionError(
                f"Git executable was not found: {self._git_executable}"
            ) from exc
        except OSError as exc:
            raise RepositoryResolutionError(
                f"could not start Git command {_format_arguments(command)}: {exc}"
            ) from exc

        if result.returncode != 0:
            raise RepositoryCommandError(command, result.returncode, result.stderr)
        return result


@contextmanager
def _directory_lock(path: Path, *, timeout: float) -> Iterator[None]:
    """Acquire a process-safe lock by exclusively creating a directory."""

    deadline = time.monotonic() + timeout
    while True:
        try:
            path.mkdir()
            break
        except FileExistsError:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise RepositoryLockTimeoutError(
                    f"timed out after {timeout} seconds waiting for cache lock: {path}"
                )
            time.sleep(min(0.05, remaining))
        except OSError as exc:
            raise RepositoryResolutionError(
                f"could not acquire cache lock {path}: {exc}"
            ) from exc

    try:
        yield
    finally:
        try:
            path.rmdir()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise RepositoryResolutionError(
                f"could not release cache lock {path}: {exc}"
            ) from exc


def _normalized_revision(ref: RepositoryRef) -> str:
    revision = ref.revision
    if not isinstance(revision, str) or not _FULL_SHA.fullmatch(revision):
        raise RepositoryResolutionError(
            "repository revision must be a full 40-character hexadecimal SHA"
        )
    return revision.lower()


def _canonicalize_network_location(
    netloc: str,
    hostname: str | None,
    scheme: str,
) -> str:
    if hostname is None:
        raise RepositoryResolutionError("repository URL must include a host")

    userinfo = ""
    if "@" in netloc:
        userinfo = netloc.rsplit("@", 1)[0] + "@"

    host = hostname.lower()
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"

    port = urlsplit(f"{scheme}://{netloc}").port
    default_ports = {"http": 80, "https": 443, "ssh": 22}
    if port is None or port == default_ports.get(scheme):
        return f"{userinfo}{host}"
    return f"{userinfo}{host}:{port}"


def _looks_like_missing_revision(stderr: str) -> bool:
    message = stderr.lower()
    return any(
        marker in message
        for marker in (
            "pathspec",
            "reference is not a tree",
            "unable to read tree",
            "unknown revision",
            "bad object",
            "did not match any file",
            "invalid reference",
        )
    )


def _format_arguments(arguments: Sequence[str]) -> str:
    return " ".join(repr(argument) for argument in arguments)


__all__ = [
    "CommandResult",
    "CommandRunner",
    "GitCommandError",
    "GitCommandTimeoutError",
    "GitRepositoryError",
    "GitRepositoryResolver",
    "RepositoryCommandError",
    "RepositoryCommandTimeoutError",
    "RepositoryLockTimeoutError",
    "RepositoryResolutionError",
    "RepositoryRevisionNotFoundError",
    "ResolvedRepository",
    "SubprocessCommandRunner",
    "canonicalize_repository_url",
    "repository_url_digest",
]
