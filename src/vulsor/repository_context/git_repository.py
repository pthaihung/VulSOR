"""Resolve Git repository references into immutable local revisions."""

from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
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
        self.arguments = _redact_arguments(arguments)
        self.returncode = returncode
        self.stderr = _redact_text(stderr)
        detail = self.stderr.strip() or "no error output"
        super().__init__(
            f"Git command failed with exit code {returncode}: "
            f"{_format_arguments(self.arguments)}: {detail}"
        )


class RepositoryCommandTimeoutError(RepositoryResolutionError):
    """A Git command exceeded its configured timeout."""

    def __init__(self, arguments: Sequence[str], timeout: float | None) -> None:
        self.arguments = _redact_arguments(arguments)
        self.timeout = timeout
        super().__init__(
            f"Git command timed out after {timeout} seconds: "
            f"{_format_arguments(self.arguments)}"
        )


class RepositoryRevisionNotFoundError(RepositoryResolutionError):
    """The requested full revision is not present in the repository."""


class RepositoryCleanupError(RepositoryResolutionError):
    """A temporary or quarantined cache path could not be removed."""


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
            f"invalid repository URL: {_redact_text(raw_url)!r}"
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
                f"invalid repository URL: {_redact_text(raw_url)!r}"
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


def revision_snapshot_path(
    cache_root: Path, repository_url: object, revision: str
) -> Path:
    """Return a prepared revision snapshot path without touching the filesystem."""

    root = Path(cache_root)
    if "\x00" in str(root):
        raise ValueError("cache_root must not contain NUL bytes")
    if not isinstance(revision, str) or not _FULL_SHA.fullmatch(revision):
        raise ValueError("revision must be a full 40-character hexadecimal SHA")
    return root / "revisions" / repository_url_digest(repository_url) / revision.lower()


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
        mirror_root.parent.mkdir(parents=True, exist_ok=True)
        revision_root = self.revision_path_for(ref)
        revision_parent = revision_root.parent
        revision_parent.mkdir(parents=True, exist_ok=True)

        with _directory_lock(
            mirror_root.parent / f".{mirror_root.name}.lock",
            timeout=self.config.lock_timeout_seconds,
        ):
            with _directory_lock(
                revision_root.parent / f".{revision}.lock",
                timeout=self.config.lock_timeout_seconds,
            ):
                if _path_exists(revision_root):
                    if self._checkout_is_valid(revision_root, revision):
                        self._verify_existing_mirror_if_present(
                            canonical_url,
                            mirror_root,
                        )
                        if not self._mirror_contains_revision(mirror_root, revision):
                            self._refresh_mirror(mirror_root)
                            if not self._mirror_contains_revision(
                                mirror_root,
                                revision,
                            ):
                                raise RepositoryRevisionNotFoundError(
                                    f"requested Git revision is not present: {revision}"
                                )
                        _make_tree_read_only(revision_root)
                        return ResolvedRepository(
                            repository_root=revision_root,
                            resolved_revision=revision,
                            mirror_root=mirror_root,
                        )

                self._ensure_mirror(canonical_url, mirror_root)
                if not self._mirror_contains_revision(mirror_root, revision):
                    self._refresh_mirror(mirror_root)
                    if not self._mirror_contains_revision(mirror_root, revision):
                        raise RepositoryRevisionNotFoundError(
                            f"requested Git revision is not present: {revision}"
                        )

                quarantine_root: Path | None = None
                if _path_exists(revision_root):
                    quarantine_root = self._quarantine_checkout(revision_root, revision)

                try:
                    self._materialize_revision(mirror_root, revision_root, revision)
                except Exception as exc:
                    if quarantine_root is not None:
                        _cleanup_failed_path(quarantine_root, exc)
                    raise
                if quarantine_root is not None:
                    _remove_tree(quarantine_root)

        return ResolvedRepository(
            repository_root=revision_root,
            resolved_revision=revision,
            mirror_root=mirror_root,
        )

    def _ensure_mirror(self, canonical_url: str, mirror_root: Path) -> None:
        mirror_parent = mirror_root.parent
        mirror_parent.mkdir(parents=True, exist_ok=True)

        if _path_exists(mirror_root):
            if mirror_root.is_symlink() or not mirror_root.is_dir():
                raise RepositoryResolutionError(
                    f"repository mirror cache entry is not a directory: {mirror_root}"
                )
            self._verify_mirror(mirror_root, canonical_url)
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
            self._verify_mirror(temporary_root, canonical_url)
            temporary_root.replace(mirror_root)
        except Exception as exc:
            _cleanup_failed_path(temporary_root, exc)
            raise

    def _verify_existing_mirror_if_present(
        self,
        canonical_url: str,
        mirror_root: Path,
    ) -> None:
        if not _path_exists(mirror_root):
            try:
                self._ensure_mirror(canonical_url, mirror_root)
            except RepositoryResolutionError as exc:
                raise RepositoryResolutionError(
                    "cached repository checkout is valid, but its mirror is "
                    "missing and could not be restored"
                ) from exc
        if mirror_root.is_symlink() or not mirror_root.is_dir():
            raise RepositoryResolutionError(
                f"repository mirror cache entry is not a directory: {mirror_root}"
            )
        self._verify_mirror(mirror_root, canonical_url)

    def _mirror_contains_revision(self, mirror_root: Path, revision: str) -> bool:
        # Reachability from a mirror ref is the practical local cache boundary.
        # It excludes arbitrary dangling objects, without claiming that Git's
        # object database alone cryptographically authenticates the repository.
        try:
            result = self._run_git(
                "-C",
                str(mirror_root),
                "for-each-ref",
                "--contains",
                revision,
                "--format=%(refname)",
            )
        except RepositoryCommandError:
            return False
        return bool(result.stdout.strip())

    def _refresh_mirror(self, mirror_root: Path) -> None:
        self._run_git(
            "-C",
            str(mirror_root),
            "fetch",
            "--prune",
            "origin",
        )

    def _verify_mirror(self, mirror_root: Path, canonical_url: str) -> None:
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

        try:
            origin = self._run_git(
                "-C",
                str(mirror_root),
                "config",
                "--get",
                "remote.origin.url",
            ).stdout.strip()
        except RepositoryCommandError:
            raise RepositoryResolutionError(
                "repository mirror remote origin URL is missing"
            ) from None
        try:
            origin_canonical = canonicalize_repository_url(origin)
        except RepositoryResolutionError:
            raise RepositoryResolutionError(
                "repository mirror remote origin URL is invalid"
            ) from None
        if origin_canonical != canonical_url:
            raise RepositoryResolutionError(
                "repository mirror remote origin URL does not match requested URL"
            )

    def _materialize_revision(
        self,
        mirror_root: Path,
        revision_root: Path,
        revision: str,
    ) -> None:
        temporary_root = Path(
            tempfile.mkdtemp(prefix=f".{revision}.", dir=str(self.cache_root))
        )
        try:
            self._run_git(
                "clone",
                "--no-checkout",
                "--no-hardlinks",
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
                    ) from None
                raise

            self._verify_checkout(temporary_root, revision)
            _make_tree_read_only(temporary_root)
            temporary_root.replace(revision_root)
        except Exception as exc:
            _cleanup_failed_path(temporary_root, exc)
            raise

    def _checkout_is_valid(self, repository_root: Path, revision: str) -> bool:
        if repository_root.is_symlink() or not repository_root.is_dir():
            return False
        try:
            self._verify_checkout(repository_root, revision)
            head_name = self._run_git(
                "-C",
                str(repository_root),
                "rev-parse",
                "--abbrev-ref",
                "HEAD",
            ).stdout.strip()
            if head_name != "HEAD":
                return False
            status = self._run_git(
                "-C",
                str(repository_root),
                "--no-optional-locks",
                "status",
                "--porcelain=v1",
                "--untracked-files=all",
                "--ignored=matching",
            ).stdout
            return status == ""
        except RepositoryCommandTimeoutError:
            raise
        except RepositoryResolutionError:
            return False

    def _quarantine_checkout(self, revision_root: Path, revision: str) -> Path:
        quarantine_root = Path(
            tempfile.mkdtemp(prefix=f".invalid-{revision}.", dir=str(self.cache_root))
        )
        try:
            _remove_tree(quarantine_root)
            revision_root.replace(quarantine_root)
        except Exception as exc:
            _cleanup_failed_path(quarantine_root, exc)
            raise
        return quarantine_root

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
        except subprocess.TimeoutExpired:
            raise RepositoryCommandTimeoutError(
                command,
                self.config.clone_timeout_seconds,
            ) from None
        except FileNotFoundError:
            raise RepositoryResolutionError(
                f"Git executable was not found: {self._git_executable}"
            ) from None
        except OSError as exc:
            safe_error = _redact_text(str(exc))
            raise RepositoryResolutionError(
                f"could not start Git command "
                f"{_format_arguments(_redact_arguments(command))}: {safe_error}"
            ) from None

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


def _path_exists(path: Path) -> bool:
    return path.exists() or path.is_symlink()


def _make_tree_read_only(path: Path) -> None:
    """Remove write permission from every non-symlink entry in a tree."""

    traversal_errors: list[OSError] = []

    def onerror(error: OSError) -> None:
        traversal_errors.append(error)

    try:
        for directory, directory_names, file_names in os.walk(
            path,
            topdown=True,
            followlinks=False,
            onerror=onerror,
        ):
            directory_path = Path(directory)
            for name in directory_names:
                child = directory_path / name
                if not child.is_symlink():
                    os.chmod(child, _read_only_mode(child))
            for name in file_names:
                child = directory_path / name
                if not child.is_symlink():
                    os.chmod(child, _read_only_mode(child))
            os.chmod(directory_path, _read_only_mode(directory_path))
    except OSError as exc:
        raise RepositoryResolutionError(
            f"could not make repository checkout read-only at {path}: "
            f"{_redact_text(str(exc))}"
        ) from exc

    if traversal_errors:
        detail = "; ".join(
            _redact_text(str(error)) for error in traversal_errors if str(error)
        )
        raise RepositoryResolutionError(
            f"could not traverse repository checkout while making it read-only: "
            f"{detail or 'unknown traversal error'}"
        ) from traversal_errors[0]


def _make_tree_writable(path: Path) -> None:
    """Restore owner write permission for tests and failed-cache cleanup."""

    for directory, directory_names, file_names in os.walk(
        path,
        topdown=True,
        followlinks=False,
    ):
        directory_path = Path(directory)
        os.chmod(directory_path, _writable_mode(directory_path))
        for name in directory_names:
            child = directory_path / name
            if not child.is_symlink():
                os.chmod(child, _writable_mode(child))
        for name in file_names:
            child = directory_path / name
            if not child.is_symlink():
                os.chmod(child, _writable_mode(child))


def _read_only_mode(path: Path) -> int:
    return os.stat(path, follow_symlinks=False).st_mode & ~(
        stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH
    )


def _writable_mode(path: Path) -> int:
    return os.stat(path, follow_symlinks=False).st_mode | stat.S_IWUSR


def _cleanup_failed_path(path: Path, original_error: BaseException) -> None:
    try:
        _remove_tree(path)
    except RepositoryCleanupError as cleanup_error:
        raise cleanup_error from original_error
    except OSError as cleanup_error:
        raise RepositoryCleanupError(
            f"could not clean up temporary repository path {path}: {cleanup_error}"
        ) from original_error


def _remove_tree(path: Path) -> None:
    """Remove a cache tree, retrying failures after making entries writable."""

    if not _path_exists(path):
        return

    failures: list[BaseException] = []

    def retry_remove(function, target: str, exc_info) -> None:
        target_path = Path(target)
        try:
            os.chmod(target_path.parent, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        except OSError:
            pass
        try:
            os.chmod(target_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)
        except OSError:
            pass
        try:
            function(target)
        except OSError as exc:
            failures.append(exc)

    try:
        if path.is_symlink():
            path.unlink()
        elif path.is_dir():
            try:
                _make_tree_writable(path)
            except OSError as exc:
                failures.append(exc)
            shutil.rmtree(path, onerror=retry_remove)
        else:
            try:
                path.unlink()
            except OSError:
                retry_remove(os.unlink, str(path), None)
    except OSError as exc:
        failures.append(exc)

    if failures or _path_exists(path):
        detail = "; ".join(str(failure) for failure in failures if str(failure))
        raise RepositoryCleanupError(
            f"could not clean up repository path {path}"
            + (f": {detail}" if detail else "")
        )


_CREDENTIAL_URL = re.compile(
    r"(?P<prefix>\b(?:https?|ssh|file)://)(?P<userinfo>[^/\s@]+)@",
    re.IGNORECASE,
)
_QUERY_PARAMETER = re.compile(
    r"(?P<prefix>[?&][^=?&#\s]+=)(?:[^&#\s]*)",
    re.IGNORECASE,
)


def _redact_text(value: str) -> str:
    redacted = _CREDENTIAL_URL.sub(r"\g<prefix>***@", value)
    return _QUERY_PARAMETER.sub(r"\g<prefix>***", redacted)


def _redact_arguments(arguments: Sequence[str]) -> tuple[str, ...]:
    return tuple(_redact_text(argument) for argument in arguments)


def _format_arguments(arguments: Sequence[str]) -> str:
    return " ".join(repr(argument) for argument in arguments)


__all__ = [
    "CommandResult",
    "CommandRunner",
    "RepositoryCleanupError",
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
    "revision_snapshot_path",
]
