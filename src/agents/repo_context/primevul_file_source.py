"""Resolve one PrimeVul target source file without cloning its repository."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import quote, urlparse
from urllib.request import Request, urlopen


HttpGet = Callable[[str], bytes]

_GITHUB_COMMIT_LINK = re.compile(r"/commit/([0-9a-f]{40})", re.IGNORECASE)


class FileSourceResolutionError(RuntimeError):
    """The dataset locator cannot be resolved to one safe source file."""


@dataclass(frozen=True)
class ResolvedFileSource:
    source_path: Path
    revision: str | None
    source_sha256: str


def _http_get(url: str) -> bytes:
    accept = "text/html" if url.startswith("https://github.com/") else "application/vnd.github+json"
    request = Request(url, headers={"Accept": accept, "User-Agent": "VulSOR/1.0"})
    with urlopen(request, timeout=30) as response:  # noqa: S310 - URL is validated below
        return response.read()


def _required_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise FileSourceResolutionError(f"missing {field}")
    return value.strip()


def _safe_repository_path(value: object, field: str) -> PurePosixPath:
    path = PurePosixPath(_required_string(value, field))
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise FileSourceResolutionError(f"unsafe {field}")
    return path


def parse_github_repository(repository_url: str) -> tuple[str, str]:
    parsed = urlparse(_required_string(repository_url, "repository_url"))
    if parsed.scheme != "https" or parsed.netloc.lower() != "github.com":
        raise FileSourceResolutionError("unsupported repository URL")
    path = parsed.path.strip("/")
    if path.endswith(".git"):
        path = path[:-4]
    parts = path.split("/")
    if len(parts) != 2 or not all(parts):
        raise FileSourceResolutionError("unsupported repository URL")
    return parts[0], parts[1]


def github_raw_url(repository_url: str, revision: str, project_file_path: str) -> str:
    owner, repository = parse_github_repository(repository_url)
    safe_path = _safe_repository_path(project_file_path, "project_file_path")
    revision = _required_string(revision, "revision")
    encoded_path = quote(safe_path.as_posix(), safe="/")
    return f"https://raw.githubusercontent.com/{owner}/{repository}/{quote(revision, safe='')}/{encoded_path}"


def _safe_dataset_path(dataset_root: Path, value: object) -> Path | None:
    if value is None:
        return None
    try:
        relative = _safe_repository_path(value, "local_file_path")
    except FileSourceResolutionError:
        raise
    root = dataset_root.resolve()
    candidate = (root / Path(*relative.parts)).resolve()
    try:
        candidate.relative_to(root)
    except ValueError as exc:
        raise FileSourceResolutionError("unsafe local_file_path") from exc
    return candidate


class PrimeVulFileSourceResolver:
    def __init__(self, cache_root: Path, *, http_get: HttpGet | None = None) -> None:
        self.cache_root = Path(cache_root)
        self.http_get = http_get or _http_get
        self._parents: dict[tuple[str, str, str], str] = {}

    def resolve(
        self,
        *,
        locator: Mapping[str, Any],
        repository_url: str,
        fix_revision: str,
        dataset_root: Path,
    ) -> ResolvedFileSource:
        local = _safe_dataset_path(Path(dataset_root), locator.get("local_file_path"))
        if local is not None and local.is_file():
            return self._from_local(local)

        owner, repository = parse_github_repository(repository_url)
        project_path = _safe_repository_path(locator.get("project_file_path"), "project_file_path")
        cached_source = self._find_cached(owner, repository, project_path, locator.get("file_hash"))
        if cached_source is not None:
            parent = cached_source.parent.name
            return ResolvedFileSource(cached_source, parent, self._sha256(cached_source.read_bytes()))
        parent = self._unique_github_parent(owner, repository, fix_revision)
        cached = self._cache_path(owner, repository, parent, project_path, locator.get("file_hash"))
        if cached.is_file():
            return ResolvedFileSource(cached, parent, self._sha256(cached.read_bytes()))

        raw_url = github_raw_url(repository_url, parent, project_path.as_posix())
        try:
            content = self.http_get(raw_url)
        except Exception as exc:
            raise FileSourceResolutionError("target source download failed") from exc
        if not isinstance(content, bytes) or not content:
            raise FileSourceResolutionError("target source is empty")
        self._atomic_write(cached, content)
        return ResolvedFileSource(cached, parent, self._sha256(content))

    def _unique_github_parent(self, owner: str, repository: str, fix_revision: str) -> str:
        revision = _required_string(fix_revision, "fix_revision")
        cache_key = (owner, repository, revision)
        cached_parent = self._parents.get(cache_key)
        if cached_parent is not None:
            return cached_parent
        url = f"https://api.github.com/repos/{owner}/{repository}/commits/{quote(revision, safe='')}"
        try:
            payload = json.loads(self.http_get(url).decode("utf-8"))
        except Exception as exc:
            try:
                parent = self._parent_from_commit_page(owner, repository, revision)
            except Exception as page_exc:
                raise FileSourceResolutionError("commit parent lookup failed") from page_exc
            self._parents[cache_key] = parent
            return parent
        parents = payload.get("parents") if isinstance(payload, Mapping) else None
        if not isinstance(parents, list) or len(parents) != 1:
            raise FileSourceResolutionError("fix commit must have exactly one parent")
        parent = parents[0].get("sha") if isinstance(parents[0], Mapping) else None
        parent_revision = _required_string(parent, "parent revision")
        self._parents[cache_key] = parent_revision
        return parent_revision

    def _parent_from_commit_page(self, owner: str, repository: str, revision: str) -> str:
        page_url = (
            f"https://github.com/{quote(owner, safe='')}/{quote(repository, safe='')}"
            f"/commit/{quote(revision, safe='')}"
        )
        html = self.http_get(page_url).decode("utf-8", errors="replace")
        candidates: list[str] = []
        for match in _GITHUB_COMMIT_LINK.finditer(html):
            candidate = match.group(1).lower()
            if candidate != revision.lower() and candidate not in candidates:
                candidates.append(candidate)
        if len(candidates) != 1:
            raise FileSourceResolutionError("commit page does not identify exactly one parent")
        return candidates[0]

    def _cache_path(
        self,
        owner: str,
        repository: str,
        parent: str,
        project_path: PurePosixPath,
        file_hash: object,
    ) -> Path:
        if isinstance(file_hash, bool) or not isinstance(file_hash, (str, int)):
            raise FileSourceResolutionError("missing file_hash")
        safe_hash = str(file_hash).strip()
        if not safe_hash:
            raise FileSourceResolutionError("missing file_hash")
        if any(char in safe_hash for char in "\\/") or safe_hash in {".", ".."}:
            raise FileSourceResolutionError("unsafe file_hash")
        suffix = project_path.suffix if project_path.suffix else ".source"
        return self.cache_root / owner / repository / parent / f"{safe_hash}{suffix}"

    def _find_cached(
        self, owner: str, repository: str, project_path: PurePosixPath, file_hash: object
    ) -> Path | None:
        if isinstance(file_hash, bool) or not isinstance(file_hash, (str, int)):
            return None
        safe_hash = str(file_hash).strip()
        if not safe_hash or any(char in safe_hash for char in "\\/"):
            return None
        root = self.cache_root / owner / repository
        if not root.is_dir():
            return None
        matches = list(root.glob(f"*/{safe_hash}{project_path.suffix or '.source'}"))
        return matches[0] if len(matches) == 1 and matches[0].is_file() and matches[0].stat().st_size > 0 else None

    @staticmethod
    def _from_local(path: Path) -> ResolvedFileSource:
        return ResolvedFileSource(path, None, PrimeVulFileSourceResolver._sha256(path.read_bytes()))

    @staticmethod
    def _sha256(content: bytes) -> str:
        return hashlib.sha256(content).hexdigest()

    @staticmethod
    def _atomic_write(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
            os.replace(temporary_name, path)
        except Exception:
            Path(temporary_name).unlink(missing_ok=True)
            raise


__all__ = [
    "FileSourceResolutionError",
    "PrimeVulFileSourceResolver",
    "ResolvedFileSource",
    "github_raw_url",
    "parse_github_repository",
]
