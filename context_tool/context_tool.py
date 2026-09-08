from __future__ import annotations

# Consolidated standalone PrimeVul file-context builder.
# The implementation below intentionally has no dependency on the old context packages.

import argparse
import sys
from typing import Sequence

"""Typed configuration for VulSOR.

Configuration is intentionally kept small. Joern executable names and timeouts
may be supplied by an optional YAML file, while the standalone tool also has
safe defaults for local execution.
"""
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictInt

class ToolsConfig(BaseModel):
    """External tool executables, resolved via PATH by default.

    Do NOT hard-code machine-specific paths here. If a machine needs a specific path, that
    belongs in that machine's own config YAML, not in this schema's
    defaults (VulSOR.md, "Environment state on Windows").
    """

    model_config = ConfigDict(populate_by_name=True)

    joern: str = "joern"
    joern_parse: str = Field(default="joern-parse", alias="joern-parse")


class FileContextConfig(BaseModel):
    build_timeout_seconds: StrictInt = Field(default=1800, ge=1)
    query_timeout_seconds: StrictInt = Field(default=120, ge=1)


class VulSORConfig(BaseModel):
    """Top-level VulSOR configuration.

    Loaded from an optional YAML file. All fields have safe defaults so that
    `load_config(None)` returns a usable config for local/dev use.
    """

    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    file_context: FileContextConfig = Field(
        default_factory=FileContextConfig
    )


class AgentLLMOverride(BaseModel):
    """Optional LLM settings that override the shared agent defaults."""

    provider: str | None = None
    base_url: str | None = None
    model: str | None = None
    api_key_env: str | None = None
    temperature: float | None = None
    timeout_seconds: int | None = None
    max_output_tokens: int | None = None
    max_tool_rounds: int | None = None
    allowed_tools: tuple[str, ...] | None = None
    extra_headers: dict[str, str] | None = None


class AgentLLMConfig(BaseModel):
    """LLM API settings loaded from a dedicated semantic-agent YAML file."""

    provider: str = "openai_compatible"
    base_url: str = "https://api.openai.com/v1/chat/completions"
    model: str = "gpt-4.1-mini"
    api_key_env: str = "OPENAI_API_KEY"
    temperature: float = 0.0
    timeout_seconds: int = 60
    max_output_tokens: int = 1200
    max_tool_rounds: int = 1
    allowed_tools: tuple[str, ...] = (
        "get_program_facts",
        "get_fact_links",
        "get_completeness",
        "get_limitations",
    )
    extra_headers: dict[str, str] = Field(default_factory=dict)
    agents: dict[str, AgentLLMOverride] = Field(default_factory=dict)

    def for_agent(self, agent_name: str) -> AgentLLMConfig:
        """Return shared settings merged with an agent-specific override."""
        override = self.agents.get(agent_name)

        if override is None:
            return self

        return self.model_copy(
            update=override.model_dump(exclude_unset=True, exclude_none=True)
        ).model_copy(update={"agents": {}})


def load_config(path: Path | None) -> VulSORConfig:
    """Load a VulSORConfig from a YAML file, or return defaults.

    Args:
        path: Path to a YAML config file, or None to use built-in defaults.

    Returns:
        A validated VulSORConfig.

    Raises:
        FileNotFoundError: if `path` is given but does not exist.
        pydantic.ValidationError: if the YAML content does not match
            the expected schema.
    """
    if path is None:
        return VulSORConfig()

    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {path}")

    raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return VulSORConfig(**raw)


def load_llm_config(path: Path | None) -> AgentLLMConfig:
    """Load semantic-agent LLM settings from a standalone YAML file."""
    if path is None:
        return AgentLLMConfig()

    if not path.exists():
        raise FileNotFoundError(f"LLM config file not found: {path}")

    raw: dict[str, Any] = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    return AgentLLMConfig(**raw)

"""Serialize complete sparse file context under one strict token budget."""

import json
from typing import Any, Mapping

MAX_FILE_CONTEXT_TOKENS = 2000

def estimate_context_tokens(text: str) -> int:
    """Conservatively estimate context tokens without a model tokenizer."""
    return (len(text.encode("utf-8")) + 2) // 3


class FileContextBudgetError(ValueError):
    """The entire sparse context cannot fit the fixed input allowance."""


def _clean(value: object) -> object | None:
    if isinstance(value, str):
        return value.strip() or None
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, (int, float)):
        return value if value > 0 else None
    if isinstance(value, Mapping):
        cleaned = {str(key): item for key, raw in value.items() if (item := _clean(raw)) is not None}
        return cleaned or None
    if isinstance(value, list):
        cleaned = [item for raw in value if (item := _clean(raw)) is not None]
        return cleaned or None
    return None


def make_sparse_context(payload: Mapping[str, object]) -> dict[str, object]:
    """Drop unmapped/blank content without fabricating context."""
    sparse: dict[str, object] = {}
    for family in sorted(payload):
        cleaned = _clean(payload[family])
        if cleaned is not None:
            sparse[family] = cleaned
    return sparse


def validate_complete_context(context: Mapping[str, object]) -> dict[str, object]:
    sparse = make_sparse_context(context)
    encoded = json.dumps(sparse, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    tokens = estimate_context_tokens(encoded)
    if tokens > MAX_FILE_CONTEXT_TOKENS:
        raise FileContextBudgetError(
            f"complete file context exceeds {MAX_FILE_CONTEXT_TOKENS} tokens ({tokens})"
        )
    return sparse

"""Resolve one PrimeVul target source file without cloning its repository."""

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

"""Safe process boundaries for Joern CPG construction and queries."""

import json
import os
import re
import shutil
import stat
import subprocess
import sysconfig
import tempfile
from pathlib import Path
from typing import Sequence, cast

_MAX_DIAGNOSTIC_CHARS = 4096
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_CMD_METACHARACTERS = frozenset('&|<>()^%!"\r\n')


class JoernError(RuntimeError):
    """Base class for failures at the Joern process or JSON boundary."""


class JoernCommandError(JoernError):
    """A Joern command completed unsuccessfully."""

    def __init__(
        self,
        arguments: Sequence[str],
        returncode: int,
        *,
        stdout: str = "",
        stderr: str = "",
        paths: Sequence[Path] = (),
    ) -> None:
        self.arguments = _redact_arguments(arguments, paths)
        self.returncode = returncode
        self.stdout, self.stderr = _capped_streams(stdout, stderr, paths)
        self.diagnostics = _truncate(_format_diagnostics(self.stdout, self.stderr))
        super().__init__(
            f"Joern command failed with exit code {returncode}: "
            f"{_format_arguments(self.arguments)}"
            f"{self.diagnostics if self.diagnostics else ''}"
        )


class JoernCommandTimeoutError(JoernError):
    """A Joern command exceeded its configured timeout."""

    def __init__(
        self,
        arguments: Sequence[str],
        timeout: float | None,
        *,
        stdout: str = "",
        stderr: str = "",
        paths: Sequence[Path] = (),
    ) -> None:
        self.arguments = _redact_arguments(arguments, paths)
        self.timeout = timeout
        self.stdout, self.stderr = _capped_streams(stdout, stderr, paths)
        self.diagnostics = _truncate(_format_diagnostics(self.stdout, self.stderr))
        super().__init__(
            f"Joern command timed out after {timeout} seconds: "
            f"{_format_arguments(self.arguments)}"
            f"{self.diagnostics if self.diagnostics else ''}"
        )


class JoernOutputError(JoernError):
    """Joern did not produce a valid explicit output file."""


class JoernSchemaError(JoernError):
    """Joern output did not satisfy the adapter's JSON boundary contract."""


class JoernCleanupError(JoernError):
    """A temporary Joern transport file could not be safely removed."""


def _is_link_like(path: Path) -> bool:
    """Return whether a path is a symlink, junction, or reparse point."""

    try:
        if path.is_symlink():
            return True
    except (OSError, RuntimeError):
        return True

    is_junction = getattr(path, "is_junction", None)
    if is_junction is not None:
        try:
            if is_junction():
                return True
        except (OSError, RuntimeError):
            return True

    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError:
        return True
    return bool(getattr(info, "st_file_attributes", 0) & _REPARSE_POINT)


def _path_variants(path: Path) -> tuple[str, ...]:
    variants = {str(path), os.fspath(path)}
    try:
        absolute = path.absolute()
        variants.add(str(absolute))
    except (OSError, RuntimeError):
        absolute = None
    try:
        resolved = path.resolve(strict=False)
        variants.add(str(resolved))
    except (OSError, RuntimeError):
        resolved = None

    for candidate in (absolute, resolved):
        if candidate is None:
            continue
        current = candidate
        while current.parent != current and current.parent.parent != current.parent:
            variants.add(str(current.parent))
            current = current.parent
    return tuple(value for value in variants if value)


def _sanitize_text(value: object, paths: Sequence[Path] = ()) -> str:
    if isinstance(value, bytes):
        text = value.decode("utf-8", errors="replace")
    else:
        text = str(value)

    variants: set[str] = set()
    for path in paths:
        variants.update(_path_variants(Path(path)))
    variants.update(variant.replace("\\", "/") for variant in tuple(variants))
    for variant in sorted(variants, key=len, reverse=True):
        if os.name == "nt":
            text = re.sub(re.escape(variant), "<local-path>", text, flags=re.IGNORECASE)
        else:
            text = text.replace(variant, "<local-path>")
    return text


def _truncate(value: str, limit: int = _MAX_DIAGNOSTIC_CHARS) -> str:
    if len(value) <= limit:
        return value
    marker = "...[truncated]"
    return value[: limit - len(marker)] + marker


def _diagnostic(value: object, paths: Sequence[Path]) -> str:
    return _truncate(_sanitize_text(value, paths))


def _capped_streams(
    stdout: object,
    stderr: object,
    paths: Sequence[Path],
) -> tuple[str, str]:
    safe_stdout = _sanitize_text(stdout, paths)
    safe_stderr = _sanitize_text(stderr, paths)
    if len(safe_stdout) + len(safe_stderr) <= _MAX_DIAGNOSTIC_CHARS:
        return safe_stdout, safe_stderr

    stdout_limit = min(len(safe_stdout), _MAX_DIAGNOSTIC_CHARS // 2)
    stderr_limit = min(len(safe_stderr), _MAX_DIAGNOSTIC_CHARS - stdout_limit)
    remaining = _MAX_DIAGNOSTIC_CHARS - stdout_limit - stderr_limit
    stdout_limit = min(len(safe_stdout), stdout_limit + remaining)
    return _truncate(safe_stdout, stdout_limit), _truncate(safe_stderr, stderr_limit)


def _redact_arguments(
    arguments: Sequence[str], paths: Sequence[Path]
) -> tuple[str, ...]:
    return tuple(_sanitize_text(argument, paths) for argument in arguments)


def _format_arguments(arguments: Sequence[str]) -> str:
    return " ".join(repr(argument) for argument in arguments)


def _format_diagnostics(stdout: str, stderr: str) -> str:
    details: list[str] = []
    if stdout:
        details.append(f" stdout={stdout!r}")
    if stderr:
        details.append(f" stderr={stderr!r}")
    return ";".join(details)


def _default_script(name: str) -> Path:
    checkout = Path(sysconfig.get_path("data")) / "share" / "vulsor" / "joern" / name
    if checkout.is_file():
        return checkout
    return Path(sysconfig.get_path("data")) / "share" / "vulsor" / "joern" / name


def _choose_alias(
    primary: str | Path | None,
    alias: str | Path | None,
    label: str,
) -> str | Path | None:
    if primary is not None and alias is not None and Path(primary) != Path(alias):
        raise ValueError(f"conflicting {label} values")
    return primary if primary is not None else alias


def _validated_executable(value: str | Path, label: str) -> str:
    executable = os.fspath(value)
    if not executable or not executable.strip() or "\x00" in executable:
        raise ValueError(f"{label} must be a non-blank path without NUL")
    # Windows CreateProcess does not search PATHEXT for a bare batch name,
    # although PowerShell and shutil.which do. Store the resolved launcher so
    # configured `joern`/`joern-parse` names work in subprocesses too.
    if os.name == "nt" and not Path(executable).suffix:
        discovered = shutil.which(executable)
        if discovered and Path(discovered).suffix.lower() in {".bat", ".cmd"}:
            return discovered
    return executable


def _reject_nul(path: Path, label: str) -> None:
    if "\x00" in os.fspath(path):
        raise JoernError(f"{label} must not contain NUL bytes")


def _validate_ancestors(path: Path, label: str) -> None:
    absolute = path.absolute()
    for ancestor in reversed(absolute.parents):
        if os.path.lexists(ancestor) and _is_link_like(ancestor):
            raise JoernError(f"{label} has a symlink, junction, or reparse ancestor")


def _validate_directory(path: Path, label: str) -> None:
    _reject_nul(path, label)
    try:
        _validate_ancestors(path, label)
        if not os.path.lexists(path):
            raise JoernError(f"{label} does not exist")
        if _is_link_like(path):
            raise JoernError(
                f"{label} must not be a symlink, junction, or reparse point"
            )
        if not path.is_dir():
            raise JoernError(f"{label} must be a directory")
    except JoernError:
        raise
    except (OSError, RuntimeError) as exc:
        raise JoernError(
            f"could not inspect {label}: {_sanitize_text(exc, (path,))}"
        ) from None


def _validate_regular_file(path: Path, label: str, *, nonempty: bool) -> None:
    _reject_nul(path, label)
    try:
        _validate_directory(path.parent, f"{label} parent")
        if not os.path.lexists(path):
            raise JoernOutputError(f"{label} is missing")
        if _is_link_like(path):
            raise JoernOutputError(f"{label} must be a regular file, not a link")
        if not path.is_file():
            raise JoernOutputError(f"{label} must be a regular file")
        if nonempty and path.stat().st_size <= 0:
            raise JoernOutputError(f"{label} must be nonempty")
    except JoernError:
        raise
    except (OSError, RuntimeError) as exc:
        raise JoernOutputError(
            f"could not inspect {label}: {_sanitize_text(exc, (path,))}"
        ) from None


def _validate_output_target(path: Path, label: str) -> bool:
    _reject_nul(path, label)
    _validate_directory(path.parent, f"{label} parent")
    try:
        exists = os.path.lexists(path)
        if exists and _is_link_like(path):
            raise JoernError(
                f"{label} must not be a symlink, junction, or reparse point"
            )
        if exists and not path.is_file():
            raise JoernError(f"{label} must be a regular file")
        return exists
    except JoernError:
        raise
    except (OSError, RuntimeError) as exc:
        raise JoernError(
            f"could not inspect {label}: {_sanitize_text(exc, (path,))}"
        ) from None


def _validate_source_tree(source_root: Path) -> None:
    pending = [source_root]
    while pending:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    child = Path(entry.path)
                    if _is_link_like(child):
                        raise JoernError(
                            "source root contains a symlink, junction, or reparse point"
                        )
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(child)
                        elif not entry.is_file(follow_symlinks=False):
                            raise JoernError(
                                "source root contains an unsupported filesystem entry"
                            )
                    except JoernError:
                        raise
                    except (OSError, RuntimeError) as exc:
                        raise JoernError(
                            "could not inspect source root: "
                            f"{_sanitize_text(exc, (source_root, child))}"
                        ) from None
        except JoernError:
            raise
        except (OSError, RuntimeError) as exc:
            raise JoernError(
                "could not traverse source root: "
                f"{_sanitize_text(exc, (source_root, directory))}"
            ) from None


def _is_batch_launcher(executable: str) -> bool:
    if Path(executable).suffix.casefold() in {".bat", ".cmd"}:
        return True
    resolved = shutil.which(executable)
    return resolved is not None and Path(resolved).suffix.casefold() in {
        ".bat",
        ".cmd",
    }


def _validate_batch_arguments(command: Sequence[str]) -> None:
    if not _is_batch_launcher(command[0]):
        return
    if any(
        any(character in _CMD_METACHARACTERS for character in argument)
        for argument in command
    ):
        raise JoernError(
            "refusing command with cmd metacharacters for a Windows batch launcher"
        )


def _as_text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


class CommandResult:
    """The text output of one completed external command."""

    def __init__(
        self,
        arguments: Sequence[str],
        returncode: int,
        stdout: str,
        stderr: str,
    ) -> None:
        self.arguments = tuple(arguments)
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


class CommandRunner:
    """Run an argument-vector command without invoking a shell."""

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
    ) -> CommandResult:
        raise NotImplementedError


class SubprocessCommandRunner(CommandRunner):
    """Run Joern commands with captured UTF-8 output."""

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
    ) -> CommandResult:
        normalized_arguments = tuple(arguments)
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
        return CommandResult(
            normalized_arguments,
            completed.returncode,
            completed.stdout or "",
            completed.stderr or "",
        )


class JoernAdapter:
    """Run Joern and exchange data only through explicit files and arguments."""

    def __init__(
        self,
        config: VulSORConfig | None = None,
        *,
        runner: CommandRunner | None = None,
        tools: ToolsConfig | None = None,
        joern_executable: str | Path | None = None,
        joern_parse_executable: str | Path | None = None,
        joern: str | Path | None = None,
        joern_parse: str | Path | None = None,
        file_context_script: str | Path | None = None,
    ) -> None:
        if config is not None and not isinstance(config, VulSORConfig):
            raise TypeError("config must be VulSORConfig")
        configured_tools = tools or (config.tools if config is not None else ToolsConfig())
        file_context = config.file_context if config is not None else VulSORConfig().file_context
        selected_joern = _choose_alias(joern_executable, joern, "joern executable")
        selected_parse = _choose_alias(
            joern_parse_executable, joern_parse, "joern-parse executable"
        )
        self.joern_executable = _validated_executable(
            configured_tools.joern if selected_joern is None else selected_joern,
            "joern_executable",
        )
        self.joern_parse_executable = _validated_executable(
            (
                configured_tools.joern_parse
                if selected_parse is None
                else selected_parse
            ),
            "joern_parse_executable",
        )
        self.config = file_context
        self._runner = runner or SubprocessCommandRunner()
        self.file_context_script = Path(
            _default_script("file_context.sc")
            if file_context_script is None
            else file_context_script
        )

    def build_cpg(self, source_root: Path, output_path: Path) -> None:
        """Build a C-language CPG into a validated nonempty regular file."""

        source_root = Path(source_root)
        output_path = Path(output_path)
        _validate_directory(source_root, "source root")
        _validate_source_tree(source_root)
        _validate_output_target(output_path, "CPG output")
        temporary_output: Path | None = None
        primary: BaseException | None = None
        try:
            temporary_output = self._temporary_file(
                f".{output_path.name}.joern-",
                directory=output_path.parent,
                paths=(output_path,),
            )
            command = (
                self.joern_parse_executable,
                os.fspath(source_root),
                "--language",
                "C",
                "-o",
                os.fspath(temporary_output),
            )
            self._run(
                command,
                timeout=self.config.build_timeout_seconds,
                paths=(source_root, output_path, temporary_output),
            )
            _validate_regular_file(
                temporary_output, "temporary CPG output", nonempty=True
            )
            try:
                temporary_output.replace(output_path)
            except OSError as exc:
                raise JoernError(
                    "could not publish CPG output: "
                    f"{_sanitize_text(exc, self._diagnostic_paths((output_path,)))}"
                ) from None
        except BaseException as exc:
            primary = exc
            raise
        finally:
            if temporary_output is not None:
                self._finish_cleanup(
                    ((temporary_output, "temporary CPG output"),), primary
                )

    def extract_file_context(
        self,
        cpg_path: Path,
        *,
        source_file: Path,
        start_line: int,
        end_line: int,
    ) -> dict[str, object]:
        """Run the file-scoped extractor for one exact source span."""
        cpg_path, source_file = Path(cpg_path), Path(source_file)
        _validate_regular_file(cpg_path, "CPG input", nonempty=True)
        _validate_regular_file(source_file, "file context source", nonempty=True)
        if (
            isinstance(start_line, bool)
            or isinstance(end_line, bool)
            or not isinstance(start_line, int)
            or not isinstance(end_line, int)
            or start_line < 1
            or end_line < start_line
        ):
            raise JoernError("file context source range must be positive and ordered")
        script_path = self._validated_script(self.file_context_script, "file context script")
        output_path: Path | None = None
        workspace: Path | None = None
        primary: BaseException | None = None
        try:
            output_path = self._temporary_file(".joern-file-context-")
            if self._uses_direct_java_for_scripts():
                workspace = self._temporary_directory(".joern-file-workspace-")
            command = self._script_command(
                script_path,
                (
                    f"cpgFile={os.fspath(cpg_path)}",
                    f"sourceFile={os.fspath(source_file)}",
                    f"startLine={start_line}",
                    f"endLine={end_line}",
                    f"outFile={os.fspath(output_path)}",
                ),
            )
            self._run(
                command,
                timeout=self.config.query_timeout_seconds,
                paths=(cpg_path, source_file, script_path, output_path),
                cwd=workspace,
            )
            payload = self._read_json_object(output_path, self._diagnostic_paths((cpg_path, source_file, script_path, output_path)))
            return self._validate_file_context_payload(payload)
        except (OSError, TypeError, ValueError) as exc:
            primary = JoernError(f"could not prepare file context request: {_truncate(str(exc))}")
            raise primary from None
        except BaseException as exc:
            primary = exc
            raise
        finally:
            if output_path is not None:
                self._finish_cleanup(((output_path, "file context output"),), primary)
            if workspace is not None:
                self._cleanup_temporary_directory(workspace, primary)

    @staticmethod
    def _validate_file_context_payload(payload: dict[str, object]) -> dict[str, object]:
        families = (
            "imports", "callee_funcs", "call_relations", "call_site_arguments",
            "data_flow", "control_dependencies", "declarations", "types",
        )
        if payload.get("target_status") not in {"exact", "not_found", "ambiguous"}:
            raise JoernSchemaError("file context output has an invalid target_status")
        for family in families:
            if not isinstance(payload.get(family), list):
                raise JoernSchemaError(f"file context output field {family} must be an array")
        if payload.get("target_status") == "exact":
            for family in families:
                for item in cast(list[object], payload[family]):
                    if not isinstance(item, dict):
                        raise JoernSchemaError(f"file context family {family} has an invalid item")
                    if family == "types":
                        continue
                    has_code = isinstance(item.get("code"), str) and bool(item["code"].strip())
                    has_callee_contract = (
                        family == "callee_funcs"
                        and any(
                            isinstance(item.get(key), str) and bool(item[key].strip())
                            for key in ("name", "signature")
                        )
                    )
                    if not has_code and not has_callee_contract:
                        raise JoernSchemaError(
                            f"file context family {family} has an invalid item"
                        )
        return payload

    def _diagnostic_paths(self, paths: Sequence[Path]) -> tuple[Path, ...]:
        return (
            *paths,
            Path(self.joern_executable),
            Path(self.joern_parse_executable),
        )

    @staticmethod
    def _temporary_file(
        prefix: str,
        *,
        directory: Path | None = None,
        paths: Sequence[Path] = (),
    ) -> Path:
        try:
            descriptor, name = tempfile.mkstemp(
                prefix=prefix,
                suffix=".json" if directory is None else ".tmp",
                dir=directory,
            )
            os.close(descriptor)
            return Path(name)
        except OSError as exc:
            raise JoernError(
                f"could not create temporary Joern file: {_diagnostic(exc, paths)}"
            ) from None

    def _cleanup_temporary_file(self, path: Path, label: str) -> None:
        try:
            if not os.path.lexists(path):
                return
            if not _is_link_like(path) and not path.is_file():
                raise JoernCleanupError(
                    f"could not clean Joern {label}: path is not a file or link"
                )
            path.unlink(missing_ok=True)
        except JoernCleanupError:
            raise
        except FileNotFoundError:
            return
        except (OSError, RuntimeError) as exc:
            raise JoernCleanupError(
                f"could not clean Joern {label}: "
                f"{_diagnostic(exc, self._diagnostic_paths((path,)))}"
            ) from None

    @staticmethod
    def _temporary_directory(prefix: str) -> Path:
        try:
            return Path(tempfile.mkdtemp(prefix=prefix))
        except OSError as exc:
            raise JoernError(f"could not create temporary Joern workspace: {exc}") from None

    def _cleanup_temporary_directory(
        self, path: Path, primary: BaseException | None
    ) -> None:
        try:
            shutil.rmtree(path)
        except FileNotFoundError:
            return
        except OSError as exc:
            cleanup_error = JoernCleanupError(
                "could not clean Joern script workspace: "
                f"{_diagnostic(exc, self._diagnostic_paths((path,)))}"
            )
            if primary is None:
                raise cleanup_error
            add_note = getattr(primary, "add_note", None)
            if callable(add_note):
                add_note(str(cleanup_error))

    def _finish_cleanup(
        self,
        paths: Sequence[tuple[Path, str]],
        primary: BaseException | None,
    ) -> None:
        failures: list[JoernCleanupError] = []
        for path, label in paths:
            try:
                self._cleanup_temporary_file(path, label)
            except JoernCleanupError as exc:
                failures.append(exc)
        if not failures:
            return

        cleanup_error = JoernCleanupError(
            "Joern temporary-file cleanup failed: "
            + "; ".join(str(failure) for failure in failures)
        )
        if primary is None:
            raise cleanup_error
        add_note = getattr(primary, "add_note", None)
        if callable(add_note):
            add_note(str(cleanup_error))
        else:
            setattr(primary, "joern_cleanup_error", cleanup_error)

    @staticmethod
    def _validated_script(path: Path, label: str) -> Path:
        _validate_regular_file(path, label, nonempty=False)
        return path

    def _script_command(
        self,
        script_path: Path,
        parameters: Sequence[str],
    ) -> tuple[str, ...]:
        launcher = self._launcher_path()
        if self._uses_direct_java_for_scripts():
            assert launcher is not None
            installation_root = launcher.parent
            java_executable = os.environ.get("JAVACMD")
            if not java_executable:
                java_home = os.environ.get("JAVA_HOME")
                java_executable = (
                    os.fspath(Path(java_home) / "bin" / "java.exe")
                    if java_home
                    else "java"
                )
            command: list[str] = [
                java_executable,
                "-XX:+UseG1GC",
                "-XX:CompressedClassSpaceSize=128m",
                "-Dlog4j.configurationFile="
                + os.fspath(installation_root / "conf" / "log4j2.xml"),
                "-cp",
                os.fspath(installation_root / "lib" / "*"),
                "io.joern.joerncli.console.ReplBridge",
                "--script",
                os.fspath(script_path),
            ]
        else:
            command = [self.joern_executable, "--script", os.fspath(script_path)]
        for parameter in parameters:
            command.extend(("--param", parameter))
        return tuple(command)

    def _uses_direct_java_for_scripts(self) -> bool:
        launcher = self._launcher_path()
        return (
            os.name == "nt"
            and launcher is not None
            and launcher.suffix.casefold() in {".bat", ".cmd"}
        )

    def _launcher_path(self) -> Path | None:
        configured = Path(self.joern_executable)
        if configured.is_absolute():
            return configured
        discovered = shutil.which(self.joern_executable)
        return Path(discovered) if discovered is not None else None

    @staticmethod
    def _read_json_object(
        output_path: Path,
        paths: Sequence[Path],
    ) -> dict[str, object]:
        _validate_regular_file(output_path, "Joern explicit output", nonempty=True)
        try:
            raw = output_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            raise JoernOutputError(
                f"could not read Joern explicit output: {_sanitize_text(exc, paths)}"
            ) from None
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise JoernSchemaError(
                f"Joern explicit output is not valid JSON: {_truncate(str(exc))}"
            ) from None
        if not isinstance(payload, dict):
            raise JoernSchemaError("Joern explicit output must be a JSON object")
        return cast(dict[str, object], payload)

    def _run(
        self,
        command: Sequence[str],
        *,
        timeout: float | None,
        paths: Sequence[Path],
        cwd: Path | None = None,
    ) -> CommandResult:
        diagnostic_paths = self._diagnostic_paths(paths)
        _validate_batch_arguments(command)
        try:
            result = self._runner.run(command, cwd=cwd, timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            output = getattr(exc, "stdout", None)
            if output is None:
                output = getattr(exc, "output", "")
            raise JoernCommandTimeoutError(
                command,
                timeout,
                stdout=_as_text(output),
                stderr=_as_text(getattr(exc, "stderr", "")),
                paths=diagnostic_paths,
            ) from None
        except FileNotFoundError:
            raise JoernError(
                f"Joern executable was not found: "
                f"{_sanitize_text(command[0], diagnostic_paths)}"
            ) from None
        except OSError as exc:
            raise JoernError(
                "could not start Joern command "
                f"{_format_arguments(_redact_arguments(command, diagnostic_paths))}: "
                f"{_diagnostic(exc, diagnostic_paths)}"
            ) from None

        if result.returncode != 0:
            raise JoernCommandError(
                command,
                result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
                paths=diagnostic_paths,
            )
        return result

"""File-scoped Joern CPG creation and extraction boundary validation."""

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

_CONTEXT_FAMILIES = (
    "imports",
    "callee_funcs",
    "call_relations",
    "call_site_arguments",
    "data_flow",
    "control_dependencies",
    "declarations",
    "types",
)


class FileContextError(RuntimeError):
    """A file CPG or its source-grounded context is invalid."""


class CpgBuilder(Protocol):
    def build_cpg(self, source_root: Path, output_path: Path) -> None: ...


@dataclass(frozen=True)
class FileCpgArtifact:
    cpg_path: Path
    staged_source: Path
    source_sha256: str
    cache_hit: bool


class FileCpgCache:
    """Cache a CPG by source bytes, not repository identity or revision."""

    def __init__(self, cache_root: Path, joern: CpgBuilder) -> None:
        self.cache_root = Path(cache_root)
        self.joern = joern

    def get_or_build(self, source: ResolvedFileSource) -> FileCpgArtifact:
        source_path = source.source_path.resolve()
        cache_root = self.cache_root.resolve()
        source_bytes = source_path.read_bytes()
        actual_digest = hashlib.sha256(source_bytes).hexdigest()
        if actual_digest != source.source_sha256:
            raise FileContextError("source digest changed before CPG construction")
        suffix = source_path.suffix or ".c"
        stage_dir = cache_root / "sources" / actual_digest
        staged_source = stage_dir / f"target{suffix}"
        cpg_path = cache_root / "cpg" / f"{actual_digest}.bin"
        self._write_if_missing(staged_source, source_bytes)
        if cpg_path.is_file() and cpg_path.stat().st_size > 0:
            return FileCpgArtifact(cpg_path, staged_source, actual_digest, True)
        cpg_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_dir = Path(tempfile.mkdtemp(prefix=f".{actual_digest}.", dir=cpg_path.parent))
        temporary_output = temporary_dir / "cpg.bin"
        try:
            self.joern.build_cpg(stage_dir, temporary_output)
            if not temporary_output.is_file() or temporary_output.stat().st_size <= 0:
                raise FileContextError("Joern did not create a non-empty file CPG")
            os.replace(temporary_output, cpg_path)
        finally:
            shutil.rmtree(temporary_dir, ignore_errors=True)
        return FileCpgArtifact(cpg_path, staged_source, actual_digest, False)

    @staticmethod
    def _write_if_missing(path: Path, content: bytes) -> None:
        if path.is_file():
            if path.read_bytes() != content:
                raise FileContextError("staged source does not match its digest")
            return
        path.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(content)
            os.replace(temporary_name, path)
        except Exception:
            Path(temporary_name).unlink(missing_ok=True)
            raise


def validate_file_context_payload(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise FileContextError("file context payload must be an object")
    if payload.get("target_status") != "exact":
        raise FileContextError("file context requires exactly one exact target")
    validated: dict[str, Any] = {"target_status": "exact"}
    for family in _CONTEXT_FAMILIES:
        values = payload.get(family, [])
        if not isinstance(values, list):
            raise FileContextError(f"file context family {family} must be an array")
        validated[family] = values
    return validated

"""Deterministic relation-aware reduction of raw file-level Joern facts."""

import json
import re
from collections.abc import Mapping
from typing import Any


MAX_CONTEXT_TOKENS = 2000
SAFE_CONTEXT_TOKENS = 1850
MAX_CONTROLLED_LINES = 8
MAX_CALLEE_BODY_CHARS = 480

FAMILY_LIMITS = {
    "imports": 2,
    "callee_funcs": 4,
    "call_relations": 8,
    "call_site_arguments": 12,
    "data_flow": 8,
    "control_dependencies": 6,
    "declarations": 8,
    "types": 4,
}

_PACK_ORDER = (
    "data_flow",
    "control_dependencies",
    "declarations",
    "types",
    "call_relations",
    "call_site_arguments",
    "callee_funcs",
    "imports",
)
_SEED_WORDS = re.compile(
    r"memcpy|memmove|strcpy|strncpy|sprintf|snprintf|malloc|calloc|realloc|read|recv|parse|decode|convert|index",
    re.I,
)
_SIZE_WORDS = re.compile(r"size|len|length|count|offset|index|bytes|capacity", re.I)
_NON_SEMANTIC_CALL = re.compile(r"^(log|debug|trace|printf|fprintf|puts|assert)", re.I)
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_KEYWORDS = {
    "if", "else", "for", "while", "switch", "case", "return", "sizeof",
    "const", "struct", "unsigned", "signed", "void", "char", "int", "long",
    "short", "static", "true", "false",
}


def _identifier_names(value: object) -> set[str]:
    if not isinstance(value, str):
        return set()
    return {
        name
        for name in _IDENTIFIER.findall(value)
        if name not in _KEYWORDS and len(name) > 1
    }


def _names(item: Mapping[str, Any], *, include_code: bool = True) -> set[str]:
    result: set[str] = set()
    for key in ("defines", "uses"):
        values = item.get(key, [])
        if isinstance(values, list):
            result.update(
                str(value)
                for value in values
                if isinstance(value, str) and value.strip()
            )
    for key in ("name", "callee", "caller", "call"):
        value = item.get(key)
        if isinstance(value, str) and value.strip():
            result.update(_identifier_names(value))
    for key in ("condition", "type"):
        result.update(_identifier_names(item.get(key)))
    if include_code:
        result.update(_identifier_names(item.get("code")))
    return result


def _semantic_call(item: Mapping[str, Any]) -> bool:
    callee = str(item.get("callee", ""))
    code = str(item.get("code", ""))
    return bool(
        _SEED_WORDS.search(callee)
        or _SEED_WORDS.search(code)
        or _SIZE_WORDS.search(code)
        or "[" in code
        or "*" in code
    )


def _relevant(item: Mapping[str, Any], names: set[str], family: str) -> bool:
    if family in {"call_relations", "call_site_arguments"} and _NON_SEMANTIC_CALL.search(
        str(item.get("callee", item.get("call", "")))
    ):
        return False
    if family == "data_flow":
        explicit = _names(item, include_code=False)
        return bool(names.intersection(explicit or _names(item)))
    if family == "declarations":
        name = item.get("name")
        return isinstance(name, str) and name in names
    if family == "types":
        return bool(names.intersection(_names(item)))
    return bool(names.intersection(_names(item)))


def _rank(family: str, item: Mapping[str, Any]) -> tuple[int, int, int, str]:
    code = str(item.get("code", ""))
    provenance = str(item.get("provenance", ""))
    provenance_rank = {
        "joern_reaching_def": 0,
        "joern_control_dependence": 0,
        "cpg_control": 1,
        "cpg_call": 1,
        "syntactic_assignment": 2,
    }.get(provenance, 1)
    priority = 0
    if family in {"call_relations", "call_site_arguments"} and _semantic_call(item):
        priority += 100
    if _SIZE_WORDS.search(code) or _SIZE_WORDS.search(str(item.get("condition", ""))):
        priority += 50
    line = item.get("line")
    line_no = line if isinstance(line, int) and line > 0 else 2**31 - 1
    return (
        provenance_rank,
        -priority,
        line_no,
        json.dumps(item, sort_keys=True, ensure_ascii=True),
    )


def _compact_item(family: str, value: Mapping[str, Any]) -> dict[str, Any]:
    item = dict(value)
    if family == "call_relations" and item.get("caller") and item.get("callee"):
        # caller/callee/location are the relation; the call expression is
        # duplicated by call_site_arguments when arguments are available.
        item.pop("code", None)
    elif family == "control_dependencies" and item.get("condition"):
        # The condition and controlled line carry the contract; the complete
        # branch body is duplicate source and is often hundreds of tokens.
        item.pop("code", None)
    elif family == "declarations" and item.get("name"):
        # name/type/location is the declaration contract. Keep no duplicate
        # source spelling when the CPG already supplied those fields.
        item.pop("code", None)
    elif family == "data_flow" and item.get("provenance") == "syntactic_assignment":
        code = item.get("code")
        if isinstance(code, str) and len(code) > 240:
            # Do not emit a misleading partial initializer. The explicit
            # defines/uses/location fields are the safe source-level summary.
            item.pop("code", None)
    elif family == "callee_funcs":
        code = item.get("code")
        if isinstance(code, str) and len(code) > MAX_CALLEE_BODY_CHARS:
            # Keep the resolved callee contract and location.  A large body
            # would consume the budget and duplicate the call relation.
            item.pop("code", None)
    return item


def _semantic_key(family: str, item: Mapping[str, Any]) -> str:
    if family == "call_relations":
        value = {key: item.get(key) for key in ("caller", "callee", "code")}
    elif family == "call_site_arguments":
        value = {key: item.get(key) for key in ("call", "argument_index", "code")}
    elif family == "data_flow":
        value = {
            key: item.get(key)
            for key in ("file", "provenance", "defines", "uses", "code")
        }
    elif family == "control_dependencies":
        value = {key: item.get(key) for key in ("file", "condition", "uses", "line", "provenance")}
    else:
        value = dict(item)
    return json.dumps(value, sort_keys=True, ensure_ascii=True)


def _dedupe_cap(family: str, values: object) -> list[dict[str, Any]]:
    if not isinstance(values, list):
        return []
    unique: dict[str, dict[str, Any]] = {}
    for value in values:
        if not isinstance(value, Mapping):
            continue
        item = _compact_item(family, value)
        if family not in {"types"}:
            code = item.get("code", item.get("name", item.get("condition", "")))
            if not isinstance(code, str) or not code.strip():
                # A compact relation may intentionally have no code, but it
                # must still carry a source-level name/condition/contract.
                if not any(item.get(key) for key in ("name", "condition", "defines", "uses", "caller", "callee", "call")):
                    continue
        key = _semantic_key(family, item)
        if key not in unique:
            unique[key] = item
            continue
        previous = unique[key]
        if family == "data_flow":
            from_lines = {
                value
                for value in previous.get("from_lines", [previous.get("from_line")])
                if isinstance(value, int) and value > 0
            }
            if isinstance(item.get("from_line"), int) and item["from_line"] > 0:
                from_lines.add(item["from_line"])
            if len(from_lines) > 1:
                previous["from_lines"] = sorted(from_lines)
                previous.pop("from_line", None)
        elif family == "control_dependencies":
            controlled_lines = {
                value
                for value in previous.get("controlled_lines", [previous.get("controlled_line")])
                if isinstance(value, int) and value > 0
            }
            if isinstance(item.get("controlled_line"), int) and item["controlled_line"] > 0:
                controlled_lines.add(item["controlled_line"])
            if len(controlled_lines) > 1:
                previous["controlled_lines"] = sorted(controlled_lines)[:MAX_CONTROLLED_LINES]
                previous.pop("controlled_line", None)
    return sorted(unique.values(), key=lambda item: _rank(family, item))[: FAMILY_LIMITS[family]]


def _pack_under_budget(
    families: Mapping[str, list[dict[str, Any]]],
    *,
    max_tokens: int,
) -> dict[str, list[dict[str, Any]]]:
    def encoded_tokens(value: Mapping[str, list[dict[str, Any]]]) -> int:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        return estimate_context_tokens(encoded)

    def has_call_relation(value: Mapping[str, Any], callee: str) -> bool:
        return str(value.get("callee", "")) == callee

    def remove_one_low_priority(
        candidate: dict[str, list[dict[str, Any]]],
        family: str,
        *,
        required_callee: str,
    ) -> bool:
        values = candidate.get(family, [])
        if not values:
            return False
        if family == "call_relations":
            removable = [
                index
                for index, item in enumerate(values)
                if not has_call_relation(item, required_callee)
            ]
            if not removable:
                return False
            values.pop(removable[-1])
            retained_callees = {
                str(item.get("callee"))
                for item in values
                if item.get("callee")
            }
            candidate["call_site_arguments"] = [
                item
                for item in candidate.get("call_site_arguments", [])
                if str(item.get("call")) in retained_callees
            ]
            return True
        values.pop()
        return True

    def reserve_call_argument(
        current: dict[str, list[dict[str, Any]]],
    ) -> dict[str, list[dict[str, Any]]]:
        retained_calls = {
            str(item.get("callee"))
            for item in current.get("call_relations", [])
            if item.get("callee")
        }
        if not retained_calls:
            return current
        if current.get("call_site_arguments"):
            # The greedy pass already kept at least one valid call-site
            # argument.  Do not append the reservation candidate twice.
            return current

        reserved_argument: dict[str, Any] | None = None
        required_callee = ""
        for item in families.get("call_site_arguments", []):
            call = str(item.get("call", ""))
            if call in retained_calls:
                reserved_argument = item
                required_callee = call
                break
        if reserved_argument is None:
            return current

        candidate = {key: list(value) for key, value in current.items()}
        candidate.setdefault("call_site_arguments", []).append(reserved_argument)
        if encoded_tokens(candidate) <= max_tokens:
            return candidate

        # Preserve the relation and one argument, evicting the least important
        # families first.  The lists are already rank-sorted, so removing the
        # tail also removes the least useful item within each family.
        eviction_order = (
            "imports",
            "types",
            "declarations",
            "control_dependencies",
            "data_flow",
            "callee_funcs",
        )
        while encoded_tokens(candidate) > max_tokens:
            removed = False
            for family in eviction_order:
                if remove_one_low_priority(
                    candidate,
                    family,
                    required_callee=required_callee,
                ):
                    removed = True
                    break
            if not removed:
                # Never evict the relation needed to explain the argument.  If
                # the minimal pair itself does not fit, normal packing remains
                # the truthful fallback and emits no partial pair.
                return current
        return candidate

    selected: dict[str, list[dict[str, Any]]] = {}
    for family in _PACK_ORDER:
        for item in families.get(family, []):
            if family == "call_site_arguments":
                retained_calls = {
                    str(call.get("callee"))
                    for call in selected.get("call_relations", [])
                    if call.get("callee")
                }
                if str(item.get("call")) not in retained_calls:
                    continue
            candidate = {key: list(value) for key, value in selected.items()}
            candidate.setdefault(family, []).append(item)
            if encoded_tokens(candidate) <= max_tokens:
                selected = candidate
    selected = reserve_call_argument(selected)
    return {family: selected[family] for family in FAMILY_LIMITS if family in selected}


def _target_range(raw_facts: Mapping[str, object]) -> tuple[int, int] | None:
    start = raw_facts.get("target_start_line")
    end = raw_facts.get("target_end_line")
    if (
        isinstance(start, int)
        and not isinstance(start, bool)
        and isinstance(end, int)
        and not isinstance(end, bool)
        and start >= 1
        and end >= start
    ):
        return start, end
    return None


def _flow_in_target_scope(item: Mapping[str, Any], raw_facts: Mapping[str, object]) -> bool:
    target = _target_range(raw_facts)
    if target is None:
        return True
    start, end = target
    target_method = raw_facts.get("target_function")
    methods = {
        str(item.get(key))
        for key in ("from_method", "to_method")
        if isinstance(item.get(key), str) and item.get(key)
    }
    if isinstance(target_method, str) and target_method in methods:
        return True
    lines = [
        item.get("line"),
        item.get("from_line"),
    ]
    return any(isinstance(value, int) and start <= value <= end for value in lines)


def select_file_context(
    raw_facts: Mapping[str, object], *, max_tokens: int = SAFE_CONTEXT_TOKENS
) -> dict[str, list[dict[str, Any]]]:
    """Select a relation-aware, complete sparse context under a token budget."""
    if isinstance(max_tokens, bool) or not isinstance(max_tokens, int) or max_tokens < 1:
        raise ValueError("max_tokens must be a positive integer")

    calls = [item for item in raw_facts.get("call_relations", []) if isinstance(item, Mapping)]
    args = [item for item in raw_facts.get("call_site_arguments", []) if isinstance(item, Mapping)]
    names: set[str] = set()
    semantic_calls = [item for item in calls if _semantic_call(item)]
    seed_calls = semantic_calls or calls
    for item in args:
        if not seed_calls or any(item.get("call") == call.get("callee") for call in seed_calls):
            names.update(_names(item))
    for item in seed_calls:
        names.update(_names(item))
    if not names:
        for item in args:
            names.update(_names(item))

    selected: dict[str, list[dict[str, Any]]] = {}
    for _ in range(3):
        previous = set(names)
        selected["data_flow"] = [
            dict(item)
            for item in raw_facts.get("data_flow", [])
            if isinstance(item, Mapping)
            and _flow_in_target_scope(item, raw_facts)
            and (not names or _relevant(item, names, "data_flow"))
        ]
        for item in selected["data_flow"]:
            names.update(_names(item, include_code=False))
        if names == previous:
            break

    selected["call_relations"] = [
        dict(item)
        for item in calls
        if not _NON_SEMANTIC_CALL.search(str(item.get("callee", "")))
        and (not names or _relevant(item, names, "call_relations") or _semantic_call(item))
    ]
    selected_call_names = {str(item.get("callee")) for item in selected["call_relations"]}
    selected["call_site_arguments"] = [
        dict(item)
        for item in args
        if str(item.get("call", "")) in selected_call_names
        or (not names or _relevant(item, names, "call_site_arguments"))
    ]
    selected["control_dependencies"] = [
        dict(item)
        for item in raw_facts.get("control_dependencies", [])
        if isinstance(item, Mapping) and (not names or _relevant(item, names, "control_dependencies"))
    ]
    selected["declarations"] = [
        dict(item)
        for item in raw_facts.get("declarations", [])
        if isinstance(item, Mapping) and (not names or _relevant(item, names, "declarations"))
    ]
    declaration_types = {
        str(item.get("type"))
        for item in selected["declarations"]
        if isinstance(item.get("type"), str) and item.get("type")
    }
    selected["types"] = [
        dict(item)
        for item in raw_facts.get("types", [])
        if isinstance(item, Mapping)
        and (not declaration_types or str(item.get("name")) in declaration_types)
    ]
    selected_call_names = {str(item.get("callee")) for item in selected["call_relations"]}
    selected["callee_funcs"] = [
        dict(item)
        for item in raw_facts.get("callee_funcs", [])
        if isinstance(item, Mapping)
        and (not selected_call_names or str(item.get("name")) in selected_call_names)
    ]
    selected["imports"] = [
        dict(item) for item in raw_facts.get("imports", []) if isinstance(item, Mapping)
    ]

    capped: dict[str, list[dict[str, Any]]] = {}
    for family, values in selected.items():
        capped_values = _dedupe_cap(family, values)
        if capped_values:
            capped[family] = capped_values
    retained_call_names = {
        str(item.get("callee"))
        for item in capped.get("call_relations", [])
        if item.get("callee")
    }
    if "callee_funcs" in capped:
        capped["callee_funcs"] = [
            item
            for item in capped["callee_funcs"]
            if str(item.get("name")) in retained_call_names
        ]
        if not capped["callee_funcs"]:
            capped.pop("callee_funcs")
    return _pack_under_budget(capped, max_tokens=max_tokens)

"""Offline PrimeVul file-context build orchestration."""
import json
import os
import tempfile
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

@dataclass(frozen=True)
class FileContextResult:
    record: dict[str, Any]
    status: str
    reason: str | None = None


ProgressCallback = Callable[[int, int, FileContextResult], None]


class PrimeVulLocatorIndex:
    def __init__(self, values: Mapping[str, Any]) -> None:
        self.values = dict(values)
        self.float_values: dict[float, Mapping[str, Any] | None] = {}
        for key, value in self.values.items():
            if isinstance(key, str) and key.isdecimal() and isinstance(value, Mapping):
                try: number = float(key)
                except OverflowError: continue
                if number in self.float_values: self.float_values[number] = None
                else: self.float_values[number] = value

    @classmethod
    def load(cls, path: Path) -> "PrimeVulLocatorIndex":
        value = json.loads(Path(path).read_text(encoding="utf-8"))
        if not isinstance(value, Mapping): raise ValueError("file_info must be an object")
        return cls(value)

    def lookup(self, func_hash: object) -> Mapping[str, Any] | None:
        if isinstance(func_hash, bool): return None
        if isinstance(func_hash, int): value = self.values.get(str(func_hash))
        elif isinstance(func_hash, float): value = self.float_values.get(func_hash)
        else: return None
        return value if isinstance(value, Mapping) else None


class FileContextService:
    def __init__(self, resolver: PrimeVulFileSourceResolver, cpg_cache: FileCpgCache, joern: Any, *, dataset_root: Path) -> None:
        self.resolver, self.cpg_cache, self.joern = resolver, cpg_cache, joern
        self.dataset_root = Path(dataset_root)

    def process(self, raw: Mapping[str, Any], locators: PrimeVulLocatorIndex) -> FileContextResult:
        record = dict(raw)
        record["context"] = {}
        locator = locators.lookup(raw.get("func_hash"))
        if locator is None: return FileContextResult(record, "unavailable", "locator_missing")
        start, end = locator.get("start_line"), locator.get("end_line")
        if not isinstance(start, int) or isinstance(start, bool) or not isinstance(end, int) or isinstance(end, bool) or start < 1 or end < start:
            return FileContextResult(record, "unavailable", "invalid_source_range")
        try:
            source = self.resolver.resolve(locator=locator, repository_url=str(raw["project_url"]), fix_revision=str(raw["commit_id"]), dataset_root=self.dataset_root)
            artifact = self.cpg_cache.get_or_build(source)
            facts = self.joern.extract_file_context(artifact.cpg_path, source_file=artifact.staged_source, start_line=start, end_line=end)
            selected = select_file_context(facts)
            record["context"] = validate_complete_context(selected)
            return FileContextResult(record, "built")
        except FileContextBudgetError: return FileContextResult(record, "oversized", "context_over_2000_tokens")
        except (KeyError, FileSourceResolutionError, FileContextError, JoernError, OSError, ValueError):
            return FileContextResult(record, "unavailable", "context_extraction_failed")

    @staticmethod
    def _target_count(pairs: Path, limit: int | None) -> int:
        if limit is not None and limit <= 0:
            return 0
        total = 0
        with Path(pairs).open("r", encoding="utf-8-sig") as source:
            for line in source:
                if not line.strip():
                    continue
                raw = json.loads(line)
                if not isinstance(raw, Mapping) or raw.get("target") != 1:
                    continue
                total += 1
                if limit is not None and total >= limit:
                    break
        return total

    def build_jsonl(
        self,
        pairs: Path,
        file_info: Path,
        output: Path,
        *,
        limit: int | None = None,
        report: Path | None = None,
        progress: ProgressCallback | None = None,
    ) -> dict[str, int]:
        locators = PrimeVulLocatorIndex.load(file_info)
        counts = {"total": 0, "built": 0, "unavailable": 0, "failed": 0, "oversized": 0}
        total_targets = self._target_count(pairs, limit)
        output.parent.mkdir(parents=True, exist_ok=True)
        fd, temp_name = tempfile.mkstemp(dir=output.parent, prefix=f".{output.name}.")
        try:
            with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as target, Path(pairs).open("r", encoding="utf-8-sig") as source:
                for line in source:
                    if not line.strip(): continue
                    raw = json.loads(line)
                    if not isinstance(raw, Mapping) or raw.get("target") != 1: continue
                    if limit is not None and counts["total"] >= limit: break
                    counts["total"] += 1
                    result = self.process(raw, locators)
                    counts[result.status] += 1
                    target.write(json.dumps(result.record, ensure_ascii=False, separators=(",", ":")) + "\n")
                    if progress is not None:
                        progress(counts["total"], total_targets, result)
            os.replace(temp_name, output)
        except Exception:
            Path(temp_name).unlink(missing_ok=True)
            raise
        if report is not None:
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(json.dumps(counts, indent=2) + "\n", encoding="utf-8")
        return counts

# The Joern transport query is embedded so this directory contains one executable file.
_FILE_CONTEXT_SC = "import java.nio.charset.StandardCharsets\r\nimport java.nio.file.{Files, Paths}\r\nimport scala.util.control.NonFatal\r\nimport io.shiftleft.codepropertygraph.generated.nodes.*\r\nimport io.shiftleft.semanticcpg.language.*\r\nimport ujson.*\r\n\r\n@main def exec(cpgFile: String, sourceFile: String, startLine: Int, endLine: Int, outFile: String): Unit = {\r\n  importCpg(cpgFile)\r\n  val normalized = sourceFile.replace('\\\\', '/')\r\n  val sourceLabel = Paths.get(sourceFile).getFileName.toString.replace('\\\\', '/')\r\n  val sourceLines = Files.readAllLines(Paths.get(sourceFile), StandardCharsets.UTF_8).toArray(new Array[String](0)).toList\r\n  def line(n: AstNode): Int = n.lineNumber.getOrElse(0)\r\n  def normalizedPath(value: String): String = value.replace('\\\\', '/')\r\n  def sameSourceFile(value: String): Boolean = {\r\n    val candidate = normalizedPath(value)\r\n    candidate == normalized || candidate.endsWith(\"/\" + normalized) || normalized.endsWith(\"/\" + candidate)\r\n  }\r\n  def file(n: AstNode): String = {\r\n    val value = n match {\r\n      case m: Method => normalizedPath(m.filename)\r\n      case _ => n.astParentOption.map(file).getOrElse(sourceLabel)\r\n    }\r\n    if (sameSourceFile(value)) sourceLabel else value\r\n  }\r\n  def enclosingMethod(n: AstNode): Option[Method] = n match {\r\n    case m: Method => Some(m)\r\n    case _ => n.astParentOption.flatMap(enclosingMethod)\r\n  }\r\n  def methodName(n: AstNode): String = enclosingMethod(n).map(_.name).getOrElse(\"\")\r\n  def code(n: AstNode): String = Option(n.code).getOrElse(\"\").trim\r\n  def ids(n: AstNode): List[String] = n.ast.isIdentifier.name.toList.filter(_.nonEmpty).distinct\r\n  def item(fields: (String, Value)*): Value = {\r\n    val result = Obj()\r\n    fields.foreach { case (key, value) => result(key) = value }\r\n    result\r\n  }\r\n  def sourceItem(n: AstNode, fields: (String, Value)*): Option[Value] =\r\n    if (line(n) > 0 && code(n).nonEmpty) Some(item(\r\n      (List(\"code\" -> Str(code(n)), \"file\" -> Str(file(n)), \"line\" -> Num(line(n).toDouble)) ++ fields.toList): _*)) else None\r\n  def controlCondition(n: AstNode): String = n match {\r\n    case c: ControlStructure =>\r\n      try c.condition.code.headOption.getOrElse(code(c)) catch { case NonFatal(_) => code(c) }\r\n    case _ => code(n)\r\n  }\r\n  def write(status: String, methodName: String = \"\", families: Map[String, List[Value]] = Map.empty, candidates: List[Method] = Nil,\r\n    targetStartLine: Int = startLine, targetEndLine: Int = endLine): Unit = {\r\n    val out = Obj(\"target_status\" -> Str(status), \"target_function\" -> Str(methodName))\r\n    out(\"target_start_line\") = Num(targetStartLine.toDouble)\r\n    out(\"target_end_line\") = Num(targetEndLine.toDouble)\r\n    out(\"candidates\") = Arr.from(candidates.map(m => item(\"name\" -> Str(m.name), \"file\" -> Str(m.filename), \"start_line\" -> Num(m.lineNumber.getOrElse(0).toDouble), \"end_line\" -> Num(m.lineNumberEnd.getOrElse(0).toDouble))))\r\n    List(\"imports\", \"callee_funcs\", \"call_relations\", \"call_site_arguments\", \"data_flow\",\r\n      \"control_dependencies\", \"declarations\", \"types\").foreach(k => out(k) = Arr.from(families.getOrElse(k, Nil)))\r\n    Files.writeString(Paths.get(outFile), out.render(), StandardCharsets.UTF_8)\r\n  }\r\n  val namedCandidates = cpg.method.filterNot(m => m.name == \"<global>\" || m.name == \"<module>\").filter { m =>\r\n    sameSourceFile(m.filename)\r\n  }.filter { m => m.lineNumber.exists(_ <= startLine) && m.lineNumberEnd.exists(_ >= endLine) }.toList\r\n  val globalCandidates = cpg.method.filter { m =>\r\n    (m.name == \"<global>\" || m.name == \"<module>\") && sameSourceFile(m.filename)\r\n  }.filter { m => m.lineNumber.exists(_ <= startLine) && m.lineNumberEnd.exists(_ >= endLine) }.toList\r\n  val sourceFallback = namedCandidates.isEmpty && globalCandidates.nonEmpty\r\n  val candidates = if (namedCandidates.nonEmpty) namedCandidates else globalCandidates\r\n  if (candidates.isEmpty) { write(\"not_found\"); return }\r\n  val ordered = candidates.sortBy(m => m.lineNumberEnd.getOrElse(Int.MaxValue) - m.lineNumber.getOrElse(0))\r\n  if (ordered.size > 1 && (ordered(0).lineNumberEnd.getOrElse(Int.MaxValue) - ordered(0).lineNumber.getOrElse(0)) ==\r\n      (ordered(1).lineNumberEnd.getOrElse(Int.MaxValue) - ordered(1).lineNumber.getOrElse(0))) {\r\n    write(\"ambiguous\", candidates = ordered.take(4)); return\r\n  }\r\n  val method = ordered.head\r\n  val sourceCallPattern = \"\"\"\\b([A-Za-z_][A-Za-z0-9_]*)\\s*\\(([^()]*)\\)\"\"\".r\r\n  val sourceControlNames = Set(\"if\", \"else\", \"for\", \"while\", \"switch\", \"catch\", \"sizeof\")\r\n  val sourceFunctionDeclPattern = \"\"\"^\\s*[A-Za-z_][A-Za-z0-9_:<>*&\\s]*\\s+([A-Za-z_][A-Za-z0-9_]*)\\s*\\(\"\"\".r\r\n  val sourceTargetDeclaration = sourceLines.zipWithIndex.collectFirst {\r\n    case (text, index) if index + 1 >= startLine && index + 1 <= endLine && sourceFunctionDeclPattern.findFirstMatchIn(text).nonEmpty =>\r\n      (sourceFunctionDeclPattern.findFirstMatchIn(text).get.group(1), index + 1)\r\n  }\r\n  val sourceTargetName = sourceTargetDeclaration.map(_._1).getOrElse(method.name)\r\n  val selectedStartLine = if (sourceFallback) sourceTargetDeclaration.map(_._2).getOrElse(startLine) else startLine\r\n  def inSelectedRange(n: AstNode): Boolean = line(n) >= selectedStartLine && line(n) <= endLine\r\n  val methodNameForContext = if (sourceFallback) sourceTargetName else method.name\r\n  val imports = sourceLines.zipWithIndex.collect {\r\n    case (text, index) if text.trim.startsWith(\"#include\") || text.trim.startsWith(\"import \") =>\r\n      item(\"code\" -> Str(text.trim), \"file\" -> Str(sourceLabel), \"line\" -> Num((index + 1).toDouble), \"provenance\" -> Str(\"source_include\"))\r\n  }\r\n  val declarationNodes = (method.parameter ++ method.local).filter(n => !sourceFallback || inSelectedRange(n)).toList\r\n  val cpgDeclarations = declarationNodes.flatMap { n =>\r\n    val t = n match { case x: MethodParameterIn => x.typeFullName; case x: Local => x.typeFullName }\r\n    sourceItem(n, \"name\" -> Str(n.name), \"type\" -> Str(t), \"provenance\" -> Str(\"cpg_declaration\"))\r\n  }.toList\r\n  val sourceFallbackDeclarations: List[Value] = if (!sourceFallback) Nil else {\r\n    val header = sourceLines.slice(selectedStartLine - 1, math.min(endLine, sourceLines.size)).mkString(\" \").split(\"\\\\{\", 2).head\r\n    val open = header.indexOf(\"(\")\r\n    val close = header.lastIndexOf(\")\")\r\n    if (open < 0 || close <= open) Nil\r\n    else header.substring(open + 1, close).split(\",\").toList.zipWithIndex.flatMap { case (raw, index) =>\r\n      val cleaned = raw.replaceAll(\"/\\\\*.*?\\\\*/\", \"\").trim\r\n      if (cleaned.isEmpty || cleaned == \"void\") Nil\r\n      else {\r\n        val namePattern = \"\"\"([A-Za-z_][A-Za-z0-9_]*)\\s*$\"\"\".r\r\n        namePattern.findFirstMatchIn(cleaned).map { matched =>\r\n          val name = matched.group(1)\r\n          val typeName = cleaned.substring(0, matched.start(1)).trim\r\n          item(\"code\" -> Str(cleaned), \"file\" -> Str(sourceLabel), \"line\" -> Num(selectedStartLine.toDouble),\r\n            \"name\" -> Str(name), \"type\" -> Str(typeName), \"argument_index\" -> Num(index.toDouble),\r\n            \"provenance\" -> Str(\"source_declaration_fallback\"))\r\n        }.toList\r\n      }\r\n    }\r\n  }\r\n  val declarations = cpgDeclarations ++ sourceFallbackDeclarations\r\n  // Materialize once: Joern traversals are iterator-backed and reusing a\r\n  // lazy traversal after callRelations can silently empty later families.\r\n  val calls = method.call.filterNot(_.name.startsWith(\"<operator\")).filter(c => !sourceFallback || inSelectedRange(c)).toList\r\n  val callRelations = calls.flatMap { c => sourceItem(c, \"caller\" -> Str(methodNameForContext), \"callee\" -> Str(c.name), \"provenance\" -> Str(\"cpg_call\")) }.toList\r\n  def argumentItem(argument: AstNode, call: Call, index: Int): Option[Value] = {\r\n    val argumentLine = if (line(argument) > 0) line(argument) else line(call)\r\n    val argumentFile = if (line(argument) > 0) file(argument) else file(call)\r\n    val argumentCode = code(argument)\r\n    if (argumentLine > 0 && argumentCode.nonEmpty) Some(item(\r\n      \"code\" -> Str(argumentCode), \"file\" -> Str(argumentFile), \"line\" -> Num(argumentLine.toDouble),\r\n      \"call\" -> Str(call.name), \"argument_index\" -> Num(index.toDouble),\r\n      \"provenance\" -> Str(\"cpg_call_argument\"))) else None\r\n  }\r\n  val arguments = calls.flatMap { c => c.argument.toList.zipWithIndex.flatMap { case (a, i) =>\r\n    argumentItem(a, c, i)\r\n  }}.toList\r\n  val callees = calls.flatMap { c => c.callee.toList.collect { case m: Method if sameSourceFile(m.filename) && !code(m).trim.startsWith(\"#define\") =>\r\n    item(\"code\" -> Str(code(m)), \"name\" -> Str(m.name), \"signature\" -> Str(m.signature),\r\n      \"file\" -> Str(sourceLabel), \"line\" -> Num(line(m).toDouble),\r\n      \"start_line\" -> Num(line(m).toDouble), \"end_line\" -> Num(m.lineNumberEnd.getOrElse(line(m)).toDouble),\r\n      \"provenance\" -> Str(\"cpg_same_file_callee\"))\r\n  }}.toList\r\n\r\n  val knownCallKeys = calls.map(c => (c.name, line(c))).toSet\r\n  val sourceCallFallbacks = sourceLines.zipWithIndex.flatMap { case (text, index) =>\r\n    val currentLine = index + 1\r\n    if (currentLine < selectedStartLine || currentLine > endLine) Nil\r\n    else sourceCallPattern.findAllMatchIn(text).toList.flatMap { matched =>\r\n      val name = matched.group(1)\r\n      val expression = matched.group(0).trim\r\n      val arguments = matched.group(2).split(\",\").toList.map(_.trim).filter(_.nonEmpty)\r\n      if (name == methodNameForContext\r\n          || currentLine == method.lineNumber.getOrElse(-1)\r\n          || sourceControlNames.contains(name)\r\n          || knownCallKeys.contains((name, currentLine))) Nil\r\n      else List((name, expression, arguments, currentLine))\r\n    }\r\n  }\r\n  val sourceCallRelations = sourceCallFallbacks.map { case (name, expression, _, currentLine) =>\r\n    item(\"code\" -> Str(expression), \"file\" -> Str(sourceLabel), \"line\" -> Num(currentLine.toDouble),\r\n      \"caller\" -> Str(methodNameForContext), \"callee\" -> Str(name), \"provenance\" -> Str(\"source_call_fallback\"))\r\n  }\r\n  val sourceCallArguments = sourceCallFallbacks.flatMap { case (name, _, arguments, currentLine) =>\r\n    arguments.zipWithIndex.map { case (argument, index) =>\r\n      item(\"code\" -> Str(argument), \"file\" -> Str(sourceLabel), \"line\" -> Num(currentLine.toDouble),\r\n        \"call\" -> Str(name), \"argument_index\" -> Num(index.toDouble),\r\n        \"provenance\" -> Str(\"source_call_fallback\"))\r\n    }\r\n  }\r\n  val assignments = method.call.filter(_.name.startsWith(\"<operator>.assignment\")).filter(a => !sourceFallback || inSelectedRange(a)).flatMap { a =>\r\n    sourceItem(a, \"defines\" -> Arr.from(a.argument.headOption.toList.flatMap(ids).map(Str(_))),\r\n      \"uses\" -> Arr.from(a.argument.drop(1).flatMap(ids).map(Str(_))), \"provenance\" -> Str(\"syntactic_assignment\"))\r\n  }.toList\r\n  val dataFlow = try {\r\n    if (!cpg.metaData.headOption.exists(_.overlays.contains(\"ossdataflow\"))) run.ossdataflow\r\n    val flowSources = declarationNodes\r\n    val flowSinks: Iterator[CfgNode] = calls.iterator.flatMap(_.argument).map(x => x: CfgNode)\r\n    flowSinks.reachableByFlows(flowSources).take(80).flatMap { path =>\r\n      path.elements.toList.collect { case n: AstNode => n }.sliding(2).flatMap {\r\n        case List(from, to) if line(from) > 0 && line(to) > 0 && code(from).nonEmpty && code(to).nonEmpty &&\r\n            (!sourceFallback || (inSelectedRange(from) && inSelectedRange(to))) =>\r\n          Some(item(\"code\" -> Str(code(from) + \" -> \" + code(to)), \"file\" -> Str(file(to)),\r\n            \"line\" -> Num(line(to).toDouble), \"from_line\" -> Num(line(from).toDouble),\r\n            \"from_file\" -> Str(file(from)), \"from_method\" -> Str(methodName(from)),\r\n            \"to_method\" -> Str(methodName(to)),\r\n            \"defines\" -> Arr.from(ids(to).map(Str(_))), \"uses\" -> Arr.from(ids(from).map(Str(_))),\r\n            \"provenance\" -> Str(\"joern_reaching_def\")))\r\n        case _ => None\r\n      }\r\n    }.toList\r\n  } catch { case NonFatal(_) => Nil }\r\n  val controls = method.ast.isControlStructure.filter(c => !sourceFallback || inSelectedRange(c)).flatMap { c =>\r\n    val condition = controlCondition(c)\r\n    if (condition.nonEmpty) sourceItem(c, \"condition\" -> Str(condition), \"provenance\" -> Str(\"cpg_control\")) else None\r\n  }.toList\r\n  val types = declarations.flatMap(v => List(v(\"type\").str)).filter(_.nonEmpty).distinct.sorted.map(t => item(\"name\" -> Str(t), \"provenance\" -> Str(\"cpg_type\")))\r\n  val controlledCalls = calls.flatMap { call =>\r\n    try call.controlledBy.flatMap { guard =>\r\n      sourceItem(guard, \"condition\" -> Str(controlCondition(guard)),\r\n        \"controlled_line\" -> Num(line(call).toDouble), \"provenance\" -> Str(\"joern_control_dependence\"))\r\n    }.toList catch { case NonFatal(_) => Nil }\r\n  }.toList\r\n  write(\"exact\", methodNameForContext, Map(\r\n    \"imports\" -> imports, \"callee_funcs\" -> callees,\r\n    \"call_site_arguments\" -> (arguments ++ sourceCallArguments),\r\n    \"call_relations\" -> (callRelations ++ sourceCallRelations),\r\n    \"data_flow\" -> (dataFlow ++ assignments), \"control_dependencies\" -> (controls ++ controlledCalls),\r\n    \"declarations\" -> declarations, \"types\" -> types),\r\n    targetStartLine = if (sourceFallback) selectedStartLine else method.lineNumber.getOrElse(startLine),\r\n    targetEndLine = if (sourceFallback) endLine else method.lineNumberEnd.getOrElse(endLine))\r\n}\r\n\r\n"

def _embedded_file_context_script() -> Path:
    digest = hashlib.sha256(_FILE_CONTEXT_SC.encode('utf-8')).hexdigest()[:16]
    path = Path(tempfile.gettempdir()) / f'vulsor-file-context-{digest}.sc'
    if not path.is_file() or path.read_text(encoding='utf-8') != _FILE_CONTEXT_SC:
        path.write_text(_FILE_CONTEXT_SC, encoding='utf-8', newline='\n')
    return path

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog='context_tool')
    parser.add_argument('command', choices=('build',), help='Build offline PrimeVul file context')
    parser.add_argument('--config', type=Path)
    parser.add_argument('--pairs', required=True, type=Path)
    parser.add_argument('--file-info', required=True, type=Path)
    parser.add_argument('--dataset-root', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--limit', type=int)
    parser.add_argument('--progress', action='store_true')
    parser.set_defaults(handler=handle_file_context)
    return parser

def _file_context_progress(current: int, total: int, result: FileContextResult) -> None:
    sample = result.record.get('idx', result.record.get('func_hash', '?'))
    detail = f' reason={result.reason}' if result.reason else ''
    ratio = current / total if total > 0 else 1.0
    percent = min(100, max(0, int(ratio * 100)))
    width = 24
    filled = int(width * percent / 100)
    bar = '#' * filled + '.' * (width - filled)
    line = f'[{bar}] {percent}% {current}/{total} {result.status} sample={sample}{detail}'
    print('\r' + line.ljust(120), end='\n' if current >= total else '', flush=True)

def handle_file_context(args: argparse.Namespace, config: VulSORConfig) -> int:
    try:
        if args.limit is not None and args.limit < 1:
            raise ValueError('limit must be >= 1')
        if args.pairs.resolve() == args.output.resolve():
            raise ValueError('pairs and output paths must differ')
        report = args.report or args.dataset_root / 'context' / 'file-context-report.json'
        joern = JoernAdapter(config, file_context_script=_embedded_file_context_script())
        service = FileContextService(
            PrimeVulFileSourceResolver(args.dataset_root / 'context' / 'files'),
            FileCpgCache(args.dataset_root / 'context' / 'file-cpg', joern),
            joern,
            dataset_root=args.dataset_root,
        )
        progress = _file_context_progress if args.progress else None
        print(json.dumps(service.build_jsonl(
            args.pairs, args.file_info, args.output, limit=args.limit, report=report, progress=progress
        )))
        return 0
    except (OSError, ValueError, TypeError, KeyError, JoernError):
        print(json.dumps({'status': 'unavailable', 'error': 'Context build failed; verify inputs, metadata and Joern availability'}))
        return 1

def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(list(sys.argv[1:] if argv is None else argv))
    return args.handler(args, load_config(args.config))

if __name__ == '__main__':
    raise SystemExit(main())
