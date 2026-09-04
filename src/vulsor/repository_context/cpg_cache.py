"""Validated revision-level cache for Joern CPG artifacts."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator, Literal, cast
from urllib.parse import urlsplit

from pydantic import Field, ValidationError, field_validator

from vulsor.config import RepositoryContextConfig

from .models import StrictModel


_FULL_SHA = re.compile(r"^[0-9a-fA-F]{40}$")
_CACHE_KEY = re.compile(r"^[0-9a-f]{64}$")
_SUPPORTED_URL_SCHEMES = frozenset({"https", "http", "ssh", "file"})
_MANIFEST_FIELDS = frozenset(
    {"schema_version", "cache_key", "identity", "status", "cpg_size_bytes"}
)
_IDENTITY_FIELDS = frozenset(
    {"repository_url", "revision", "joern_version", "frontend", "frontend_args"}
)


class CpgIdentity(StrictModel):
    """Inputs that uniquely identify one revision-level CPG artifact."""

    repository_url: str = Field(min_length=1)
    revision: str = Field(pattern=r"^[0-9a-fA-F]{40}$")
    joern_version: str = Field(min_length=1)
    frontend: str = Field(default="C", min_length=1)
    frontend_args: tuple[str, ...] = ()

    @field_validator("repository_url")
    @classmethod
    def supported_repository_url(cls, value: str) -> str:
        parsed = urlsplit(value)
        if parsed.scheme not in _SUPPORTED_URL_SCHEMES:
            raise ValueError("repository URL must use a supported scheme")
        if parsed.scheme == "file":
            if not parsed.path:
                raise ValueError("file repository URL must include a path")
        elif not parsed.netloc:
            raise ValueError("network repository URL must include a host")
        if "\x00" in value:
            raise ValueError("repository URL must not contain NUL")
        return value

    @field_validator("joern_version", "frontend")
    @classmethod
    def safe_text_fields(cls, value: str) -> str:
        if "\x00" in value:
            raise ValueError("identity fields must not contain NUL")
        return value

    @field_validator("frontend_args", mode="before")
    @classmethod
    def accept_json_frontend_args(cls, value: object) -> object:
        if isinstance(value, list):
            return tuple(value)
        if isinstance(value, tuple):
            return value
        raise ValueError("frontend_args must be a JSON array")

    @field_validator("frontend_args")
    @classmethod
    def safe_frontend_args(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if any("\x00" in argument for argument in value):
            raise ValueError("frontend_args must not contain NUL")
        return value


class CpgManifest(StrictModel):
    """On-disk manifest for a complete CPG cache entry."""

    schema_version: int = 1
    cache_key: str = Field(pattern=r"^[0-9a-f]{64}$")
    identity: CpgIdentity
    status: Literal["ready"] = "ready"
    cpg_size_bytes: int = Field(gt=0)


@dataclass(frozen=True)
class CpgArtifact:
    """A validated CPG artifact returned by :class:`CpgCache`."""

    cache_key: str
    root: Path
    cpg_path: Path
    cache_hit: bool


class CpgCacheError(RuntimeError):
    """Base class for CPG cache failures."""


class CpgCacheLockTimeoutError(CpgCacheError):
    """A CPG cache lock remained held until the configured timeout."""

    def __init__(
        self,
        lock_path: Path,
        timeout_seconds: float,
        lock_age_seconds: float,
        recorded_pid: int | None,
    ) -> None:
        self.lock_path = lock_path
        self.timeout_seconds = timeout_seconds
        self.lock_age_seconds = lock_age_seconds
        self.recorded_pid = recorded_pid
        self.pid = recorded_pid
        pid_text = str(recorded_pid) if recorded_pid is not None else "unknown"
        super().__init__(
            f"timed out after {timeout_seconds} seconds waiting for CPG cache lock "
            f"{lock_path}; lock_age_seconds={lock_age_seconds:.3f}; "
            f"recorded_pid={pid_text}"
        )


# Short aliases keep the error discoverable for callers that use a concise name.
CpgLockTimeoutError = CpgCacheLockTimeoutError


CpgBuilder = Callable[[Path], None]


class CpgCache:
    """Store and validate one CPG artifact per deterministic identity key.

    A builder receives a private temporary directory named ``<key>.building-<pid>``
    and must write a non-empty regular file named ``cpg.bin`` in that directory.
    The directory is promoted to the ready entry only after the file and manifest
    have been validated.
    """

    def __init__(
        self,
        config: RepositoryContextConfig | Path | str | None = None,
        *,
        cache_root: Path | str | None = None,
    ) -> None:
        if isinstance(config, (Path, str)):
            if cache_root is not None:
                raise ValueError("cache_root conflicts with positional cache root")
            cache_root = config
            config = None

        if config is None:
            repository_config = RepositoryContextConfig(
                cache_root=Path(cache_root)
                if cache_root is not None
                else Path("workspace/repository_context")
            )
        else:
            repository_config = cast(RepositoryContextConfig, config)
            if cache_root is not None and Path(repository_config.cache_root) != Path(
                cache_root
            ):
                raise ValueError("cache_root conflicts with config.cache_root")

        self.config: RepositoryContextConfig = repository_config
        self.cache_root = Path(repository_config.cache_root).expanduser().resolve()
        self.cache_root.mkdir(parents=True, exist_ok=True)
        self.cache_dir = self.cache_root / "cpg"
        self._ensure_cache_directory()

    @staticmethod
    def cache_key_for(identity: CpgIdentity) -> str:
        """Return the SHA-256 key for a validated CPG identity."""

        if not isinstance(identity, CpgIdentity):
            identity = CpgIdentity.model_validate(identity)
        payload = identity.model_dump(mode="json")
        serialized = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def entry_path_for(self, identity: CpgIdentity | str) -> Path:
        """Return the ready-entry path without reading or creating it."""

        return self.cache_dir / self._key_for(identity)

    def lock_path_for(self, identity: CpgIdentity | str) -> Path:
        """Return the lock path for an identity."""

        return self.cache_dir / f".{self._key_for(identity)}.lock"

    def building_path_for(self, identity: CpgIdentity | str) -> Path:
        """Return this process's temporary build path for an identity."""

        return self.cache_dir / f"{self._key_for(identity)}.building-{os.getpid()}"

    def read(self, identity: CpgIdentity) -> CpgArtifact | None:
        """Return a validated ready artifact, or ``None`` for a cache miss."""

        current = self._validated_identity(identity)
        key = self.cache_key_for(current)
        return self._read_ready(current, key)

    def get_or_build(self, identity: CpgIdentity, builder: CpgBuilder) -> CpgArtifact:
        """Return a ready artifact, invoking ``builder`` exactly on a cache miss."""

        current = self._validated_identity(identity)
        key = self.cache_key_for(current)
        entry_path = self.cache_dir / key
        lock_path = self.cache_dir / f".{key}.lock"

        ready = self._read_ready(current, key)
        if ready is not None:
            return ready

        building_path: Path | None = None
        with self._cache_lock(lock_path):
            ready = self._read_ready(current, key)
            if ready is not None:
                return ready

            self._remove_invalid_entry(entry_path)
            building_path = self.cache_dir / f"{key}.building-{os.getpid()}"
            self._create_building_directory(building_path)
            try:
                builder(building_path)
                self._assert_safe_existing_path(
                    building_path,
                    "temporary CPG build path",
                )
                cpg_path = self._validate_build_output(building_path)
                manifest = CpgManifest(
                    cache_key=key,
                    identity=current,
                    cpg_size_bytes=self._file_size(cpg_path),
                )
                self._write_manifest(building_path / "manifest.json", manifest)
                self._assert_safe_existing_path(building_path, "building directory")
                building_path.replace(entry_path)
                building_path = None
            finally:
                if building_path is not None:
                    self._remove_temporary_directory(building_path)

        return CpgArtifact(
            cache_key=key,
            root=entry_path,
            cpg_path=entry_path / "cpg.bin",
            cache_hit=False,
        )

    def _validated_identity(self, identity: CpgIdentity) -> CpgIdentity:
        if isinstance(identity, CpgIdentity):
            return identity
        return CpgIdentity.model_validate(identity)

    def _key_for(self, identity_or_key: CpgIdentity | str) -> str:
        if isinstance(identity_or_key, str):
            if not _CACHE_KEY.fullmatch(identity_or_key):
                raise ValueError("cache key must be a lowercase SHA-256 digest")
            return identity_or_key
        return self.cache_key_for(self._validated_identity(identity_or_key))

    def _ensure_cache_directory(self) -> None:
        if os.path.lexists(self.cache_dir):
            if self.cache_dir.is_symlink() or not self.cache_dir.is_dir():
                raise CpgCacheError(
                    f"CPG cache directory is not a real directory: {self.cache_dir}"
                )
            return
        self.cache_dir.mkdir()

    def _read_ready(self, identity: CpgIdentity, key: str) -> CpgArtifact | None:
        entry_path = self.cache_dir / key
        if not os.path.lexists(entry_path):
            return None
        if entry_path.is_symlink():
            return None
        if not entry_path.is_dir():
            return None
        try:
            self._assert_safe_existing_path(entry_path, "cache entry")
        except CpgCacheError:
            return None

        manifest_path = entry_path / "manifest.json"
        cpg_path = entry_path / "cpg.bin"
        if not self._is_regular_file(manifest_path) or not self._is_regular_file(
            cpg_path
        ):
            return None

        try:
            payload = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError):
            return None
        if not isinstance(payload, dict) or set(payload) != _MANIFEST_FIELDS:
            return None
        identity_payload = payload.get("identity")
        if not isinstance(identity_payload, dict) or set(identity_payload) != (
            _IDENTITY_FIELDS
        ):
            return None

        try:
            manifest = CpgManifest.model_validate(payload)
        except ValidationError:
            return None
        if manifest.schema_version != 1:
            return None
        if manifest.cache_key != key or manifest.identity != identity:
            return None

        try:
            cpg_size = self._file_size(cpg_path)
        except OSError:
            return None
        if cpg_size <= 0 or manifest.cpg_size_bytes != cpg_size:
            return None

        return CpgArtifact(
            cache_key=key,
            root=entry_path,
            cpg_path=cpg_path,
            cache_hit=True,
        )

    def _remove_invalid_entry(self, entry_path: Path) -> None:
        if not os.path.lexists(entry_path):
            return
        if entry_path.is_symlink():
            raise CpgCacheError(f"refusing to use symlink cache entry: {entry_path}")
        self._assert_safe_existing_path(entry_path, "cache entry")
        try:
            if entry_path.is_dir():
                shutil.rmtree(entry_path)
            else:
                entry_path.unlink()
        except OSError as exc:
            raise CpgCacheError(
                f"could not remove invalid CPG cache entry {entry_path}: {exc}"
            ) from exc

    def _create_building_directory(self, building_path: Path) -> None:
        if os.path.lexists(building_path):
            raise CpgCacheError(
                f"temporary CPG build path already exists: {building_path}"
            )
        try:
            building_path.mkdir()
        except OSError as exc:
            raise CpgCacheError(
                f"could not create temporary CPG build path {building_path}: {exc}"
            ) from exc

    def _validate_build_output(self, building_path: Path) -> Path:
        cpg_path = building_path / "cpg.bin"
        if not self._is_regular_file(cpg_path):
            raise ValueError("CPG builder must create a regular non-empty cpg.bin")
        size = self._file_size(cpg_path)
        if size <= 0:
            raise ValueError("CPG builder must create a non-empty cpg.bin")
        return cpg_path

    @staticmethod
    def _write_manifest(path: Path, manifest: CpgManifest) -> None:
        serialized = json.dumps(
            manifest.model_dump(mode="json"),
            sort_keys=True,
            indent=2,
            ensure_ascii=False,
        )
        with path.open("x", encoding="utf-8") as manifest_file:
            manifest_file.write(serialized + "\n")

    @staticmethod
    def _is_regular_file(path: Path) -> bool:
        try:
            info = os.lstat(path)
        except OSError:
            return False
        return stat.S_ISREG(info.st_mode)

    @staticmethod
    def _file_size(path: Path) -> int:
        info = os.stat(path, follow_symlinks=False)
        if not stat.S_ISREG(info.st_mode):
            raise OSError(f"not a regular file: {path}")
        return info.st_size

    def _assert_safe_existing_path(self, path: Path, label: str) -> None:
        if path.parent != self.cache_dir and path != self.cache_dir:
            raise CpgCacheError(f"{label} escaped the deterministic cache directory")
        if path != self.cache_dir and path.is_symlink():
            raise CpgCacheError(f"{label} must not be a symlink: {path}")
        try:
            resolved = path.resolve(strict=False)
        except OSError as exc:
            raise CpgCacheError(f"could not resolve {label} {path}: {exc}") from exc
        try:
            resolved.relative_to(self.cache_dir)
        except ValueError as exc:
            raise CpgCacheError(
                f"{label} escaped the deterministic cache directory: {path}"
            ) from exc

    def _remove_temporary_directory(self, building_path: Path) -> None:
        if not os.path.lexists(building_path):
            return
        if building_path.is_symlink():
            try:
                building_path.unlink()
            except OSError as exc:
                raise CpgCacheError(
                    f"could not clean temporary CPG path {building_path}: {exc}"
                ) from exc
            return
        self._assert_safe_existing_path(building_path, "temporary CPG build path")
        try:
            if building_path.is_dir():
                shutil.rmtree(building_path)
            else:
                building_path.unlink()
        except OSError as exc:
            raise CpgCacheError(
                f"could not clean temporary CPG path {building_path}: {exc}"
            ) from exc

    @contextmanager
    def _cache_lock(self, lock_path: Path) -> Iterator[None]:
        self._acquire_lock(lock_path)
        try:
            yield
        finally:
            try:
                lock_path.unlink()
            except FileNotFoundError:
                pass
            except OSError as exc:
                raise CpgCacheError(
                    f"could not release CPG cache lock {lock_path}: {exc}"
                ) from exc

    def _acquire_lock(self, lock_path: Path) -> None:
        timeout = float(self.config.lock_timeout_seconds)
        deadline = time.monotonic() + timeout
        while True:
            try:
                flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
                descriptor = os.open(lock_path, flags, 0o600)
            except FileExistsError:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    age, pid = self._lock_details(lock_path)
                    raise CpgCacheLockTimeoutError(
                        lock_path,
                        timeout,
                        age,
                        pid,
                    )
                time.sleep(min(0.05, remaining))
                continue
            except OSError as exc:
                raise CpgCacheError(
                    f"could not acquire CPG cache lock {lock_path}: {exc}"
                ) from exc

            created_at = time.time()
            try:
                with os.fdopen(descriptor, "w", encoding="utf-8") as lock_file:
                    lock_file.write(
                        f"pid={os.getpid()}\ncreated_at={created_at:.6f}\n"
                    )
                    lock_file.flush()
                    os.fsync(lock_file.fileno())
            except Exception as exc:
                try:
                    lock_path.unlink()
                except OSError:
                    pass
                raise CpgCacheError(
                    f"could not initialize CPG cache lock {lock_path}: {exc}"
                ) from exc
            return

    @staticmethod
    def _lock_details(lock_path: Path) -> tuple[float, int | None]:
        try:
            info = os.lstat(lock_path)
        except OSError:
            return 0.0, None

        created_at = float(info.st_mtime)
        recorded_pid: int | None = None
        if stat.S_ISREG(info.st_mode) and not stat.S_ISLNK(info.st_mode):
            try:
                values: dict[str, str] = {}
                for line in lock_path.read_text(encoding="utf-8").splitlines():
                    name, separator, value = line.partition("=")
                    if separator:
                        values[name] = value
                created_at = float(values.get("created_at", created_at))
                recorded_pid = int(values["pid"])
            except (OSError, UnicodeError, ValueError, KeyError):
                pass
        return max(0.0, time.time() - created_at), recorded_pid


__all__ = [
    "CpgArtifact",
    "CpgBuilder",
    "CpgCache",
    "CpgCacheError",
    "CpgCacheLockTimeoutError",
    "CpgIdentity",
    "CpgLockTimeoutError",
    "CpgManifest",
]
