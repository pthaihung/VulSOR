"""Safe process boundaries for Joern CPG construction and queries."""

from __future__ import annotations

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

from vulsor.config import (  # type: ignore[import-untyped]
    RepositoryContextConfig,
    ToolsConfig,
    VulSORConfig,
)

from .git_repository import CommandResult, CommandRunner, SubprocessCommandRunner
from .models import EvidenceRequest


_MAX_DIAGNOSTIC_CHARS = 4096
_REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
_SMOKE_FIELDS = ("methodCount", "callCount", "fileCount")
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
    checkout = Path(__file__).resolve().parents[3] / "scripts" / "joern" / name
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


class JoernAdapter:
    """Run Joern and exchange data only through explicit files and arguments."""

    def __init__(
        self,
        config: RepositoryContextConfig | VulSORConfig | None = None,
        *,
        runner: CommandRunner | None = None,
        tools: ToolsConfig | None = None,
        joern_executable: str | Path | None = None,
        joern_parse_executable: str | Path | None = None,
        joern: str | Path | None = None,
        joern_parse: str | Path | None = None,
        smoke_script: str | Path | None = None,
        smoke_script_path: str | Path | None = None,
        evidence_script: str | Path | None = None,
        evidence_script_path: str | Path | None = None,
        query_script: str | Path | None = None,
        query_script_path: str | Path | None = None,
    ) -> None:
        if isinstance(config, VulSORConfig):
            repository_config = config.repository_context
            configured_tools = config.tools
        elif isinstance(config, RepositoryContextConfig):
            repository_config = config
            configured_tools = ToolsConfig()
        elif config is None:
            repository_config = RepositoryContextConfig()
            configured_tools = ToolsConfig()
        else:
            raise TypeError("config must be RepositoryContextConfig or VulSORConfig")

        configured_tools = tools or configured_tools
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
        self.config = repository_config
        self._runner = runner or SubprocessCommandRunner()

        selected_smoke = _choose_alias(smoke_script, smoke_script_path, "smoke script")
        selected_evidence = _choose_alias(
            evidence_script, evidence_script_path, "evidence script"
        )
        selected_query = _choose_alias(query_script, query_script_path, "query script")
        if selected_evidence is not None and selected_query is not None:
            if Path(selected_evidence) != Path(selected_query):
                raise ValueError("conflicting evidence script values")
        selected_evidence_path: str | Path
        if selected_evidence is not None:
            selected_evidence_path = selected_evidence
        elif selected_query is not None:
            selected_evidence_path = selected_query
        else:
            selected_evidence_path = _default_script("repository_evidence.sc")
        self.smoke_script = Path(
            _default_script("smoke_cpg.sc")
            if selected_smoke is None
            else selected_smoke
        )
        self.evidence_script = Path(selected_evidence_path)

    def version(self) -> str:
        """Return the first nonblank line from ``joern --version``."""

        command = (self.joern_executable, "--version")
        result = self._run(
            command,
            timeout=self.config.query_timeout_seconds,
            paths=(Path(self.joern_executable),),
        )
        for line in _as_text(result.stdout).splitlines():
            normalized = line.strip()
            if normalized:
                return normalized
        raise JoernOutputError("Joern --version returned no nonblank output")

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

    def smoke(self, cpg_path: Path) -> dict[str, object]:
        """Run the smoke script and validate its readiness counts."""

        cpg_path = Path(cpg_path)
        _validate_regular_file(cpg_path, "CPG input", nonempty=True)
        script_path = self._validated_script(self.smoke_script, "smoke script")
        output_path: Path | None = None
        primary: BaseException | None = None
        try:
            output_path = self._temporary_file(".joern-smoke-")
            command = self._script_command(
                script_path,
                (f"cpgFile={os.fspath(cpg_path)}", f"outFile={os.fspath(output_path)}"),
            )
            self._run(
                command,
                timeout=self.config.query_timeout_seconds,
                paths=(cpg_path, script_path, output_path),
            )
            payload = self._read_json_object(
                output_path,
                self._diagnostic_paths((cpg_path, script_path, output_path)),
            )
            self._validate_smoke_payload(payload)
            return payload
        except BaseException as exc:
            primary = exc
            raise
        finally:
            if output_path is not None:
                self._finish_cleanup(((output_path, "smoke output"),), primary)

    def query(
        self,
        cpg_path: Path,
        request: EvidenceRequest,
    ) -> dict[str, object]:
        """Run the repository evidence script using request-file transport."""

        cpg_path = Path(cpg_path)
        _validate_regular_file(cpg_path, "CPG input", nonempty=True)
        script_path = self._validated_script(
            self.evidence_script, "repository evidence script"
        )
        try:
            request_model = (
                request
                if isinstance(request, EvidenceRequest)
                else EvidenceRequest.model_validate(request)
            )
        except (TypeError, ValueError) as exc:
            raise JoernError(
                f"invalid Joern evidence request: {_truncate(str(exc))}"
            ) from None

        output_path: Path | None = None
        request_path: Path | None = None
        primary: BaseException | None = None
        try:
            output_path = self._temporary_file(".joern-query-")
            request_path = self._temporary_file(".joern-request-")
            request_path.write_text(request_model.model_dump_json(), encoding="utf-8")

            command = self._script_command(
                script_path,
                (
                    f"cpgFile={os.fspath(cpg_path)}",
                    f"requestFile={os.fspath(request_path)}",
                    f"outFile={os.fspath(output_path)}",
                ),
            )
            self._run(
                command,
                timeout=self.config.query_timeout_seconds,
                paths=(cpg_path, script_path, request_path, output_path),
            )
            payload = self._read_json_object(
                output_path,
                self._diagnostic_paths(
                    (cpg_path, script_path, request_path, output_path)
                ),
            )
            return self._validate_query_payload(payload, request_model)
        except (OSError, TypeError, ValueError) as exc:
            request_error_paths = (request_path,) if request_path is not None else ()
            primary = JoernError(
                f"could not write Joern request file: "
                f"{_sanitize_text(exc, self._diagnostic_paths(request_error_paths))}"
            )
            raise primary from None
        except BaseException as exc:
            primary = exc
            raise
        finally:
            cleanup_paths: list[tuple[Path, str]] = []
            if request_path is not None:
                cleanup_paths.append((request_path, "request file"))
            if output_path is not None:
                cleanup_paths.append((output_path, "query output"))
            self._finish_cleanup(cleanup_paths, primary)

    def _diagnostic_paths(self, paths: Sequence[Path]) -> tuple[Path, ...]:
        return (
            *paths,
            Path(self.config.cache_root),
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
        command: list[str] = [self.joern_executable, "--script", os.fspath(script_path)]
        for parameter in parameters:
            command.extend(("--param", parameter))
        return tuple(command)

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

    @staticmethod
    def _validate_query_payload(
        payload: dict[str, object],
        request: EvidenceRequest,
    ) -> dict[str, object]:
        from .evidence import validate_raw_result

        try:
            return validate_raw_result(payload, request)
        except ValueError:
            raise JoernSchemaError(
                "Joern query output violates raw result schema"
            ) from None

    @staticmethod
    def _validate_smoke_payload(payload: dict[str, object]) -> None:
        missing = [field for field in _SMOKE_FIELDS if field not in payload]
        if missing:
            raise JoernSchemaError(
                "Joern smoke output is missing fields: " + ", ".join(missing)
            )
        counts: dict[str, int] = {}
        for field in _SMOKE_FIELDS:
            value = payload[field]
            if isinstance(value, bool) or not isinstance(value, int):
                raise JoernSchemaError(
                    f"Joern smoke field {field} must be a nonnegative integer"
                )
            if value < 0:
                raise JoernSchemaError(
                    f"Joern smoke field {field} must be a nonnegative integer"
                )
            counts[field] = value
        if counts["methodCount"] < 1:
            raise JoernSchemaError("Joern smoke field methodCount must be at least 1")

    def _run(
        self,
        command: Sequence[str],
        *,
        timeout: float | None,
        paths: Sequence[Path],
    ) -> CommandResult:
        diagnostic_paths = self._diagnostic_paths(paths)
        _validate_batch_arguments(command)
        try:
            result = self._runner.run(command, timeout=timeout)
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


__all__ = [
    "JoernAdapter",
    "JoernCommandError",
    "JoernCommandTimeoutError",
    "JoernError",
    "JoernOutputError",
    "JoernSchemaError",
]
