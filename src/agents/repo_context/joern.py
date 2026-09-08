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

from .config import ToolsConfig, VulSORConfig


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


__all__ = [
    "JoernAdapter",
    "JoernCommandError",
    "JoernCommandTimeoutError",
    "JoernError",
    "JoernOutputError",
    "JoernSchemaError",
]
