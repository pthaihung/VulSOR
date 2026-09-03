"""Joern tool integration status for VulSOR."""

from __future__ import annotations

import subprocess
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


@dataclass(frozen=True)
class JoernStatus:
    """Availability and integration status for Joern/CPG analysis."""

    executable: str
    available: bool
    resolved_path: str | None
    cpg_integrated: bool
    message: str


@dataclass(frozen=True)
class CPGMethodFact:
    """Method fact extracted from a real Joern CPG."""

    name: str
    full_name: str
    filename: str
    line: int | None = None
    line_end: int | None = None


@dataclass(frozen=True)
class CPGCallFact:
    """Call fact extracted from a real Joern CPG."""

    caller: str
    callee: str
    method_full_name: str
    dispatch_type: str
    code: str
    filename: str
    line: int | None = None
    column: int | None = None


@dataclass(frozen=True)
class CPGAnalysisResult:
    """Result of a Joern CPG extraction attempt."""

    available: bool
    complete: bool
    cpg_integrated: bool
    methods: tuple[CPGMethodFact, ...] = ()
    calls: tuple[CPGCallFact, ...] = ()
    diagnostics: tuple[str, ...] = ()


class JoernAdapter:
    """Report Joern availability without pretending CPG facts exist."""

    def __init__(
        self,
        executable: str = "joern",
        c2cpg_executable: str = "c2cpg",
    ) -> None:
        self._executable = executable
        self._c2cpg_executable = c2cpg_executable

    def status(self) -> JoernStatus:
        """Return current Joern availability and B1 integration status."""
        resolved = shutil.which(self._executable)

        if resolved is None:
            return JoernStatus(
                executable=self._executable,
                available=False,
                resolved_path=None,
                cpg_integrated=False,
                message=(
                    "joern executable was not found; CPG facts are unavailable"
                ),
            )

        return JoernStatus(
            executable=self._executable,
            available=True,
            resolved_path=resolved,
            cpg_integrated=True,
            message=(
                "joern executable is available; Program Analysis can attempt "
                "CPG extraction"
            ),
        )

    def analyze_source_code(
        self,
        source_code: str,
        *,
        suffix: str = ".c",
        include_paths: Sequence[str] = (),
        defines: Sequence[str] = (),
        timeout_seconds: int = 120,
    ) -> CPGAnalysisResult:
        """Build a real CPG for source text and extract method/call facts."""
        joern_executable = shutil.which(self._executable)

        if joern_executable is None:
            return CPGAnalysisResult(
                available=False,
                complete=False,
                cpg_integrated=True,
                diagnostics=(
                    f"joern executable was not found: {self._executable}",
                ),
            )

        c2cpg_executable = self._resolve_c2cpg(joern_executable)

        if c2cpg_executable is None:
            return CPGAnalysisResult(
                available=False,
                complete=False,
                cpg_integrated=True,
                diagnostics=(
                    f"c2cpg executable was not found: {self._c2cpg_executable}",
                ),
            )

        with tempfile.TemporaryDirectory(prefix="vulsor-cpg-") as directory:
            root = Path(directory)
            source_dir = root / "src"
            source_dir.mkdir()
            source_file = source_dir / f"input{suffix}"
            source_file.write_text(source_code, encoding="utf-8")
            cpg_file = root / "cpg.bin"

            try:
                c2cpg_result = self._run_c2cpg(
                    c2cpg_executable,
                    source_dir,
                    cpg_file,
                    include_paths=include_paths,
                    defines=defines,
                    timeout_seconds=timeout_seconds,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                return CPGAnalysisResult(
                    available=True,
                    complete=False,
                    cpg_integrated=True,
                    diagnostics=(f"c2cpg execution failed: {exc}",),
                )

            if c2cpg_result.returncode != 0 or not cpg_file.is_file():
                return CPGAnalysisResult(
                    available=True,
                    complete=False,
                    cpg_integrated=True,
                    diagnostics=(
                        "c2cpg failed to create a CPG",
                        c2cpg_result.stderr.strip()
                        or c2cpg_result.stdout.strip(),
                    ),
                )

            script_file = self._write_query_script(root, cpg_file)
            try:
                joern_result = self._run_joern_script(
                    joern_executable,
                    script_file,
                    timeout_seconds=timeout_seconds,
                )
            except (OSError, subprocess.TimeoutExpired) as exc:
                return CPGAnalysisResult(
                    available=True,
                    complete=False,
                    cpg_integrated=True,
                    diagnostics=(f"joern execution failed: {exc}",),
                )

            if joern_result.returncode != 0:
                return CPGAnalysisResult(
                    available=True,
                    complete=False,
                    cpg_integrated=True,
                    diagnostics=(
                        "joern CPG query failed",
                        joern_result.stderr.strip()
                        or joern_result.stdout.strip(),
                    ),
                )

            methods, calls, parse_diagnostics = _parse_cpg_facts(
                joern_result.stdout
            )

            return CPGAnalysisResult(
                available=True,
                complete=not parse_diagnostics,
                cpg_integrated=True,
                methods=methods,
                calls=calls,
                diagnostics=parse_diagnostics,
            )

    def _resolve_c2cpg(self, joern_executable: str) -> str | None:
        resolved = shutil.which(self._c2cpg_executable)

        if resolved is not None:
            return resolved

        joern_path = Path(joern_executable)
        sibling = joern_path.with_name("c2cpg.bat")

        if sibling.is_file():
            return str(sibling)

        return None

    def _run_c2cpg(
        self,
        executable: str,
        source_dir: Path,
        cpg_file: Path,
        *,
        include_paths: Sequence[str],
        defines: Sequence[str],
        timeout_seconds: int,
    ) -> subprocess.CompletedProcess[str]:
        command = [
            executable,
            str(source_dir),
            "-o",
            str(cpg_file),
        ]

        for include_path in include_paths:
            command.extend(["--include", include_path])

        for define in defines:
            command.extend(["--define", define])

        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )

    def _run_joern_script(
        self,
        executable: str,
        script_file: Path,
        *,
        timeout_seconds: int,
    ) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                executable,
                "--script",
                str(script_file),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )

    def _write_query_script(
        self,
        root: Path,
        cpg_file: Path,
    ) -> Path:
        template_path = (
            Path(__file__).resolve().parents[3]
            / "scripts"
            / "joern"
            / "b1_facts.sc"
        )
        template = template_path.read_text(encoding="utf-8")
        cpg_path = str(cpg_file.resolve()).replace("\\", "/")
        script = template.replace("__VULSOR_CPG_PATH__", cpg_path)
        script_file = root / "b1_facts.sc"
        script_file.write_text(script, encoding="utf-8")
        return script_file


def _parse_cpg_facts(
    output: str,
) -> tuple[tuple[CPGMethodFact, ...], tuple[CPGCallFact, ...], tuple[str, ...]]:
    """Parse marked Joern output into CPG facts."""
    if "VULSOR_CPG_BEGIN" not in output or "VULSOR_CPG_END" not in output:
        return (), (), ("joern output did not contain CPG fact markers",)

    body = output.split("VULSOR_CPG_BEGIN", 1)[1].split(
        "VULSOR_CPG_END",
        1,
    )[0]
    methods: list[CPGMethodFact] = []
    calls: list[CPGCallFact] = []
    diagnostics: list[str] = []

    for line in body.splitlines():
        if not line.strip():
            continue

        parts = line.rstrip("\n").split("\t")

        if parts[0] == "METHOD" and len(parts) == 6:
            methods.append(
                CPGMethodFact(
                    name=parts[1],
                    full_name=parts[2],
                    filename=parts[3],
                    line=_optional_int(parts[4]),
                    line_end=_optional_int(parts[5]),
                )
            )
        elif parts[0] == "CALL" and len(parts) == 9:
            calls.append(
                CPGCallFact(
                    caller=parts[1],
                    callee=parts[2],
                    method_full_name=parts[3],
                    dispatch_type=parts[4],
                    code=parts[5],
                    filename=parts[6],
                    line=_optional_int(parts[7]),
                    column=_optional_int(parts[8]),
                )
            )
        else:
            diagnostics.append(f"unrecognized CPG fact line: {line}")

    return tuple(methods), tuple(calls), tuple(diagnostics)


def _optional_int(value: str) -> int | None:
    if not value:
        return None

    try:
        return int(value)
    except ValueError:
        return None
