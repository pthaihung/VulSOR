import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

import pytest

from agents.repo_context.config import FileContextConfig, VulSORConfig
from agents.repo_context.joern import (
    CommandResult,
    JoernAdapter,
    JoernCommandError,
    JoernError,
    JoernSchemaError,
)


@dataclass
class FakeRunner:
    response: CommandResult | Callable[[tuple[str, ...]], CommandResult] = field(
        default_factory=lambda: CommandResult((), 0, "", "")
    )
    calls: list[tuple[tuple[str, ...], Path | None, float | None]] = field(
        default_factory=list
    )

    def run(
        self,
        arguments: Sequence[str],
        *,
        cwd: Path | None = None,
        timeout: float | None = None,
    ) -> CommandResult:
        normalized = tuple(arguments)
        self.calls.append((normalized, cwd, timeout))
        return self.response(normalized) if callable(self.response) else self.response


def adapter(tmp_path: Path, runner: FakeRunner) -> JoernAdapter:
    script = tmp_path / "file_context.sc"
    script.write_text("// fake file context script", encoding="utf-8")
    config = VulSORConfig(
        file_context=FileContextConfig(
            build_timeout_seconds=17,
            query_timeout_seconds=23,
        )
    )
    return JoernAdapter(
        config=config,
        runner=runner,
        joern_executable="joern-test",
        joern_parse_executable="joern-parse-test",
        file_context_script=script,
    )


def cpg_path(tmp_path: Path) -> Path:
    path = tmp_path / "cpg.bin"
    path.write_bytes(b"cpg")
    return path


def file_payload() -> dict[str, object]:
    return {
        "target_status": "exact",
        "imports": [],
        "callee_funcs": [],
        "call_relations": [],
        "call_site_arguments": [],
        "data_flow": [],
        "control_dependencies": [],
        "declarations": [],
        "types": [],
    }


def test_build_cpg_uses_c_frontend_argument_list_and_publishes_output(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    (source_root / "demo.c").write_text("int target(void) { return 0; }", encoding="utf-8")
    output_path = tmp_path / "cpg.bin"

    def parse(arguments: tuple[str, ...]) -> CommandResult:
        Path(arguments[-1]).write_bytes(b"built-cpg")
        return CommandResult(arguments, 0, "", "")

    runner = FakeRunner(parse)
    assert adapter(tmp_path, runner).build_cpg(source_root, output_path) is None
    assert output_path.read_bytes() == b"built-cpg"
    assert runner.calls[0][0][1:] == (
        str(source_root),
        "--language",
        "C",
        "-o",
        runner.calls[0][0][-1],
    )
    assert runner.calls[0][2] == 17


def test_extract_file_context_uses_source_span_and_validates_payload(
    tmp_path: Path,
) -> None:
    source_file = tmp_path / "demo.c"
    source_file.write_text("int target(void) { return 0; }", encoding="utf-8")
    observed: dict[str, str] = {}

    def extract(arguments: tuple[str, ...]) -> CommandResult:
        parameters = {
            arguments[index + 1].split("=", 1)[0]: arguments[index + 1].split("=", 1)[1]
            for index, value in enumerate(arguments[:-1])
            if value == "--param"
        }
        observed.update(parameters)
        Path(parameters["outFile"]).write_text(
            json.dumps(file_payload()), encoding="utf-8"
        )
        return CommandResult(arguments, 0, "", "")

    runner = FakeRunner(extract)
    result = adapter(tmp_path, runner).extract_file_context(
        cpg_path(tmp_path),
        source_file=source_file,
        start_line=4,
        end_line=8,
    )

    assert result == file_payload()
    assert observed["sourceFile"] == str(source_file)
    assert observed["startLine"] == "4"
    assert observed["endLine"] == "8"
    assert runner.calls[0][2] == 23


def test_extract_file_context_rejects_invalid_range_before_running_joern(
    tmp_path: Path,
) -> None:
    source_file = tmp_path / "demo.c"
    source_file.write_text("int target(void) { return 0; }", encoding="utf-8")
    runner = FakeRunner()

    with pytest.raises(JoernError, match="positive and ordered"):
        adapter(tmp_path, runner).extract_file_context(
            cpg_path(tmp_path),
            source_file=source_file,
            start_line=8,
            end_line=4,
        )

    assert runner.calls == []


def test_extract_file_context_rejects_malformed_output_and_cleans_transport(
    tmp_path: Path,
) -> None:
    source_file = tmp_path / "demo.c"
    source_file.write_text("int target(void) { return 0; }", encoding="utf-8")
    observed: list[Path] = []

    def malformed(arguments: tuple[str, ...]) -> CommandResult:
        output = Path(arguments[-1].split("=", 1)[1])
        observed.append(output)
        output.write_text("not json", encoding="utf-8")
        return CommandResult(arguments, 0, "", "")

    with pytest.raises(JoernSchemaError, match="JSON"):
        adapter(tmp_path, FakeRunner(malformed)).extract_file_context(
            cpg_path(tmp_path),
            source_file=source_file,
            start_line=1,
            end_line=1,
        )

    assert observed and not observed[0].exists()


def test_build_cpg_reports_nonzero_exit_without_leaking_paths(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    secret = str(source_root)
    runner = FakeRunner(CommandResult((), 7, "", f"failed at {secret}"))

    with pytest.raises(JoernCommandError) as caught:
        adapter(tmp_path, runner).build_cpg(source_root, tmp_path / "cpg.bin")

    assert secret not in str(caught.value)
    assert runner.calls
