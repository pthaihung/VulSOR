import json
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

import pytest

from vulsor.config import RepositoryContextConfig
from vulsor.repository_context.git_repository import CommandResult
from vulsor.repository_context.joern import JoernAdapter, JoernError
from vulsor.repository_context.models import EvidenceRequest


@dataclass
class FakeRunner:
    response: CommandResult | Exception | Callable[[tuple[str, ...]], CommandResult] \
        = field(default_factory=lambda: CommandResult((), 0, "", ""))
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
        response = self.response
        if callable(response):
            return response(normalized)
        if isinstance(response, Exception):
            raise response
        return response


def request() -> EvidenceRequest:
    return EvidenceRequest.model_validate(
        {
            "request_id": "req-1",
            "phase": "evaluate",
            "obligation_ref": "obligation-1",
            "repository_ref": {
                "repository_id": "demo",
                "repository_url": "https://example.test/demo.git",
                "revision": "a" * 40,
            },
            "anchor": {
                "file_path": "src/demo.c",
                "function_name": "target",
                "operation_kind": "call",
                "operation_name": "memcpy",
                "line": 4,
            },
            "questions": ["What calls this operation?"],
            "allowed_relations": ["call"],
        }
    )


def adapter(
    tmp_path: Path,
    runner: FakeRunner,
    *,
    evidence_script: Path | None = None,
) -> JoernAdapter:
    smoke_script = tmp_path / "smoke.sc"
    smoke_script.write_text("// fake smoke script", encoding="utf-8")
    return JoernAdapter(
        config=RepositoryContextConfig(
            cache_root=tmp_path / "cache",
            build_timeout_seconds=17,
            query_timeout_seconds=23,
        ),
        runner=runner,
        joern_executable="joern-test",
        joern_parse_executable="joern-parse-test",
        smoke_script=smoke_script,
        evidence_script=evidence_script,
    )


def cpg_path(tmp_path: Path) -> Path:
    path = tmp_path / "cpg.bin"
    path.write_bytes(b"cpg")
    return path


def test_version_uses_joern_version_and_normalizes_first_nonblank_line(
    tmp_path: Path,
) -> None:
    runner = FakeRunner(CommandResult((), 0, "\n  Joern 2.0.0  \nother\n", "logs"))
    current = adapter(tmp_path, runner)

    assert current.version() == "Joern 2.0.0"
    assert runner.calls == [(('joern-test', '--version'), None, 23)]


def test_build_cpg_uses_c_frontend_argument_list_and_requires_output(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    output_path = tmp_path / "building" / "cpg.bin"
    output_path.parent.mkdir()

    def parse(arguments: tuple[str, ...]) -> CommandResult:
        output_path.write_bytes(b"built cpg")
        return CommandResult(arguments, 0, "joern output", "")

    runner = FakeRunner(parse)
    current = adapter(tmp_path, runner)

    assert current.build_cpg(source_root, output_path) is None
    assert runner.calls == [
        (
            (
                "joern-parse-test",
                str(source_root),
                "--language",
                "C",
                "-o",
                str(output_path),
            ),
            None,
            17,
        )
    ]
    assert output_path.read_bytes() == b"built cpg"


def test_smoke_uses_repeated_params_and_reads_only_explicit_output(
    tmp_path: Path,
) -> None:
    cpg = cpg_path(tmp_path)

    def smoke(arguments: tuple[str, ...]) -> CommandResult:
        output = Path(arguments[-1].split("=", 1)[1])
        output.write_text(
            json.dumps({"methodCount": 2, "callCount": 3, "fileCount": 1}),
            encoding="utf-8",
        )
        return CommandResult(arguments, 0, '{"methodCount": 999}', "console log")

    runner = FakeRunner(smoke)
    current = adapter(tmp_path, runner)

    assert current.smoke(cpg) == {
        "methodCount": 2,
        "callCount": 3,
        "fileCount": 1,
    }
    arguments = runner.calls[0][0]
    assert arguments[:3] == ("joern-test", "--script", str(tmp_path / "smoke.sc"))
    assert arguments[3:] == (
        "--param",
        f"cpgFile={cpg}",
        "--param",
        "outFile=" + arguments[-1].split("=", 1)[1],
    )
    assert arguments.count("--param") == 2


def test_query_uses_request_file_and_cleans_transport_files(tmp_path: Path) -> None:
    cpg = cpg_path(tmp_path)
    evidence_script = tmp_path / "repository_evidence.sc"
    evidence_script.write_text("// fake evidence script", encoding="utf-8")
    observed_request_files: list[Path] = []

    def query(arguments: tuple[str, ...]) -> CommandResult:
        params = {
            arguments[index + 1].split("=", 1)[0]: Path(
                arguments[index + 1].split("=", 1)[1]
            )
            for index, value in enumerate(arguments[:-1])
            if value == "--param"
        }
        request_file = params["requestFile"]
        observed_request_files.append(request_file)
        assert json.loads(request_file.read_text(encoding="utf-8"))["request_id"] == (
            "req-1"
        )
        params["outFile"].write_text('{"status":"partial"}', encoding="utf-8")
        return CommandResult(arguments, 0, "ignored stdout", "ignored stderr")

    runner = FakeRunner(query)
    current = adapter(tmp_path, runner, evidence_script=evidence_script)

    assert current.query(cpg, request()) == {"status": "partial"}
    arguments = runner.calls[0][0]
    assert arguments[:3] == ("joern-test", "--script", str(evidence_script))
    assert arguments.count("--param") == 3
    assert any(argument.startswith("cpgFile=") for argument in arguments)
    assert any(argument.startswith("requestFile=") for argument in arguments)
    assert any(argument.startswith("outFile=") for argument in arguments)
    assert all(not path.exists() for path in observed_request_files)


@pytest.mark.parametrize("operation", ["smoke", "query"])
def test_nonzero_exit_is_typed_sanitized_and_truncated(
    tmp_path: Path,
    operation: str,
) -> None:
    cpg = cpg_path(tmp_path)
    evidence_script = tmp_path / "repository_evidence.sc"
    evidence_script.write_text("// fake evidence script", encoding="utf-8")
    secret_path = str(tmp_path)
    runner = FakeRunner(
        CommandResult(
            (),
            7,
            "stdout " + secret_path,
            "stderr " + secret_path + "\n" + ("x" * 5000),
        )
    )
    current = adapter(tmp_path, runner, evidence_script=evidence_script)

    with pytest.raises(JoernError) as caught:
        if operation == "smoke":
            current.smoke(cpg)
        else:
            current.query(cpg, request())

    message = str(caught.value)
    assert "exit code 7" in message
    assert secret_path not in message
    assert len(message) < 5000


def test_timeout_is_typed(tmp_path: Path) -> None:
    runner = FakeRunner(subprocess.TimeoutExpired("joern-test", 23, output="partial"))
    current = adapter(tmp_path, runner)

    with pytest.raises(JoernError, match="timed out"):
        current.version()


def test_smoke_rejects_missing_output_and_cleans_it(tmp_path: Path) -> None:
    cpg = cpg_path(tmp_path)

    def missing(arguments: tuple[str, ...]) -> CommandResult:
        output = Path(arguments[-1].split("=", 1)[1])
        output.unlink()
        return CommandResult(arguments, 0, "", "")

    runner = FakeRunner(missing)
    current = adapter(tmp_path, runner)

    with pytest.raises(JoernError, match="output"):
        current.smoke(cpg)


def test_smoke_rejects_malformed_json_and_cleans_output(tmp_path: Path) -> None:
    cpg = cpg_path(tmp_path)

    def malformed(arguments: tuple[str, ...]) -> CommandResult:
        output = Path(arguments[-1].split("=", 1)[1])
        output.write_text("not json", encoding="utf-8")
        return CommandResult(arguments, 0, "", "")

    runner = FakeRunner(malformed)
    current = adapter(tmp_path, runner)

    with pytest.raises(JoernError, match="JSON"):
        current.smoke(cpg)


@pytest.mark.parametrize(
    "payload",
    [
        {"methodCount": True, "callCount": 0, "fileCount": 0},
        {"methodCount": 0, "callCount": 0, "fileCount": 0},
        {"methodCount": 1, "callCount": -1, "fileCount": 0},
        {"methodCount": 1, "callCount": 0},
    ],
)
def test_smoke_rejects_json_that_violates_count_schema(
    tmp_path: Path,
    payload: dict[str, object],
) -> None:
    cpg = cpg_path(tmp_path)

    def invalid(arguments: tuple[str, ...]) -> CommandResult:
        output = Path(arguments[-1].split("=", 1)[1])
        output.write_text(json.dumps(payload), encoding="utf-8")
        return CommandResult(arguments, 0, "", "")

    runner = FakeRunner(invalid)
    current = adapter(tmp_path, runner)

    with pytest.raises(JoernError, match="schema|methodCount|callCount|fileCount"):
        current.smoke(cpg)


def test_query_rejects_non_object_json_and_cleans_output(tmp_path: Path) -> None:
    cpg = cpg_path(tmp_path)
    evidence_script = tmp_path / "repository_evidence.sc"
    evidence_script.write_text("// fake evidence script", encoding="utf-8")

    def invalid(arguments: tuple[str, ...]) -> CommandResult:
        output = Path(arguments[-1].split("=", 1)[1])
        output.write_text("[]", encoding="utf-8")
        return CommandResult(arguments, 0, "", "")

    runner = FakeRunner(invalid)
    current = adapter(tmp_path, runner, evidence_script=evidence_script)

    with pytest.raises(JoernError, match="object"):
        current.query(cpg, request())


def test_missing_query_script_is_reported_only_when_query_runs(tmp_path: Path) -> None:
    runner = FakeRunner()
    current = adapter(tmp_path, runner, evidence_script=tmp_path / "missing.sc")

    with pytest.raises(JoernError, match="script"):
        current.query(cpg_path(tmp_path), request())

    assert runner.calls == []
