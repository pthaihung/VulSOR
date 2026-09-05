import json
import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

import pytest

from vulsor.config import RepositoryContextConfig
from vulsor.repository_context.git_repository import CommandResult
from vulsor.repository_context.joern import (
    JoernAdapter,
    JoernCleanupError,
    JoernCommandError,
    JoernError,
)
from vulsor.repository_context.models import EvidenceRequest


@pytest.mark.skipif(os.name != "nt", reason="Windows path casing")
def test_windows_forward_slash_case_and_custom_executable_are_redacted(tmp_path):
    from vulsor.repository_context.joern import _sanitize_text

    sensitive = tmp_path / "Private" / "joern.exe"
    emitted = sensitive.as_posix().swapcase()
    assert emitted not in _sanitize_text(emitted, (sensitive,))
    runner = FakeRunner(CommandResult((), 1, "", emitted))
    current = JoernAdapter(runner=runner, joern_executable=sensitive)
    with pytest.raises(JoernError) as caught:
        current.version()
    assert emitted not in str(caught.value)
    assert str(sensitive) not in str(caught.value)


@dataclass
class FakeRunner:
    response: CommandResult | Exception | Callable[[tuple[str, ...]], CommandResult] = (
        field(default_factory=lambda: CommandResult((), 0, "", ""))
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
    cache_root: Path | None = None,
) -> JoernAdapter:
    smoke_script = tmp_path / "smoke.sc"
    smoke_script.write_text("// fake smoke script", encoding="utf-8")
    return JoernAdapter(
        config=RepositoryContextConfig(
            cache_root=cache_root or tmp_path / "cache",
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


def evidence_payload(*, request_id: str = "req-1") -> dict[str, object]:
    return {
        "request_id": request_id,
        "schema_version": 1,
        "resolved_revision": "a" * 40,
        "anchor_resolution": {"status": "exact", "candidate_count": 1},
        "families": {"call": []},
        "limitations": [],
        "truncated": False,
    }


def test_version_reads_the_single_joern_cli_jar_next_to_launcher(tmp_path: Path) -> None:
    launcher = tmp_path / "joern.bat"
    launcher.write_text("@echo off", encoding="utf-8")
    library = tmp_path / "lib"
    library.mkdir()
    (library / "io.joern.joern-cli-4.0.592.jar").write_bytes(b"jar")
    runner = FakeRunner()
    current = JoernAdapter(runner=runner, joern_executable=launcher)

    assert current.version() == "4.0.592"
    assert runner.calls == []


def test_build_cpg_uses_c_frontend_argument_list_and_requires_output(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    output_path = tmp_path / "building" / "cpg.bin"
    output_path.parent.mkdir()

    def parse(arguments: tuple[str, ...]) -> CommandResult:
        Path(arguments[-1]).write_bytes(b"built cpg")
        return CommandResult(arguments, 0, "joern output", "")

    runner = FakeRunner(parse)
    current = adapter(tmp_path, runner)

    assert current.build_cpg(source_root, output_path) is None
    assert runner.calls[0][1:] == (None, 17)
    arguments = runner.calls[0][0]
    assert arguments[:4] == (
        "joern-parse-test",
        str(source_root),
        "--language",
        "C",
    )
    assert arguments[4] == "-o"
    temporary_output = Path(arguments[5])
    assert temporary_output != output_path
    assert temporary_output.parent == output_path.parent
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
        params["outFile"].write_text(json.dumps(evidence_payload()), encoding="utf-8")
        return CommandResult(arguments, 0, "ignored stdout", "ignored stderr")

    runner = FakeRunner(query)
    current = adapter(tmp_path, runner, evidence_script=evidence_script)

    assert current.query(cpg, request()) == evidence_payload()
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


def test_combined_command_diagnostics_are_capped_at_4096_chars(
    tmp_path: Path,
) -> None:
    cpg = cpg_path(tmp_path)
    runner = FakeRunner(CommandResult((), 9, "s" * 8000, "e" * 8000))
    current = adapter(tmp_path, runner)

    with pytest.raises(JoernCommandError) as caught:
        current.smoke(cpg)

    error = caught.value
    assert len(error.stdout) + len(error.stderr) <= 4096
    assert len(error.diagnostics) <= 4096


def test_command_diagnostics_redact_source_and_cache_parent_paths(
    tmp_path: Path,
) -> None:
    source_parent = tmp_path / "source-parent"
    source_root = source_parent / "repository"
    source_root.mkdir(parents=True)
    cache_root = tmp_path / "cache-root"
    cpg = cpg_path(tmp_path)
    runner = FakeRunner(
        CommandResult(
            (),
            3,
            "",
            f"source={source_parent}; cache={cache_root}",
        )
    )
    current = adapter(tmp_path, runner, cache_root=cache_root)

    with pytest.raises(JoernError) as caught:
        current.smoke(cpg)

    message = str(caught.value)
    assert str(source_parent) not in message
    assert str(cache_root) not in message


def test_batch_launcher_rejects_metacharacter_paths_before_running(
    tmp_path: Path,
) -> None:
    cpg = tmp_path / "cpg&input.bin"
    cpg.write_bytes(b"cpg")
    smoke_script = tmp_path / "smoke.sc"
    smoke_script.write_text("// fake smoke script", encoding="utf-8")
    runner = FakeRunner()
    current = JoernAdapter(
        config=RepositoryContextConfig(cache_root=tmp_path / "cache"),
        runner=runner,
        joern_executable=tmp_path / "joern.cmd",
        joern_parse_executable="joern-parse-test",
        smoke_script=smoke_script,
    )

    with pytest.raises(JoernError, match="batch|metacharacter"):
        current.smoke(cpg)

    assert runner.calls == []


def test_build_failure_preserves_existing_output_after_partial_temp_write(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    output_path = tmp_path / "cpg.bin"
    output_path.write_bytes(b"pre-existing cpg")

    def partial(arguments: tuple[str, ...]) -> CommandResult:
        Path(arguments[-1]).write_bytes(b"partial replacement")
        return CommandResult(arguments, 12, "", "parse failed")

    runner = FakeRunner(partial)
    current = adapter(tmp_path, runner)

    with pytest.raises(JoernError, match="exit code 12"):
        current.build_cpg(source_root, output_path)

    assert output_path.read_bytes() == b"pre-existing cpg"
    assert not list(tmp_path.glob(f".{output_path.name}.joern-*"))


def test_version_requires_a_discoverable_joern_installation(tmp_path: Path) -> None:
    runner = FakeRunner(subprocess.TimeoutExpired("joern-test", 23, output="partial"))
    current = adapter(tmp_path, runner)

    with pytest.raises(JoernError, match="locate"):
        current.version()
    assert runner.calls == []


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


@pytest.mark.parametrize(
    "payload",
    [
        {"request_id": "req-1"},
        evidence_payload(request_id="different"),
    ],
)
def test_query_rejects_invalid_or_mismatched_repository_evidence(
    tmp_path: Path,
    payload: dict[str, object],
) -> None:
    cpg = cpg_path(tmp_path)
    evidence_script = tmp_path / "repository_evidence.sc"
    evidence_script.write_text("// fake evidence script", encoding="utf-8")

    def invalid(arguments: tuple[str, ...]) -> CommandResult:
        output = Path(arguments[-1].split("=", 1)[1])
        output.write_text(json.dumps(payload), encoding="utf-8")
        return CommandResult(arguments, 0, "", "")

    runner = FakeRunner(invalid)
    current = adapter(tmp_path, runner, evidence_script=evidence_script)

    with pytest.raises(JoernError, match="schema|request_id|RepositoryEvidence"):
        current.query(cpg, request())


def test_cleanup_failure_is_typed_when_no_primary_error_exists(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cpg = cpg_path(tmp_path)

    def valid_smoke(arguments: tuple[str, ...]) -> CommandResult:
        output = Path(arguments[-1].split("=", 1)[1])
        output.write_text(
            json.dumps({"methodCount": 1, "callCount": 0, "fileCount": 1}),
            encoding="utf-8",
        )
        return CommandResult(arguments, 0, "", "")

    runner = FakeRunner(valid_smoke)
    current = adapter(tmp_path, runner)

    def fail_unlink(self: Path, *, missing_ok: bool = False) -> None:
        raise OSError("cleanup denied")

    monkeypatch.setattr(Path, "unlink", fail_unlink)

    with pytest.raises(JoernCleanupError, match="cleanup"):
        current.smoke(cpg)


def test_cleanup_failure_is_reported_without_replacing_primary_error(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    cpg = cpg_path(tmp_path)

    def malformed(arguments: tuple[str, ...]) -> CommandResult:
        output = Path(arguments[-1].split("=", 1)[1])
        output.write_text("not json", encoding="utf-8")
        return CommandResult(arguments, 0, "", "")

    runner = FakeRunner(malformed)
    current = adapter(tmp_path, runner)

    def fail_unlink(self: Path, *, missing_ok: bool = False) -> None:
        raise OSError("cleanup denied")

    monkeypatch.setattr(Path, "unlink", fail_unlink)

    with pytest.raises(JoernError, match="JSON") as caught:
        current.smoke(cpg)

    assert any("cleanup" in note for note in getattr(caught.value, "__notes__", []))


def test_build_rejects_source_tree_links_before_invoking_joern(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    link = source_root / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are unavailable in this environment")

    runner = FakeRunner()
    current = adapter(tmp_path, runner)

    with pytest.raises(JoernError, match="symlink|reparse|junction"):
        current.build_cpg(source_root, tmp_path / "cpg.bin")

    assert runner.calls == []


def test_missing_query_script_is_reported_only_when_query_runs(tmp_path: Path) -> None:
    runner = FakeRunner()
    current = adapter(tmp_path, runner, evidence_script=tmp_path / "missing.sc")

    with pytest.raises(JoernError, match="script"):
        current.query(cpg_path(tmp_path), request())

    assert runner.calls == []
