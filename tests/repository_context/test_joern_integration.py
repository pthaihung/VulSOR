"""Run with VULSOR_RUN_JOERN=1 and both Joern executables on PATH."""

import os
import shutil
from pathlib import Path

import pytest

from vulsor.repository_context.evidence import normalize_repository_evidence
from vulsor.repository_context.joern import JoernAdapter
from vulsor.repository_context.models import EvidenceRequest


@pytest.mark.joern
@pytest.mark.skipif(
    os.environ.get("VULSOR_RUN_JOERN") != "1"
    or not shutil.which("joern")
    or not shutil.which("joern-parse"),
    reason="opt-in integration requires VULSOR_RUN_JOERN=1 and local Joern",
)
def test_real_anchored_call_and_optional_graph_families(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    fixture = Path(__file__).parents[1] / "fixtures/repository_context/demo.c"
    shutil.copyfile(fixture, root / "demo.c")
    adapter = JoernAdapter(
        joern_executable=shutil.which("joern"),
        joern_parse_executable=shutil.which("joern-parse"),
    )
    cpg_path = tmp_path / "cpg.bin"
    adapter.build_cpg(root, cpg_path)
    assert adapter.smoke(cpg_path)["methodCount"] >= 2
    request = EvidenceRequest.model_validate(
        {
            "request_id": "integration",
            "phase": "evaluate",
            "obligation_ref": "ob1",
            "repository_ref": {
                "repository_id": "demo",
                "repository_url": "https://example.test/demo.git",
                "revision": "a" * 40,
            },
            "anchor": {
                "file_path": "demo.c",
                "function_name": "target",
                "operation_kind": "call",
                "operation_name": "consume",
                "line": 7,
                "argument_index": 1,
                "entity": "input",
            },
            "questions": ["Where does this argument originate?"],
            "allowed_relations": [
                "call",
                "argument",
                "data_flow",
                "control_dependence",
            ],
        }
    )
    raw = adapter.query(cpg_path, request)
    result = normalize_repository_evidence(raw, request, root)
    assert result.status in {"complete", "partial"}
    assert result.anchor_resolution.status == "exact"
    assert any(item.kind == "argument" for item in result.evidence)
    assert all(item.source.file_path == "demo.c" for item in result.evidence)
    for family in ("data_flow", "control_dependence"):
        assert raw["families"][family] or any(
            family in item["detail"] for item in raw["limitations"]
        )


@pytest.mark.joern
@pytest.mark.skipif(
    os.environ.get("VULSOR_RUN_JOERN") != "1"
    or not shutil.which("joern")
    or not shutil.which("joern-parse"),
    reason="opt-in integration requires VULSOR_RUN_JOERN=1 and local Joern",
)
def test_real_smoke_script_with_windows_batch_launcher(tmp_path):
    root = tmp_path / "source"
    root.mkdir()
    fixture = Path(__file__).parents[1] / "fixtures/repository_context/demo.c"
    shutil.copyfile(fixture, root / "demo.c")
    adapter = JoernAdapter(
        joern_executable=shutil.which("joern"),
        joern_parse_executable=shutil.which("joern-parse"),
    )
    cpg_path = tmp_path / "cpg.bin"
    adapter.build_cpg(root, cpg_path)

    assert adapter.smoke(cpg_path)["methodCount"] >= 2


def test_script_has_request_transport_and_anchored_queries():
    from vulsor.repository_context.joern import _default_script

    script = _default_script("repository_evidence.sc").read_text(encoding="utf-8")
    for required in (
        "@main def exec",
        "requestFile",
        "outFile",
        "importCpg",
        "reachableByFlows",
        "controlledBy",
        "dominatedBy",
        "postDominatedBy",
        "callee",
        "argument",
    ):
        assert required in script
    assert script.index("candidates.size > 1") < script.index("candidates.head")
    assert 'nameExact("target")' not in script
