import importlib.util
from pathlib import Path

from vulsor.repository_context.prompt_context import PromptContextRecord


SCRIPT = (
    Path(__file__).resolve().parents[2]
    / "scripts"
    / "verify_repository_context_samples.py"
)


def _verifier_module():
    spec = importlib.util.spec_from_file_location("verify_repository_context_samples", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_verifier_reports_compact_categories_without_source_code() -> None:
    verifier = _verifier_module()
    record = PromptContextRecord(
        sample_id="sample-a",
        context=(
            "[DATA DEPENDENCIES]\n- p = base + offset (demo.c:2)\n\n"
            "[CONTROL DEPENDENCIES]\n- p < end (demo.c:3)\n\n"
            "[DECLARATIONS, TYPES AND CONTRACTS]\n- p: char * (demo.c:1)\n\n"
            "[CALL RELATIONS]\n- consume(p) (demo.c:4)"
        ),
        limitations=("context_truncated",),
    )

    report = verifier.verify_cases(
        [verifier.VerificationCase("sample-a", "pointer")],
        identity_for=lambda _: {"repository": "demo/repo", "revision": "a" * 40},
        build_context=lambda _: record,
    )

    assert report == [
        {
            "sample_id": "sample-a",
            "category": "pointer",
            "repository": "demo/repo",
            "revision": "a" * 40,
            "status": "built",
            "context_characters": len(record.context),
            "family_counts": {
                "data_dependencies": 1,
                "control_dependencies": 1,
                "declarations_types_contracts": 1,
                "calls": 1,
            },
            "limitations": ["context_truncated"],
        }
    ]
    assert "base + offset" not in str(report)


def test_verifier_records_controlled_unavailability() -> None:
    verifier = _verifier_module()

    report = verifier.verify_cases(
        [verifier.VerificationCase("sample-b", "incomplete-flow")],
        identity_for=lambda _: {"repository": "demo/repo", "revision": "b" * 40},
        build_context=lambda _: (_ for _ in ()).throw(ValueError("repository_unavailable")),
    )

    assert report[0]["status"] == "unavailable"
    assert report[0]["limitations"] == ["repository_unavailable"]


def test_verifier_marks_unexpected_failures_separately() -> None:
    verifier = _verifier_module()

    report = verifier.verify_cases(
        [verifier.VerificationCase("sample-c", "macro")],
        identity_for=lambda _: {"repository": "demo/repo", "revision": "c" * 40},
        build_context=lambda _: (_ for _ in ()).throw(RuntimeError("unexpected")),
    )

    assert report[0]["status"] == "failed"
    assert report[0]["limitations"] == ["unexpected"]
