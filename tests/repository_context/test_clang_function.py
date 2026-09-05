import json
import shutil

import pytest

from vulsor.repository_context.clang_function import (
    ClangFunctionError,
    extract_function_name,
)


def _ast(*names: str) -> str:
    return json.dumps(
        {
            "kind": "TranslationUnitDecl",
            "inner": [
                {
                    "kind": "FunctionDecl",
                    "name": name,
                    "loc": {"file": "sample.c"},
                }
                for name in names
            ],
        }
    )


def test_extract_function_name_reads_one_main_file_function() -> None:
    def runner(arguments, timeout):
        return _ast("target")

    assert extract_function_name("int target(void) { return 0; }", ".c", runner) == "target"


def test_extract_function_name_rejects_ambiguous_main_file_functions() -> None:
    def runner(arguments, timeout):
        return _ast("first", "second")

    with pytest.raises(ClangFunctionError, match="ambiguous_function"):
        extract_function_name("int first(void) {} int second(void) {}", ".c", runner)


@pytest.mark.skipif(shutil.which("clang") is None, reason="clang is required")
def test_extract_function_name_accepts_real_clang_location() -> None:
    assert extract_function_name("int target(void) { return 0; }", ".c") == "target"
