import hashlib

import pytest

from vulsor.repository_context.source_match import (
    SourceMatchStatus,
    all_offsets,
    match_sample_to_file,
    normalize_source,
    normalized_code_sha256,
    normalized_lines_with_numbers,
)


def test_whitespace_normalized_match_is_accepted() -> None:
    sample = "int f(int x) {\n  return x + 1;\n}\n"
    source = "/* header */\r\nint f(int x) {\r\n  return x + 1;  \r\n}\r\n"

    result = match_sample_to_file(sample, source)

    assert result.status is SourceMatchStatus.NORMALIZED
    assert result.start_line == 2
    assert result.end_line == 4
    assert result.candidate_count == 1


def test_exact_match_is_accepted_with_original_line_numbers() -> None:
    sample = "int f(void) { return 1; }"
    source = "/* header */\nint f(void) { return 1; }\n"

    result = match_sample_to_file(sample, source)

    assert result.status is SourceMatchStatus.EXACT
    assert result.start_line == 2
    assert result.end_line == 2
    assert result.candidate_count == 1


def test_exact_duplicate_matches_are_ambiguous() -> None:
    sample = "return 1;"
    source = "int first(void) { return 1; }\nint second(void) { return 1; }"

    result = match_sample_to_file(sample, source)

    assert result.status is SourceMatchStatus.AMBIGUOUS
    assert result.start_line is None
    assert result.end_line is None
    assert result.candidate_count == 2


def test_similarity_without_exact_normalized_match_is_rejected() -> None:
    result = match_sample_to_file(
        "int f(void) { return 1; }",
        "int f(void) { return 2; }",
    )

    assert result.status is SourceMatchStatus.MISMATCH
    assert result.start_line is None
    assert result.end_line is None
    assert result.candidate_count == 0


def test_normalized_match_ignores_blank_lines_and_horizontal_whitespace() -> None:
    sample = "\n  int f(void) {\n\n return 1; \n}\n"
    source = "int f(void) {\r\n\r\n  return 1;\r\n}\r\n"

    result = match_sample_to_file(sample, source)

    assert result.status is SourceMatchStatus.NORMALIZED
    assert result.start_line == 1
    assert result.end_line == 4
    assert result.candidate_count == 1


def test_normalized_match_preserves_file_line_numbers_around_blank_lines() -> None:
    sample = "int f(void) {\nreturn 1;\n}"
    source = "/* header */\n\n int f(void) { \n\n return 1;\n }\n"

    result = match_sample_to_file(sample, source)

    assert result.status is SourceMatchStatus.NORMALIZED
    assert result.start_line == 3
    assert result.end_line == 6


def test_normalized_matches_are_ambiguous_when_functions_repeat() -> None:
    sample = "int f(void) {\nreturn 1;\n}"
    source = (
        "int f(void) {\n"
        " return 1;\n"
        "}\n"
        "\n"
        "int f(void) {\n"
        " return 1;\n"
        "}\n"
    )

    result = match_sample_to_file(sample, source)

    assert result.status is SourceMatchStatus.AMBIGUOUS
    assert result.candidate_count == 2


def test_normalized_lines_with_numbers_normalizes_line_endings_and_blank_lines() -> None:
    code = "  first  \r\n\r\n\tsecond\n third \r"

    assert normalized_lines_with_numbers(code) == [
        (1, "first"),
        (3, "second"),
        (4, "third"),
    ]


def test_normalize_source_joins_retained_normalized_lines() -> None:
    assert normalize_source(" first \r\n\r\n second ") == "first\nsecond"


def test_all_offsets_finds_overlapping_occurrences() -> None:
    assert all_offsets("aaaa", "aa") == [0, 1, 2]
    assert all_offsets("aaaa", "") == []


def test_normalized_code_sha256_hashes_normalized_source() -> None:
    code = " first\r\n\r\n second  \n"

    assert normalized_code_sha256(code) == hashlib.sha256(
        b"first\nsecond"
    ).hexdigest()


@pytest.mark.parametrize("sample_code", ("", " \t\r\n"))
def test_match_sample_to_file_rejects_blank_sample_before_matching(
    sample_code: str,
) -> None:
    with pytest.raises(ValueError, match="source code must not be blank"):
        match_sample_to_file(sample_code, "int f(void) { return 1; }")


@pytest.mark.parametrize("code", ("", " \t\r\n"))
def test_normalized_code_sha256_rejects_blank_source_before_hashing(
    code: str,
) -> None:
    with pytest.raises(ValueError, match="source code must not be blank"):
        normalized_code_sha256(code)
