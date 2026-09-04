"""Conservative matching of sampled source code to a selected file."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum


class SourceMatchStatus(str, Enum):
    EXACT = "exact"
    NORMALIZED = "normalized"
    MISMATCH = "mismatch"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class SourceMatch:
    status: SourceMatchStatus
    start_line: int | None
    end_line: int | None
    candidate_count: int


def _validate_nonblank_source(code: str) -> None:
    if not code.strip():
        raise ValueError("source code must not be blank")


def normalized_lines_with_numbers(code: str) -> list[tuple[int, str]]:
    normalized_newlines = code.replace("\r\n", "\n").replace("\r", "\n")
    return [
        (line_number, line.strip())
        for line_number, line in enumerate(normalized_newlines.split("\n"), start=1)
        if line.strip()
    ]


def normalize_source(code: str) -> str:
    return "\n".join(text for _, text in normalized_lines_with_numbers(code))


def all_offsets(text: str, needle: str) -> list[int]:
    offsets: list[int] = []
    start = 0
    while needle and (offset := text.find(needle, start)) >= 0:
        offsets.append(offset)
        start = offset + 1
    return offsets


def normalized_code_sha256(code: str) -> str:
    _validate_nonblank_source(code)
    return hashlib.sha256(normalize_source(code).encode("utf-8")).hexdigest()


def match_sample_to_file(sample_code: str, file_text: str) -> SourceMatch:
    _validate_nonblank_source(sample_code)
    exact_offsets = all_offsets(file_text, sample_code)
    if len(exact_offsets) == 1:
        offset = exact_offsets[0]
        normalized_prefix = file_text[:offset].replace("\r\n", "\n").replace(
            "\r", "\n"
        )
        start_line = normalized_prefix.count("\n") + 1
        normalized_sample = sample_code.rstrip("\r\n").replace(
            "\r\n", "\n"
        ).replace("\r", "\n")
        end_line = start_line + normalized_sample.count("\n")
        return SourceMatch(SourceMatchStatus.EXACT, start_line, end_line, 1)
    if len(exact_offsets) > 1:
        return SourceMatch(
            SourceMatchStatus.AMBIGUOUS, None, None, len(exact_offsets)
        )

    normalized_sample = normalize_source(sample_code).splitlines()
    numbered_file_lines = normalized_lines_with_numbers(file_text)
    matches = []
    width = len(normalized_sample)
    for index in range(0, len(numbered_file_lines) - width + 1):
        window = numbered_file_lines[index : index + width]
        if [text for _, text in window] == normalized_sample:
            matches.append((window[0][0], window[-1][0]))
    if len(matches) == 1:
        start_line, end_line = matches[0]
        return SourceMatch(SourceMatchStatus.NORMALIZED, start_line, end_line, 1)
    if len(matches) > 1:
        return SourceMatch(SourceMatchStatus.AMBIGUOUS, None, None, len(matches))
    return SourceMatch(SourceMatchStatus.MISMATCH, None, None, 0)
