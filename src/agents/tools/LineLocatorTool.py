from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class LineMatch:
    line: int
    text: str
    match_type: str
    score: float

    def to_dict(self) -> dict[str, object]:
        return {
            "line": self.line,
            "text": self.text,
            "match_type": self.match_type,
            "score": self.score,
        }


class LineLocatorTool:
    def __init__(self, code: str) -> None:
        self.lines = code.splitlines()

    def locate(self, name: str) -> list[dict[str, object]]:
        query = normalize_query(name)
        if not query:
            return []

        exact_matches = self._exact_matches(query)
        if exact_matches:
            return [match.to_dict() for match in exact_matches]

        identifier = extract_identifier(query)
        if identifier and identifier != query:
            identifier_matches = self._exact_matches(identifier)
            if identifier_matches:
                return [match.to_dict() for match in identifier_matches]

        call_matches = self._source_call_matches(query)
        if call_matches:
            return [match.to_dict() for match in call_matches]

        token_matches = self._token_matches(query)
        return [match.to_dict() for match in token_matches]

    def has_match(self, name: str) -> bool:
        return bool(self.locate(name))

    def _exact_matches(self, query: str) -> list[LineMatch]:
        matches = []
        lowered_query = query.lower()
        for line_no, line in enumerate(self.lines, start=1):
            if lowered_query in line.lower():
                matches.append(LineMatch(line=line_no, text=line, match_type="exact", score=1.0))
        return matches

    def _token_matches(self, query: str) -> list[LineMatch]:
        tokens = [token.lower() for token in extract_tokens(query)]
        if not tokens:
            return []

        matches = []
        for line_no, line in enumerate(self.lines, start=1):
            lowered_line = line.lower()
            hit_count = sum(1 for token in tokens if token in lowered_line)
            if hit_count == 0:
                continue
            score = hit_count / len(tokens)
            if score >= 0.5:
                matches.append(LineMatch(line=line_no, text=line, match_type="token", score=round(score, 3)))
        return sorted(matches, key=lambda item: (-item.score, item.line))

    def _source_call_matches(self, query: str) -> list[LineMatch]:
        query_identifiers = {
            identifier
            for identifier in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", query)
            if identifier not in CONTROL_KEYWORDS
        }
        if not query_identifiers:
            return []

        matches = []
        for line_no, line in enumerate(self.lines, start=1):
            source_calls = re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", line)
            if not query_identifiers.intersection(source_calls):
                continue
            matches.append(LineMatch(line=line_no, text=line, match_type="identifier", score=1.0))
        return matches


def normalize_query(value: str) -> str:
    value = str(value).strip()
    if not value:
        return ""
    value = re.sub(r"^line\s+\d+\s*:\s*", "", value, flags=re.IGNORECASE)
    value = value.strip("`\"' ")
    return value


def extract_identifier(value: str) -> str:
    call_match = re.search(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", value)
    if call_match:
        return call_match.group(1)
    identifiers = re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", value)
    return identifiers[0] if len(identifiers) == 1 else ""


def extract_tokens(value: str) -> list[str]:
    return [
        token
        for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b|\d+", value)
        if token not in {"static", "const", "unsigned", "signed", "int", "char", "void", "return"}
    ]


CONTROL_KEYWORDS = {
    "for",
    "if",
    "switch",
    "while",
    "sizeof",
}

