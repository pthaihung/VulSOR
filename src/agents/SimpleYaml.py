from __future__ import annotations

from pathlib import Path
from typing import Any


def load_yaml(path: str | Path) -> dict[str, Any]:
    """Load the small YAML subset used by VulSOR without external dependencies."""
    lines = Path(path).read_text(encoding="utf-8-sig").splitlines()
    value = _Parser(lines).parse()
    return value if isinstance(value, dict) else {}


class _Parser:
    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.index = 0

    def parse(self) -> Any:
        self._skip_ignorable()
        if self.index >= len(self.lines):
            return {}
        return self._parse_block(_indent_of(self.lines[self.index]))

    def _skip_ignorable(self) -> None:
        while self.index < len(self.lines):
            stripped = self.lines[self.index].strip()
            if stripped and not stripped.startswith("#"):
                break
            self.index += 1

    def _parse_block(self, indent: int) -> Any:
        self._skip_ignorable()
        if self.index >= len(self.lines):
            return {}
        raw = self.lines[self.index]
        if _indent_of(raw) != indent:
            return {}
        if raw.strip().startswith("-"):
            return self._parse_sequence(indent)
        return self._parse_mapping(indent)

    def _parse_mapping(self, indent: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        while self.index < len(self.lines):
            self._skip_ignorable()
            if self.index >= len(self.lines):
                break
            raw = self.lines[self.index]
            current_indent = _indent_of(raw)
            if current_indent < indent:
                break
            if current_indent > indent:
                break
            stripped = raw.strip()
            if stripped.startswith("-"):
                break

            key, sep, value_text = stripped.partition(":")
            if not sep:
                self.index += 1
                continue
            key = key.strip()
            value_text = value_text.strip()
            self.index += 1

            if value_text in {"|", ">"}:
                result[key] = self._parse_multiline(
                    indent + 2, folded=value_text == ">"
                )
                continue
            if value_text:
                result[key] = _parse_scalar(value_text)
                continue

            saved = self.index
            self._skip_ignorable()
            if self.index < len(self.lines) and _indent_of(self.lines[self.index]) > indent:
                child_indent = _indent_of(self.lines[self.index])
                result[key] = self._parse_block(child_indent)
            else:
                result[key] = {}
                # preserve skipped blank/comment progress; only restore when EOF/shallower
                if self.index < len(self.lines) and _indent_of(self.lines[self.index]) <= indent:
                    pass
                elif self.index >= len(self.lines):
                    pass
                else:
                    self.index = saved
        return result

    def _parse_sequence(self, indent: int) -> list[Any]:
        result: list[Any] = []
        while self.index < len(self.lines):
            self._skip_ignorable()
            if self.index >= len(self.lines):
                break
            raw = self.lines[self.index]
            current_indent = _indent_of(raw)
            stripped = raw.strip()
            if current_indent != indent or not stripped.startswith("-"):
                break

            value_text = stripped[1:].strip()
            self.index += 1
            if not value_text:
                self._skip_ignorable()
                if self.index < len(self.lines) and _indent_of(self.lines[self.index]) > indent:
                    result.append(self._parse_block(_indent_of(self.lines[self.index])))
                else:
                    result.append(None)
                continue

            key, sep, nested_value = value_text.partition(":")
            if sep and key.strip():
                item: dict[str, Any] = {}
                key = key.strip()
                nested_value = nested_value.strip()
                if nested_value:
                    item[key] = _parse_scalar(nested_value)
                else:
                    self._skip_ignorable()
                    if self.index < len(self.lines) and _indent_of(self.lines[self.index]) > indent + 1:
                        child_indent = _indent_of(self.lines[self.index])
                        item[key] = self._parse_block(child_indent)
                    else:
                        item[key] = {}

                # Remaining fields of this list-item are a mapping at indent+2.
                self._skip_ignorable()
                if self.index < len(self.lines):
                    next_raw = self.lines[self.index]
                    next_indent = _indent_of(next_raw)
                    if next_indent == indent + 2 and not next_raw.strip().startswith("-"):
                        item.update(self._parse_mapping(indent + 2))
                result.append(item)
            else:
                result.append(_parse_scalar(value_text))
        return result

    def _parse_multiline(self, indent: int, folded: bool) -> str:
        parts: list[str] = []
        while self.index < len(self.lines):
            raw = self.lines[self.index]
            if raw.strip():
                current_indent = _indent_of(raw)
                if current_indent < indent:
                    break
                parts.append(raw[indent:])
            else:
                parts.append("")
            self.index += 1
        if folded:
            return " ".join(part.strip() for part in parts if part.strip())
        return "\n".join(parts).rstrip()


def _indent_of(line: str) -> int:
    return len(line) - len(line.lstrip(" "))


def _parse_scalar(value: str) -> Any:
    if value == "null":
        return None
    if value == "true":
        return True
    if value == "false":
        return False
    try:
        return int(value)
    except ValueError:
        return value.strip('"').strip("'")
