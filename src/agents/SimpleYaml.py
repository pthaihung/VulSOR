from __future__ import annotations

from pathlib import Path
from typing import Any


def load_yaml(path: str | Path) -> dict[str, Any]:
    """Load the small YAML subset used by this project's config and prompts."""
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return _Parser(lines).parse()


class _Parser:
    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.index = 0

    def parse(self) -> dict[str, Any]:
        value = self._parse_block(0)
        return value if isinstance(value, dict) else {}

    def _parse_block(self, indent: int) -> Any:
        items: dict[str, Any] = {}
        sequence: list[Any] | None = None

        while self.index < len(self.lines):
            raw = self.lines[self.index]
            if not raw.strip() or raw.lstrip().startswith("#"):
                self.index += 1
                continue

            current_indent = _indent_of(raw)
            if current_indent < indent:
                break
            if current_indent > indent:
                break

            stripped = raw.strip()
            if stripped.startswith("- "):
                if sequence is None:
                    sequence = []
                value_text = stripped[2:].strip()
                self.index += 1
                if value_text:
                    item = _parse_sequence_item(value_text)
                    if isinstance(item, dict) and self.index < len(self.lines):
                        next_indent = _indent_of(self.lines[self.index])
                        if next_indent > current_indent:
                            nested = self._parse_block(indent + 2)
                            if isinstance(nested, dict):
                                item.update(nested)
                    sequence.append(item)
                else:
                    sequence.append(self._parse_block(indent + 2))
                continue

            if sequence is not None:
                break

            key, sep, value_text = stripped.partition(":")
            if not sep:
                self.index += 1
                continue

            key = key.strip()
            value_text = value_text.strip()
            self.index += 1

            if value_text in {"|", ">"}:
                items[key] = self._parse_multiline(indent + 2, folded=value_text == ">")
            elif value_text:
                items[key] = _parse_scalar(value_text)
            else:
                items[key] = self._parse_block(indent + 2)

        return sequence if sequence is not None else items

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


def _parse_sequence_item(value: str) -> Any:
    key, sep, nested_value = value.partition(":")
    if sep and key.strip():
        return {key.strip(): _parse_scalar(nested_value.strip()) if nested_value.strip() else {}}
    return _parse_scalar(value)
