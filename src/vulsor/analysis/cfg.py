"""Control-flow graph analysis for VulSOR."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class CFGBlock:
    """A normalized basic block from Clang's textual CFG."""

    id: str
    statements: tuple[str, ...]


@dataclass(frozen=True)
class CFGEdge:
    """A directed edge between two CFG basic blocks."""

    source: str
    target: str
    condition: str | None


class CFGAnalyzer:
    """Normalize Clang's textual CFG into blocks and edges."""

    _BLOCK_RE = re.compile(
        r"^\s*\[(B\d+)(?:\s+\((?:ENTRY|EXIT)\))?\]\s*$"
    )
    _SUCCESSORS_RE = re.compile(
        r"^\s*Succs\s+\(\d+\):\s*(.*)$"
    )
    _CONDITION_RE = re.compile(
        r"^\s*T:\s+(.+)$"
    )
    _BLOCK_ID_RE = re.compile(r"\b(B\d+)\b")

    def analyze(
        self,
        cfg_output: str,
    ) -> tuple[CFGEdge, ...]:
        """Parse Clang textual CFG into normalized edges."""
        if not cfg_output.strip():
            raise ValueError("Clang CFG output must not be empty.")

        _, edges = self._parse(cfg_output)

        return edges

    def analyze_blocks(
        self,
        cfg_output: str,
    ) -> tuple[CFGBlock, ...]:
        """Parse Clang textual CFG into normalized basic blocks."""
        if not cfg_output.strip():
            raise ValueError("Clang CFG output must not be empty.")

        blocks, _ = self._parse(cfg_output)

        return blocks

    def _parse(
        self,
        cfg_output: str,
    ) -> tuple[
        tuple[CFGBlock, ...],
        tuple[CFGEdge, ...],
    ]:
        """Parse both CFG blocks and edges."""
        blocks: list[CFGBlock] = []
        edges: list[CFGEdge] = []

        current_block: str | None = None
        current_condition: str | None = None
        current_statements: list[str] = []

        def flush_block() -> None:
            if current_block is None:
                return

            blocks.append(
                CFGBlock(
                    id=current_block,
                    statements=tuple(current_statements),
                )
            )

        for line in cfg_output.splitlines():
            block_match = self._BLOCK_RE.match(line)

            if block_match:
                flush_block()

                current_block = block_match.group(1)
                current_condition = None
                current_statements = []

                continue

            if current_block is None:
                continue

            condition_match = self._CONDITION_RE.match(line)

            if condition_match:
                current_condition = condition_match.group(1).strip()
                continue

            successors_match = self._SUCCESSORS_RE.match(line)

            if successors_match:
                successor_text = successors_match.group(1)

                for target in self._BLOCK_ID_RE.findall(
                    successor_text
                ):
                    edges.append(
                        CFGEdge(
                            source=current_block,
                            target=target,
                            condition=current_condition,
                        )
                    )

                continue

            stripped = line.strip()

            if stripped:
                current_statements.append(stripped)

        flush_block()

        return tuple(blocks), tuple(edges)