"""Data-flow facts for VulSOR."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class DefinitionFact:
    """A variable definition discovered during program analysis."""

    id: str
    variable: str
    line: int | None
    column: int | None
    ast_node_id: str | None = None


@dataclass(frozen=True)
class UseFact:
    """A variable use discovered during program analysis."""

    id: str
    variable: str
    line: int | None
    column: int | None
    ast_node_id: str | None = None


@dataclass(frozen=True)
class DataFlowFact:
    """A data-flow relation between a definition and a use."""

    id: str
    variable: str
    relation: str
    definition_line: int | None
    definition_column: int | None
    use_line: int | None
    use_column: int | None


class DataFlowAnalyzer:
    """Build conservative variable-level reaching-definition facts."""

    def analyze(
        self,
        definitions: tuple[DefinitionFact, ...],
        uses: tuple[UseFact, ...],
    ) -> tuple[DataFlowFact, ...]:
        """Relate each variable use to known definitions of the same name.

        This intentionally stays syntactic and local. It does not prove path
        feasibility; later verification stages own feasibility evidence.
        """
        facts: list[DataFlowFact] = []

        for use in uses:
            for definition in definitions:
                if definition.variable != use.variable:
                    continue

                if not self._definition_can_reach_use(
                    definition,
                    use,
                ):
                    continue

                facts.append(
                    DataFlowFact(
                        id=(
                            "dataflow:"
                            f"{use.variable}:"
                            f"{definition.line}:"
                            f"{definition.column}:"
                            f"{use.line}:"
                            f"{use.column}"
                        ),
                        variable=use.variable,
                        relation="syntactic_reaching_definition",
                        definition_line=definition.line,
                        definition_column=definition.column,
                        use_line=use.line,
                        use_column=use.column,
                    )
                )

        return tuple(facts)

    @staticmethod
    def _definition_can_reach_use(
        definition: DefinitionFact,
        use: UseFact,
    ) -> bool:
        """Return whether source order allows a definition to reach a use."""
        if definition.line is None or use.line is None:
            return True

        if definition.line < use.line:
            return True

        if definition.line > use.line:
            return False

        if definition.column is None or use.column is None:
            return True

        return definition.column <= use.column
