"""Normalize Clang AST data into VulSOR program facts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from vulsor.analysis.cfg import CFGAnalyzer, CFGBlock, CFGEdge
from vulsor.tools.clang import ASTOutput
from vulsor.analysis.dataflow import (
    DataFlowFact,
    DataFlowAnalyzer,
    DefinitionFact,
    UseFact,
)


@dataclass(frozen=True)
class FunctionFact:
    """A function discovered during program analysis."""

    id: str
    name: str
    start_line: int | None
    end_line: int | None


@dataclass(frozen=True)
class OperationFact:
    """An operation or function call discovered in the program."""

    id: str
    kind: str
    name: str
    line: int | None
    column: int | None
    arguments: tuple[str, ...]


@dataclass(frozen=True)
class CallGraphEdge:
    """A caller-callee relation discovered in the program."""

    id: str
    caller: str
    callee: str
    line: int | None
    column: int | None
    operation_id: str


@dataclass(frozen=True)
class ProgramFacts:
    """Normalized program facts extracted from compiler analysis."""

    functions: tuple[FunctionFact, ...]
    operations: tuple[OperationFact, ...]
    control_flow: tuple[CFGEdge, ...]
    definitions: tuple[DefinitionFact, ...]
    uses: tuple[UseFact, ...]
    data_flow: tuple[DataFlowFact, ...]
    cfg_blocks: tuple[CFGBlock, ...] = ()
    call_graph: tuple[CallGraphEdge, ...] = ()


class ASTAnalyzer:
    """Convert Clang AST and CFG data into normalized VulSOR facts."""

    def __init__(
        self,
        cfg_analyzer: CFGAnalyzer | None = None,
        data_flow_analyzer: DataFlowAnalyzer | None = None,
    ) -> None:
        self._cfg_analyzer = cfg_analyzer or CFGAnalyzer()
        self._data_flow_analyzer = (
            data_flow_analyzer or DataFlowAnalyzer()
        )
        self._ast_occurrence_counter = 0

    def _next_ast_node_id(self, kind: str) -> str:
        """Return a unique AST occurrence ID for the current analysis run."""
        node_id = (
            f"ast-node:{kind}:{self._ast_occurrence_counter}"
        )
        self._ast_occurrence_counter += 1

        return node_id

    def analyze(self, ast_output: str | ASTOutput) -> ProgramFacts:
        """Extract functions, calls, definitions, and uses from a Clang AST.

        Args:
            ast_output:
                Raw JSON AST or an ``ASTOutput`` containing the AST and
                original source text.

        Returns:
            Normalized program facts.

        Raises:
            ValueError: If the AST is not a valid JSON object.
        """
        source: str | None = None
        source_path: str | None = None

        if isinstance(ast_output, ASTOutput):
            source = ast_output.source
            source_path = ast_output.source_path
            ast_json = ast_output.ast_json
        else:
            ast_json = ast_output

        try:
            ast = json.loads(ast_json)
        except json.JSONDecodeError as exc:
            raise ValueError("Invalid Clang AST JSON.") from exc

        if not isinstance(ast, dict):
            raise ValueError("Clang AST root must be a JSON object.")

        functions: list[FunctionFact] = []
        operations: list[OperationFact] = []
        definitions: list[DefinitionFact] = []
        uses: list[UseFact] = []
        call_graph: list[CallGraphEdge] = []

        self._ast_occurrence_counter = 0

        self._walk(
            node=ast,
            functions=functions,
            operations=operations,
            definitions=definitions,
            uses=uses,
            call_graph=call_graph,
            source=source,
            source_path=source_path,
            current_function=None,
        )

        return ProgramFacts(
            functions=tuple(functions),
            operations=tuple(operations),
            control_flow=(),
            definitions=tuple(definitions),
            uses=tuple(uses),
            data_flow=(),
            call_graph=tuple(call_graph),
        )

    def analyze_with_cfg(
        self,
        ast_output: str | ASTOutput,
        cfg_output: str,
    ) -> ProgramFacts:
        """Combine normalized AST and CFG facts."""
        ast_facts = self.analyze(ast_output)
        control_flow = self._cfg_analyzer.analyze(cfg_output)
        cfg_blocks = self._cfg_analyzer.analyze_blocks(cfg_output)

        return ProgramFacts(
            functions=ast_facts.functions,
            operations=ast_facts.operations,
            control_flow=control_flow,
            definitions=ast_facts.definitions,
            uses=ast_facts.uses,
            data_flow=ast_facts.data_flow,
            cfg_blocks=cfg_blocks,
            call_graph=ast_facts.call_graph,
        )

    def analyze_program(
        self,
        ast_output: str | ASTOutput,
        cfg_output: str,
    ) -> ProgramFacts:
        """Build complete program-analysis facts currently supported."""
        facts = self.analyze_with_cfg(
            ast_output,
            cfg_output,
        )

        data_flow = self._data_flow_analyzer.analyze(
            facts.definitions,
            facts.uses,
        )

        return ProgramFacts(
            functions=facts.functions,
            operations=facts.operations,
            control_flow=facts.control_flow,
            definitions=facts.definitions,
            uses=facts.uses,
            data_flow=data_flow,
            cfg_blocks=facts.cfg_blocks,
            call_graph=facts.call_graph,
        )

    def _walk(
        self,
        node: Any,
        functions: list[FunctionFact],
        operations: list[OperationFact],
        definitions: list[DefinitionFact],
        uses: list[UseFact],
        call_graph: list[CallGraphEdge],
        source: str | None,
        source_path: str | None,
        current_function: str | None,
    ) -> None:
        """Recursively visit AST nodes and collect supported facts."""
        if isinstance(node, dict):
            kind = node.get("kind")
            next_function = current_function

            if kind == "FunctionDecl":
                if source_path is not None and not self._has_function_body(node):
                    return

                if not self._is_from_source_file(
                    node,
                    source_path,
                    source,
                ):
                    return

                function = self._function_fact(
                    node,
                    source,
                )

                if function is not None:
                    functions.append(function)
                    next_function = function.name

                self._extract_function_data_flow(
                    node,
                    definitions,
                    uses,
                    source,
                )

            elif kind == "CallExpr":
                self._add_call(
                    node,
                    operations,
                    call_graph,
                    source,
                    next_function,
                )

            for value in node.values():
                self._walk(
                    node=value,
                    functions=functions,
                    operations=operations,
                    definitions=definitions,
                    uses=uses,
                    call_graph=call_graph,
                    source=source,
                    source_path=source_path,
                    current_function=next_function,
                )

        elif isinstance(node, list):
            for item in node:
                self._walk(
                    node=item,
                    functions=functions,
                    operations=operations,
                    definitions=definitions,
                    uses=uses,
                    call_graph=call_graph,
                    source=source,
                    source_path=source_path,
                    current_function=current_function,
                )

    @staticmethod
    def _has_function_body(node: dict[str, Any]) -> bool:
        """Return whether a FunctionDecl is a definition with a body."""
        inner = node.get("inner")

        if not isinstance(inner, list):
            return False

        return any(
            isinstance(child, dict)
            and child.get("kind") == "CompoundStmt"
            for child in inner
        )

    @staticmethod
    def _is_from_source_file(
        node: dict[str, Any],
        source_path: str | None,
        source: str | None = None,
    ) -> bool:
        """Return whether an AST declaration belongs to the analyzed file."""
        if source_path is None:
            return True

        node_file = ASTAnalyzer._location_file(node.get("loc"))

        if node_file is None:
            range_node = node.get("range")

            if isinstance(range_node, dict):
                node_file = ASTAnalyzer._location_file(
                    range_node.get("begin")
                )

        if node_file is None:
            loc = node.get("loc")
            line = (
                ASTAnalyzer._line(loc)
                if isinstance(loc, dict)
                else None
            )
            range_node = node.get("range")

            if line is None and isinstance(range_node, dict):
                begin = range_node.get("begin")
                line = (
                    ASTAnalyzer._line(begin)
                    if isinstance(begin, dict)
                    else None
                )

            name = node.get("name")
            return (
                isinstance(name, str)
                and source is not None
                and ASTAnalyzer._source_line_contains(
                    source,
                    line,
                    name,
                )
            )

        try:
            return Path(node_file).resolve() == Path(source_path).resolve()
        except OSError:
            return node_file == source_path

    @staticmethod
    def _location_file(location: Any) -> str | None:
        """Extract a direct source file from a Clang JSON location."""
        if not isinstance(location, dict):
            return None

        file_name = location.get("file")

        if isinstance(file_name, str):
            return file_name

        expansion_location = location.get("expansionLoc")

        if isinstance(expansion_location, dict):
            file_name = expansion_location.get("file")

            if isinstance(file_name, str):
                return file_name

        spelling_location = location.get("spellingLoc")

        if isinstance(spelling_location, dict):
            file_name = spelling_location.get("file")

            if isinstance(file_name, str):
                return file_name

        return None

    @staticmethod
    def _source_line_contains(
        source: str,
        line: int | None,
        needle: str,
    ) -> bool:
        """Return whether a 1-based source line contains text."""
        if line is None or line < 1:
            return False

        lines = source.splitlines()

        if line > len(lines):
            return False

        return needle in lines[line - 1]

    def _extract_function_data_flow(
        self,
        function_node: dict[str, Any],
        definitions: list[DefinitionFact],
        uses: list[UseFact],
        source: str | None,
    ) -> None:
        """Extract declaration definitions and variable reads in one function.

        This pass intentionally does not infer reaching-definition relations.
        It also does not treat references to functions as variable uses.
        """
        declaration_ids: set[str] = set()

        self._collect_local_declarations(
            node=function_node,
            declaration_ids=declaration_ids,
            definitions=definitions,
            source=source,
        )

        self._collect_variable_uses(
            node=function_node,
            declaration_ids=declaration_ids,
            uses=uses,
            source=source,
        )

    def _collect_local_declarations(
        self,
        node: Any,
        declaration_ids: set[str],
        definitions: list[DefinitionFact],
        source: str | None,
    ) -> None:
        """Collect parameter and local-variable declarations."""
        if isinstance(node, dict):
            kind = node.get("kind")

            if kind in {"ParmVarDecl", "VarDecl"}:
                declaration_id = node.get("id")
                name = node.get("name")

                if (
                    isinstance(declaration_id, str)
                    and isinstance(name, str)
                    and declaration_id not in declaration_ids
                ):
                    declaration_ids.add(declaration_id)

                    line, column = self._location_from_decl(
                        node,
                        source,
                    )

                    ast_node_id = declaration_id

                    definitions.append(
                        DefinitionFact(
                            id=f"definition:{name}:{line}:{column}",
                            variable=name,
                            line=line,
                            column=column,
                            ast_node_id=ast_node_id,
                        )
                    )

            for value in node.values():
                self._collect_local_declarations(
                    node=value,
                    declaration_ids=declaration_ids,
                    definitions=definitions,
                    source=source,
                )

        elif isinstance(node, list):
            for item in node:
                self._collect_local_declarations(
                    node=item,
                    declaration_ids=declaration_ids,
                    definitions=definitions,
                    source=source,
                )

    def _collect_variable_uses(
        self,
        node: Any,
        declaration_ids: set[str],
        uses: list[UseFact],
        source: str | None,
    ) -> None:
        """Collect reads of variables declared in the current function."""
        if isinstance(node, dict):
            if node.get("kind") == "DeclRefExpr":
                referenced_decl = node.get("referencedDecl")

                if isinstance(referenced_decl, dict):
                    declaration_id = referenced_decl.get("id")
                    declaration_kind = referenced_decl.get("kind")
                    name = referenced_decl.get("name")

                    if (
                        isinstance(declaration_id, str)
                        and declaration_id in declaration_ids
                        and declaration_kind in {"ParmVarDecl", "VarDecl"}
                        and isinstance(name, str)
                    ):
                        line, column = self._location_from_range_start(
                            node,
                            source,
                        )

                        ast_node_id = self._next_ast_node_id("DeclRefExpr")
                        
                        uses.append(
                            UseFact(
                                id=f"use:{name}:{line}:{column}",
                                variable=name,
                                line=line,
                                column=column,
                                ast_node_id=ast_node_id,
                            )
                        )

            for value in node.values():
                self._collect_variable_uses(
                    node=value,
                    declaration_ids=declaration_ids,
                    uses=uses,
                    source=source,
                )

        elif isinstance(node, list):
            for item in node:
                self._collect_variable_uses(
                    node=item,
                    declaration_ids=declaration_ids,
                    uses=uses,
                    source=source,
                )

    @staticmethod
    def _function_fact(
        node: dict[str, Any],
        source: str | None,
    ) -> FunctionFact | None:
        """Convert a FunctionDecl AST node into a FunctionFact."""
        name = node.get("name")

        if not isinstance(name, str):
            return None

        start_line, _ = ASTAnalyzer._location_from_decl(node, source)
        end_line, _ = ASTAnalyzer._location_from_range_end(node, source)

        function_id = f"function:{name}:{start_line}"

        return FunctionFact(
            id=function_id,
            name=name,
            start_line=start_line,
            end_line=end_line,
        )

    @staticmethod
    def _add_call(
        node: dict[str, Any],
        operations: list[OperationFact],
        call_graph: list[CallGraphEdge],
        source: str | None,
        current_function: str | None,
    ) -> None:
        """Convert a CallExpr AST node into an OperationFact."""
        name = ASTAnalyzer._call_name(node)

        if name is None:
            return

        line, column = ASTAnalyzer._location_from_range_start(
            node,
            source,
        )

        operation_id = f"operation:{name}:{line}:{column}"

        arguments = ASTAnalyzer._call_arguments(node)

        operation = OperationFact(
            id=operation_id,
            kind="call",
            name=name,
            line=line,
            column=column,
            arguments=tuple(arguments),
        )

        operations.append(operation)

        if current_function is None:
            return

        call_graph.append(
            CallGraphEdge(
                id=f"callgraph:{current_function}:{name}:{line}:{column}",
                caller=current_function,
                callee=name,
                line=line,
                column=column,
                operation_id=operation.id,
            )
        )

    @staticmethod
    def _call_name(node: dict[str, Any]) -> str | None:
        """Extract the called function name from a CallExpr node."""
        inner = node.get("inner")

        if not isinstance(inner, list) or not inner:
            return None

        callee = inner[0]

        return ASTAnalyzer._referenced_decl_name(callee)

    @staticmethod
    def _call_arguments(node: dict[str, Any]) -> list[str]:
        """Extract simple argument names from a CallExpr node."""
        inner = node.get("inner")

        if not isinstance(inner, list):
            return []

        arguments: list[str] = []

        for child in inner[1:]:
            name = ASTAnalyzer._first_decl_ref_name(child)

            if name is not None:
                arguments.append(name)

        return arguments

    @staticmethod
    def _first_decl_ref_name(node: Any) -> str | None:
        """Find a referenced declaration name below an AST node."""
        if isinstance(node, dict):
            if node.get("kind") == "DeclRefExpr":
                return ASTAnalyzer._referenced_decl_name(node)

            for value in node.values():
                result = ASTAnalyzer._first_decl_ref_name(value)

                if result is not None:
                    return result

        elif isinstance(node, list):
            for item in node:
                result = ASTAnalyzer._first_decl_ref_name(item)

                if result is not None:
                    return result

        return None

    @staticmethod
    def _referenced_decl_name(node: Any) -> str | None:
        """Find the name of a referenced declaration below an AST node."""
        if isinstance(node, dict):
            referenced_decl = node.get("referencedDecl")

            if isinstance(referenced_decl, dict):
                name = referenced_decl.get("name")

                if isinstance(name, str):
                    return name

            for value in node.values():
                result = ASTAnalyzer._referenced_decl_name(value)

                if result is not None:
                    return result

        elif isinstance(node, list):
            for item in node:
                result = ASTAnalyzer._referenced_decl_name(item)

                if result is not None:
                    return result

        return None

    @staticmethod
    def _location_from_decl(
        node: dict[str, Any],
        source: str | None = None,
    ) -> tuple[int | None, int | None]:
        """Return the declaration source location.

        Clang may omit line/column information from a declaration location
        while still providing a byte offset. When that happens, recover the
        source line from the original source text.
        """
        location = node.get("loc")

        if not isinstance(location, dict):
            range_node = node.get("range")

            if isinstance(range_node, dict):
                location = range_node.get("begin")

        if not isinstance(location, dict):
            return None, None

        line = ASTAnalyzer._line(location)

        if line is None:
            line = ASTAnalyzer._line_from_offset(
                location.get("offset"),
                source,
            )

        column = ASTAnalyzer._column(location)

        return line, column

    @staticmethod
    def _location_from_range_start(
        node: dict[str, Any],
        source: str | None = None,
    ) -> tuple[int | None, int | None]:
        """Return the source line and column at an AST range start."""
        range_node = node.get("range")

        if not isinstance(range_node, dict):
            return None, None

        location = range_node.get("begin")

        if not isinstance(location, dict):
            return None, None

        line = ASTAnalyzer._line(location)
        column = ASTAnalyzer._column(location)

        if line is None:
            line = ASTAnalyzer._line_from_offset(
                location.get("offset"),
                source,
            )

        return line, column

    @staticmethod
    def _location_from_range_end(
        node: dict[str, Any],
        source: str | None = None,
    ) -> tuple[int | None, int | None]:
        """Return the source line and column at an AST range end."""
        range_node = node.get("range")

        if not isinstance(range_node, dict):
            return None, None

        location = range_node.get("end")

        if not isinstance(location, dict):
            return None, None

        line = ASTAnalyzer._line(location)
        column = ASTAnalyzer._column(location)

        if line is None:
            line = ASTAnalyzer._line_from_offset(
                location.get("offset"),
                source,
            )

        return line, column
    
    @staticmethod
    def _line(location: dict[str, Any]) -> int | None:
        """Extract a source line number from a Clang location."""
        value = location.get("line")
        return value if isinstance(value, int) else None

    @staticmethod
    def _column(location: dict[str, Any]) -> int | None:
        """Extract a source column from a Clang location."""
        value = location.get("col")
        return value if isinstance(value, int) else None

    @staticmethod
    def _line_from_offset(
        offset: Any,
        source: str | None,
    ) -> int | None:
        """Resolve a Clang byte offset to a one-based source line."""
        if not isinstance(offset, int):
            return None

        if source is None:
            return None

        source_bytes = source.encode("utf-8")

        if offset < 0 or offset > len(source_bytes):
            return None

        return source_bytes[:offset].count(b"\n") + 1
