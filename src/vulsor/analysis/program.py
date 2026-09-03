"""Program-analysis orchestration."""

from __future__ import annotations

import tempfile
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence

from vulsor.analysis.ast import ASTAnalyzer, ProgramFacts
from vulsor.analysis.dataflow import DataFlowAnalyzer
from vulsor.tools.clang import ASTOutput, ClangAdapter, ClangRunResult


@dataclass(frozen=True)
class AnalysisPassStatus:
    """Availability of one analysis pass for the current input."""

    status: str
    reason: str | None = None


@dataclass(frozen=True)
class MissingContext:
    """Project context inferred as missing from tool diagnostics."""

    kind: str
    symbol: str
    occurrences: int = 1
    line: int | None = None
    column: int | None = None
    diagnostic: str | None = None


@dataclass(frozen=True)
class FunctionLinks:
    """Facts that belong to one analyzed function."""

    function_id: str
    operation_ids: tuple[str, ...]
    definition_ids: tuple[str, ...]
    use_ids: tuple[str, ...]
    call_graph_edge_ids: tuple[str, ...]


@dataclass(frozen=True)
class OperationCallLink:
    """Connect a call operation fact to its call-graph edge."""

    operation_id: str
    call_graph_edge_id: str


@dataclass(frozen=True)
class DefinitionUseLink:
    """Connect a reaching-definition fact to concrete def/use facts."""

    definition_id: str
    use_id: str
    data_flow_id: str
    variable: str
    relation: str


@dataclass(frozen=True)
class ProgramFactLinks:
    """Explicit cross-links between normalized program facts."""

    function_links: tuple[FunctionLinks, ...]
    operation_call_links: tuple[OperationCallLink, ...]
    definition_use_links: tuple[DefinitionUseLink, ...]
    unresolved_notes: tuple[str, ...] = ()


@dataclass(frozen=True)
class ProgramAnalysisResult:
    """Program facts together with completeness metadata."""

    facts: ProgramFacts
    complete: bool
    diagnostics: tuple[str, ...] = ()
    recovered_ast: bool = False
    cfg_available: bool = True
    scope: str = "file"
    context_mode: str = "strict_file"
    limitations: tuple[str, ...] = ()
    completeness: dict[str, AnalysisPassStatus] | None = None
    missing_context: tuple[MissingContext, ...] = ()
    links: ProgramFactLinks | None = None


def analyze_source_file(
    source_file: Path,
    clang_executable: str = "clang",
    *,
    clang_args: Sequence[str] = (),
) -> ProgramFacts:
    """Run the supported analysis passes on one C/C++ source file."""
    adapter = ClangAdapter(executable=clang_executable)
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast_with_source(
        source_file,
        extra_args=clang_args,
    )
    cfg_output = adapter.dump_cfg(
        source_file,
        extra_args=clang_args,
    )

    return analyzer.analyze_program(
        ast_output,
        cfg_output,
    )


def analyze_source_file_tolerant(
    source_file: Path,
    clang_executable: str = "clang",
    *,
    scope: str = "function",
    clang_args: Sequence[str] = (),
) -> ProgramAnalysisResult:
    """Run analysis while preserving recoverable AST facts."""
    adapter = ClangAdapter(executable=clang_executable)
    analyzer = ASTAnalyzer()
    diagnostics: list[str] = []

    ast_result = adapter.dump_ast_with_source(
        source_file,
        allow_errors=True,
        extra_args=clang_args,
    )

    ast_output: ASTOutput
    recovered_ast = False

    if isinstance(ast_result, tuple):
        ast_output, ast_diagnostics = ast_result

        if ast_diagnostics:
            diagnostics.append(ast_diagnostics)
            recovered_ast = True
    else:
        ast_output = ast_result

    cfg_result = adapter.dump_cfg(
        source_file,
        allow_errors=True,
        extra_args=clang_args,
    )

    if isinstance(cfg_result, ClangRunResult):
        cfg_output = cfg_result.output

        if cfg_result.diagnostics:
            diagnostics.append(cfg_result.diagnostics)
    else:
        cfg_output = cfg_result

    if cfg_output.strip():
        facts = analyzer.analyze_program(
            ast_output,
            cfg_output,
        )
    else:
        facts = analyzer.analyze(ast_output)

    facts = _ensure_data_flow(facts)
    cfg_available = bool(cfg_output.strip())
    complete = not diagnostics and cfg_available
    context_mode = (
        f"strict_{scope}"
        if complete
        else f"recovered_{scope}"
    )
    limitations = _analysis_limitations(
        facts=facts,
        diagnostics=tuple(diagnostics),
        recovered_ast=recovered_ast,
        cfg_available=cfg_available,
        scope=scope,
    )
    missing_context = _extract_missing_context(tuple(diagnostics))
    completeness = _analysis_completeness(
        facts=facts,
        recovered_ast=recovered_ast,
        cfg_available=cfg_available,
        diagnostics=tuple(diagnostics),
    )

    return ProgramAnalysisResult(
        facts=facts,
        complete=complete,
        diagnostics=tuple(diagnostics),
        recovered_ast=recovered_ast,
        cfg_available=cfg_available,
        scope=scope,
        context_mode=context_mode,
        limitations=limitations,
        completeness=completeness,
        missing_context=missing_context,
        links=build_program_fact_links(facts),
    )


def analyze_source_code(
    source_code: str,
    clang_executable: str = "clang",
    suffix: str = ".cpp",
    *,
    clang_args: Sequence[str] = (),
) -> ProgramFacts:
    """Run analysis on source text via a temporary source file."""
    with tempfile.TemporaryDirectory(prefix="vulsor-b1-") as directory:
        source_file = Path(directory) / f"input{suffix}"
        source_file.write_text(source_code, encoding="utf-8")

        return analyze_source_file(
            source_file,
            clang_executable=clang_executable,
            clang_args=clang_args,
        )


def analyze_source_code_tolerant(
    source_code: str,
    clang_executable: str = "clang",
    suffix: str = ".c",
    *,
    scope: str = "function",
    clang_args: Sequence[str] = (),
) -> ProgramAnalysisResult:
    """Run recoverable analysis on source text."""
    with tempfile.TemporaryDirectory(prefix="vulsor-b1-") as directory:
        source_file = Path(directory) / f"input{suffix}"
        source_file.write_text(source_code, encoding="utf-8")

        return analyze_source_file_tolerant(
            source_file,
            clang_executable=clang_executable,
            scope=scope,
            clang_args=clang_args,
        )


def _analysis_limitations(
    *,
    facts: ProgramFacts,
    diagnostics: tuple[str, ...],
    recovered_ast: bool,
    cfg_available: bool,
    scope: str,
) -> tuple[str, ...]:
    """Explain expected limits instead of hiding missing context."""
    limitations: list[str] = []

    if scope == "function":
        limitations.append(
            "input is analyzed as a standalone function-level sample"
        )
    elif scope == "file":
        limitations.append(
            "input is analyzed as a single translation-unit source file"
        )
    else:
        limitations.append(f"input is analyzed with declared scope: {scope}")

    if diagnostics:
        limitations.append(
            "project headers, typedefs, macros, and build flags may be unavailable"
        )
        limitations.append(
            "AST/call facts are recovered from Clang AST when parsing succeeds; diagnostics may make them partial"
        )

    if not cfg_available:
        limitations.append(
            "CFG facts are unavailable because Clang could not complete semantic analysis"
        )
        limitations.append(
            "CFG missing: usually caused by incomplete dataset/project compile context such as headers, typedefs, macros, or build flags"
        )

    if facts.data_flow:
        limitations.append(
            "data-flow facts are syntactic AST-based reaching-definition links; they do not prove path feasibility, aliases, pointer or field flows, macros, or interprocedural flows"
        )
    elif facts.definitions or facts.uses:
        limitations.append(
            "data-flow missing: no matching definition/use pairs were available from the recovered AST facts"
        )
    else:
        limitations.append(
            "data-flow missing: Clang AST did not expose enough local definitions and uses to link"
        )

    limitations.append(
        "program analysis emits facts only; it does not infer vulnerability verdicts"
    )

    return tuple(limitations)


def _analysis_completeness(
    *,
    facts: ProgramFacts,
    recovered_ast: bool,
    cfg_available: bool,
    diagnostics: tuple[str, ...],
) -> dict[str, AnalysisPassStatus]:
    """Describe which facts are complete for this sample."""
    ast_reason = None

    if recovered_ast:
        ast_reason = "Clang emitted recoverable AST JSON despite diagnostics"

    cfg_reason = None

    if not cfg_available:
        cfg_reason = "Clang CFG dump failed or produced no CFG text"

    data_flow_status = "available" if facts.data_flow else "empty"
    data_flow_reason = None

    if facts.data_flow and diagnostics:
        data_flow_status = "limited"
        data_flow_reason = (
            "syntactic data-flow was built from recovered AST facts; semantic diagnostics may hide additional definitions or uses"
        )
    elif not facts.data_flow and diagnostics:
        data_flow_status = "limited"
        data_flow_reason = (
            "no matching definition/use links were found in recovered AST facts; semantic diagnostics may hide additional facts"
        )

    call_graph_status = "available" if facts.call_graph else "empty"

    return {
        "ast": AnalysisPassStatus(
            status="recovered" if recovered_ast else "available",
            reason=ast_reason,
        ),
        "cfg": AnalysisPassStatus(
            status="available" if cfg_available else "missing",
            reason=cfg_reason,
        ),
        "data_flow": AnalysisPassStatus(
            status=data_flow_status,
            reason=data_flow_reason,
        ),
        "call_graph": AnalysisPassStatus(
            status=call_graph_status,
        ),
    }


def _ensure_data_flow(facts: ProgramFacts) -> ProgramFacts:
    """Build AST-based data-flow facts even when CFG generation failed."""
    if facts.data_flow:
        return facts

    data_flow = DataFlowAnalyzer().analyze(
        facts.definitions,
        facts.uses,
    )

    if not data_flow:
        return facts

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


def focus_analysis_on_line_range(
    analysis: ProgramAnalysisResult,
    *,
    start_line: int,
    end_line: int,
) -> ProgramAnalysisResult:
    """Keep facts that belong to a target function line range."""
    facts = analysis.facts
    functions = tuple(
        function
        for function in facts.functions
        if _range_overlaps(
            function.start_line,
            function.end_line,
            start_line,
            end_line,
        )
    )
    operations = tuple(
        operation
        for operation in facts.operations
        if _line_in_range(operation.line, start_line, end_line)
    )
    definitions = tuple(
        definition
        for definition in facts.definitions
        if _line_in_range(definition.line, start_line, end_line)
    )
    uses = tuple(
        use
        for use in facts.uses
        if _line_in_range(use.line, start_line, end_line)
    )
    data_flow = tuple(
        flow
        for flow in facts.data_flow
        if _line_in_range(flow.definition_line, start_line, end_line)
        and _line_in_range(flow.use_line, start_line, end_line)
    )
    operation_ids = {
        operation.id
        for operation in operations
    }
    call_graph = tuple(
        edge
        for edge in facts.call_graph
        if edge.operation_id in operation_ids
    )
    focused_facts = ProgramFacts(
        functions=functions,
        operations=operations,
        control_flow=(),
        definitions=definitions,
        uses=uses,
        data_flow=data_flow,
        cfg_blocks=(),
        call_graph=call_graph,
    )
    completeness = dict(analysis.completeness or {})

    if analysis.cfg_available:
        completeness["cfg"] = AnalysisPassStatus(
            status="omitted",
            reason=(
                "whole-file CFG is not yet mapped to the target function range"
            ),
        )

    completeness["data_flow"] = AnalysisPassStatus(
        status="available" if data_flow else "empty",
        reason=None,
    )

    complete = analysis.complete and bool(functions)

    if analysis.cfg_available:
        complete = False

    limitations = list(analysis.limitations)
    limitations.append(
        "whole-file facts were filtered to the target function line range"
    )

    return ProgramAnalysisResult(
        facts=focused_facts,
        complete=complete,
        diagnostics=analysis.diagnostics,
        recovered_ast=analysis.recovered_ast,
        cfg_available=False,
        scope=analysis.scope,
        context_mode=analysis.context_mode,
        limitations=tuple(dict.fromkeys(limitations)),
        completeness=completeness,
        missing_context=analysis.missing_context,
        links=build_program_fact_links(focused_facts),
    )


def build_program_fact_links(facts: ProgramFacts) -> ProgramFactLinks:
    """Build explicit cross-links between facts from the same analysis."""
    function_links = tuple(
        FunctionLinks(
            function_id=function.id,
            operation_ids=tuple(
                operation.id
                for operation in facts.operations
                if _line_in_function(operation.line, function)
            ),
            definition_ids=tuple(
                definition.id
                for definition in facts.definitions
                if _line_in_function(definition.line, function)
            ),
            use_ids=tuple(
                use.id
                for use in facts.uses
                if _line_in_function(use.line, function)
            ),
            call_graph_edge_ids=tuple(
                edge.id
                for edge in facts.call_graph
                if _line_in_function(edge.line, function)
            ),
        )
        for function in facts.functions
    )

    operation_ids = {
        operation.id
        for operation in facts.operations
    }
    operation_call_links = tuple(
        OperationCallLink(
            operation_id=edge.operation_id,
            call_graph_edge_id=edge.id,
        )
        for edge in facts.call_graph
        if edge.operation_id in operation_ids
    )

    definitions_by_location = {
        (
            definition.variable,
            definition.line,
            definition.column,
        ): definition
        for definition in facts.definitions
    }
    uses_by_location = {
        (
            use.variable,
            use.line,
            use.column,
        ): use
        for use in facts.uses
    }
    definition_use_links: list[DefinitionUseLink] = []

    for flow in facts.data_flow:
        definition = definitions_by_location.get(
            (
                flow.variable,
                flow.definition_line,
                flow.definition_column,
            )
        )
        use = uses_by_location.get(
            (
                flow.variable,
                flow.use_line,
                flow.use_column,
            )
        )

        if definition is None or use is None:
            continue

        definition_use_links.append(
            DefinitionUseLink(
                definition_id=definition.id,
                use_id=use.id,
                data_flow_id=flow.id,
                variable=flow.variable,
                relation=flow.relation,
            )
        )

    unresolved_notes: list[str] = []

    if facts.cfg_blocks or facts.control_flow:
        unresolved_notes.append(
            "CFG links are not emitted because CFG blocks do not yet carry source locations"
        )

    if facts.call_graph:
        unresolved_notes.append(
            "call-graph links are syntactic and not project-resolved"
        )

    if facts.data_flow:
        unresolved_notes.append(
            "data-flow links are syntactic reaching-definition links"
        )

    return ProgramFactLinks(
        function_links=function_links,
        operation_call_links=operation_call_links,
        definition_use_links=tuple(definition_use_links),
        unresolved_notes=tuple(unresolved_notes),
    )


def _line_in_function(
    line: int | None,
    function,
) -> bool:
    """Return whether a source line belongs to a function fact."""
    if function.start_line is None or function.end_line is None:
        return False

    return _line_in_range(
        line,
        function.start_line,
        function.end_line,
    )


def _line_in_range(
    line: int | None,
    start_line: int,
    end_line: int,
) -> bool:
    return line is not None and start_line <= line <= end_line


def _range_overlaps(
    actual_start: int | None,
    actual_end: int | None,
    target_start: int,
    target_end: int,
) -> bool:
    if actual_start is None or actual_end is None:
        return False

    return actual_start <= target_end and actual_end >= target_start


def _extract_missing_context(
    diagnostics: tuple[str, ...],
) -> tuple[MissingContext, ...]:
    """Extract concrete missing project context from Clang diagnostics."""
    findings: dict[tuple[str, str], MissingContext] = {}

    for diagnostic_blob in diagnostics:
        for line in diagnostic_blob.splitlines():
            finding = _extract_missing_context_line(line)

            if finding is None:
                continue

            key = (finding.kind, finding.symbol)

            if key in findings:
                previous = findings[key]
                findings[key] = MissingContext(
                    kind=previous.kind,
                    symbol=previous.symbol,
                    occurrences=previous.occurrences + 1,
                    line=previous.line,
                    column=previous.column,
                    diagnostic=previous.diagnostic,
                )
                continue

            findings[key] = finding

    return tuple(findings.values())


def _extract_missing_context_line(
    line: str,
) -> MissingContext | None:
    """Parse one Clang diagnostic line when it names missing context."""
    location = re.search(
        r":(?P<line>\d+):(?P<column>\d+):\s+"
        r"(?P<level>error|fatal error):\s+(?P<message>.+)",
        line,
    )

    if location is None:
        return None

    message = location.group("message")
    source_line = int(location.group("line"))
    source_column = int(location.group("column"))

    patterns = (
        (
            "unknown_type",
            r"unknown type name ['\"](?P<symbol>[^'\"]+)['\"]",
        ),
        (
            "undeclared_identifier",
            r"use of undeclared identifier ['\"](?P<symbol>[^'\"]+)['\"]",
        ),
        (
            "missing_include",
            r"['\"](?P<symbol>[^'\"]+)['\"] file not found",
        ),
    )

    for kind, pattern in patterns:
        match = re.search(pattern, message)

        if match:
            return MissingContext(
                kind=kind,
                symbol=match.group("symbol"),
                line=source_line,
                column=source_column,
                diagnostic=message,
            )

    return None
