"""Tests for VulSOR program analysis."""

import json
from pathlib import Path

from vulsor.analysis.ast import ASTAnalyzer
from vulsor.analysis.cfg import CFGAnalyzer
from vulsor.analysis.dataflow import DataFlowFact
from vulsor.analysis.dataflow import (
    DataFlowAnalyzer,
    DefinitionFact,
    UseFact,
)
from vulsor.analysis.program import analyze_source_file
from vulsor.analysis.program import analyze_source_code_tolerant
from vulsor.analysis.program import analyze_source_file_tolerant
from vulsor.tools.clang import ASTOutput, ClangAdapter


FIXTURE = Path(__file__).parent / "fixtures" / "simple.cpp"


def test_clang_dump_ast_returns_json():
    """Clang adapter should return a valid JSON AST."""
    adapter = ClangAdapter()

    ast_output = adapter.dump_ast(FIXTURE)

    assert ast_output
    assert ast_output.lstrip().startswith("{")


def test_ast_finds_function():
    """AST analysis should find the foo function."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast(FIXTURE)
    facts = analyzer.analyze(ast_output)

    foo = next(
        function
        for function in facts.functions
        if function.name == "foo"
    )

    assert foo.start_line == 3
    assert foo.end_line == 6


def test_ast_finds_memcpy_call():
    """AST analysis should find the memcpy call."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast(FIXTURE)
    facts = analyzer.analyze(ast_output)

    memcpy = next(
        operation
        for operation in facts.operations
        if operation.name == "memcpy"
    )

    assert memcpy.kind == "call"


def test_ast_preserves_memcpy_location():
    """AST analysis should preserve the memcpy source location."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast(FIXTURE)
    facts = analyzer.analyze(ast_output)

    memcpy = next(
        operation
        for operation in facts.operations
        if operation.name == "memcpy"
    )

    assert memcpy.line == 5
    assert memcpy.column is not None


def test_ast_preserves_memcpy_arguments():
    """AST analysis should preserve simple memcpy argument names."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast(FIXTURE)
    facts = analyzer.analyze(ast_output)

    memcpy = next(
        operation
        for operation in facts.operations
        if operation.name == "memcpy"
    )

    assert memcpy.arguments == ("dst", "src", "len")


def test_clang_dump_cfg_returns_cfg():
    """Clang adapter should return the CFG for the fixture."""
    adapter = ClangAdapter()

    cfg_output = adapter.dump_cfg(FIXTURE)

    assert cfg_output
    assert "void foo" in cfg_output
    assert "[B3 (ENTRY)]" in cfg_output
    assert "[B0 (EXIT)]" in cfg_output
    assert "Succs (2): B1 B0" in cfg_output


def test_cfg_finds_expected_edges():
    """CFG analysis should recover the fixture's basic-block edges."""
    adapter = ClangAdapter()
    analyzer = CFGAnalyzer()

    cfg_output = adapter.dump_cfg(FIXTURE)
    edges = analyzer.analyze(cfg_output)

    actual = {
        (edge.source, edge.target)
        for edge in edges
    }

    expected = {
        ("B3", "B2"),
        ("B2", "B1"),
        ("B2", "B0"),
        ("B1", "B0"),
    }

    assert actual == expected


def test_cfg_preserves_branch_condition():
    """CFG analysis should preserve the branch condition from Clang."""
    adapter = ClangAdapter()
    analyzer = CFGAnalyzer()

    cfg_output = adapter.dump_cfg(FIXTURE)
    edges = analyzer.analyze(cfg_output)

    branch_edges = [
        edge
        for edge in edges
        if edge.source == "B2"
    ]

    assert len(branch_edges) == 2
    assert all(edge.condition is not None for edge in branch_edges)


def test_analysis_combines_ast_and_cfg_facts():
    """Combined analysis should include both AST and CFG facts."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast(FIXTURE)
    cfg_output = adapter.dump_cfg(FIXTURE)

    facts = analyzer.analyze_with_cfg(
        ast_output,
        cfg_output,
    )

    assert any(
        function.name == "foo"
        for function in facts.functions
    )

    assert any(
        operation.name == "memcpy"
        for operation in facts.operations
    )

    actual_edges = {
        (edge.source, edge.target)
        for edge in facts.control_flow
    }

    expected_edges = {
        ("B3", "B2"),
        ("B2", "B1"),
        ("B2", "B0"),
        ("B1", "B0"),
    }

    assert actual_edges == expected_edges


def test_data_flow_fact_preserves_location_provenance():
    """Data-flow facts should preserve definition and use locations."""
    fact = DataFlowFact(
        id="dataflow:n:4:9:6:25",
        variable="n",
        relation="reaching_definition",
        definition_line=4,
        definition_column=9,
        use_line=6,
        use_column=25,
    )

    assert fact.variable == "n"
    assert fact.relation == "reaching_definition"

    assert fact.definition_line == 4
    assert fact.definition_column == 9

    assert fact.use_line == 6
    assert fact.use_column == 25


def test_program_facts_contains_empty_data_flow_after_ast_analysis():
    """AST analysis should extract definitions and uses but no relations."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast(FIXTURE)
    facts = analyzer.analyze(ast_output)

    assert facts.definitions
    assert facts.uses
    assert facts.data_flow == ()


def test_definition_fact_preserves_location():
    """Definition facts should preserve variable location."""
    fact = DefinitionFact(
        id="definition:n:4:9",
        variable="n",
        line=4,
        column=9,
    )

    assert fact.variable == "n"
    assert fact.line == 4
    assert fact.column == 9


def test_use_fact_preserves_location():
    """Use facts should preserve variable location."""
    fact = UseFact(
        id="use:n:6:25",
        variable="n",
        line=6,
        column=25,
    )

    assert fact.variable == "n"
    assert fact.line == 6
    assert fact.column == 25


def test_ast_extracts_parameter_definitions():
    """AST analysis should extract function parameters as definitions."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast(FIXTURE)
    facts = analyzer.analyze(ast_output)

    definitions = {
        definition.variable
        for definition in facts.definitions
    }

    assert {"dst", "src", "len"} <= definitions


def test_ast_extracts_variable_uses():
    """AST analysis should extract variable references as uses."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast(FIXTURE)
    facts = analyzer.analyze(ast_output)

    uses = {
        use.variable
        for use in facts.uses
    }

    assert {"dst", "src", "len"} <= uses


def test_ast_does_not_treat_function_reference_as_variable_use():
    """Function references such as memcpy should not become variable uses."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast(FIXTURE)
    facts = analyzer.analyze(ast_output)

    assert all(
        use.variable != "memcpy"
        for use in facts.uses
    )


def test_ast_preserves_definition_locations():
    """AST analysis should preserve parameter declaration locations."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    # A1: provide the original source together with the AST.
    ast_output = adapter.dump_ast_with_source(FIXTURE)
    facts = analyzer.analyze(ast_output)

    definitions = {
        definition.variable: definition
        for definition in facts.definitions
    }

    assert definitions["dst"].line == 3
    assert definitions["dst"].column == 16

    assert definitions["src"].line == 3
    assert definitions["src"].column == 27

    assert definitions["len"].line == 3
    assert definitions["len"].column == 36


def test_ast_preserves_use_locations():
    """AST analysis should preserve variable use locations."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    # A1: provide the original source so missing expression lines
    # can be resolved from Clang byte offsets.
    ast_output = adapter.dump_ast_with_source(FIXTURE)
    facts = analyzer.analyze(ast_output)

    len_uses = [
        use
        for use in facts.uses
        if use.variable == "len"
    ]

    assert any(
        use.line == 4 and use.column == 9
        for use in len_uses
    )

    assert any(
        use.line == 5 and use.column == 26
        for use in len_uses
    )


def test_analysis_combines_ast_cfg_and_data_flow_facts():
    """Combined analysis should preserve AST data-flow facts."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast(FIXTURE)
    cfg_output = adapter.dump_cfg(FIXTURE)

    facts = analyzer.analyze_with_cfg(
        ast_output,
        cfg_output,
    )

    definitions = {
        definition.variable
        for definition in facts.definitions
    }

    uses = {
        use.variable
        for use in facts.uses
    }

    assert {"dst", "src", "len"} <= definitions
    assert {"dst", "src", "len"} <= uses
    assert facts.data_flow == ()


def test_ast_output_preserves_ast_and_source() -> None:
    """ASTOutput should preserve both AST JSON and source text."""
    output = ASTOutput(
        ast_json='{"kind": "TranslationUnitDecl"}',
        source="int main() {}\n",
    )

    assert output.ast_json == '{"kind": "TranslationUnitDecl"}'
    assert output.source == "int main() {}\n"


def test_ast_resolves_missing_expression_line_from_source() -> None:
    """ASTAnalyzer should resolve a missing line from a Clang byte offset."""
    source = (
        "void foo(char *dst, char *src, int len) {\n"
        "    memcpy(dst, src, len);\n"
        "}\n"
    )

    ast = {
        "kind": "TranslationUnitDecl",
        "inner": [
            {
                "kind": "FunctionDecl",
                "name": "foo",
                "loc": {
                    "line": 1,
                    "col": 6,
                },
                "range": {
                    "begin": {
                        "line": 1,
                        "col": 1,
                    },
                    "end": {
                        "line": 3,
                        "col": 2,
                    },
                },
                "inner": [
                    {
                        "kind": "ParmVarDecl",
                        "id": "dst-id",
                        "name": "dst",
                        "loc": {
                            "offset": 15,
                            "col": 16,
                        },
                    },
                    {
                        "kind": "DeclRefExpr",
                        "range": {
                            "begin": {
                                "offset": 57,
                                "col": 25,
                            },
                        },
                        "referencedDecl": {
                            "id": "len-id",
                            "kind": "ParmVarDecl",
                            "name": "len",
                        },
                    },
                ],
            },
        ],
    }

    analyzer = ASTAnalyzer()

    facts = analyzer.analyze(
        ASTOutput(
            ast_json=json.dumps(ast),
            source=source,
        )
    )

    assert facts.uses[0].line == 2
    assert facts.uses[0].column == 25


def test_ast_output_is_compatible_with_combined_cfg_analysis() -> None:
    """A1 AST output should work with combined AST and CFG analysis."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast_with_source(FIXTURE)
    cfg_output = adapter.dump_cfg(FIXTURE)

    facts = analyzer.analyze_with_cfg(
        ast_output,
        cfg_output,
    )

    assert any(
        function.name == "foo"
        for function in facts.functions
    )

    assert any(
        operation.name == "memcpy"
        for operation in facts.operations
    )

    assert any(
        definition.variable == "dst"
        and definition.line == 3
        and definition.column == 16
        for definition in facts.definitions
    )

    assert any(
        use.variable == "len"
        and use.line == 4
        and use.column == 9
        for use in facts.uses
    )

    assert facts.data_flow == ()

def test_cfg_finds_expected_basic_blocks():
    """CFG analysis should recover normalized basic blocks."""
    adapter = ClangAdapter()
    analyzer = CFGAnalyzer()

    cfg_output = adapter.dump_cfg(FIXTURE)
    blocks = analyzer.analyze_blocks(cfg_output)

    block_ids = {
        block.id
        for block in blocks
    }

    assert block_ids == {"B0", "B1", "B2", "B3"}


def test_cfg_preserves_basic_block_statements():
    """CFG blocks should preserve normalized Clang statements."""
    adapter = ClangAdapter()
    analyzer = CFGAnalyzer()

    cfg_output = adapter.dump_cfg(FIXTURE)
    blocks = analyzer.analyze_blocks(cfg_output)

    blocks_by_id = {
        block.id: block
        for block in blocks
    }

    assert blocks_by_id["B2"].statements
    assert blocks_by_id["B1"].statements

def test_definition_fact_has_ast_node_identity():
    """Definitions extracted from AST should have node identities."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast(FIXTURE)
    facts = analyzer.analyze(ast_output)

    definitions = {
        definition.variable: definition
        for definition in facts.definitions
    }

    assert definitions["dst"].ast_node_id
    assert definitions["src"].ast_node_id
    assert definitions["len"].ast_node_id

    assert len(
        {
            definitions["dst"].ast_node_id,
            definitions["src"].ast_node_id,
            definitions["len"].ast_node_id,
        }
    ) == 3


def test_use_facts_have_distinct_ast_node_identities():
    """Different variable-use occurrences should have distinct identities."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast(FIXTURE)
    facts = analyzer.analyze(ast_output)

    uses = [
        use
        for use in facts.uses
        if use.variable == "len"
    ]

    assert len(uses) >= 2

    ast_node_ids = [
        use.ast_node_id
        for use in uses
    ]

    assert all(ast_node_ids)
    assert len(set(ast_node_ids)) == len(ast_node_ids)


def test_use_ast_node_identity_is_distinct_from_definition_identity():
    """A use occurrence must not reuse its declaration identity."""
    adapter = ClangAdapter()
    analyzer = ASTAnalyzer()

    ast_output = adapter.dump_ast(FIXTURE)
    facts = analyzer.analyze(ast_output)

    len_definition = next(
        definition
        for definition in facts.definitions
        if definition.variable == "len"
    )

    len_uses = [
        use
        for use in facts.uses
        if use.variable == "len"
    ]

    assert len_definition.ast_node_id
    assert all(
        use.ast_node_id != len_definition.ast_node_id
        for use in len_uses
    )

def test_dataflow_fact_schema_remains_unchanged():
    """Existing data-flow relation schema should remain compatible."""
    fact = DataFlowFact(
        id="dataflow:n:4:9:6:25",
        variable="n",
        relation="reaching_definition",
        definition_line=4,
        definition_column=9,
        use_line=6,
        use_column=25,
    )

    assert fact.definition_line == 4
    assert fact.use_line == 6


def test_dataflow_analyzer_links_matching_definitions_and_uses():
    """Data-flow analysis should link definitions to matching uses."""
    analyzer = DataFlowAnalyzer()

    facts = analyzer.analyze(
        definitions=(
            DefinitionFact(
                id="definition:len:3:36",
                variable="len",
                line=3,
                column=36,
            ),
        ),
        uses=(
            UseFact(
                id="use:len:5:26",
                variable="len",
                line=5,
                column=26,
            ),
        ),
    )

    assert len(facts) == 1
    assert facts[0].variable == "len"
    assert facts[0].relation == "syntactic_reaching_definition"


def test_full_program_analysis_returns_b1_facts():
    """B1 orchestration should return AST, CFG, data-flow, and calls."""
    facts = analyze_source_file(FIXTURE)

    assert any(
        function.name == "foo"
        for function in facts.functions
    )

    assert any(
        operation.name == "memcpy"
        for operation in facts.operations
    )

    assert facts.cfg_blocks
    assert facts.control_flow
    assert facts.definitions
    assert facts.uses
    assert facts.data_flow

    assert any(
        edge.caller == "foo" and edge.callee == "memcpy"
        for edge in facts.call_graph
    )


def test_program_analysis_links_related_facts():
    """Program analysis should expose explicit cross-links between facts."""
    analysis = analyze_source_file_tolerant(
        FIXTURE,
        scope="file",
    )

    assert analysis.links is not None

    function_link = next(
        link
        for link in analysis.links.function_links
        if link.function_id == "function:foo:3"
    )
    memcpy = next(
        operation
        for operation in analysis.facts.operations
        if operation.name == "memcpy"
    )
    memcpy_edge = next(
        edge
        for edge in analysis.facts.call_graph
        if edge.callee == "memcpy"
    )

    assert memcpy.id in function_link.operation_ids
    assert memcpy_edge.id in function_link.call_graph_edge_ids
    assert any(
        link.operation_id == memcpy.id
        and link.call_graph_edge_id == memcpy_edge.id
        for link in analysis.links.operation_call_links
    )

    definition_use_links = [
        link
        for link in analysis.links.definition_use_links
        if link.variable == "len"
    ]

    assert definition_use_links
    assert all(
        link.definition_id.startswith("definition:len:")
        for link in definition_use_links
    )
    assert all(
        link.use_id.startswith("use:len:")
        for link in definition_use_links
    )


def test_tolerant_analysis_builds_data_flow_when_cfg_is_missing():
    """Recovered AST facts should still feed syntactic data-flow."""
    analysis = analyze_source_code_tolerant(
        (
            "static int example(int object) {\n"
            "    ProjectType missing;\n"
            "    return object != 0;\n"
            "}\n"
        ),
        scope="function",
    )

    assert analysis.cfg_available is False
    assert analysis.facts.definitions
    assert analysis.facts.uses
    assert analysis.facts.data_flow
    assert analysis.completeness is not None
    assert analysis.completeness["cfg"].status == "missing"
    assert analysis.completeness["data_flow"].status == "limited"
    assert any(
        limitation.startswith("CFG missing:")
        for limitation in analysis.limitations
    )
    assert any(
        limitation.startswith("data-flow facts are syntactic")
        for limitation in analysis.limitations
    )


def test_tolerant_analysis_accepts_clang_args(tmp_path):
    """B1 should pass compile context flags through to Clang."""
    source = tmp_path / "macro_guard.c"
    source.write_text(
        (
            "#ifndef VALUE\n"
            "#error VALUE must be provided\n"
            "#endif\n"
            "int configured(void) {\n"
            "    return VALUE;\n"
            "}\n"
        ),
        encoding="utf-8",
    )

    analysis = analyze_source_file_tolerant(
        source,
        scope="file",
        clang_args=("-DVALUE=7",),
    )

    assert analysis.complete is True
    assert analysis.cfg_available is True
    assert not analysis.diagnostics
    assert any(
        function.name == "configured"
        for function in analysis.facts.functions
    )
