from tests.context_tool_module import context_tool


def test_file_context_script_uses_argument_fallback_and_variable_flow_sinks() -> None:
    script = context_tool._FILE_CONTEXT_SC
    for required in (
        "def argumentItem",
        "line(call)",
        "method.parameter",
        "calls.iterator.flatMap(_.argument)",
        'val calls = method.call.filterNot(_.name.startsWith("<operator"))',
        ".filter(c => !sourceFallback || inSelectedRange(c)).toList",
        '"condition" -> Str(controlCondition(guard))',
    ):
        assert required in script


def test_file_context_script_preserves_macro_calls_and_callee_source() -> None:
    script = context_tool._FILE_CONTEXT_SC
    for required in (
        "source_call_fallback",
        "def sameSourceFile",
        '"code" -> Str(code(m))',
        '!code(m).trim.startsWith("#define")',
        '"from_method"',
        "source_declaration_fallback",
        'filterNot(m => m.name == "<global>" || m.name == "<module>")',
        "name == methodNameForContext",
        "sourceFallback",
        "inSelectedRange",
        "declarationNodes = (method.parameter ++ method.local).filter(n => !sourceFallback || inSelectedRange(n)).toList",
    ):
        assert required in script
