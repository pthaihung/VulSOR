from vulsor.repository_context.file_context_selection import select_file_context


def test_selection_keeps_transitive_variables_and_related_guard() -> None:
    facts = {
        "call_relations": [
            {"code": "memcpy(buf, src, size)", "file": "target.c", "line": 20, "callee": "memcpy"},
            {"code": "log_debug(size)", "file": "target.c", "line": 30, "callee": "log_debug"},
        ],
        "call_site_arguments": [
            {"code": "buf", "file": "target.c", "line": 20, "call": "memcpy"},
            {"code": "size", "file": "target.c", "line": 20, "call": "memcpy"},
        ],
        "data_flow": [
            {"code": "size = header.length", "file": "target.c", "line": 12, "defines": ["size"], "uses": ["header"]},
            {"code": "header = read_header(src)", "file": "target.c", "line": 10, "defines": ["header"], "uses": ["src"]},
        ],
        "control_dependencies": [
            {"code": "if (size <= capacity)", "file": "target.c", "line": 18, "uses": ["size", "capacity"]},
            {"code": "if (debug)", "file": "target.c", "line": 29, "uses": ["debug"]},
        ],
        "declarations": [
            {"code": "char *buf", "name": "buf", "type": "char *", "file": "target.c", "line": 5},
            {"code": "size_t size", "name": "size", "type": "size_t", "file": "target.c", "line": 6},
            {"code": "int debug", "name": "debug", "type": "int", "file": "target.c", "line": 7},
        ],
        "types": [{"name": "char *"}, {"name": "size_t"}, {"name": "int"}],
    }

    context = select_file_context(facts)

    assert "data_flow" in context
    assert {"size", "header"}.issubset(
        {name for item in context["data_flow"] for name in item.get("defines", []) + item.get("uses", [])}
    )
    assert any("size" in item.get("code", "") for item in context["control_dependencies"])
    assert all("debug" not in item.get("code", "") for item in context.get("call_relations", []))


def test_selection_falls_back_to_target_arguments_when_no_sensitive_seed() -> None:
    facts = {
        "call_relations": [{"code": "helper(value)", "file": "target.c", "line": 8, "callee": "helper"}],
        "call_site_arguments": [{"code": "value", "file": "target.c", "line": 8, "call": "helper"}],
        "data_flow": [], "control_dependencies": [],
        "declarations": [{"code": "int value", "name": "value", "type": "int", "file": "target.c", "line": 3}],
        "types": [{"name": "int"}],
    }
    context = select_file_context(facts)
    assert context["call_relations"][0]["callee"] == "helper"
    assert context["declarations"][0]["name"] == "value"
