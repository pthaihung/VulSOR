from vulsor.repository_context.file_context_selection import (
    SAFE_CONTEXT_TOKENS,
    select_file_context,
)
from vulsor.repository_context.prompt_context import estimate_context_tokens


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
    assert any("size" in item.get("condition", item.get("code", "")) for item in context["control_dependencies"])
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


def test_selection_removes_unrelated_assignments_and_compacts_long_facts() -> None:
    facts = {
        "call_relations": [
            {"code": "memcpy(buf, src, size)", "file": "target.c", "line": 20, "callee": "memcpy"},
        ],
        "call_site_arguments": [
            {"code": "buf", "file": "target.c", "line": 20, "call": "memcpy", "argument_index": 0},
            {"code": "size", "file": "target.c", "line": 20, "call": "memcpy", "argument_index": 2},
        ],
        "data_flow": [
            {
                "code": "size = header.length",
                "file": "target.c",
                "line": 12,
                "defines": ["size"],
                "uses": ["header"],
                "provenance": "syntactic_assignment",
            },
            {
                "code": "debug_table[] = {" + "0," * 1000 + "}",
                "file": "target.c",
                "line": 3,
                "defines": ["debug_table"],
                "uses": [],
                "provenance": "syntactic_assignment",
            },
        ],
        "control_dependencies": [
            {
                "code": "if (size <= capacity) {" + "\n    consume(buf);" * 80 + "\n}",
                "condition": "size <= capacity",
                "file": "target.c",
                "line": 18,
                "uses": ["size", "capacity"],
                "provenance": "cpg_control",
            },
            {
                "code": "if (debug) { log_debug(); }",
                "condition": "debug",
                "file": "target.c",
                "line": 19,
                "uses": ["debug"],
                "provenance": "cpg_control",
            },
        ],
        "declarations": [
            {"code": "char *buf", "name": "buf", "type": "char *", "file": "target.c", "line": 5},
            {"code": "size_t size", "name": "size", "type": "size_t", "file": "target.c", "line": 6},
            {"code": "int debug", "name": "debug", "type": "int", "file": "target.c", "line": 7},
        ],
        "types": [{"name": "char *"}, {"name": "size_t"}, {"name": "int"}],
        "imports": [
            {"code": "#include <string.h>", "file": "target.c", "line": 1},
            {"code": "#include <unrelated/header_1.h>", "file": "target.c", "line": 2},
        ],
    }

    context = select_file_context(facts)
    encoded = estimate_context_tokens(__import__("json").dumps(context, separators=(",", ":")))

    assert encoded <= 2000
    assert all("debug_table" not in item.get("code", "") for item in context.get("data_flow", []))
    assert all("debug" not in item.get("condition", "") for item in context.get("control_dependencies", []))
    assert all("code" not in item for item in context.get("control_dependencies", []))
    assert context["data_flow"][0]["defines"] == ["size"]


def test_selection_prefers_joern_data_flow_over_syntactic_fallback() -> None:
    facts = {
        "call_relations": [
            {"code": "memcpy(buf, src, size)", "file": "target.c", "line": 20, "callee": "memcpy"},
        ],
        "call_site_arguments": [
            {"code": "size", "file": "target.c", "line": 20, "call": "memcpy", "argument_index": 2},
        ],
        "data_flow": [
            {
                "code": "size = header.length",
                "file": "target.c",
                "line": 12,
                "defines": ["size"],
                "uses": ["header"],
                "provenance": "syntactic_assignment",
            },
            {
                "code": "header.length -> size",
                "file": "target.c",
                "line": 12,
                "from_line": 10,
                "defines": ["size"],
                "uses": ["header"],
                "provenance": "joern_reaching_def",
            },
        ],
        "control_dependencies": [],
        "declarations": [],
        "types": [],
    }

    context = select_file_context(facts)

    assert context["data_flow"][0]["provenance"] == "joern_reaching_def"


def test_selection_reserves_data_control_and_contract_families() -> None:
    facts = {
        "call_relations": [
            {
                "code": f"helper_{index}(value, size) /* {'x' * 180} */",
                "file": "target.c",
                "line": index + 20,
                "callee": f"helper_{index}",
            }
            for index in range(16)
        ],
        "call_site_arguments": [
            {
                "code": f"value_{index} /* {'x' * 100} */",
                "file": "target.c",
                "line": index + 20,
                "call": f"helper_{index}",
                "argument_index": 0,
            }
            for index in range(16)
        ],
        "data_flow": [
            {
                "code": "size = header.length",
                "file": "target.c",
                "line": 12,
                "defines": ["size"],
                "uses": ["header"],
                "provenance": "joern_reaching_def",
            }
        ],
        "control_dependencies": [
            {
                "code": "if (size <= capacity) { huge body }",
                "condition": "size <= capacity",
                "file": "target.c",
                "line": 18,
                "uses": ["size", "capacity"],
                "provenance": "joern_control_dependence",
            }
        ],
        "declarations": [
            {"code": "size_t size", "name": "size", "type": "size_t", "file": "target.c", "line": 6},
        ],
        "types": [{"name": "size_t"}],
    }

    context = select_file_context(facts)

    assert context.get("data_flow")
    assert context.get("control_dependencies")
    assert context.get("declarations")
    assert context.get("types")


def test_selection_keeps_call_relations_with_core_slice_under_budget() -> None:
    facts = {
        "call_relations": [
            {"code": "memcpy(buf, src, size)", "file": "target.c", "line": 30, "caller": "target", "callee": "memcpy"},
            {"code": "helper(size)", "file": "target.c", "line": 31, "caller": "target", "callee": "helper"},
        ],
        "call_site_arguments": [
            {"code": "buf", "file": "target.c", "line": 30, "call": "memcpy", "argument_index": 0},
            {"code": "size", "file": "target.c", "line": 30, "call": "memcpy", "argument_index": 2},
        ],
        "data_flow": [
            {
                "code": f"size = header_{index}.length /* {'x' * 120} */",
                "file": "target.c",
                "line": index + 10,
                "defines": ["size"],
                "uses": [f"header_{index}"],
                "provenance": "joern_reaching_def",
            }
            for index in range(32)
        ],
        "control_dependencies": [
            {
                "code": "if (size <= capacity) { body }",
                "condition": "size <= capacity",
                "file": "target.c",
                "line": 28,
                "uses": ["size", "capacity"],
                "provenance": "joern_control_dependence",
            }
        ],
        "declarations": [
            {"code": "char *buf", "name": "buf", "type": "char *", "file": "target.c", "line": 5},
            {"code": "size_t size", "name": "size", "type": "size_t", "file": "target.c", "line": 6},
        ],
        "types": [{"name": "char *"}, {"name": "size_t"}],
    }

    context = select_file_context(facts)

    assert context.get("data_flow")
    assert context.get("control_dependencies")
    assert context.get("declarations")
    assert context.get("types")
    assert context.get("call_relations")
    assert context.get("call_site_arguments")


def test_selection_merges_duplicate_flow_edges_and_control_guards() -> None:
    facts = {
        "call_relations": [
            {"code": "memcpy(buf, src, size)", "file": "target.c", "line": 30, "caller": "target", "callee": "memcpy"},
        ],
        "call_site_arguments": [
            {"code": "size", "file": "target.c", "line": 30, "call": "memcpy", "argument_index": 2},
        ],
        "data_flow": [
            {"code": "length -> size", "file": "target.c", "line": 20, "from_line": 10, "defines": ["size"], "uses": ["length"], "provenance": "joern_reaching_def"},
            {"code": "length -> size", "file": "target.c", "line": 20, "from_line": 12, "defines": ["size"], "uses": ["length"], "provenance": "joern_reaching_def"},
        ],
        "control_dependencies": [
            {"code": "if (size <= capacity) { ... }", "condition": "size <= capacity", "file": "target.c", "line": 25, "controlled_line": 30, "provenance": "joern_control_dependence"},
            {"code": "if (size <= capacity) { ... }", "condition": "size <= capacity", "file": "target.c", "line": 25, "controlled_line": 31, "provenance": "joern_control_dependence"},
        ],
        "declarations": [],
        "types": [],
    }

    context = select_file_context(facts)

    assert len(context["data_flow"]) == 1
    assert context["data_flow"][0]["from_lines"] == [10, 12]
    assert len(context["control_dependencies"]) == 1
    assert context["control_dependencies"][0]["controlled_lines"] == [30, 31]


def test_selection_never_keeps_argument_without_retained_call() -> None:
    facts = {
        "call_relations": [
            {"code": f"helper_{index}(value_{index})", "file": "target.c", "line": index + 10, "caller": "target", "callee": f"helper_{index}"}
            for index in range(10)
        ],
        "call_site_arguments": [
            {"code": f"value_{index}", "file": "target.c", "line": index + 10, "call": f"helper_{index}", "argument_index": 0}
            for index in range(10)
        ],
        "data_flow": [],
        "control_dependencies": [],
        "declarations": [],
        "types": [],
    }

    context = select_file_context(facts)
    retained_calls = {item["callee"] for item in context["call_relations"]}

    assert context.get("call_site_arguments")
    assert {item["call"] for item in context["call_site_arguments"]} <= retained_calls


def test_selection_caps_aggregated_control_lines() -> None:
    facts = {
        "call_relations": [
            {"code": "memcpy(buf, src, size)", "file": "target.c", "line": 30, "caller": "target", "callee": "memcpy"},
        ],
        "call_site_arguments": [
            {"code": "size", "file": "target.c", "line": 30, "call": "memcpy", "argument_index": 2},
        ],
        "data_flow": [],
        "control_dependencies": [
            {
                "code": "if (size <= capacity) { ... }",
                "condition": "size <= capacity",
                "file": "target.c",
                "line": 25,
                "controlled_line": line,
                "provenance": "joern_control_dependence",
            }
            for line in range(30, 50)
        ],
        "declarations": [],
        "types": [],
    }

    context = select_file_context(facts)

    assert len(context["control_dependencies"]) == 1
    assert len(context["control_dependencies"][0]["controlled_lines"]) <= 8


def test_selection_uses_safe_token_headroom() -> None:
    facts = {
        "call_relations": [
            {
                "code": f"memcpy(buf, src, size_{index}) /* {'x' * 160} */",
                "file": "target.c",
                "line": index + 30,
                "caller": "target",
                "callee": "memcpy",
            }
            for index in range(12)
        ],
        "call_site_arguments": [
            {
                "code": f"size_{index} /* {'x' * 100} */",
                "file": "target.c",
                "line": index + 30,
                "call": "memcpy",
                "argument_index": 2,
            }
            for index in range(12)
        ],
        "data_flow": [],
        "control_dependencies": [],
        "declarations": [],
        "types": [],
    }

    context = select_file_context(facts)
    encoded = __import__("json").dumps(context, separators=(",", ":"))

    assert estimate_context_tokens(encoded) <= SAFE_CONTEXT_TOKENS
    assert context.get("call_relations")
    assert context.get("call_site_arguments")
    assert {
        item["call"] for item in context["call_site_arguments"]
    } <= {item["callee"] for item in context["call_relations"]}


def test_selection_drops_unconnected_out_of_target_flow_but_keeps_linked_flow() -> None:
    facts = {
        "target_function": "target",
        "target_start_line": 10,
        "target_end_line": 20,
        "call_relations": [
            {"code": "consume(size)", "file": "target.c", "line": 18, "callee": "consume"}
        ],
        "call_site_arguments": [
            {"code": "size", "file": "target.c", "line": 18, "call": "consume", "argument_index": 0}
        ],
        "data_flow": [
            {
                "code": "size = header.length",
                "file": "target.c",
                "line": 18,
                "from_line": 12,
                "from_method": "target",
                "to_method": "target",
                "defines": ["size"],
                "uses": ["header"],
                "provenance": "joern_reaching_def",
            },
            {
                "code": "unrelated = global_value",
                "file": "target.c",
                "line": 4,
                "from_line": 3,
                "from_method": "other",
                "to_method": "other",
                "defines": ["size"],
                "uses": ["global_value"],
                "provenance": "joern_reaching_def",
            },
        ],
        "control_dependencies": [],
        "declarations": [],
        "types": [],
    }

    context = select_file_context(facts)

    assert len(context["data_flow"]) == 1
    assert context["data_flow"][0]["line"] == 18


def test_selection_keeps_callee_metadata_when_body_is_large() -> None:
    facts = {
        "call_relations": [
            {"code": "helper(size)", "file": "target.c", "line": 18, "callee": "helper"}
        ],
        "call_site_arguments": [
            {"code": "size", "file": "target.c", "line": 18, "call": "helper", "argument_index": 0}
        ],
        "callee_funcs": [
            {
                "name": "helper",
                "signature": "void helper(int)",
                "code": "void helper(int size) {" + "\n    use(size);" * 500 + "\n}",
                "file": "target.c",
                "line": 30,
                "start_line": 30,
                "end_line": 532,
            }
        ],
        "data_flow": [],
        "control_dependencies": [],
        "declarations": [],
        "types": [],
    }

    context = select_file_context(facts)

    assert context["callee_funcs"][0]["name"] == "helper"
    assert "signature" in context["callee_funcs"][0]
    assert "code" not in context["callee_funcs"][0]


def test_selection_drops_callee_without_retained_call_relation() -> None:
    facts = {
        "call_relations": [
            {
                "code": f"helper_{index}(size)",
                "file": "target.c",
                "line": index + 10,
                "caller": "target",
                "callee": f"helper_{index}",
            }
            for index in range(9)
        ],
        "callee_funcs": [
            {
                "name": "helper_8",
                "signature": "int helper_8(int)",
                "code": "int helper_8(int size) { return size; }",
                "file": "target.c",
                "line": 100,
                "start_line": 100,
                "end_line": 100,
            }
        ],
        "call_site_arguments": [],
        "data_flow": [],
        "control_dependencies": [],
        "declarations": [],
        "types": [],
    }

    context = select_file_context(facts)

    assert len(context["call_relations"]) == 8
    assert "callee_funcs" not in context


def test_selection_reserves_call_argument_by_evicting_low_priority_items() -> None:
    facts = {
        "call_relations": [
            {
                "code": "helper(size)",
                "file": "target.c",
                "line": 30,
                "caller": "target",
                "callee": "helper",
            }
        ],
        "call_site_arguments": [
            {
                "code": f"size_{index} /* {'x' * 240} */",
                "file": "target.c",
                "line": 30,
                "call": "helper",
                "argument_index": index,
            }
            for index in range(4)
        ],
        "data_flow": [
            {
                "code": f"size = source_{index} /* {'x' * 420} */",
                "file": "target.c",
                "line": index + 10,
                "defines": ["size"],
                "uses": [f"source_{index}"],
                "provenance": "joern_reaching_def",
            }
            for index in range(8)
        ],
        "control_dependencies": [
            {
                "code": f"if (size > limit_{index}) {{ {'x' * 150} }}",
                "condition": f"size > limit_{index}",
                "file": "target.c",
                "line": index + 40,
                "uses": ["size", f"limit_{index}"],
                "provenance": "joern_control_dependence",
            }
            for index in range(6)
        ],
        "declarations": [
            {
                "code": f"size_t value_{index}",
                "name": f"value_{index}",
                "type": "size_t",
                "file": "target.c",
                "line": index + 60,
            }
            for index in range(8)
        ],
        "types": [{"name": f"type_{index}"} for index in range(4)],
        "callee_funcs": [
            {
                "name": "helper",
                "signature": "int helper(int)",
                "code": "int helper(int size) {" + "\n  use(size);" * 80 + "\n}",
                "file": "target.c",
                "line": 80,
                "start_line": 80,
                "end_line": 161,
            }
        ],
    }

    context = select_file_context(facts)

    assert context.get("call_relations")
    assert context.get("call_site_arguments")
    assert context["call_site_arguments"][0]["call"] == "helper"
    assert context.get("callee_funcs")
    assert context["callee_funcs"][0]["name"] == "helper"


def test_selection_does_not_duplicate_existing_call_argument() -> None:
    facts = {
        "call_relations": [
            {"code": "helper(size)", "file": "target.c", "line": 30, "callee": "helper"}
        ],
        "call_site_arguments": [
            {"code": "size", "file": "target.c", "line": 30, "call": "helper", "argument_index": 0}
        ],
        "data_flow": [],
        "control_dependencies": [],
        "declarations": [],
        "types": [],
    }

    context = select_file_context(facts)

    assert len(context["call_site_arguments"]) == 1
