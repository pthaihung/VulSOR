from vulsor.repository_context.relation_selection import select_repository_relations


def fact(code, line, *, defines=(), uses=(), **extra):
    return {
        "code": code,
        "file": "demo.c",
        "line": line,
        "defines": list(defines),
        "uses": list(uses),
        "provenance": extra.pop("provenance", "cpg_dataflow"),
        **extra,
    }


def payload(**overrides):
    value = {
        "target_status": "exact",
        "seeds": [fact("*(double *)p1", 50, uses=("p1",), priority=100)],
        "data_candidates": [],
        "control_candidates": [],
        "declaration_candidates": [],
        "contract_candidates": [],
        "call_candidates": [],
        "limitations": [],
        "truncated": False,
    }
    value.update(overrides)
    return value


def test_selects_transitive_backward_data_chain_and_excludes_unrelated_facts():
    selected = select_repository_relations(
        payload(
            data_candidates=[
                fact("p1 = p", 45, defines=("p1",), uses=("p",)),
                fact("p = q + 8", 40, defines=("p",), uses=("q",)),
                fact(
                    "q = exif + dir_offset",
                    35,
                    defines=("q",),
                    uses=("exif", "dir_offset"),
                ),
                fact(
                    "dir_offset = read(base + 8)",
                    30,
                    defines=("dir_offset",),
                    uses=("base",),
                    provenance="syntactic_assignment_fallback",
                ),
                fact("unrelated = 1", 10, defines=("unrelated",)),
            ]
        )
    )

    assert [item["code"] for item in selected["data_dependencies"]] == [
        "dir_offset = read(base + 8)",
        "q = exif + dir_offset",
        "p = q + 8",
        "p1 = p",
    ]
    assert "unrelated = 1" not in str(selected)
    assert any("syntactic assignment fallback" in item for item in selected["limitations"])


def test_no_seed_uses_parameters_returns_and_sensitive_calls_as_fallback():
    selected = select_repository_relations(
        payload(
            seeds=[],
            data_candidates=[
                fact("size", 2, defines=("size",), kind="parameter"),
                fact("return result", 20, uses=("result",), kind="return"),
                fact("result = parse(size)", 15, defines=("result",), uses=("size",)),
            ],
            call_candidates=[
                fact(
                    "memcpy(dst, src, size)",
                    12,
                    uses=("dst", "src", "size"),
                    callee="memcpy",
                    sensitive=True,
                    arguments=["dst", "src", "size"],
                )
            ],
        )
    )

    assert selected["anchors"]
    assert {"size", "result"}.issubset(
        {name for item in selected["anchors"] for name in item["entities"]}
    )
    assert "seed_fallback_used" in selected["limitations"]
    assert selected["data_dependencies"]


def test_filters_related_controls_declarations_contracts_and_calls():
    selected = select_repository_relations(
        payload(
            data_candidates=[fact("p1 = p", 45, defines=("p1",), uses=("p",))],
            control_candidates=[
                fact(
                    "p + size <= end",
                    42,
                    uses=("p", "size", "end"),
                    role="bounds_check",
                    governs_lines=[45, 50],
                ),
                fact("debug != 0", 5, uses=("debug",), role="other_guard"),
            ],
            declaration_candidates=[
                fact("unsigned char *p", 3, defines=("p",), name="p", type="unsigned char *"),
                fact("int debug", 4, defines=("debug",), name="debug", type="int"),
            ],
            contract_candidates=[
                fact(
                    "#define STEP(x) p += (x)",
                    1,
                    defines=("p",),
                    uses=("p",),
                    name="STEP",
                )
            ],
            call_candidates=[
                fact("STEP(size)", 44, uses=("p", "size"), callee="STEP", arguments=["size"]),
                fact("consume(p)", 46, uses=("p",), callee="consume", arguments=["p"]),
                fact("log(debug)", 6, uses=("debug",), callee="log", arguments=["debug"]),
            ],
        )
    )

    assert [item["code"] for item in selected["control_dependencies"]] == [
        "p + size <= end"
    ]
    assert [item["name"] for item in selected["declarations_types"]] == ["p"]
    assert [item["name"] for item in selected["local_contracts"]] == ["STEP"]
    assert [item["callee"] for item in selected["calls"]] == ["consume"]


def test_deduplicates_and_applies_family_budgets_deterministically():
    repeated = fact("p1 = p", 45, defines=("p1",), uses=("p",))
    selected = select_repository_relations(
        payload(data_candidates=[repeated, dict(repeated)])
    )

    assert len(selected["data_dependencies"]) == 1
    assert selected["anchor_status"] == "exact"
    assert selected["truncated"] is False
