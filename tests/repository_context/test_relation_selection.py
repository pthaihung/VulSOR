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


def test_deduplicates_equivalent_control_conditions_from_macro_expansion():
    selected = select_repository_relations(
        payload(
            control_candidates=[
                fact("component < components", 40, uses=("p1",), role="bounds_check"),
                fact("component < components", 45, uses=("p1",), role="bounds_check"),
            ]
        )
    )

    assert len(selected["control_dependencies"]) == 1


def test_keeps_only_two_nearest_definitions_for_each_retained_entity():
    selected = select_repository_relations(
        payload(
            data_candidates=[
                fact(f"p1 = old_{line}", line, defines=("p1",), uses=(f"old_{line}",))
                for line in (10, 20, 30, 40, 45, 49)
            ]
        )
    )

    assert [item["line"] for item in selected["data_dependencies"]] == [45, 49]


def test_budget_keeps_near_seed_data_and_high_priority_controls():
    selected = select_repository_relations(
        payload(
            data_candidates=[
                fact(f"p1 = source_{line}", line, defines=("p1",), uses=(f"source_{line}",))
                for line in range(1, 50)
            ],
            control_candidates=[
                fact(
                    f"other_{line}", line, uses=("p1",), role="other_guard"
                )
                for line in range(1, 25)
            ]
            + [fact("p1 < end", 48, uses=("p1",), role="bounds_check")],
        )
    )

    assert [item["line"] for item in selected["data_dependencies"]] == [48, 49]
    assert any(item["code"] == "p1 < end" for item in selected["control_dependencies"])


def test_control_budget_prefers_a_guard_that_governs_the_retained_slice():
    selected = select_repository_relations(
        payload(
            data_candidates=[fact("p1 = p", 45, defines=("p1",), uses=("p",))],
            control_candidates=[
                fact(f"p != bad_{line}", line, uses=("p",), role="bounds_check")
                for line in range(1, 21)
            ]
            + [
                fact(
                    "p < end",
                    44,
                    uses=("p", "end"),
                    role="bounds_check",
                    governs_lines=[45, 50],
                )
            ],
        )
    )

    assert any(item["code"] == "p < end" for item in selected["control_dependencies"])


def test_contract_must_be_invoked_on_the_retained_slice():
    selected = select_repository_relations(
        payload(
            data_candidates=[fact("p1 = p", 45, defines=("p1",), uses=("p",))],
            contract_candidates=[
                fact(
                    "#define USED(x) p1 = p",
                    1,
                    defines=("p1",),
                    uses=("p",),
                    name="USED",
                    invocation_lines=[50],
                ),
                fact(
                    "#define OLD(x) p1 = p",
                    2,
                    defines=("p1",),
                    uses=("p",),
                    name="OLD",
                    invocation_lines=[10],
                ),
            ],
        )
    )

    assert [item["name"] for item in selected["local_contracts"]] == ["USED"]


def test_includes_definitions_for_size_entities_used_by_related_guards():
    selected = select_repository_relations(
        payload(
            data_candidates=[
                fact("p1 = p", 45, defines=("p1",), uses=("p",)),
                fact("p = base + offset", 40, defines=("p",), uses=("base", "offset")),
                fact(
                    "number_bytes = components * widths[format]",
                    30,
                    defines=("number_bytes",),
                    uses=("components", "widths", "format"),
                ),
                fact("components = read_count(base)", 25, defines=("components",), uses=("base",)),
                fact("format = read_format(base)", 26, defines=("format",), uses=("base",)),
            ],
            control_candidates=[
                fact(
                    "offset + number_bytes > length",
                    42,
                    uses=("offset", "number_bytes", "length"),
                    role="overflow_check",
                    governs_lines=[45, 50],
                )
            ],
        )
    )

    codes = {item["code"] for item in selected["data_dependencies"]}
    assert "number_bytes = components * widths[format]" in codes
    assert "components = read_count(base)" in codes
    assert "format = read_format(base)" in codes


def test_null_sentinel_does_not_connect_unrelated_guards():
    selected = select_repository_relations(
        payload(
            data_candidates=[fact("p1 = p", 45, defines=("p1",), uses=("p",))],
            control_candidates=[
                fact("p != NULL", 44, uses=("p", "NULL"), role="null_check"),
                fact("unrelated != NULL", 5, uses=("unrelated", "NULL"), role="null_check"),
            ],
        )
    )

    assert [item["code"] for item in selected["control_dependencies"]] == [
        "p != NULL"
    ]


def test_does_not_keep_controls_for_entities_dropped_by_the_data_budget():
    roots = tuple(f"a{index}" for index in range(10))
    chain = [
        fact(f"a{index} = b{index}", 90 - index, defines=(f"a{index}",), uses=(f"b{index}",))
        for index in range(10)
    ] + [
        fact(f"b{index} = c{index}", 50 - index, defines=(f"b{index}",), uses=(f"c{index}",))
        for index in range(10)
    ]
    selected = select_repository_relations(
        payload(
            seeds=[fact("sink(roots)", 100, uses=roots, priority=100)],
            data_candidates=chain,
            control_candidates=[
                fact("c9 < end", 39, uses=("c9",), role="bounds_check")
            ],
        )
    )

    assert all(
        item["code"] != "c9 < end" for item in selected["control_dependencies"]
    )
