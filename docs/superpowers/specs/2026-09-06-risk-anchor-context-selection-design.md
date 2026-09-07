# Risk-anchor repository context selection

## Goal

Replace function-wide repository-context extraction with a source-grounded,
risk-anchor-centered selection pass. The offline output must give the LLM the
smallest repository evidence needed to reason about a target operation, capped
at 2,000 context tokens without dropping essential data, control, type, or
macro facts.

## Scope

This change affects only the offline `build-context` path and the prompt-ready
JSONL record. Runtime remains JSONL-only and does not invoke Git, Joern, or a
CPG. Batch processing, target-function source truncation, and deletion of
temporary repositories/CPGs are outside scope.

## Selection model

1. Resolve the target method exactly in its revision CPG.
2. Identify at most two risk anchors in source order. The initial C/C++ anchor
   patterns are pointer-cast dereferences, pointer indexing/pointer arithmetic,
   size/offset arithmetic, and calls to a small configured memory-sensitive API
   set. Anchors without source code or source lines are ignored.
3. For each anchor, collect a bounded backward value slice. Keep assignments,
   parameters, locals, literals, and direct call results that establish the
   anchor operands. Stop at parameters, literals, unresolved external calls,
   or the maximum slice depth.
4. Collect controls that guard the anchor or a retained data-slice node. First
   use Joern control dependence; when it is empty, use enclosing source-level
   `if`, `switch`, `while`, `for`, and conditional-expression ancestors. Keep
   only controls mentioning a retained value-slice entity.
5. Collect the declarations/types for retained slice entities and the anchor
   operands. If a retained node originates in a macro expansion, include the
   minimal macro definition/body fragment that establishes the value relation as
   a `local_contract`; macros are never emitted as call relations.
6. Collect direct non-operator calls that define, validate, or consume a
   retained slice entity. Deduplicate repeated callees by source role rather
   than retaining repeated formatting calls.
7. Merge facts across anchors by source location and relation. Preserve source
   code, file, line, and relation category; report any unavailable family in
   `limitations`.

## Output contract

The JSONL record remains:

```json
{
  "sample_id": "test_194963",
  "context": "...",
  "limitations": []
}
```

Anchors remain internal extraction metadata and are not rendered for the LLM.
The rendered context has four fixed sections in order:

1. `[DATA DEPENDENCIES]`
2. `[CONTROL DEPENDENCIES]`
3. `[DECLARATIONS, TYPES AND CONTRACTS]`
4. `[CALL RELATIONS]`

An empty section is explicit. A relation never becomes evidence merely because
the renderer needs to fill a section.

## Budgets

The budget is hierarchical rather than one global `max_items` value:

```text
max_anchors:                  2
max_data_facts_per_anchor:    8
max_control_facts_per_anchor: 10
max_declaration_facts:        12
max_call_facts:               12
max_local_contract_lines:     15
max_context_tokens:           2,000
```

The implementation uses a deterministic conservative character equivalent of
8,000 characters for the 2,000-token cap. It retains complete facts only,
never cuts source code or a relation in the middle. The renderer records
`context_truncated` if an otherwise relevant fact does not fit.

## Sample acceptance criterion

For `test_194963` (`GetEXIFProperty`), the selected context must retain the
`float` and `double` pointer-cast dereference anchors; the lineage through
`p1`, `p`, `q`, `dir_offset`, `number_bytes`, `components`, and `format`; the
bounds/overflow/type-format guards; and the macro contract that assigns or
increments `p1`. It must exclude unrelated formatting/allocation repetitions
unless one is on the retained lineage.

The resulting repository context must be 1,200–1,800 tokens in normal output,
with the hard 2,000-token cap.

## Failure handling and tests

- A target with no anchor produces an explicit empty anchor section and
  `no_risk_anchor_found`; it does not revert to a full-function dump.
- A missing data/control relation produces its family-specific limitation.
- Tests cover anchor priority, source-order tie breaking, per-family budgets,
  macro contract rendering, deterministic merge, 8,000-character truncation,
  and tool-free JSONL loading.
- A real Joern smoke run on `test_194963` verifies that the selected record is
  materially smaller than the existing 21,495-character function-wide context
  while preserving the stated sample facts.
