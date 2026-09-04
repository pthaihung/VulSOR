# Remove Legacy Repository Context Design

**Date:** 2026-09-04

## Goal

Remove every current repository-context path that does not match the paper's
obligation-driven retrieval design. B1 will analyze only the dataset function
snippet; repository-level CPG retrieval will be rebuilt later as a B3/B4
capability.

## Scope

Remove the per-sample Joern/CPG path, PrimeVul context sidecar loading and
whole-file selection, same-file caller/callee heuristics, and their CLI,
artifact, configuration, documentation, and test surfaces.

Keep Clang-based local AST, CFG, syntactic data-flow, syntactic call-graph
facts, source locations, missing-context diagnostics, B2 semantic views,
agent artifacts, and the B2 semantic graph overlay. These operate on the
target function and remain valid paper-aligned foundations.

## Resulting boundary

```text
dataset inputs/{split}.jsonl
    -> sample.code
    -> B1 function-scope Clang analysis
    -> ProgramFacts and limitations
    -> B2 semantic views
```

No B1 artifact will contain `source_context`, `context_facts`, or `cpg_facts`.
No B2 agent will receive sidecar caller/callee hints. The existing
`missing_context` field remains a report of unavailable local facts, not a
repository evidence bundle.

## Compatibility decision

The old `--analysis-scope`, `--cpg`, context sidecar format, Joern adapter, and
context-specific tests are removed rather than deprecated. Existing generated
artifacts are not migrated; users must regenerate B1 artifacts after this
change.

## Acceptance criteria

1. Dataset inspection analyzes `sample.code` with function scope and does not
   read `dataset_root/context`.
2. CLI output and B1 artifacts contain no CPG or sidecar-context fields.
3. The agent registry exposes only current-artifact program-fact tools and no
   context/CPG tools.
4. No production or test source imports the removed Joern/context APIs.
5. Existing local B1 and B2 behavior remains covered by tests.
