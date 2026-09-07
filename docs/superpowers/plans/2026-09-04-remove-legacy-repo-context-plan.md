# Remove Legacy Repository Context Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Remove the current non-paper repository-context implementation and leave a function-only B1 input boundary for the future obligation-driven retriever.

**Architecture:** `iter_dataset_samples` yields only `sample.code`; dataset inspection always invokes function-scope Clang analysis. B1 artifacts contain local `ProgramFacts` and diagnostics only, while B2 consumes those artifacts without sidecar or Joern context.

**Tech Stack:** Python 3, argparse, Pydantic/YAML configuration, pytest, Clang program analysis, existing B2 agent artifacts.

---

### Task 1: Remove context and CPG inputs from dataset analysis

**Files:**
- Modify: `src/vulsor/datasets.py`
- Modify: `src/vulsor/cli.py`
- Test: `tests/test_cli.py`

- [x] **Step 1: Remove dataset context loading.**

  Change `DatasetSample` to contain only `sample_id` and `code`; remove the
  `context` field, `include_context` parameter, `_load_context_map`, and the
  `context_by_sample_id` lookup. Every yielded sample must be constructed as
  `DatasetSample(sample_id=current_sample_id, code=code)`.

- [x] **Step 2: Make dataset B1 function-only.**

  Remove `--analysis-scope` from the inspect parser and interactive inspect
  flow. Replace `_analyze_dataset_sample` with a call to
  `analyze_source_code_tolerant(source_code=sample.code, scope="function", ...)`.
  Remove `source_context` arguments and the `_resolved_context_file`,
  `_source_context_metadata`, `_source_suffix`, and compile-context plumbing
  that exists only to analyze a sidecar-resolved file. Retain the normal
  Clang executable and local function-analysis diagnostics.

- [x] **Step 3: Remove CPG execution from sample inspection.**

  Remove the `--cpg` argument, `enable_cpg` parameters, `_analyze_cpg_for_sample`,
  `_cpg_not_requested`, `_cpg_metadata`, `_cpg_compile_inputs`, and the
  `JoernAdapter` import. `_inspect_dataset_sample` must call B1 once and build
  its artifact from that result.

- [x] **Step 4: Update focused CLI tests.**

  Delete tests that assert sidecar loading, whole-file auto selection, or
  real CPG output. Update remaining dataset inspection tests to omit
  `--analysis-scope` and to assert that the sample code is analyzed at
  function scope.

- [x] **Step 5: Run the focused tests.**

  Run: `python -m pytest tests/test_cli.py -q`

  Expected: only failures caused by the still-present artifact/rendering
  fields remain; record their exact names for Task 2.

### Task 2: Remove context/CPG fields from artifacts and CLI rendering

**Files:**
- Modify: `src/vulsor/cli.py`
- Modify: `src/vulsor/agents/SemanticViews.py`
- Modify: `src/vulsor/tools/agent_tool_registry.py`
- Test: `tests/test_cli.py`

- [x] **Step 1: Simplify analysis metadata.**

  Remove `source_context`, `context_facts`, `tool_status`, and `cpg_facts` from
  `_analysis_metadata`. Keep `scope`, `context_mode` if still produced by
  local analysis, `complete`, completeness, build diagnosis, missing-context
  summary, links, limitations, and rules.

- [x] **Step 2: Remove context and CPG display paths.**

  Remove context/CPG detail helpers, stage columns, coverage counters,
  sidecar coverage readers, context-gap summaries, and interactive prompts
  whose only data source is the removed metadata. Keep AST, CFG, data-flow,
  call-graph, diagnostics, and local missing-context reporting.

- [x] **Step 3: Remove sidecar data from B2 views.**

  In `build_state_view`, derive the target summary from the local
  `program_facts.functions` list. In `build_operation_view`, remove
  `helper_call_context`. Preserve operation facts, call roles, local
  uncertainty, and missing semantic context summaries.

- [x] **Step 4: Remove context tools.**

  Delete `get_context_facts` and `get_cpg_facts` from tool descriptions,
  schemas, dispatch, and configuration. Keep current-artifact program-fact,
  link, completeness, limitation, location, and related-fact tools.

- [x] **Step 5: Update artifact and semantic-view tests.**

  Replace assertions on removed keys with assertions that those keys are
  absent. Add an assertion that the state view target is derived from the
  local function fact and that the operation view has no helper-context field.

- [x] **Step 6: Run B1/B2 tests.**

  Run: `python -m pytest tests/test_analysis.py tests/test_cli.py -q`

  Expected: exit code 0 with all retained local-analysis and B2 tests passing.

### Task 3: Delete obsolete Joern/context code and update configuration

**Files:**
- Delete: `src/vulsor/tools/joern.py`
- Delete: `scripts/joern/b1_facts.sc`
- Delete: `tests/test_primevul_context.py`
- Modify: `src/vulsor/config.py`
- Modify: `README.md`
- Modify: `AGENT.md`

- [x] **Step 1: Remove obsolete files.**

  Delete the three files listed above after confirming no remaining import or
  test reference exists.

- [x] **Step 2: Remove Joern-only configuration.**

  Remove `ToolsConfig.joern` and any doctor/status output that only reports
  Joern. Do not remove Clang configuration or the Java executable if another
  retained feature still references it; remove Java only after a repository
  search confirms no retained consumer.

- [x] **Step 3: Correct project documentation.**

  Change the pipeline and artifact descriptions to say that B1 consumes only
  function source and produces local facts. Remove commands and schemas for
  `--cpg`, context sidecars, whole-file analysis, and Joern facts. Describe
  repository CPG retrieval as a future B3/B4 implementation, not as current
  functionality. Keep the unimplemented-stage roadmap.

- [x] **Step 4: Verify no obsolete references remain.**

  Run: `rg -n --hidden --glob '!\.git/**' "--cpg|analysis-scope|cpg_facts|context_facts|same_file_call_context|helper_call_context|JoernAdapter|b1_facts|context/" src scripts tests configs README.md AGENT.md`

  Expected: no production/test references to removed repository-context paths;
  only explicitly historical/future wording may remain after manual review.

### Task 4: Full verification and handoff

**Files:**
- Modify: `AGENT.md` if test/status details changed

- [x] **Step 1: Run the complete test suite.**

  Run: `python -m pytest -q`

  Expected: exit code 0 and zero failures.

- [x] **Step 2: Run compilation and import checks.**

  Run: `python -m compileall -q src`

  Expected: exit code 0 and no syntax errors.

- [x] **Step 3: Inspect the final diff and status.**

  Run: `git diff --check; git status --short; git diff --stat`

  Expected: no whitespace errors; only the approved context-removal files
  are changed or deleted.
