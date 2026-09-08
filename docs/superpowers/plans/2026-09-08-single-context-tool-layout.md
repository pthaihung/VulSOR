# Single Context Tool Layout Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the repository expose one standalone file-context builder at `context_tool/context_tool.py`, while retaining the main application under `src/` and datasets under `data/`.

**Architecture:** The new context flow is a single executable Python module. It owns PrimeVul metadata resolution, source retrieval, one-file Joern CPG construction, relation selection, 2,000-token validation, progress reporting, and atomic JSONL output. The old `input_context`, `repo_context`, `scripts/context_tool.py`, and standalone context config/script paths are removed from the active code path.

**Tech Stack:** Python 3.10+, argparse, pydantic, PyYAML, Joern, pytest.

---

### Task 1: Lock the new public layout with boundary tests

**Files:**
- Create: `tests/test_context_tool_layout.py`
- Modify: `tests/test_context_tool.py`

- [ ] **Step 1: Write tests for the new entrypoint and forbidden legacy imports**

Assert that `context_tool/context_tool.py` exists, accepts `build`, exposes the required PrimeVul arguments, and does not import `agents.input_context` or `agents.repo_context`.

- [ ] **Step 2: Run the focused tests and confirm they fail**

Run: `python -m pytest tests/test_context_tool_layout.py tests/test_context_tool.py -q`

Expected: failure because `context_tool/context_tool.py` does not exist yet.

### Task 2: Create the standalone context tool

**Files:**
- Create: `context_tool/context_tool.py`
- Create: `context_tool/__init__.py`
- Modify: `tests/test_context_tool_layout.py`

- [ ] **Step 1: Move the file-level context implementation behind the standalone module**

Implement the existing behavior in one module: source resolution through `func_hash`/`file_info.json`, file-scoped CPG caching, Joern process boundary, relation selection, sparse context validation, 2,000-token hard limit, atomic JSONL writing, and progress output.

- [ ] **Step 2: Run the focused tests and confirm they pass**

Run: `python -m pytest tests/test_context_tool_layout.py tests/test_context_tool.py -q`

Expected: all focused tests pass.

### Task 3: Remove the old context implementation from the active tree

**Files:**
- Delete: `scripts/context_tool.py`
- Delete: `scripts/joern/file_context.sc`
- Delete: `config/primevul.yaml`
- Delete: `src/agents/input_context/`
- Delete: `src/agents/repo_context/`
- Modify: `.gitignore`

- [ ] **Step 1: Update defaults and Joern script location**

The standalone tool must use its own embedded/default configuration and create any temporary Joern transport script at runtime, so no context implementation remains outside `context_tool/`.

- [ ] **Step 2: Run the full preserved context suite**

Run: `python -m pytest tests -q -m "not joern"`

Expected: preserved function-level tests and new layout tests pass; tests that specifically assert removed legacy modules are deleted or rewritten to target the standalone tool.

### Task 4: Update reproducibility documentation and verify the repository

**Files:**
- Modify: `README.md`
- Modify: `AGENT.md`
- Modify: `pyproject.toml` only if package discovery or script entrypoints require it

- [ ] **Step 1: Document the only supported context command**

Use:

```powershell
python context_tool\context_tool.py build `
  --pairs data\primevul\primevul_test_pairs.jsonl `
  --file-info data\primevul\file_info.json `
  --dataset-root data\primevul `
  --output data\primevul\primevul_withcontext.jsonl
```

- [ ] **Step 2: Verify the final boundaries**

Run the new help commands, the non-Joern test suite, and `git diff --check`. Expected: only the new standalone context tool is documented and callable, tests pass, and the diff has no whitespace errors.

- [ ] **Step 3: Commit the structural change**

```powershell
git add context_tool tests README.md AGENT.md .gitignore pyproject.toml
git commit -m "refactor: consolidate context builder"
```
