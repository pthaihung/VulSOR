# Context Tool Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Provide a small `scripts/context_tool.py` entry point for building the existing offline PrimeVul file context.

**Architecture:** The script bootstraps the repository `src` directory, then delegates to the existing `vulsor.cli` `file-context build` handler. It does not duplicate Joern extraction, fallback, selection, validation, or token-budget logic. A focused test verifies argument forwarding and source-path bootstrapping without starting Joern.

**Tech Stack:** Python 3.10+, `argparse` from the existing CLI, pytest.

---

### Task 1: Add the wrapper entry point

**Files:**
- Create: `scripts/context_tool.py`
- Test: `tests/test_context_tool.py`

- [ ] Write a failing test that imports the wrapper with a temporary `src` path and verifies `main(["build", ...])` delegates to `vulsor.cli.main` as `["file-context", "build", ...]`.
- [ ] Run the focused test and confirm it fails because `scripts/context_tool.py` does not exist.
- [ ] Implement a `main(argv=None)` wrapper that inserts `<repo>/src` into `sys.path`, prepends `file-context build`, and returns the existing CLI status.
- [ ] Add a `__main__` block that exits with the returned status.
- [ ] Run the focused test and `python scripts/context_tool.py --help`.

### Task 2: Verify the packaged command

**Files:**
- No additional production files.

- [ ] Run the repository-context test suite.
- [ ] Run a two-sample or ten-sample command with the existing Joern/JDK environment and verify the output/report are produced by the existing service.
- [ ] Run `git diff --check`.
