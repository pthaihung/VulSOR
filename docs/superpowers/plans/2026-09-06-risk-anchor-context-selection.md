# Risk-Anchor Context Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the full-function relation dump with a source-grounded context slice around at most two risk anchors.

**Architecture:** Joern identifies pointer-cast dereference anchors and returns only their nearby data, control, declaration, macro-contract, and call facts. Python renders those facts in five bounded sections and persists one JSONL record; runtime remains JSONL-only.

**Tech Stack:** Python, Pydantic, pytest, Joern Scala scripts, JSONL.

---

### Task 1: Render hierarchical anchor context

**Files:**
- Modify: `src/vulsor/repository_context/prompt_context.py`
- Modify: `tests/repository_context/test_prompt_context.py`

- [ ] **Step 1: Write failing tests for anchors and contracts**

Add a fixture with these fields:

```python
{
    "anchor_status": "exact",
    "anchors": [{"code": "*(double *)p1", "file": "demo.c", "line": 42}],
    "data_dependencies": [{"anchor_line": 42, "code": "p1 = p", "file": "demo.c", "line": 31}],
    "control_dependencies": [{"anchor_line": 42, "code": "format == DOUBLE", "file": "demo.c", "line": 40}],
    "declarations_types": [{"code": "unsigned char *p1", "file": "demo.c", "line": 7}],
    "local_contracts": [{"code": "p1 = p;", "file": "demo.c", "line": 30}],
    "calls": [{"code": "read(p)", "callee": "read", "file": "demo.c", "line": 20}],
    "limitations": [],
    "truncated": False,
}
```

Assert the rendered headings are exactly `[DATA DEPENDENCIES]`, `[CONTROL DEPENDENCIES]`, `[DECLARATIONS, TYPES AND CONTRACTS]`, `[CALL RELATIONS]`. Anchors remain internal metadata used to retain facts for at most two source locations. Add cases for three anchors, 13 calls, and a 16-line local contract; verify the renderer uses 2 anchors internally, retains 12 calls and 15 contract lines, preserves source order, and records `context_truncated`.

- [ ] **Step 2: Verify RED**

Run: `pytest tests/repository_context/test_prompt_context.py -q -k anchor`

Expected: failure because relation sections do not yet use internal anchors and render local contracts.

- [ ] **Step 3: Implement fixed budgets and rendering**

Define and apply:

```python
MAX_ANCHORS = 2
MAX_DATA_FACTS_PER_ANCHOR = 8
MAX_CONTROL_FACTS_PER_ANCHOR = 10
MAX_DECLARATION_FACTS = 12
MAX_CALL_FACTS = 12
MAX_LOCAL_CONTRACT_LINES = 15
DEFAULT_MAX_CONTEXT_CHARACTERS = 8_000
```

Keep facts with a matching retained `anchor_line`; deduplicate by source location/code; preserve complete facts only; add `context_truncated` once whenever a family or character cap discards evidence.

- [ ] **Step 4: Verify GREEN and commit**

Run: `pytest tests/repository_context/test_prompt_context.py -q`

Expected: all tests pass.

```bash
git add src/vulsor/repository_context/prompt_context.py tests/repository_context/test_prompt_context.py
git commit -m "feat: render bounded risk-anchor context"
```

### Task 2: Extract source-backed anchor slices

**Files:**
- Modify: `scripts/joern/function_context.sc`
- Modify: `src/vulsor/repository_context/joern.py`
- Modify: `tests/repository_context/test_joern.py`

- [ ] **Step 1: Write failing raw-schema tests**

Extend the fake function-context payload with `anchors` and `local_contracts`. Assert the adapter rejects an anchor without nonblank `code`/`file`/positive `line`, and rejects a contract without source code/location.

- [ ] **Step 2: Verify RED**

Run: `pytest tests/repository_context/test_joern.py -q -k function_context`

Expected: failure because the adapter does not require the new fields.

- [ ] **Step 3: Validate the raw payload**

Extend `_validate_function_context_payload` to require arrays `anchors` and `local_contracts`; require source-grounded anchor and contract objects; retain empty data/control arrays only with explicit limitations.

- [ ] **Step 4: Replace function-wide extraction**

In `function_context.sc`, select at most two source-ordered `indirection(cast(pointer))` nodes. For each anchor, emit:

```text
anchor
≤8 backward data facts from its operand
≤10 guarding controls mentioning retained entities
declarations/types of anchor and retained entities
≤15 lines of macro-origin pointer contract when present
direct non-operator calls on the retained slice
```

Use `controlledBy` first; fall back to enclosing `ControlStructure` ancestors that mention a slice entity. If no anchor exists, output no calls and limitation `no_risk_anchor_found`; never fall back to all method calls.

- [ ] **Step 5: Verify GREEN and commit**

Run: `pytest tests/repository_context/test_joern.py -q`

Expected: all adapter tests pass.

```bash
git add scripts/joern/function_context.sc src/vulsor/repository_context/joern.py tests/repository_context/test_joern.py
git commit -m "feat: extract risk-anchor repository slices"
```

### Task 3: Enforce offline storage budget

**Files:**
- Modify: `src/vulsor/repository_context/service.py`
- Modify: `src/vulsor/repository_context/cli.py`
- Modify: `tests/repository_context/test_service.py`
- Modify: `tests/repository_context/test_repository_cli.py`
- Modify: `README.md`

- [ ] **Step 1: Write failing budget tests**

Assert `build_prompt_context` defaults to `8_000` characters. Assert `build-context` defaults `--max-characters` to `8000`, rejects values above `8000`, and has no public `--max-items` override. Keep the existing test proving `show-context` builds no Git/Joern/CPG dependency.

- [ ] **Step 2: Verify RED**

Run: `pytest tests/repository_context/test_service.py tests/repository_context/test_repository_cli.py -q -k context`

Expected: failure because the current default is 24,000 and the CLI exposes `--max-items`.

- [ ] **Step 3: Implement the budget boundary**

Set the service and CLI default to `8_000`; remove public `--max-items`; reject a requested character cap greater than `8_000`. Update README with `data/primevul_withcontext/context.jsonl` as the durable selected-evidence store and identify repo/CPG/raw outputs as offline temporary artifacts.

- [ ] **Step 4: Verify GREEN and commit**

Run: `pytest tests/repository_context/test_service.py tests/repository_context/test_repository_cli.py -q`

Expected: all tests pass.

```bash
git add src/vulsor/repository_context/service.py src/vulsor/repository_context/cli.py tests/repository_context/test_service.py tests/repository_context/test_repository_cli.py README.md
git commit -m "feat: cap risk-anchor context at two-thousand tokens"
```

### Task 4: Verify the exact sample

**Files:**
- Create outside Git tracking: `build/test_194963-context.jsonl`

- [ ] **Step 1: Run the complete subsystem suite**

Run: `pytest tests/repository_context -q`

Expected: all tests pass.

- [ ] **Step 2: Re-run Joern on the existing exact-revision CPG**

Run `function_context.sc` against `build/test_194963.cpg.bin`, `magick/property.c`, and `GetEXIFProperty` using JDK 21. Render the raw payload to `build/test_194963-context.jsonl`.

Expected: two `float`/`double` pointer-cast dereference anchors, lineage through `p1`/`p`/`q`/`dir_offset`/`format`, relevant guards, and macro contract; no `<operator` or full-function call dump.

- [ ] **Step 3: Verify output constraints**

Assert all five headings exist; context is at most 8,000 characters; every fact has source location; unavailable relations are limitations rather than inferred evidence.

- [ ] **Step 4: Final verification**

Run: `pytest tests/repository_context -q` and `git diff --check`.

Expected: tests pass and no whitespace errors. Leave `build/` and `workspace/` artifacts untracked for inspection; delete them only on explicit user direction.

## Self-review

- Tasks cover risk-anchor selection, data/control/type/macro/call context, the 2,000-token hard cap, JSONL-only runtime, tests, and the real sample.
- Scope excludes batch preprocessing and runtime graph queries.
- All payload names used by rendering are introduced by extractor validation.
