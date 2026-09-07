# Repository Context Relation Selection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce compact four-section repository context by selecting source-grounded data, control, declaration/type/contract, and call relations rooted at an exact PrimeVul sample function.

**Architecture:** Joern emits a bounded candidate pool and internal seeds from the exact revision CPG. A new pure-Python selector performs entity closure, fallback selection, role-based filtering, deterministic deduplication, and family budgets before the existing renderer writes JSONL.

**Tech Stack:** Python 3.11, Pydantic, pytest, Scala 3 Joern scripts, Joern 4.0.592, JSONL.

---

### Task 1: Add deterministic relation selection

**Files:**
- Create: `src/vulsor/repository_context/relation_selection.py`
- Create: `tests/repository_context/test_relation_selection.py`

- [ ] **Step 1: Write failing tests for entity closure and fallback**

Create candidate fixtures containing `p1 = p`, `p = q + 8`, `p = exif + dir_offset`, `dir_offset = read(q + 8)`, and unrelated assignments. Assert the selector retains the transitive chain and excludes unrelated facts. Add a no-seed fixture and assert parameters, returns, and sensitive calls become fallback seeds.

- [ ] **Step 2: Verify RED**

Run: `pytest tests/repository_context/test_relation_selection.py -q`

Expected: collection fails because `relation_selection` does not exist.

- [ ] **Step 3: Implement the selector models and closure**

Implement:

```python
def select_repository_relations(raw: Mapping[str, object]) -> dict[str, object]:
    candidates = validate_candidate_payload(raw)
    seeds, fallback_used = choose_seeds(candidates)
    entities = close_data_entities(seeds, candidates.data, max_depth=6)
    return select_families(candidates, seeds, entities, fallback_used)
```

Identifiers come from explicit `defines` and `uses` arrays emitted by Joern, never from substring matching. Prefer `cpg_dataflow`; permit `syntactic_assignment_fallback` with an explicit limitation.

- [ ] **Step 4: Add control, declaration, contract, and call tests**

Assert controls must govern a retained node or share a retained entity; rank null/bounds/overflow/dispatch/loop roles before other guards. Assert declarations close over retained entities, macro calls represented as contracts are excluded from calls, and duplicate facts merge by family/file/line/code/role/provenance.

- [ ] **Step 5: Verify GREEN and commit**

Run: `pytest tests/repository_context/test_relation_selection.py -q`

Commit:

```powershell
git add src/vulsor/repository_context/relation_selection.py tests/repository_context/test_relation_selection.py
git commit -m "feat: select repository relation candidates"
```

### Task 2: Emit bounded Joern candidates

**Files:**
- Modify: `scripts/joern/function_context.sc`
- Modify: `src/vulsor/repository_context/joern.py`
- Modify: `tests/repository_context/test_joern.py`

- [ ] **Step 1: Write failing adapter schema tests**

Require arrays `seeds`, `data_candidates`, `control_candidates`, `declaration_candidates`, `contract_candidates`, and `call_candidates`. Require each candidate to have nonblank `code`/`file`, positive `line`, `provenance`, and string arrays `defines`/`uses` where applicable.

- [ ] **Step 2: Verify RED**

Run: `pytest tests/repository_context/test_joern.py -q -k function_context`

Expected: candidate payload validation fails because the adapter still requires the old selected arrays.

- [ ] **Step 3: Replace function-wide selected output with candidate output**

Joern must emit:

```json
{
  "target_status": "exact",
  "seeds": [],
  "data_candidates": [],
  "control_candidates": [],
  "declaration_candidates": [],
  "contract_candidates": [],
  "call_candidates": [],
  "limitations": [],
  "truncated": false
}
```

For data candidates, emit assignments, parameters, returns, and call results with `defines`, `uses`, and provenance. Use OSS data-flow paths where available; retain source-level assignments as fallback candidates. Emit compact control conditions with classified roles. Emit direct callers/callees at depth one. Keep macro definitions in `contract_candidates` and mark corresponding macro names so the selector can remove them from calls.

- [ ] **Step 4: Compile against the real CPG**

Run `function_context.sc` with JDK 21 against `build/test_194963.cpg.bin`. Expected: exit code 0 and a schema-valid candidate payload.

- [ ] **Step 5: Verify tests and commit**

Run: `pytest tests/repository_context/test_joern.py -q`

Commit:

```powershell
git add scripts/joern/function_context.sc src/vulsor/repository_context/joern.py tests/repository_context/test_joern.py
git commit -m "feat: emit repository relation candidates"
```

### Task 3: Integrate selection before rendering

**Files:**
- Modify: `src/vulsor/repository_context/service.py`
- Modify: `src/vulsor/repository_context/prompt_context.py`
- Modify: `tests/repository_context/test_service.py`
- Modify: `tests/repository_context/test_prompt_context.py`

- [ ] **Step 1: Write failing service tests**

Assert `build_prompt_context` calls `select_repository_relations` on Joern output and passes only selected families to the renderer. Assert fallback limitations survive into the JSONL record.

- [ ] **Step 2: Verify RED**

Run: `pytest tests/repository_context/test_service.py tests/repository_context/test_prompt_context.py -q`

Expected: the service sends raw candidates directly to the renderer.

- [ ] **Step 3: Implement integration and remove anchor-specific rendering**

Call:

```python
selected = select_repository_relations(raw)
return render_prompt_context(sample_id, selected, max_characters=max_characters)
```

Render exactly the four approved sections. Apply total family budgets after selection and preserve complete facts only.

- [ ] **Step 4: Verify GREEN and commit**

Run: `pytest tests/repository_context/test_service.py tests/repository_context/test_prompt_context.py -q`

Commit:

```powershell
git add src/vulsor/repository_context/service.py src/vulsor/repository_context/prompt_context.py tests/repository_context/test_service.py tests/repository_context/test_prompt_context.py
git commit -m "feat: integrate selected repository context"
```

### Task 4: Meet the real-sample acceptance criteria

**Files:**
- Generate outside Git tracking: `build/test_194963-context-raw.json`
- Generate outside Git tracking: `build/test_194963-context.jsonl`

- [ ] **Step 1: Run Joern and selection for `test_194963`**

Expected data entities include `p1`, `p`, `q`, `dir_offset`, `number_bytes`, `components`, and `format`.

- [ ] **Step 2: Assert relevant guards and contracts**

Require bounds/overflow checks for `dir_offset`, `number_bytes`, and `p`; require the `EXIFMultipleValues` contract; reject unrelated property-name and allocation repetitions.

- [ ] **Step 3: Assert output constraints**

Require exactly four headings, no anchor heading, no macro invocation in call relations when represented as a contract, complete source locations, and at most 8,000 characters.

- [ ] **Step 4: Run subsystem verification and commit fixes**

Run: `pytest tests/repository_context -q` and `git diff --check`.

### Task 5: Add and run representative-sample verification

**Files:**
- Create: `scripts/verify_repository_context_samples.py`
- Create: `tests/repository_context/test_verify_samples.py`
- Generate outside Git tracking: `build/repository-context-verification.json`

- [ ] **Step 1: Test deterministic sample-category reporting**

The report must record sample id, repository, revision, category, context size, family counts, limitations, and success/failure without storing repository source.

- [ ] **Step 2: Implement the verifier**

Accept 10–20 explicit sample IDs and run the existing offline build path one sample at a time. Stop before batch preprocessing. Persist only the compact verification report and generated JSONL contexts.

- [ ] **Step 3: Select and run 10–20 available PrimeVul samples**

Cover pointer/index, size/offset, memory API, macro, caller/callee, no-risk-seed, and incomplete-flow cases when metadata permits. Missing repositories or revisions count as controlled unavailable outcomes, not successful context cases.

- [ ] **Step 4: Review failures and rerun**

Fix selection defects exposed by the representative set, rerun affected unit tests, then rerun the complete set.

- [ ] **Step 5: Final verification and commit**

Run: `pytest tests/repository_context -q` and `git diff --check`.

Commit:

```powershell
git add scripts/verify_repository_context_samples.py tests/repository_context/test_verify_samples.py
git commit -m "test: verify representative repository contexts"
```

## Self-review

- Every design requirement maps to a task.
- Candidate and selected payload field names remain consistent across Joern, adapter, selector, service, and renderer.
- Runtime remains JSONL-only.
- The real sample and representative-set gates occur before batch preprocessing.
- Interprocedural traversal is explicitly limited to one direct hop.
