# PrimeVul File Context Remaining Logic Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Finish the file-level PrimeVul pipeline so one offline command resolves each target file, extracts source-grounded Joern facts, deterministically selects useful context, and writes complete sparse context objects bounded to 2,000 estimated tokens.

**Architecture:** Joern emits uncapped source-grounded facts for exactly one method selected by `[start_line, end_line]`; it does not decide the LLM budget. Python validates those facts, builds relation-aware slices, ranks and caps whole evidence items, then either accepts the complete serialized context or stores `{}`. A streaming coordinator preserves raw target records, but publishes the output JSONL atomically only after the invocation completes.

**Tech Stack:** Python 3.10+, Scala/Joern 4.0.592, JSON/JSONL, pytest, PowerShell.

---

## Locked file responsibilities

- `scripts/joern/file_context.sc`: select one method by source span and export raw source-grounded facts.
- `src/vulsor/repository_context/joern.py`: safely execute the file-context script and validate its transport schema.
- `src/vulsor/repository_context/file_cpg.py`: cache one CPG per source digest and validate exact-target payloads.
- `src/vulsor/repository_context/file_context_selection.py`: build, rank, deduplicate, and cap the eight context families.
- `src/vulsor/repository_context/file_prompt_context.py`: clean sparse values and enforce the all-or-nothing 2,000-token limit.
- `src/vulsor/repository_context/file_context_service.py`: join PrimeVul records with locators and orchestrate every offline stage.
- `src/vulsor/repository_context/cli.py`: expose `file-context build` and print a sanitized summary.

### Task 1: Exact method selection and Joern transport

**Files:**
- Create: `scripts/joern/file_context.sc`
- Modify: `src/vulsor/repository_context/joern.py`
- Modify: `src/vulsor/repository_context/file_cpg.py`
- Modify: `tests/repository_context/test_file_cpg.py`
- Modify: `tests/repository_context/test_joern.py`

- [ ] **Step 1: Write failing adapter tests**

Add tests proving that `extract_file_context()` sends only `cpgFile`, `sourceFile`, `startLine`, `endLine`, and `outFile`; rejects non-positive/inverted ranges; and rejects `not_found`, `ambiguous`, malformed arrays, blank code, or invalid source lines.

```python
payload = adapter.extract_file_context(cpg, source_file=source, start_line=8, end_line=14)
assert payload["target_status"] == "exact"
assert observed_params["startLine"] == "8"
assert observed_params["endLine"] == "14"
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/repository_context/test_joern.py tests/repository_context/test_file_cpg.py -q`

Expected: FAIL because `JoernAdapter.extract_file_context` and the script do not exist.

- [ ] **Step 3: Implement the safe adapter boundary**

Add `file_context_script` to `JoernAdapter.__init__` and implement:

```python
def extract_file_context(
    self, cpg_path: Path, *, source_file: Path, start_line: int, end_line: int
) -> dict[str, object]:
    # validate regular files and 1 <= start_line <= end_line
    # execute file_context.sc through _script_command
    # read only the explicit temporary JSON output
    # always clean the temporary output/workspace
```

Use the existing `_run`, `_read_json_object`, `_finish_cleanup`, and diagnostic redaction helpers. Pass scalar parameters directly; do not write source text into transport files or logs.

- [ ] **Step 4: Implement exact range selection in Scala**

The script normalizes slashes and selects methods satisfying all conditions:

```scala
method.filename.replace('\\', '/').endsWith(normalizedSourceFile) &&
method.lineNumber.exists(_ <= startLine) &&
method.lineNumberEnd.exists(_ >= endLine)
```

Emit `target_status = "exact"` only when exactly one method matches. For zero or multiple matches, emit the status plus eight empty arrays; Python treats either status as unavailable.

- [ ] **Step 5: Export raw facts without budget truncation**

Each exported item must contain nonblank `code`, normalized `file`, and positive `line`. Emit:

- `imports`: `#include` lines read from the staged source file;
- `callee_funcs`: direct call names that resolve to one method in the same staged file, with method signature/location;
- `call_relations`: non-operator calls in the target, with caller/callee/location;
- `call_site_arguments`: one item per direct argument with call name, argument index/code/location;
- `data_flow`: Joern reaching-definition/DDG edges when available, plus explicitly labelled `syntactic_assignment` facts when the overlay has no edge;
- `control_dependencies`: controlling `if/switch/loop` conditions and the controlled call/assignment line;
- `declarations`: target parameters and locals with name/type/code/location;
- `types`: unique nonblank `typeFullName` values referenced by retained declarations, arguments, and calls.

Never emit a vulnerability label, CVE, CWE, dataset target, or inferred verdict.

- [ ] **Step 6: Run a real Joern smoke fixture**

Create a temporary C fixture with one target, one bounds check, one assignment, and one same-file callee. Run with `E:\tools\joern-v4.0.592\joern-cli\joern-parse.bat` and `joern.bat`; assert exact status and at least one call, declaration, and control item. Keep the fixture in the test temp directory only.

- [ ] **Step 7: Verify and commit**

Run: `python -m pytest tests/repository_context/test_joern.py tests/repository_context/test_file_cpg.py -q`

Commit: `git commit -m "feat: extract source-grounded file context facts"`

### Task 2: Relation-aware selection and deterministic family caps

**Files:**
- Create: `src/vulsor/repository_context/file_context_selection.py`
- Create: `tests/repository_context/test_file_context_selection.py`
- Modify: `src/vulsor/repository_context/file_prompt_context.py`
- Modify: `tests/repository_context/test_file_prompt_context.py`

- [ ] **Step 1: Write failing selection tests**

Use a fixture containing relevant and irrelevant variables. Assert that a memory/index/copy call seeds `size`, `offset`, pointer and call-result variables; backwards data dependencies retain their parameters/assignments; guards retain only conditions sharing a retained variable; declarations/types follow retained variables; and unrelated calls disappear.

```python
context = select_file_context(raw_facts)
assert {item["name"] for item in context["declarations"]} == {"buf", "size", "offset"}
assert all("debug" not in item["code"] for item in context.get("call_relations", []))
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/repository_context/test_file_context_selection.py -q`

Expected: FAIL because `file_context_selection` does not exist.

- [ ] **Step 3: Implement seed discovery**

Seed variables come from source-grounded operations in the target function, with descending priority:

1. memory/string/allocation/read/parse calls;
2. pointer dereference and array indexing;
3. arithmetic using names containing `size`, `len`, `count`, `offset`, `index`, `bytes`, `capacity`;
4. target return values and direct call results.

When no high-priority operation exists, seed all target call arguments and return identifiers instead of returning empty context.

- [ ] **Step 4: Implement bounded relation closure**

Perform at most three backwards rounds over `data_flow`: if an edge defines a retained variable, retain its used variables and source item. Then retain controls intersecting the variable set, declarations/types for retained variables, calls producing/checking/consuming them, and same-file callees reached by those calls. Do not cross into another file.

- [ ] **Step 5: Deduplicate, rank, and cap whole items**

Use stable keys `(family, normalized_file, line, canonical_json)` and order by semantic priority, then line, then canonical JSON. Apply these pre-serialization caps:

```python
FAMILY_LIMITS = {
    "imports": 12,
    "callee_funcs": 6,
    "call_relations": 16,
    "call_site_arguments": 24,
    "data_flow": 32,
    "control_dependencies": 16,
    "declarations": 24,
    "types": 24,
}
```

Caps select complete items only. `validate_complete_context()` then serializes the resulting complete sparse object once; if the estimate exceeds 2,000 tokens, raise `FileContextBudgetError` and write no partial family.

- [ ] **Step 6: Verify and commit**

Run: `python -m pytest tests/repository_context/test_file_context_selection.py tests/repository_context/test_file_prompt_context.py -q`

Commit: `git commit -m "feat: select bounded file context relations"`

### Task 3: PrimeVul join and per-record state machine

**Files:**
- Create: `src/vulsor/repository_context/file_context_service.py`
- Create: `tests/repository_context/test_file_context_service.py`
- Modify: `src/vulsor/repository_context/primevul_import.py`

- [ ] **Step 1: Expose the tested locator lookup**

Promote the existing scientific-notation matching into:

```python
class PrimeVulLocatorIndex:
    @classmethod
    def load(cls, path: Path) -> "PrimeVulLocatorIndex": ...
    def lookup(self, func_hash: object) -> Mapping[str, object] | None: ...
```

Preserve the rule that a float is accepted only when it maps to exactly one integer key.

- [ ] **Step 2: Write failing service tests**

Test all terminal states: `built`, `locator_missing`, `source_unavailable`, `target_not_found`, `target_ambiguous`, `joern_failed`, and `oversized`. Verify every output is a copy of the raw `target: 1` record with exactly one added/replaced `context` field, and every non-built state has `context == {}`.

- [ ] **Step 3: Implement one-record processing**

Implement an injected service boundary:

```python
result = service.process(raw_record, locator_index)
assert result.record["context"] == validated_context_or_empty_dict
assert result.status in {"built", "unavailable", "failed", "oversized"}
```

The state order is fixed: validate raw record → lookup locator → validate positive range → resolve source → build/reuse CPG → extract exact facts → select relations → validate complete budget → attach context. Catch typed boundary errors and store only a controlled reason code; never write paths, source text, HTTP bodies, or Joern diagnostics to the report.

- [ ] **Step 4: Implement streaming input and atomic publication**

Read JSONL using `utf-8-sig`, skip non-target paired records, stop after `limit` selected target records, preserve order, and write to a temporary sibling file. Replace the requested output only after EOF/limit completes. A process-level fatal error leaves the prior output untouched.

- [ ] **Step 5: Verify and commit**

Run: `python -m pytest tests/repository_context/test_primevul_import.py tests/repository_context/test_file_context_service.py -q`

Commit: `git commit -m "feat: orchestrate PrimeVul file context records"`

### Task 4: CLI, configuration, and progress reporting

**Files:**
- Modify: `src/vulsor/repository_context/cli.py`
- Modify: `configs/primevul.yaml`
- Modify: `tests/repository_context/test_repository_cli.py`

- [ ] **Step 1: Write failing parser and handler tests**

Assert this command parses independently of legacy `repo-context` actions:

```text
file-context build --config CONFIG --pairs PAIRS --file-info INFO
  --dataset-root ROOT --output OUTPUT --limit 10
```

Reject `limit < 1`, identical input/output paths, and output/report path collisions.

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/repository_context/test_repository_cli.py -q`

Expected: FAIL because top-level `file-context` is not registered.

- [ ] **Step 3: Add command construction**

Construct `PrimeVulFileSourceResolver`, `JoernAdapter`, `FileCpgCache`, and `FileContextService` from config. Default caches are:

```yaml
repository_context:
  file_cache_root: data/primevul/context/files
  file_cpg_cache_root: data/primevul/context/file-cpg
  file_context_report: data/primevul/context/file-context-report.json
```

Point Joern commands to configured `tools.joern` and `tools.joern-parse`; do not invoke Git.

- [ ] **Step 4: Emit progress and sanitized report**

Print one compact progress line after each selected sample (`processed/limit`, sample id, controlled status), then atomically write counts for `total`, `built`, `unavailable`, `failed`, and `oversized`. Assert the counts sum to `total`; no source code, absolute path, URL response, CVE/CWE, or dataset label enters the report.

- [ ] **Step 5: Verify and commit**

Run: `python -m pytest tests/repository_context/test_repository_cli.py tests/repository_context/test_file_context_service.py -q`

Commit: `git commit -m "feat: add PrimeVul file-context build command"`

### Task 5: Offline/runtime separation

**Files:**
- Create: `src/vulsor/repository_context/prebuilt_context.py`
- Create: `tests/repository_context/test_prebuilt_context.py`
- Modify: `src/vulsor/cli.py`
- Modify: `src/vulsor/agents/BaseAgent.py`
- Modify: `tests/test_cli.py`
- Modify: `README.md`

- [ ] **Step 1: Write a failing enriched-record loader test**

Verify `PrebuiltContextStore.load(enriched_jsonl)` indexes only `idx -> context`, rejects duplicate IDs/malformed context, performs no network/subprocess call, and maps `{}` to unavailable context without error. Keep `DatasetSample` unchanged as the existing `sample_id + code` label-leakage boundary.

- [ ] **Step 2: Add read-only context loading**

Add `--prebuilt-context PATH` to dataset `inspect` and `agent` workflows. During artifact creation, look up `test_<idx>` and store the sparse object under `sample["repository_context"]`; during `_llm_payload`, copy only that object into a separate `repository_context` field. Do not concatenate it into source text and do not expose PrimeVul labels/metadata. Do not import resolver, Joern, or CPG modules from agent code; it only reads the already stored object. Document that preprocessing is the only phase allowed to access GitHub and Joern.

- [ ] **Step 3: Verify and commit**

Run: `python -m pytest tests/repository_context/test_prebuilt_context.py tests/test_cli.py -q`

Commit: `git commit -m "feat: consume prebuilt PrimeVul context offline"`

### Task 6: Ten-sample real pilot and release gate

**Files:**
- Generate, do not commit: `data/primevul/primevul_test_pairs_context_pilot10.jsonl`
- Generate, do not commit: `data/primevul/context/file-context-pilot10-report.json`

- [ ] **Step 1: Run the pilot from the repository root**

```powershell
Set-Location D:\research\code\VulSOR
$env:PYTHONPATH = ".\.worktrees\repository-context\src"
$env:PATH = "E:\tools\joern-v4.0.592\joern-cli;E:\tools\jdk-21.0.12+1\jdk-21.0.12.1+1\bin;$env:PATH"
python -m vulsor.cli file-context build `
  --config ".\.worktrees\repository-context\configs\primevul.yaml" `
  --pairs ".\data\primevul\primevul_test_pairs.jsonl" `
  --file-info ".\data\primevul\file_info.json" `
  --dataset-root ".\data\primevul" `
  --output ".\data\primevul\primevul_test_pairs_context_pilot10.jsonl" `
  --report ".\data\primevul\context\file-context-pilot10-report.json" `
  --limit 10
```

- [ ] **Step 2: Validate pilot invariants**

Run a read-only validator asserting: exactly ten selected target records; original fields unchanged; each context is `{}` or has only the eight approved families; each nonempty context is at most 2,000 estimated tokens; all locations are positive and source-grounded; report counts sum to ten.

- [ ] **Step 3: Manually inspect representative outcomes**

Inspect one built sample with data/control/call facts, one fallback-seed sample if present, and one unavailable sample. Fail the release gate if context contains unrelated debug/log calls, another file, label leakage, an incomplete relation item, or an oversized object.

- [ ] **Step 4: Run full verification**

```powershell
python -m pytest tests/repository_context tests/test_datasets.py -q
git diff --check
git status --short
```

Expected: all tests pass; only the pre-existing untracked user plan may remain; pilot/cache artifacts remain ignored and uncommitted.

- [ ] **Step 5: Record pilot results**

If built coverage is low, classify controlled reasons before changing extraction logic. Do not run the full dataset until the ten-record pilot passes every invariant and the sampled contexts are judged relevant.

## Self-review

- Spec coverage: exact range, eight families, source-only download, source-digest CPG, sparse output, 2,000-token rejection, atomic output, sanitized report, runtime-only consumption, and pilot gate each map to a task.
- No repository clone or Git invocation exists in this plan.
- Joern exports facts; deterministic Python code owns semantic selection and budgets.
- Missing DDG/CDG capability degrades to explicitly labelled source-grounded facts, never invented edges.
- Empty/ambiguous/oversized outcomes all produce `{}` rather than partial context.
- Type and method names are consistent across Tasks 1–6.
