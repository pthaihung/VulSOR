# Single-Sample Prompt Context Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify one offline, prompt-ready repository-context record for PrimeVul sample `test_194963`.

**Architecture:** Reuse the existing repository resolver, source matcher, CPG cache, and Joern process boundary. Add a function-anchored Joern extraction, normalize it into a small typed payload, render four deterministic paper-aligned sections, and persist one JSONL record that runtime can load without Git or Joern.

**Tech Stack:** Python 3.11+, Pydantic 2, Joern 4.0.592/Scala, pytest, JSONL, existing VulSOR CLI/configuration.

---

### Task 1: Define and render the compact context record

**Files:**
- Create: `src/vulsor/repository_context/prompt_context.py`
- Create: `tests/repository_context/test_prompt_context.py`

- [ ] **Step 1: Write failing model and renderer tests**

Create tests that construct this normalized extraction payload:

```python
RAW = {
    "anchor_status": "exact",
    "calls": [
        {
            "code": "GetImageProfile(image, \"exif\")",
            "callee": "GetImageProfile",
            "arguments": ["image", "\"exif\""],
            "file": "magick/property.c",
            "line": 101,
        }
    ],
    "data_dependencies": [],
    "control_dependencies": [],
    "declarations_types": [
        {
            "code": "const Image *image",
            "name": "image",
            "type": "const Image *",
            "file": "magick/property.c",
            "line": 1,
        }
    ],
    "limitations": ["data_dependencies: no mapped evidence was found"],
    "truncated": False,
}
```

Assert that `render_prompt_context("test_194963", RAW, max_characters=4000)` returns a frozen `PromptContextRecord`, contains each heading exactly once in this order, includes source locations, retains the empty data section, and preserves the limitation. Add tests that duplicate input items are removed, character truncation is deterministic, and an anchor status other than `exact` raises `PromptContextError`.

- [ ] **Step 2: Run tests and verify failure**

Run: `pytest tests/repository_context/test_prompt_context.py -q`

Expected: collection fails because `vulsor.repository_context.prompt_context` does not exist.

- [ ] **Step 3: Implement the record, validator, renderer, and JSONL store**

Implement these public contracts in `prompt_context.py`:

```python
class PromptContextError(RuntimeError): ...

class PromptContextRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    sample_id: str = Field(min_length=1)
    context: str = Field(min_length=1)
    limitations: tuple[str, ...] = ()

def render_prompt_context(
    sample_id: str,
    raw: Mapping[str, object],
    *,
    max_characters: int = 24_000,
) -> PromptContextRecord: ...

def upsert_prompt_context(path: Path, record: PromptContextRecord) -> None: ...

def load_prompt_context(path: Path, sample_id: str) -> PromptContextRecord | None: ...
```

Use the fixed headings `[CALL RELATIONS]`, `[DATA DEPENDENCIES]`, `[CONTROL DEPENDENCIES]`, and `[DECLARATIONS AND TYPES]`. Sort entries by normalized file, line, and rendered text; deduplicate identical entries; render missing families as `- No mapped evidence found.`; truncate only at item boundaries; add `context_truncated` once when the character budget is exceeded. Write JSONL atomically with `_atomic_write_text`, preserving valid records for other sample IDs and replacing the selected sample.

- [ ] **Step 4: Add JSONL isolation tests**

Assert that upserting `test_194963` twice leaves one record for that ID, preserves an unrelated record, and that `load_prompt_context` returns `None` for a missing ID without creating files.

- [ ] **Step 5: Run tests and commit**

Run: `pytest tests/repository_context/test_prompt_context.py -q`

Expected: all tests pass.

Commit:

```bash
git add src/vulsor/repository_context/prompt_context.py tests/repository_context/test_prompt_context.py
git commit -m "feat: add prompt-ready repository context"
```

### Task 2: Extract the four evidence families from one target function

**Files:**
- Create: `scripts/joern/function_context.sc`
- Modify: `src/vulsor/repository_context/joern.py`
- Modify: `tests/repository_context/test_joern.py`

- [ ] **Step 1: Write a failing adapter transport test**

Add a fake-runner test for:

```python
payload = adapter.extract_function_context(
    cpg,
    file_path="magick/property.c",
    function_name="GetEXIFProperty",
    max_items=120,
)
```

Assert that the adapter writes a temporary request object containing exactly `file_path`, `function_name`, and `max_items`; invokes the configured function-context script with `cpgFile`, `requestFile`, and `outFile`; reads only `outFile`; validates all four arrays and `anchor_status`; and removes transport files.

- [ ] **Step 2: Run the focused test and verify failure**

Run: `pytest tests/repository_context/test_joern.py -q -k function_context`

Expected: failure because `extract_function_context` is absent.

- [ ] **Step 3: Add the Joern adapter method**

Extend `JoernAdapter.__init__` with an optional `function_context_script`, defaulting through `_default_script("function_context.sc")`. Implement:

```python
def extract_function_context(
    self,
    cpg_path: Path,
    *,
    file_path: str,
    function_name: str,
    max_items: int = 120,
) -> dict[str, object]: ...
```

Follow the existing `query()` request-file boundary and cleanup behavior. Reject blank paths/names and `max_items` outside `1..1000`. Require the returned object to have `anchor_status` in `exact|not_found|ambiguous`, arrays named `calls`, `data_dependencies`, `control_dependencies`, `declarations_types`, `limitations`, and a boolean `truncated`.

- [ ] **Step 4: Implement the function-anchored Joern script**

In `function_context.sc`, resolve methods by exact function name plus normalized file suffix and stop unless exactly one method matches. Emit source-level JSON objects only:

```scala
Obj(
  "anchor_status" -> Str("exact"),
  "calls" -> calls,
  "data_dependencies" -> dataDependencies,
  "control_dependencies" -> controlDependencies,
  "declarations_types" -> declarationsTypes,
  "limitations" -> limitations,
  "truncated" -> Bool(truncated)
)
```

For calls, emit call code/name/methodFullName, ordered argument code, filename, and line. For declarations/types, emit parameters and locals with code/name/typeFullName/location. For control dependencies, emit each call/return with its distinct `controlledBy` condition. Ensure `ossdataflow` exists, then emit bounded `reachableByFlows` paths from method parameters and identifiers to calls and returns; each path contains source-level code/file/line nodes. Apply `max_items` independently per family, deduplicate by stable source keys, and append a family-specific limitation when Joern yields nothing or throws a non-fatal query error.

- [ ] **Step 5: Run adapter tests and commit**

Run: `pytest tests/repository_context/test_joern.py -q`

Expected: all Joern boundary tests pass without requiring a real Joern process.

Commit:

```bash
git add scripts/joern/function_context.sc src/vulsor/repository_context/joern.py tests/repository_context/test_joern.py
git commit -m "feat: extract function repository context"
```

### Task 3: Build the context entirely during preprocessing

**Files:**
- Modify: `src/vulsor/repository_context/service.py`
- Create: `tests/repository_context/test_offline_context.py`

- [ ] **Step 1: Write the failing offline builder test**

Create fakes for the index, resolver, cache, and Joern adapter. Assert that:

```python
record = preprocessor.build_prompt_context(
    "s1", "int target(int value) { return helper(value); }"
)
```

first performs the same revision/source checks as `preprocess_sample`, obtains a ready CPG, calls `extract_function_context` once with the indexed file/function, and returns a rendered `PromptContextRecord`. Add cases for a non-exact anchor and Joern failure, both converted to `RepositoryPreparationError` without fabricated context.

- [ ] **Step 2: Run the test and verify failure**

Run: `pytest tests/repository_context/test_offline_context.py -q`

Expected: failure because `build_prompt_context` is absent.

- [ ] **Step 3: Refactor preparation without changing existing behavior**

Extract the shared revision, source-match, CPG-build, and smoke logic from `preprocess_sample` into a private method returning `(record, resolved, match, artifact)`. Keep `preprocess_sample` output and existing tests unchanged.

- [ ] **Step 4: Implement `build_prompt_context`**

Add:

```python
def build_prompt_context(
    self,
    sample_id: str,
    sample_code: str,
    *,
    max_items: int = 120,
    max_characters: int = 24_000,
) -> PromptContextRecord: ...
```

Call the new Joern extraction only after exact repository/source preparation, then call `render_prompt_context`. Convert Joern and rendering errors to controlled `RepositoryPreparationError` kinds `joern_unavailable` and `context_unavailable`.

- [ ] **Step 5: Run service tests and commit**

Run: `pytest tests/repository_context/test_service.py tests/repository_context/test_offline_context.py -q`

Expected: all tests pass.

Commit:

```bash
git add src/vulsor/repository_context/service.py tests/repository_context/test_offline_context.py
git commit -m "feat: build context during offline preparation"
```

### Task 4: Expose one-sample build and read-only retrieval commands

**Files:**
- Modify: `src/vulsor/repository_context/cli.py`
- Modify: `tests/repository_context/test_repository_cli.py`
- Modify: `README.md`

- [ ] **Step 1: Write failing CLI tests**

Add parser and handler tests for:

```text
vulsor repo-context build-context --config CONFIG --dataset primevul \
  --split test --sample test_194963 --output context.jsonl

vulsor repo-context show-context --sample test_194963 --input context.jsonl
```

Assert `build-context` has no `--all` option, invokes `build_prompt_context`, and atomically upserts its record. Assert `show-context` constructs neither `GitRepositoryResolver`, `CpgCache`, nor `JoernAdapter`; it prints the stored record, and prints an empty context result for a missing sample.

- [ ] **Step 2: Run CLI tests and verify failure**

Run: `pytest tests/repository_context/test_repository_cli.py -q -k context`

Expected: parser rejects the new actions.

- [ ] **Step 3: Implement both CLI actions**

Add explicit `build-context` arguments `--config`, `--dataset`, `--split`, `--sample`, `--output`, `--max-items` (default 120), and `--max-characters` (default 24000). Load only the selected dataset sample and index record, construct offline dependencies, build, then upsert. Add `show-context` with only `--sample` and `--input`; load and print the record, or print `{"sample_id": ID, "context": "", "limitations": ["repository_context_unavailable"]}` when absent.

- [ ] **Step 4: Document the hard phase boundary**

In `README.md`, document one offline command and one runtime read command. State explicitly that `build-context` may use Git/Joern, while `show-context` and model execution consume only JSONL.

- [ ] **Step 5: Run CLI tests and commit**

Run: `pytest tests/repository_context/test_repository_cli.py -q`

Expected: all CLI tests pass.

Commit:

```bash
git add src/vulsor/repository_context/cli.py tests/repository_context/test_repository_cli.py README.md
git commit -m "feat: add offline context build command"
```

### Task 5: Run the complete automated verification

**Files:**
- Modify only if a test reveals a defect in files from Tasks 1-4.

- [ ] **Step 1: Run repository-context tests**

Run: `pytest tests/repository_context -q`

Expected: all tests pass.

- [ ] **Step 2: Run the full test suite**

Run: `pytest -q`

Expected: all tests pass, with only previously documented skips.

- [ ] **Step 3: Inspect the diff and status**

Run: `git diff --check` and `git status --short`.

Expected: no whitespace errors; only the pre-existing untracked Clang import plan may remain outside this feature.

### Task 6: Produce and inspect the real `test_194963` record

**Files:**
- Create outside Git tracking: `build/primevul-single-context.yaml`
- Create data artifact: `data/primevul_withcontext/context.jsonl`

- [ ] **Step 1: Write a local one-sample configuration**

Configure absolute local tools and the existing PrimeVul paths:

```yaml
tools:
  clang: C:/msys64/mingw64/bin/clang.exe
  git: git
  joern: E:/tools/joern-v4.0.592/joern.bat
  joern-parse: E:/tools/joern-v4.0.592/joern-parse.bat
repository_context:
  cache_root: D:/research/code/VulSOR/data/primevul_withcontext/context
  build_timeout_seconds: 1800
  query_timeout_seconds: 300
datasets:
  primevul:
    root: D:/research/code/VulSOR/data/primevul_withcontext
    input_files:
      test: D:/research/code/VulSOR/data/primevul_withcontext/test.jsonl
    repository_index_files:
      test: D:/research/code/VulSOR/data/primevul_withcontext/index.jsonl
```

- [ ] **Step 2: Confirm the selected index record before invoking tools**

Run `vulsor repo-context status` for `test_194963` and verify the repository URL, vulnerable revision, file path, and function name agree with the approved design. Stop with an explicit unavailable result if they differ.

- [ ] **Step 3: Build exactly one context record**

Set `JAVA_HOME` and `JAVACMD` to the installed JDK 21 paths, then run:

```text
vulsor repo-context build-context --config build/primevul-single-context.yaml --dataset primevul --split test --sample test_194963 --output D:/research/code/VulSOR/data/primevul_withcontext/context.jsonl
```

Expected: the command reports one built record and never iterates over other samples.

- [ ] **Step 4: Verify prompt-ready output without tools**

Run:

```text
vulsor repo-context show-context --sample test_194963 --input D:/research/code/VulSOR/data/primevul_withcontext/context.jsonl
```

Inspect that all four headings exist, facts point to `magick/property.c`, limitations are explicit, the JSONL contains only the requested new/updated record, and context length does not exceed 24,000 characters.

- [ ] **Step 5: Record real-run findings**

If Joern returns weak or empty data/control evidence, capture the exact limitation and source-grounded counts in the final report. Do not broaden the extraction, process another sample, or delete temporary repository/CPG artifacts during this proof.

## Self-review

- Spec coverage: Tasks 1-4 implement fixed storage, four evidence families, offline generation, atomic per-sample persistence, and tool-free runtime loading. Tasks 5-6 provide automated and real-sample verification.
- Scope: only `test_194963` is authorized for the real run; batch processing and cleanup automation are excluded.
- Type consistency: `extract_function_context` returns the normalized raw mapping consumed by `render_prompt_context`; `build_prompt_context` returns `PromptContextRecord`; JSONL helpers persist that same record.
- Placeholder scan: the plan contains no deferred implementation steps; every behavior has an explicit test, interface, and command.
