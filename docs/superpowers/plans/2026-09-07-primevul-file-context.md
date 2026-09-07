# PrimeVul File-Level Context Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build sparse Joern context from only the source file containing each PrimeVul target function, without cloning full repositories.

**Architecture:** A file resolver reads PrimeVul locators, prefers an existing dataset source file, otherwise obtains only `project_file_path` from GitHub at the unique parent of the fix commit. A file-scoped CPG extractor resolves the target method by its source range, emits source-grounded relations, and a sparse serializer accepts the complete object only when it fits the 2,000-token budget.

**Tech Stack:** Python 3.10+, urllib standard library HTTP client, JSON/JSONL, Joern 4.0.592, pytest.

---

### Task 1: PrimeVul source-file resolver

**Files:**
- Create: `src/vulsor/repository_context/primevul_file_source.py`
- Create: `tests/repository_context/test_primevul_file_source.py`

- [ ] **Step 1: Write failing tests for local source preference and GitHub URLs**

```python
def test_resolve_prefers_existing_local_file(tmp_path):
    source = tmp_path / "file_contents" / "demo" / "1.txt"
    source.parent.mkdir(parents=True)
    source.write_text("int target(void) {}", encoding="utf-8")
    resolver = PrimeVulFileSourceResolver(tmp_path / "cache", http_get=fail_http)
    result = resolver.resolve(locator={"local_file_path": "file_contents/demo/1.txt"},
                              repository_url="https://github.com/acme/demo",
                              fix_revision="a" * 40,
                              dataset_root=tmp_path)
    assert result.source_path == source
    assert result.revision is None

def test_github_raw_url_uses_parent_revision_and_repository_path():
    assert github_raw_url("https://github.com/acme/demo", "b" * 40, "src/demo.c") == \
        "https://raw.githubusercontent.com/acme/demo/" + "b" * 40 + "/src/demo.c"
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/repository_context/test_primevul_file_source.py -q`

Expected: import error because `primevul_file_source` does not exist.

- [ ] **Step 3: Implement narrow source resolution**

Implement `PrimeVulFileSourceResolver.resolve()` with the following behavior:

```python
@dataclass(frozen=True)
class ResolvedFileSource:
    source_path: Path
    revision: str | None
    source_sha256: str

class PrimeVulFileSourceResolver:
    def resolve(self, *, locator, repository_url, fix_revision, dataset_root) -> ResolvedFileSource:
        local = safe_dataset_path(dataset_root, locator.get("local_file_path"))
        if local is not None and local.is_file():
            return materialize_local(local)
        owner, repository = parse_github_repository(repository_url)
        parent = unique_github_parent(owner, repository, fix_revision)
        return download_cached_file(owner, repository, parent, locator["project_file_path"], locator["file_hash"])
```

Reject unsupported repository URLs, unsafe relative paths, non-unique parents,
HTTP failures, and empty source. Cache only source bytes below
`data/primevul/context/files/`; use atomic writes.

- [ ] **Step 4: Add ambiguity and cache tests**

Test that a two-parent API response is rejected, a second resolver call uses
the cache without HTTP, and `../` local paths are rejected.

- [ ] **Step 5: Verify GREEN and commit**

Run: `python -m pytest tests/repository_context/test_primevul_file_source.py -q`

Commit:

```powershell
git add src/vulsor/repository_context/primevul_file_source.py tests/repository_context/test_primevul_file_source.py
git commit -m "feat: resolve PrimeVul target source files"
```

### Task 2: File-scoped CPG cache and target range extraction

**Files:**
- Create: `src/vulsor/repository_context/file_cpg.py`
- Create: `scripts/joern/file_context.sc`
- Create: `tests/repository_context/test_file_cpg.py`

- [ ] **Step 1: Write failing target-range tests**

```python
def test_select_target_requires_exactly_one_method_containing_span():
    payload = {"target_status": "ambiguous", "candidates": []}
    with pytest.raises(FileContextError, match="exact target"):
        validate_file_context_payload(payload)
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/repository_context/test_file_cpg.py -q`

Expected: import error because `file_cpg` does not exist.

- [ ] **Step 3: Implement source-keyed CPG creation**

Stage a downloaded/local file under a safe filename preserving its C/C++ suffix.
Build one CPG with `joern-parse` or `joern` and cache it by the source SHA-256,
not repository revision. Validate CPG output before reuse.

- [ ] **Step 4: Implement `file_context.sc` payload**

The Scala script accepts `cpgFile`, `sourceFile`, `startLine`, `endLine`, and
`outFile`. Select methods whose file matches and whose complete range contains
the locator range. Emit `target_status: exact` only for one selected method.
Emit source-grounded arrays for `imports`, `callee_funcs`, `call_relations`,
`call_site_arguments`, `data_flow`, `control_dependencies`, `declarations`,
and `types`.

- [ ] **Step 5: Verify real script compilation and commit**

Run `file_context.sc` against one staged `.c` file and assert valid JSON.

```powershell
git add src/vulsor/repository_context/file_cpg.py scripts/joern/file_context.sc tests/repository_context/test_file_cpg.py
git commit -m "feat: extract file-scoped Joern context"
```

### Task 3: Sparse context serializer and all-or-nothing budget

**Files:**
- Create: `src/vulsor/repository_context/file_prompt_context.py`
- Create: `tests/repository_context/test_file_prompt_context.py`

- [ ] **Step 1: Write failing sparse-output tests**

```python
def test_sparse_context_omits_empty_families():
    assert make_sparse_context({"imports": [], "types": [{"name": "size_t"}]}) == {
        "types": [{"name": "size_t"}]
    }

def test_oversized_context_is_rejected_without_truncation():
    with pytest.raises(FileContextBudgetError, match="2000"):
        validate_complete_context({"data_flow": [very_large_edge]})
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/repository_context/test_file_prompt_context.py -q`

Expected: import error because `file_prompt_context` does not exist.

- [ ] **Step 3: Implement deterministic mapping and budget**

Map only nonblank code/file/positive-line fields. Deduplicate each relation
family by source location and relation fields. Apply documented family limits
before serialization. Serialize the full sparse object, estimate tokens using
the existing conservative estimator, and reject it when the complete object is
above 2,000 tokens. Never remove an individual relation after serialization
starts.

- [ ] **Step 4: Verify GREEN and commit**

Run: `python -m pytest tests/repository_context/test_file_prompt_context.py -q`

```powershell
git add src/vulsor/repository_context/file_prompt_context.py tests/repository_context/test_file_prompt_context.py
git commit -m "feat: serialize bounded sparse file context"
```

### Task 4: Build command and pilot report

**Files:**
- Modify: `src/vulsor/repository_context/cli.py`
- Create: `src/vulsor/repository_context/file_context_service.py`
- Create: `tests/repository_context/test_file_context_service.py`
- Modify: `configs/primevul.yaml`

- [ ] **Step 1: Write failing service tests for complete record preservation**

```python
def test_build_preserves_raw_record_and_sets_empty_context_when_unavailable(tmp_path):
    output = build_records([raw_record], resolver=unavailable_resolver)
    assert output[0]["idx"] == raw_record["idx"]
    assert output[0]["context"] == {}
```

- [ ] **Step 2: Verify RED**

Run: `python -m pytest tests/repository_context/test_file_context_service.py -q`

Expected: import error because `file_context_service` does not exist.

- [ ] **Step 3: Implement `file-context build` CLI action**

Accept:

```text
--pairs data/primevul/primevul_test_pairs.jsonl
--file-info data/primevul/file_info.json
--dataset-root data/primevul
--output data/primevul/primevul_test_pairs_context.jsonl
--limit 10
```

Read each raw record, resolve the source, create/reuse the file CPG, extract
and serialize context, set `record["context"]` to the complete sparse object
or `{}`, and write the complete output atomically. Emit a source-free summary
report with total, built, unavailable, failed, and oversized counts.

- [ ] **Step 4: Configure file cache paths and test `--limit 10`**

Configure `data/primevul/context/files` and `data/primevul/context/file-cpg`.
Test that exactly ten input records are processed and output ordering is
preserved.

- [ ] **Step 5: Verify and commit**

Run: `python -m pytest tests/repository_context/test_file_context_service.py tests/repository_context/test_repository_cli.py -q`

```powershell
git add src/vulsor/repository_context/file_context_service.py src/vulsor/repository_context/cli.py configs/primevul.yaml tests/repository_context/test_file_context_service.py tests/repository_context/test_repository_cli.py
git commit -m "feat: build PrimeVul file contexts"
```

### Task 5: Real ten-sample pilot

**Files:**
- Generate outside Git tracking: `data/primevul/primevul_test_pairs_context_pilot10.jsonl`
- Generate outside Git tracking: `data/primevul/context/file-context-pilot10-report.json`

- [ ] **Step 1: Run source resolution and extraction for ten raw records**

```powershell
$env:PYTHONPATH = ".\\.worktrees\\repository-context\\src"
python -m vulsor.cli file-context build --config .\\.worktrees\\repository-context\\configs\\primevul.yaml --pairs data\\primevul\\primevul_test_pairs.jsonl --file-info data\\primevul\\file_info.json --dataset-root data\\primevul --output data\\primevul\\primevul_test_pairs_context_pilot10.jsonl --limit 10
```

- [ ] **Step 2: Validate pilot invariants**

Assert output has ten records, every context is either a complete sparse object
or `{}`, no context exceeds 2,000 estimated tokens, and report counts sum to
ten. Inspect at least one built context for source locations and one
unavailable record for a controlled reason.

- [ ] **Step 3: Run full subsystem verification and commit tests only**

Run: `python -m pytest tests/repository_context -q` and `git diff --check`.

Do not commit downloaded source files, CPG files, pilot JSONL, or reports.

## Self-review

- Task 1 replaces unavailable legacy `file_contents` with target-file-only
  acquisition and does not clone a repository.
- Task 2 gives exact source-span method selection and file-scoped Joern facts.
- Task 3 enforces sparse output and all-or-nothing 2,000-token acceptance.
- Task 4 preserves raw PrimeVul records and exposes an explicit pilot command.
- Task 5 validates the requested ten-record run before any larger processing.
