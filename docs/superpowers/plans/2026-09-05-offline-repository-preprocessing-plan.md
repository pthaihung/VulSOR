# Offline Repository Preprocessing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make repository context an offline preprocessing phase followed by a query-only runtime that returns empty evidence for unavailable context.

**Architecture:** A READY catalog binds each sample to an immutable revision snapshot and one smoke-validated CPG. `RepositoryPreprocessor` owns Git and the mutable CPG cache; the runtime query service only receives a read-only catalog, snapshot/CPG readers, and Joern query adapter.

**Tech Stack:** Python 3.10+, Pydantic 2, JSONL, Git, Joern 4.0.592, pytest.

---

### Task 1: Add strict READY and unresolved catalogs

**Files:**
- Create: `src/vulsor/repository_context/prepared.py`
- Create: `tests/repository_context/test_prepared.py`
- Modify: `src/vulsor/repository_context/models.py`

- [ ] **Step 1: Write failing catalog tests**

```python
def test_ready_catalog_round_trip_only_persists_whitelisted_fields(tmp_path):
    record = PreparedRecord.model_validate({
        "sample_id": "s1", "repository": repository_ref(), "target": target_anchor(),
        "source_match": {"status": "exact", "start_line": 3, "end_line": 5},
        "cpg": {"cache_key": "a" * 64, "joern_version": "4.0.592", "frontend": "C", "frontend_args": []},
        "status": "ready",
    })
    write_prepared_catalog([record], tmp_path / "test.jsonl")
    assert PreparedCatalog.load(tmp_path / "test.jsonl").get_or_none("s1") == record

def test_missing_ready_catalog_is_empty_and_unresolved_is_separate(tmp_path):
    write_unresolved_catalog([UnresolvedPreparedRecord(sample_id="s1", kind="source_mismatch")], tmp_path / "test.unresolved.jsonl")
    assert PreparedCatalog.load(tmp_path / "missing.jsonl").get_or_none("s1") is None
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `$env:PYTHONPATH='src'; python -m pytest tests/repository_context/test_prepared.py -q`

Expected: collection fails because `PreparedRecord` and `PreparedCatalog` do not exist.

- [ ] **Step 3: Implement the strict catalog contract**

Add `PreparedSourceMatch`, `PreparedCpg`, `PreparedRecord`, and `UnresolvedPreparedRecord` to `models.py`. Add this public API to `prepared.py`:

```python
class PreparedCatalog:
    @classmethod
    def load(cls, path: Path) -> "PreparedCatalog": ...
    def get_or_none(self, sample_id: str) -> PreparedRecord | None: ...

def prepared_catalog_paths(cache_root: Path, dataset: str, split: str) -> tuple[Path, Path]: ...
def write_prepared_catalog(records: Iterable[PreparedRecord], path: Path) -> None: ...
def write_unresolved_catalog(records: Iterable[UnresolvedPreparedRecord], path: Path) -> None: ...
```

READY records contain only sample/repository/target/source-match/CPG identity and `status="ready"`; unresolved records contain a controlled kind, no exception text. Writers sort sample IDs, reject duplicates, and atomically replace JSONL files under `cache_root/prepared/<dataset>/`.

- [ ] **Step 4: Verify and commit**

Run: `$env:PYTHONPATH='src'; python -m pytest tests/repository_context/test_prepared.py tests/repository_context/test_models.py -q`

Expected: all pass.

```powershell
git add src/vulsor/repository_context/models.py src/vulsor/repository_context/prepared.py tests/repository_context/test_prepared.py
git commit -m "feat: persist prepared repository context catalogs"
```

### Task 2: Split the service by mutable versus query-only dependencies

**Files:**
- Modify: `src/vulsor/repository_context/git_repository.py`
- Modify: `src/vulsor/repository_context/cpg_cache.py`
- Modify: `src/vulsor/repository_context/service.py`
- Modify: `tests/repository_context/test_service.py`

- [ ] **Step 1: Write failing no-fallback tests**

```python
def test_query_without_ready_record_returns_empty_without_git_or_build():
    result = query_service(PreparedCatalog.empty(), forbidden_artifact_reader(), forbidden_joern()).retrieve(request(), CODE, sample_id="s1")
    assert result.status == "not_found" and result.evidence == ()
    assert result.limitations[0].kind == "repository_context_unavailable"

def test_query_with_ready_record_calls_only_joern_query(prepared_runtime):
    result = prepared_runtime.retrieve(request(), CODE, sample_id="s1")
    assert result.status == "complete"
    assert prepared_runtime.joern.calls == ["query"]

def test_preprocessor_builds_smokes_and_returns_ready(preprocessor):
    record = preprocessor.preprocess_sample("s1", CODE)
    assert record.status == "ready"
    assert preprocessor.joern.calls == ["version", "build", "smoke"]
```

- [ ] **Step 2: Run the tests to verify the old hybrid service fails**

Run: `$env:PYTHONPATH='src'; python -m pytest tests/repository_context/test_service.py -q`

Expected: failures because `retrieve` calls `prepare_sample` and `RepositoryContextQueryService` does not exist.

- [ ] **Step 3: Implement pure artifact readers and separate services**

Add pure `revision_snapshot_path(cache_root, repository_url, revision)` without Git/process/directory calls. Add `read_ready_cpg(cache_root, PreparedCpg)` that validates existing manifest and `cpg.bin` without constructing `CpgCache`, locking, creating, or deleting files.

Replace `RepositoryContextService` with:

```python
class RepositoryPreprocessor:
    def preprocess_sample(self, sample_id: str, sample_code: str) -> PreparedRecord: ...

class RepositoryContextQueryService:
    def retrieve(self, request: EvidenceRequest, sample_code: str, *, sample_id: str) -> RepositoryEvidence: ...
```

The preprocessor owns `GitRepositoryResolver`, `CpgCache`, and `JoernAdapter`; it validates source, resolves SHA, builds/reuses plus smokes the CPG, and emits READY data. The query service accepts index/catalog/cache root/Joern only. It validates READY/request/source/snapshot/CPG and calls only `joern.query`; absent or invalid prepared context returns empty `not_found` evidence with `repository_context_unavailable`. A query process failure remains `unavailable`.

- [ ] **Step 4: Verify and commit**

Run: `$env:PYTHONPATH='src'; python -m pytest tests/repository_context/test_service.py tests/repository_context/test_cpg_cache.py tests/repository_context/test_git_repository.py -q`

Expected: all pass and query tests prove no resolver/build/smoke calls.

```powershell
git add src/vulsor/repository_context/git_repository.py src/vulsor/repository_context/cpg_cache.py src/vulsor/repository_context/service.py tests/repository_context/test_service.py
git commit -m "refactor: separate repository preprocessing from query runtime"
```

### Task 3: Replace prepare CLI with preprocessing and strict query

**Files:**
- Modify: `src/vulsor/repository_context/cli.py`
- Modify: `tests/repository_context/test_repository_cli.py`
- Modify: `README.md`
- Modify: `AGENT.md`

- [ ] **Step 1: Write failing parser and isolation tests**

```python
def test_preprocess_requires_exactly_one_of_sample_or_all(parser):
    with pytest.raises(SystemExit):
        parser.parse_args(["repo-context", "preprocess", "--dataset", "primevul", "--split", "test"])

def test_query_missing_ready_context_does_not_construct_git_or_cache(monkeypatch, tmp_path):
    monkeypatch.setattr("vulsor.repository_context.cli.GitRepositoryResolver", forbidden)
    monkeypatch.setattr("vulsor.repository_context.cli.CpgCache", forbidden)
    assert main(query_args(tmp_path)) == 0
    assert json.loads(output_path.read_text(encoding="utf-8"))["evidence"] == []
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `$env:PYTHONPATH='src'; python -m pytest tests/repository_context/test_repository_cli.py -q`

Expected: `preprocess` is absent and current query constructs mutable dependencies.

- [ ] **Step 3: Implement commands and documentation**

Replace `prepare` with:

```text
vulsor repo-context preprocess --config CONFIG --dataset primevul --split test --sample ID
vulsor repo-context preprocess --config CONFIG --dataset primevul --split test --all
```

Require exactly one selection. Preprocess records per-sample unresolved results, atomically publishes READY/unresolved catalogs, and reports counts. Query loads only `PreparedCatalog` and `RepositoryContextQueryService`; it never imports or constructs Git/CpgCache. Missing context writes empty evidence and exits zero. `status` reads catalog and CPG files only.

Update docs with `preprocess: Git + joern-parse + smoke`, `query: Joern script only`, and `missing: status=not_found, evidence=[]`. Document local Java 21/Joern setup without adding machine paths to tracked config.

- [ ] **Step 4: Verify and commit**

Run: `$env:PYTHONPATH='src'; python -m pytest tests/repository_context/test_repository_cli.py tests/test_cli.py -q`

Expected: all pass.

```powershell
git add src/vulsor/repository_context/cli.py tests/repository_context/test_repository_cli.py README.md AGENT.md
git commit -m "feat: preprocess repository context before runtime queries"
```

### Task 4: Support Joern 4.0.592 and complete verification

**Files:**
- Modify: `src/vulsor/repository_context/joern.py`
- Modify: `tests/repository_context/test_joern.py`
- Modify: `tests/repository_context/test_joern_integration.py`

- [ ] **Step 1: Write a failing installed-version test**

```python
def test_version_reads_the_single_joern_cli_jar_next_to_launcher(tmp_path):
    launcher = tmp_path / "joern.bat"
    library = tmp_path / "lib"
    library.mkdir()
    (library / "io.joern.joern-cli-4.0.592.jar").write_bytes(b"jar")
    adapter = JoernAdapter(joern_executable=launcher)
    assert adapter.version() == "4.0.592"
```

- [ ] **Step 2: Run the test to verify `--version` fails**

Run: `$env:PYTHONPATH='src'; python -m pytest tests/repository_context/test_joern.py::test_version_accepts_joern_4_banner_from_a_noninteractive_probe -q`

Expected: failure because the current adapter invokes unsupported `--version`
instead of reading the installed Joern CLI JAR name.

- [ ] **Step 3: Implement and run all checks**

Make `JoernAdapter.version()` resolve the configured launcher, inspect its
sibling `lib/io.joern.joern-cli-<version>.jar`, and accept exactly one matching
version. It must not start a process or open a REPL. Update integration to
preprocess the fixture then query its READY catalog and assert no parser command
occurs during query.

Run:

```powershell
$env:PYTHONPATH = "src"
python -m pytest -q -m "not joern"
python -m compileall -q src
git diff --check
$env:JAVA_HOME = "E:\tools\jdk-21.0.12+1\jdk-21.0.12.1+1"
$env:JAVACMD = "$env:JAVA_HOME\bin\java.exe"
$env:VULSOR_RUN_JOERN = "1"
python -m pytest tests/repository_context/test_joern_integration.py -q -m joern
```

Expected: non-Joern suite passes; the real integration passes or exposes one concrete Joern API incompatibility.

- [ ] **Step 4: Commit**

```powershell
git add src/vulsor/repository_context/joern.py tests/repository_context/test_joern.py tests/repository_context/test_joern_integration.py
git commit -m "fix: support Joern 4 offline context preprocessing"
```
