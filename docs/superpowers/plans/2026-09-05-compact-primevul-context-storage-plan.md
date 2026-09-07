# Compact PrimeVul Context Storage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Store normalized PrimeVul test input, its repository index, and all query-safe repository context under `data/primevul_withcontext/` without modifying the raw export in `data/primevul/`.

**Architecture:** Optional split-to-file maps preserve legacy dataset paths while supporting compact single-file input and index paths. Optional explicit catalog paths preserve the legacy catalog layout for other datasets; new PrimeVul configuration places Git artifacts under `context/repos/` and CPGs under `context/cpg/`.

**Tech Stack:** Python 3.10+, Pydantic 2, YAML, JSONL, Git, Joern 4.0.592, pytest.

---

### Task 1: Select compact input and index files by split

**Files:**
- Modify: `src/vulsor/config.py`
- Modify: `src/vulsor/datasets.py`
- Modify: `src/vulsor/repository_context/cli.py`
- Create: `tests/test_datasets.py`
- Modify: `tests/repository_context/test_repository_cli.py`

- [ ] **Step 1: Write failing selector tests**

Add this test to `tests/test_datasets.py`:

```python
def test_iter_dataset_samples_uses_configured_input_file_for_split(tmp_path):
    compact = tmp_path / "test.jsonl"
    compact.write_text('{"sample_id":"s1","code":"int f(void) {}"}\n', encoding="utf-8")
    config = VulSORConfig.model_validate({"datasets": {"primevul": {
        "root": str(tmp_path), "input_files": {"test": str(compact)},
    }}})
    assert list(iter_dataset_samples(config, "primevul", "test")) == [
        DatasetSample(sample_id="s1", code="int f(void) {}")
    ]
```

Add a CLI status test with `repository_index_files: {"test": str(index_path)}` and no `repository_index_dir`; it must load the index.

- [ ] **Step 2: Confirm tests fail**

Run: `$env:PYTHONPATH="src"; python -m pytest tests/test_datasets.py tests/repository_context/test_repository_cli.py -q`

Expected: the two new config fields do not exist and the loader appends legacy directory names.

- [ ] **Step 3: Implement selectors**

Add these fields to `DatasetConfig`:

```python
input_files: dict[str, Path] = Field(default_factory=dict)
repository_index_files: dict[str, Path] = Field(default_factory=dict)
```

Add `dataset_input_path(dataset, split)` to `datasets.py`, returning `dataset.input_files.get(split, dataset.root / "inputs" / f"{split}.jsonl")`, and make `iter_dataset_samples` use it. In repository CLI add `_repository_index_path(dataset, split)`: use the explicit map first, otherwise require `repository_index_dir` and append `<split>.jsonl`. Make `_index` call this helper.

- [ ] **Step 4: Verify and commit**

Run: `$env:PYTHONPATH="src"; python -m pytest tests/test_datasets.py tests/repository_context/test_repository_cli.py -q`

Commit:

```powershell
git add src/vulsor/config.py src/vulsor/datasets.py src/vulsor/repository_context/cli.py tests/test_datasets.py tests/repository_context/test_repository_cli.py
git commit -m "feat: support compact dataset split files"
```

### Task 2: Add compact catalog and repository cache paths

**Files:**
- Modify: `src/vulsor/config.py`
- Modify: `src/vulsor/repository_context/prepared.py`
- Modify: `src/vulsor/repository_context/git_repository.py`
- Modify: `src/vulsor/repository_context/cli.py`
- Modify: `tests/repository_context/test_prepared.py`
- Modify: `tests/repository_context/test_git_repository.py`
- Modify: `tests/repository_context/test_repository_cli.py`

- [ ] **Step 1: Write failing path tests**

```python
def test_configured_catalog_paths_override_legacy_split_paths(tmp_path):
    config = RepositoryContextConfig(
        cache_root=tmp_path / "context",
        catalog_path=tmp_path / "context" / "catalog.jsonl",
        unavailable_path=tmp_path / "context" / "unavailable.jsonl",
    )
    assert configured_catalog_paths(config, "primevul", "test") == (
        tmp_path / "context" / "catalog.jsonl",
        tmp_path / "context" / "unavailable.jsonl",
    )
```

Add a Git path test asserting that a mirror parent is `context/repos/mirrors` and `revision_snapshot_path(...).parent.parent` is `context/repos/revisions`.

- [ ] **Step 2: Confirm tests fail**

Run: `$env:PYTHONPATH="src"; python -m pytest tests/repository_context/test_prepared.py tests/repository_context/test_git_repository.py tests/repository_context/test_repository_cli.py -q`

Expected: `configured_catalog_paths` is absent and cache paths use top-level `mirrors/` and `revisions/`.

- [ ] **Step 3: Implement the immutable path contract**

Add `catalog_path: Path | None = None` and `unavailable_path: Path | None = None` to `RepositoryContextConfig`. Add `configured_catalog_paths(config, dataset, split)` in `prepared.py`: it requires both explicit paths or neither, rejects NUL paths, returns explicit paths when present, and otherwise calls the current `prepared_catalog_paths` fallback. Update all CLI catalog loads/writes to call this helper.

Change only repository artifact paths:

```python
cache_root / "repos" / "mirrors" / f"{repository_url_digest(url)}.git"
cache_root / "repos" / "revisions" / url_digest / revision
```

Use that same `repos/revisions` layout in `revision_snapshot_path`. Do not move or delete legacy artifacts; fresh preprocessing populates the new paths atomically.

- [ ] **Step 4: Verify and commit**

Run: `$env:PYTHONPATH="src"; python -m pytest tests/repository_context/test_prepared.py tests/repository_context/test_git_repository.py tests/repository_context/test_repository_cli.py -q`

Commit:

```powershell
git add src/vulsor/config.py src/vulsor/repository_context/prepared.py src/vulsor/repository_context/git_repository.py src/vulsor/repository_context/cli.py tests/repository_context/test_prepared.py tests/repository_context/test_git_repository.py tests/repository_context/test_repository_cli.py
git commit -m "refactor: use compact repository context paths"
```

### Task 3: Configure and document the compact PrimeVul layout

**Files:**
- Modify: `configs/primevul.yaml`
- Modify: `README.md`
- Modify: `AGENT.md`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write a failing configuration test**

```python
def test_primevul_config_uses_compact_context_layout():
    config = load_config(Path("configs/primevul.yaml"))
    dataset = config.datasets["primevul"]
    assert dataset.input_files["test"] == Path("data/primevul_withcontext/test.jsonl")
    assert dataset.repository_index_files["test"] == Path("data/primevul_withcontext/index.jsonl")
    assert config.repository_context.cache_root == Path("data/primevul_withcontext/context")
    assert config.repository_context.catalog_path == Path("data/primevul_withcontext/context/catalog.jsonl")
    assert config.repository_context.unavailable_path == Path("data/primevul_withcontext/context/unavailable.jsonl")
```

- [ ] **Step 2: Confirm it fails**

Run: `$env:PYTHONPATH="src"; python -m pytest tests/test_config.py::test_primevul_config_uses_compact_context_layout -q`

Expected: current configuration points to legacy paths.

- [ ] **Step 3: Update checked-in config and docs**

Set the exact five paths asserted above in `configs/primevul.yaml`; retain `enabled: false`, and do not add machine-specific Joern paths. Update README and AGENT layout documentation to show raw `data/primevul/` separate from `data/primevul_withcontext/{test.jsonl,index.jsonl,context/}` and explain `catalog.jsonl` replaces the filename `ready.jsonl` while JSON records retain `status: "ready"`.

- [ ] **Step 4: Verify and commit**

Run:

```powershell
$env:PYTHONPATH="src"
python -m pytest tests/test_config.py -q
rg -n "primevul_withcontext|catalog\.jsonl|unavailable\.jsonl" README.md AGENT.md configs/primevul.yaml
```

Commit:

```powershell
git add configs/primevul.yaml README.md AGENT.md tests/test_config.py
git commit -m "docs: configure compact PrimeVul context storage"
```

### Task 4: Regression verification without preprocessing data

**Files:**
- Modify: none

- [ ] **Step 1: Run non-Joern repository-context tests**

Run: `$env:PYTHONPATH="src"; python -m pytest tests/repository_context -q -m "not joern"`

Expected: all selected tests pass.

- [ ] **Step 2: Compile and inspect the worktree**

```powershell
$env:PYTHONPATH="src"
python -m compileall -q src
git diff --check
git status --short
```

Expected: compilation and whitespace checks pass; no file under `data/` is created or changed by this layout-only migration.
