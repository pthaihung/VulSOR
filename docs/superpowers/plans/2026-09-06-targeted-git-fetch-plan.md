# Targeted Git Fetch Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fetch only a PrimeVul patch commit and its first parent while retaining immutable repository snapshots for offline preprocessing.

**Architecture:** `GitRepositoryResolver` will initialize and verify a bare origin cache, then fetch a requested SHA with `--depth=2` instead of cloning every remote ref.  Parent resolution reads the first parent from this verified cache; existing detached checkout, SHA verification, locking, timeouts, and atomic cache publication remain unchanged.

**Tech Stack:** Python 3.10+, Git CLI, pytest.

---

### Task 1: Test the targeted mirror fetch contract

**Files:**
- Modify: `tests/repository_context/test_git_repository.py`

- [ ] **Step 1: Write failing test**

Add a command-recording resolver test that requests a full SHA and asserts the
network fetch command is exactly:

```python
("git", "-C", str(mirror_root), "fetch", "--depth=2", "origin", f"+{revision}:refs/vulsor/{revision}")
```

The test must also assert that the command sequence does not contain
`("git", "clone", "--mirror", ...)`.

- [ ] **Step 2: Run test to verify it fails**

Run: `set PYTHONPATH=src&&python -m pytest tests\repository_context\test_git_repository.py::test_resolve_fetches_only_requested_revision_and_parent -q`

Expected: FAIL because the resolver currently invokes `git clone --mirror`.

- [ ] **Step 3: Commit the failing test**

```text
git add tests/repository_context/test_git_repository.py
git commit -m test:cover-targeted-git-fetch
```

### Task 2: Replace full mirror cloning with a targeted bare cache

**Files:**
- Modify: `src/vulsor/repository_context/git_repository.py`
- Test: `tests/repository_context/test_git_repository.py`

- [ ] **Step 1: Implement bare-cache initialization**

Replace the missing-mirror branch in `_ensure_mirror` with a temporary bare
repository initialized by:

```python
self._run_git("init", "--bare", str(temporary_root))
self._run_git("-C", str(temporary_root), "remote", "add", "origin", canonical_url)
```

Verify the temporary cache with `_verify_mirror`, then atomically rename it to
`mirror_root`.

- [ ] **Step 2: Implement revision-targeted fetch**

Add `_fetch_revision(mirror_root, revision)`:

```python
self._run_git(
    "-C", str(mirror_root), "fetch", "--depth=2", "origin",
    f"+{revision}:refs/vulsor/{revision}",
)
```

Call it whenever `_mirror_contains_revision` is false.  Replace the existing
unbounded `_refresh_mirror` call in this path.  The private ref makes the
fetched SHA durable and discoverable by `_mirror_contains_revision`. Preserve
the final check and raise `RepositoryRevisionNotFoundError` when unavailable.

- [ ] **Step 3: Run focused tests**

Run: `set PYTHONPATH=src&&python -m pytest tests\repository_context\test_git_repository.py -q`

Expected: PASS, including immutable checkout, cache reuse, and new targeted
fetch coverage.

- [ ] **Step 4: Commit implementation**

```text
git add src/vulsor/repository_context/git_repository.py tests/repository_context/test_git_repository.py
git commit -m fix:fetch-git-revisions-on-demand
```

### Task 3: Verify parent revision and real PrimeVul source matching

**Files:**
- No tracked source changes expected.

- [ ] **Step 1: Run the importer for a single controlled sample**

Create a temporary JSONL containing the `test_194963` target-one input record
and invoke `repo-context import-primevul` with `build\primevul-local.yaml`.

- [ ] **Step 2: Validate the generated index**

Assert the single output record has a 40-character parent revision, null
`start_line/end_line`, and `magick/property.c` as its path.

- [ ] **Step 3: Preprocess the same sample**

Run `repo-context preprocess --sample test_194963` against the generated
single-sample input/index.  Expected: one ready record and no
`source_mismatch` unresolved record.

- [ ] **Step 4: Run regression verification**

Run:

```text
set PYTHONPATH=src&&python -m pytest tests\repository_context\test_git_repository.py tests\repository_context\test_primevul_import.py tests\repository_context\test_repository_cli.py -q&&python -m compileall -q src&&git diff --check
```

Expected: all selected tests pass; no Python compilation or whitespace errors.
