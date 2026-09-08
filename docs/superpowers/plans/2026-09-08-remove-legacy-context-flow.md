# Remove Legacy Context Flow Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the repository-wide preprocess/query context implementation while preserving one offline file-level PrimeVul context builder with its 2,000-token contract.

**Architecture:** The supported context CLI will expose only `file-context build`. Its dependency closure will resolve one target file, build/cache a CPG keyed by source bytes, run the file-scoped Joern extractor, select sparse relations, validate the all-or-nothing 2,000-token budget, and write JSONL atomically. Repository cloning, revision indexing, prepared catalogs, query-time evidence requests, and legacy prompt-context records will no longer exist in active code.

**Tech Stack:** Python 3.10+, argparse, Pydantic, PyYAML, Joern/joern-parse, pytest, PowerShell.

---

## File Map

Preserve and simplify:

- `scripts/context_tool.py`: the single user-facing offline wrapper.
- `src/agents/repo_context/cli.py`: only the `file-context build` parser and handler.
- `src/agents/repo_context/file_context_service.py`: per-record orchestration, progress, atomic JSONL and report.
- `src/agents/repo_context/file_cpg.py`: source-digest CPG cache.
- `src/agents/repo_context/file_context_selection.py`: relation filtering, deduplication and packing.
- `src/agents/repo_context/primevul_file_source.py`: target-file resolution.
- `src/agents/repo_context/joern.py`: only build CPG and extract file context.
- `src/agents/input_context/file_prompt_context.py`: sparse cleanup and the 2,000-token validator.
- `src/agents/repo_context/config.py`: tools and file-context timeout configuration only.
- `config/primevul.yaml`: tools and file-context settings only.

Delete after imports are removed:

- `src/agents/repo_context/clang_function.py`
- `src/agents/repo_context/cpg_cache.py`
- `src/agents/repo_context/datasets.py`
- `src/agents/repo_context/evidence.py`
- `src/agents/repo_context/git_repository.py`
- `src/agents/repo_context/index.py`
- `src/agents/repo_context/models.py`
- `src/agents/repo_context/primevul_import.py`
- `src/agents/repo_context/primevul_index.py`
- `src/agents/repo_context/prepared.py`
- `src/agents/repo_context/relation_selection.py`
- `src/agents/repo_context/service.py`
- `src/agents/input_context/prompt_context.py`
- `src/agents/input_context/prebuilt_context.py`
- `scripts/verify_repository_context_samples.py`
- `scripts/inspect_ast.py`
- `scripts/joern/smoke_cpg.sc`
- `scripts/joern/function_context.sc`
- `scripts/joern/repository_evidence.sc`
- `native/CMakeLists.txt`
- `native/clang_analysis.cpp`
- `native/clang_driver_probe.cpp`
- `native/clang_link_probe.cpp`
- `native/rav_minimal_probe.cpp`
- `native/rav_probe.cpp`
- `native/rav_traversal_probe.cpp`

Delete tests whose only subject is removed code: `tests/repository_context/test_clang_function.py`, `test_cpg_cache.py`, `test_evidence.py`, `test_git_repository.py`, `test_index.py`, `test_models.py`, `test_prebuilt_context.py`, `test_prepared.py`, `test_primevul_import.py`, `test_prompt_context.py`, `test_relation_selection.py`, `test_service.py`, and `test_verify_samples.py`. Keep and update the file-context tests, `tests/test_context_tool.py`, and the main pipeline boundary tests.

### Task 1: Lock the Supported CLI and Dependency Boundary

**Files:**
- Modify: `tests/test_context_tool.py`
- Create: `tests/repository_context/test_file_context_boundary.py`
- Modify: `src/agents/repo_context/cli.py`

- [ ] **Step 1: Add failing CLI-surface tests**

Add a parser factory test and a supported-path smoke test:

```python
from pathlib import Path

import argparse

from agents.repo_context.cli import build_parser


def test_context_cli_exposes_only_file_context_build() -> None:
    parser = build_parser()
    command_action = next(
        action
        for action in parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    assert set(command_action.choices) == {"file-context"}

    file_parser = command_action.choices["file-context"]
    file_action = next(
        action
        for action in file_parser._actions
        if isinstance(action, argparse._SubParsersAction)
    )
    assert set(file_action.choices) == {"build"}
```

Add a source-level boundary assertion to the same test module:

```python
def test_context_cli_has_no_repository_query_symbols() -> None:
    source = Path("src/agents/repo_context/cli.py").read_text(encoding="utf-8")
    for legacy_name in (
        "RepositoryPreprocessor",
        "RepositoryContextQueryService",
        "repo-context",
        "import-primevul",
        "build-context",
        "show-context",
    ):
        assert legacy_name not in source
```

- [ ] **Step 2: Run the new tests and verify the old CLI fails the contract**

Run:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
python -m pytest tests/repository_context/test_file_context_boundary.py -q
```

Expected: FAIL because the existing parser still exposes `repo-context` and has no `build_parser` factory.

- [ ] **Step 3: Refactor the CLI to expose only the file builder**

Replace the parser setup with this shape and preserve the existing file-builder handler body:

```python
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="context_tool")
    commands = parser.add_subparsers(dest="command", required=True)
    file_context = commands.add_parser(
        "file-context", help="Build offline file-level PrimeVul context"
    )
    actions = file_context.add_subparsers(dest="file_action", required=True)
    build = actions.add_parser("build")
    build.add_argument("--config", type=Path)
    build.add_argument("--pairs", required=True, type=Path)
    build.add_argument("--file-info", required=True, type=Path)
    build.add_argument("--dataset-root", required=True, type=Path)
    build.add_argument("--output", required=True, type=Path)
    build.add_argument("--report", type=Path)
    build.add_argument("--limit", type=int)
    build.add_argument("--progress", action="store_true")
    build.set_defaults(handler=handle_file_context)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    config = load_config(args.config)
    return args.handler(args, config)
```

`handle_file_context(args, config)` must retain the current flow: validate a positive limit, reject identical input/output paths, create `JoernAdapter(config)`, `FileContextService(PrimeVulFileSourceResolver(...), FileCpgCache(...), joern, ...)`, attach `_file_context_progress` only when requested, and call `service.build_jsonl(...)`.

- [ ] **Step 4: Run the boundary tests**

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
python -m pytest tests/repository_context/test_file_context_boundary.py tests/test_context_tool.py -q
```

Expected: all tests pass and `python scripts/context_tool.py --help` shows only `file-context build`.

- [ ] **Step 5: Commit**

```powershell
git add src/agents/repo_context/cli.py tests/repository_context/test_file_context_boundary.py tests/test_context_tool.py
git commit -m "refactor: restrict context CLI to offline file builder"
```

### Task 2: Remove Legacy Context Models and Prompt Records

**Files:**
- Modify: `src/agents/input_context/file_prompt_context.py`
- Modify: `src/agents/repo_context/file_context_selection.py`
- Modify: `src/agents/input_context/__init__.py`
- Modify: `src/agents/repo_context/__init__.py`
- Delete: `src/agents/input_context/prompt_context.py`
- Delete: `src/agents/input_context/prebuilt_context.py`

- [ ] **Step 1: Add a failing import-boundary test**

Add to `tests/repository_context/test_file_context_boundary.py`:

```python
def test_file_context_budget_has_no_legacy_prompt_context_dependency() -> None:
    from agents.input_context.file_prompt_context import (
        MAX_FILE_CONTEXT_TOKENS,
        estimate_context_tokens,
        validate_complete_context,
    )

    assert MAX_FILE_CONTEXT_TOKENS == 2000
    assert estimate_context_tokens("abcd") == 2
    assert validate_complete_context({"data_flow": [{"code": "x = y"}]})
```

- [ ] **Step 2: Move the shared token estimator into `file_prompt_context.py`**

Add this function before `FileContextBudgetError`, export it in `__all__`, and change its existing import use:

```python
def estimate_context_tokens(text: str) -> int:
    """Conservatively estimate context tokens without a model tokenizer."""
    return (len(text.encode("utf-8")) + 2) // 3
```

Change `file_context_selection.py` to import it from `..input_context.file_prompt_context`, then delete the old prompt serializer/upsert and prebuilt-store modules. Trim both `__init__.py` files so they export only the preserved file-context symbols.

- [ ] **Step 3: Run the import and budget tests**

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
python -m pytest tests/repository_context/test_file_context_boundary.py tests/repository_context/test_file_context_selection.py tests/repository_context/test_file_prompt_context.py -q
```

Expected: all preserved tests pass and no test imports `PromptContextRecord`, `PrebuiltContextStore`, `render_prompt_context`, or `upsert_prompt_context`.

- [ ] **Step 4: Commit**

```powershell
git add `
  src/agents/input_context/file_prompt_context.py `
  src/agents/input_context/__init__.py `
  src/agents/input_context/prompt_context.py `
  src/agents/input_context/prebuilt_context.py `
  src/agents/repo_context/file_context_selection.py `
  tests/repository_context/test_file_context_boundary.py
git commit -m "refactor: remove legacy prompt context records"
```

### Task 3: Keep Only File-Level Joern and File Configuration

**Files:**
- Modify: `src/agents/repo_context/joern.py`
- Modify: `src/agents/repo_context/config.py`
- Modify: `config/primevul.yaml`
- Modify: `tests/repository_context/test_joern.py`
- Modify: `tests/repository_context/test_joern_integration.py`
- Delete: `scripts/joern/smoke_cpg.sc`
- Delete: `scripts/joern/function_context.sc`
- Delete: `scripts/joern/repository_evidence.sc`

- [ ] **Step 1: Add a failing Joern API boundary test**

Add:

```python
def test_joern_adapter_exposes_only_file_context_operations() -> None:
    from agents.repo_context.joern import JoernAdapter

    assert hasattr(JoernAdapter, "build_cpg")
    assert hasattr(JoernAdapter, "extract_file_context")
    assert not hasattr(JoernAdapter, "query")
    assert not hasattr(JoernAdapter, "extract_function_context")
    assert not hasattr(JoernAdapter, "smoke")
```

- [ ] **Step 2: Reduce JoernAdapter**

Preserve command validation, `build_cpg`, `extract_file_context`, cleanup helpers and file-payload validation. Remove `query`, `smoke`, `extract_function_context`, repository evidence script selection, request-model validation and payload validators that serve only those methods. Remove the old script-selection attributes completely; the constructor must accept the reduced file-context config and select only the retained script:

```python
self.file_context_script = Path(
    _default_script("file_context.sc")
    if file_context_script is None
    else file_context_script
)
```

The retained `build_cpg` and `extract_file_context` behavior must remain unchanged apart from reading the reduced timeout/tool config.

- [ ] **Step 3: Reduce configuration to file-context needs**

Replace repository-oriented settings with a file-context section:

```yaml
tools:
  joern: joern
  joern-parse: joern-parse

file_context:
  build_timeout_seconds: 1800
  query_timeout_seconds: 120
```

The Python model must expose the same values as `config.file_context` and no `repository_context`, repository index, clone, catalog, lock, or Git settings. Keep the unrelated `AgentLLMConfig` definitions in this module, but reduce the context models to this concrete shape:

```python
class ToolsConfig(BaseModel):
    joern: str = "joern"
    joern_parse: str = Field(default="joern-parse", alias="joern-parse")


class FileContextConfig(BaseModel):
    build_timeout_seconds: StrictInt = Field(default=1800, ge=1)
    query_timeout_seconds: StrictInt = Field(default=120, ge=1)


class VulSORConfig(BaseModel):
    tools: ToolsConfig = Field(default_factory=ToolsConfig)
    file_context: FileContextConfig = Field(default_factory=FileContextConfig)
```

Make `JoernAdapter` read the tools plus `file_context.build_timeout_seconds` and `file_context.query_timeout_seconds` from this reduced model. The file CLI must load this shape without compatibility aliases.

- [ ] **Step 4: Run Joern boundary tests without starting Joern**

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
python -m pytest tests/repository_context/test_file_context_boundary.py tests/repository_context/test_joern.py tests/repository_context/test_joern_integration.py -q
```

Expected: preserved tests pass; tests for removed smoke/query/function-context APIs are deleted or rewritten to cover `extract_file_context` only.

- [ ] **Step 5: Commit**

```powershell
git add `
  config/primevul.yaml `
  src/agents/repo_context/config.py `
  src/agents/repo_context/joern.py `
  scripts/joern/smoke_cpg.sc `
  scripts/joern/function_context.sc `
  scripts/joern/repository_evidence.sc `
  tests/repository_context/test_joern.py `
  tests/repository_context/test_joern_integration.py `
  tests/repository_context/test_file_context_boundary.py
git commit -m "refactor: keep only file-level Joern context extraction"
```

### Task 4: Delete Repository-Wide Services and Their Tests

**Files:**
- Delete the legacy implementation files listed in the File Map.
- Delete the legacy tests listed in the File Map.
- Modify: `src/agents/repo_context/file_context_service.py` only when an import points to a removed module.
- Modify: `src/agents/repo_context/primevul_file_source.py` only when an import points to a removed module.

- [ ] **Step 1: Add a failing source-boundary scan**

Add a test that scans active context code and documentation:

```python
from pathlib import Path


def test_legacy_repository_context_surface_is_absent() -> None:
    roots = (Path("src/agents"), Path("scripts"), Path("config"), Path("README.md"))
    forbidden = (
        "RepositoryPreprocessor",
        "RepositoryContextQueryService",
        "GitRepositoryResolver",
        "PreparedCatalog",
        "repo-context",
        "repository_evidence.sc",
        "import-primevul",
    )
    for root in roots:
        files = [root] if root.is_file() else root.rglob("*")
        for path in files:
            if path.is_file() and path.suffix in {".py", ".yml", ".yaml", ".md", ".sc"}:
                text = path.read_text(encoding="utf-8")
                assert not any(name in text for name in forbidden), path
```

Expected before deletion: FAIL with at least one legacy symbol.

- [ ] **Step 2: Delete repository-only modules**

Delete the exact legacy files from the File Map. Update `__init__.py` exports and run `rg` to remove imports before running tests. Do not delete `file_context_service.py`, `file_cpg.py`, `file_context_selection.py`, `primevul_file_source.py`, or the file-level Joern test fixture.

- [ ] **Step 3: Delete repository-only native, AST, and verifier tooling**

Delete the seven exact files listed in the File Map, plus `scripts/verify_repository_context_samples.py` and `scripts/inspect_ast.py`, because their only callers and purpose belong to the removed repository preprocessing/import paths. Remove their documentation and references from `README.md`, `AGENT.md`, and `.gitignore` where those references become stale. Do not alter any file under `data/`.

- [ ] **Step 4: Run the boundary scan and preserved unit tests**

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
python -m pytest tests/repository_context/test_file_context_boundary.py tests/repository_context/test_file_context_selection.py tests/repository_context/test_file_context_service.py tests/repository_context/test_file_cpg.py tests/repository_context/test_file_prompt_context.py tests/repository_context/test_primevul_file_source.py tests/test_context_tool.py -q
```

Expected: all preserved tests pass and the legacy-surface test passes.

- [ ] **Step 5: Commit**

```powershell
git add README.md AGENT.md .gitignore `
  src/agents/repo_context/clang_function.py `
  src/agents/repo_context/cpg_cache.py `
  src/agents/repo_context/datasets.py `
  src/agents/repo_context/evidence.py `
  src/agents/repo_context/git_repository.py `
  src/agents/repo_context/index.py `
  src/agents/repo_context/models.py `
  src/agents/repo_context/primevul_import.py `
  src/agents/repo_context/primevul_index.py `
  src/agents/repo_context/prepared.py `
  src/agents/repo_context/relation_selection.py `
  src/agents/repo_context/service.py `
  src/agents/input_context/prompt_context.py `
  src/agents/input_context/prebuilt_context.py `
  scripts/verify_repository_context_samples.py `
  scripts/inspect_ast.py `
  scripts/joern/smoke_cpg.sc `
  scripts/joern/function_context.sc `
  scripts/joern/repository_evidence.sc `
  src/agents/repo_context/file_context_service.py `
  src/agents/repo_context/primevul_file_source.py `
  native/CMakeLists.txt `
  native/clang_analysis.cpp `
  native/clang_driver_probe.cpp `
  native/clang_link_probe.cpp `
  native/rav_minimal_probe.cpp `
  native/rav_probe.cpp `
  native/rav_traversal_probe.cpp `
  tests/repository_context/test_clang_function.py `
  tests/repository_context/test_cpg_cache.py `
  tests/repository_context/test_evidence.py `
  tests/repository_context/test_git_repository.py `
  tests/repository_context/test_index.py `
  tests/repository_context/test_models.py `
  tests/repository_context/test_prebuilt_context.py `
  tests/repository_context/test_prepared.py `
  tests/repository_context/test_primevul_import.py `
  tests/repository_context/test_prompt_context.py `
  tests/repository_context/test_relation_selection.py `
  tests/repository_context/test_service.py `
  tests/repository_context/test_verify_samples.py
git commit -m "refactor: remove repository-wide context services"
```

### Task 5: Final Verification of the Single Context Flow

**Files:**
- Modify: `README.md` only if a stale legacy command remains after Task 4.
- No data files may be modified.

- [ ] **Step 1: Verify CLI surface**

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
python scripts/context_tool.py --help
python scripts/context_tool.py file-context build --help
```

Expected: only `file-context build` is exposed and no `repo-context` command is listed.

- [ ] **Step 2: Run the complete preserved test suite**

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) "src")
python -m pytest tests/repository_context tests/test_context_tool.py tests/test_main_context_boundary.py -q
```

Expected: zero failures; the test count may be lower than the old suite because repository-wide tests were intentionally removed.

- [ ] **Step 3: Run a two-sample offline build**

```powershell
python scripts/context_tool.py build `
  --config "config/primevul.yaml" `
  --pairs "data/primevul/primevul_test_pairs.jsonl" `
  --file-info "data/primevul/file_info.json" `
  --dataset-root "data/primevul" `
  --output "data/primevul/primevul_withcontext_pilot2.jsonl" `
  --limit 2 `
  --progress
```

Expected: the command exits 0, writes an atomically completed output file, and reports counts for exactly two eligible records. Existing dataset files remain untouched; the pilot output is a generated artifact and must not be committed.

- [ ] **Step 4: Verify removed surface and data safety**

```powershell
rg -n "RepositoryPreprocessor|RepositoryContextQueryService|GitRepositoryResolver|PreparedCatalog|repo-context|repository_evidence\.sc|import-primevul" src scripts config README.md AGENT.md .gitignore
git status --short -- data
git diff --check
```

Expected: the source scan has no matches, `git status --short -- data` has no output, and `git diff --check` exits 0.

- [ ] **Step 5: Commit final documentation and test corrections**

```powershell
git status --short
```

Expected: only intentional non-data changes are present. Do not commit generated pilot JSONL, CPG caches, or repository snapshots.
