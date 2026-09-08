# Remove Legacy Repository-Context Flow Design

## Goal

Remove the legacy repository-wide preprocess-and-query context flow while preserving the newer offline PrimeVul file-context builder. Dataset contents and generated artifacts under `data/` are outside this change.

## Selected Approach

Use hard removal rather than deprecation or compatibility wrappers. The legacy commands and implementation are not consumed by the main model pipeline, and retaining wrappers would keep two competing context architectures visible to users.

The rejected alternatives are:

- Keep the old commands but mark them deprecated. This preserves ambiguity and maintenance cost.
- Redirect old commands to the file-context builder. Their repository-index and query contracts do not map cleanly to the new JSONL builder and would present misleading behavior.

## Supported Context Flow After the Change

The only supported context-building path is:

```text
PrimeVul pairs JSONL + file_info.json
    -> select eligible target records
    -> resolve func_hash to local target file and source range
    -> build or reuse a file-level CPG
    -> identify the target function from start_line/end_line
    -> extract file-level Joern facts
    -> select data, control, declaration/type/contract, and call context
    -> validate the complete context against the 2,000-token budget
    -> attach sparse context to the sample record
    -> atomically write a new JSONL file and progress report
```

The supported entry point remains the offline builder exposed by `scripts/context_tool.py build` until the separate top-level `context_tool/` reorganization is implemented.

## Legacy Surface to Remove

Remove the repository-wide command family from the context CLI:

- `repo-context index`
- `repo-context import-primevul`
- `repo-context preprocess`
- `repo-context build-context`
- `repo-context status`
- `repo-context query`
- `repo-context show-context`

Remove implementation that exists only for those commands:

- repository index normalization and lookup;
- Git repository cloning, revision resolution, and snapshot preparation;
- repository-level CPG caching;
- prepared and unresolved repository catalogs;
- request-driven repository evidence retrieval;
- repository evidence normalization used only by query-time retrieval;
- the old prompt-context record/upsert path when it is not required by the file-context builder;
- Clang function-name extraction used only by the legacy PrimeVul importer.

Files that combine legacy and file-level behavior, especially the CLI, Joern adapter, and configuration module, must be reduced rather than deleted wholesale. Only symbols reached by the supported file-context build path remain.

## Components to Preserve

Preserve the complete dependency closure of the file-context builder:

- `FileContextService` and its progress/result contract;
- `PrimeVulLocatorIndex`;
- local target-file resolution through `PrimeVulFileSourceResolver`;
- `FileCpgCache` and file staging;
- Joern file-context extraction;
- file-context relation selection;
- complete-context validation and the 2,000-token limit;
- atomic JSONL output and report generation;
- tests and fixtures that exercise this supported flow.

The target-function model pipeline in `src/agents/Pipeline.py` remains unchanged in this change. Stage 2 continues to expose the neutral `input_context` boundary with `status: not_provided`; connecting the new JSONL output to Stage 2 is a separate follow-up change.

## Configuration and Documentation

Reduce `config/primevul.yaml` and its Python configuration models to fields required by file-level Joern processing. Remove repository index, repository clone/cache, prepared catalog, and query-runtime settings when no preserved code reads them.

Update README and command examples so they describe only the supported offline file-context build command. Remove documentation for legacy repository preprocess/query commands.

The later directory reorganization will move the preserved implementation into top-level `context_tool/`. This deletion change must not mix broad path moves with behavioral removal, which keeps review and rollback tractable.

## Tests

Retain and update tests for:

- `scripts/context_tool.py build` delegation and CLI arguments;
- locator lookup and invalid locator handling;
- local file resolution;
- file-level CPG cache behavior;
- Joern file-context extraction;
- context selection, deduplication, and required sections;
- the strict 2,000-token all-or-nothing budget;
- progress reporting, atomic output, unavailable records, and report counts.

Delete tests whose only subject is a removed repository index, Git clone/revision flow, repository CPG cache, prepared catalog, importer, preprocessor, status command, query service, or legacy prompt-context upsert path.

Verification must include:

1. the remaining context-tool test suite;
2. `python scripts/context_tool.py --help`;
3. a two-sample offline file-context build;
4. the main pipeline boundary tests;
5. a source scan proving the removed command and class names are absent from active code and documentation;
6. `git status --short -- data` proving dataset files were not modified.

## Error Handling

The supported builder keeps its current per-record behavior:

- missing or invalid locator: write the sample with empty context and mark it unavailable;
- file or Joern extraction failure: write empty context and mark it unavailable;
- context over 2,000 tokens: write empty context and mark it oversized;
- fatal output failure: preserve atomic-write behavior and do not replace the destination with a partial file.

Removing legacy APIs is intentionally breaking. There are no compatibility aliases for deleted `repo-context` commands.

## Non-Goals

- Do not delete or rewrite anything under `data/`.
- Do not connect prebuilt context to the model pipeline in this change.
- Do not move the preserved code into top-level `context_tool/` yet.
- Do not change context selection semantics or the token budget.
- Do not modify the target-function semantic agents or obligation stages.

