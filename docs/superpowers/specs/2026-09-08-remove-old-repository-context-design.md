# Remove the Old Repository-Context Flow

## Purpose

Remove the incomplete repository-context path inherited from the pre-merge `main` pipeline while preserving its target-function analysis. This cleanup establishes a neutral Stage 2 boundary that can later consume context produced offline by `context_tool`.

## Background

The pre-merge pipeline contains two distinct ideas under the word “context”:

1. Function-level semantic analysis performed from the target function by the Operation, State, Value, and Execution agents.
2. A repository/CPG evidence placeholder that marks unresolved or project-specific operations as requiring repository evidence but never builds or queries a CPG.

The function-level path remains valid and must be preserved. The repository path is misleading because it emits `status: not_built`, an empty `repository_evidence` list, and a limitation saying that CPG integration is not configured. Dataset configuration also declares context JSONL files that the pipeline never loads.

The new repository context implementation is a separate offline process. It must not coexist with the old placeholder or be invoked from the inference pipeline.

## Scope

### Preserve

- Target-function input loading.
- Function line numbering and line-location validation.
- Operation, State, Value, and Execution agents.
- Function-derived semantic model output.
- Existing downstream obligation reasoning and adjudication behavior.
- Existing stage numbering during this cleanup.

### Remove

- The `cpg_evidence_retrieval` agent configuration.
- `CPG_Evidence_Retrieval.yml`.
- Logic that selects `unresolved` or `project_specific` operations as repository-context requests.
- The placeholder `build_cpg_evidence_record` behavior.
- Empty `repository_evidence` output and the “CPG builder/query integration is not configured yet” limitation.
- Diagnostics specific to missing placeholder CPG evidence.
- Unused `context_file` and `pretty_context_file` entries in dataset configuration.

### Do Not Change

- Files under `data/`.
- The new offline context extraction implementation.
- PrimeVul labels or ground-truth handling.
- Function-agent prompts other than references that become invalid after repository-placeholder removal.
- Stage output directories beyond the schema change described below.

## Pipeline Design

Stage 1 continues to derive a semantic model from the target function.

Stage 2 remains present as a stable integration boundary but becomes neutral. Before offline context is integrated, it produces:

```json
{
  "sample_id": "test_...",
  "stage": "input_context",
  "output": {
    "status": "not_provided",
    "context": {}
  }
}
```

Stage 3 and Stage 4 continue to receive the Stage 2 output through their existing orchestration path. They must treat `not_provided` context as optional input rather than an error. They must not infer repository facts when the context object is empty.

The resulting temporary flow is:

```text
target function
    -> Stage 1 function semantic model
    -> Stage 2 neutral input-context boundary
    -> Stage 3 obligation reasoning
    -> Stage 4 adjudication
```

The later integration will replace only the internals of Stage 2 with a read of `record["context"]` generated offline by `context_tool`.

## Error Handling

- Missing context is represented as `status: not_provided` with an empty object.
- Missing context is not a pipeline failure.
- No Git, Clang, Joern, repository lookup, or network operation may occur in the inference pipeline.
- The pipeline must not fabricate repository limitations or evidence.
- Existing errors in function analysis, LLM responses, quality gates, and stage prerequisites retain their current behavior.

## Data Boundary

This cleanup does not move or delete dataset files. In particular, `data/PrimeVul_clean/context/` remains untouched until the separate data-layout migration has a validated source-to-destination map.

After this cleanup, dataset configuration describes only files actually read by the main pipeline. Offline context paths will be owned by `context_tool`, not by the main dataset loader.

## Verification

The implementation is complete when all of the following hold:

1. Stage 1 output for representative function-only samples remains unchanged.
2. Stage 2 emits the neutral `input_context` schema.
3. Stage 3 and Stage 4 accept empty optional context.
4. A two-sample dry run completes through the requested stage.
5. Searches of active main-pipeline code find no old `repository_evidence`, `cpg_evidence`, `context_file`, or placeholder CPG message.
6. Unit tests cover neutral Stage 2 generation and downstream empty-context handling.
7. No files under `data/` are modified or deleted.

## Out of Scope

- Moving repository-context implementation into the top-level `context_tool/` package.
- Reorganizing `data/` into `raw`, `processed`, and cache areas.
- Loading enriched JSONL records into Stage 2.
- Renaming the main package or reorganizing the full repository tree.
- Changing vulnerability-detection logic or prompt semantics.
