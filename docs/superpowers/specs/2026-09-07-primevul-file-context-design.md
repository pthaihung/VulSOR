# PrimeVul File-Level Context Design

## Goal

Build sparse repository context from only the source file that contains each
PrimeVul target function. The system must not clone or retain whole upstream
repositories.

## Inputs and output layout

Inputs are kept under `data/primevul/`:

```text
primevul_test_pairs.jsonl
file_info.json
```

Each selected `target: 1` record supplies the project URL and fix commit. Its
`func_hash` locates an entry in `file_info.json`; scientific-notation float
hashes are matched only when they map uniquely to an integer key. The locator
provides `project_file_path`, `start_line`, `end_line`, `file_hash`, and an
optional legacy `local_file_path`.

The command writes a new JSONL file. It preserves each original input record
and adds `context` only when all extraction stages succeed. Empty relation
families are omitted. An unavailable or oversized sample receives
`"context": {}`; it never receives partial context.

## Source acquisition

The extractor first uses `local_file_path` if the referenced file exists under
the dataset root. Otherwise it obtains only the target source file:

1. Parse a supported GitHub `project_url`.
2. Read the fix commit metadata from the GitHub API and select its sole parent
   SHA as the vulnerable revision.
3. Download `project_file_path` from GitHub Raw at that parent SHA.
4. Cache the downloaded bytes under
   `data/primevul/context/files/<repository-id>/<parent-sha>/<file-hash>`.
5. Reject the sample if the URL is unsupported, the commit has zero or more
   than one parent, or the downloaded file cannot be fetched/read.

No full repository clone, mirror, checkout, or revision-level CPG is created.
The parent SHA and normalized source digest are recorded in the processing
report, not in the LLM context.

## File-level Joern extraction

The source file is staged with its original extension and parsed by Joern into
a CPG cached by source digest. The target method is selected only if its source
range contains `[start_line, end_line]`; ties are unavailable rather than
guessed. The extractor emits source-grounded candidates only from this file:

- includes/imports;
- direct same-file resolved callees;
- direct calls and their arguments;
- data-flow edges scoped to the target method when Joern supports them;
- conditions controlling retained call sites;
- target parameters, locals, and their types.

Each node or edge is mapped to compact source-level code, file, line, type and
relation fields. Invalid locations and empty snippets are omitted.

## Sparse context and budget

The output context contains only nonempty keys:

```json
{
  "imports": [],
  "callee_funcs": [],
  "call_relations": [],
  "call_site_arguments": [],
  "data_flow": [],
  "control_dependencies": [],
  "declarations": [],
  "types": []
}
```

The extractor first deduplicates and applies deterministic family caps, then
serializes the complete sparse object. It estimates its token size
conservatively. If it exceeds 2,000 tokens, it discards the entire context for
that record; it does not truncate individual fields or write a partial object.

## Operational behavior

`file-context build` supports `--limit 10` for pilot work and a per-record
report with `built`, `unavailable`, or `failed` outcomes. It is resumable:
source and file CPG caches are reused, while output is atomically rewritten
only after a full invocation succeeds. The runtime consumes the emitted JSONL
only and never invokes GitHub or Joern.

## Tests

Tests cover unique float-hash lookup, local-file preference, GitHub raw URL
construction, parent revision validation, source cache identity, exact method
range selection, sparse omission, rejection of oversized context, and the CLI
pilot limit. Joern subprocesses are isolated behind adapters and integration
tests remain opt-in.
