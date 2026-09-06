# Targeted Source-Slice Repository Context

## Goal

Prepare repository context only for source needed by a selected vulnerability
sample, then run Joern only on that bounded source slice.  Runtime remains
query-only.

## Pipeline

`import-primevul` is local-only: it uses PrimeVul metadata and Clang AST to
write sample code plus a provisional repository locator.  It does not access
Git or Joern.

`prepare-context` is an explicit offline command accepting one sample, a list
of samples, or `--all`.  It resolves the selected sample's immutable source
revision, locates the target function, collects the target translation unit,
direct callers and callees, and source/header files needed by those units.  It
copies selected files with their repository-relative paths into a per-sample
source slice and records the selected functions/files in a manifest.

Joern parses only the slice.  The catalog records the CPG key, resolved
revision, source match, manifest digest, and limits applied.

## Bounds and limitations

The initial defaults are caller depth one, callee depth one, at most 20 files,
and at most 2,000 source lines.  External calls, system headers, and candidates
outside the budget are omitted and recorded as limitations.  The CPG therefore
provides bounded local/interprocedural context, not a guarantee of a complete
repository-wide call graph.

## Storage

Each prepared sample has `context/slices/<sample_id>/source/` and
`manifest.json`; CPG artifacts remain content-addressed under `context/cpg/`.
No repository mirror or source checkout is read by runtime queries.

## Failure behavior

Unresolvable repositories, missing sources, ambiguous matches, or a slice that
cannot be parsed are written to `unavailable.jsonl`.  Runtime returns empty
repository context for those samples.
