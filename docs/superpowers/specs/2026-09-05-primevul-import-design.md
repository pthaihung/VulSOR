# PrimeVul Import and Repository Preparation Design

## Goal

Turn the raw paired PrimeVul test export into a leakage-safe, queryable test
dataset, then prepare repository context in a separate Joern phase.

## Inputs

The importer reads only:

```text
data/primevul/primevul_test_pairs.jsonl
data/primevul/file_info.json
```

It selects only records with `target == 1`. This is the 435-sample vulnerable
side of the paired test export. Labels, CVE, CWE, commit message, and NVD
fields are never copied to runtime input, repository index, or prepared
catalogs.

`file_info.json` is keyed by the record's `func_hash`; its
`project_file_path`, `start_line`, and `end_line` provide the source locator.
A raw record without a valid matching locator is rejected during import and is
not assigned a guessed path.

## Import phase: Clang AST only

For each selected raw record with a valid locator, the importer writes its
`func` source to a temporary file using the source file extension and runs the
configured Clang frontend with JSON AST output. It accepts one explicit
function-like declaration whose source range belongs to the temporary main
file and covers the sampled function body. Its declaration name becomes
`function_name`.

Clang is not used for call graph, data-flow, control-flow, Git resolution, or
repository analysis. If parsing fails, produces no eligible declaration, or
produces multiple eligible declarations, the record is rejected with a
controlled import reason. The importer never extracts a name using a text
regular expression.

Each accepted sample ID is `test_<idx>`, where `idx` is the unique raw record
identifier within the selected test split. The importer atomically writes:

```text
data/primevul_withcontext/test.jsonl
data/primevul_withcontext/index.jsonl
data/primevul_withcontext/import-rejects.jsonl
```

`test.jsonl` has exactly `sample_id` and `code`. `index.jsonl` contains only
the repository URL/identity, 40-character revision, file path, function name,
source range, and normalized source hash.

## Preparation phase: Joern only

After import, `repo-context preprocess --all` is the sole phase that resolves
the exact Git revision, verifies the indexed source against the snapshot,
builds or reuses the revision-level Joern CPG, and smoke-checks it. It writes:

```text
data/primevul_withcontext/context/repos/
data/primevul_withcontext/context/cpg/
data/primevul_withcontext/context/catalog.jsonl
data/primevul_withcontext/context/unavailable.jsonl
```

Joern is therefore used after Clang-derived metadata is accepted, not as a
replacement for AST name extraction. Runtime remains query-only and returns
empty repository evidence if the sample is absent from `catalog.jsonl`.

## Validation

Tests must prove that target-zero records and protected fields never enter
output, locator lookup is keyed by `func_hash`, Clang ambiguity/failure creates
a sanitized reject, and output writes are atomic. An integration test may use
a fake Clang AST runner; real Joern remains an opt-in test and is not required
for importing data.
