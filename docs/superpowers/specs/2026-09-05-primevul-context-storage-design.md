# PrimeVul Context Storage Layout

## Goal

Keep the source PrimeVul export immutable while placing all normalized input and
repository-context artifacts in one compact, portable directory.

## Layout

```text
data/
├── primevul/
│   ├── primevul_test_pairs.jsonl
│   └── file_info.json
│
└── primevul_withcontext/
    ├── test.jsonl
    ├── index.jsonl
    └── context/
        ├── repos/
        ├── cpg/
        ├── catalog.jsonl
        └── unavailable.jsonl
```

`data/primevul/` is read-only input.  It is never rewritten by preparation or
runtime commands.

`data/primevul_withcontext/test.jsonl` contains only the sample identifier and
source code used at runtime.  `index.jsonl` contains the corresponding
repository locator, exact revision, source file path, function name, source
range, and normalized source hash.  It contains no label, CVE, or CWE fields.

The `context/` directory is an implementation-owned artifact cache:

- `repos/` stores Git mirrors and immutable revision snapshots.
- `cpg/` stores one manifest-validated Joern CPG per repository URL, revision,
  Joern version, frontend, and frontend arguments.
- `catalog.jsonl` contains only samples whose snapshot, source anchor, and CPG
  were prepared successfully.
- `unavailable.jsonl` contains a sample ID and one controlled failure kind for
  each sample without usable context.  It never contains raw exceptions.

The old filename `ready.jsonl` is not used.  The status value inside a catalog
record remains `"ready"`; the filename is `catalog.jsonl` because it is the
runtime lookup catalog.

## Runtime boundary

Runtime reads `test.jsonl`, `index.jsonl`, `context/catalog.jsonl`, the
referenced revision snapshot, and the referenced CPG.  It does not clone,
fetch, checkout, build a CPG, or smoke-test a CPG.  A sample absent from the
catalog or listed as unavailable yields empty repository evidence.

## Migration requirements

The repository-context configuration and catalog path helpers must be updated
to use this layout.  Existing cache content may remain in the legacy layout;
it is not moved or deleted automatically.  A fresh offline run writes the new
layout atomically.
