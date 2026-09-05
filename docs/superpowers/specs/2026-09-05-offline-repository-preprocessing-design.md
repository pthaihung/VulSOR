# Offline Repository Preprocessing and Query-Only Runtime Design

## Objective

Split repository context into two hard phases:

1. an offline preprocessing phase that is the only component allowed to
   materialize Git revisions and create Joern CPGs; and
2. a runtime retrieval phase that reads only validated prepared artifacts and
   invokes the bounded Joern evidence query.

This replaces the current hybrid behavior in which `query` can call
`prepare_sample`, fetch a repository, or build a missing CPG.

## Non-Negotiable Runtime Boundary

The runtime query path must never invoke:

- Git clone, fetch, checkout, `rev-parse`, or any `GitRepositoryResolver`;
- `joern-parse` or any CPG builder;
- CPG cache locks, cache promotion, deletion, or directory creation;
- network access.

It may only:

- read a prepared manifest, CPG, and immutable revision snapshot;
- validate paths, manifest identity, request/index correspondence, and source
  mapping;
- invoke `joern --script repository_evidence.sc` against the existing CPG;
- normalize the resulting bounded evidence.

If a required artifact is missing, invalid, or not READY, the result is an
empty `RepositoryEvidence(status="not_found", evidence=())` with the controlled
limitation `repository_context_unavailable`. The runtime does not attempt
recovery. Missing context is an expected coverage outcome, not a query error.

## Prepared Artifact Layout

The existing cache root is the offline artifact root:

```text
workspace/repository_context/
  revisions/<repository-url-sha256>/<revision>/  # immutable source snapshot
  cpg/<cpg-identity-sha256>/
    cpg.bin
    manifest.json
  prepared/<dataset>/<split>.jsonl
```

`revisions/` is produced and made read-only by the existing exact-revision Git
materializer. It remains available because source-grounded evidence can point
to arbitrary repository files, not just the target file.

Each nonblank `prepared/<dataset>/<split>.jsonl` line is a strict,
whitelisted record:

```json
{
  "sample_id": "test_000123",
  "repository": {
    "repository_id": "project",
    "repository_url": "https://example.test/project.git",
    "revision": "full-40-character-sha"
  },
  "target": {
    "file_path": "src/demo.c",
    "function_name": "target",
    "normalized_code_sha256": "sha256-of-normalized-sample"
  },
  "source_match": {"status": "exact", "start_line": 10, "end_line": 22},
  "cpg": {
    "cache_key": "sha256-cpg-identity",
    "joern_version": "4.0.592",
    "frontend": "C",
    "frontend_args": []
  },
  "status": "ready"
}
```

It contains no label, CWE/CVE, commit message, patch, paired-sample identity,
or source text. Failed preprocessing is written to a separate
`prepared/<dataset>/<split>.unresolved.jsonl` with a controlled failure kind
and never appears as a READY record.

## Offline Preprocessing

`vulsor repo-context preprocess` is the only command that accepts work capable
of changing the artifact root. It reads the dataset sample plus repository
index, then for each selected sample:

```text
index lookup
  -> verify sample hash
  -> Git resolve exact SHA and retain read-only snapshot
  -> unique source match in indexed file
  -> determine CPG identity
  -> build/reuse CPG under lock with joern-parse
  -> smoke-check the CPG with Joern
  -> atomically publish READY record
```

The command supports one sample for diagnosis and explicit `--all` for a whole
split. A split-wide run continues after expected per-sample failures, publishes
the READY and unresolved files atomically, and reports counts. The first run
for a shared repository revision may create a CPG; later samples at that same
revision reuse it.

Existing `repo-context prepare` is renamed to `preprocess` to make its
side-effecting role explicit. A compatibility alias is not retained: invoking
the old command must fail rather than obscuring phase boundaries.

## Query-Only Runtime

`vulsor repo-context query` loads one sample, its `prepared/<dataset>/<split>`
record, and the request. It then:

```text
READY record lookup
  -> verify request repository and target anchor match the record
  -> verify sample hash and source span against immutable snapshot
  -> validate existing manifest/cpg.bin read-only
  -> joern evidence script query
  -> source-grounded normalization and budgeting
```

The runtime does not call `JoernAdapter.version()` or `smoke()`: version and
smoke validation are preprocessing responsibilities. The query call itself is
the only subprocess permitted at runtime. `status` is read-only and reports
whether a READY record references a structurally valid local CPG; it does not
run Joern.

The runtime service is constructed with a read-only prepared-artifact reader,
not `GitRepositoryResolver` or mutable `CpgCache`. This makes the no-fetch and
no-build property enforceable by dependency shape, not merely by convention.

## Joern Environment

This workstation uses:

```text
Joern: E:\tools\joern-v4.0.592\joern-cli\joern.bat
Parser: E:\tools\joern-v4.0.592\joern-cli\joern-parse.bat
JDK home: E:\tools\jdk-21.0.12+1\jdk-21.0.12.1+1
```

The tracked project config remains machine-neutral. A developer supplies those
paths in an ignored local YAML config and starts commands with `JAVA_HOME` and
`JAVACMD` set to the JDK 21 paths. Joern 4.0.592 supports `--script` and
`--param`, but does not implement the adapter's current `joern --version`
contract; preprocessing obtains and persists the compatible version using a
version probe tailored to this release.

## Failure Semantics

- no prepared record: empty `not_found` evidence with
  `repository_context_unavailable`;
- record is unresolved: empty `not_found` evidence with
  `repository_context_unavailable`;
- snapshot, manifest, or CPG missing/corrupt: empty `not_found` evidence with
  `repository_context_unavailable`;
- request/index/record mismatch: `not_found` or `unavailable`, without query;
- Joern query failure: `unavailable`, without any fallback preprocessing;
- source mapping or budget limitation: existing `partial` behavior.

## Tests and Acceptance Criteria

Tests must prove all of the following:

1. preprocessing resolves a revision, validates source, builds/smokes a CPG,
   and publishes a READY record;
2. a second sample at the same identity reuses the CPG;
3. query with READY artifacts invokes only `joern.query`;
4. query with no record, unresolved record, absent snapshot, or absent CPG
   returns empty `not_found` evidence and never instantiates/calls Git
   resolution, CPG build, smoke, or `joern-parse`;
5. split preprocessing publishes READY and unresolved outputs without leaking
   protected raw metadata;
6. `status` is still side-effect-free;
7. the real Joern integration test uses the configured 4.0.592 environment
   when explicitly enabled.

This remains independent of B1/B2. B3/B4 integration is still deferred; only
their future `EvidenceRequest` will consume the query-only service.
