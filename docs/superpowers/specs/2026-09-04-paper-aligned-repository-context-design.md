# Paper-Aligned Repository Context Design

## Objective

Add a repository-context subsystem that reproduces the paper's selective
evidence flow without reintroducing repository data into B1 or B2. The
subsystem resolves each dataset sample to its exact repository revision,
preprocesses that revision into one cached Joern CPG, and answers bounded,
obligation-anchored evidence requests from future B3/B4 stages.

## Paper Constraints

The implementation must preserve these invariants:

1. The target function remains the primary analysis unit.
2. B2 receives only the target function and local program-analysis artifacts.
3. Project-specific semantics that cannot be established locally remain
   unresolved.
4. Repository retrieval starts only when B3 or B4 submits a concrete missing
   semantic property anchored to an operation or entity.
5. One repository revision is preprocessed once and reused by samples that
   resolve to that same revision.
6. Queries are bounded by structural and source-context budgets.
7. CPG nodes and paths are mapped back to source locations before they leave
   the subsystem.
8. Repository output contains facts and limitations, never an obligation,
   CWE, vulnerability hypothesis, or verdict.
9. Patch diffs, labels, paired counterparts, CVE descriptions, commit
   messages, and other answer-bearing metadata never enter an evidence
   request or evidence response.

## Scope

The subsystem owns:

- normalized sample-to-repository metadata;
- Git repository mirroring and exact revision materialization;
- target-function/source validation;
- Joern CPG creation, validation, manifests, locking, and cache reuse;
- source-anchor resolution inside a CPG;
- call, argument, data-flow, control-dependence, declaration, and type
  queries;
- evidence normalization, ranking, deduplication, budgeting, provenance, and
  limitation reporting;
- standalone CLI commands and an application service callable by B3/B4.

It does not own:

- B1 program analysis or B2 semantic reconstruction;
- generation or interpretation of semantic obligations;
- deciding whether evidence establishes a violation;
- repository-wide vulnerability discovery;
- LLM tool access from B2.

## Architecture

```text
PrimeVul metadata + function sample
              |
              v
Repository index builder/loader
              |
              v
RepositoryRef + TargetAnchor
              |
              v
GitRepositoryResolver -> exact revision workspace
              |
              v
SourceMatcher -> exact / normalized / mismatch
              |
              v
CpgCache -> cache hit or JoernBuilder
              |
              v
EvidenceRequest from B3/B4
              |
              v
AnchorResolver -> QueryEngine -> EvidenceNormalizer
              |
              v
EvidenceRanker/BudgetFilter
              |
              v
RepositoryEvidence for B3/B4
```

The Python implementation lives under `src/vulsor/repository_context/`.
Joern scripts live under `scripts/joern/` and must print exactly one JSON
document to stdout; diagnostic text is written to stderr. Python is the owner
of process timeouts, cache paths, schema validation, and output persistence.

## Data Contracts

### Repository index

Repository metadata is deliberately separate from `DatasetSample`. The
normalized per-split index is stored as
`<repository_index_dir>/<split>.jsonl` and contains only locator data:

```json
{
  "sample_id": "test_000123",
  "repository": {
    "repository_id": "imagemagick",
    "repository_url": "https://github.com/ImageMagick/ImageMagick.git",
    "revision": "full-commit-sha"
  },
  "target": {
    "file_path": "coders/foo.c",
    "function_name": "WriteFOOImage",
    "start_line": 120,
    "end_line": 190,
    "normalized_code_sha256": "..."
  }
}
```

The index builder accepts explicit field mappings for raw PrimeVul metadata.
It whitelists output fields and rejects records without an exact repository
URL, revision, and file path. If raw metadata identifies a fixing commit but
not the sample's exact revision, candidate revisions may be checked against
the function code; no candidate is accepted unless the source matcher finds
one unique match.

### EvidenceRequest

```json
{
  "request_id": "req_001",
  "phase": "instantiate",
  "obligation_ref": "draft_obl_001",
  "repository_ref": {
    "repository_id": "imagemagick",
    "repository_url": "https://github.com/ImageMagick/ImageMagick.git",
    "revision": "full-commit-sha"
  },
  "anchor": {
    "file_path": "coders/foo.c",
    "function_name": "WriteFOOImage",
    "operation_kind": "call",
    "operation_name": "WriteImages",
    "line": 157,
    "column": 5,
    "argument_index": 2,
    "entity": "write_images"
  },
  "questions": ["callee_definition", "argument_usage", "nullability"],
  "allowed_relations": [
    "call",
    "argument",
    "data_flow",
    "control_dependence",
    "declaration",
    "type"
  ],
  "budget": {
    "max_call_depth": 2,
    "max_flow_paths": 10,
    "max_nodes": 150,
    "max_source_lines": 200,
    "max_evidence_items": 30
  }
}
```

`phase` is either `instantiate` for B3 contract recovery or `evaluate` for B4
grounding. The request is invalid unless it contains an anchor, at least one
question, at least one allowed relation, and positive finite budgets.

### RepositoryEvidence

```json
{
  "request_id": "req_001",
  "status": "complete",
  "resolved_revision": "full-commit-sha",
  "anchor_resolution": {
    "status": "exact",
    "candidate_count": 1
  },
  "evidence": [
    {
      "evidence_id": "repo_ev_001",
      "kind": "callee_parameter_use",
      "subject": "WriteImages.parameter[2]",
      "relation": "used_as_dereference_base",
      "object": "write_images",
      "conditions": [],
      "source": {
        "file_path": "magick/image.c",
        "start_line": 311,
        "end_line": 314,
        "code": "..."
      },
      "provenance": {
        "query_family": "call_argument",
        "cpg_node_types": ["METHOD_PARAMETER_IN", "IDENTIFIER", "CALL"]
      }
    }
  ],
  "limitations": [],
  "budget_usage": {
    "nodes": 47,
    "flow_paths": 3,
    "source_lines": 62,
    "evidence_items": 1,
    "truncated": false
  }
}
```

Status is one of `complete`, `partial`, `unavailable`, `not_found`, or
`ambiguous`. Empty or truncated results retain an explicit limitation; absence
inside a bounded query is not represented as proof that a relation is absent.

## Repository and Revision Handling

Repositories are mirrored once per canonical URL. Revision workspaces are
read-only analysis inputs materialized by full commit SHA. The subsystem does
not run configure scripts, builds, package managers, hooks, or executables from
an analyzed repository.

Before CPG construction, the source matcher validates the dataset function
against the target file. It tries exact text first and then normalized line
endings/whitespace. Fuzzy similarity is reported for diagnostics only and
never accepted as proof of a revision match.

## CPG Cache

The cache key is the SHA-256 digest of canonical repository URL, full revision,
Joern version, language frontend, and frontend arguments. Each entry contains
`cpg.bin` and `manifest.json`. A cache is reusable only when the manifest is
complete, its key matches, the CPG exists and is non-empty, and a smoke query
loads it successfully.

CPGs are built under a temporary sibling directory while holding a per-key
lock, then atomically promoted. A failed or timed-out build never becomes a
valid cache entry.

## Query Families

The query engine dispatches only request-approved families:

- call/argument: exact call site, caller, callee, call-in/call-out, arguments,
  and parameter mapping;
- data flow: sources reaching anchored arguments or operations, with bounded
  `reachableBy`/`reachableByFlows` paths;
- control dependence: guards, dominance, post-dominance, and early-exit
  relations around the anchor;
- declaration/type: local, parameter, member, method signature, type, and type
  declaration facts.

Anchor resolution uses normalized file path, method name/signature when
available, operation name, line, column, and code. Joern node IDs are retained
only as within-response provenance and never used as durable cross-build IDs.

## Evidence Selection and Budgeting

Evidence is ranked in this order:

1. exact anchored operation;
2. directly referenced arguments/entities;
3. callee definitions and corresponding parameter uses;
4. shortest data-flow paths;
5. direct control conditions and dominance relations;
6. depth-one then depth-two call neighbors.

Duplicate source spans and graph relations are collapsed. Truncation removes
whole evidence items or whole paths, never partial JSON or half a path. Budget
usage and truncation are always reported.

## Existing Project Changes

1. Keep `DatasetSample` in `src/vulsor/datasets.py` code-only. Add repository
   metadata loading under the new package rather than restoring a context
   sidecar.
2. Extend `ToolsConfig` with Git and Joern executables and add a separate
   `RepositoryContextConfig` with cache, timeout, and budget settings.
3. Add a top-level `repo-context` CLI with `index`, `prepare`, `query`, and
   `status` actions. It remains independent of `run_pipeline` until B3/B4 are
   implemented.
4. Extend `doctor` to check Git and Joern only when repository-context checks
   are requested or repository context is enabled.
5. Do not register repository tools in the B2 agent tool registry.
6. Rename the B2 artifact `semantic_cpg.json` to `semantic_graph.json` and its
   artifact kind to `semantic_graph_overlay`, preventing confusion with the
   revision-level Joern CPG.
7. Do not restore the deleted per-sample `scripts/joern/b1_facts.sc` or
   `src/vulsor/tools/joern.py` architecture.

## Failure Semantics

- Missing repository metadata: `not_found` with `repository_ref_missing`.
- Clone/fetch/checkout failure: `unavailable` with sanitized command details.
- Source/revision mismatch: `not_found` with `source_mismatch`; no CPG query.
- CPG build/load failure or timeout: `unavailable`; incomplete cache removed or
  ignored.
- Zero anchor candidates: `not_found`.
- Multiple anchor candidates: `ambiguous`; no arbitrary first-node fallback.
- Query-family failure: preserve successful families, return `partial`, and
  record the failed family.
- Budget exhaustion: `partial` with `truncated=true`.

## Testing Strategy

Unit tests use temporary local Git repositories and a fake Joern process
adapter; they require no network or Joern installation. Contract, index,
revision matching, cache keys, locking, command construction, anchor parsing,
normalization, ranking, and failure semantics are tested independently.

An opt-in integration test marked `joern` runs against a small C/C++ fixture
when the configured Joern executables are available. It verifies call,
argument, data-flow, control, declaration/type, and source mapping output. The
normal test suite skips it cleanly when Joern is absent.

## Acceptance Criteria

The subsystem is complete when it can:

1. resolve a normalized sample to one exact local revision;
2. build one CPG and reuse it for a second sample on the same revision;
3. reject a source/revision mismatch;
4. resolve one exact operation anchor;
5. answer every supported query family with source-grounded JSON;
6. enforce every budget and report truncation;
7. return partial/unavailable results without inventing evidence;
8. run independently through the CLI and through a Python service interface;
9. leave B1/B2 artifacts free of repository evidence and answer-bearing
   metadata.
