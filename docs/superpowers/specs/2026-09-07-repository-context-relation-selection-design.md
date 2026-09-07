# Repository Context Relation Selection

## Goal

Build compact, source-grounded repository context for a PrimeVul function-level
sample. The sample function identifies the root scope of the query. Evidence may
cross that function boundary when caller, callee, global, member, header, type,
or macro relations are relevant.

The prompt-ready output contains only:

1. `[DATA DEPENDENCIES]`
2. `[CONTROL DEPENDENCIES]`
3. `[DECLARATIONS, TYPES AND CONTRACTS]`
4. `[CALL RELATIONS]`

Risk anchors or seeds are internal selection metadata and are never rendered as
a prompt section.

## Architecture

The offline pipeline has two responsibilities. Joern produces a bounded pool of
source-grounded relation candidates from the exact function and repository
revision. A deterministic Python selector then chooses, merges, ranks, and
budgets the evidence. Runtime reads the resulting JSONL and invokes no Git,
Clang, Joern, or CPG operation.

```text
PrimeVul sample function
        |
exact repository revision and function resolution
        |
Joern candidate extraction from the function and relevant neighbors
        |
internal seed selection and fallback
        |
Python relation selection, deduplication, and budgeting
        |
four-section context.jsonl record
```

## Query root and internal seeds

The exact sample function is the query root, not the final context boundary.
Joern may traverse to direct callers and callees, declarations in headers,
referenced globals and members, and macro contracts in repository source.

Within that scope, internal seeds prioritize:

- pointer dereference, indexing, and pointer arithmetic;
- allocation, copy, parsing, conversion, and memory-sensitive calls;
- size, length, count, offset, and index arithmetic;
- return expressions and error-producing operations.

Seed records remain in raw offline metadata so relation provenance can be
audited. They are not evidence sections shown to the model.

When no prioritized seed is available, selection starts from function
parameters, return expressions, and sensitive direct calls. If none exist, it
uses direct calls and referenced non-local values in source order. An exactly
resolved function therefore produces relation context when source-grounded
candidates exist; failure to find a risk seed alone does not make context empty.

## Candidate extraction

Joern emits source-grounded candidates with `code`, normalized repository file,
positive source line, relation family, source node identity, and provenance.
Candidates without source code or location are discarded.

### Data dependencies

For every internal seed, Joern performs a bounded backward data-flow traversal.
It retains assignments, parameters, call results, literals, referenced globals
or members, and size or offset expressions that contribute to the seed. The
default maximum traversal depth is six edges.

CPG reaching-definition or data-flow edges have priority. When those edges are
unavailable, a same-function syntactic assignment walk may be emitted with
provenance `syntactic_assignment_fallback`. Fallback evidence must not be
presented as a proven reaching definition or alias relation.

### Control dependencies

Control candidates are collected for retained data nodes and seeds. Joern uses
control-dependence edges first and enclosing source control structures second.
The selector retains controls only when they reference a retained entity or
govern a retained source node.

Controls receive one of these roles:

- `null_check`;
- `bounds_check`;
- `overflow_check`;
- `type_or_format_dispatch`;
- `loop_bound`;
- `other_guard`.

The first five roles rank above `other_guard`. Large control bodies are reduced
to their condition expression and source location rather than emitted as whole
blocks.

### Declarations, types, and contracts

The extractor collects declarations and resolved types for every retained data
entity, including parameters, locals, members, globals, and relevant function
signatures. Duplicate macro-expanded locals are merged by symbol and type.

When a retained expression originates from a macro invocation, the offline
source reader emits the minimal definition fragment that explains assignment,
increment, size, or bounds behavior. A macro definition is a contract and is
not emitted as a call relation.

### Call relations

Calls are retained only when they define, validate, transform, or consume a
retained data entity, or connect the target function to a relevant direct
caller or callee. Operator nodes, macro invocations already represented as
contracts, repeated formatting calls, and unrelated calls on the same source
line are excluded.

Interprocedural traversal is bounded to one direct caller/callee hop for the
initial implementation. Deeper traversal is outside this change.

## Selection and budgets

The Python selector normalizes candidates and deduplicates by relation family,
normalized file, source line, code, role, and provenance. It preserves source
order within equal priority and does not synthesize missing relations.

Budgets are deterministic:

```text
internal seeds:                  2
data facts per seed:             8
control facts per seed:          10
declaration/type facts total:    12
contract source lines total:     15
call facts total:                12
caller/callee depth:             1
data traversal depth:            6
rendered context characters:     8,000
```

The renderer keeps complete facts only. When a relevant candidate is removed by
a family or character budget, the record includes `context_truncated`.

## Failure behavior

- A missing repository, revision, CPG, or exact function resolution produces an
  unavailable record through the existing offline error path.
- Missing prioritized seeds activates the fallback selection policy.
- An unavailable relation family produces a family-specific limitation.
- A failed graph query does not silently become syntactic evidence; fallback
  provenance and limitations remain explicit.
- Prompt rendering never invents evidence to fill an empty section.

## Storage contract

Joern candidate payloads, repositories, CPGs, and workspaces are temporary
offline artifacts. The durable runtime artifact is one JSONL record per sample:

```json
{"sample_id":"test_194963","context":"...","limitations":[]}
```

The `context` value contains the four fixed sections. Internal seed metadata is
not persisted in the prompt text.

## Verification

Automated tests cover data traversal, syntactic fallback provenance, control
role filtering, symbol/type closure, macro-call exclusion, direct call
relevance, no-seed fallback, deterministic deduplication, and all budgets.

The existing `test_194963` smoke case must retain the chain involving `p1`,
`p`, `q`, `dir_offset`, `number_bytes`, `components`, and `format`, together
with associated bounds and overflow checks and the `EXIFMultipleValues`
contract. It must not render an anchor section.

After this case passes, evaluation runs on 10–20 samples selected to cover:

- pointer dereference and array indexing;
- size or offset overflow;
- memory-sensitive library calls;
- macro-expanded operations;
- caller/callee context;
- no prioritized risk seed;
- missing or incomplete data-flow overlays.

Batch preprocessing begins only after the representative sample set produces
bounded, source-grounded context without unrelated function-wide dumps.
