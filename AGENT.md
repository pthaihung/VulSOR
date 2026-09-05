# VulSOR - Project Context

> Current project context for future VulSOR sessions.
> Encoding target: UTF-8 content using ASCII text only. Avoid decorative
> Unicode and emoji because Windows terminals in this workspace can render
> Vietnamese accents as mojibake.

---

## 1. Project Goal

VulSOR is a C/C++ vulnerability detection framework at function level.
The intended approach is semantic-obligation-based reasoning, not fine-tuning.

Default semantic agent retrieval guide:

```text
brain_context/AGENT_GUIDE.md
```

Every semantic agent should read `brain_context/AGENT_GUIDE.md` first for its
role/boundary contract, then `AGENT.md`, then
`brain_context/{dataset}/{split}/manifest.json`.

Intended flow:

```text
C/C++ source
-> Program facts
-> Semantic reconstruction
-> Safety obligations
-> Grounding / validation
-> Verification evidence
-> Final verdict: VULNERABLE / BENIGN
```

Important boundary:

| Component | Allowed | Not allowed |
|---|---|---|
| Tools | Produce facts from code | Infer vulnerability verdict |
| Program analysis | AST, CFG, data-flow, call graph, fact links, context facts | Produce verdict |
| LLM | Interpret semantics and propose obligations | Prove feasibility by itself |
| Validator | Ground obligations into facts/rules/context | Invent evidence |
| Verifier | Find real evidence | Trust LLM claims as evidence |
| Adjudicator | Make final decision from evidence | Invent missing facts |

Core rule:

```text
tools -> facts
LLM -> interpretation / obligation proposal
validator -> grounding
verifier -> evidence
adjudicator -> verdict
```

---

## 2. Current Pipeline Status

| Stage | Status | Notes |
|---|---|---|
| B1 Program Analysis | Mostly implemented, still limited | Clang AST, CFG parser, syntactic data-flow, syntactic call graph, fact links, and function-only dataset inspection |
| B2 Semantic Reconstruction | Started | State/Value/Execution/Operation agents exist as OOP classes; deterministic semantic fallback exists; optional LLM API interpretation and tool access are configured separately |
| B3 Obligation Generation | Not implemented | No LLM obligation generation yet |
| B4 Obligation Validation | Not implemented | No real validator yet |
| B5 Violation Verification | Not implemented | No runtime/symbolic evidence yet |
| B6 Adjudication | Not implemented | No final verdict yet |
| B7 CWE + Localization | Not implemented | Derived only after verdict |
| B8 PrimeVul Evaluation | Partially implemented | Dataset inspection exists; verdict evaluation does not |

Do not remove unimplemented stages from this file. This document must keep both
implemented and pending pipeline work.

---

## 2.1 Full Pipeline Roadmap

Target pipeline:

```text
B1 Program Analysis
  Input: C/C++ source or PrimeVul sample
  Output: AST/CFG/data-flow/call graph/CPG facts, source locations, fact links,
          source context facts
  Status: mostly implemented, still limited

B2 Semantic Reconstruction
  Input: Program facts from B1
  Output: semantic views: State, Value, Execution, Operation
  Status: started; State/Value/Execution/Operation agents implemented with
          merge artifact, JSON prompts, dedicated LLM YAML config, and
          allowlisted artifact tools; B2 remains interpretation-only

B3 Obligation Generation
  Input: semantic views + operation facts
  Output: safety obligations attached to operations/state transitions
  Status: not implemented

B4 Obligation Validation / Grounding
  Input: obligations + facts + rules + context
  Output: grounded obligations, rejected obligations, missing evidence requests
  Status: not implemented

B5 Violation Verification
  Input: grounded obligations
  Output: real evidence for feasible violation, or evidence that no violation
          was found
  Status: not implemented

B6 Adjudication
  Input: facts + obligations + validation + verification evidence
  Output: VULNERABLE / BENIGN
  Status: not implemented

B7 CWE + Localization
  Input: final verdict + supporting evidence
  Output: CWE mapping and vulnerable/fix-relevant source locations
  Status: not implemented

B8 PrimeVul Evaluation
  Input: PrimeVul clean samples + labels kept separate
  Output: metrics, per-sample predictions, optional pair-level analysis
  Status: dataset inspection exists; verdict evaluation does not
```

Do not treat B2-B8 as complete just because B1 can produce JSON. In
`PipelineResult`, fields such as `semantics`, `obligations`, `verdict`, and
`evidence` are currently `None` or empty until their real stages are
implemented.

---

## 3. B1 Program Analysis Status

Preferred technical order:

```text
AST -> CFG -> data-flow -> call graph
```

Current implementation:

| Item | Status | Source |
|---|---|---|
| Clang adapter | Implemented | `src/vulsor/tools/clang.py` |
| AST JSON | Real Clang call | `-Xclang -ast-dump=json` |
| Source locations | Implemented | line/column, fallback from byte offset |
| Function facts | Implemented | `FunctionDecl` with body |
| Operation facts | Implemented | `CallExpr` |
| Definitions | Implemented | `ParmVarDecl`, `VarDecl` |
| Uses | Implemented | `DeclRefExpr` pointing to local declaration |
| CFG facts | Implemented but fragile | `debug.DumpCFG`, depends on Clang semantic analysis |
| CFG parser | Basic implementation | basic blocks, edges, branch condition |
| Data-flow | Implemented, syntactic | same variable + source order |
| Call graph | Implemented, syntactic | caller -> callee, linked by `operation_id` |
| Fact links | Implemented | function -> facts, operation -> call, definition -> use |
| Dataset input boundary | Implemented | function snippet only; no sidecar or whole-file loading |
| Evidence | Not implemented | `verification/*` has no real verifier yet |

Dataset inspection is intentionally limited to the function source supplied in
`inputs/{split}.jsonl`. Repository-wide context retrieval is reserved for the
future obligation-driven B3/B4 stages.

Data-flow no longer depends on CFG. If CFG fails but AST recovers definitions
and uses, VulSOR still builds syntactic data-flow.

## 4. ProgramFacts

`ProgramFacts` contains tool/analysis facts only:

```text
functions
operations
control_flow
definitions
uses
data_flow
cfg_blocks
call_graph
```

Main facts:

| Fact | Meaning |
|---|---|
| `FunctionFact` | function id, name, start_line, end_line |
| `OperationFact` | call/operation id, kind, name, source location, arguments |
| `CFGBlock` | basic block id and statements from Clang CFG text |
| `CFGEdge` | source block, target block, branch condition |
| `DefinitionFact` | variable definition/declaration, location, AST node id |
| `UseFact` | variable use, location, AST node id |
| `DataFlowFact` | syntactic reaching-definition from definition to use |
| `CallGraphEdge` | caller, callee, location, `operation_id` |

Fact links:

| Link | Meaning |
|---|---|
| `function_links` | groups operations/definitions/uses/call edges by function |
| `operation_call_links` | links `OperationFact` to `CallGraphEdge` |
| `definition_use_links` | links `DefinitionFact` -> `UseFact` through `DataFlowFact` |
| `unresolved_notes` | records facts that cannot be linked yet, e.g. CFG block source location |

ProgramFacts contains only facts extracted from the target function source.
Missing project symbols are recorded as limitations and are not replaced with
repository guesses.

---

## 5. Inspect Output

CLI dataset inspect:

```powershell
vulsor inspect --config configs\primevul.yaml --dataset primevul --split test --limit 1 --format json
```

The dataset inspect command analyzes each `code` field at function scope and
writes per-sample artifacts for later B2 stages:

```text
brain_context/{dataset}/{split}/manifest.json
brain_context/{dataset}/{split}/{sample_id}.json
```

The artifact contains `program_facts`, local analysis completeness,
`missing_context`, diagnostics, limitations, and fact links. It does not
contain repository sidecars or repository CPG facts.

Interactive output reports source, AST, CFG, data-flow, and call-graph status.
The `brain_context` directory is an artifact cache name; it is not repository
context supplied to B2.

B2 should read Program Analysis input from `brain_context`, not from terminal
output and not directly from PrimeVul labels.

Semantic agent CLI:

```powershell
vulsor agent --agent state --dataset primevul --split test --sample test_000000
vulsor agent --agent value --dataset primevul --split test --sample test_000000
vulsor agent --agent execution --dataset primevul --split test --sample test_000000
vulsor agent --agent operation --dataset primevul --split test --sample test_000000
```

Run all B2 semantic agents and merge their brain views:

```powershell
vulsor agent --agent all --dataset primevul --split test --sample test_000000
```

B2 output remains under:

```text
brain_context/{dataset}/{split}/agents/{sample_id}/
```


## 5.1 B2 Semantic Agent Architecture

B2 is implemented under `src/vulsor/agents/`:

| File | Responsibility |
|---|---|
| `BaseAgent.py` | Shared agent lifecycle: read artifact, read guides/prompts, compute cache key, call deterministic view builder, optionally call LLM, write JSON output |
| `StateAgent.py` | Concrete OOP agent for `state_view` |
| `ValueAgent.py` | Concrete OOP agent for `value_view` |
| `ExecutionAgent.py` | Concrete OOP agent for `execution_view` |
| `OperationAgent.py` | Concrete OOP agent for `operation_view` |
| `SemanticViews.py` | Deterministic local semantic view builders and shared semantic helpers |
| `LLMClient.py` | OpenAI-compatible transport client for JSON chat completions |
| `prompts/*.json` | Agent-specific prompt config and boundary text |

Do not put B3/B6 placeholder files in `src/vulsor/agents/` until those stages
are implemented. Empty files such as old `obligation.py`, `adjudicator.py`, or
misspelled `sematic.py` should not be restored.

Concrete class structure:

```text
BaseAgent
  StateAgent
  ValueAgent
  ExecutionAgent
  OperationAgent
```

Each concrete agent overrides:

```text
build_local_view(artifact) -> dict
```

The returned dict is inserted into one of:

```text
state_view
value_view
execution_view
operation_view
```

The local deterministic output is always generated. If `--llm` is used, the
LLM reads the existing matching brain and source, then stores its output under
the `llm` field in the brain artifact and copies the complete agent result to
`experiments/{dataset}/{split}/{agent}/{sample_id}.json`. LLM reasoning is
interpretation only. It must not replace grounded facts and must not become
verification evidence.

### B2 Output Contract

Each per-agent artifact has this high-level shape:

```text
schema_version
artifact_kind
agent
status
sample_id
source_status
{agent}_view
llm:
  enabled
  provider
  model
  result
_meta:
  cache_key
  input artifact/hash
  guide path/hash
  prompt path/hash/id/version
  runtime
  view_validation
  limitations
  boundary
```

The canonical merge artifact for B3 is:

```text
brain_context/{dataset}/{split}/agents/{sample_id}/agent_semantics.json
```

The merge is deterministic and does not call the LLM.

and contains:

```text
agent_semantics:
  sample_id
  source_artifact
  state_view
  value_view
  execution_view
  operation_view
  cross_view_links
  missing_semantic_context
  inherited_limitations
```

### B2 LLM Configuration

LLM transport/config is not stored in the general project config. It is stored
in:

```text
configs/agent_llm.yaml
```

Current fields:

```yaml
provider: openai_compatible
base_url: https://api.openai.com/v1/chat/completions
model: gpt-4.1-mini
api_key_env: OPENAI_API_KEY
temperature: 0.0
timeout_seconds: 60
max_tool_rounds: 1
allowed_tools:
  - get_program_facts
  - get_fact_links
  - get_completeness
  - get_limitations

OpenRouter uses the same OpenAI-compatible client. Configure it independently
for any agent, for example:

```yaml
agents:
  state:
    provider: openrouter
    base_url: https://openrouter.ai/api/v1/chat/completions
    model: openai/gpt-4.1-mini
    api_key_env: OPENROUTER_API_KEY
    extra_headers:
      HTTP-Referer: https://example.com
      X-Title: VulSOR
```

Then set the key in PowerShell without placing it in YAML:

```powershell
$env:OPENROUTER_API_KEY = "your-key"
```

Per-agent overrides are configured below the shared fields:

```yaml
agents:
  state:
    model: state-model
    max_tool_rounds: 2
    allowed_tools:
      - get_program_facts
  value:
    model: value-model
  execution:
    model: execution-model
  operation:
    model: operation-model
```

An agent inherits any field omitted in its section from the shared settings.
```

The API key is read from `api_key_env`. Do not write API keys into config
files, prompts, tests, logs, or artifacts.

### B2 Prompt Files

Prompts are JSON files:

```text
src/vulsor/agents/prompts/state.json
src/vulsor/agents/prompts/value.json
src/vulsor/agents/prompts/execution.json
src/vulsor/agents/prompts/operation.json
```

Each prompt file currently contains:

```text
prompt_id
version
agent
view_key
system
required_boundaries
```

Do not convert these prompts back to `.txt`; the JSON shape is intentional so
prompt metadata can be versioned and validated later.

### B2 LLM Tool Access

LLM tool implementations live in the existing package:

```text
src/vulsor/tools/agent_tool_registry.py
```

These tools are not general repository tools. They expose only data already
recorded in the current B1 artifact. They must not:

```text
read arbitrary repository files
run analyzers again
fetch network context
use labels/CWE/CVE/pair metadata
produce verdicts
produce vulnerability evidence
```

Current allowlisted tool names:

| Tool | Purpose |
|---|---|
| `get_program_facts` | Return all or selected `program_facts`; accepts optional `fact_type` and `limit` |
| `get_fact_links` | Return `analysis.links` |
| `get_completeness` | Return `analysis.completeness` and `analysis.build_diagnosis` |
| `get_limitations` | Return inherited `limitations` and `rules` |

The LLM receives an `available_tools` manifest and a `tool_call_contract`.
When it needs more current-artifact detail, it may return:

```json
{
  "tool_requests": [
    {
      "tool": "get_program_facts",
      "arguments": {
        "fact_type": "operations",
        "limit": 50
      }
    }
  ]
}
```

VulSOR runs only allowlisted tools from `configs/agent_llm.yaml`, then sends
`tool_results` back to the LLM for the final semantic JSON. If a requested tool
is not allowlisted, it is rejected and recorded as such.

### B2 Anti-Leakage Rule

B2 code and tools must strip or ignore these metadata keys:

```text
target
cwe
cve
cve_desc
nvd_url
pair_id
commit_id
commit_url
commit_message
side
```

The target function in B2 is derived from local `ProgramFacts.functions`.
Dataset label fields named `target` are not allowed as reasoning input.

---

## 6. Rules, Limitations, Diagnosis

`rules` are fixed Program Analysis policy:

```text
tools produce program facts only
program analysis does not infer VULNERABLE/BENIGN verdicts
missing project symbols are reported as limitations, not fabricated
dataset labels, CWE, CVE, and pair metadata are not used as analysis input
```

`limitations` are semi-dynamic per sample. They depend on Clang diagnostics,
CFG availability, and the quality of syntactic local data-flow.

Current meaning:

```text
AST/call facts:
  Usually recoverable if Clang can parse the function snippet.
  Partial if Clang emits diagnostics.

CFG:
  May be missing when the function snippet lacks project declarations or
  when local Clang analysis cannot produce a CFG dump.

Data-flow:
  Syntactic AST-based reaching-definition only.
  Does not prove path feasibility, aliasing, pointer flow, field flow, macro
  expansion, or interprocedural flow.
```

`build_diagnosis` reports local Clang and parser limitations. Repository
context is not silently inferred or loaded by B1.

---

## 7. PrimeVul Clean Dataset

PrimeVul clean is used to avoid leakage. The B1 loader reads only the source
inputs; labels and pair metadata stay outside the analysis artifact.

For the compact PrimeVul repository-context layout:

```text
data/primevul/primevul_test_pairs.jsonl
data/primevul/file_info.json
data/primevul_withcontext/test.jsonl
data/primevul_withcontext/index.jsonl
data/primevul_withcontext/context/{repos,cpg,catalog.jsonl,unavailable.jsonl}
```

The raw export remains immutable. Each normalized input record supplies only
`sample_id` and `code`; the index has repository locator fields only. B1 does
not resolve a whole file, index same-file functions, or inject caller/callee
hints into B2.

PrimeVul remains function-level. Any missing header, type, macro, or external
symbol is represented as a local analysis limitation and remains available for
future obligation-driven repository retrieval.

---

## 8. Repository Context Boundary

Repository context is implemented as a standalone, disabled-by-default,
two-phase service. Offline `repo-context preprocess` resolves one exact Git
revision, verifies indexed source, and caches one smoke-validated Joern CPG.
Runtime `repo-context query` reads only `context/catalog.jsonl`, an immutable snapshot,
and prepared CPG, then returns bounded source-grounded evidence. It must never
invoke Git, build a CPG, or smoke-test at query time. Missing or invalid
prepared context returns empty `not_found` evidence with
`repository_context_unavailable`; it is not a fallback trigger.

`catalog.jsonl` replaces the old `ready.jsonl` filename, while successful JSON
records retain `status: "ready"`. `unavailable.jsonl` contains only a sample ID
and controlled failure kind. Legacy cache directories are not moved or deleted
automatically.

For the paired PrimeVul export, the offline order is:

```text
repo-context import-primevul (Clang AST function name)
  -> repo-context preprocess --all (Git revision + Joern CPG)
  -> repo-context query (prepared Joern CPG only)
```

The service requires an explicit `EvidenceRequest` with an operation anchor and
finite budget. It is available through `vulsor repo-context`; it is not exposed
to B1/B2 and is not automatically connected to B3/B4 yet.

## 9. Tool Integration

| Tool | Status | Notes |
|---|---|---|
| Clang | Integrated in production Python path | AST JSON, debug.DumpCFG |
| clang++ | Checked by config/doctor | C/C++ toolchain availability |
| Git | Optional repository-context tool | Exact revision resolution and read-only checkout |
| Joern | Standalone repository-context adapter | Whole-repository CPG build and bounded queries |
| Native probe | Experimental/debug | `native/`, not production pipeline |

`vulsor doctor` normally checks PATH for:

```text
clang
clang++
```

`vulsor doctor --repository-context` additionally checks `git`, `joern`, and
`joern-parse`. The same checks apply when repository context is enabled in the
project config.

Native probe purpose:

```text
debug Clang frontend
debug RecursiveASTVisitor traversal
debug CFG/RAV integration
diagnose crash/toolchain issues before production integration
```

Native probe rules:

```text
Do not modify production CMake casually.
Do not conclude a crash is a RAV bug without stack/evidence.
Do not treat native debug output as vulnerability evidence.
Only move native helpers into production after interface and tests are clear.
```

## 10. Known Technical Limits

1. CFG depends on Clang semantic analysis and can be missing for function
   snippets without project headers.
2. CFG blocks do not have source locations yet, so they cannot be precisely
   linked to function or operation ranges.
3. Data-flow is syntactic local reaching-definition only.
4. Call graph is syntactic direct calls only.
5. Function pointers, C++ virtual dispatch, macro-generated calls, and external
   callees may remain unresolved even with Joern evidence and must be reported
   as limitations.
6. Standalone repository evidence retrieval is implemented, but B3/B4 do not
   create requests or consume its evidence yet. `PipelineResult.evidence`
   remains empty until that integration exists.
7. The Joern script has unit-level boundary coverage; its real runtime
   integration must be run in an environment with `joern` and `joern-parse`.
8. `AGENT.md` must be updated after important code changes.

Short classification:

```text
CFG missing       -> local Clang/source limitation
data-flow limited -> syntactic local analysis only
call graph limited -> syntactic direct calls only
repository facts  -> standalone bounded service; B3/B4 integration pending
```

## 11. Latest Test Status

The test groups include:

```text
tests/test_analysis.py
tests/test_cli.py
tests/repository_context/
```

Run the unit suite without the opt-in Joern runtime test with:

```powershell
$env:PYTHONPATH = "src"
python -m pytest -q -m "not joern"
```

## 12. Next Work

Priority:

1. Strengthen B2 semantic agents with richer grounding and schema tests.
2. Implement B3 obligation generation from the merged B2 views.
3. Connect the standalone repository-context service to B3/B4 after the final
   obligation schema exists; construct only obligation-scoped requests.
4. Implement B4 grounding and obligation-specific evidence bundles using
   `RepositoryEvidence`, without injecting raw repository state into B1/B2.
5. Implement B5 verification, B6 adjudication, and B8 evaluation.
6. Map CFG blocks and edges to source locations where local analysis permits.

Avoid for now:

```text
Do not jump to LLM verdict.
Do not put CWE/CVE/target/pair metadata into model input.
Do not call partial output vulnerability evidence.
Do not treat syntactic data-flow as feasibility proof.
Do not implement the whole pipeline at once.
```

## 13. Pending Stages To Preserve

### B2 Semantic Reconstruction

B2 should convert raw program facts into semantic views:

```text
State:
  variables, buffers, objects, resources, ownership, initialization state

Value:
  constants, symbolic values, bounds, sizes, nullability, taint-like source if
  facts exist

Execution:
  control dependencies, branch context, reachable operations, order constraints

Operation:
  call/action semantic role, for example copy, allocation, free, parse,
  bounds check
```

B2 must not decide vulnerability. If facts are missing, B2 must report missing
context or uncertainty.

### B3 Obligation Generation

B3 produces safety obligations from semantic operations.

Example:

```text
Operation: memcpy(dst, src, len)
Obligation: len must be within destination buffer capacity
Grounding needed: dst capacity, len value/range, path condition
```

B3 may use an LLM to propose obligations, but the LLM must not prove
feasibility by itself.

### B4 Obligation Validation / Grounding

B4 checks whether obligations are grounded in facts:

```text
accepted:
  obligation has a real operation, real source location, and related facts

rejected:
  obligation depends on a symbol/fact that does not exist

needs_more_context:
  obligation is plausible but lacks size/type/header/build context
```

B4 must not invent evidence.

### B5 Violation Verification

B5 needs real evidence:

```text
symbolic reasoning
dynamic execution/harness if available
solver/path feasibility if implemented
tool evidence from Joern/CodeQL/native checker if available
```

Currently `src/vulsor/verification/*.py` has no real implementation, so empty
`PipelineResult.evidence` is expected.

### B6 Adjudication

B6 can conclude only:

```text
VULNERABLE
BENIGN
```

It needs enough facts, grounded obligations, and verification evidence. It must
not conclude from dataset labels or LLM claims.

### B7 CWE + Localization

B7 is derived after verdict:

```text
CWE mapping
vulnerable operation location
supporting source lines
fix-relevant location if available
```

Do not use PrimeVul CWE/CVE as model or verifier input.

### B8 PrimeVul Evaluation

B8 needs:

```text
run pipeline over samples
keep labels separate from model/verifier input
cache per-sample results for large runs
compute metrics
optionally compute pair-level metric without exposing pair relationship to model
```

PrimeVul currently has dataset inspection, but no end-to-end
prediction/evaluation because B2-B6 are not implemented.

---

## 14. AGENT.md Update Rules

When editing this file:

```text
Keep UTF-8.
Use ASCII text only unless there is a strong reason not to.
Avoid mojibake.
Avoid decorative Unicode and emoji.
Do not remove roadmap for unimplemented stages.
Do not remove methodology boundaries.
If code changes, update corresponding status.
If something is not implemented, say "not implemented" instead of deleting it.
```
