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
| B1 Program Analysis | Mostly implemented, still limited | Clang AST, CFG parser, syntactic data-flow, syntactic call graph, fact links, dataset inspection, context_facts, compile-context arg plumbing, optional Joern/CPG facts |
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
AST -> CFG -> data-flow -> call graph -> Joern/CPG
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
| Compile context args | Implemented when concrete args exist | include paths, system includes, defines, undefines, extra clang args |
| Dataset context facts | Implemented | `analysis.context_facts` from PrimeVul sidecar |
| Context function index | Improved | Handles functions/methods inside C/C++ scoped blocks such as namespaces |
| Joern status adapter | Implemented | `src/vulsor/tools/joern.py` reports availability/integration status |
| Joern/CPG facts | Implemented when requested | `inspect --cpg` runs c2cpg + Joern script and emits real method/call CPG facts |
| Evidence | Not implemented | `verification/*` has no real verifier yet |

Data-flow no longer depends on CFG. If CFG fails but AST recovers definitions
and uses, VulSOR still builds syntactic data-flow.

---

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

Important: PrimeVul caller/callee context is not inserted into `ProgramFacts`.
It is exposed separately as `analysis.context_facts` because it is currently a
same-file heuristic, not Clang/Joern proof.

---

## 5. Inspect Output

CLI dataset inspect:

```powershell
vulsor inspect --config configs\primevul.yaml --dataset primevul --split test --limit 1 --analysis-scope auto --format json
vulsor inspect --config configs\primevul.yaml --dataset primevul --split test --limit 1 --analysis-scope auto --cpg --format json
```

Interactive JSON/pretty dataset inspect renders a compact `Stage Summary` table
below the main sample table. It uses one column per stage (`Source`, `Context`,
`AST`, `CFG`, `Data Flow`, `CPG`) plus a `Dataset` column. When printed to an
interactive terminal, both `--format json` and `--format text` also show the
summary tables on screen. `--format text` keeps the saved/plain payload as text
sections and includes fuller detail behind the table cells: stage reasons, fact
counts, dataset context factors, artifact paths, missing symbol summaries,
root-cause diagnosis, and diagnostics.

The summary panel reports dynamic percentages:

```text
status counts:
  complete / partial / stopped
dataset_context_selected:
  source/context factors available in the inspected sample subset
dataset_context_split:
  source/context factors available across the full dataset split sidecar,
  even when only a small --limit/--sample subset is inspected
stage_coverage:
  B1 stages that produced usable facts/statuses in the inspected subset
stage_vs_dataset:
  B1 extracted facts in the inspected subset compared with the relevant
  dataset-context denominator, for example ast/target_body, cfg/target_index,
  data_flow/target_index, call_graph/call_context, and cpg/call_context
```

Interactive terminal summary formatting uses separate headed blocks with
`count/total (percent)` metrics, so selected-sample coverage, full-split dataset
coverage, stage coverage, and stage-vs-dataset ratios do not collapse into one
long wrapped line.

Interactive menu supports:

```text
Inspect a sample
-> Source file
-> Dataset samples
   -> One sample id
   -> First N samples
   -> All samples
   -> Random N samples
   -> Scope: auto/function/file
   -> Optional Joern/CPG facts
   -> Output: text/json
```

Main JSON shape:

```text
dataset
split
count
brain_context
samples[]
  sample_id
  status
  result.program_facts
  analysis.scope
  analysis.requested_scope
  analysis.context_mode
  analysis.complete
  analysis.source_context
  analysis.context_facts
  analysis.tool_status
  analysis.cpg_facts
  analysis.completeness
  analysis.build_diagnosis
  analysis.missing_context_summary
  analysis.missing_context
  analysis.links
  analysis.limitations
  analysis.rules
  diagnostics
```

`analysis.context_facts` summary:

```text
available
target:
  available, name, start_line, end_line, indexed, body_available
same_file_index:
  available, function_count
same_file_call_context:
  available, scope, direct_callee_count, direct_callee_body_count,
  direct_caller_count, limitations
provenance
trust_boundary
```

`analysis.source_context` keeps the fuller sidecar context. `analysis.context_facts`
is the compact summary for B1 output and later grounding.

`analysis.tool_status` records Program Analysis tool capability:

```text
clang:
  executable, available, uses = ast_json/cfg_dump
joern:
  executable, available, resolved_path, cpg_integrated, message
```

`analysis.cpg_facts` records Joern facts only when `--cpg` is enabled:

```text
status = not_requested / unavailable / partial / available
method_count
call_count
methods[]:
  name, full_name, filename, line, line_end
calls[]:
  caller, callee, method_full_name, dispatch_type, code, filename, line, column
diagnostics
provenance = joern/c2cpg
trust_boundary
```

If Joern/c2cpg fails, B1 reports diagnostics and does not fabricate CPG facts.

No label/CWE/CVE/pair metadata is used as analysis input.

B1 also writes per-sample artifacts for later stages:

```text
brain_context/{dataset}/{split}/manifest.json
brain_context/{dataset}/{split}/{sample_id}.json
```

The default artifact directory is `brain_context`. It can be changed with:

```powershell
vulsor inspect ... --brain-context-dir custom_dir
```

Artifact shape:

```text
schema_version = 1
artifact_kind = program_analysis
dataset
split
sample_id
sample:
  sample_id
  status
  result.program_facts
  analysis.source_context
  analysis.context_facts
  analysis.tool_status
  analysis.cpg_facts
  analysis.completeness
  analysis.build_diagnosis
  analysis.missing_context
  analysis.links
  analysis.limitations
  analysis.rules
  diagnostics
```

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

Run all four agents concurrently with an optional progress bar:

```powershell
vulsor agent --agent all --dataset primevul --split test --sample test_000000 --parallel
```

Without `--parallel`, agents run sequentially. Parallel mode uses four worker
threads, one for each semantic agent, and reports completed agent/sample jobs;
the deterministic merge runs after all four agents finish.

Run with optional LLM interpretation:

```powershell
vulsor agent --agent all --dataset primevul --split test --sample test_000000 --llm --llm-config configs\agent_llm.yaml
```

The B2 flow has two phases:

```text
phase 1 (without --llm): B1 artifact -> one filtered brain per agent
phase 2 (with --llm): that agent brain + source -> concise reasoning output
```

The LLM phase does not receive the full B1 artifact as its main context and
does not replace the brain. Each agent receives only its matching brain:
`state_view`, `value_view`, `execution_view`, or `operation_view`. The source
from the dataset input is provided for exact source grounding. API results are
stored separately under `experiments/{dataset}/{split}/{agent}/{sample_id}.json`.

The merge step is deterministic assembly, not a fifth reasoning agent. It
combines the four filtered brain views and their cross-view links into
`agent_semantics.json` for later pipeline stages. It does not merge or invent
LLM reasoning and it does not produce a verdict.

Interactive `vulsor` menu includes `Run semantic agents`. That flow reads the
existing `brain_context/{dataset}/{split}/manifest.json`, displays analyzed
sample ids, lets the user choose one by number or id, then can preview the
separate output JSON for each selected semantic agent.

Optional LLM interpretation uses `configs/agent_llm.yaml` and JSON prompt files
under `src/vulsor/agents/prompts/`. API keys are read from the configured
environment variable, default `OPENAI_API_KEY`; prompt content and model/API
configuration are kept outside agent logic.

LLM tool access for B2 is also configured in `configs/agent_llm.yaml` through
`allowed_tools` and `max_tool_rounds`. Shared values can be overridden for
each semantic agent under `agents`:

```yaml
model: gpt-4.1-mini
max_tool_rounds: 1
agents:
  state:
    model: state-model
    allowed_tools:
      - get_program_facts
  value:
    model: value-model
    max_tool_rounds: 2
  execution:
    model: execution-model
  operation:
    model: operation-model
```

Each agent inherits unspecified values from the shared settings. Tools live in the existing
`src/vulsor/tools` package, currently in `agent_tool_registry.py`, and only
return facts already present in the current B1 artifact. They do not inspect
the repository independently and do not produce verdict/CWE/evidence.

B2 uses OOP inheritance:

```text
BaseAgent in src/vulsor/agents/BaseAgent.py
  -> StateAgent      in src/vulsor/agents/StateAgent.py
  -> ValueAgent      in src/vulsor/agents/ValueAgent.py
  -> ExecutionAgent  in src/vulsor/agents/ExecutionAgent.py
  -> OperationAgent  in src/vulsor/agents/OperationAgent.py
```

The base class owns shared execution concerns such as artifact I/O, cache keys,
prompt loading, and optional LLM API calls. Each concrete agent owns only its
local semantic view construction.

State Agent output/cache:

```text
brain_context/{dataset}/{split}/agents/{sample_id}/state.json
```

Other B2 output/cache paths:

```text
brain_context/{dataset}/{split}/agents/{sample_id}/value.json
brain_context/{dataset}/{split}/agents/{sample_id}/execution.json
brain_context/{dataset}/{split}/agents/{sample_id}/operation.json
brain_context/{dataset}/{split}/agents/{sample_id}/agent_semantics.json
```

--- 

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
  - get_context_facts
  - get_cpg_facts
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
run Clang/Joern again
fetch network context
use labels/CWE/CVE/pair metadata
produce verdicts
produce vulnerability evidence
```

Current allowlisted tool names:

| Tool | Purpose |
|---|---|
| `get_program_facts` | Return all or selected `program_facts`; accepts optional `fact_type` and `limit` |
| `get_context_facts` | Return `analysis.context_facts`; context remains a hint, not proof |
| `get_cpg_facts` | Return `analysis.cpg_facts` when B1 was run with CPG enabled |
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

Note: `analysis.context_facts.target` means the target function summary in B1
artifacts. It is allowed as function context. Dataset label fields named
`target` are not allowed as reasoning input.

---

## 6. Rules, Limitations, Diagnosis

`rules` are fixed Program Analysis policy:

```text
tools produce program facts only
program analysis does not infer VULNERABLE/BENIGN verdicts
missing project context is reported as a limitation, not fabricated
dataset labels, CWE, CVE, and pair metadata are not used as analysis input
```

`limitations` are semi-dynamic per sample. They depend on selected scope,
diagnostics, CFG availability, and data-flow quality.

Current meaning:

```text
AST/call facts:
  Usually recoverable if Clang can parse AST.
  Partial if Clang emits diagnostics.

CFG:
  Missing mostly because dataset/project compile context lacks headers,
  typedefs, macros, or build flags.
  Another known case: whole-file CFG exists but is not mapped back to selected
  function range yet.

Data-flow:
  Currently syntactic AST-based reaching-definition.
  Does not prove path feasibility, aliasing, pointer flow, field flow, macro
  expansion, or interprocedural flow.
```

`build_diagnosis` separates dataset/context problems from fixable pipeline
problems:

| Classification | Meaning | Fixable by code? |
|---|---|---|
| `dataset_file_context_missing` | No whole-file source context | No, context must be added |
| `dataset_compile_context_missing` | File exists but headers/typedefs/macros/build flags are missing | Partly, by adding compile context |
| `pipeline_context_not_applied` | Dataset advertises compile info but no concrete args are available to pass | Partly, enrich context with concrete args |
| `dataset_compile_context_incomplete` | Concrete compile args were passed but Clang still cannot produce complete facts | Partly, add more headers/macros/flags |
| `function_range_cfg_omitted` | Whole-file CFG may exist but is not mapped to selected function range | Yes |
| `clang_diagnostics_unclassified` | Clang emitted diagnostics not matched by known missing-context patterns | Yes, extend diagnosis |
| `tool_or_parser_issue` | CFG missing without useful diagnostics | Yes, debug invocation/parser/toolchain |
| `recovered_ast_limited` | AST recovered but may miss facts | Partly, better compile context helps |

---

## 7. PrimeVul Clean Dataset

PrimeVul clean is used to avoid leakage.

Main directories:

```text
data/PrimeVul_clean/inputs/{train,valid,test}.jsonl
data/PrimeVul_clean/labels/{train,valid,test}.jsonl
data/PrimeVul_clean/paired/{train,valid,test}.jsonl
data/PrimeVul_clean/context/{train,valid,test}.jsonl
```

Current sidecar coverage:

| Split | Total | Has file_info | Resolved whole-file |
|---|---:|---:|---:|
| train | 7578 | 4873 | 4839 |
| valid | 960 | 783 | 783 |
| test | 870 | 703 | 703 |

Context sidecar contains technical information:

```text
sample_id
analysis_scope
source_kind
func_hash
file_context_available
resolved_file_available
compile_context
target_function
file_function_index
call_context
file_name
file_hash
original_file_path
raw_local_file_path
resolved_file_content_path
function_start_line
function_end_line
```

Expanded context:

```text
target_function:
  name, file, file_name, start_line, end_line, body_available, indexed

file_function_index:
  available, function_count, functions[] with name/start_line/end_line/
  direct_call_count

call_context:
  scope = same_file
  direct_callees[] with call line/column, body_available, same-file definition
  when found
  direct_callers[] in the same file when found
  limitations explicitly say function pointers, virtual dispatch,
  macro-generated calls, and cross-file calls need Joern/CPG or compile context
```

This caller/callee context is built by a same-file heuristic parser over the
resolved whole-file source. It does not replace Joern/CPG.

Context sidecar must not contain leakage keys:

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

PrimeVul is mostly function-level. With `--analysis-scope auto`, VulSOR tries
whole-file context when available, filters analysis to target function range,
and falls back to the clean function snippet if whole-file analysis cannot
recover the target function.

Current real-data check:

```text
test_000000:
  target = GetEXIFProperty
  selected_source = function_snippet after whole-file fallback
  context_facts.same_file_call_context.direct_callee_count = 65
  context_facts.same_file_call_context.direct_callee_body_count = 25
  context_facts.same_file_call_context.direct_caller_count = 1

test_000004:
  target = ImmutableExecutorState::Initialize / Initialize
  context builder now indexes the C++ method inside scoped source context
  file_function_index.function_count = 8
  context_facts.same_file_call_context.direct_callee_count = 98
```

---

## 8. Context Builder

Context builder:

```text
data/build_primevul_context.py
```

Current behavior:

```text
reads raw PrimeVul metadata
keeps labels/CVE/CWE/pair data out of context
resolves whole-file source when file_info is available
extracts target function by function name first, then line overlap fallback
builds same-file function index
builds same-file direct callee/caller context
does not duplicate raw callee body text into every context record
writes JSONL sidecar files used by the dataset loader
```

Pretty inspection copy:

```text
data/PrimeVul_clean/context/test.pretty.json
```

Important: `.jsonl` files are the operational files used by the loader.
`test.pretty.json` is for human reading only.

---

## 9. Tool Integration

| Tool | Status | Notes |
|---|---|---|
| Clang | Integrated in production Python path | AST JSON, debug.DumpCFG, optional compile args |
| clang++ | Checked by config/doctor | Not used in main Python B1 path yet |
| Java | Checked by config/doctor | Needed for Joern later |
| Joern | Integrated as optional B1 CPG source | `inspect --cpg` uses c2cpg + Joern query script |
| Native probe | Experimental/debug | `native/`, not production pipeline |

`vulsor doctor` checks PATH for:

```text
clang
clang++
java
joern
```

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

---

## 10. Known Technical Limits

1. Clang adapter can receive concrete compile args from context:
   include paths, system includes, defines, undefines, and extra clang args.
   Current PrimeVul clean context mostly stores availability flags, so many
   samples still have no concrete args to apply.
2. CFG depends on Clang semantic analysis and can be missing for function
   snippets or whole files without project headers.
3. CFG blocks do not have source locations yet, so they cannot be precisely
   linked to function/operation ranges.
4. Data-flow is syntactic local reaching-definition only.
5. Call graph is syntactic direct calls only.
6. Context caller/callee is same-file heuristic only.
7. Function pointers, C++ virtual dispatch, macro-generated calls, and external
   callees/callers still need deeper Joern queries or a project-level index.
8. Joern/CPG method/call facts are integrated only when `--cpg` is enabled.
   They are not used as vulnerability evidence.
9. Evidence/verification is not implemented; `PipelineResult.evidence` is empty.
10. `AGENT.md` must be updated after important code changes.

Short classification:

```text
CFG missing       -> mostly dataset/project compile context missing
Data-flow missing -> partly dataset/context, partly current pipeline limits
AST/call facts    -> usually recoverable if Clang can parse AST
Context calls     -> same-file helper, not full project call graph
CPG facts         -> real Joern/c2cpg facts when --cpg is enabled
```

---

## 11. Latest Test Status

Most recent verification after B2 agent/OOP/LLM-tool integration:

```text
python -m py_compile src\vulsor\config.py src\vulsor\agents\BaseAgent.py src\vulsor\agents\SemanticViews.py src\vulsor\agents\LLMClient.py src\vulsor\agents\StateAgent.py src\vulsor\agents\ValueAgent.py src\vulsor\agents\ExecutionAgent.py src\vulsor\agents\OperationAgent.py src\vulsor\tools\agent_tool_registry.py src\vulsor\cli.py
.\.venv\Scripts\python.exe -m pytest
```

Result:

```text
74 passed
```

Main test groups:

```text
tests/test_analysis.py
tests/test_cli.py
tests/test_primevul_context.py
```

---

## 12. Next Work

Priority:

1. Strengthen B2 semantic agents with richer fact grounding and schema tests.
2. Enrich PrimeVul context with concrete include paths, macro definitions, and
   compile args when available from project build data.
3. Upgrade Joern query coverage beyond method/call facts:
   - resolved project-level call graph
   - data-dependence / control-dependence facts
   - function pointer and virtual dispatch handling when Joern can resolve them
4. Upgrade caller/callee context from same-file heuristic to Joern/CPG or a
   project-level index.
5. Map CFG blocks/edges to source locations or function ranges.
6. Improve diagnosis for parser/toolchain issues.

Avoid for now:

```text
Do not jump to LLM verdict.
Do not put CWE/CVE/target/pair metadata into model input.
Do not call partial output vulnerability evidence.
Do not treat syntactic data-flow as feasibility proof.
Do not implement the whole pipeline at once.
```

---

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
