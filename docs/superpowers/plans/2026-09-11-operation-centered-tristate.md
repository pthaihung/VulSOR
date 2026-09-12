# Operation-Centered Tri-State Pipeline Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Align the existing semantic-v2 implementation with `VulSOR_detailed_plan.md`: facts explicitly target operations, Stage 1.5 is removed, obligations are operation-centered, adjudication uses the three evidence-backed states, and final aggregation is deterministic.

**Architecture:** Stage 1A emits operations, and Stage 1B facts carry `operation_ids` so relevance is stated by the producing agent rather than inferred by a heuristic linker. Python validates those references and deterministically assembles one context per operation. Stage 2 derives atomic requirements from those contexts; Stage 3 applies the five-gate policy and either emits one valid assessment per requirement or records `analysis_failure` without silently inventing a verdict.

**Tech Stack:** Python 3.13, `unittest`, YAML prompts loaded through the existing `SimpleYaml`/`PromptAgent` stack, JSON stage artifacts, no new dependency and no network call in automated tests.

---

## File map

- Create `src/agents/OperationContext.py`: validate fact-to-operation references and build deterministic operation contexts.
- Modify `src/agents/SemanticContract.py`: distinguish the five-field operation schema from the six-field State/Value/Execution schema containing `operation_ids`.
- Modify `src/agents/QualityGate.py`: enforce operation reference integrity and remove regex-based minimum-claim requirements.
- Modify `src/agents/Pipeline.py`: remove Stage 1.5 reads/writes/link scoring, pass operation contexts to Stage 2, retry invalid adjudication once through the existing agent retry mechanism, and aggregate only complete valid adjudications.
- Modify semantic and obligation YAML prompts: encode role boundaries, atomic requirements, the five gates, and exact output schemas.
- Modify `src/agents/ArtifactContract.py`: change dependency metadata from context-link hashes to deterministic operation-context hashes.
- Modify `src/UI/cli.py`, `scripts/eval_pipeline_metrics.py`, and `docs/semantic-claims-v2.md`: expose new counts/statuses and remove linker/undetermined terminology.
- Replace `tests/test_semantic_linker.py` with `tests/test_operation_context.py`; update contract, consumer, prompt, pipeline, safety, artifact, and metrics tests.

### Task 1: Operation-linked semantic contract and deterministic contexts

**Files:**
- Create: `src/agents/OperationContext.py`
- Modify: `src/agents/SemanticContract.py`
- Modify: `src/agents/QualityGate.py`
- Test: `tests/test_semantic_contract.py`
- Test: `tests/test_operation_context.py`

- [ ] **Step 1: Write failing contract tests**

Add tests asserting that an operation has exactly `id/location/entities/claim/evidence`, while State/Value/Execution each additionally require a non-empty, duplicate-free `operation_ids` list. Assert unknown IDs, orphan facts, duplicate IDs, unsupported fields, invalid locations, and invalid evidence fail.

```python
self.assertEqual([], validate_claim_output({"operations": [OP]}, "operation_agent", 4))
self.assertEqual([], validate_claim_output({"executions": [dict(EXEC, operation_ids=["o1"])]}, "execution_agent", 4))
self.assertTrue(validate_claim_output({"executions": [EXEC]}, "execution_agent", 4))
```

- [ ] **Step 2: Run the focused tests and confirm RED**

Run: `python -B -m unittest tests.test_semantic_contract tests.test_operation_context -v`

Expected: failures because semantic facts do not yet require `operation_ids` and `OperationContext` does not exist.

- [ ] **Step 3: Implement the schema and context builder**

Expose these interfaces:

```python
OPERATION_FIELDS = ("id", "location", "entities", "claim", "evidence")
SEMANTIC_FACT_FIELDS = OPERATION_FIELDS + ("operation_ids",)

def validate_operation_references(semantic_model: Mapping[str, Any]) -> list[str]: ...
def build_operation_contexts(semantic_model: Mapping[str, Any]) -> list[dict[str, Any]]: ...
```

Each context must contain exactly `operation_id`, `operation`, `state_facts`, `value_facts`, and `execution_facts`. Preserve source order, attach a multi-operation fact to every referenced operation, reject orphan references, and never infer relevance from entity overlap or line distance.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Run: `python -B -m unittest tests.test_semantic_contract tests.test_operation_context -v`

Expected: all tests pass.

### Task 2: Stage 1 prompts and orchestration without Stage 1.5

**Files:**
- Modify: `src/agents/prompts/SemanticAgent/Operation_Agent.yml`
- Modify: `src/agents/prompts/SemanticAgent/State_Agent.yml`
- Modify: `src/agents/prompts/SemanticAgent/Value_Agent.yml`
- Modify: `src/agents/prompts/SemanticAgent/Execution_Agent.yml`
- Modify: `src/agents/Pipeline.py`
- Modify: `src/agents/ArtifactContract.py`
- Test: `tests/test_prompt_contracts.py`
- Test: `tests/test_semantic_pipeline_v2.py`
- Test: `tests/test_artifact_contract.py`

- [ ] **Step 1: Write failing orchestration and prompt tests**

Assert Stage 1 creates no `stage_1_5_context_links.json`, `stage_1_semantic_model.json` contains `operation_contexts`, every semantic prompt requires `operation_ids`, and Stage 2 receives `operation_contexts_json` rather than `semantic_link_clusters_json`. Assert artifact metadata depends on the semantic model and operation-context fingerprint only.

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `python -B -m unittest tests.test_prompt_contracts tests.test_semantic_pipeline_v2 tests.test_artifact_contract -v`

Expected: failures mentioning context links, the old template variable, or missing operation IDs.

- [ ] **Step 3: Rewrite the prompts and pipeline path**

Operation identifies only safety-check points. State answers object/resource state at referenced operations, Value answers value/size/alias relationships at referenced operations, and Execution answers reachability conditions for referenced operations. Remove `_context_links_file`, `_read_or_build_context_links`, `build_context_links_record`, link-scoring helpers, context-link metadata, and Stage 1.5 summaries. Build contexts immediately after all four semantic outputs validate and store them under `output.operation_contexts`.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Run the Step 2 command; expected all pass.

### Task 3: Atomic operation-centered obligations

**Files:**
- Modify: `src/agents/prompts/Obligation_Reasoner.yml`
- Modify: `src/agents/Pipeline.py`
- Test: `tests/test_claim_consumers.py`
- Test: `tests/test_prompt_contracts.py`

- [ ] **Step 1: Write failing Stage 2 tests**

Require each operation to produce at least one obligation. Every obligation must contain `id`, `operation_id`, `safety_requirement`, `applicable_condition`, and `evidence_refs`; IDs and operation IDs must be unique/valid, refs must belong to that operation context, and a requirement must be atomic. Reject `cluster_id`, `link_confidence`, duplicate requirements, empty requirements, and an operation with zero obligations.

- [ ] **Step 2: Run tests and confirm RED**

Run: `python -B -m unittest tests.test_claim_consumers tests.test_prompt_contracts -v`

- [ ] **Step 3: Implement Stage 2 validation and prompt**

Render `{operation_contexts_json}`. Explain that missing evidence must not suppress a requirement and that concrete bounds may not be invented. Validate exact schema, context-scoped refs, unique IDs, at least one requirement per operation, and reject obvious compound requirements joined as independent safety properties.

- [ ] **Step 4: Run tests and confirm GREEN**

Run the Step 2 command; expected all pass.

### Task 4: Five-gate adjudication and explicit analysis failure

**Files:**
- Modify: `src/agents/prompts/Obligation_Adjudicator.yml`
- Modify: `src/agents/Pipeline.py`
- Test: `tests/test_claim_consumers.py`
- Test: `tests/test_pipeline_safety.py`
- Test: `tests/test_prompt_contracts.py`

- [ ] **Step 1: Write the four curated RED cases**

Test S=`satisfied`, V=`violated`, P=`potentially_violated`, and X=`analysis_failure`. A valid adjudication contains exactly:

```python
{
    "obligation_id": "r1",
    "assessment": "potentially_violated",
    "possibility": "i may be negative when o1 executes",
    "supporting_evidence_refs": ["value_agent.values[0]"],
    "contradicting_evidence_refs": [],
    "confirmation_gap": "no supplied caller/path establishes a negative value",
}
```

For `satisfied`, evidence must establish the full requirement. For `violated`, evidence must establish an actual reachable violation. For `potentially_violated`, all five gates must be represented: concrete possibility, positive support, operation relevance, no supplied contradiction, and a specific confirmation gap. Missing/duplicate obligation results and unsupported refs must fail validation rather than becoming a semantic assessment.

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `python -B -m unittest tests.test_claim_consumers tests.test_pipeline_safety tests.test_prompt_contracts -v`

- [ ] **Step 3: Implement validator, retry, and failure record**

Replace `undetermined` everywhere. Keep the existing agent validation retry path for one corrected adjudication attempt. If the result is still invalid, return a Stage 3 record with `quality_gate.status="failed"`, `analysis_failure=True`, diagnostics, and no fabricated assessment or binary prediction.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Run the Step 2 command; expected all pass.

### Task 5: Deterministic final aggregation and metrics

**Files:**
- Modify: `src/agents/Pipeline.py`
- Modify: `scripts/eval_pipeline_metrics.py`
- Modify: `scripts/eval_cwe_coverage.py`
- Modify: `src/UI/cli.py`
- Test: `tests/test_pipeline_safety.py`
- Test: `tests/test_eval_pipeline_metrics.py`

- [ ] **Step 1: Write failing aggregation and metric tests**

Assert any `violated` yields `Vulnerable/confirmed_violation`; otherwise any `potentially_violated` yields `Vulnerable/potential_violation`; otherwise all satisfied yields `Benign/established_safety`. Zero, missing, duplicate, invalid, or failed adjudications yield `analysis_failure` and no decision. Assert metrics separately report satisfied/violated/potential/failure rates and precision for confirmed versus potential predictions.

- [ ] **Step 2: Run focused tests and confirm RED**

Run: `python -B -m unittest tests.test_pipeline_safety tests.test_eval_pipeline_metrics -v`

- [ ] **Step 3: Implement aggregation and reporting**

Return `decision`, `decision_basis`, and `triggering_obligations`; retain compatibility aliases only where existing CLI consumers require them. Never use voting or confidence thresholds. Treat `analysis_failure` as its own pipeline result, never Benign or potential.

- [ ] **Step 4: Run focused tests and confirm GREEN**

Run the Step 2 command with `TEMP`/`TMP` directed to a workspace-local temporary directory when sandbox permissions require it.

### Task 6: Integration cleanup, documentation, and verification

**Files:**
- Modify: `tests/test_semantic_pipeline_v2.py`
- Modify: `docs/semantic-claims-v2.md`
- Remove: `tests/test_semantic_linker.py`
- Remove runtime production of: `stage_1_5_context_links.json`

- [ ] **Step 1: Add end-to-end scripted-client coverage**

Exercise Stage 1 through Stage 3 without an API key, assert operation IDs survive into contexts and obligations, verify the three final decision bases, and verify invalid adjudication produces analysis failure after one retry.

- [ ] **Step 2: Remove stale linker and undetermined references**

Run:

```powershell
rg -n "STAGE_1_5|context_links|semantic_link|link_confidence|cluster_id|undetermined" src tests scripts docs/semantic-claims-v2.md
```

Expected: no runtime/schema hits; compatibility text is allowed only when explicitly marked historical.

- [ ] **Step 3: Document the final contracts and migration**

Document output paths, operation/fact/requirement/adjudication schemas, analysis-failure behavior, aggregation rules, and the fact that old semantic-v2 artifacts must be regenerated because the pipeline fingerprint and dependency graph changed.

- [ ] **Step 4: Run complete offline verification**

Run:

```powershell
python -B -m unittest discover -s tests -v
python -B -m compileall -q src scripts tests
python -B -m src.UI --split test --samples 0 --dry-run --overwrite --output-root stages/semantic-v2-verification
```

Expected: all unit tests pass, compilation exits 0, and the dry-run creates Stage 1/2/3 artifacts without Stage 1.5. A real LLM run is outside offline verification because it consumes provider tokens.

## Self-review

- The plan covers the attachment's Stage 1 operation-centered schema, explicit operation references, removal of the linker, operation contexts, atomic obligations, five-gate adjudication, explicit analysis failure, deterministic aggregation, and stage-specific metrics.
- No task treats missing evidence as vulnerability or uses confidence/voting for the final decision.
- Names are consistent across tasks: `operation_ids`, `operation_contexts`, `potentially_violated`, `analysis_failure`, `decision_basis`, and `triggering_obligations`.
- Because the user explicitly requested edits in the current dirty `master` checkout, workers must not create a worktree, switch branches, reset existing changes, or commit mixed user changes.
