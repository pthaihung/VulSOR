# VulSOR semantic v4.13 — Verification Report

## Scope

v4.13 keeps the binary obligation ontology unchanged: `satisfied | violated`, with the deterministic final rule `any violated obligation -> Vulnerable; otherwise Benign`.

This revision targets two issues observed in the clean v4.12 PrimeVul run:

1. **Safety-contract precision**: Operation/Reasoner could confuse ordinary API success conditions with security-relevant safety preconditions, producing false-positive obligations for safely reportable failures or opaque helper calls.
2. **Retry/token efficiency**: truncated JSON could force a full semantic regeneration, repeating already-completed reasoning and increasing token cost.

## Semantic changes

### Operation safety-contract gate

The Operation prompt now explicitly gates every candidate:

- keep an action only when executing that action consumes an established security-relevant safety precondition;
- distinguish invalid/unsafe execution from ordinary API failure;
- do not treat success/domain conditions as safety preconditions merely because they are required for a call to succeed;
- omit opaque project/helper calls when their safety contract is not established by supplied semantics;
- anchor a safety obligation at the actual consumer when a producer/search/lookup can fail safely but a later dereference/use cannot.

No function-name whitelist or benchmark-specific API dictionary is used.

### Stage-2 safety-relevance gate

The Obligation Reasoner now has a second gate. It must return one temporary group per supplied Operation, but may use `requirements: []` when no established security-relevant safety precondition exists. Empty groups are deterministically removed before persistence/adjudication.

A successful Stage 2 that filters all candidates to zero obligations is a valid semantic result and produces **Benign**, not `AnalysisFailure`. `AnalysisFailure` remains reserved for technical/protocol failures.

### Value-output compression

The Value prompt now explicitly suppresses intermediate assignments/relations that cannot materially change a later safety judgment. It prefers the strongest source-supported relation for bounds, extent, size, offsets, pointer displacement, alignment, numeric representability/overflow, allocation size, or resource count. This is intended to reduce output length and truncation pressure without imposing an arbitrary hard count.

## Retry / recovery changes

The retry path now distinguishes semantic regeneration from serialization continuation.

### Recovery order

1. Parse normally.
2. Apply deterministic normalization and item-level recovery.
3. If JSON is truncated, salvage only fully serialized records from the top-level collection.
4. Ask the LLM for **only the remaining records**; do not regenerate/revise completed records.
5. Merge prefix + continuation deterministically and deduplicate exact repeats.
6. Use full semantic regeneration only when the artifact remains semantically/protocol invalid.

Attempt diagnostics now record `retry_mode`, including `initial`, `serialization_continuation`, and `semantic_regeneration`.

The retry token ceiling no longer doubles twice when reasoning is disabled; disabling reasoning is treated as a repair choice, not as justification for another automatic 2x expansion.

## Versions

- `SCHEMA_VERSION = semantic-claims-v4.13`
- `PIPELINE_REVISION = independent-semantic-views-v4.13`
- `artifact_version = 9`

These version changes invalidate older cached artifacts through the existing artifact metadata / pipeline fingerprint mechanism.

## Verification

Executed from the release source tree:

- **99 named regression checks: PASS**
- **2,047 exhaustive valid aggregation combinations: PASS**
- **200,000 malformed-shape fuzz cases: PASS (no validator crash)**
- Python `py_compile` / `compileall`: **PASS**

New targeted checks include:

- zero safety obligations after Stage-2 filtering -> Benign, not AnalysisFailure;
- empty `requirements` accepted only as the Reasoner safety-gate rejection mechanism;
- empty groups removed before Stage 3;
- truncated collection prefix salvage preserves only complete records;
- continuation merge preserves prior records and deduplicates exact repeats;
- a truncated Value-Agent response performs `serialization_continuation` rather than semantic regeneration;
- continuation prompt explicitly forbids regenerating/revising prior records;
- real unrecoverable parse failures still produce AnalysisFailure and do not stop the batch;
- item-level grounding recovery, cached-token accounting, triggering-obligation tracing, and progress completion remain covered.

## Important limitation

These are pipeline/contract regression tests, not a claim of improved PrimeVul accuracy. A fresh, no-cache live run is required to measure whether the new safety-contract gates remove the observed false-positive obligations and whether continuation reduces actual token usage on long generations.
