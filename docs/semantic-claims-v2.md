# Semantic claims v2

V2 writes exactly three artifacts for each sample:

```text
stages/semantic-v2/<sample_id>/stage_1_semantic_model.json
stages/semantic-v2/<sample_id>/stage_2_rules.json
stages/semantic-v2/<sample_id>/stage_3_obligation_adjudicator.json
```

There is no intermediate linking stage. Stage 1 produces a semantic model and
deterministically builds `operation_contexts` directly from explicit IDs.

## Stage 1: raw claims and operation contexts

The Operation Agent emits `operations`. Every operation has exactly five fields:
`id`, `location`, `entities`, `claim`, and `evidence`. Operation IDs are `o1`,
`o2`, and so on.

The State, Value, and Execution agents emit `states`, `values`, and `executions`.
Their records have the same five fields plus a sixth field, `operation_ids`.
Those IDs must name one or more existing operations. Their prefixes are `s`, `v`,
and `e`; for example, `e1` is an execution fact, not an operation.

`location` is `L<number>`, and every evidence fragment is exact source text in
the form `L<number>: <exact source text>`. Raw claims are semantic assertions,
not vulnerability conclusions.

`operation_contexts` contains one context per operation in source order:

```json
{
  "operation_id": "o1",
  "operation": { "id": "o1", "location": "L4", "entities": ["p"], "claim": "read p[i]", "evidence": "L4: return p[i];" },
  "state_facts": [],
  "value_facts": [],
  "execution_facts": []
}
```

A fact appears in a context only when its `operation_ids` explicitly contains
that context's `operation_id`; no relevance is inferred from similar names,
locations, or prose.

## Stage 2: atomic obligations

Stage 2 consumes these contexts and creates one or more atomic obligations for
each operation. Every obligation has exactly `id`, `operation_id`,
`safety_requirement`, `applicable_condition`, and `evidence_refs`.
`safety_requirement` states one required property using “must”; independent
properties are separate obligations. Evidence references use raw Stage 1 paths
such as `operation_agent.operations[0]` and must include the anchored operation.

## Stage 3: adjudication and aggregation

Each Stage 3 adjudication has exactly six fields: `obligation_id`, `assessment`,
`possibility`, `supporting_evidence_refs`, `contradicting_evidence_refs`, and
`confirmation_gap`. `assessment` is one of `violated`, `potentially_violated`,
or `satisfied`.

Aggregation is deterministic and requires a complete valid adjudication for
every produced obligation:

- Any `violated` result produces `Vulnerable`, binary prediction `1`, and
  decision basis `confirmed_violation`.
- Otherwise, any `potentially_violated` result produces `Vulnerable`, binary
  prediction `1`, and decision basis `potential_violation`.
- Only all-`satisfied` results produce `Benign`, binary prediction `0`, and
  decision basis `established_safety`.
- Missing, malformed, duplicate, or failed adjudications produce
  `AnalysisFailure`, `analysis_failure: true`, no binary prediction or decision,
  and decision basis `analysis_failure`.

## Caching, regeneration, and metrics

Every artifact has source/split identity, prompt/config fingerprint, policy
revision, and upstream hashes. The semantic-model fingerprint and operation
context dependency graph changed in v2, so regenerate artifacts rather than
reusing earlier output. Dry-run and provider artifacts have distinct fingerprints.

```powershell
python -B -m unittest discover -s tests -v
python -B -m src.UI --split test --samples 0 --dry-run --overwrite --output-root stages/semantic-v2-verification
python scripts/eval_cwe_coverage.py --stage-root stages/semantic-v2 --split test
python scripts/eval_pipeline_metrics.py --stage-root stages/semantic-v2 --split test
```

The dry-run checks orchestration and serialization only; it does not assess real
provider quality or cost. `eval_pipeline_metrics.py` reports TP/FP/TN/FN,
accuracy/precision/recall/F1, prediction coverage, analysis-failure rate,
claim/operation/obligation coverage, duplicate-claim rate, evidence references
per obligation, and token totals by stage.
