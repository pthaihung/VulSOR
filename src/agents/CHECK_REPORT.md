# VulSOR semantic v4.12 — Verification Report

## Scope
v4.12 keeps the binary obligation ontology unchanged: `satisfied | violated` and the deterministic final rule `any violated obligation -> Vulnerable; otherwise Benign`.

This revision addresses two issues observed in the clean v4.11 PrimeVul run:
1. Stage 3 had become too conservative because `violated` effectively required a proof-like concrete witness. v4.12 restores a symmetric semantic decision: `violated` iff a feasible violating execution exists; `satisfied` iff the relevant feasible executions exclude all violating states. A concrete input/proof object is not required.
2. Small formatting/grounding defects were causing whole-sample `AnalysisFailure`. v4.12 adds deterministic item-level recovery without inventing semantic facts.

## AnalysisFailure recovery policy
The pipeline now repairs or locally drops representation-only defects before rejecting an entire stage:
- duplicate semantic `entities` and duplicate Operation locations are deduplicated;
- wrong Operation line anchors are canonicalized when the source occurrence can be resolved safely;
- ungroundable individual Stage-1 facts/Operations are dropped rather than invalidating the whole semantic view;
- semantic evidence line anchors are rewritten to exact source lines when uniquely or locally resolvable;
- common Stage-3 `{ "assessments": [...] }` wrappers are unwrapped and labels normalized;
- a valid first JSON value is accepted when a provider appends trailing extra data;
- safely splittable Stage-2 requirements are split before validation;
- Stage-2 copy-only `locations` and `expression` fields are restored from the matching Operation;
- unsplittable compound requirements are no longer protocol-fatal.

`AnalysisFailure` is retained for genuine unrecoverable protocol/technical failures such as repeatedly unparseable JSON, missing required stage structure after retry, API failure, or an irreconcilable assessment count.

## Versioning
- `SCHEMA_VERSION = semantic-claims-v4.12`
- `PIPELINE_REVISION = independent-semantic-views-v4.12`
- artifact version = 8

## Verification
The packaged source passes:
- Python compile / compileall
- 88 named regression checks
- exhaustive aggregation over 2,047 valid `satisfied/violated` arrays
- 200,000 malformed-shape fuzz cases without validator crashes
- end-to-end Benign and Vulnerable mock flows
- cache reuse checks
- true technical failure -> `AnalysisFailure` with preserved token attribution
- batch continuation after technical failure
- item-level ungrounded Operation recovery without `AnalysisFailure`
- duplicate-entity normalization
- unique wrong-line Operation grounding repair
- multiline call / macro grounding tests
- Stage-2 atomic/copy-field normalization

These are pipeline/contract tests, not a claim of PrimeVul accuracy. A fresh live run is still required to measure v4.12's prediction behavior.
