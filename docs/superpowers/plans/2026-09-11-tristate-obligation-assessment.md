# Tri-state obligation assessment implementation

This revision implements the approved second approach: extraction and obligation
generation remain evidence-grounded, while final adjudication distinguishes proven
safety, proven violation, and insufficient evidence.

Implemented contract:

- Stage 1 records have exactly `id`, `location`, `entities`, `claim`, `evidence`.
- Every evidence line is an exact `L<number>:` source fragment.
- Operation emits one distinct safety-relevant action per record.
- State does not derive state from guards; Value does not own control-flow facts;
  Execution owns reachability and does not propagate guards through mutations or
  omitted source windows.
- Operation anchors define relevance, not truth and not mandatory claim coverage.
- Stage 1, Stage 1.5, Stage 2, and Stage 3 do not silently truncate records or facts
  to fixed caps.
- Stage 2 may emit an abstract required safety property even when support claims do
  not instantiate a concrete bound. Absence of a claim is not evidence that a guard
  or cleanup is missing.
- Stage 3 uses `assessment: satisfied | violated | undetermined`; cited refs must
  belong to the evidence supplied for that exact obligation.
- Final policy is `Vulnerable` for any violation, `Benign` only when every produced
  obligation is satisfied, and `InsufficientEvidence` otherwise. A separate
  best-effort binary result is retained for benchmark compatibility.

Offline verification consists of prompt-contract tests, semantic-schema and
grounding tests, evidence-scope tests, aggregation tests, metrics tests, a complete
unit-test discovery run, compilation, and a one-sample dry-run. A real provider run
is deliberately separate because it consumes API tokens.
