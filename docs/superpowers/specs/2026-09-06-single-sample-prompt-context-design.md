# Single-sample prompt context design

## Goal

Prove the repository-context pipeline on one PrimeVul sample (`test_194963`)
before any batch processing. The offline phase must emit context that can be
inserted directly into an LLM prompt. Runtime must only read the emitted
record; it must not access Git, Joern, or a CPG.

## Fixed sample

- Sample: `test_194963`
- Project: `ImageMagick6`
- Repository: `https://github.com/ImageMagick/ImageMagick6`
- Vulnerable revision: `98abe54e6b54b4cfeef90ea7a5943cf453b680a3`
- File: `magick/property.c`
- Function: `GetEXIFProperty`

The repository metadata and function body remain the source of truth. A
context record is unavailable if the revision or target function cannot be
resolved exactly.

## Pipeline

1. Load only `test_194963` and its repository index record.
2. Resolve the vulnerable revision and verify that the dataset function maps
   uniquely to `magick/property.c`.
3. Build or reuse the revision CPG during offline preprocessing.
4. Run one fixed Joern extraction anchored to the target function. No runtime
   obligation or agent query is required.
5. Normalize, deduplicate, bound, and render the extracted evidence into four
   prompt sections.
6. Append or replace the sample's single record in `context.jsonl`.
7. Validate that the record can be loaded without Git or Joern.

The prototype keeps temporary repository and CPG artifacts until its output is
verified. Cleanup automation is outside this one-sample proof and will be
designed before batch execution.

## Evidence contract

The fixed extraction covers the repository evidence named in the paper:

1. **Call relations**: calls made by the target, resolved callees when
   available, call-site code, arguments, and direct callers.
2. **Data dependencies**: bounded definition/use or data-flow paths involving
   target parameters, locals, calls, and return values.
3. **Control dependencies**: branch or loop conditions controlling relevant
   target operations, with dominance information only when it adds a distinct
   source-level fact.
4. **Declarations and types**: target signature, parameters, locals, referenced
   members, and their resolved types or declarations.

Every retained item maps back to source-level text and a file/line when Joern
provides it. Unresolved relations are reported in `limitations`; they are not
invented or inferred by the renderer.

## Storage format

The output is one JSON object per line:

```json
{
  "sample_id": "test_194963",
  "context": "[CALL RELATIONS]\n...\n\n[DATA DEPENDENCIES]\n...\n\n[CONTROL DEPENDENCIES]\n...\n\n[DECLARATIONS AND TYPES]\n...",
  "limitations": []
}
```

The context text is deterministic. Empty sections remain present and say that
no mapped evidence was found. The renderer enforces a fixed item/character
budget and records truncation in `limitations`.

## Implementation boundary

The existing Git resolver, source matcher, CPG cache, and Joern adapter are
reused. A new offline context builder coordinates a function-level extraction
and rendering. The existing dynamic query service is not called by the new
runtime path and is not removed as part of this prototype.

The CLI accepts an explicit sample ID and output path. It must reject batch
selection for this proof, preserve unrelated JSONL records, and atomically
replace the selected sample's record.

## Verification

- Unit tests cover deterministic rendering, empty evidence, limitations,
  truncation, and JSONL replacement.
- A service/CLI test proves that loading the generated record requires neither
  Git nor Joern.
- The real smoke run processes only `test_194963` with Joern
  `E:\\tools\\joern-v4.0.592` and inspects all four output sections.
- The result is considered a successful prototype even when one evidence
  family is empty, provided the limitation is explicit and the other evidence
  is source-grounded.
