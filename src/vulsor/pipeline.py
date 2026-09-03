"""Pipeline orchestration for VulSOR."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

from vulsor.analysis.program import analyze_source_code
from vulsor.config import VulSORConfig


class Stage(str, Enum):
    """The six pipeline stages, in execution order.

    See the project notes for the pipeline and incremental
    implementation policy.
    """

    PROGRAM_ANALYSIS = "program_analysis"
    SEMANTIC = "semantic"
    OBLIGATION = "obligation"
    VALIDATION = "validation"
    VERIFICATION = "verification"
    ADJUDICATION = "adjudication"


STAGE_ORDER: list[Stage] = [
    Stage.PROGRAM_ANALYSIS,
    Stage.SEMANTIC,
    Stage.OBLIGATION,
    Stage.VALIDATION,
    Stage.VERIFICATION,
    Stage.ADJUDICATION,
]


@dataclass
class PipelineResult:
    """Whatever the pipeline actually produced, up to `stage_reached`.

    Fields for stages that did not run are left as None / empty.
    Do not populate a field with a guessed or placeholder value; an
    unreached stage must leave its field unset (see project rule:
    "Do not fabricate missing values, facts, evidence, or tool results").
    """

    stage_reached: Stage
    program_facts: Optional[Any] = None
    semantics: Optional[Any] = None
    obligations: Optional[Any] = None
    verdict: Optional[str] = None
    evidence: list[Any] = field(default_factory=list)


def run_pipeline(
    source_code: str,
    config: VulSORConfig,
    until_stage: Stage = Stage.ADJUDICATION,
) -> PipelineResult:
    """Run the VulSOR pipeline on a single function's source code.

    Args:
        source_code: the C/C++ source of one function (or a small
            fixture containing it).
        config: resolved VulSORConfig (tool paths, dataset roots, ...).
        until_stage: run only up to and including this stage.

    Returns:
        A PipelineResult describing how far execution got.

    Raises:
        NotImplementedError: If a later stage is requested.
    """
    if until_stage not in STAGE_ORDER:
        raise ValueError(f"Unknown stage: {until_stage!r}")

    program_facts = analyze_source_code(
        source_code,
        clang_executable=config.tools.clang,
    )

    if until_stage is Stage.PROGRAM_ANALYSIS:
        return PipelineResult(
            stage_reached=Stage.PROGRAM_ANALYSIS,
            program_facts=program_facts,
        )

    raise NotImplementedError(
        f"Pipeline stage after {Stage.PROGRAM_ANALYSIS.value!r} "
        "is not implemented yet."
    )
