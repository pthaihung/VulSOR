"""Contracts for bounded, obligation-driven repository evidence."""

from typing import TYPE_CHECKING, Any

from .models import (
    AnchorResolution,
    AnchorStatus,
    BudgetUsage,
    EvidenceBudget,
    EvidenceItem,
    EvidencePhase,
    EvidenceProvenance,
    EvidenceRequest,
    EvidenceStatus,
    Limitation,
    QueryFamily,
    RelationFamily,
    RepositoryEvidence,
    RepositoryIndexRecord,
    RepositoryRef,
    PreparedCpg,
    PreparedRecord,
    PreparedSourceMatch,
    SourceAnchor,
    SourceLocation,
    StrictModel,
    TargetAnchor,
)

if TYPE_CHECKING:
    from .service import RepositoryContextQueryService, RepositoryPreprocessor


def __getattr__(name: str) -> Any:
    """Load service types lazily so config can import model contracts safely."""
    if name in {"RepositoryContextQueryService", "RepositoryPreprocessor"}:
        from .service import RepositoryContextQueryService, RepositoryPreprocessor

        return {
            "RepositoryContextQueryService": RepositoryContextQueryService,
            "RepositoryPreprocessor": RepositoryPreprocessor,
        }[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = (
    "AnchorResolution",
    "AnchorStatus",
    "BudgetUsage",
    "EvidenceBudget",
    "EvidenceItem",
    "EvidencePhase",
    "EvidenceProvenance",
    "EvidenceRequest",
    "EvidenceStatus",
    "Limitation",
    "QueryFamily",
    "RelationFamily",
    "PreparedCpg",
    "PreparedRecord",
    "PreparedSourceMatch",
    "RepositoryContextQueryService",
    "RepositoryPreprocessor",
    "RepositoryEvidence",
    "RepositoryIndexRecord",
    "RepositoryRef",
    "SourceAnchor",
    "SourceLocation",
    "StrictModel",
    "TargetAnchor",
)
