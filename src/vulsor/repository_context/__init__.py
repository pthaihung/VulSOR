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
    SourceAnchor,
    SourceLocation,
    StrictModel,
    TargetAnchor,
)

if TYPE_CHECKING:
    from .service import PreparedRepository, RepositoryContextService


def __getattr__(name: str) -> Any:
    """Load service types lazily so config can import model contracts safely."""
    if name in {"PreparedRepository", "RepositoryContextService"}:
        from .service import PreparedRepository, RepositoryContextService

        return {
            "PreparedRepository": PreparedRepository,
            "RepositoryContextService": RepositoryContextService,
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
    "PreparedRepository",
    "RepositoryContextService",
    "RepositoryEvidence",
    "RepositoryIndexRecord",
    "RepositoryRef",
    "SourceAnchor",
    "SourceLocation",
    "StrictModel",
    "TargetAnchor",
)
