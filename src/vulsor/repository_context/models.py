"""Typed contracts for repository-context evidence requests and results."""

from enum import Enum

from pydantic import AnyUrl, BaseModel, ConfigDict, Field, field_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EvidencePhase(str, Enum):
    INSTANTIATE = "instantiate"
    EVALUATE = "evaluate"


class RelationFamily(str, Enum):
    CALL = "call"
    ARGUMENT = "argument"
    DATA_FLOW = "data_flow"
    CONTROL_DEPENDENCE = "control_dependence"
    DECLARATION = "declaration"
    TYPE = "type"


class EvidenceStatus(str, Enum):
    COMPLETE = "complete"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    NOT_FOUND = "not_found"
    AMBIGUOUS = "ambiguous"


class AnchorStatus(str, Enum):
    EXACT = "exact"
    NOT_FOUND = "not_found"
    AMBIGUOUS = "ambiguous"


class RepositoryRef(StrictModel):
    repository_id: str = Field(min_length=1)
    repository_url: AnyUrl
    revision: str = Field(pattern=r"^[0-9a-fA-F]{40}$")

    @field_validator("repository_url")
    @classmethod
    def supported_repository_scheme(cls, value: AnyUrl) -> AnyUrl:
        if value.scheme not in {"https", "http", "ssh", "file"}:
            raise ValueError("unsupported repository URL scheme")
        return value


class TargetAnchor(StrictModel):
    file_path: str = Field(min_length=1)
    function_name: str = Field(min_length=1)
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    normalized_code_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class RepositoryIndexRecord(StrictModel):
    sample_id: str = Field(min_length=1)
    repository: RepositoryRef
    target: TargetAnchor


class SourceAnchor(StrictModel):
    file_path: str = Field(min_length=1)
    function_name: str = Field(min_length=1)
    function_signature: str | None = None
    operation_kind: str = Field(min_length=1)
    operation_name: str = Field(min_length=1)
    line: int = Field(ge=1)
    column: int | None = Field(default=None, ge=1)
    argument_index: int | None = Field(default=None, ge=0)
    entity: str | None = None


class EvidenceBudget(StrictModel):
    max_call_depth: int = Field(default=2, ge=1, le=5)
    max_flow_paths: int = Field(default=10, ge=1, le=100)
    max_nodes: int = Field(default=150, ge=1, le=5000)
    max_source_lines: int = Field(default=200, ge=1, le=10000)
    max_evidence_items: int = Field(default=30, ge=1, le=1000)


class EvidenceRequest(StrictModel):
    request_id: str = Field(min_length=1)
    phase: EvidencePhase
    obligation_ref: str = Field(min_length=1)
    repository_ref: RepositoryRef
    anchor: SourceAnchor
    questions: tuple[str, ...] = Field(min_length=1)
    allowed_relations: tuple[RelationFamily, ...] = Field(min_length=1)
    budget: EvidenceBudget = Field(default_factory=EvidenceBudget)

    @field_validator("questions")
    @classmethod
    def non_blank_questions(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(not value.strip() for value in values):
            raise ValueError("questions must not contain blank values")
        return values


class SourceLocation(StrictModel):
    file_path: str = Field(min_length=1)
    start_line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    start_column: int | None = Field(default=None, ge=1)
    code: str | None = None


class EvidenceProvenance(StrictModel):
    query_family: RelationFamily
    cpg_node_types: tuple[str, ...] = ()
    cpg_node_ids: tuple[int, ...] = ()


class EvidenceItem(StrictModel):
    evidence_id: str = Field(pattern=r"^repo_ev_[0-9a-f]{16}$")
    kind: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    relation: str = Field(min_length=1)
    object: str | None = None
    conditions: tuple[str, ...] = ()
    source: SourceLocation
    provenance: EvidenceProvenance
    path: tuple[SourceLocation, ...] = ()


class Limitation(StrictModel):
    kind: str = Field(min_length=1)
    detail: str = Field(min_length=1)


class AnchorResolution(StrictModel):
    status: AnchorStatus
    candidate_count: int = Field(ge=0)


class BudgetUsage(StrictModel):
    nodes: int = Field(default=0, ge=0)
    flow_paths: int = Field(default=0, ge=0)
    source_lines: int = Field(default=0, ge=0)
    evidence_items: int = Field(default=0, ge=0)
    truncated: bool = False


class RepositoryEvidence(StrictModel):
    request_id: str = Field(min_length=1)
    status: EvidenceStatus
    resolved_revision: str | None = None
    anchor_resolution: AnchorResolution
    evidence: tuple[EvidenceItem, ...] = ()
    limitations: tuple[Limitation, ...] = ()
    budget_usage: BudgetUsage = Field(default_factory=BudgetUsage)
