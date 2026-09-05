"""Validate raw graph results and select source-grounded, bounded evidence."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PureWindowsPath
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from .models import (
    AnchorResolution,
    BudgetUsage,
    EvidenceItem,
    EvidenceProvenance,
    EvidenceRequest,
    Limitation,
    RepositoryEvidence,
    SourceLocation,
)

RANK = {
    "anchor": 0,
    "argument": 1,
    "direct_entity": 1,
    "callee_definition": 2,
    "callee_parameter_use": 2,
    "declaration": 2,
    "type": 2,
    "data_flow_path": 3,
    "control_dependence": 4,
    "dominance": 4,
    "call_neighbor": 5,
}


class RawModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class RawNode(RawModel):
    id: int = Field(ge=0)
    nodeType: str = Field(min_length=1)
    name: str | None
    code: str | None
    file: str | None
    line: int | None = Field(ge=1)
    column: int | None = Field(ge=1)
    method: str | None
    typeFullName: str | None
    argumentIndex: int | None = Field(ge=-1)


class RawRecord(RawModel):
    kind: str
    relation: str = Field(min_length=1)
    subject: str = Field(min_length=1)
    object: str | None = None
    conditions: list[str]
    node: RawNode
    path: list[RawNode]

    @model_validator(mode="after")
    def check_record(self):
        if (
            self.kind not in RANK
            or not self.subject.strip()
            or not self.relation.strip()
        ):
            raise ValueError("invalid record identity")
        if any(not condition.strip() for condition in self.conditions):
            raise ValueError("empty condition")
        if bool(self.path) != (self.kind == "data_flow_path"):
            raise ValueError("only flow records must contain a path")
        return self


class RawResult(RawModel):
    schema_version: int
    request_id: str
    resolved_revision: str
    anchor_resolution: AnchorResolution
    families: dict[str, list[RawRecord]]
    limitations: list[Limitation]
    truncated: bool


def validate_raw_result(raw: dict, request: EvidenceRequest) -> dict:
    """Validate the transport without touching source files or echoing payloads."""
    try:
        result = RawResult.model_validate(raw)
        if result.schema_version != 1 or result.request_id != request.request_id:
            raise ValueError("invalid result identity")
        if result.resolved_revision.lower() != request.repository_ref.revision.lower():
            raise ValueError("revision mismatch")
        allowed = {family.value for family in request.allowed_relations}
        if set(result.families) - allowed:
            raise ValueError("unrequested query family")
        if result.anchor_resolution.status != "exact" and result.families:
            raise ValueError("nonexact anchor must have no families")
    except (ValidationError, ValueError, TypeError):
        raise ValueError("invalid repository query result schema") from None
    return result.model_dump(mode="json")


def source_path(repository_root: Path, filename: str) -> Path:
    """Resolve an indexed/source-mapped path without following repository links."""
    root = repository_root.resolve()
    normalized = filename.replace("\\", "/")
    parts = normalized.split("/")
    if "\x00" in normalized or ".." in parts:
        raise ValueError("unsafe repository source path")
    candidate = Path(normalized)
    if candidate.is_absolute():
        try:
            relative = candidate.relative_to(root)
        except ValueError:
            raise ValueError("source path is outside the repository") from None
    else:
        if PureWindowsPath(normalized).drive or ":" in normalized:
            raise ValueError("unsafe repository source path")
        relative = candidate
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink() or getattr(current, "is_junction", lambda: False)():
            raise ValueError("repository source links are unsupported")
    try:
        current.resolve().relative_to(root)
    except ValueError:
        raise ValueError("source path is outside the repository") from None
    return current


class _MissingSource(Exception):
    pass


def normalize_repository_evidence(
    raw: dict,
    request: EvidenceRequest,
    repository_root: Path,
) -> RepositoryEvidence:
    validated = validate_raw_result(raw, request)
    result = RawResult.model_validate(validated)
    anchor = result.anchor_resolution
    base = dict(
        request_id=request.request_id,
        resolved_revision=result.resolved_revision,
        anchor_resolution=anchor,
    )
    if anchor.status != "exact":
        return RepositoryEvidence(**base, status=anchor.status.value)

    limits: list[Limitation] = []
    allowed = {family.value for family in request.allowed_relations}
    for limitation in result.limitations:
        # Tool diagnostics may contain host paths or repository secrets. Keep only
        # the family identity and a controlled message in the evidence boundary.
        families = sorted(f for f in allowed if f in limitation.detail)
        limits.append(
            Limitation(
                kind="query_family_failed",
                detail=", ".join(families or sorted(allowed))
                + ": query reported a limitation",
            )
        )
    for family in sorted(allowed - result.families.keys()):
        limits.append(
            Limitation(
                kind="query_family_missing", detail=f"{family}: no result returned"
            )
        )
    root = Path(repository_root).resolve()
    files: dict[Path, list[str]] = {}

    def locate(node: RawNode) -> SourceLocation:
        if not node.file or node.line is None:
            raise _MissingSource()
        path = source_path(root, node.file)
        if path not in files:
            try:
                files[path] = path.read_text(encoding="utf-8").splitlines()
            except (OSError, UnicodeError):
                raise _MissingSource() from None
        lines = files[path]
        if node.line > len(lines):
            raise _MissingSource()
        return SourceLocation(
            file_path=path.relative_to(root).as_posix(),
            start_line=node.line,
            end_line=node.line,
            start_column=node.column,
            code=lines[node.line - 1] or None,
        )

    # Canonical source content determines identity; graph IDs remain provenance.
    candidates: dict[str, tuple[dict, set[int], set[str], str]] = {}
    for family in sorted(result.families):
        for record in result.families[family]:
            try:
                source = locate(record.node)
                path = tuple(locate(node) for node in record.path)
            except _MissingSource:
                limits.append(
                    Limitation(
                        kind="source_mapping_missing",
                        detail=f"{family}: an entire record lacked readable source positions",
                    )
                )
                continue
            item = dict(
                kind=record.kind,
                subject=record.subject,
                relation=record.relation,
                object=record.object,
                conditions=tuple(sorted(set(record.conditions))),
                source=source.model_dump(mode="json"),
                path=[location.model_dump(mode="json") for location in path],
            )
            canonical = json.dumps(item, sort_keys=True, separators=(",", ":"))
            nodes = [record.node, *record.path]
            ids = {node.id for node in nodes}
            types = {node.nodeType for node in nodes}
            if canonical in candidates:
                candidates[canonical][1].update(ids)
                candidates[canonical][2].update(types)
            else:
                candidates[canonical] = (item, ids, types, family)

    def make_item(canonical, entry):
        item, ids, types, family = entry
        return EvidenceItem(
            evidence_id="repo_ev_"
            + hashlib.sha256(canonical.encode()).hexdigest()[:16],
            **item,
            provenance=EvidenceProvenance(
                query_family=family,
                cpg_node_ids=tuple(sorted(ids)),
                cpg_node_types=tuple(sorted(types)),
            ),
        )

    items = [make_item(key, value) for key, value in candidates.items()]
    items.sort(
        key=lambda item: (
            RANK[item.kind],
            len(item.path),
            item.source.file_path,
            item.source.start_line,
            item.evidence_id,
        )
    )
    selected = []
    node_ids: set[int] = set()
    source_lines: set[tuple[str, int]] = set()
    flow_count = 0
    truncated = result.truncated
    budget = request.budget
    for item in items:
        next_nodes = node_ids | set(item.provenance.cpg_node_ids)
        next_lines = source_lines | {
            (loc.file_path, loc.start_line) for loc in (item.source, *item.path)
        }
        next_flows = flow_count + int(item.kind == "data_flow_path")
        if (
            len(next_nodes) > budget.max_nodes
            or len(next_lines) > budget.max_source_lines
            or next_flows > budget.max_flow_paths
            or len(selected) >= budget.max_evidence_items
        ):
            truncated = True
            continue
        selected.append(item)
        node_ids, source_lines, flow_count = next_nodes, next_lines, next_flows
    if truncated:
        limits.append(
            Limitation(
                kind="context_budget_exceeded",
                detail="Repository evidence was truncated by the requested budget",
            )
        )
    unique_limits = {(lim.kind, lim.detail): lim for lim in limits}
    return RepositoryEvidence(
        **base,
        status="partial" if limits else "complete",
        evidence=tuple(selected),
        limitations=tuple(unique_limits[key] for key in sorted(unique_limits)),
        budget_usage=BudgetUsage(
            nodes=len(node_ids),
            source_lines=len(source_lines),
            flow_paths=flow_count,
            evidence_items=len(selected),
            truncated=truncated,
        ),
    )
