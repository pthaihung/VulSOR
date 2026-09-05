"""Prepare exact repository revisions and retrieve obligation-scoped context."""

from dataclasses import dataclass
from pathlib import Path

from .cpg_cache import CpgArtifact, CpgCache, CpgCacheError, CpgIdentity
from .evidence import normalize_repository_evidence, source_path
from .git_repository import (
    GitRepositoryResolver,
    RepositoryResolutionError,
    canonicalize_repository_url,
)
from .index import RepositoryIndex, _validate_repository_relative_file_path
from .joern import JoernAdapter, JoernError
from .models import AnchorResolution, EvidenceRequest, Limitation, RepositoryEvidence
from .source_match import (
    SourceMatch,
    SourceMatchStatus,
    match_sample_to_file,
    normalized_code_sha256,
)


class RepositoryPreparationError(RuntimeError):
    def __init__(self, kind: str, detail: str, status: str = "unavailable"):
        self.kind, self.detail, self.status = kind, detail, status
        super().__init__(detail)


@dataclass(frozen=True)
class PreparedRepository:
    sample_id: str
    repository_root: Path
    resolved_revision: str
    source_match: SourceMatch
    cpg: CpgArtifact


@dataclass
class RepositoryContextService:
    index: RepositoryIndex
    repositories: GitRepositoryResolver
    cache: CpgCache
    joern: JoernAdapter

    def _record(self, sample_id):
        try:
            return self.index.get(sample_id)
        except KeyError:
            raise RepositoryPreparationError(
                "repository_ref_missing",
                "No repository metadata exists for the selected sample",
                "not_found",
            ) from None

    def prepare_sample(self, sample_id: str, sample_code: str) -> PreparedRepository:
        record = self._record(sample_id)
        try:
            digest = normalized_code_sha256(sample_code)
        except ValueError:
            raise RepositoryPreparationError(
                "source_mismatch", "Sample code is empty"
            ) from None
        if digest != record.target.normalized_code_sha256:
            raise RepositoryPreparationError(
                "source_mismatch", "Sample hash differs from repository index"
            )
        resolved = self.repositories.resolve(record.repository)
        if resolved.resolved_revision.lower() != record.repository.revision.lower():
            raise RepositoryPreparationError(
                "revision_mismatch", "Resolved revision differs from repository index"
            )
        try:
            filename = _validate_repository_relative_file_path(record.target.file_path)
            target_file = source_path(resolved.repository_root, filename)
            content = target_file.read_text(encoding="utf-8")
        except (OSError, UnicodeError, ValueError):
            raise RepositoryPreparationError(
                "source_unavailable", "Indexed source cannot be read safely"
            ) from None
        match = match_sample_to_file(sample_code, content)
        if match.status not in {SourceMatchStatus.EXACT, SourceMatchStatus.NORMALIZED}:
            raise RepositoryPreparationError(
                "source_" + match.status.value,
                "Sample does not have a unique match in the indexed revision",
            )
        if (
            record.target.start_line is not None
            and record.target.start_line != match.start_line
        ) or (
            record.target.end_line is not None
            and record.target.end_line != match.end_line
        ):
            raise RepositoryPreparationError(
                "source_mismatch", "Indexed span differs from source match"
            )
        identity = CpgIdentity(
            repository_url=str(record.repository.repository_url),
            revision=resolved.resolved_revision,
            joern_version=self.joern.version(),
        )

        def build(directory: Path):
            self.joern.build_cpg(resolved.repository_root, directory / "cpg.bin")
            self.joern.smoke(directory / "cpg.bin")

        artifact = self.cache.get_or_build(identity, build)
        if artifact.cache_hit:
            self.joern.smoke(artifact.cpg_path)
        return PreparedRepository(
            sample_id,
            resolved.repository_root,
            resolved.resolved_revision,
            match,
            artifact,
        )

    def retrieve(
        self, request: EvidenceRequest, sample_code: str, *, sample_id: str
    ) -> RepositoryEvidence:
        """Sample identity is explicit: request_id identifies a query, not a sample."""
        revision = None
        try:
            record = self._record(sample_id)
            indexed, supplied = record.repository, request.repository_ref
            if (
                indexed.repository_id != supplied.repository_id
                or indexed.revision.lower() != supplied.revision.lower()
                or canonicalize_repository_url(indexed.repository_url)
                != canonicalize_repository_url(supplied.repository_url)
            ):
                raise RepositoryPreparationError(
                    "repository_ref_mismatch",
                    "Request and index refer to different repositories or revisions",
                )
            if (
                request.anchor.file_path.replace("\\", "/") != record.target.file_path
                or request.anchor.function_name != record.target.function_name
            ):
                raise RepositoryPreparationError(
                    "anchor_mismatch", "Request does not target the indexed function"
                )
            prepared = self.prepare_sample(sample_id, sample_code)
            revision = prepared.resolved_revision
            assert prepared.source_match.start_line is not None
            assert prepared.source_match.end_line is not None
            if (
                not prepared.source_match.start_line
                <= request.anchor.line
                <= prepared.source_match.end_line
            ):
                raise RepositoryPreparationError(
                    "anchor_mismatch",
                    "Request operation is outside the sampled function",
                )
            raw = self.joern.query(prepared.cpg.cpg_path, request)
            try:
                return normalize_repository_evidence(
                    raw, request, prepared.repository_root
                )
            except ValueError:
                raise RepositoryPreparationError(
                    "invalid_repository_evidence",
                    "Graph results could not be validated or mapped safely",
                ) from None
        except RepositoryPreparationError as exc:
            kind, detail, status = exc.kind, exc.detail, exc.status
        except RepositoryResolutionError:
            kind, detail, status = (
                "repository_unavailable",
                "Repository resolution failed",
                "unavailable",
            )
        except CpgCacheError:
            kind, detail, status = (
                "cpg_cache_unavailable",
                "CPG cache could not be prepared",
                "unavailable",
            )
        except JoernError:
            kind, detail, status = (
                "joern_unavailable",
                "Joern failed to build, validate or query the CPG",
                "unavailable",
            )
        return RepositoryEvidence(
            request_id=request.request_id,
            status=status,
            resolved_revision=revision,
            anchor_resolution=AnchorResolution(status="not_found", candidate_count=0),
            limitations=(Limitation(kind=kind, detail=detail),),
        )
