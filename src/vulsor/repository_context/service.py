"""Separate offline repository preparation from query-only context retrieval."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from .cpg_cache import CpgCache, CpgCacheError, CpgIdentity, read_ready_cpg
from .evidence import normalize_repository_evidence, source_path
from .git_repository import (
    GitRepositoryResolver,
    RepositoryResolutionError,
    canonicalize_repository_url,
    revision_snapshot_path,
)
from .index import RepositoryIndex, _validate_repository_relative_file_path
from .joern import JoernAdapter, JoernError
from .models import (
    AnchorResolution,
    EvidenceRequest,
    Limitation,
    PreparedCpg,
    PreparedRecord,
    PreparedSourceMatch,
    RepositoryEvidence,
)
from .prepared import PreparedCatalog
from .prompt_context import PromptContextError, PromptContextRecord, render_prompt_context
from .source_match import SourceMatchStatus, match_sample_to_file, normalized_code_sha256


class RepositoryPreparationError(RuntimeError):
    """A controlled failure during the explicitly offline preparation phase."""

    def __init__(self, kind: str, detail: str):
        self.kind, self.detail = kind, detail
        super().__init__(detail)


def _record_or_error(index: RepositoryIndex, sample_id: str):
    try:
        return index.get(sample_id)
    except KeyError:
        raise RepositoryPreparationError(
            "repository_ref_missing", "No repository metadata exists for the sample"
        ) from None


def _validate_sample(record, sample_code: str, repository_root: Path):
    try:
        if normalized_code_sha256(sample_code) != record.target.normalized_code_sha256:
            raise RepositoryPreparationError(
                "source_mismatch", "Sample hash differs from repository index"
            )
        filename = _validate_repository_relative_file_path(record.target.file_path)
        file_text = source_path(repository_root, filename).read_text(encoding="utf-8")
    except RepositoryPreparationError:
        raise
    except (OSError, UnicodeError, ValueError):
        raise RepositoryPreparationError(
            "source_unavailable", "Indexed source cannot be read safely"
        ) from None
    match = match_sample_to_file(sample_code, file_text)
    if match.status not in {SourceMatchStatus.EXACT, SourceMatchStatus.NORMALIZED}:
        raise RepositoryPreparationError(
            f"source_{match.status.value}",
            "Sample does not have a unique match in the indexed revision",
        )
    if (
        record.target.start_line is not None
        and record.target.start_line != match.start_line
    ) or (
        record.target.end_line is not None and record.target.end_line != match.end_line
    ):
        raise RepositoryPreparationError(
            "source_mismatch", "Indexed span differs from source match"
        )
    return match


@dataclass
class RepositoryPreprocessor:
    """The only service allowed to resolve Git revisions and build CPGs."""

    index: RepositoryIndex
    repositories: GitRepositoryResolver
    cache: CpgCache
    joern: JoernAdapter

    def preprocess_sample(self, sample_id: str, sample_code: str) -> PreparedRecord:
        record = _record_or_error(self.index, sample_id)
        try:
            resolved = self.repositories.resolve(record.repository)
        except RepositoryResolutionError:
            raise RepositoryPreparationError(
                "repository_unavailable", "Repository resolution failed"
            ) from None
        if resolved.resolved_revision.lower() != record.repository.revision.lower():
            raise RepositoryPreparationError(
                "revision_mismatch", "Resolved revision differs from repository index"
            )
        match = _validate_sample(record, sample_code, resolved.repository_root)
        try:
            version = self.joern.version()
            identity = CpgIdentity(
                repository_url=str(record.repository.repository_url),
                revision=resolved.resolved_revision,
                joern_version=version,
            )

            def build(directory: Path) -> None:
                self.joern.build_cpg(resolved.repository_root, directory / "cpg.bin")
                self.joern.smoke(directory / "cpg.bin")

            artifact = self.cache.get_or_build(identity, build)
            if artifact.cache_hit:
                self.joern.smoke(artifact.cpg_path)
        except CpgCacheError:
            raise RepositoryPreparationError("cpg_unavailable", "CPG cache failed") from None
        except JoernError:
            raise RepositoryPreparationError("joern_unavailable", "Joern preprocessing failed") from None
        assert match.start_line is not None and match.end_line is not None
        return PreparedRecord(
            sample_id=sample_id,
            repository=record.repository,
            target=record.target,
            source_match=PreparedSourceMatch(
                status=match.status.value,
                start_line=match.start_line,
                end_line=match.end_line,
            ),
            cpg=PreparedCpg(
                cache_key=artifact.cache_key,
                joern_version=identity.joern_version,
                frontend=identity.frontend,
                frontend_args=identity.frontend_args,
            ),
        )

    def build_prompt_context(
        self,
        sample_id: str,
        sample_code: str,
        *,
        max_items: int = 120,
        max_characters: int = 24_000,
    ) -> PromptContextRecord:
        """Build fixed prompt context while Git and Joern are still offline-only."""

        prepared = self.preprocess_sample(sample_id, sample_code)
        artifact = read_ready_cpg(self.cache.cache_root, prepared)
        if artifact is None:
            raise RepositoryPreparationError(
                "cpg_unavailable", "Prepared CPG could not be read"
            )
        try:
            raw = self.joern.extract_function_context(
                artifact.cpg_path,
                file_path=prepared.target.file_path,
                function_name=prepared.target.function_name,
                max_items=max_items,
            )
            return render_prompt_context(
                sample_id, raw, max_characters=max_characters
            )
        except PromptContextError:
            raise RepositoryPreparationError(
                "context_unavailable", "Function context could not be rendered"
            ) from None
        except JoernError:
            raise RepositoryPreparationError(
                "joern_unavailable", "Joern context extraction failed"
            ) from None


@dataclass
class RepositoryContextQueryService:
    """Read-only runtime: it never resolves Git, builds a CPG, or smoke-tests."""

    index: RepositoryIndex
    catalog: PreparedCatalog
    cache_root: Path
    joern: JoernAdapter

    def _not_found(self, request: EvidenceRequest) -> RepositoryEvidence:
        return RepositoryEvidence(
            request_id=request.request_id,
            status="not_found",
            resolved_revision=None,
            anchor_resolution=AnchorResolution(status="not_found", candidate_count=0),
            limitations=(
                Limitation(
                    kind="repository_context_unavailable",
                    detail="Prepared repository context is unavailable for this sample",
                ),
            ),
        )

    def retrieve(
        self, request: EvidenceRequest, sample_code: str, *, sample_id: str
    ) -> RepositoryEvidence:
        prepared = self.catalog.get_or_none(sample_id)
        if prepared is None:
            return self._not_found(request)
        try:
            indexed = self.index.get(sample_id)
            if prepared.repository != indexed.repository or prepared.target != indexed.target:
                return self._not_found(request)
            supplied = request.repository_ref
            if (
                indexed.repository.repository_id != supplied.repository_id
                or indexed.repository.revision.lower() != supplied.revision.lower()
                or canonicalize_repository_url(indexed.repository.repository_url)
                != canonicalize_repository_url(supplied.repository_url)
                or request.anchor.file_path.replace("\\", "/") != indexed.target.file_path
                or request.anchor.function_name != indexed.target.function_name
            ):
                return self._not_found(request)
            root = revision_snapshot_path(
                self.cache_root, prepared.repository.repository_url, prepared.repository.revision
            )
            if root.is_symlink() or not root.is_dir():
                return self._not_found(request)
            match = _validate_sample(indexed, sample_code, root)
            if (
                match.status.value != prepared.source_match.status
                or match.start_line != prepared.source_match.start_line
                or match.end_line != prepared.source_match.end_line
                or not prepared.source_match.start_line <= request.anchor.line <= prepared.source_match.end_line
            ):
                return self._not_found(request)
            artifact = read_ready_cpg(self.cache_root, prepared)
            if artifact is None:
                return self._not_found(request)
            raw = self.joern.query(artifact.cpg_path, request)
            return normalize_repository_evidence(raw, request, root)
        except RepositoryPreparationError:
            return self._not_found(request)
        except (OSError, UnicodeError, ValueError, KeyError):
            return self._not_found(request)
        except JoernError:
            return RepositoryEvidence(
                request_id=request.request_id,
                status="unavailable",
                resolved_revision=prepared.repository.revision,
                anchor_resolution=AnchorResolution(status="not_found", candidate_count=0),
                limitations=(
                    Limitation(kind="joern_unavailable", detail="Joern query failed"),
                ),
            )


__all__ = [
    "RepositoryContextQueryService",
    "RepositoryPreprocessor",
    "RepositoryPreparationError",
]
