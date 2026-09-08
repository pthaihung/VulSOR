"""File-level repository context extraction components."""

from .file_context_selection import select_file_context
from .file_context_service import FileContextResult, FileContextService
from .file_cpg import FileContextError, FileCpgCache
from .primevul_file_source import (
    FileSourceResolutionError,
    PrimeVulFileSourceResolver,
    ResolvedFileSource,
)

__all__ = (
    "FileContextError",
    "FileContextResult",
    "FileContextService",
    "FileCpgCache",
    "FileSourceResolutionError",
    "PrimeVulFileSourceResolver",
    "ResolvedFileSource",
    "select_file_context",
)
