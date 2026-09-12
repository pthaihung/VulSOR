from __future__ import annotations

"""Small compatibility envelope for versioned VulSOR pipeline artifacts."""

import hashlib
import json
from typing import Any

from .SemanticContract import SCHEMA_VERSION


def canonical_fingerprint(value: Any) -> str:
    payload = json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def artifact_metadata(
    stage: str,
    *,
    source_hash: str | None = None,
    upstream_hashes: dict[str, str] | None = None,
    sample_id: str | None = None,
    split: str | None = None,
    pipeline_fingerprint: str | None = None,
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "artifact_version": 8,
        "stage": stage,
        "sample_id": sample_id,
        "split": split,
        "source_hash": source_hash,
        "upstream_hashes": dict(upstream_hashes or {}),
        "pipeline_fingerprint": pipeline_fingerprint,
    }


def validate_artifact(
    record: Any,
    expected_stage: str | None = None,
    expected_metadata: dict[str, Any] | None = None,
) -> list[str]:
    if not isinstance(record, dict):
        return ["artifact must be an object"]
    errors: list[str] = []
    if record.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"artifact schema_version must be {SCHEMA_VERSION}")
    if expected_stage is not None and record.get("stage") != expected_stage:
        errors.append(f"artifact stage must be {expected_stage}")
    if expected_metadata:
        actual = record.get("artifact_metadata")
        if not isinstance(actual, dict):
            errors.append("artifact_metadata is missing")
        else:
            for key, expected in expected_metadata.items():
                if actual.get(key) != expected:
                    errors.append(
                        f"artifact_metadata.{key} does not match current inputs"
                    )
    return errors
