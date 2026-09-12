from __future__ import annotations

import unittest

from src.agents.ArtifactContract import (
    artifact_metadata,
    canonical_fingerprint,
    operation_context_fingerprint,
    validate_artifact,
)


class ArtifactContractTests(unittest.TestCase):
    def test_metadata_accepts_current_stage(self) -> None:
        record = {**artifact_metadata("semantic_model"), "sample_id": "sample"}
        self.assertEqual([], validate_artifact(record, "semantic_model"))

    def test_old_or_wrong_stage_is_rejected(self) -> None:
        self.assertTrue(validate_artifact({"schema_version": "legacy", "stage": "semantic_model"}, "semantic_model"))
        self.assertTrue(validate_artifact({"schema_version": "semantic-claims-v2", "stage": "rules"}, "semantic_model"))

    def test_fingerprint_is_canonical(self) -> None:
        self.assertEqual(canonical_fingerprint({"b": 2, "a": 1}), canonical_fingerprint({"a": 1, "b": 2}))

    def test_dependency_metadata_mismatch_is_stale(self) -> None:
        metadata = artifact_metadata(
            "rules",
            source_hash="source-a",
            upstream_hashes={"semantic_model": "stage1-a"},
            pipeline_fingerprint="pipeline-a",
        )
        record = {**metadata, "sample_id": "sample", "artifact_metadata": metadata}
        self.assertEqual([], validate_artifact(record, "rules", metadata))
        changed = dict(metadata, upstream_hashes={"semantic_model": "stage1-b"})
        self.assertTrue(validate_artifact(record, "rules", changed))

    def test_rules_dependencies_use_operation_context_fingerprint(self) -> None:
        contexts = [{"operation_id": "o1", "operation": {"id": "o1"}}]
        metadata = artifact_metadata(
            "rules",
            upstream_hashes={
                "semantic_model": "stage1-a",
                "operation_contexts": operation_context_fingerprint(contexts),
            },
        )
        self.assertEqual(
            {"semantic_model", "operation_contexts"},
            set(metadata["upstream_hashes"]),
        )


if __name__ == "__main__":
    unittest.main()
