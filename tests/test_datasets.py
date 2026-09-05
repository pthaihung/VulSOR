from pathlib import Path

from vulsor.config import VulSORConfig
from vulsor.datasets import DatasetSample, iter_dataset_samples


def test_iter_dataset_samples_uses_configured_input_file_for_split(tmp_path: Path) -> None:
    compact = tmp_path / "test.jsonl"
    compact.write_text(
        '{"sample_id":"s1","code":"int f(void) {}"}\n', encoding="utf-8"
    )
    config = VulSORConfig.model_validate(
        {
            "datasets": {
                "primevul": {
                    "root": str(tmp_path),
                    "input_files": {"test": str(compact)},
                }
            }
        }
    )

    assert list(iter_dataset_samples(config, "primevul", "test")) == [
        DatasetSample(sample_id="s1", code="int f(void) {}")
    ]
