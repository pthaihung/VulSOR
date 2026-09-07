from pathlib import Path

from vulsor.config import load_config


def test_primevul_config_uses_compact_context_layout() -> None:
    config = load_config(Path("configs/primevul.yaml"))
    dataset = config.datasets["primevul"]

    assert dataset.input_files["test"] == Path("data/primevul/test.jsonl")
    assert dataset.repository_index_files["test"] == Path(
        "data/primevul/index.jsonl"
    )
    assert config.repository_context.cache_root == Path("data/primevul/context")
    assert config.repository_context.catalog_path == Path(
        "data/primevul/context/catalog.jsonl"
    )
    assert config.repository_context.unavailable_path == Path(
        "data/primevul/context/unavailable.jsonl"
    )
