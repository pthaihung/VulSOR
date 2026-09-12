from __future__ import annotations

from pathlib import Path
import shutil
from types import SimpleNamespace
import unittest

from src.agents.Pipeline import VulSORPipeline


class OverwriteCacheTests(unittest.TestCase):
    def test_overwrite_clears_split_outputs_and_configured_llm_cache(self) -> None:
        temporary = Path.cwd() / "stages" / ".overwrite-cache-test"
        shutil.rmtree(temporary, ignore_errors=True)
        try:
            split_output = temporary / "stages" / "test_000001"
            split_output.mkdir(parents=True)
            (split_output / "stage_1_semantic_model.json").write_text("{}", encoding="utf-8")
            other_output = temporary / "stages" / "train_000001"
            other_output.mkdir(parents=True)

            cache_dir = temporary / "cache" / "llm"
            cache_dir.mkdir(parents=True)
            (cache_dir / "response.json").write_text("{}", encoding="utf-8")

            pipeline = object.__new__(VulSORPipeline)
            pipeline.stage_root = temporary / "stages"
            pipeline.split = "test"
            pipeline.llm_client = SimpleNamespace(cache_dir=cache_dir, cache_enabled=True)

            pipeline._clear_split_outputs()

            self.assertFalse(split_output.exists())
            self.assertTrue(other_output.exists())
            self.assertFalse(cache_dir.exists())
            self.assertFalse(pipeline.llm_client.cache_enabled)
        finally:
            shutil.rmtree(temporary, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
