from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path
from typing import Any, Callable, Iterable

from .ArtifactContract import artifact_metadata, canonical_fingerprint, validate_artifact
from .LLMClient import DryRunClient, OpenAICompatibleClient
from .BaseAgent import AgentRunError
from .ObligationAgent import ObligationAdjudicator, ObligationReasoner
from .QualityGate import (
    repair_semantic_claim_output,
    validate_semantic_claim_grounding,
    validate_semantic_claim_output,
)
from .SemanticAgent import ExecutionAgent, OperationAgent, StateAgent, ValueAgent
from .SemanticContract import SCHEMA_VERSION, iter_claims
from .SimpleYaml import load_yaml


STAGE_FILES = {
    1: "stage_1_semantic_model.json",
    2: "stage_2_rules.json",
    3: "stage_3_obligation_adjudicator.json",
}
STAGE_LABELS = {
    1: "Stage 1 - semantic model",
    2: "Stage 2 - obligations",
    3: "Stage 3 - adjudication",
}
PIPELINE_REVISION = "independent-semantic-views-v4.13"

AGENT_CLASSES = {
    "operation_agent": OperationAgent,
    "state_agent": StateAgent,
    "value_agent": ValueAgent,
    "execution_agent": ExecutionAgent,
    "obligation_reasoner": ObligationReasoner,
    "obligation_adjudicator": ObligationAdjudicator,
}

ProgressCallback = Callable[[dict[str, Any]], None]


class StageExecutionError(RuntimeError):
    """Per-stage failure carrying cumulative usage for experiment accounting."""

    def __init__(
        self,
        message: str,
        *,
        stage: int,
        token_usage: dict[str, int] | None = None,
        failed_agent: str | None = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.failed_agent = failed_agent
        self.token_usage = dict(token_usage or empty_token_usage())


def emit_progress(progress_callback: ProgressCallback | None, **event: Any) -> None:
    if progress_callback is not None:
        progress_callback(event)


class VulSORPipeline:
    def __init__(
        self,
        project_root: Path,
        split: str = "test",
        dry_run: bool = False,
        overwrite: bool = False,
        no_cache: bool = False,
        refresh_cache: bool = False,
        output_root: Path | None = None,
    ) -> None:
        self.project_root = project_root
        self.split = split
        self.dry_run = bool(dry_run)
        self.datasets_config = load_yaml(project_root / "config" / "datasets.yml")
        self.agents_config = load_yaml(project_root / "config" / "agents.yml")
        self._labels_by_sample_id: dict[str, dict[str, Any]] | None = None
        self._contexts_by_sample_id: dict[str, dict[str, Any]] | None = None

        provider = dict(self.agents_config.get("provider", {}))
        cache_config = dict(provider.get("cache", {}) or {})
        configured_cache_dir = cache_config.get("dir")
        if configured_cache_dir:
            cache_path = Path(configured_cache_dir)
            if not cache_path.is_absolute():
                cache_config["dir"] = str(project_root / cache_path)
            provider["cache"] = cache_config

        self.llm_client = (
            DryRunClient()
            if self.dry_run
            else OpenAICompatibleClient(
                provider, cache_dir=project_root / ".cache" / "llm"
            )
        )
        self.agents = self._build_agents()
        self.pipeline_fingerprint = self._compute_pipeline_fingerprint()
        self.stage_root = output_root or project_root / "stages"
        self._ensure_stage_dirs()
        if no_cache and refresh_cache:
            raise ValueError("Choose either no_cache or refresh_cache, not both.")
        if overwrite:
            self._clear_split_outputs()
        if refresh_cache:
            self._clear_llm_cache()
        if no_cache:
            self._disable_llm_cache()

    def run(self, limit: int | None = None) -> None:
        self.run_samples(self.load_samples(limit=limit), up_to_stage=3)

    def run_samples(
        self,
        samples: Iterable[dict[str, Any]],
        up_to_stage: int = 3,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        """Run a batch without allowing one bad sample to abort the experiment.

        run_sample() is itself failure-isolated, but this outer guard is retained as a
        last-resort boundary for unexpected per-sample exceptions. KeyboardInterrupt
        and SystemExit are intentionally not swallowed because they are BaseException,
        not Exception.
        """
        for sample in samples:
            terminal_record: dict[str, Any] | None = None
            try:
                terminal_record = self.run_sample(
                    sample, up_to_stage=up_to_stage, progress_callback=progress_callback
                )
            except Exception as exc:  # final batch isolation boundary
                terminal_record = self._record_sample_analysis_failure(
                    sample,
                    failed_stage=0,
                    exc=exc,
                    progress_callback=progress_callback,
                )
            finally:
                output = terminal_record.get("output", {}) if isinstance(terminal_record, dict) else {}
                emit_progress(
                    progress_callback,
                    event="sample_done",
                    sample_id=str(sample.get("sample_id", "unknown")),
                    status=("failed" if output.get("analysis_failure") else "passed"),
                    analysis_failure=bool(output.get("analysis_failure")),
                    label=output.get("label"),
                )

    def run_sample(
        self,
        sample: dict[str, Any],
        up_to_stage: int = 3,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        """Run one sample with stage-level failure isolation.

        Any normal Exception raised by an agent, validator, provider, artifact read,
        or stage implementation becomes an AnalysisFailure record for this sample.
        The exception never escapes into the dataset runner, so later samples continue.
        """
        record: dict[str, Any] = {}
        for stage in range(1, up_to_stage + 1):
            emit_progress(
                progress_callback,
                event="stage_start",
                sample_id=sample["sample_id"],
                stage=stage,
            )
            output_path = self._stage_file_for_number(sample["sample_id"], stage)
            cached = False
            try:
                if output_path.exists():
                    candidate = read_json_file(output_path)
                    if not self._validate_cached_stage(sample, stage, candidate):
                        record = candidate
                        cached = True
                    else:
                        record = self.run_stage(
                            sample, stage, progress_callback=progress_callback
                        )
                else:
                    record = self.run_stage(
                        sample, stage, progress_callback=progress_callback
                    )
            except Exception as exc:
                failure = self._record_sample_analysis_failure(
                    sample,
                    failed_stage=stage,
                    exc=exc,
                    progress_callback=progress_callback,
                )
                emit_progress(
                    progress_callback,
                    event="stage_done",
                    sample_id=sample["sample_id"],
                    stage=stage,
                    token_usage=token_usage_from_record(failure),
                    status="failed",
                    output_path=str(self._stage_file_for_number(sample["sample_id"], 3)),
                    summary=stage_summary(3, failure),
                    cached=False,
                    analysis_failure=True,
                )
                return failure

            artifact_usage = token_usage_from_record(record)
            emit_progress(
                progress_callback,
                event="stage_done",
                sample_id=sample["sample_id"],
                stage=stage,
                # Cached artifacts cost zero tokens in the current run. Preserve the
                # historical generation usage separately for reporting/debugging.
                token_usage=empty_token_usage() if cached else artifact_usage,
                artifact_token_usage=artifact_usage,
                status="cached" if cached else stage_status_from_record(record),
                output_path=str(output_path),
                summary=stage_summary(stage, record),
                cached=cached,
            )
        return record

    def run_exact_stage(
        self,
        sample: dict[str, Any],
        stage: int,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        emit_progress(
            progress_callback,
            event="stage_start",
            sample_id=sample["sample_id"],
            stage=stage,
        )
        try:
            record = self.run_stage(sample, stage, progress_callback=progress_callback)
            status = stage_status_from_record(record)
            output_path = self._stage_file_for_number(sample["sample_id"], stage)
            summary = stage_summary(stage, record)
        except Exception as exc:
            record = self._record_sample_analysis_failure(
                sample,
                failed_stage=stage,
                exc=exc,
                progress_callback=progress_callback,
            )
            status = "failed"
            output_path = self._stage_file_for_number(sample["sample_id"], 3)
            summary = stage_summary(3, record)
        emit_progress(
            progress_callback,
            event="stage_done",
            sample_id=sample["sample_id"],
            stage=stage,
            token_usage=token_usage_from_record(record),
            status=status,
            output_path=str(output_path),
            summary=summary,
        )
        return record

    def run_stage(
        self,
        sample: dict[str, Any],
        stage: int,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        if stage == 1:
            return self.run_stage_1(sample, progress_callback=progress_callback)
        if stage == 2:
            return self.run_stage_2(sample, progress_callback=progress_callback)
        if stage == 3:
            return self.run_stage_3(sample, progress_callback=progress_callback)
        raise ValueError(f"Unsupported stage: {stage}")

    # ------------------------------------------------------------------
    # Stage 1: four independent full-function views.
    # ------------------------------------------------------------------
    def run_stage_1(
        self,
        sample: dict[str, Any],
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        sample_id = sample["sample_id"]
        numbered_code = add_line_numbers(sample["code"])
        max_line = count_lines(sample["code"])
        semantic_outputs: dict[str, dict[str, Any]] = {}
        agent_keys = [
            "operation_agent",
            "state_agent",
            "value_agent",
            "execution_agent",
        ]
        stage_usage = empty_token_usage()

        # Deliberately no Operation -> State/Value/Execution dependency.
        for index, agent_key in enumerate(agent_keys, start=1):
            emit_progress(
                progress_callback,
                event="agent_start",
                sample_id=sample_id,
                stage=1,
                agent_key=agent_key,
                index=index,
                total=len(agent_keys),
            )
            try:
                semantic_outputs[agent_key] = self._run_agent(
                    agent_key,
                    {"numbered_function_code": numbered_code},
                    source_code=sample["code"],
                    max_line=max_line,
                    progress_callback=progress_callback,
                    progress_context={"sample_id": sample_id, "stage": 1},
                )
            except Exception as exc:
                stage_usage = add_token_usage(
                    stage_usage, token_usage_from_exception(exc)
                )
                raise StageExecutionError(
                    f"{agent_key} failed: {exc}",
                    stage=1,
                    token_usage=stage_usage,
                    failed_agent=agent_key,
                ) from exc
            agent_usage = token_usage_from_agent_output(semantic_outputs[agent_key])
            stage_usage = add_token_usage(stage_usage, agent_usage)
            emit_progress(
                progress_callback,
                event="agent_done",
                sample_id=sample_id,
                stage=1,
                agent_key=agent_key,
                index=index,
                total=len(agent_keys),
                token_usage=agent_usage,
                max_tokens=max_tokens_from_agent_output(
                    semantic_outputs[agent_key]
                ),
                summary=agent_output_summary(semantic_outputs[agent_key]),
            )

        record = build_semantic_model_record(sample_id, semantic_outputs)
        record["artifact_metadata"] = self._artifact_metadata_for(
            sample, "semantic_model"
        )
        self._write_stage_json(sample_id, 1, record)
        return read_json_file(self._stage_file_for_number(sample_id, 1))

    # ------------------------------------------------------------------
    # Stage 2: one compact global semantic model, no per-operation contexts.
    # ------------------------------------------------------------------
    def run_stage_2(
        self,
        sample: dict[str, Any],
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        sample_id = sample["sample_id"]
        semantic_record = self._read_required_stage(sample, 1)
        semantic_model = semantic_record["output"]["semantic_model"]

        emit_progress(
            progress_callback,
            event="agent_start",
            sample_id=sample_id,
            stage=2,
            agent_key="obligation_reasoner",
            index=1,
            total=1,
        )
        def _normalize_reasoner_parsed(parsed: Any) -> list[str]:
            if isinstance(parsed, dict) and isinstance(parsed.get("obligations"), list):
                normalized = normalize_obligations_requirements(
                    parsed.get("obligations", [])
                )
                # locations/expression are copy-only fields. When the Reasoner
                # changes their spelling/anchor, restore them from the corresponding
                # Operation instead of retrying or failing the sample.
                operations = semantic_model.get("operations", [])
                if isinstance(operations, list) and len(normalized) == len(operations):
                    for index, obligation in enumerate(normalized):
                        operation = operations[index]
                        if isinstance(obligation, dict) and isinstance(operation, dict):
                            obligation["locations"] = operation.get("locations", [])
                            obligation["expression"] = operation.get("expression", "")
                parsed["obligations"] = normalized
            return []

        reasoner_output = self.agents["obligation_reasoner"].run(
            {"semantic_model_json": compact_semantic_model_for_llm(semantic_model)},
            extra_validators=[
                _normalize_reasoner_parsed,
                lambda parsed: validate_obligations(parsed, semantic_model)
            ],
            progress_callback=progress_callback,
            progress_context={"sample_id": sample_id, "stage": 2},
        )
        emit_progress(
            progress_callback,
            event="agent_done",
            sample_id=sample_id,
            stage=2,
            agent_key="obligation_reasoner",
            index=1,
            total=1,
            token_usage=token_usage_from_agent_output(reasoner_output),
            max_tokens=max_tokens_from_agent_output(reasoner_output),
            summary=agent_output_summary(reasoner_output),
        )

        # Canonicalize safely splittable compound requirements before persistence.
        # This keeps the Stage-2 artifact atomic without turning a presentation-only
        # conjunction into a terminal AnalysisFailure.
        reasoner_output = normalize_reasoner_output(reasoner_output)
        record = build_rules_record(sample_id, reasoner_output)
        record["artifact_metadata"] = self._artifact_metadata_for(
            sample,
            "rules",
            {"semantic_model": payload_fingerprint(semantic_record)},
        )
        self._write_stage_json(sample_id, 2, record)
        return read_json_file(self._stage_file_for_number(sample_id, 2))

    # ------------------------------------------------------------------
    # Stage 3: global facts once + requirements. Raw assessment array only.
    # ------------------------------------------------------------------
    def run_stage_3(
        self,
        sample: dict[str, Any],
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        sample_id = sample["sample_id"]
        semantic_record = self._read_required_stage(sample, 1)
        rules_record = self._read_required_stage(sample, 2)
        semantic_model = semantic_record["output"]["semantic_model"]
        obligations = rules_from_record(rules_record)
        obligation_count = len(obligations)
        requirement_count = count_requirements(obligations)
        semantic_facts = {
            "states": semantic_model.get("states", []),
            "values": semantic_model.get("values", []),
            "executions": semantic_model.get("executions", []),
        }
        operation_count = len(semantic_model.get("operations", [])) if isinstance(semantic_model.get("operations"), list) else 0

        assessments: list[str] = []
        adjudicator_error: str | None = None
        adjudicator_quality_gate: dict[str, Any] | None = None
        stage_token_usage = empty_token_usage()

        if obligation_count > 0:
            emit_progress(
                progress_callback,
                event="agent_start",
                sample_id=sample_id,
                stage=3,
                agent_key="obligation_adjudicator",
                index=1,
                total=1,
            )
            try:
                adjudicator_output = self.agents["obligation_adjudicator"].run(
                    {
                        "numbered_function_code": add_line_numbers(str(sample.get("code", ""))),
                        "semantic_facts_json": semantic_facts,
                        "obligations_json": {"obligations": obligations},
                        "obligation_count": obligation_count,
                    },
                    extra_validators=[
                        lambda parsed: validate_assessments(parsed, obligation_count)
                    ],
                    progress_callback=progress_callback,
                    progress_context={"sample_id": sample_id, "stage": 3},
                )
                assessments = list(adjudicator_output["parsed"])
                adjudicator_quality_gate = adjudicator_output["quality_gate"]
                adjudicator_usage = token_usage_from_agent_output(adjudicator_output)
                stage_token_usage = add_token_usage(stage_token_usage, adjudicator_usage)
                emit_progress(
                    progress_callback,
                    event="agent_done",
                    sample_id=sample_id,
                    stage=3,
                    agent_key="obligation_adjudicator",
                    index=1,
                    total=1,
                    token_usage=adjudicator_usage,
                    max_tokens=max_tokens_from_agent_output(adjudicator_output),
                    summary=agent_output_summary(adjudicator_output),
                )

            except (ValueError, TypeError) as exc:
                adjudicator_error = str(exc)
                stage_token_usage = add_token_usage(
                    stage_token_usage, token_usage_from_exception(exc)
                )
        # Zero obligations after a successful Stage-2 safety-relevance gate is a
        # valid semantic result, not a technical failure. The deterministic rule over
        # an empty obligation set yields Benign.

        final_verdict = aggregate_final_verdict(
            assessments,
            obligation_count=obligation_count,
            operation_count=operation_count,
            analysis_error=adjudicator_error,
        )
        triggering_obligations = build_triggering_obligations(assessments, obligations)

        try:
            ground_truth = self.ground_truth_for_sample(sample_id)
        except Exception:
            ground_truth = None
        correct = None
        if (
            ground_truth is not None
            and ground_truth.get("target") is not None
            and final_verdict["binary_prediction"] is not None
        ):
            correct = int(final_verdict["binary_prediction"]) == int(ground_truth["target"])

        record = {
            "sample_id": sample_id,
            "schema_version": SCHEMA_VERSION,
            "stage": "obligation_adjudicator",
            "agent_key": "obligation_adjudicator",
            "ground_truth": ground_truth,
            "output": {
                "assessments": assessments,
                "obligation_count": obligation_count,
                "requirement_count": requirement_count,
                "violation": final_verdict["violation"],
                "binary_prediction": final_verdict["binary_prediction"],
                "label": final_verdict["label"],
                "decision": final_verdict["decision"],
                "decision_basis": final_verdict["decision_basis"],
                "triggering_obligations": triggering_obligations,
                "correct": correct,
                "analysis_failure": final_verdict["analysis_failure"],
                "analysis_failure_reasons": final_verdict["analysis_failure_reasons"],
                "assessment_counts": assessment_counts(assessments),
                "aggregation_rule": final_verdict["aggregation_rule"],
            },
            "quality_gate": {
                "status": "failed" if final_verdict["analysis_failure"] else "passed",
                "adjudicator": adjudicator_quality_gate,
            },
            "token_usage": stage_token_usage,
            "pipeline_diagnostics": {
                "errors": ([adjudicator_error] if adjudicator_error else []),
                "stage_status": {
                    "Stage 1": semantic_record.get("quality_gate", {}).get("status", "unknown"),
                    "Stage 2": rules_record.get("quality_gate", {}).get("status", "unknown"),
                    "Stage 3": "failed" if adjudicator_error else "passed",
                },
            },
        }
        record["artifact_metadata"] = self._artifact_metadata_for(
            sample,
            "obligation_adjudicator",
            {
                "semantic_model": payload_fingerprint(semantic_record),
                "rules": payload_fingerprint(rules_record),
            },
        )
        self._write_stage_json(sample_id, 3, record)
        return read_json_file(self._stage_file_for_number(sample_id, 3))

    def _record_sample_analysis_failure(
        self,
        sample: dict[str, Any],
        failed_stage: int,
        exc: Exception,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        """Persist a terminal non-binary result for one failed sample.

        The final Stage-3 path is used deliberately so dataset runners can consume one
        uniform terminal artifact regardless of whether failure happened in Stage 1, 2,
        or 3. Existing valid upstream artifacts are fingerprinted; missing upstream
        artifacts are simply absent.
        """
        sample_id = str(sample.get("sample_id", "unknown"))
        stage_label = STAGE_LABELS.get(failed_stage, "Sample execution")
        reason = f"{stage_label} failed: {type(exc).__name__}: {exc}"
        usage = token_usage_from_exception(exc)
        try:
            ground_truth = self.ground_truth_for_sample(sample_id)
        except Exception:
            ground_truth = None
        upstream: dict[str, str] = {}
        stage1_path = self._stage_file_for_number(sample_id, 1)
        stage2_path = self._stage_file_for_number(sample_id, 2)
        try:
            if stage1_path.exists():
                upstream["semantic_model"] = payload_fingerprint(read_json_file(stage1_path))
            if stage2_path.exists():
                upstream["rules"] = payload_fingerprint(read_json_file(stage2_path))
        except Exception:
            # Failure reporting must never fail because a partial/stale artifact is unreadable.
            upstream = {}

        record = {
            "sample_id": sample_id,
            "schema_version": SCHEMA_VERSION,
            "stage": "obligation_adjudicator",
            "agent_key": "obligation_adjudicator",
            "ground_truth": ground_truth,
            "output": {
                "assessments": [],
                "obligation_count": 0,
                "requirement_count": 0,
                "violation": None,
                "binary_prediction": None,
                "label": "AnalysisFailure",
                "decision": None,
                "decision_basis": "analysis_failure",
                "triggering_obligations": [],
                "correct": None,
                "analysis_failure": True,
                "analysis_failure_reasons": [reason],
                "assessment_counts": assessment_counts([]),
                "aggregation_rule": "Analysis failures never produce a binary decision.",
                "failed_stage": failed_stage,
                "failed_stage_label": stage_label,
                "exception_type": type(exc).__name__,
            },
            "quality_gate": {
                "status": "failed",
                "failure_stage": failed_stage,
                "exception_type": type(exc).__name__,
            },
            "token_usage": usage,
            "token_usage_stage": failed_stage,
            "token_usage_by_stage": {
                "stage_1": usage if failed_stage == 1 else empty_token_usage(),
                "stage_2": usage if failed_stage == 2 else empty_token_usage(),
                "stage_3": usage if failed_stage in (0, 3) else empty_token_usage(),
            },
            "pipeline_diagnostics": {
                "errors": [reason],
                "stage_status": {
                    "Stage 1": "failed" if failed_stage == 1 else "not_run" if failed_stage < 1 else "passed",
                    "Stage 2": "failed" if failed_stage == 2 else "not_run" if failed_stage < 2 else "passed",
                    "Stage 3": "failed",
                },
            },
        }
        record["artifact_metadata"] = self._artifact_metadata_for(
            sample, "obligation_adjudicator", upstream
        )
        # Always make a best effort to persist the terminal result. A disk error is
        # intentionally contained so it cannot resurrect the original batch abort.
        try:
            self._write_stage_json(sample_id, 3, record)
        except Exception:
            pass
        emit_progress(
            progress_callback,
            event="sample_analysis_failure",
            sample_id=sample_id,
            stage=failed_stage,
            error=reason,
            token_usage=usage,
            output_path=str(self._stage_file_for_number(sample_id, 3)),
        )
        return record

    def load_samples(self, limit: int | None = None) -> list[dict[str, Any]]:
        samples = []
        contexts = self.load_contexts()
        for index, sample in enumerate(read_jsonl(self._input_file())):
            if limit is not None and index >= limit:
                break
            sample_context = contexts.get(str(sample.get("sample_id")))
            if sample_context is not None:
                sample = dict(sample)
                sample["context"] = sample_context.get("context")
                sample["context_record"] = sample_context
            samples.append(sample)
        return samples

    def find_sample(self, sample_id: str) -> dict[str, Any]:
        for sample in self.load_samples():
            if sample.get("sample_id") == sample_id:
                return sample
        raise ValueError(f"Sample not found: {sample_id}")

    def _build_agents(self) -> dict[str, Any]:
        agent_configs = self.agents_config.get("agents", {})
        agents = {}
        for key, cls in AGENT_CLASSES.items():
            config = dict(agent_configs.get(key, {}) or {})
            if not config:
                continue
            if config.get("enabled", True):
                agents[key] = cls(key, config, self.project_root, self.llm_client)
        return agents

    def _compute_pipeline_fingerprint(self) -> str:
        prompts: dict[str, Any] = {}
        for agent_key, config in self.agents_config.get("agents", {}).items():
            prompt_file = config.get("prompt_file") if isinstance(config, dict) else None
            prompt_path = self.project_root / prompt_file if prompt_file else None
            prompts[agent_key] = {
                "config": config,
                "prompt": (
                    prompt_path.read_text(encoding="utf-8")
                    if prompt_path and prompt_path.exists()
                    else None
                ),
            }
        return canonical_fingerprint(
            {
                "schema_version": SCHEMA_VERSION,
                "pipeline_revision": PIPELINE_REVISION,
                "dry_run": self.dry_run,
                "agents": prompts,
            }
        )

    def _sample_source_hash(self, sample: dict[str, Any]) -> str:
        return canonical_fingerprint(
            {"sample_id": sample.get("sample_id"), "code": sample.get("code", "")}
        )

    def _artifact_metadata_for(
        self,
        sample: dict[str, Any],
        stage: str,
        upstream_hashes: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        return artifact_metadata(
            stage,
            sample_id=(
                str(sample.get("sample_id"))
                if sample.get("sample_id") is not None
                else None
            ),
            split=self.split,
            source_hash=self._sample_source_hash(sample),
            upstream_hashes=upstream_hashes,
            pipeline_fingerprint=self.pipeline_fingerprint,
        )

    def _expected_metadata_for_stage(
        self, sample: dict[str, Any], stage: int
    ) -> dict[str, Any]:
        stage_name = {1: "semantic_model", 2: "rules", 3: "obligation_adjudicator"}[
            stage
        ]
        upstream: dict[str, str] = {}
        if stage >= 2:
            path = self._stage_file_for_number(sample["sample_id"], 1)
            if path.exists():
                upstream["semantic_model"] = payload_fingerprint(read_json_file(path))
        if stage == 3:
            path = self._stage_file_for_number(sample["sample_id"], 2)
            if path.exists():
                upstream["rules"] = payload_fingerprint(read_json_file(path))
        return self._artifact_metadata_for(sample, stage_name, upstream)

    def _validate_cached_stage(
        self, sample: dict[str, Any], stage: int, record: dict[str, Any]
    ) -> bool:
        stage_name = {1: "semantic_model", 2: "rules", 3: "obligation_adjudicator"}[
            stage
        ]
        return bool(
            validate_artifact(
                record, stage_name, self._expected_metadata_for_stage(sample, stage)
            )
        )

    def _run_agent(
        self,
        agent_key: str,
        variables: dict[str, Any],
        source_code: str,
        max_line: int,
        progress_callback: ProgressCallback | None = None,
        progress_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        recovery_events: list[dict[str, Any]] = []

        def _repair(parsed: Any) -> list[str]:
            recovery_events.extend(
                repair_semantic_claim_output(parsed, agent_key, source_code)
            )
            return []

        result = self.agents[agent_key].run(
            variables,
            extra_validators=[
                _repair,
                lambda parsed: validate_semantic_claim_output(
                    parsed, agent_key, max_line
                ),
                lambda parsed: validate_semantic_claim_grounding(
                    parsed, agent_key, source_code
                )[0],
            ],
            progress_callback=progress_callback,
            progress_context=progress_context,
        )
        _, grounding_metadata = validate_semantic_claim_grounding(
            result.get("parsed", {}), agent_key, source_code
        )
        result.setdefault("quality_gate", {})["grounding"] = grounding_metadata
        result.setdefault("quality_gate", {})["item_recovery"] = recovery_events
        return result

    def _stage_file_for_number(self, sample_id: str, stage: int) -> Path:
        return self.stage_root / sample_id / STAGE_FILES[stage]

    def _read_required_stage(
        self, sample: dict[str, Any], stage: int
    ) -> dict[str, Any]:
        path = self._stage_file_for_number(sample["sample_id"], stage)
        if not path.exists():
            raise FileNotFoundError(
                f"{STAGE_LABELS[stage]} output is required before running the next stage: {path}"
            )
        record = read_json_file(path)
        stage_name = {1: "semantic_model", 2: "rules", 3: "obligation_adjudicator"}[
            stage
        ]
        errors = validate_artifact(
            record, stage_name, self._expected_metadata_for_stage(sample, stage)
        )
        if errors:
            raise ValueError(
                f"stale semantic artifact at {path}; rerun Stage 1-3 under {SCHEMA_VERSION}: "
                + "; ".join(errors)
            )
        return record

    def _write_stage_json(
        self, sample_id: str, stage: int, record: dict[str, Any]
    ) -> None:
        output_path = self._stage_file_for_number(sample_id, stage)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )

    def _ensure_stage_dirs(self) -> None:
        self.stage_root.mkdir(parents=True, exist_ok=True)

    def _clear_split_outputs(self) -> None:
        for sample_dir in self.stage_root.glob(f"{self.split}_*"):
            if sample_dir.is_dir():
                shutil.rmtree(sample_dir)
            elif sample_dir.is_file():
                sample_dir.unlink()

    def _clear_llm_cache(self) -> None:
        cache_dir = getattr(self.llm_client, "cache_dir", None)
        if isinstance(cache_dir, Path) and cache_dir.exists():
            if cache_dir.is_dir():
                shutil.rmtree(cache_dir)
            else:
                cache_dir.unlink()

    def _disable_llm_cache(self) -> None:
        if hasattr(self.llm_client, "cache_enabled"):
            self.llm_client.cache_enabled = False

    def _input_file(self) -> Path:
        active_dataset = self.datasets_config["defaults"]["active_dataset"]
        split_config = self.datasets_config["datasets"][active_dataset]["splits"][
            self.split
        ]
        return self.project_root / split_config["input_file"]

    def _label_file(self) -> Path | None:
        active_dataset = self.datasets_config["defaults"]["active_dataset"]
        split_config = self.datasets_config["datasets"][active_dataset]["splits"].get(
            self.split, {}
        )
        label_file = split_config.get("label_file")
        return self.project_root / label_file if label_file else None

    def _context_file(self) -> Path | None:
        active_dataset = self.datasets_config["defaults"]["active_dataset"]
        split_config = self.datasets_config["datasets"][active_dataset]["splits"].get(
            self.split, {}
        )
        context_file = split_config.get("context_file")
        return self.project_root / context_file if context_file else None

    def load_labels(self) -> dict[str, dict[str, Any]]:
        if self._labels_by_sample_id is not None:
            return self._labels_by_sample_id
        labels: dict[str, dict[str, Any]] = {}
        label_path = self._label_file()
        if label_path is not None and label_path.exists():
            for label in read_jsonl(label_path):
                sample_id = label.get("sample_id")
                if sample_id:
                    labels[sample_id] = {
                        "sample_id": sample_id,
                        "pair_id": label.get("pair_id"),
                        "target": label.get("target"),
                        "label": (
                            "vulnerable" if label.get("target") == 1 else "benign"
                        ),
                        "cve": label.get("cve"),
                        "cwe": label.get("cwe") or [],
                    }
        self._labels_by_sample_id = labels
        return labels

    def load_contexts(self) -> dict[str, dict[str, Any]]:
        if self._contexts_by_sample_id is not None:
            return self._contexts_by_sample_id
        contexts: dict[str, dict[str, Any]] = {}
        context_path = self._context_file()
        if context_path is not None and context_path.exists():
            for context_record in read_jsonl(context_path):
                sample_id = context_record.get("sample_id")
                if sample_id:
                    contexts[str(sample_id)] = context_record
        self._contexts_by_sample_id = contexts
        return contexts

    def ground_truth_for_sample(self, sample_id: str) -> dict[str, Any] | None:
        return self.load_labels().get(sample_id)

    def stage_status(self, sample_id: str) -> dict[int, str]:
        return {
            stage: (
                "ready"
                if self._stage_file_for_number(sample_id, stage).exists()
                else "missing"
            )
            for stage in range(1, 4)
        }


# ----------------------------------------------------------------------
# Artifact construction and validators
# ----------------------------------------------------------------------

def build_semantic_model_record(
    sample_id: str, semantic_outputs: dict[str, dict[str, Any]]
) -> dict[str, Any]:
    raw_operations = semantic_outputs.get("operation_agent", {}).get("parsed", {}).get("operations", [])
    operations, dropped_operations = normalize_operations_for_reasoning(raw_operations)
    semantic_model = {
        "operations": operations,
        "states": semantic_outputs.get("state_agent", {})
        .get("parsed", {})
        .get("states", []),
        "values": semantic_outputs.get("value_agent", {})
        .get("parsed", {})
        .get("values", []),
        "executions": semantic_outputs.get("execution_agent", {})
        .get("parsed", {})
        .get("executions", []),
    }
    return {
        "sample_id": sample_id,
        "schema_version": SCHEMA_VERSION,
        "stage": "semantic_model",
        "output": {
            "semantic_model": semantic_model,
            "agent_quality_gates": {
                agent_key: output.get("quality_gate", {})
                for agent_key, output in semantic_outputs.items()
            },
        },
        "quality_gate": {
            "status": "passed",
            "agent_count": len(semantic_outputs),
            "mode": "independent_global_views",
            "counts": semantic_model_counts(semantic_model),
            "schema_version": SCHEMA_VERSION,
            "operation_normalization": {
                "dropped_forbidden_preparation_only": len(dropped_operations),
            },
        },
        "token_usage": sum_token_usages(
            token_usage_from_agent_output(output)
            for output in semantic_outputs.values()
        ),
    }


def normalize_operations_for_reasoning(operations: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Drop only syntactically certain preparation-only actions forbidden by the Operation contract.

    This deliberately does not classify function calls or use a callee-name whitelist.
    It only removes bare increment/decrement expressions such as ``q++`` that cannot
    themselves consume memory/object/resource state. Consuming forms such as ``*p++``
    are preserved.
    """
    if not isinstance(operations, list):
        return [], []
    kept: list[dict[str, Any]] = []
    dropped: list[dict[str, Any]] = []
    bare_incdec = re.compile(
        r"^\s*(?:(?:\+\+|--)\s*)?[A-Za-z_]\w*(?:(?:->|\.)[A-Za-z_]\w*)?\s*(?:(?:\+\+|--))?\s*$"
    )
    for item in operations:
        if not isinstance(item, dict):
            kept.append(item)
            continue
        expression = item.get("expression")
        if isinstance(expression, str):
            expr = expression.strip()
            if ("++" in expr or "--" in expr) and bare_incdec.fullmatch(expr):
                dropped.append(item)
                continue
        kept.append(item)
    return kept, dropped


def compact_semantic_model_for_llm(semantic_model: dict[str, Any]) -> dict[str, Any]:
    return {
        "operations": semantic_model.get("operations", []),
        "states": semantic_model.get("states", []),
        "values": semantic_model.get("values", []),
        "executions": semantic_model.get("executions", []),
    }


def semantic_model_counts(semantic_model: dict[str, Any]) -> dict[str, int]:
    return {
        name: len(semantic_model.get(name, []))
        if isinstance(semantic_model.get(name), list)
        else 0
        for name in ("operations", "states", "values", "executions")
    }


def validate_obligations(
    output: Any, semantic_model: dict[str, Any]
) -> list[str]:
    if not isinstance(output, dict):
        return ["Stage 2 output must be an object"]
    obligations = output.get("obligations")
    if not isinstance(obligations, list):
        return ["$.obligations must be an array"]

    operations = semantic_model.get("operations", [])
    operations = operations if isinstance(operations, list) else []
    errors: list[str] = []
    if len(obligations) != len(operations):
        errors.append(
            f"Stage 2 must return exactly one obligation group per operation: expected {len(operations)}, got {len(obligations)}"
        )

    for index, obligation in enumerate(obligations):
        path = f"$.obligations[{index}]"
        if not isinstance(obligation, dict):
            errors.append(f"{path} must be an object")
            continue
        expected_fields = {"locations", "expression", "requirements"}
        if set(obligation) != expected_fields:
            errors.append(
                f"{path} must contain exactly locations, expression, requirements"
            )

        if index < len(operations) and isinstance(operations[index], dict):
            operation = operations[index]
            if obligation.get("locations") != operation.get("locations"):
                errors.append(f"{path}.locations must copy the Operation locations")
            if obligation.get("expression") != operation.get("expression"):
                errors.append(f"{path}.expression must copy the Operation expression")

        requirements = obligation.get("requirements")
        if not isinstance(requirements, list):
            errors.append(f"{path}.requirements must be an array")
            continue
        # Empty requirements is a deliberate Stage-2 safety-relevance rejection.
        # It is filtered before persistence/adjudication and is not an AnalysisFailure.
        if not requirements:
            continue
        normalized: set[str] = set()
        for requirement_index, requirement in enumerate(requirements):
            rpath = f"{path}.requirements[{requirement_index}]"
            if not isinstance(requirement, str) or not requirement.strip():
                errors.append(f"{rpath} must be a non-empty string")
                continue
            if "must" not in requirement.lower().split():
                errors.append(f"{rpath} must use the word 'must'")
            key = " ".join(requirement.lower().split())
            if key in normalized:
                errors.append(f"{rpath} duplicates another requirement")
            normalized.add(key)
            # Atomicity is a reasoning-quality preference, not a protocol-fatal
            # condition. Safely splittable repeated-`must` conjunctions are already
            # canonicalized before validation; an unsplittable conjunction remains
            # one requirement rather than causing whole-sample AnalysisFailure.
    return errors


def _looks_compound(requirement: str) -> bool:
    return bool(
        re.search(
            r"\bmust\b[^.;]*(?:\band\b|;)[^.;]*\bmust\b",
            requirement,
            re.IGNORECASE,
        )
    )


def split_atomic_requirement(requirement: str) -> list[str]:
    """Split only explicit repeated-`must` conjunctions without inventing text.

    Example: `p must be non-null and p must be live` becomes two requirements.
    A phrase such as `p must be non-null and live` is intentionally left untouched
    because mechanically splitting it would require synthesizing a subject/verb.
    """
    text = " ".join(str(requirement).strip().split())
    if not text or not _looks_compound(text):
        return [text] if text else []
    parts = [
        part.strip()
        for part in re.split(
            r"\s*(?:;|\band\b)\s*(?=[^.;]*\bmust\b)",
            text,
            flags=re.IGNORECASE,
        )
        if part.strip()
    ]
    if len(parts) <= 1 or any("must" not in part.lower().split() for part in parts):
        return [text]
    return dedupe_preserving_order(parts)


def normalize_obligations_requirements(obligations: Any) -> list[dict[str, Any]]:
    if not isinstance(obligations, list):
        return []
    normalized_obligations: list[dict[str, Any]] = []
    for obligation in obligations:
        if not isinstance(obligation, dict):
            normalized_obligations.append(obligation)
            continue
        item = dict(obligation)
        requirements = item.get("requirements")
        if isinstance(requirements, list):
            normalized_requirements: list[str] = []
            for requirement in requirements:
                if isinstance(requirement, str):
                    normalized_requirements.extend(split_atomic_requirement(requirement))
                else:
                    normalized_requirements.append(requirement)
            item["requirements"] = dedupe_preserving_order(normalized_requirements)
        normalized_obligations.append(item)
    return normalized_obligations


def normalize_reasoner_output(reasoner_output: dict[str, Any]) -> dict[str, Any]:
    normalized = dict(reasoner_output)
    parsed = normalized.get("parsed")
    if isinstance(parsed, dict):
        parsed_copy = dict(parsed)
        all_obligations = normalize_obligations_requirements(
            parsed_copy.get("obligations", [])
        )
        filtered = [
            obligation for obligation in all_obligations
            if not isinstance(obligation, dict)
            or not isinstance(obligation.get("requirements"), list)
            or len(obligation.get("requirements", [])) > 0
        ]
        parsed_copy["obligations"] = filtered
        normalized["parsed"] = parsed_copy
        quality_gate = dict(normalized.get("quality_gate", {}))
        quality_gate["safety_relevance_filter"] = {
            "input_operation_groups": len(all_obligations),
            "kept_obligations": len(filtered),
            "filtered_non_safety_candidates": max(len(all_obligations) - len(filtered), 0),
        }
        normalized["quality_gate"] = quality_gate
    return normalized


def build_rules_record(
    sample_id: str, reasoner_output: dict[str, Any]
) -> dict[str, Any]:
    obligations = reasoner_output.get("parsed", {}).get("obligations", [])
    return {
        "sample_id": sample_id,
        "schema_version": SCHEMA_VERSION,
        "stage": "rules",
        "agent_key": "obligation_reasoner",
        "output": {"rules": obligations},
        "quality_gate": reasoner_output.get("quality_gate", {}),
        "token_usage": token_usage_from_agent_output(reasoner_output),
    }


def rules_from_record(rules_record: dict[str, Any]) -> list[dict[str, Any]]:
    output = rules_record.get("output", {})
    rules = output.get("rules", output.get("obligations", []))
    return rules if isinstance(rules, list) else []


def count_requirements(obligations: list[dict[str, Any]]) -> int:
    total = 0
    for obligation in obligations:
        if not isinstance(obligation, dict):
            continue
        requirements = obligation.get("requirements", [])
        if isinstance(requirements, list):
            total += len(requirements)
    return total


def validate_assessments(output: Any, obligation_count: int) -> list[str]:
    if not isinstance(output, list):
        return ["Stage 3 output must be a raw JSON array"]
    errors: list[str] = []
    if len(output) != obligation_count:
        errors.append(
            f"Stage 3 assessment count must equal obligation count: expected {obligation_count}, got {len(output)}"
        )
    allowed = {"satisfied", "violated"}
    for index, assessment in enumerate(output):
        if not isinstance(assessment, str) or assessment not in allowed:
            errors.append(f"$[{index}] must be satisfied or violated")
    return errors


def aggregate_final_verdict(
    assessments: list[str],
    obligation_count: int,
    operation_count: int = 0,
    analysis_error: str | None = None,
) -> dict[str, Any]:
    reasons: list[str] = []
    if analysis_error:
        reasons.append(analysis_error)
    reasons.extend(validate_assessments(assessments, obligation_count))

    aggregation_rule = (
        "Any violated obligation -> Vulnerable; otherwise all obligations are "
        "satisfied -> Benign."
    )

    if reasons:
        return {
            "violation": None,
            "binary_prediction": None,
            "label": "AnalysisFailure",
            "decision": None,
            "decision_basis": "analysis_failure",
            "analysis_failure": True,
            "analysis_failure_reasons": dedupe_preserving_order(reasons),
            "aggregation_rule": aggregation_rule,
        }

    if obligation_count == 0:
        return {
            "violation": 0,
            "binary_prediction": 0,
            "label": "Benign",
            "decision": "Benign",
            "decision_basis": (
                "no_nontrivial_reasoning_operations"
                if operation_count == 0
                else "no_security_relevant_obligations"
            ),
            "analysis_failure": False,
            "analysis_failure_reasons": [],
            "aggregation_rule": aggregation_rule,
        }

    if "violated" in assessments:
        return {
            "violation": 1,
            "binary_prediction": 1,
            "label": "Vulnerable",
            "decision": "Vulnerable",
            "decision_basis": "violated_obligation",
            "analysis_failure": False,
            "analysis_failure_reasons": [],
            "aggregation_rule": aggregation_rule,
        }

    return {
        "violation": 0,
        "binary_prediction": 0,
        "label": "Benign",
        "decision": "Benign",
        "decision_basis": "all_obligations_satisfied",
        "analysis_failure": False,
        "analysis_failure_reasons": [],
        "aggregation_rule": aggregation_rule,
    }


def build_triggering_obligations(
    assessments: list[str], obligations: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Deterministically trace violated assessments back to Stage-2 obligations."""
    triggers: list[dict[str, Any]] = []
    for index, assessment in enumerate(assessments):
        if assessment != "violated" or index >= len(obligations):
            continue
        obligation = obligations[index]
        if not isinstance(obligation, dict):
            continue
        triggers.append(
            {
                "index": index,
                "locations": obligation.get("locations", []),
                "expression": obligation.get("expression"),
                "requirements": obligation.get("requirements", []),
            }
        )
    return triggers


def assessment_counts(assessments: list[str]) -> dict[str, int]:
    return {
        value: sum(1 for assessment in assessments if assessment == value)
        for value in ("satisfied", "violated")
    }


# ----------------------------------------------------------------------
# Generic helpers
# ----------------------------------------------------------------------

def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def read_json_file(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def add_line_numbers(code: str) -> str:
    return "\n".join(
        f"{line_no}: {line}"
        for line_no, line in enumerate(code.splitlines(), start=1)
    )


def count_lines(code: str) -> int:
    return len(code.splitlines())


def empty_token_usage() -> dict[str, int]:
    return {"input_tokens": 0, "output_tokens": 0, "total_tokens": 0}


def add_token_usage(left: dict[str, Any], right: dict[str, Any]) -> dict[str, int]:
    return sum_token_usages([left, right])


def sum_token_usages(usages: Iterable[dict[str, Any]]) -> dict[str, int]:
    total = empty_token_usage()
    for usage in usages:
        input_tokens = int(usage.get("input_tokens", 0) or 0)
        output_tokens = int(usage.get("output_tokens", 0) or 0)
        total_tokens = int(usage.get("total_tokens", 0) or 0)
        if total_tokens == 0:
            total_tokens = input_tokens + output_tokens
        total["input_tokens"] += input_tokens
        total["output_tokens"] += output_tokens
        total["total_tokens"] += total_tokens
    return total


def token_usage_from_agent_output(output: dict[str, Any]) -> dict[str, int]:
    return sum_token_usages(
        [output.get("quality_gate", {}).get("token_usage", {})]
    )


def max_tokens_from_agent_output(output: dict[str, Any]) -> int:
    attempts = output.get("quality_gate", {}).get("attempts", [])
    if not attempts:
        return 0
    return max(int(item.get("max_tokens", 0) or 0) for item in attempts)


def token_usage_from_exception(exc: Exception) -> dict[str, int]:
    usage = getattr(exc, "token_usage", None)
    if isinstance(usage, dict):
        return sum_token_usages([usage])
    return empty_token_usage()


def token_usage_from_record(record: dict[str, Any] | None) -> dict[str, int]:
    if not record:
        return empty_token_usage()
    return sum_token_usages([record.get("token_usage", {})])


def stage_status_from_record(record: dict[str, Any] | None) -> str:
    if not record:
        return "unknown"
    gate = record.get("quality_gate", {})
    return str(gate.get("status", "unknown")) if isinstance(gate, dict) else "unknown"


def agent_output_summary(output: dict[str, Any]) -> str:
    parsed = output.get("parsed")
    if isinstance(parsed, list):
        counts = assessment_counts(parsed)
        return "assessments=" + "/".join(
            f"{key}:{value}" for key, value in counts.items()
        )
    if not isinstance(parsed, dict):
        return ""
    for key in ("operations", "states", "values", "executions", "obligations"):
        value = parsed.get(key)
        if isinstance(value, list):
            if key == "obligations":
                return f"obligations={len(value)}, requirements={count_requirements(value)}"
            return f"{key}={len(value)}"
    return ""


def stage_summary(stage: int, record: dict[str, Any] | None) -> str:
    if not record:
        return ""
    if stage == 1:
        counts = record.get("quality_gate", {}).get("counts", {})
        return ", ".join(f"{key}={value}" for key, value in counts.items())
    if stage == 2:
        rules = rules_from_record(record)
        return f"obligations={len(rules)}, requirements={count_requirements(rules)}"
    if stage == 3:
        output = record.get("output", {})
        return (
            f"verdict={str(output.get('label', 'unknown')).lower()}, "
            f"obligations={output.get('obligation_count', 0)}, requirements={output.get('requirement_count', 0)}, "
            f"analysis_failure={output.get('analysis_failure')}"
        )
    return ""


def payload_fingerprint(record: Any) -> str:
    if isinstance(record, dict):
        payload = {
            key: value for key, value in record.items() if key != "artifact_metadata"
        }
    else:
        payload = record
    return canonical_fingerprint(payload)


def dedupe_preserving_order(values: list[Any]) -> list[Any]:
    result: list[Any] = []
    seen: set[str] = set()
    for value in values:
        marker = json.dumps(value, ensure_ascii=False, sort_keys=True)
        if marker in seen:
            continue
        seen.add(marker)
        result.append(value)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the VulSOR prompt-agent pipeline.")
    parser.add_argument("--split", default="test", choices=["train", "valid", "test"])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--overwrite", action="store_true")
    parser.add_argument("--no-cache", action="store_true")
    parser.add_argument("--refresh-cache", action="store_true")
    parser.add_argument("--output-root", type=Path, default=None)
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[2]
    pipeline = VulSORPipeline(
        project_root=project_root,
        split=args.split,
        dry_run=args.dry_run,
        overwrite=args.overwrite,
        no_cache=args.no_cache,
        refresh_cache=args.refresh_cache,
        output_root=(
            (
                args.output_root
                if args.output_root and args.output_root.is_absolute()
                else project_root / args.output_root
            )
            if args.output_root
            else None
        ),
    )
    pipeline.run(limit=args.limit)


if __name__ == "__main__":
    main()
