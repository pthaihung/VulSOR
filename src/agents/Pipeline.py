from __future__ import annotations

import argparse
import json
import re
import shutil
from pathlib import Path
from typing import Any, Callable, Iterable

from .LLMClient import DryRunClient, OpenAICompatibleClient
from .ObligationAgent import ObligationAdjudicator, ObligationReasoner
from .QualityGate import (
    validate_line_numbers,
    validate_nonempty_semantic_output,
    validate_semantic_fact_contract,
    validate_source_grounding,
)
from .SemanticAgent import ExecutionAgent, OperationAgent, StateAgent, ValueAgent
from .SimpleYaml import load_yaml
from .tools.LineLocatorTool import LineLocatorTool


STAGE_FILES = {
    1: "stage_1_semantic_model.json",
    2: "stage_2_rules.json",
    3: "stage_3_obligation_adjudicator.json",
}

STAGE_1_5_FILE = "stage_1_5_context_links.json"


STAGE_LABELS = {
    1: "Stage 1 - semantic model",
    2: "Stage 2 - obligations",
    3: "Stage 3 - adjudication",
}


AGENT_CLASSES = {
    "operation_agent": OperationAgent,
    "state_agent": StateAgent,
    "value_agent": ValueAgent,
    "execution_agent": ExecutionAgent,
    "obligation_reasoner": ObligationReasoner,
    "obligation_adjudicator": ObligationAdjudicator,
}


ProgressCallback = Callable[[dict[str, Any]], None]


def emit_progress(progress_callback: ProgressCallback | None, **event: Any) -> None:
    if progress_callback is not None:
        progress_callback(event)


class VulSORPipeline:
    def __init__(self, project_root: Path, split: str = "test", dry_run: bool = False, overwrite: bool = False) -> None:
        self.project_root = project_root
        self.split = split
        self.datasets_config = load_yaml(project_root / "config" / "datasets.yml")
        self.agents_config = load_yaml(project_root / "config" / "agents.yml")
        self._labels_by_sample_id: dict[str, dict[str, Any]] | None = None
        provider = dict(self.agents_config.get("provider", {}))
        cache_config = dict(provider.get("cache", {}) or {})
        configured_cache_dir = cache_config.get("dir")
        if configured_cache_dir:
            cache_path = Path(configured_cache_dir)
            if not cache_path.is_absolute():
                cache_config["dir"] = str(project_root / cache_path)
            provider["cache"] = cache_config
        self.llm_client = DryRunClient() if dry_run else OpenAICompatibleClient(provider, cache_dir=project_root / ".cache" / "llm")
        self.agents = self._build_agents()
        self.stage_root = project_root / "stages"
        self._ensure_stage_dirs()
        if overwrite:
            self._clear_split_outputs()

    def run(self, limit: int | None = None) -> None:
        self.run_samples(self.load_samples(limit=limit), up_to_stage=3)

    def run_samples(
        self,
        samples: Iterable[dict[str, Any]],
        up_to_stage: int = 3,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        for sample in samples:
            self.run_sample(sample, up_to_stage=up_to_stage, progress_callback=progress_callback)

    def run_sample(
        self,
        sample: dict[str, Any],
        up_to_stage: int = 3,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        record = {}
        for stage in range(1, up_to_stage + 1):
            emit_progress(progress_callback, event="stage_start", sample_id=sample["sample_id"], stage=stage)
            output_path = self._stage_file_for_number(sample["sample_id"], stage)
            cached_stage = output_path.exists()
            if cached_stage:
                record = read_json_file(output_path)
            else:
                record = self.run_stage(sample, stage, progress_callback=progress_callback)
            emit_progress(
                progress_callback,
                event="stage_done",
                sample_id=sample["sample_id"],
                stage=stage,
                token_usage=token_usage_from_record(record),
                status="cached" if cached_stage else stage_status_from_record(record),
                output_path=str(output_path),
                summary=stage_summary(stage, record),
                cached=cached_stage,
            )
        return record

    def run_exact_stage(
        self,
        sample: dict[str, Any],
        stage: int,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        emit_progress(progress_callback, event="stage_start", sample_id=sample["sample_id"], stage=stage)
        record = self.run_stage(sample, stage, progress_callback=progress_callback)
        output_path = self._stage_file_for_number(sample["sample_id"], stage)
        emit_progress(
            progress_callback,
            event="stage_done",
            sample_id=sample["sample_id"],
            stage=stage,
            token_usage=token_usage_from_record(record),
            status=stage_status_from_record(record),
            output_path=str(output_path),
            summary=stage_summary(stage, record),
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

    def run_stage_1(
        self,
        sample: dict[str, Any],
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        sample_id = sample["sample_id"]
        max_line = count_lines(sample["code"])
        numbered_code = add_line_numbers(sample["code"])
        operation_numbered_code = add_security_signal_line_windows(sample["code"])
        line_locator = LineLocatorTool(sample["code"])

        semantic_outputs = {}
        agent_keys = ["operation_agent", "state_agent", "value_agent", "execution_agent"]

        emit_progress(
            progress_callback,
            event="agent_start",
            sample_id=sample_id,
            stage=1,
            agent_key="operation_agent",
            index=1,
            total=len(agent_keys),
        )
        semantic_outputs["operation_agent"] = self._run_agent(
            "operation_agent",
            {"numbered_function_code": operation_numbered_code},
            source_code=sample["code"],
            max_line=max_line,
            line_locator=line_locator,
            progress_callback=progress_callback,
            progress_context={"sample_id": sample_id, "stage": 1},
        )
        emit_progress(
            progress_callback,
            event="agent_done",
            sample_id=sample_id,
            stage=1,
            agent_key="operation_agent",
            index=1,
            total=len(agent_keys),
            token_usage=token_usage_from_agent_output(semantic_outputs["operation_agent"]),
            max_tokens=max_tokens_from_agent_output(semantic_outputs["operation_agent"]),
            summary=agent_output_summary(semantic_outputs["operation_agent"]),
        )

        operation_anchors = operation_anchors_for_llm(semantic_outputs["operation_agent"]["parsed"])
        anchor_numbered_code = add_anchor_line_windows(
            sample["code"],
            operation_anchors.get("anchors", []),
        )
        for agent_index, agent_key in enumerate(["state_agent", "value_agent", "execution_agent"], start=2):
            emit_progress(
                progress_callback,
                event="agent_start",
                sample_id=sample_id,
                stage=1,
                agent_key=agent_key,
                index=agent_index,
                total=len(agent_keys),
            )
            semantic_outputs[agent_key] = self._run_agent(
                agent_key,
                {
                    "numbered_function_code": anchor_numbered_code,
                    "operation_anchors_json": operation_anchors,
                },
                source_code=sample["code"],
                max_line=max_line,
                line_locator=line_locator,
                progress_callback=progress_callback,
                progress_context={"sample_id": sample_id, "stage": 1},
            )
            agent_token_usage = token_usage_from_agent_output(semantic_outputs[agent_key])
            emit_progress(
                progress_callback,
                event="agent_done",
                sample_id=sample_id,
                stage=1,
                agent_key=agent_key,
                index=agent_index,
                total=len(agent_keys),
                token_usage=agent_token_usage,
                max_tokens=max_tokens_from_agent_output(semantic_outputs[agent_key]),
                summary=agent_output_summary(semantic_outputs[agent_key]),
            )

        semantic_model_record = build_semantic_model_record(sample_id, semantic_outputs)
        context_links_record = build_context_links_record(
            sample_id,
            semantic_model_record["output"]["semantic_model"],
        )
        semantic_model_record["quality_gate"]["context_links_summary"] = context_links_record["output"]["summary"]
        self._write_stage_json(sample_id, 1, semantic_model_record)
        self._write_context_links_json(sample_id, context_links_record)
        return read_json_file(self._stage_file_for_number(sample_id, 1))

    def run_stage_2(
        self,
        sample: dict[str, Any],
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        sample_id = sample["sample_id"]
        semantic_model_record = self._read_required_stage(sample_id, 1)
        merged_semantic_model = semantic_model_record["output"]["semantic_model"]
        context_links_record = self._read_or_build_context_links(sample_id, merged_semantic_model)
        semantic_link_clusters = compact_context_links_for_llm(context_links_record["output"])
        emit_progress(
            progress_callback,
            event="agent_start",
            sample_id=sample_id,
            stage=2,
            agent_key="obligation_reasoner",
            index=1,
            total=1,
        )
        reasoner_output = self.agents["obligation_reasoner"].run(
            {
                "semantic_link_clusters_json": semantic_link_clusters,
            },
            extra_validators=[
                lambda parsed: validate_obligation_evidence_refs(
                    parsed,
                    merged_semantic_model,
                )
            ],
            progress_callback=progress_callback,
            progress_context={"sample_id": sample_id, "stage": 2},
        )
        normalize_obligation_evidence_refs(
            reasoner_output["parsed"],
            merged_semantic_model,
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
        rules_record = build_rules_record(sample_id, reasoner_output)
        self._write_stage_json(sample_id, 2, rules_record)
        return read_json_file(self._stage_file_for_number(sample_id, 2))

    def run_stage_3(
        self,
        sample: dict[str, Any],
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        sample_id = sample["sample_id"]
        semantic_model_record = self._read_required_stage(sample_id, 1)
        rules_record = self._read_required_stage(sample_id, 2)
        merged_semantic_model = semantic_model_record["output"]["semantic_model"]
        operation_inventory = merged_semantic_model["operation_agent"]
        obligations = rules_from_record(rules_record)
        adjudications = []
        adjudicator_errors = []
        adjudicator_token_usage = empty_token_usage()
        adjudicator_quality_gate = None
        obligation_payload = []
        for obligation_index, obligation in enumerate(obligations, start=1):
            operation = find_operation(operation_inventory, obligation.get("operation_id"))
            evidence = filter_evidence_for_obligation(
                merged_semantic_model,
                obligation,
            )
            obligation_id = obligation.get("id", f"obligation_{obligation_index}")
            obligation_payload.append(
                {
                    "obligation_id": obligation_id,
                    "rule": compact_obligation_for_adjudicator(obligation),
                    "anchored_operation": strip_llm_noise(operation),
                    "obligation_specific_evidence": evidence,
                }
            )
        if obligations:
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
                        "obligations_json": obligation_payload,
                    },
                    extra_validators=[
                        lambda parsed: validate_batch_adjudications(
                            parsed,
                            [item["obligation_id"] for item in obligation_payload],
                        )
                    ],
                    progress_callback=progress_callback,
                    progress_context={"sample_id": sample_id, "stage": 3},
                )
                adjudicator_token_usage = token_usage_from_agent_output(adjudicator_output)
                adjudicator_quality_gate = adjudicator_output["quality_gate"]
                outputs_by_id = {
                    item.get("obligation_id"): item
                    for item in adjudicator_output["parsed"].get("adjudications", [])
                    if isinstance(item, dict)
                }
                for obligation_index, obligation in enumerate(obligations, start=1):
                    obligation_id = obligation.get("id", f"obligation_{obligation_index}")
                    adjudications.append(
                        {
                            "rule": obligation,
                            "output": outputs_by_id.get(obligation_id, missing_adjudication(obligation_id)),
                        }
                    )
                emit_progress(
                    progress_callback,
                    event="agent_done",
                    sample_id=sample_id,
                    stage=3,
                    agent_key="obligation_adjudicator",
                    index=1,
                    total=1,
                    token_usage=token_usage_from_agent_output(adjudicator_output),
                    max_tokens=max_tokens_from_agent_output(adjudicator_output),
                    summary=agent_output_summary(adjudicator_output),
                )
            except ValueError as exc:
                adjudicator_errors.append(
                    {
                        "stage": "Stage 3",
                        "agent_key": "obligation_adjudicator",
                        "error": str(exc),
                    }
                )

        input_quality = assess_input_quality(sample.get("code", ""), merged_semantic_model)
        evidence_status = assess_evidence_status(input_quality, rules_record, adjudications, adjudicator_errors)
        final_verdict = aggregate_final_verdict(adjudications, evidence_status)
        ground_truth = self.ground_truth_for_sample(sample_id)
        correct = None
        if (
            ground_truth is not None
            and ground_truth.get("target") is not None
            and final_verdict["binary_prediction"] is not None
        ):
            correct = int(final_verdict["binary_prediction"]) == int(ground_truth["target"])
        best_effort_correct = None
        if ground_truth is not None and ground_truth.get("target") is not None:
            best_effort_correct = int(final_verdict["best_effort_binary_prediction"]) == int(ground_truth["target"])
        evaluation_diagnostics = build_evaluation_diagnostics(
            ground_truth,
            correct,
            input_quality,
            evidence_status,
            rules_record,
            adjudications,
            final_verdict,
        )
        diagnostics = build_pipeline_diagnostics(
            semantic_model_record,
            rules_record,
            adjudications,
            adjudicator_errors,
            input_quality,
            evidence_status,
            adjudicator_quality_gate,
        )
        record = {
            "sample_id": sample_id,
            "agent_key": "obligation_adjudicator",
            "ground_truth": ground_truth,
            "output": {
                "adjudications": adjudications,
                "violation": final_verdict["violation"],
                "binary_prediction": final_verdict["binary_prediction"],
                "best_effort_binary_prediction": final_verdict["best_effort_binary_prediction"],
                "label": final_verdict["label"],
                "verdict_confidence": final_verdict["verdict_confidence"],
                "evidence_status": evidence_status["status"],
                "input_quality": input_quality,
                "ground_truth": ground_truth,
                "correct": correct,
                "best_effort_correct": best_effort_correct,
                "evaluation_diagnostics": evaluation_diagnostics,
                "aggregation_rule": final_verdict["aggregation_rule"],
                "violated_obligation_ids": final_verdict["violated_obligation_ids"],
            },
            "quality_gate": {
                "status": "passed" if not diagnostics["errors"] else "failed",
                "adjudication_count": len(adjudications),
                "adjudicator": adjudicator_quality_gate,
            },
            "token_usage": adjudicator_token_usage,
            "pipeline_diagnostics": diagnostics,
        }
        self._write_stage_json(
            sample_id,
            3,
            record,
        )
        return record

    def load_samples(self, limit: int | None = None) -> list[dict[str, Any]]:
        samples = []
        for index, sample in enumerate(read_jsonl(self._input_file())):
            if limit is not None and index >= limit:
                break
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
            config = agent_configs.get(key, {})
            if config.get("enabled", True):
                agents[key] = cls(key, config, self.project_root, self.llm_client)
        return agents

    def _run_and_save(
        self,
        agent_key: str,
        sample_id: str,
        variables: dict[str, Any],
        suffix: str | None = None,
        max_line: int | None = None,
        line_locator: LineLocatorTool | None = None,
    ) -> dict[str, Any]:
        extra_validators = []
        extra_validators.append(lambda parsed: validate_semantic_fact_contract(parsed, agent_key))
        if max_line is not None:
            extra_validators.append(lambda parsed: validate_line_numbers(parsed, max_line))
        if line_locator is not None:
            extra_validators.append(lambda parsed: validate_source_grounding(parsed, line_locator))
        output = self.agents[agent_key].run(variables, extra_validators=extra_validators)
        record = {
            "sample_id": sample_id,
            "agent_key": agent_key,
            "output": output["parsed"],
            "quality_gate": output["quality_gate"],
        }
        file_stem = agent_key if suffix is None else f"{agent_key}_{suffix}"
        output_path = self.stage_root / sample_id / f"stage_1_{file_stem}.json"
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        return output

    def _run_agent(
        self,
        agent_key: str,
        variables: dict[str, Any],
        source_code: str | None = None,
        max_line: int | None = None,
        line_locator: LineLocatorTool | None = None,
        progress_callback: ProgressCallback | None = None,
        progress_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        extra_validators = []
        extra_validators.append(lambda parsed: validate_semantic_fact_contract(parsed, agent_key))
        if source_code is not None:
            extra_validators.append(lambda parsed: validate_nonempty_semantic_output(parsed, agent_key, source_code))
        if max_line is not None:
            extra_validators.append(lambda parsed: validate_line_numbers(parsed, max_line))
        if line_locator is not None:
            extra_validators.append(lambda parsed: validate_source_grounding(parsed, line_locator))
        return self.agents[agent_key].run(
            variables,
            extra_validators=extra_validators,
            progress_callback=progress_callback,
            progress_context=progress_context,
        )

    def _stage_file_for_number(self, sample_id: str, stage: int) -> Path:
        return self.stage_root / sample_id / STAGE_FILES[stage]

    def _read_required_stage(self, sample_id: str, stage: int) -> dict[str, Any]:
        path = self._stage_file_for_number(sample_id, stage)
        if not path.exists():
            raise FileNotFoundError(
                f"{STAGE_LABELS[stage]} output is required before running the next stage: {path}"
            )
        return read_json_file(path)

    def _write_stage_json(self, sample_id: str, stage: int, record: dict[str, Any]) -> None:
        output_path = self._stage_file_for_number(sample_id, stage)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def _context_links_file(self, sample_id: str) -> Path:
        return self.stage_root / sample_id / STAGE_1_5_FILE

    def _write_context_links_json(self, sample_id: str, record: dict[str, Any]) -> None:
        output_path = self._context_links_file(sample_id)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def _read_or_build_context_links(self, sample_id: str, semantic_model: dict[str, Any]) -> dict[str, Any]:
        path = self._context_links_file(sample_id)
        if path.exists():
            return read_json_file(path)
        record = build_context_links_record(sample_id, semantic_model)
        self._write_context_links_json(sample_id, record)
        return record

    def _ensure_stage_dirs(self) -> None:
        self.stage_root.mkdir(exist_ok=True)

    def _clear_split_outputs(self) -> None:
        for sample_dir in self.stage_root.glob(f"{self.split}_*"):
            if sample_dir.is_dir():
                shutil.rmtree(sample_dir)
            elif sample_dir.is_file():
                sample_dir.unlink()
        for legacy_stage_dir in self.stage_root.glob("Stage *"):
            if not legacy_stage_dir.is_dir():
                continue
            for sample_dir in legacy_stage_dir.glob(f"{self.split}_*"):
                if sample_dir.is_dir():
                    shutil.rmtree(sample_dir)

    def _input_file(self) -> Path:
        active_dataset = self.datasets_config["defaults"]["active_dataset"]
        split_config = self.datasets_config["datasets"][active_dataset]["splits"][self.split]
        return self.project_root / split_config["input_file"]

    def _label_file(self) -> Path | None:
        active_dataset = self.datasets_config["defaults"]["active_dataset"]
        split_config = self.datasets_config["datasets"][active_dataset]["splits"].get(self.split, {})
        label_file = split_config.get("label_file")
        if not label_file:
            return None
        return self.project_root / label_file

    def load_labels(self) -> dict[str, dict[str, Any]]:
        if self._labels_by_sample_id is not None:
            return self._labels_by_sample_id
        label_path = self._label_file()
        labels: dict[str, dict[str, Any]] = {}
        if label_path is not None and label_path.exists():
            for label in read_jsonl(label_path):
                sample_id = label.get("sample_id")
                if sample_id:
                    labels[sample_id] = {
                        "sample_id": sample_id,
                        "pair_id": label.get("pair_id"),
                        "target": label.get("target"),
                        "label": "vulnerable" if label.get("target") == 1 else "benign",
                        "cve": label.get("cve"),
                        "cwe": label.get("cwe") or [],
                    }
        self._labels_by_sample_id = labels
        return labels

    def ground_truth_for_sample(self, sample_id: str) -> dict[str, Any] | None:
        return self.load_labels().get(sample_id)

    def stage_status(self, sample_id: str) -> dict[int, str]:
        status = {}
        for stage in range(1, 4):
            path = self._stage_file_for_number(sample_id, stage)
            status[stage] = "ready" if path.exists() else "missing"
        return status


def read_jsonl(path: Path) -> Iterable[dict[str, Any]]:
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                yield json.loads(line)


def read_json_file(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def add_line_numbers(code: str) -> str:
    return "\n".join(f"{line_no}: {line}" for line_no, line in enumerate(code.splitlines(), start=1))


def add_security_signal_line_windows(code: str, radius: int = 2) -> str:
    lines = code.splitlines()
    signal_lines = [
        index
        for index, line in enumerate(lines, start=1)
        if is_security_signal_line(line)
    ]
    return add_windows_for_lines(code, signal_lines, radius=radius)


def add_anchor_line_windows(code: str, anchors: list[Any], radius: int = 28) -> str:
    lines = code.splitlines()
    anchor_lines = sorted(
        {
            int(anchor["line"])
            for anchor in anchors
            if isinstance(anchor, dict)
            and isinstance(anchor.get("line"), int)
            and 1 <= int(anchor["line"]) <= len(lines)
        }
    )
    return add_windows_for_lines(code, anchor_lines, radius=radius)


def add_windows_for_lines(code: str, selected_lines: list[int], radius: int) -> str:
    lines = code.splitlines()
    if not lines:
        return ""

    selected = sorted({line_no for line_no in selected_lines if 1 <= line_no <= len(lines)})
    if not selected:
        return add_line_numbers(code)

    ranges = []
    for line_no in selected:
        start = max(1, line_no - radius)
        end = min(len(lines), line_no + radius)
        if ranges and start <= ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], max(ranges[-1][1], end))
        else:
            ranges.append((start, end))

    numbered_lines = []
    for range_index, (start, end) in enumerate(ranges):
        if range_index > 0:
            numbered_lines.append("...")
        numbered_lines.extend(f"{line_no}: {lines[line_no - 1]}" for line_no in range(start, end + 1))
    return "\n".join(numbered_lines)


def is_security_signal_line(line: str) -> bool:
    stripped = line.strip()
    if not stripped or stripped.startswith("//"):
        return False
    patterns = (
        r"->",
        r"\[[^\]]+\]",
        r"\*\s*[A-Za-z_]\w*",
        r"\*\s*\([^)]*\*\s*\)\s*[A-Za-z_]\w*",
        r"\b(?:memcpy|memmove|memset|strcpy|strncpy|snprintf|sprintf|strlen|malloc|calloc|realloc|free)\s*\(",
        r"\b(?:AcquireQuantumMemory|RelinquishMagickMemory|DestroySplayTree|CloneString|GetStringInfo(?:Datum|Length)|ReadProperty(?:Signed|Unsigned)?(?:Byte|Short|Long)|Write[A-Za-z_0-9]*|Copy[A-Za-z_0-9]*)\s*\(",
        r"\b(?:size_t|ssize_t|int|long|short|char|float|double|void|unsigned\s+char|signed\s+char)\s*\*?\s*\)",
        r"\([^)]*\*\s*\)\s*[A-Za-z_]\w*",
        r"\b(?:length|size|count|offset|index|bytes?|entries|components|format|tag)\b.*(?:\+|\-|\*|/|%|<<|>>|=)",
    )
    return any(re.search(pattern, stripped) for pattern in patterns)


def count_lines(code: str) -> int:
    return len(code.splitlines())


def empty_token_usage() -> dict[str, int]:
    return {
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
    }


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
    quality_gate = output.get("quality_gate", {})
    usage = quality_gate.get("token_usage", {})
    return sum_token_usages([usage])


def max_tokens_from_agent_output(output: dict[str, Any]) -> int:
    attempts = output.get("quality_gate", {}).get("attempts", [])
    if not attempts:
        return 0
    return max(int(attempt.get("max_tokens", 0) or 0) for attempt in attempts)


def agent_output_summary(output: dict[str, Any]) -> str:
    parsed = output.get("parsed", {})
    if not isinstance(parsed, dict):
        return ""
    parts = []
    operations = parsed.get("operations")
    records = parsed.get("records")
    obligations = parsed.get("obligations")
    adjudications = parsed.get("adjudications")
    if isinstance(operations, list):
        parts.append(f"operations={len(operations)}")
    if isinstance(records, list):
        parts.append(f"records={len(records)}")
    if isinstance(obligations, list):
        parts.append(f"obligations={len(obligations)}")
    if isinstance(adjudications, list):
        parts.append(f"adjudications={len(adjudications)}")
    if "violation" in parsed:
        parts.append(f"violation={parsed.get('violation')}")
    if "evidence_sufficiency" in parsed:
        parts.append(f"sufficiency={parsed.get('evidence_sufficiency')}")
    return ", ".join(parts)


def token_usage_from_record(record: dict[str, Any] | None) -> dict[str, int]:
    if not record:
        return empty_token_usage()
    return sum_token_usages([record.get("token_usage", {})])


def stage_status_from_record(record: dict[str, Any] | None) -> str:
    if not record:
        return "unknown"
    quality_gate = record.get("quality_gate", {})
    if isinstance(quality_gate, dict):
        return str(quality_gate.get("status", "unknown"))
    return "unknown"


def stage_summary(stage: int, record: dict[str, Any] | None) -> str:
    if not record:
        return ""
    if stage == 1:
        agent_count = record.get("quality_gate", {}).get("agent_count", 0)
        mode = record.get("quality_gate", {}).get("mode", "split")
        link_summary = record.get("quality_gate", {}).get("context_links_summary", {})
        if isinstance(link_summary, dict) and link_summary:
            return (
                f"agents={agent_count}, mode={mode}, "
                f"clusters={link_summary.get('cluster_count', 0)}, links={link_summary.get('link_count', 0)}"
            )
        return f"agents={agent_count}, mode={mode}"
    if stage == 2:
        obligations = rules_from_record(record)
        return f"obligations={len(obligations)}"
    if stage == 3:
        output = record.get("output", {})
        return (
            f"verdict={str(output.get('label', 'unknown')).lower()}, "
            f"violation={output.get('violation')}, correct={output.get('correct')}"
        )
    return ""


def build_semantic_model_record(sample_id: str, semantic_outputs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    semantic_model = {
        agent_key: output["parsed"]
        for agent_key, output in semantic_outputs.items()
    }
    return {
        "sample_id": sample_id,
        "stage": "semantic_model",
        "output": {
            "semantic_model": semantic_model,
            "agent_quality_gates": {
                agent_key: output["quality_gate"]
                for agent_key, output in semantic_outputs.items()
            },
        },
        "quality_gate": {
            "status": "passed",
            "agent_count": len(semantic_outputs),
            "mode": "split_agents",
            "grounding_summary": summarize_grounding(semantic_model),
        },
        "token_usage": sum_token_usages(
            token_usage_from_agent_output(output)
            for output in semantic_outputs.values()
        ),
    }


def compact_semantic_model_for_llm(semantic_model: dict[str, Any]) -> dict[str, Any]:
    return strip_llm_noise(semantic_model)


def compact_context_links_for_llm(context_links: dict[str, Any]) -> dict[str, Any]:
    clusters = context_links.get("clusters", [])
    if not isinstance(clusters, list):
        clusters = []
    return {
        "clusters": [compact_context_cluster_for_llm(cluster) for cluster in clusters],
    }


def compact_context_cluster_for_llm(cluster: Any) -> dict[str, Any]:
    if not isinstance(cluster, dict):
        return {}
    linked_facts = cluster.get("linked_facts", [])
    if not isinstance(linked_facts, list):
        linked_facts = []
    compact = {
        "id": cluster.get("id"),
        "anchor_ref": cluster.get("anchor_ref"),
        "operation_id": cluster.get("operation_id"),
        "line": cluster.get("line"),
        "entity": cluster.get("entity"),
        "base_entity": cluster.get("base_entity"),
        "access_path": cluster.get("access_path"),
        "role": cluster.get("role"),
        "effect": cluster.get("effect"),
        "risk_tags": cluster.get("risk_tags", []),
        "link_confidence": cluster.get("link_confidence"),
        "anchor_operation": compact_fact_for_llm(cluster.get("anchor_operation")),
        "linked_facts": [compact_fact_for_llm(fact) for fact in linked_facts[:4]],
        "omitted_link_count": int(cluster.get("omitted_link_count", 0) or 0) + max(0, len(linked_facts) - 4),
    }
    return drop_empty_values(compact)


def compact_fact_for_llm(fact: Any) -> dict[str, Any]:
    if not isinstance(fact, dict):
        return {}
    keys = (
        "ref",
        "id",
        "line",
        "entity",
        "base_entity",
        "access_path",
        "role",
        "effect",
        "relation",
        "condition",
        "target_entity",
        "value_entity",
        "target_line",
        "evidence",
    )
    return drop_empty_values({key: fact.get(key) for key in keys})


def operation_anchors_for_llm(operation_output: dict[str, Any]) -> dict[str, Any]:
    operations = operation_output.get("operations", [])
    if not isinstance(operations, list):
        operations = []
    return {
        "anchors": [
            compact_fact_for_llm({"ref": f"operation_agent.operations[{index}]", **strip_llm_noise(operation)})
            for index, operation in enumerate(operations)
            if isinstance(operation, dict)
        ]
    }


def compact_fact_for_adjudicator(fact: Any) -> dict[str, Any]:
    if not isinstance(fact, dict):
        return {}
    keys = (
        "ref",
        "id",
        "line",
        "role",
        "effect",
        "relation",
        "condition",
        "target_line",
        "evidence",
        "unresolved",
    )
    compact = {key: fact.get(key) for key in keys}
    for key in ("entity", "base_entity", "access_path", "target_entity", "value_entity"):
        value = fact.get(key)
        if value:
            compact[key] = value
    return drop_empty_values(compact)


def drop_empty_values(value: dict[str, Any]) -> dict[str, Any]:
    return {
        key: child
        for key, child in value.items()
        if child not in (None, "", [], {}) and child is not False
    }


def strip_llm_noise(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: strip_llm_noise(child)
            for key, child in value.items()
            if key not in {"grounding", "raw_response", "quality_gate"}
        }
    if isinstance(value, list):
        return [strip_llm_noise(item) for item in value]
    return value


def build_context_links_record(sample_id: str, semantic_model: dict[str, Any]) -> dict[str, Any]:
    facts = collect_semantic_facts(semantic_model)
    operations = [fact for fact in facts if fact["agent_key"] == "operation_agent" and fact["collection"] == "operations"]
    operation_refs = {fact["ref"] for fact in operations}
    support_facts = [fact for fact in facts if fact["ref"] not in operation_refs]
    clusters = []
    all_links = []
    linked_refs: set[str] = set()

    for cluster_index, operation in enumerate(operations, start=1):
        ranked_links = []
        for fact in support_facts:
            score, link_types, confidence, basis = score_semantic_link(operation, fact)
            if score <= 0:
                continue
            ranked_links.append(
                {
                    "source_ref": fact["ref"],
                    "target_ref": operation["ref"],
                    "types": link_types,
                    "confidence": confidence,
                    "score": score,
                    "basis": basis,
                    "source_fact": fact_for_cluster(fact),
                }
            )

        ranked_links.sort(
            key=lambda link: (
                -int(link["score"]),
                line_sort_key(link["source_fact"].get("line")),
                link["source_ref"],
            )
        )
        kept_links = ranked_links[:16]
        linked_refs.update(link["source_ref"] for link in kept_links)
        linked_refs.add(operation["ref"])
        all_links.extend({key: value for key, value in link.items() if key != "source_fact"} for link in kept_links)
        cluster_confidence = cluster_link_confidence(kept_links)
        cluster = {
            "id": f"cluster_{cluster_index}",
            "anchor_ref": operation["ref"],
            "operation_id": operation["id"],
            "line": operation.get("line"),
            "entity": operation.get("entity"),
            "base_entity": operation.get("base_entity"),
            "access_path": operation.get("access_path"),
            "role": operation.get("role"),
            "effect": operation.get("effect"),
            "risk_tags": infer_operation_risk_tags(operation),
            "link_confidence": cluster_confidence,
            "anchor_operation": fact_for_cluster(operation),
            "linked_facts": [link["source_fact"] for link in kept_links],
            "links": [{key: value for key, value in link.items() if key not in {"source_fact", "score"}} for link in kept_links],
            "omitted_link_count": max(0, len(ranked_links) - len(kept_links)),
        }
        clusters.append(cluster)

    unclustered_refs = [
        fact["ref"]
        for fact in facts
        if fact["ref"] not in linked_refs
    ]
    summary = {
        "operation_count": len(operations),
        "fact_count": len(facts),
        "cluster_count": len(clusters),
        "link_count": len(all_links),
        "unclustered_fact_count": len(unclustered_refs),
        "strong_cluster_count": sum(1 for cluster in clusters if cluster["link_confidence"] == "strong"),
        "weak_cluster_count": sum(1 for cluster in clusters if cluster["link_confidence"] == "weak"),
        "unlinked_operation_count": sum(1 for cluster in clusters if not cluster["linked_facts"]),
    }
    return {
        "sample_id": sample_id,
        "stage": "context_links",
        "output": {
            "clusters": clusters,
            "links": all_links,
            "unclustered_refs": unclustered_refs,
            "summary": summary,
        },
        "quality_gate": {
            "status": "passed",
            "mode": "deterministic_stage_1_5_linker",
            "notes": [
                "No LLM call is used in Stage 1.5.",
                "Every Stage 1 operation remains represented even when no support fact links strongly.",
            ],
        },
        "token_usage": empty_token_usage(),
    }


def collect_semantic_facts(semantic_model: dict[str, Any]) -> list[dict[str, Any]]:
    facts = []
    for agent_key, output in semantic_model.items():
        if not isinstance(output, dict):
            continue
        for collection_name in ("operations", "records"):
            collection = output.get(collection_name, [])
            if not isinstance(collection, list):
                continue
            for index, item in enumerate(collection):
                if not isinstance(item, dict):
                    continue
                fact = strip_llm_noise(item)
                facts.append(
                    {
                        "ref": f"{agent_key}.{collection_name}[{index}]",
                        "agent_key": agent_key,
                        "collection": collection_name,
                        "index": index,
                        "id": str(fact.get("id") or ""),
                        "line": parse_int_or_none(fact.get("line")),
                        "target_line": parse_int_or_none(fact.get("target_line")),
                        "entity": normalize_entity(fact.get("entity")),
                        "base_entity": normalize_entity(fact.get("base_entity") or fact.get("entity")),
                        "access_path": normalize_entity(fact.get("access_path")),
                        "target_entity": normalize_entity(fact.get("target_entity")),
                        "value_entity": normalize_entity(fact.get("value_entity")),
                        "role": normalize_entity(fact.get("role")),
                        "effect": normalize_entity(fact.get("effect")),
                        "relation": normalize_entity(fact.get("relation")),
                        "condition": normalize_entity(fact.get("condition")),
                        "unresolved": bool(fact.get("unresolved")),
                        "fact": fact,
                    }
                )
    return facts


def fact_for_cluster(fact: dict[str, Any]) -> dict[str, Any]:
    compact = {
        "ref": fact["ref"],
        "id": fact["id"],
        "line": fact.get("line"),
        "agent_key": fact["agent_key"],
        "entity": fact.get("entity"),
        "base_entity": fact.get("base_entity"),
        "access_path": fact.get("access_path"),
        "role": fact.get("role"),
        "effect": fact.get("effect"),
        "relation": fact.get("relation"),
        "condition": fact.get("condition"),
        "target_entity": fact.get("target_entity"),
        "value_entity": fact.get("value_entity"),
        "target_line": fact.get("target_line"),
        "unresolved": fact.get("unresolved"),
        "evidence": fact.get("fact", {}).get("evidence", ""),
    }
    return {key: value for key, value in compact.items() if value not in (None, "", [])}


def score_semantic_link(operation: dict[str, Any], fact: dict[str, Any]) -> tuple[int, list[str], str, str]:
    score = 0
    link_types: list[str] = []
    basis = []
    distance = None
    if fact.get("line") is not None and operation.get("line") is not None:
        distance = abs(int(fact["line"]) - int(operation["line"]))
    op_entities = fact_entity_set(operation)
    fact_entities = fact_entity_set(fact)
    shared_entities = sorted(op_entities & fact_entities)

    if shared_entities:
        score += 5
        link_types.append("shared_entity")
        basis.append("shared=" + ",".join(shared_entities[:3]))
    if operation.get("base_entity") and operation.get("base_entity") == fact.get("base_entity"):
        score += 4
        link_types.append("same_base_entity")
    if operation.get("access_path") and operation.get("access_path") == fact.get("access_path"):
        score += 3
        link_types.append("same_access_path")
    if operation.get("line") is not None and fact.get("target_line") == operation.get("line"):
        score += 6
        link_types.append("control_targets_operation")
    if distance is not None:
        if distance <= 3:
            score += 3
            link_types.append("nearby_line")
        elif distance <= 10 and shared_entities:
            score += 1
            link_types.append("nearby_entity_line")
        if int(fact["line"]) <= int(operation["line"]) and shared_entities:
            score += 1
            link_types.append("reaches_operation_line")
    if fact["agent_key"] == "execution_agent" and fact.get("role") in {"guard", "branch", "path"}:
        if fact.get("target_line") == operation.get("line") or (shared_entities and (distance is None or distance <= 80)):
            score += 4
            link_types.append("path_guard")
    if fact["agent_key"] == "state_agent" and (shared_entities or operation.get("entity") == fact.get("target_entity")):
        score += 3
        link_types.append("state_reaches_operation")
        if fact.get("role") == "alias" or fact.get("effect") == "alias":
            score += 2
            link_types.append("alias_relation")
    if fact["agent_key"] == "value_agent" and shared_entities:
            score += 3
            link_types.append("value_constrains_operation")

    link_types = dedupe_preserving_order(link_types)
    if is_far_name_only_link(distance, link_types):
        return 0, [], "weak", ""
    confidence = "strong" if score >= 8 else "weak"
    return score, link_types, confidence, "; ".join(basis)


def is_far_name_only_link(distance: int | None, link_types: list[str]) -> bool:
    if distance is None or distance <= 80:
        return False
    durable_links = {
        "control_targets_operation",
        "path_guard",
        "alias_relation",
    }
    if any(link_type in durable_links for link_type in link_types):
        return False
    name_only_links = {
        "shared_entity",
        "same_base_entity",
        "same_access_path",
        "reaches_operation_line",
        "state_reaches_operation",
        "value_constrains_operation",
        "nearby_entity_line",
    }
    return bool(link_types) and all(link_type in name_only_links for link_type in link_types)


def fact_entity_set(fact: dict[str, Any]) -> set[str]:
    return {
        value
        for key in ("entity", "base_entity", "access_path", "target_entity", "value_entity")
        for value in [fact.get(key)]
        if isinstance(value, str) and value
    }


def infer_operation_risk_tags(operation: dict[str, Any]) -> list[str]:
    text = " ".join(
        str(operation.get(key, ""))
        for key in ("operation", "role", "effect", "kind", "contract", "entity", "access_path")
    ).lower()
    tags = []
    keyword_tags = [
        ("dereference", "memory-access"),
        ("index", "bounds"),
        ("bound", "bounds"),
        ("copy", "copy-size"),
        ("memcpy", "copy-size"),
        ("strcpy", "copy-size"),
        ("alloc", "allocation"),
        ("free", "lifetime"),
        ("cleanup", "lifetime"),
        ("cast", "type-conversion"),
        ("arith", "integer-arithmetic"),
        ("overflow", "integer-arithmetic"),
        ("lock", "locking"),
        ("unlock", "locking"),
        ("call", "api-call"),
    ]
    for keyword, tag in keyword_tags:
        if keyword in text and tag not in tags:
            tags.append(tag)
    return tags or ["semantic-operation"]


def cluster_link_confidence(links: list[dict[str, Any]]) -> str:
    if any(link.get("confidence") == "strong" for link in links):
        return "strong"
    if links:
        return "weak"
    return "unlinked"


def normalize_entity(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    text = re.sub(r"\s+", "", text)
    text = re.sub(r"^\*+", "", text)
    text = re.sub(r"^\&+", "", text)
    text = re.sub(r"^\(([^()]+)\)$", r"\1", text)
    return text


def parse_int_or_none(value: Any) -> int | None:
    try:
        if value in (None, ""):
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def line_sort_key(value: Any) -> int:
    parsed = parse_int_or_none(value)
    return parsed if parsed is not None else 10**9


def summarize_grounding(semantic_model: dict[str, Any]) -> dict[str, int]:
    summary = {
        "records": 0,
        "pass": 0,
        "warning": 0,
        "retry": 0,
        "missing": 0,
    }
    for agent_output in semantic_model.values():
        if not isinstance(agent_output, dict):
            continue
        for collection_name in ("operations", "records"):
            for item in agent_output.get(collection_name, []):
                if not isinstance(item, dict):
                    continue
                summary["records"] += 1
                grounding = item.get("grounding")
                if not isinstance(grounding, dict):
                    summary["missing"] += 1
                    continue
                status = grounding.get("status")
                if status in {"pass", "warning", "retry"}:
                    summary[status] += 1
                else:
                    summary["missing"] += 1
    return summary


def build_rules_record(sample_id: str, reasoner_output: dict[str, Any]) -> dict[str, Any]:
    obligations = reasoner_output["parsed"].get("obligations", [])
    return {
        "sample_id": sample_id,
        "stage": "rules",
        "agent_key": "obligation_reasoner",
        "output": {
            "rules": obligations,
        },
        "quality_gate": reasoner_output["quality_gate"],
        "token_usage": token_usage_from_agent_output(reasoner_output),
    }


def rules_from_record(rules_record: dict[str, Any]) -> list[dict[str, Any]]:
    output = rules_record.get("output", {})
    rules = output.get("rules", output.get("obligations", []))
    return rules if isinstance(rules, list) else []


def compact_obligation_for_adjudicator(obligation: dict[str, Any]) -> dict[str, Any]:
    keep = (
        "id",
        "cluster_id",
        "operation_id",
        "coverage_category",
        "safety_requirement",
        "applicable_condition",
        "link_confidence",
        "evidence_refs",
    )
    return drop_empty_values({key: obligation.get(key) for key in keep})


def missing_adjudication(obligation_id: str) -> dict[str, Any]:
    return {
        "obligation_id": obligation_id,
        "violation": 0,
        "refs": [],
    }


def validate_batch_adjudications(output: dict[str, Any], obligation_ids: list[str]) -> list[str]:
    adjudications = output.get("adjudications", [])
    returned_ids = [
        item.get("obligation_id")
        for item in adjudications
        if isinstance(item, dict)
    ]
    expected = set(obligation_ids)
    returned = set(returned_ids)
    errors = []
    missing = sorted(expected - returned)
    extra = sorted(returned - expected)
    if missing:
        errors.append(f"adjudications missing obligation_id(s): {', '.join(missing)}")
    if extra:
        errors.append(f"adjudications contain unknown obligation_id(s): {', '.join(extra)}")
    if len(returned_ids) != len(returned):
        errors.append("adjudications contain duplicate obligation_id values")
    return errors


def validate_obligation_evidence_refs(
    output: dict[str, Any],
    semantic_model: dict[str, Any],
) -> list[str]:
    errors: list[str] = []
    for owner, item_index, item in _items_with_evidence_refs(output):
        for ref_index, ref in enumerate(item.get("evidence_refs", [])):
            if not isinstance(ref, str) or _canonical_evidence_ref(ref, semantic_model) is None:
                errors.append(
                    f"{owner}[{item_index}].evidence_refs[{ref_index}]={ref!r} must reference an existing "
                    "semantic_model path like operation_agent.operations[0] or an existing operation id like op_3"
                )
    return errors


def normalize_obligation_evidence_refs(
    output: dict[str, Any],
    semantic_model: dict[str, Any],
) -> None:
    for _, _, item in _items_with_evidence_refs(output):
        normalized = []
        for ref in item.get("evidence_refs", []):
            canonical = _canonical_evidence_ref(str(ref), semantic_model)
            normalized.append(canonical or ref)
        item["evidence_refs"] = dedupe_preserving_order(normalized)


def dedupe_preserving_order(values: list[Any]) -> list[Any]:
    deduped = []
    seen = set()
    for value in values:
        marker = json.dumps(value, ensure_ascii=False, sort_keys=True) if isinstance(value, (dict, list)) else value
        if marker in seen:
            continue
        seen.add(marker)
        deduped.append(value)
    return deduped


def _items_with_evidence_refs(output: dict[str, Any]) -> Iterable[tuple[str, int, dict[str, Any]]]:
    for owner in ("coverage_review", "obligations"):
        items = output.get(owner, [])
        if not isinstance(items, list):
            continue
        for item_index, item in enumerate(items):
            if isinstance(item, dict):
                yield owner, item_index, item


def _canonical_evidence_ref(
    ref: str,
    semantic_model: dict[str, Any],
) -> str | None:
    ref = ref.strip()
    id_ref = _semantic_id_ref(ref, semantic_model)
    if id_ref is not None:
        return id_ref

    agent_key, dot, rest = ref.partition(".")
    if not dot or agent_key not in semantic_model:
        return None
    collection_name, bracket, index_text = rest.partition("[")
    if bracket != "[" or not index_text.endswith("]"):
        return None
    if collection_name not in {"operations", "records"}:
        return None
    try:
        index = int(index_text[:-1])
    except ValueError:
        return None
    collection = semantic_model.get(agent_key, {}).get(collection_name, [])
    if not isinstance(collection, list):
        return None
    if 0 <= index < len(collection):
        return f"{agent_key}.{collection_name}[{index}]"
    one_based_index = index - 1
    if 0 <= one_based_index < len(collection):
        return f"{agent_key}.{collection_name}[{one_based_index}]"
    return None


def _semantic_id_ref(ref: str, semantic_model: dict[str, Any]) -> str | None:
    if not re.fullmatch(r"[A-Za-z]+_\d+|u_\d+", ref):
        return None
    for agent_key, output in semantic_model.items():
        if not isinstance(output, dict):
            continue
        for collection_name in ("operations", "records"):
            collection = output.get(collection_name, [])
            if not isinstance(collection, list):
                continue
            for index, item in enumerate(collection):
                if isinstance(item, dict) and item.get("id") == ref:
                    return f"{agent_key}.{collection_name}[{index}]"
    return None


def assess_input_quality(code: str, semantic_model: dict[str, Any]) -> dict[str, Any]:
    operation_records = semantic_model.get("operation_agent", {}).get("operations", [])
    operations = operation_records if isinstance(operation_records, list) else []
    semantic_record_count = 0
    for agent_key, output in semantic_model.items():
        if agent_key == "operation_agent" or not isinstance(output, dict):
            continue
        records = output.get("records", [])
        if isinstance(records, list):
            semantic_record_count += len(records)

    unresolved_operations = [
        operation
        for operation in operations
        if isinstance(operation, dict) and (operation.get("unresolved") or operation.get("kind") == "project_specific")
    ]
    concrete_operations = [
        operation
        for operation in operations
        if isinstance(operation, dict) and not operation.get("unresolved") and operation.get("kind") != "project_specific"
    ]
    function_name = extract_function_name(code)
    reasons = []
    status = "adequate"

    if is_harness_like_function(function_name, code):
        status = "suspicious"
        reasons.append("function appears to be a test harness, registration wrapper, or entry-point scaffold")
    if operations and len(unresolved_operations) == len(operations) and not concrete_operations:
        status = "suspicious" if semantic_record_count <= 2 else max_input_quality(status, "limited")
        reasons.append("all visible operations are unresolved or project-specific")
    if not operations and semantic_record_count == 0:
        status = max_input_quality(status, "limited")
        reasons.append("no security-relevant operations or semantic records were extracted")
    return {
        "status": status,
        "function_name": function_name,
        "reasons": reasons,
        "operation_count": len(operations),
        "concrete_operation_count": len(concrete_operations),
        "unresolved_operation_count": len(unresolved_operations),
        "semantic_record_count": semantic_record_count,
    }


def max_input_quality(left: str, right: str) -> str:
    severity = {"adequate": 0, "limited": 1, "suspicious": 2}
    return left if severity.get(left, 0) >= severity.get(right, 0) else right


def extract_function_name(code: str) -> str | None:
    match = re.search(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*\{", code)
    return match.group(1) if match else None


def is_harness_like_function(function_name: str | None, code: str) -> bool:
    lowered_name = (function_name or "").lower()
    harness_name_patterns = (
        "setup_tests",
        "setup_test",
        "register_tests",
        "register_test",
        "test_main",
        "main",
    )
    if lowered_name in harness_name_patterns:
        return True
    if lowered_name.startswith("test_") or lowered_name.endswith("_test"):
        return True
    harness_markers = (
        "ADD_TEST(",
        "ADD_ALL_TESTS(",
        "RUN_TEST(",
        "REGISTER_TEST",
        "TEST_CASE(",
    )
    return any(marker in code for marker in harness_markers)


def assess_evidence_status(
    input_quality: dict[str, Any],
    rules_record: dict[str, Any],
    adjudications: list[dict[str, Any]],
    adjudicator_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    reasons = []
    obligations = rules_from_record(rules_record)
    if adjudicator_errors:
        reasons.append("adjudicator failed before producing a complete verdict")
    if input_quality.get("status") in {"limited", "suspicious"}:
        reasons.extend(input_quality.get("reasons", []))
    if not obligations and input_quality.get("status") != "adequate":
        reasons.append("no obligations were produced from a limited or suspicious input scope")
    for item in adjudications:
        output = item.get("output", {})
        if output.get("violation") == 1:
            return {
                "status": "adequate",
                "reasons": [],
            }
        if output.get("evidence_sufficiency") in {"insufficient", "ambiguous"}:
            reasons.append(f"{output.get('obligation_id', 'unknown')} has insufficient or ambiguous evidence")

    status = "insufficient" if reasons else "adequate"
    return {
        "status": status,
        "reasons": dedupe_preserving_order(reasons),
    }


def aggregate_final_verdict(adjudications: list[dict[str, Any]], evidence_status: dict[str, Any]) -> dict[str, Any]:
    violated_obligation_ids = []
    for item in adjudications:
        output = item.get("output", {})
        if output.get("violation") != 1:
            continue
        obligation_id = output.get("obligation_id") or item.get("rule", {}).get("id")
        if obligation_id:
            violated_obligation_ids.append(obligation_id)

    violation = 1 if violated_obligation_ids else 0
    if violation == 1:
        label = "Vulnerable"
        binary_prediction = 1
        verdict_confidence = "normal"
    else:
        label = "Benign"
        binary_prediction = 0
        verdict_confidence = "low" if evidence_status.get("status") == "insufficient" else "normal"
    return {
        "violation": violation,
        "binary_prediction": binary_prediction,
        "best_effort_binary_prediction": violation,
        "label": label,
        "verdict_confidence": verdict_confidence,
        "aggregation_rule": (
            "Vulnerable iff at least one obligation has violation=1. "
            "Otherwise Benign. Missing or ambiguous evidence is ignored for the binary label and tracked only in diagnostics."
        ),
        "violated_obligation_ids": violated_obligation_ids,
    }


def build_evaluation_diagnostics(
    ground_truth: dict[str, Any] | None,
    correct: bool | None,
    input_quality: dict[str, Any],
    evidence_status: dict[str, Any],
    rules_record: dict[str, Any],
    adjudications: list[dict[str, Any]],
    final_verdict: dict[str, Any],
) -> dict[str, Any]:
    obligations = rules_from_record(rules_record)
    diagnostic_label = "not_evaluated"
    failure_stage = "none"
    reason = "Ground truth is unavailable."

    if ground_truth is not None and correct is not None:
        if correct and evidence_status.get("status") == "insufficient":
            diagnostic_label = "correct_but_uninformative"
            failure_stage = likely_failure_stage(input_quality, obligations, adjudications, final_verdict)
            reason = "Binary prediction matches ground truth, but the pipeline did not have enough evidence for a strong benign/vulnerable conclusion."
        elif correct:
            diagnostic_label = "correct"
            reason = "Binary prediction matches ground truth with adequate evidence status."
        else:
            diagnostic_label = "incorrect"
            failure_stage = likely_failure_stage(input_quality, obligations, adjudications, final_verdict)
            reason = "Binary prediction does not match ground truth."
    elif ground_truth is not None and final_verdict.get("label") == "InsufficientEvidence":
        diagnostic_label = "abstained"
        failure_stage = likely_failure_stage(input_quality, obligations, adjudications, final_verdict)
        reason = "The pipeline abstained because the available evidence was insufficient for a reliable binary prediction."

    return {
        "diagnostic_label": diagnostic_label,
        "failure_stage": failure_stage,
        "reason": reason,
        "ground_truth_used_only_for_evaluation": True,
    }


def likely_failure_stage(
    input_quality: dict[str, Any],
    obligations: list[dict[str, Any]],
    adjudications: list[dict[str, Any]],
    final_verdict: dict[str, Any],
) -> str:
    if input_quality.get("status") == "suspicious":
        return "input_scope"
    if input_quality.get("status") == "limited":
        return "evidence_gap"
    if not obligations:
        return "stage2_obligation_generation"
    if obligations and not adjudications:
        return "stage3_adjudication"
    if final_verdict.get("verdict_confidence") == "low":
        return "aggregation"
    return "none"


def build_pipeline_diagnostics(
    semantic_model_record: dict[str, Any],
    rules_record: dict[str, Any],
    adjudications: list[dict[str, Any]],
    adjudicator_errors: list[dict[str, Any]],
    input_quality: dict[str, Any] | None = None,
    evidence_status: dict[str, Any] | None = None,
    adjudicator_quality_gate: dict[str, Any] | None = None,
) -> dict[str, Any]:
    diagnostics = {
        "errors": [],
        "warnings": [],
        "missing_information": [],
        "conflicts": [],
        "stage_status": {},
        "input_quality": input_quality or {},
        "evidence_status": evidence_status or {},
    }

    semantic_gate = semantic_model_record.get("quality_gate", {})
    diagnostics["stage_status"]["Stage 1"] = semantic_gate.get("status", "unknown")
    for agent_key, gate in semantic_model_record.get("output", {}).get("agent_quality_gates", {}).items():
        _collect_gate_attempt_errors(diagnostics, "Stage 1", agent_key, gate)

    diagnostics["stage_status"]["Stage 2"] = rules_record.get("quality_gate", {}).get("status", "unknown")
    _collect_gate_attempt_errors(diagnostics, "Stage 2", "obligation_reasoner", rules_record.get("quality_gate", {}))
    if evidence_status and evidence_status.get("status") == "insufficient":
        diagnostics["warnings"].append(
            {
                "stage": "Aggregation",
                "kind": "insufficient_evidence",
                "message": "No strong binary verdict should be inferred from insufficient evidence.",
                "reasons": evidence_status.get("reasons", []),
            }
        )

    diagnostics["stage_status"]["Stage 3"] = "passed" if not adjudicator_errors else "failed"
    diagnostics["errors"].extend(adjudicator_errors)
    if adjudicator_quality_gate is not None:
        _collect_gate_attempt_errors(
            diagnostics,
            "Stage 3",
            "obligation_adjudicator",
            adjudicator_quality_gate,
        )

    _collect_rule_conflicts(diagnostics, semantic_model_record, rules_record)
    return diagnostics


def _collect_gate_attempt_errors(
    diagnostics: dict[str, Any],
    stage: str,
    agent_key: str,
    gate: dict[str, Any],
    obligation_id: str | None = None,
) -> None:
    for attempt in gate.get("attempts", []):
        errors = attempt.get("errors", [])
        if not errors:
            continue
        diagnostics["warnings"].append(
            {
                "stage": stage,
                "agent_key": agent_key,
                "obligation_id": obligation_id,
                "attempt": attempt.get("attempt"),
                "message": "Quality gate found issues and requested retry.",
                "issues": errors,
            }
        )


def _collect_rule_conflicts(
    diagnostics: dict[str, Any],
    semantic_model_record: dict[str, Any],
    rules_record: dict[str, Any],
) -> None:
    semantic_model = semantic_model_record.get("output", {}).get("semantic_model", {})
    operation_ids = {
        operation.get("id")
        for operation in semantic_model.get("operation_agent", {}).get("operations", [])
        if operation.get("id")
    }
    for rule in rules_record.get("output", {}).get("rules", []):
        operation_id = rule.get("operation_id")
        if operation_id and operation_id not in operation_ids:
            diagnostics["conflicts"].append(
                {
                    "stage": "Stage 3",
                    "kind": "unknown_operation_id",
                    "message": "Rule references an operation_id that does not exist in Stage 1 operation inventory.",
                    "rule_id": rule.get("id"),
                    "operation_id": operation_id,
                }
            )


def find_operation(operation_inventory: dict[str, Any], operation_id: str | None) -> dict[str, Any]:
    for operation in operation_inventory.get("operations", []):
        if operation.get("id") == operation_id:
            return operation
    return {}


def filter_evidence_for_obligation(
    semantic_model: dict[str, Any],
    obligation: dict[str, Any],
) -> dict[str, Any]:
    evidence_refs = set(obligation.get("evidence_refs", []))
    operation_id = obligation.get("operation_id")
    if not evidence_refs and not operation_id:
        return {
            "semantic_evidence": compact_semantic_model_for_llm(semantic_model),
        }

    filtered: dict[str, Any] = {}
    for agent_key, output in semantic_model.items():
        records = []
        for collection_name in ("operations", "records"):
            for index, item in enumerate(output.get(collection_name, [])):
                structured_ref = f"{agent_key}.{collection_name}[{index}]"
                if item.get("id") == operation_id or structured_ref in evidence_refs or item.get("id") in evidence_refs:
                    record = compact_fact_for_adjudicator({"ref": structured_ref, **strip_llm_noise(item)})
                    records.append(record)
        if records:
            filtered[agent_key] = records[:8]
    return {
        "semantic_evidence": filtered,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the VulSOR prompt-agent pipeline.")
    parser.add_argument("--split", default="test", choices=["train", "valid", "test"])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true", help="Render prompts without calling the configured LLM provider.")
    parser.add_argument("--overwrite", action="store_true", help="Clear this split's stage outputs before running.")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parents[2]
    pipeline = VulSORPipeline(
        project_root=project_root,
        split=args.split,
        dry_run=args.dry_run,
        overwrite=args.overwrite,
    )
    pipeline.run(limit=args.limit)


if __name__ == "__main__":
    main()
