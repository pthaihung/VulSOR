from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path
from typing import Any, Callable, Iterable

from .LLMClient import DryRunClient, OpenRouterClient
from .ObligationAgent import ObligationAdjudicator, ObligationReasoner
from .QualityGate import validate_line_numbers, validate_source_grounding
from .SemanticAgent import ExecutionAgent, OperationAgent, StateAgent, ValueAgent
from .SimpleYaml import load_yaml
from .tools.LineLocatorTool import LineLocatorTool


STAGE_DIRS = {
    "semantic_model": "Stage 1",
    "input_context": "Stage 2",
    "obligation_reasoner": "Stage 3",
    "obligation_adjudicator": "Stage 4",
}


STAGE_FILES = {
    1: ("semantic_model", "semantic_model"),
    2: ("input_context", "input_context"),
    3: ("obligation_reasoner", "rules"),
    4: ("obligation_adjudicator", "obligation_adjudicator"),
}


STAGE_LABELS = {
    1: "Stage 1 - semantic model",
    2: "Stage 2 - input context",
    3: "Stage 3 - obligations",
    4: "Stage 4 - adjudication",
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
        provider = self.agents_config.get("provider", {})
        self.llm_client = DryRunClient() if dry_run else OpenRouterClient(provider)
        self.agents = self._build_agents()
        self.stage_root = project_root / "stages"
        self._ensure_stage_dirs()
        if overwrite:
            self._clear_split_outputs()

    def run(self, limit: int | None = None) -> None:
        self.run_samples(self.load_samples(limit=limit), up_to_stage=4)

    def run_samples(
        self,
        samples: Iterable[dict[str, Any]],
        up_to_stage: int = 4,
        progress_callback: ProgressCallback | None = None,
    ) -> None:
        for sample in samples:
            self.run_sample(sample, up_to_stage=up_to_stage, progress_callback=progress_callback)

    def run_sample(
        self,
        sample: dict[str, Any],
        up_to_stage: int = 4,
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        record = {}
        for stage in range(1, up_to_stage + 1):
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
            return self.run_stage_2(sample)
        if stage == 3:
            return self.run_stage_3(sample, progress_callback=progress_callback)
        if stage == 4:
            return self.run_stage_4(sample, progress_callback=progress_callback)
        raise ValueError(f"Unsupported stage: {stage}")

    def run_stage_1(
        self,
        sample: dict[str, Any],
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        sample_id = sample["sample_id"]
        numbered_code = add_line_numbers(sample["code"])
        max_line = count_lines(sample["code"])
        line_locator = LineLocatorTool(sample["code"])

        semantic_outputs = {}
        agent_keys = ["operation_agent", "state_agent", "value_agent", "execution_agent"]
        for agent_index, agent_key in enumerate(agent_keys, start=1):
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
                {"numbered_function_code": numbered_code},
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
        self._write_stage_json("semantic_model", sample_id, "semantic_model", semantic_model_record)
        return read_json_file(self._stage_file("semantic_model", sample_id, "semantic_model"))

    def run_stage_2(self, sample: dict[str, Any]) -> dict[str, Any]:
        sample_id = sample["sample_id"]
        input_context_record = build_input_context_record(sample_id)
        self._write_stage_json("input_context", sample_id, "input_context", input_context_record)
        return read_json_file(self._stage_file("input_context", sample_id, "input_context"))

    def run_stage_3(
        self,
        sample: dict[str, Any],
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        sample_id = sample["sample_id"]
        semantic_model_record = self._read_required_stage(sample_id, 1)
        cpg_evidence_record = self._read_required_stage(sample_id, 2)
        merged_semantic_model = semantic_model_record["output"]["semantic_model"]
        operation_inventory = merged_semantic_model["operation_agent"]
        emit_progress(
            progress_callback,
            event="agent_start",
            sample_id=sample_id,
            stage=3,
            agent_key="obligation_reasoner",
            index=1,
            total=1,
        )
        reasoner_output = self.agents["obligation_reasoner"].run(
            {
                "merged_semantic_model_json": merged_semantic_model,
                "operation_inventory_json": operation_inventory,
                "cpg_evidence_json": cpg_evidence_record["output"],
            },
            progress_callback=progress_callback,
            progress_context={"sample_id": sample_id, "stage": 3},
        )
        emit_progress(
            progress_callback,
            event="agent_done",
            sample_id=sample_id,
            stage=3,
            agent_key="obligation_reasoner",
            index=1,
            total=1,
            token_usage=token_usage_from_agent_output(reasoner_output),
            max_tokens=max_tokens_from_agent_output(reasoner_output),
            summary=agent_output_summary(reasoner_output),
        )
        rules_record = build_rules_record(sample_id, reasoner_output)
        self._write_stage_json("obligation_reasoner", sample_id, "rules", rules_record)
        return read_json_file(self._stage_file("obligation_reasoner", sample_id, "rules"))

    def run_stage_4(
        self,
        sample: dict[str, Any],
        progress_callback: ProgressCallback | None = None,
    ) -> dict[str, Any]:
        sample_id = sample["sample_id"]
        semantic_model_record = self._read_required_stage(sample_id, 1)
        cpg_evidence_record = self._read_required_stage(sample_id, 2)
        rules_record = self._read_required_stage(sample_id, 3)
        merged_semantic_model = semantic_model_record["output"]["semantic_model"]
        operation_inventory = merged_semantic_model["operation_agent"]
        obligations = rules_record["output"]["rules"]
        adjudications = []
        adjudicator_errors = []
        total_obligations = len(obligations)
        for obligation_index, obligation in enumerate(obligations, start=1):
            operation = find_operation(operation_inventory, obligation.get("operation_id"))
            evidence = filter_evidence_for_obligation(
                merged_semantic_model,
                obligation,
                cpg_evidence_record["output"],
            )
            obligation_id = obligation.get("id", f"o_{obligation_index}")
            emit_progress(
                progress_callback,
                event="obligation_start",
                sample_id=sample_id,
                stage=4,
                obligation_id=obligation_id,
                index=obligation_index,
                total=total_obligations,
            )
            try:
                adjudicator_output = self.agents["obligation_adjudicator"].run(
                    {
                        "obligation_id": obligation_id,
                        "anchored_operation": operation,
                        "safety_requirement": obligation.get("safety_requirement", ""),
                        "applicable_condition": obligation.get("applicable_condition", ""),
                        "obligation_specific_evidence_json": evidence,
                    },
                    progress_callback=progress_callback,
                    progress_context={"sample_id": sample_id, "stage": 4},
                )
                adjudications.append(
                    {
                        "rule": obligation,
                        "output": adjudicator_output["parsed"],
                        "quality_gate": adjudicator_output["quality_gate"],
                    }
                )
                emit_progress(
                    progress_callback,
                    event="obligation_done",
                    sample_id=sample_id,
                    stage=4,
                    obligation_id=obligation_id,
                    index=obligation_index,
                    total=total_obligations,
                    token_usage=token_usage_from_agent_output(adjudicator_output),
                    max_tokens=max_tokens_from_agent_output(adjudicator_output),
                    summary=agent_output_summary(adjudicator_output),
                )
            except ValueError as exc:
                adjudicator_errors.append(
                    {
                        "stage": "Stage 4",
                        "agent_key": "obligation_adjudicator",
                        "obligation_id": obligation_id,
                        "error": str(exc),
                    }
                )
                emit_progress(
                    progress_callback,
                    event="obligation_error",
                    sample_id=sample_id,
                    stage=4,
                    obligation_id=obligation_id,
                    index=obligation_index,
                    total=total_obligations,
                    error=str(exc),
                )

        final_verdict = aggregate_final_verdict(adjudications)
        ground_truth = self.ground_truth_for_sample(sample_id)
        correct = None
        if ground_truth is not None and ground_truth.get("target") is not None:
            correct = int(final_verdict["violation"]) == int(ground_truth["target"])
        diagnostics = build_pipeline_diagnostics(
            semantic_model_record,
            cpg_evidence_record,
            rules_record,
            adjudications,
            adjudicator_errors,
        )
        record = {
            "sample_id": sample_id,
            "agent_key": "obligation_adjudicator",
            "ground_truth": ground_truth,
            "output": {
                "adjudications": adjudications,
                "violation": final_verdict["violation"],
                "label": final_verdict["label"],
                "ground_truth": ground_truth,
                "correct": correct,
                "aggregation_rule": final_verdict["aggregation_rule"],
                "violated_obligation_ids": final_verdict["violated_obligation_ids"],
            },
            "quality_gate": {
                "status": "passed" if not diagnostics["errors"] else "failed",
                "adjudication_count": len(adjudications),
            },
            "token_usage": sum_token_usages(
                item.get("quality_gate", {}).get("token_usage", empty_token_usage())
                for item in adjudications
            ),
            "pipeline_diagnostics": diagnostics,
        }
        self._write_stage_json(
            "obligation_adjudicator",
            sample_id,
            "obligation_adjudicator",
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
        self._write_stage_json(agent_key, sample_id, file_stem, record)
        return output

    def _run_agent(
        self,
        agent_key: str,
        variables: dict[str, Any],
        max_line: int | None = None,
        line_locator: LineLocatorTool | None = None,
        progress_callback: ProgressCallback | None = None,
        progress_context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        extra_validators = []
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

    def _stage_file(self, agent_key: str, sample_id: str, file_stem: str) -> Path:
        stage_dir = self.stage_root / STAGE_DIRS[agent_key]
        return stage_dir / sample_id / f"{file_stem}.json"

    def _stage_file_for_number(self, sample_id: str, stage: int) -> Path:
        agent_key, file_stem = STAGE_FILES[stage]
        return self._stage_file(agent_key, sample_id, file_stem)

    def _read_required_stage(self, sample_id: str, stage: int) -> dict[str, Any]:
        path = self._stage_file_for_number(sample_id, stage)
        if not path.exists():
            raise FileNotFoundError(
                f"{STAGE_LABELS[stage]} output is required before running the next stage: {path}"
            )
        return read_json_file(path)

    def _write_stage_json(self, agent_key: str, sample_id: str, file_stem: str, record: dict[str, Any]) -> None:
        output_path = self._stage_file(agent_key, sample_id, file_stem)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(json.dumps(record, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def _ensure_stage_dirs(self) -> None:
        self.stage_root.mkdir(exist_ok=True)
        for stage_dir in STAGE_DIRS.values():
            (self.stage_root / stage_dir).mkdir(exist_ok=True)

    def _clear_split_outputs(self) -> None:
        for stage_dir in self.stage_root.glob("Stage *"):
            if not stage_dir.is_dir():
                continue
            for output_path in stage_dir.glob(f"{self.split}_*.jsonl"):
                output_path.unlink()
            for sample_dir in stage_dir.glob(f"{self.split}_*"):
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
        for stage in range(1, 5):
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
        total["input_tokens"] += int(usage.get("input_tokens", 0) or 0)
        total["output_tokens"] += int(usage.get("output_tokens", 0) or 0)
        total["total_tokens"] += int(usage.get("total_tokens", 0) or 0)
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
    if isinstance(operations, list):
        parts.append(f"operations={len(operations)}")
    if isinstance(records, list):
        parts.append(f"records={len(records)}")
    if isinstance(obligations, list):
        parts.append(f"obligations={len(obligations)}")
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
        return f"agents={agent_count}"
    if stage == 2:
        output = record.get("output", {})
        return f"status={output.get('status', 'unknown')}"
    if stage == 3:
        obligations = record.get("output", {}).get("rules", [])
        return f"obligations={len(obligations)}"
    if stage == 4:
        output = record.get("output", {})
        return (
            f"verdict={str(output.get('label', 'unknown')).lower()}, "
            f"violation={output.get('violation')}, correct={output.get('correct')}"
        )
    return ""


def build_semantic_model_record(sample_id: str, semantic_outputs: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {
        "sample_id": sample_id,
        "stage": "semantic_model",
        "output": {
            "semantic_model": {
                agent_key: output["parsed"]
                for agent_key, output in semantic_outputs.items()
            },
            "agent_quality_gates": {
                agent_key: output["quality_gate"]
                for agent_key, output in semantic_outputs.items()
            },
        },
        "quality_gate": {
            "status": "passed",
            "agent_count": len(semantic_outputs),
        },
        "token_usage": sum_token_usages(
            token_usage_from_agent_output(output)
            for output in semantic_outputs.values()
        ),
    }


def build_input_context_record(sample_id: str) -> dict[str, Any]:
    return {
        "sample_id": sample_id,
        "stage": "input_context",
        "output": {"status": "not_provided", "context": {}},
        "quality_gate": {
            "status": "passed",
        },
        "token_usage": empty_token_usage(),
    }


def build_rules_record(sample_id: str, reasoner_output: dict[str, Any]) -> dict[str, Any]:
    obligations = reasoner_output["parsed"].get("obligations", [])
    return {
        "sample_id": sample_id,
        "stage": "rules",
        "agent_key": "obligation_reasoner",
        "output": {
            "rules": obligations,
            "obligations": obligations,
            "raw_reasoner_output": reasoner_output["parsed"],
        },
        "quality_gate": reasoner_output["quality_gate"],
        "token_usage": token_usage_from_agent_output(reasoner_output),
    }


def aggregate_final_verdict(adjudications: list[dict[str, Any]]) -> dict[str, Any]:
    violated_obligation_ids = []
    for item in adjudications:
        output = item.get("output", {})
        if output.get("violation") != 1:
            continue
        obligation_id = output.get("obligation_id") or item.get("rule", {}).get("id")
        if obligation_id:
            violated_obligation_ids.append(obligation_id)

    violation = 1 if violated_obligation_ids else 0
    return {
        "violation": violation,
        "label": "Vulnerable" if violation == 1 else "Benign",
        "aggregation_rule": "Vulnerable iff exists obligation o_i,k with v_i,k=1; otherwise Benign.",
        "violated_obligation_ids": violated_obligation_ids,
    }


def build_pipeline_diagnostics(
    semantic_model_record: dict[str, Any],
    cpg_evidence_record: dict[str, Any],
    rules_record: dict[str, Any],
    adjudications: list[dict[str, Any]],
    adjudicator_errors: list[dict[str, Any]],
) -> dict[str, Any]:
    diagnostics = {
        "errors": [],
        "warnings": [],
        "missing_information": [],
        "conflicts": [],
        "stage_status": {},
    }

    semantic_gate = semantic_model_record.get("quality_gate", {})
    diagnostics["stage_status"]["Stage 1"] = semantic_gate.get("status", "unknown")
    for agent_key, gate in semantic_model_record.get("output", {}).get("agent_quality_gates", {}).items():
        _collect_gate_attempt_errors(diagnostics, "Stage 1", agent_key, gate)

    cpg_output = cpg_evidence_record.get("output", {})
    diagnostics["stage_status"]["Stage 2"] = cpg_evidence_record.get("quality_gate", {}).get("status", "unknown")
    if cpg_output.get("required") and cpg_output.get("status") != "built":
        diagnostics["missing_information"].append(
            {
                "stage": "Stage 2",
                "kind": "cpg_evidence",
                "message": "CPG evidence is required but was not built.",
                "required_operations": cpg_output.get("required_operations", []),
            }
        )
    for limitation in cpg_output.get("limitations", []):
        diagnostics["warnings"].append(
            {
                "stage": "Stage 2",
                "kind": "limitation",
                "message": limitation,
            }
        )

    diagnostics["stage_status"]["Stage 3"] = rules_record.get("quality_gate", {}).get("status", "unknown")
    _collect_gate_attempt_errors(diagnostics, "Stage 3", "obligation_reasoner", rules_record.get("quality_gate", {}))

    diagnostics["stage_status"]["Stage 4"] = "passed" if not adjudicator_errors else "failed"
    diagnostics["errors"].extend(adjudicator_errors)
    for item in adjudications:
        _collect_gate_attempt_errors(
            diagnostics,
            "Stage 4",
            "obligation_adjudicator",
            item.get("quality_gate", {}),
            obligation_id=item.get("rule", {}).get("id"),
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
    cpg_evidence: dict[str, Any] | None = None,
) -> dict[str, Any]:
    evidence_refs = set(obligation.get("evidence_refs", []))
    operation_id = obligation.get("operation_id")
    if not evidence_refs and not operation_id:
        return {
            "semantic_evidence": semantic_model,
            "cpg_evidence": cpg_evidence or {},
        }

    filtered: dict[str, Any] = {}
    for agent_key, output in semantic_model.items():
        records = []
        for collection_name in ("operations", "records"):
            for item in output.get(collection_name, []):
                encoded = json.dumps(item, ensure_ascii=False)
                if item.get("id") == operation_id or any(ref in encoded for ref in evidence_refs):
                    records.append(item)
        filtered[agent_key] = records
    return {
        "semantic_evidence": filtered,
        "cpg_evidence": cpg_evidence or {},
    }


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the VulSOR prompt-agent pipeline.")
    parser.add_argument("--split", default="test", choices=["train", "valid", "test"])
    parser.add_argument("--limit", type=int, default=None)
    parser.add_argument("--dry-run", action="store_true", help="Render prompts without calling OpenRouter.")
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
